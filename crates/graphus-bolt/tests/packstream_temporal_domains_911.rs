//! **Out-of-domain temporal values are handled at the boundary, exactly as the reference reader
//! handles them** (`rmp` task #911).
//!
//! Graphus accepted a `Time` with a nanos-of-day past midnight, a `DateTime`/`LocalDateTime` with a
//! nanos field up to `u32::MAX`, an unbounded `Date.days`, and any `tz_offset_seconds` at all. Two
//! consequences, the second larger than the first:
//!
//! 1. Graphus **re-emitted** the out-of-domain value to a driver that must reject it, so the failure
//!    surfaced at the client as a corrupt server response rather than at the boundary as a client
//!    error — and the bad value could be stored as a property in the meantime.
//! 2. The un-normalised field caused **the same identity divergence as `rmp` #908**: the wire kept
//!    `nanos: 1_500_000_000` while the engine normalises to `(+1s, 500_000_000)`, and the temporal
//!    types derive `Eq`/`Ord`/`Hash` **component-wise** — so one instant with two spellings compared
//!    unequal and *sorted apart*. [`a_wire_value_and_its_in_engine_twin_are_the_same_value`] is the
//!    gate for that.
//!
//! # The rules are per-tag, and they disagree
//!
//! The single most important thing about this task: the reference readers do **not** apply one rule.
//! Three of the four premises this task started from were wrong when checked against the source, so
//! every rule below is asserted against the class it was read from:
//!
//! | tag | field | behaviour | reference |
//! |---|---|---|---|
//! | `Date` 0x44 | `days` | REJECT | `DateValue.epochDateRaw` → `assertValidArgument(LocalDate.ofEpochDay)` |
//! | `LocalTime` 0x74 | `nanoseconds` | REJECT | `LocalTimeValue.localTimeRaw` → `assertValidArgument(LocalTime.ofNanoOfDay)` |
//! | `Time` 0x54 | `nanoseconds` | NORMALISE | `TimeValue.timeRaw` → `OffsetTime.ofInstant(Instant.ofEpochSecond(0, n), offset)` |
//! | `Time` / `DateTime` | `tz_offset_seconds` | REJECT above ±64800 | `zoneOffsetOfTotalSeconds` → `ZoneOffset.ofTotalSeconds` |
//! | `LocalDateTime` 0x64 | `nanoseconds` | NORMALISE | `LocalDateTimeValue.localDateTimeRaw` → `ofInstant(Instant.ofEpochSecond(s, n), UTC)` |
//! | `DateTime` 0x49 / `DateTimeZoneId` 0x69 | `nanoseconds` | bound to `i32`, then NORMALISE | the readers' explicit `Integer` bound + `Instant.ofEpochSecond` |
//! | `Duration` 0x45 | `nanoseconds` | full `i64`, then NORMALISE | `DurationValue`'s constructor carries `nanos / 1e9` into `seconds` |
//!
//! `Time` and `LocalTime` carry the same field and take **opposite** rules; asserting one rule for
//! both would be wrong in one direction whichever rule were chosen.

use graphus_bolt::{Packer, Unpacker, pack_value, unpack_value};
use graphus_core::Value;
use graphus_core::value::temporal::{Duration, LocalDateTime, LocalTime, ZonedTime};

/// PackStream structure signatures.
mod tag {
    pub const DATE: u8 = 0x44;
    pub const TIME: u8 = 0x54;
    pub const LOCAL_TIME: u8 = 0x74;
    pub const LOCAL_DATE_TIME: u8 = 0x64;
    pub const DATE_TIME: u8 = 0x49;
    pub const DURATION: u8 = 0x45;
}

/// Nanoseconds in one standard day.
const NANOS_PER_DAY: i64 = 86_400_000_000_000;
/// The reference's maximum absolute UTC offset (`ZoneOffset.ofTotalSeconds`).
const MAX_OFFSET: i64 = 18 * 60 * 60;

/// Hand-builds the wire bytes for a structure with `tag` and integer `fields`.
///
/// Written by hand rather than through the encoder on purpose: the encoder can only emit values the
/// engine can hold, so it is structurally incapable of producing the out-of-domain input under test.
/// That is precisely how these defects survived a round-trip property test.
fn struct_bytes(tag: u8, fields: &[i64]) -> Vec<u8> {
    let mut p = Packer::new();
    p.write_struct_header(tag, fields.len())
        .expect("field count is within the tiny-struct nibble");
    for f in fields {
        p.write_int(*f);
    }
    p.into_inner()
}

/// Decodes hand-built structure bytes.
fn decode(tag: u8, fields: &[i64]) -> Result<Value, String> {
    let bytes = struct_bytes(tag, fields);
    let mut u = Unpacker::new(&bytes);
    unpack_value(&mut u).map_err(|e| e.to_string())
}

/// Decodes and expects success.
fn decode_ok(tag: u8, fields: &[i64]) -> Value {
    decode(tag, fields).unwrap_or_else(|e| panic!("tag {tag:#04x} {fields:?} must decode: {e}"))
}

/// Decodes and expects a refusal whose message mentions `needle`.
fn decode_err(tag: u8, fields: &[i64], needle: &str) {
    match decode(tag, fields) {
        Ok(v) => panic!("tag {tag:#04x} {fields:?} must be refused, decoded to {v:?}"),
        Err(msg) => assert!(
            msg.contains(needle),
            "the refusal must say what is wrong (looking for {needle:?}): {msg}"
        ),
    }
}

#[test]
fn date_days_outside_the_opencypher_year_range_is_refused() {
    // `LocalDate.ofEpochDay` inside `assertValidArgument`: the reference refuses a day outside the
    // proleptic-Gregorian years -999999999..=999999999. An accepted one would be stored and
    // re-emitted as a date no driver can construct.
    const MIN: i64 = -365_243_219_162;
    const MAX: i64 = 365_241_780_471;

    // The boundaries themselves are legal — the gate must not be "reject anything large".
    assert_eq!(
        decode_ok(tag::DATE, &[MIN]),
        Value::Date(graphus_core::value::temporal::Date {
            days_since_epoch: MIN
        })
    );
    assert_eq!(
        decode_ok(tag::DATE, &[MAX]),
        Value::Date(graphus_core::value::temporal::Date {
            days_since_epoch: MAX
        })
    );
    // One day past either end is not.
    decode_err(tag::DATE, &[MIN - 1], "out of range");
    decode_err(tag::DATE, &[MAX + 1], "out of range");
    decode_err(tag::DATE, &[i64::MAX], "out of range");
    decode_err(tag::DATE, &[i64::MIN], "out of range");
}

#[test]
fn local_time_past_midnight_is_refused_but_time_normalises() {
    // THE PAIR THAT DISAGREES. Both tags carry "nanoseconds", and the reference takes opposite
    // rules: `LocalTime.ofNanoOfDay` throws, while `OffsetTime.ofInstant(Instant.ofEpochSecond(0,
    // n), offset)` wraps. Getting either one wrong is a conformance defect in a different direction,
    // so both are asserted here, side by side, from the same input.

    // LocalTime (0x74): the last nanosecond of the day is legal; one more is refused.
    assert_eq!(
        decode_ok(tag::LOCAL_TIME, &[NANOS_PER_DAY - 1]),
        Value::LocalTime(LocalTime {
            nanos_of_day: (NANOS_PER_DAY - 1) as u64
        })
    );
    decode_err(tag::LOCAL_TIME, &[NANOS_PER_DAY], "out of range");
    decode_err(tag::LOCAL_TIME, &[NANOS_PER_DAY + 5], "out of range");
    decode_err(tag::LOCAL_TIME, &[i64::MAX], "out of range");
    decode_err(tag::LOCAL_TIME, &[-1], "negative");

    // Time (0x54): the identical counts WRAP into the day rather than being refused.
    assert_eq!(
        decode_ok(tag::TIME, &[NANOS_PER_DAY + 5, 0]),
        Value::ZonedTime(ZonedTime {
            time: LocalTime { nanos_of_day: 5 },
            offset_seconds: 0,
        }),
        "a Time past midnight wraps, as OffsetTime.ofInstant does"
    );
    // ...including a negative count, which wraps to the end of the day (Euclidean, not truncating:
    // a `%` here would yield a negative nanos-of-day and break the core's own invariant).
    assert_eq!(
        decode_ok(tag::TIME, &[-1, 0]),
        Value::ZonedTime(ZonedTime {
            time: LocalTime {
                nanos_of_day: (NANOS_PER_DAY - 1) as u64
            },
            offset_seconds: 0,
        }),
        "a negative Time wraps to the end of the day, not to a negative nanos-of-day"
    );
}

#[test]
fn a_tz_offset_beyond_eighteen_hours_is_refused_on_both_tags() {
    // `ZoneOffset.ofTotalSeconds` bounds the offset to ±18h. Graphus accepted any i32 and then used
    // the value as an ORDERING KEY (`ZonedTime` orders by `local - offset`), so an absurd offset
    // displaced the value in every index and comparison it took part in.
    for offset in [MAX_OFFSET, -MAX_OFFSET] {
        // The boundary itself is legal.
        assert!(
            decode(tag::TIME, &[0, offset]).is_ok(),
            "±18h exactly must be accepted"
        );
        assert!(decode(tag::DATE_TIME, &[0, 0, offset]).is_ok());
    }
    for offset in [MAX_OFFSET + 1, -(MAX_OFFSET + 1), i64::from(i32::MAX)] {
        decode_err(tag::TIME, &[0, offset], "out of range");
        decode_err(tag::DATE_TIME, &[0, 0, offset], "out of range");
    }
}

#[test]
fn a_nanos_field_is_normalised_into_the_seconds() {
    // NORMALISE, not reject — the premise correction this task was created with. The reference
    // bounds `nanos` only to the INT range and then hands it to `Instant.ofEpochSecond(sec, nanos)`,
    // which CARRIES the overflow into the seconds.

    // LocalDateTime: 1.5 seconds of "nanos" becomes +1s and 500_000_000.
    assert_eq!(
        decode_ok(tag::LOCAL_DATE_TIME, &[10, 1_500_000_000]),
        Value::LocalDateTime(LocalDateTime {
            epoch_seconds: 11,
            nanos: 500_000_000,
        })
    );
    // A NEGATIVE nanos borrows a second — the reference explicitly permits negatives here.
    assert_eq!(
        decode_ok(tag::LOCAL_DATE_TIME, &[10, -1]),
        Value::LocalDateTime(LocalDateTime {
            epoch_seconds: 9,
            nanos: 999_999_999,
        })
    );

    // DateTime: the same carry, and the `i32` bound applies FIRST. `u32::MAX` was accepted before
    // (Graphus read the field as u32); the reference refuses it as out of INTEGER range.
    let dt = decode_ok(tag::DATE_TIME, &[10, 1_500_000_000, 0]);
    match dt {
        Value::ZonedDateTime(z) => {
            assert_eq!(z.local.epoch_seconds, 11);
            assert_eq!(z.local.nanos, 500_000_000);
        }
        other => panic!("expected a zoned date-time, got {other:?}"),
    }
    decode_err(tag::DATE_TIME, &[0, i64::from(u32::MAX), 0], "i32");
}

#[test]
fn duration_accepts_the_full_i64_nanosecond_range_and_normalises_it() {
    // Graphus narrowed the field to `i32`, so a driver could not express a duration the reference
    // accepts (`DurationValue.duration` takes four `long`s). The constructor then normalises exactly
    // as this does, which is why no wider in-engine representation is needed to carry the wider wire
    // domain.
    assert_eq!(
        decode_ok(tag::DURATION, &[0, 0, 0, 2_500_000_000]),
        Value::Duration(Duration {
            months: 0,
            days: 0,
            seconds: 2,
            nanos: 500_000_000,
        }),
        "a nanos field beyond i32 is accepted and carried into the seconds"
    );
    assert_eq!(
        decode_ok(tag::DURATION, &[0, 0, 5, -1]),
        Value::Duration(Duration {
            months: 0,
            days: 0,
            seconds: 4,
            nanos: 999_999_999,
        }),
        "a negative nanos borrows a second"
    );
    // Overflow is refused, not saturated: saturating would silently change the duration.
    decode_err(tag::DURATION, &[0, 0, i64::MAX, 1_000_000_000], "overflow");
}

#[test]
fn the_utc_to_local_combination_is_checked_not_clamped() {
    // Graphus used SATURATING arithmetic, so `DateTime { seconds: i64::MAX, offset: 3600 }` silently
    // discarded the offset and re-encoded to DIFFERENT bytes — a value that fails no check anywhere
    // and is simply a different instant than the client named. The reference throws.
    decode_err(tag::DATE_TIME, &[i64::MAX, 0, 3600], "overflow");
    decode_err(tag::DATE_TIME, &[i64::MIN, 0, -3600], "overflow");
    // The nanosecond carry is checked on the same terms.
    decode_err(tag::LOCAL_DATE_TIME, &[i64::MAX, 1_000_000_000], "overflow");

    // CONTROL: an ordinary instant with the same shape is untouched, so the gate above cannot be
    // passing because the combination is refused in general.
    match decode_ok(tag::DATE_TIME, &[1_000, 0, 3600]) {
        Value::ZonedDateTime(z) => assert_eq!(z.local.epoch_seconds, 4_600),
        other => panic!("expected a zoned date-time, got {other:?}"),
    }
}

#[test]
fn a_structure_signature_above_0x7f_is_refused_as_a_signature() {
    // PackStream specifies the signature as a single SIGNED byte, so `0..=127` is the tag space.
    // Behaviourally this agrees with the old code (every such tag was unknown anyway); the point is
    // that the refusal now names the real fault and the tag table can never claim a byte the
    // specification does not give it.
    let mut p = Packer::new();
    p.write_struct_header(0x80, 0).expect("header");
    let bytes = p.into_inner();
    let mut u = Unpacker::new(&bytes);
    let err = unpack_value(&mut u)
        .expect_err("0x80 is not a valid signature")
        .to_string();
    assert!(
        err.contains("signature") && err.contains("out of range"),
        "the refusal must name the signature bound: {err}"
    );

    // CONTROL: 0x7F itself is a well-formed (if unassigned) signature, so it is refused as an
    // UNKNOWN structure rather than as a malformed one. Without this the gate above would pass for a
    // decoder that refused every structure.
    let mut p = Packer::new();
    p.write_struct_header(0x7F, 0).expect("header");
    let bytes = p.into_inner();
    let mut u = Unpacker::new(&bytes);
    let err = unpack_value(&mut u)
        .expect_err("0x7F is unassigned")
        .to_string();
    assert!(
        err.contains("unknown"),
        "0x7F is a valid signature, merely unassigned: {err}"
    );
}

#[test]
fn a_wire_value_and_its_in_engine_twin_are_the_same_value() {
    // THE HEADLINE GATE — the identity divergence, the same class as `rmp` #908.
    //
    // The temporal types derive Eq/Ord/Hash COMPONENT-WISE. So when the wire kept
    // `nanos: 1_500_000_000` and the engine normalised the same instant to `(+1s, 500_000_000)`, the
    // two were not merely stored differently: they compared UNEQUAL and SORTED APART. A property
    // indexed from one spelling could not be found by a query written with the other.
    //
    // Each pair below is two spellings of ONE instant: the un-normalised wire form, and the form the
    // engine builds. They must decode to the same value, and therefore compare equal and order
    // together.
    let pairs: [(u8, Vec<i64>, Vec<i64>); 4] = [
        // LocalDateTime: 10s + 1.5e9 nanos  ==  11s + 0.5e9 nanos.
        (
            tag::LOCAL_DATE_TIME,
            vec![10, 1_500_000_000],
            vec![11, 500_000_000],
        ),
        // DateTime: the same carry, with an offset.
        (
            tag::DATE_TIME,
            vec![10, 1_500_000_000, 3600],
            vec![11, 500_000_000, 3600],
        ),
        // Time: one day and 5ns past midnight  ==  5ns past midnight.
        (tag::TIME, vec![NANOS_PER_DAY + 5, 0], vec![5, 0]),
        // Duration: 2.5e9 nanos  ==  2s + 0.5e9 nanos.
        (
            tag::DURATION,
            vec![0, 0, 0, 2_500_000_000],
            vec![0, 0, 2, 500_000_000],
        ),
    ];

    for (tag, wire, twin) in pairs {
        let from_wire = decode_ok(tag, &wire);
        let from_engine = decode_ok(tag, &twin);
        assert_eq!(
            from_wire, from_engine,
            "tag {tag:#04x}: {wire:?} and {twin:?} are one instant and must be one value"
        );

        // ...and they must SORT TOGETHER, which is the half that actually breaks an index. Equality
        // alone would not catch an ordering key derived from a different field.
        let mut a = Packer::new();
        pack_value(&mut a, &from_wire);
        let mut b = Packer::new();
        pack_value(&mut b, &from_engine);
        assert_eq!(
            a.into_inner(),
            b.into_inner(),
            "tag {tag:#04x}: one value must re-encode to one byte sequence"
        );
    }

    // NON-VACUITY CONTROL: the two spellings really are DIFFERENT on the wire. If the pairs above
    // happened to be byte-identical, the gate would prove nothing at all.
    for (tag, wire, twin) in [
        (
            tag::LOCAL_DATE_TIME,
            vec![10i64, 1_500_000_000],
            vec![11i64, 500_000_000],
        ),
        (tag::TIME, vec![NANOS_PER_DAY + 5, 0], vec![5, 0]),
    ] {
        assert_ne!(
            struct_bytes(tag, &wire),
            struct_bytes(tag, &twin),
            "tag {tag:#04x}: the two spellings must differ on the wire, or this proves nothing"
        );
    }
}

/// **The encoder's `utc = local - offset` can never need to saturate** (`rmp` #911, criterion 5's
/// encode half).
///
/// `pack_value` is infallible by design — it is called mid-`RECORD`, after the chunk framing is
/// committed, so there is no point at which an error could leave the stream in a state a client
/// could act on. That is sound only if the subtraction cannot overflow for any value the system can
/// hold, so this gate proves the property instead of asserting it.
///
/// Two guards make it hold, and the test exercises the union of what they admit:
///
/// * a value from a client passed `unpack_value`, which bounds the offset to ±18 h and refuses an
///   unrepresentable `local = utc + offset`;
/// * a value the engine built came from `temporal_fns`, which works in the openCypher year range, so
///   `|epoch_seconds| ≤ ~3.2e16` — five orders of magnitude below `i64::MAX`.
#[test]
fn encoding_a_zoned_date_time_never_needs_to_saturate() {
    use graphus_core::value::temporal::ZonedDateTime;

    /// The largest `|epoch_seconds|` the openCypher year range can produce: 999999999 years, taken
    /// generously at 366 days each so the bound is an over-estimate, never an under-estimate.
    const MAX_ENGINE_SECONDS: i64 = 999_999_999 * 366 * 86_400;

    // The bound really is far from the edge — the load-bearing arithmetic fact behind the encoder's
    // infallibility. Asserted at COMPILE time: it is a statement about the constants themselves, so a
    // future widening of the year range must fail the build rather than wait for this test to run.
    const _: () = assert!(
        MAX_ENGINE_SECONDS < i64::MAX / 100,
        "the openCypher range must sit orders of magnitude below i64::MAX, else the encoder's \
         infallibility argument does not hold"
    );

    // Every extreme the two guards jointly admit: both ends of the range, both offset extremes, and
    // the zero point — the full corner set for a subtraction.
    for seconds in [
        MAX_ENGINE_SECONDS,
        -MAX_ENGINE_SECONDS,
        0,
        i64::from(i32::MAX),
        i64::from(i32::MIN),
    ] {
        for offset in [MAX_OFFSET as i32, -(MAX_OFFSET as i32), 0] {
            assert!(
                seconds.checked_sub(i64::from(offset)).is_some(),
                "utc = local - offset must be representable for every value the system can hold \
                 (local {seconds}, offset {offset})"
            );

            // And the value really does round-trip through the encoder to the same instant, so the
            // check above is about the value the encoder actually writes.
            let v = Value::zoned_date_time(ZonedDateTime {
                local: LocalDateTime {
                    epoch_seconds: seconds,
                    nanos: 0,
                },
                offset_seconds: offset,
                zone_id: String::new(),
            });
            let mut p = Packer::new();
            pack_value(&mut p, &v);
            let bytes = p.into_inner();
            let mut u = Unpacker::new(&bytes);
            let back = unpack_value(&mut u).expect("an in-range zoned date-time must round-trip");
            assert_eq!(back, v, "local {seconds}, offset {offset}");
        }
    }

    // NON-VACUITY: the decoder is what closes the loop, so confirm it genuinely refuses the values
    // this argument relies on it refusing. Without this the invariant would rest on an unchecked
    // claim about the boundary.
    decode_err(tag::DATE_TIME, &[i64::MAX, 0, 3600], "overflow");
    decode_err(tag::DATE_TIME, &[0, 0, MAX_OFFSET + 1], "out of range");
}

/// **A decoded `element_id` survives re-encoding unchanged** (`rmp` #911, criterion 6).
///
/// `graphus-bolt` is the codec for Graphus's **clients** — the CLI and the DST simulator — as well as
/// its server. A client decodes entities produced by a server that is not necessarily Graphus, whose
/// `element_id` is an opaque string with no relationship to the integer id (a real Neo4j emits a
/// UUID-shaped one). Graphus discarded it on decode and regenerated `id.to_string()` on re-encode,
/// so a client silently **rewrote entity identity**: the value it forwarded was not the value it
/// received, and nothing reported it.
///
/// The gate uses an element id that could not possibly be derived from the integer id, which is what
/// makes it discriminating: a codec that regenerates from the id cannot produce this string.
#[test]
fn an_opaque_element_id_survives_a_client_decode_and_re_encode() {
    use graphus_bolt::{BoltNode, BoltRelationship, BoltValue, pack_bolt_value, unpack_bolt_value};

    const NODE_EID: &str = "4:9f2c1e5a-7b3d-4f18-8a6c-2d0e1b4c7a99:12";
    const REL_EID: &str = "5:9f2c1e5a-7b3d-4f18-8a6c-2d0e1b4c7a99:77";
    const START_EID: &str = "4:9f2c1e5a-7b3d-4f18-8a6c-2d0e1b4c7a99:12";
    const END_EID: &str = "4:9f2c1e5a-7b3d-4f18-8a6c-2d0e1b4c7a99:34";

    // A NODE as some other server would emit it: integer id 12, opaque element id.
    let mut p = Packer::new();
    p.write_struct_header(0x4E, 4).expect("Node header");
    p.write_int(12);
    p.write_list_header(1);
    p.write_string("Person");
    p.write_map_header(0);
    p.write_string(NODE_EID);
    let node_bytes = p.into_inner();

    let mut u = Unpacker::new(&node_bytes);
    let decoded = unpack_bolt_value(&mut u).expect("a foreign node must decode");
    match &decoded {
        BoltValue::Node(BoltNode {
            id, element_ids, ..
        }) => {
            assert_eq!(*id, 12);
            assert_eq!(
                element_ids.as_deref().map(|ids| ids.element_id.as_str()),
                Some(NODE_EID),
                "the opaque element_id must be kept, not discarded"
            );
        }
        other => panic!("expected a node, got {other:?}"),
    }
    let mut p = Packer::new();
    pack_bolt_value(&mut p, &decoded);
    assert_eq!(
        p.into_inner(),
        node_bytes,
        "re-encoding must reproduce the foreign node byte for byte"
    );

    // A RELATIONSHIP, where all THREE element-id strings must survive — the endpoints too, which a
    // node-only fix would miss.
    let mut p = Packer::new();
    p.write_struct_header(0x52, 8).expect("Relationship header");
    p.write_int(77);
    p.write_int(12);
    p.write_int(34);
    p.write_string("KNOWS");
    p.write_map_header(0);
    p.write_string(REL_EID);
    p.write_string(START_EID);
    p.write_string(END_EID);
    let rel_bytes = p.into_inner();

    let mut u = Unpacker::new(&rel_bytes);
    let decoded = unpack_bolt_value(&mut u).expect("a foreign relationship must decode");
    match &decoded {
        BoltValue::Relationship(BoltRelationship { element_ids, .. }) => {
            let ids = element_ids.as_deref().expect("the ids must be kept");
            assert_eq!(ids.element_id, REL_EID);
            assert_eq!(ids.start_element_id, START_EID);
            assert_eq!(ids.end_element_id, END_EID);
        }
        other => panic!("expected a relationship, got {other:?}"),
    }
    let mut p = Packer::new();
    pack_bolt_value(&mut p, &decoded);
    assert_eq!(
        p.into_inner(),
        rel_bytes,
        "re-encoding must reproduce the foreign relationship byte for byte"
    );

    // NON-VACUITY: the opaque ids really are un-derivable from the integer ids, so a codec that
    // regenerated them could not have produced these bytes. Without this the gate would pass for the
    // very implementation it exists to catch.
    assert_ne!(NODE_EID, "12");
    assert_ne!(REL_EID, "77");
    assert_ne!(START_EID, "12");
    assert_ne!(END_EID, "34");

    // CONTROL: the SERVER path is unchanged — an entity built with no carried ids still emits the
    // synthesised decimals, so this change costs the hot path nothing and alters no server output.
    let server_node = BoltValue::Node(BoltNode {
        id: 12,
        labels: vec!["Person".to_owned()],
        properties: vec![],
        element_ids: None,
    });
    let mut p = Packer::new();
    pack_bolt_value(&mut p, &server_node);
    let server_bytes = p.into_inner();
    let mut u = Unpacker::new(&server_bytes);
    match unpack_bolt_value(&mut u).expect("decode") {
        BoltValue::Node(n) => assert_eq!(
            n.element_ids.as_deref().map(|ids| ids.element_id.as_str()),
            Some("12"),
            "the server still synthesises the element id from the integer id"
        ),
        other => panic!("expected a node, got {other:?}"),
    }
}
