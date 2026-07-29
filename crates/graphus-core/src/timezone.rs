//! IANA time-zone resolution shared by every layer that has to turn a named zone into a UTC
//! offset (`rmp` tasks #60, #908).
//!
//! [`crate::temporal_calc`] deliberately performs no zone-rule resolution
//! (`parse_zoned_date_time_parts` hands the bracketed zone id back unresolved); this module owns
//! the time-zone database. The data is the compiled TZif table of **vanilla** IANA tzdata
//! embedded statically by `jiff-tzdb` — identical on every supported OS and architecture, with
//! no runtime filesystem access — parsed and queried through `tz-rs` (historical offsets, DST
//! transitions, and the POSIX extra rule for instants beyond the last recorded transition).
//! Vanilla (no-`backzone`) data is a TCK requirement: `Temporal2.feature` scenario \[6\] pins
//! 1818 Stockholm to `+00:53:28`, the local mean time of Europe/Berlin, which Europe/Stockholm
//! links to in vanilla tzdata since release 2022b.
//!
//! It lives in `graphus-core` — rather than in the Cypher evaluator that first needed it —
//! because both ingress paths must resolve zones **identically**: the Cypher constructors
//! (`datetime({timezone: 'Europe/Paris'})`) and the PackStream `DateTimeZoneId` decoder
//! (structure `0x69`), which carries a zone id and no numeric offset and must localize the UTC
//! instant it receives. Resolving in only one of the two made a wire-supplied value and a
//! Cypher-built value for the same instant disagree on `offset_seconds`, so they neither
//! compared equal nor sorted together (`rmp` #908).
//!
//! The resolution *direction* matters:
//!
//! - [`offset_at_instant`] answers "which UTC offset is in effect at this instant" — total:
//!   every instant has exactly one offset. This is the direction `DateTimeZoneId` decoding
//!   needs, and it is what `java.time.ZonedDateTime.ofInstant` performs.
//! - [`resolve_local`] answers "which UTC offset applies to this **local wall-clock**
//!   date-time" — partial: around a DST transition a local time can be skipped (*gap*, spring
//!   forward) or repeated (*overlap*, fall back).
//!
//! The gap/overlap disambiguation follows `java.time.ZonedDateTime.ofLocal`, which is what
//! Neo4j (the openCypher reference implementation) uses, so it is what the TCK constructor
//! expectations encode (`Temporal1.feature` scenario \[10\], `Temporal2.feature` scenario \[6\],
//! `Temporal3.feature` scenario \[10\], `Temporal10.feature` scenario \[8\]):
//!
//! - **gap**: the local time does not exist; it is moved *later* by the length of the gap and
//!   takes the offset in effect *after* the transition;
//! - **overlap**: the local time exists twice; the caller's `preferred` offset wins when it is
//!   one of the two candidates (so re-deriving a value keeps its offset), otherwise the offset
//!   in effect *before* the transition (java.time's "earlier offset") is chosen.

use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

use crate::temporal_calc::TemporalError;
use crate::value::temporal::LocalDateTime;

/// Parsed zones, keyed by canonical id. TZif parsing allocates, so each zone is parsed once and
/// leaked: the set is bounded by the embedded database (~600 zones) and lives for the process.
static ZONES: LazyLock<RwLock<HashMap<&'static str, &'static tz::TimeZone>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Looks `zone` up in the embedded IANA database (case-insensitive, e.g. `"Europe/Stockholm"`)
/// and returns its canonical id with the parsed zone rules.
///
/// # Errors
/// [`TemporalError::UnknownTimeZone`] for an id absent from the database, or
/// [`TemporalError::TimeZoneRules`] for TZif data the parser rejects (unreachable for the
/// embedded, generated tables).
fn lookup(zone: &str) -> Result<(&'static str, &'static tz::TimeZone), TemporalError> {
    let (canonical, data) = jiff_tzdb::get(zone).ok_or_else(|| unknown_zone(zone))?;
    if let Some(tz) = ZONES
        .read()
        .expect("INVARIANT: no panics while holding the zone-cache lock")
        .get(canonical)
    {
        return Ok((canonical, tz));
    }
    let mut zones = ZONES
        .write()
        .expect("INVARIANT: no panics while holding the zone-cache lock");
    // Re-check under the write lock: another thread may have parsed it meanwhile.
    if let Some(tz) = zones.get(canonical) {
        return Ok((canonical, tz));
    }
    let parsed = tz::TimeZone::from_tz_data(data).map_err(|e| zone_rules(zone, &e))?;
    let leaked: &'static tz::TimeZone = Box::leak(Box::new(parsed));
    zones.insert(canonical, leaked);
    Ok((canonical, leaked))
}

/// The canonical id of `zone` (`"europe/stockholm"` → `"Europe/Stockholm"`), or an unknown-zone
/// error.
///
/// # Errors
/// [`TemporalError::UnknownTimeZone`] for an id absent from the database.
pub fn canonical_id(zone: &str) -> Result<&'static str, TemporalError> {
    jiff_tzdb::get(zone)
        .map(|(canonical, _)| canonical)
        .ok_or_else(|| unknown_zone(zone))
}

/// The typed error for a zone id absent from the embedded IANA database.
fn unknown_zone(zone: &str) -> TemporalError {
    TemporalError::UnknownTimeZone(zone.to_owned())
}

/// The typed error for zone data or an instant the zone rules cannot serve.
fn zone_rules(zone: &str, reason: &dyn std::fmt::Display) -> TemporalError {
    TemporalError::TimeZoneRules {
        zone: zone.to_owned(),
        reason: reason.to_string(),
    }
}

/// Localizes the UTC instant `unix_seconds` to `zone`: returns the zone's canonical id together
/// with the UTC offset (seconds east of UTC) in effect at that instant.
///
/// This is the whole of `java.time.ZonedDateTime.ofInstant(instant, zoneId)` as far as the value
/// model is concerned, and it is the operation the PackStream `DateTimeZoneId` decoder performs
/// (`rmp` #908): the wire form carries a zone id and no numeric offset, so the offset must come
/// from the zone rules at that instant. Returning the canonical id in the same call keeps a
/// wire-supplied value identical to the one the Cypher constructors build for the same instant
/// and zone (both normalise here), which is what makes the two compare equal and sort together —
/// `zone_id` is a tiebreaker in the Cypher ordering.
///
/// Canonicalisation is **case-only**. Link ids are separate entries in the embedded database and
/// are returned unchanged (`"US/Eastern"` stays `"US/Eastern"`, as in `java.time.ZoneId.of`), so
/// a decoded value re-encodes to the bytes it arrived as.
///
/// # Errors
/// [`TemporalError::UnknownTimeZone`] for an unknown zone id, or
/// [`TemporalError::TimeZoneRules`] if the instant falls outside the range the zone rules cover
/// (unreachable for values the calendar engine can represent).
pub fn localize_instant(
    zone: &str,
    unix_seconds: i64,
) -> Result<(&'static str, i32), TemporalError> {
    let (canonical, tz) = lookup(zone)?;
    let offset = tz
        .find_local_time_type(unix_seconds)
        .map(tz::LocalTimeType::ut_offset)
        .map_err(|e| zone_rules(zone, &e))?;
    Ok((canonical, offset))
}

/// The UTC offset (seconds east of UTC) `zone` is in at the instant `unix_seconds`.
///
/// # Errors
/// [`TemporalError::UnknownTimeZone`] for an unknown zone id, or
/// [`TemporalError::TimeZoneRules`] if the instant falls outside the range the zone rules cover
/// (unreachable for values the calendar engine can represent).
pub fn offset_at_instant(zone: &str, unix_seconds: i64) -> Result<i32, TemporalError> {
    localize_instant(zone, unix_seconds).map(|(_, offset)| offset)
}

/// Probe distance for bracketing the DST transition (if any) nearest to a local time. It must
/// exceed the largest representable |offset| (18 h) plus the largest gap in the IANA database
/// (24 h — Pacific/Apia skipping 2011-12-30), and stay shorter than the spacing between
/// consecutive transitions, so that the two probes land on opposite sides of at most one
/// transition.
const PROBE_SECONDS: i64 = 2 * 86_400;

/// Resolves the UTC offset for the local wall-clock value `local` in the named `zone`,
/// applying the gap/overlap rules in the module docs. Returns the (gap-adjusted) local value
/// together with the resolved offset.
///
/// `preferred` is the offset to keep when the local time is ambiguous (overlap) — pass the
/// offset the value already carried when re-deriving it (component overrides, truncation), or
/// `None` to take java.time's default (the offset before the transition).
///
/// # Errors
/// [`TemporalError::UnknownTimeZone`] for an unknown zone id, or
/// [`TemporalError::TimeZoneRules`] for an instant outside the zone rules.
pub fn resolve_local(
    zone: &str,
    local: &LocalDateTime,
    preferred: Option<i32>,
) -> Result<(LocalDateTime, i32), TemporalError> {
    let (_, tz) = lookup(zone)?;
    let offset_at = |instant: i64| -> Result<i32, TemporalError> {
        tz.find_local_time_type(instant)
            .map(tz::LocalTimeType::ut_offset)
            .map_err(|e| zone_rules(zone, &e))
    };
    let wall = local.epoch_seconds;
    // The offsets in effect strictly before and strictly after any transition near `wall`.
    let before = offset_at(wall.saturating_sub(PROBE_SECONDS))?;
    let after = offset_at(wall.saturating_add(PROBE_SECONDS))?;
    // A candidate offset is valid when interpreting the wall clock with it round-trips.
    let valid = |offset: i32| -> Result<bool, TemporalError> {
        Ok(offset_at(wall - i64::from(offset))? == offset)
    };
    let before_valid = valid(before)?;
    let after_valid = valid(after)?;
    match (before_valid, after_valid) {
        // Overlap: both readings exist; keep the caller's offset when it is one of them,
        // otherwise the pre-transition ("earlier") offset.
        (true, true) if before != after => {
            let chosen = match preferred {
                Some(p) if p == before || p == after => p,
                _ => before,
            };
            Ok((*local, chosen))
        }
        (true, _) => Ok((*local, before)),
        (false, true) => Ok((*local, after)),
        // Gap: the local time was skipped; move it later by the gap length and take the
        // post-transition offset.
        (false, false) => {
            let gap = i64::from(after) - i64::from(before);
            let adjusted = LocalDateTime {
                epoch_seconds: wall.saturating_add(gap),
                nanos: local.nanos,
            };
            Ok((adjusted, after))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::temporal_calc::parse_local_date_time;

    fn local(s: &str) -> LocalDateTime {
        parse_local_date_time(s).expect("test literal parses")
    }

    #[test]
    fn stockholm_winter_and_summer_1984() {
        // DST in Sweden, 1984: March 25 to September 30 (pinned by Temporal1 scenario [10]).
        let (l, off) = resolve_local("Europe/Stockholm", &local("1984-10-11T12:31:14"), None)
            .expect("resolves");
        assert_eq!((l, off), (local("1984-10-11T12:31:14"), 3600));
        let (l, off) = resolve_local("Europe/Stockholm", &local("1984-07-20T12:31:14"), None)
            .expect("resolves");
        assert_eq!((l, off), (local("1984-07-20T12:31:14"), 7200));
    }

    #[test]
    fn stockholm_historical_lmt_1818() {
        // Pinned by Temporal2 scenario [6]: 1818 Stockholm resolves to the pre-standard-time
        // local mean time +00:53:28 (Europe/Stockholm links to Europe/Berlin since tzdata 2022b).
        let (_, off) = resolve_local("Europe/Stockholm", &local("1818-07-21T21:40:32"), None)
            .expect("resolves");
        assert_eq!(off, 53 * 60 + 28);
    }

    #[test]
    fn honolulu_is_fixed_offset() {
        // Pacific/Honolulu has been -10:00 with no DST since 1947 (Temporal3 scenario [8]).
        let (_, off) = resolve_local("Pacific/Honolulu", &local("1984-10-28T10:10:10"), None)
            .expect("resolves");
        assert_eq!(off, -36_000);
        assert_eq!(
            offset_at_instant("Pacific/Honolulu", 469_020_674).expect("resolves"),
            -36_000
        );
    }

    #[test]
    fn dst_gap_moves_the_local_time_later() {
        // Stockholm springs forward 2017-03-26 02:00 -> 03:00 (+01:00 -> +02:00): 02:30 does
        // not exist and is adjusted later by the 1 h gap, per java.time.ZonedDateTime.ofLocal.
        let (l, off) =
            resolve_local("Europe/Stockholm", &local("2017-03-26T02:30"), None).expect("resolves");
        assert_eq!((l, off), (local("2017-03-26T03:30"), 7200));
    }

    #[test]
    fn dst_overlap_prefers_the_carried_offset_then_the_earlier_one() {
        // Stockholm falls back 2017-10-29 03:00 -> 02:00 (+02:00 -> +01:00): 02:30 happens
        // twice. Default: the offset before the transition (+02:00).
        let ambiguous = local("2017-10-29T02:30");
        let (l, off) = resolve_local("Europe/Stockholm", &ambiguous, None).expect("resolves");
        assert_eq!((l, off), (ambiguous, 7200));
        // A valid preferred offset is kept; an invalid one falls back to the default.
        let (_, off) = resolve_local("Europe/Stockholm", &ambiguous, Some(3600)).expect("ok");
        assert_eq!(off, 3600);
        let (_, off) = resolve_local("Europe/Stockholm", &ambiguous, Some(0)).expect("ok");
        assert_eq!(off, 7200);
    }

    #[test]
    fn unambiguous_times_around_the_fall_back_transition() {
        // Pinned indirectly by Temporal10 scenario [8]: midnight is still summer time,
        // 04:00 is already winter time.
        let (_, off) =
            resolve_local("Europe/Stockholm", &local("2017-10-29T00:00"), None).expect("resolves");
        assert_eq!(off, 7200);
        let (_, off) =
            resolve_local("Europe/Stockholm", &local("2017-10-29T04:00"), None).expect("resolves");
        assert_eq!(off, 3600);
    }

    #[test]
    fn unknown_zone_is_a_typed_error() {
        let err = resolve_local("Mars/Olympus_Mons", &local("2017-10-29T00:00"), None)
            .expect_err("unknown zone");
        assert!(
            matches!(err, TemporalError::UnknownTimeZone(ref z) if z == "Mars/Olympus_Mons"),
            "{err:?}"
        );
        // The rendered message is the contract the Cypher evaluator surfaces verbatim as a
        // `TypeError` context, so it is pinned here.
        assert_eq!(err.to_string(), "unknown time zone id `Mars/Olympus_Mons`");
        assert!(canonical_id("Europe/Stockholm").is_ok());
    }

    #[test]
    fn whole_day_gap_pacific_apia() {
        // Pacific/Apia skipped 2011-12-30 entirely (-10:00 DST -> +14:00 DST): the worst-case
        // gap the probe distance must bracket.
        let (l, off) =
            resolve_local("Pacific/Apia", &local("2011-12-30T12:00"), None).expect("resolves");
        assert_eq!((l, off), (local("2011-12-31T12:00"), 14 * 3600));
    }

    #[test]
    fn canonical_id_corrects_case() {
        assert_eq!(
            canonical_id("europe/stockholm").expect("known zone"),
            "Europe/Stockholm"
        );
        assert!(canonical_id("Mars/Olympus_Mons").is_err());
    }

    #[test]
    fn localize_instant_normalises_the_zone_id_by_case_only() {
        // Both ingress paths (Cypher constructors and the PackStream `DateTimeZoneId` decoder)
        // normalise through this one lookup, so an id differing only in case lands on the same
        // string and the two values stay identical (`rmp` #908).
        let (canonical, offset) =
            localize_instant("europe/paris", 4_500).expect("known zone, valid instant");
        assert_eq!(canonical, "Europe/Paris");
        assert_eq!(offset, 3600);
        // Link/alias ids are their own entries in the embedded database and are preserved
        // verbatim — matching `java.time.ZoneId.of("US/Eastern").getId()`. Pinned because it is
        // what keeps wire bytes round-tripping unchanged.
        assert_eq!(
            localize_instant("US/Eastern", 0).expect("known alias").0,
            "US/Eastern"
        );
        assert!(matches!(
            localize_instant("Mars/Olympus_Mons", 0),
            Err(TemporalError::UnknownTimeZone(_))
        ));
    }

    #[test]
    fn offset_at_instant_tracks_the_dst_transition() {
        // Europe/Paris springs forward 2017-03-26 01:00 UTC (+01:00 -> +02:00). `offset_at_instant`
        // is the *instant* direction used by the PackStream `DateTimeZoneId` decoder (`rmp` #908):
        // one second before the transition it is still winter time, at the transition it is summer.
        let spring_forward = 1_490_490_000; // 2017-03-26T01:00:00Z
        assert_eq!(
            offset_at_instant("Europe/Paris", spring_forward - 1).expect("resolves"),
            3600
        );
        assert_eq!(
            offset_at_instant("Europe/Paris", spring_forward).expect("resolves"),
            7200
        );
    }
}
