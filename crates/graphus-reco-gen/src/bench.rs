//! Pure, hermetic helpers for the `reco_bench` concurrent read driver: latency-percentile
//! summarisation, the `/proc/<pid>` field parsers the server-resource sampler relies on, the
//! concurrency-ladder CSV parser, and the read-battery family index lookup.
//!
//! Everything here is a **pure function of its inputs** — no sockets, no threads, no clock, no
//! `/proc` access — so it is unit-testable without a running server (the driver orchestration that
//! actually samples `/proc` and drives the Bolt connections lives in the `reco_bench` binary). The
//! `/proc` *format* parsers live here (and are tested against synthetic fixtures) precisely because
//! their edge cases — a `(comm)` field that itself contains spaces and parentheses, the `kB` unit
//! suffix, a permission-restricted `io` file — are exactly the kind of thing a hermetic test should
//! pin, independent of what any particular kernel reports at run time.

#![forbid(unsafe_code)]

use crate::queries::{QuerySpec, READ_BATTERY};

/// Per-mille rank of the 50th percentile (median), for [`percentile_ns`] / [`summarize`].
pub const P50: u32 = 500;
/// Per-mille rank of the 90th percentile.
pub const P90: u32 = 900;
/// Per-mille rank of the 99th percentile.
pub const P99: u32 = 990;
/// Per-mille rank of the 99.9th percentile.
pub const P999: u32 = 999;
/// Per-mille rank of the maximum (100th percentile).
pub const MAX: u32 = 1000;

/// A summary of a latency distribution: the percentiles the report prints, in the same unit as the
/// input samples (the driver feeds nanoseconds).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Pcts {
    /// 50th-percentile (median) latency.
    pub p50: u64,
    /// 90th-percentile latency.
    pub p90: u64,
    /// 99th-percentile latency.
    pub p99: u64,
    /// 99.9th-percentile latency.
    pub p999: u64,
    /// Maximum observed latency.
    pub max: u64,
}

/// The **nearest-rank** percentile of a **pre-sorted ascending** slice, computed in pure integer
/// arithmetic so it is free of the floating-point rounding hazards a `ceil(q * n)` formulation
/// suffers at the exact percentile boundaries (e.g. `0.9 * 100` landing at `90.00000000000001`).
///
/// `permille` is the rank in parts-per-thousand (`500` == p50, `990` == p99, `1000` == max); values
/// above `1000` are clamped to the maximum. The rank is `ceil(permille * n / 1000)` (1-based),
/// mapped to a 0-based index and clamped into range. An empty slice returns `0`.
///
/// The caller MUST pass a slice already sorted ascending (the driver sorts once per family, then
/// reads several percentiles off the same sorted buffer).
#[must_use]
pub fn percentile_ns(sorted: &[u64], permille: u32) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let n = sorted.len() as u64;
    let permille = u64::from(permille.min(1000));
    if permille == 0 {
        return sorted[0];
    }
    // Nearest-rank: rank = ceil(permille * n / 1000), 1-based. `permille <= 1000` and `n` fits a
    // `u64`, so `permille * n` cannot overflow for any realistic sample count.
    let rank = (permille * n).div_ceil(1000);
    let idx = (rank.max(1) - 1).min(n - 1) as usize;
    sorted[idx]
}

/// Summarises a **pre-sorted ascending** latency slice into the report's five percentiles.
#[must_use]
pub fn summarize(sorted: &[u64]) -> Pcts {
    Pcts {
        p50: percentile_ns(sorted, P50),
        p90: percentile_ns(sorted, P90),
        p99: percentile_ns(sorted, P99),
        p999: percentile_ns(sorted, P999),
        max: percentile_ns(sorted, MAX),
    }
}

/// Converts a nanosecond count to milliseconds as an `f64` (the unit the evidence report and the
/// human table print latencies in).
#[must_use]
pub fn ns_to_ms(ns: u64) -> f64 {
    ns as f64 / 1_000_000.0
}

/// Parses a concurrency-ladder CSV (`"1,2,4,8"`) into the list of rung sizes.
///
/// Whitespace around each entry is trimmed. Every entry must be a positive integer; an empty entry
/// (e.g. the `""` in `"1,,2"`), a zero, or a non-numeric token is rejected with a clear message, as
/// is an empty ladder.
///
/// # Errors
/// Returns a human-readable error string describing the first offending entry.
pub fn parse_ladder(csv: &str) -> Result<Vec<usize>, String> {
    let mut out = Vec::new();
    for (i, part) in csv.split(',').enumerate() {
        let token = part.trim();
        if token.is_empty() {
            return Err(format!(
                "ladder entry {} is empty (in {csv:?}); expected positive integers like 1,2,4,8",
                i + 1
            ));
        }
        let n: usize = token
            .parse()
            .map_err(|_| format!("ladder entry {token:?} is not a positive integer"))?;
        if n == 0 {
            return Err(format!("ladder entry {token:?} must be > 0"));
        }
        out.push(n);
    }
    if out.is_empty() {
        return Err("ladder is empty; expected positive integers like 1,2,4,8".to_string());
    }
    Ok(out)
}

/// Extracts `utime` (field 14) and `stime` (field 15), in clock ticks, from a `/proc/<pid>/stat`
/// (or `/proc/<pid>/task/<tid>/stat`) line.
///
/// The awkward part of the `stat` format is field 2, `(comm)`: the executable name, which may itself
/// contain spaces **and** parentheses (e.g. `(cat (foo) bar)`), so a naive whitespace split
/// mis-aligns every later field. The robust rule — used by the kernel's own tooling — is to split
/// **after the last `)`** in the line; the remaining whitespace-separated fields then begin at
/// field 3 (`state`), so `utime`/`stime` sit at offsets 11/12 in that tail.
///
/// Returns `None` if the line has no `)` or too few trailing fields to reach `stime`.
#[must_use]
pub fn parse_stat_utime_stime(stat: &str) -> Option<(u64, u64)> {
    let close = stat.rfind(')')?;
    let tail = stat.get(close + 1..)?;
    let fields: Vec<&str> = tail.split_whitespace().collect();
    // The tail begins at field 3 (state): field 14 (utime) -> index 11, field 15 (stime) -> index 12.
    let utime = fields.get(11)?.parse().ok()?;
    let stime = fields.get(12)?.parse().ok()?;
    Some((utime, stime))
}

/// Extracts a `VmXxx` line's value from a `/proc/<pid>/status` blob, converting the reported **kB**
/// to bytes. `key` is the line label without its colon, e.g. `"VmRSS"` or `"VmHWM"`.
///
/// Returns `None` if the key is absent or its value is unparseable.
#[must_use]
pub fn parse_status_kb_bytes(status: &str, key: &str) -> Option<u64> {
    let needle = format!("{key}:");
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(&needle) {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

/// Extracts a named byte counter (e.g. `read_bytes` or `rchar`) from a `/proc/<pid>/io` blob.
///
/// `/proc/<pid>/io` may be permission-restricted (unreadable) for a process the driver does not own;
/// that is handled by the caller (an unreadable file is simply treated as unavailable). This parser
/// only concerns itself with the well-formed contents, returning `None` if the key is absent or
/// unparseable.
#[must_use]
pub fn parse_proc_io_bytes(io: &str, key: &str) -> Option<u64> {
    let needle = format!("{key}:");
    for line in io.lines() {
        if let Some(rest) = line.strip_prefix(&needle) {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// The verdict of an index-seek PROFILE gate (`rmp` #746/#755): a query genuinely uses its declared
/// index **at runtime** iff (a) the expected index operator is present in the plan AND (b) the measured
/// `dbHits` are a **small fraction** of the whole-store scan's.
///
/// Both halves are load-bearing, and (b) is why the operator alone is not enough. The off-thread reader
/// pool declines every index seek and falls back to a full scan (`rmp` #755), yet the *planner* still
/// picked the index — so the plan reports `NodeTextIndexSeek` / `RelIndexRangeSeek` while the execution
/// reads the whole store. Only the measured `dbHits` tell a genuine seek from a mislabelled scan. This
/// is the exact defect this task exists to prevent an example from hiding behind a green tick.
///
/// `seek_hits` is the measured `dbHits` of the (allegedly) index-backed run; `scan_hits` is the measured
/// `dbHits` of the same shape executed as a full scan (either the identical query declined to the reader
/// pool, or a forced label/type scan). `factor` is the margin the seek must beat: the seek must read
/// **strictly less than `scan_hits / factor`** (e.g. `factor = 4` ⇒ the seek reads under a quarter of the
/// scan). A larger `factor` is a stricter gate.
///
/// Returns `Ok(())` when the index is genuinely used, or `Err(reason)` describing why the gate FAILS —
/// the operator was absent (the planner did not pick the index at all), or the seek read as much of the
/// store as the scan (the `rmp` #755 decline: a seek in name only).
///
/// # Errors
/// A human-readable reason when the gate fails: a missing operator or a non-selective `dbHits`.
pub fn index_seek_verdict(
    op_present: bool,
    seek_hits: i64,
    scan_hits: i64,
    factor: i64,
) -> Result<(), String> {
    if !op_present {
        return Err(
            "the expected index operator is absent from the plan — the planner did not pick the \
             index (a scan, or a different plan)"
                .to_owned(),
        );
    }
    if scan_hits <= 0 {
        return Err(format!(
            "the scan reference measured no dbHits ({scan_hits}); cannot prove the seek is a fraction \
             of it (is the scan query really a full scan?)"
        ));
    }
    // Strictly less than scan_hits / factor, computed WITHOUT division so a small scan reference cannot
    // round the threshold to zero: `seek_hits * factor < scan_hits`.
    if seek_hits.saturating_mul(factor.max(1)) < scan_hits {
        Ok(())
    } else {
        Err(format!(
            "the operator is present but the measured dbHits are NOT a small fraction of the scan's: \
             seek={seek_hits}, scan={scan_hits} (need seek × {factor} < scan). This is the rmp #755 \
             decline — a seek reported in the plan but a full scan at runtime."
        ))
    }
}

/// The index of a read-battery [`QuerySpec`] within [`READ_BATTERY`], used to bucket per-family
/// latencies. `spec` is one of the entries [`crate::queries::pick`] returns; the lookup is by the
/// family's unique `name` (the report key), which is stable regardless of const-promotion (a pointer
/// comparison would be unsound here: [`READ_BATTERY`] is a `const &[QuerySpec]`, so the compiler may
/// materialise distinct copies of the array, giving a `pick` result and this iteration different
/// addresses). Family names are unique — asserted by `queries::tests::battery_is_nonempty_and_weighted`
/// — so exactly one entry matches. Falls back to `0` for a foreign spec (never happens for a `pick`
/// result).
#[must_use]
pub fn family_index(spec: &QuerySpec) -> usize {
    READ_BATTERY
        .iter()
        .position(|q| q.name == spec.name)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SplitMix64;
    use crate::queries::pick;

    #[test]
    fn percentiles_on_1_to_100_are_exact() {
        let v: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile_ns(&v, P50), 50);
        assert_eq!(percentile_ns(&v, P90), 90);
        assert_eq!(percentile_ns(&v, P99), 99);
        assert_eq!(percentile_ns(&v, P999), 100);
        assert_eq!(percentile_ns(&v, MAX), 100);

        let s = summarize(&v);
        assert_eq!(
            s,
            Pcts {
                p50: 50,
                p90: 90,
                p99: 99,
                p999: 100,
                max: 100,
            }
        );
    }

    #[test]
    fn percentiles_handle_small_n_and_empty() {
        // Empty distribution -> zeros (a rung that recorded no successful latencies).
        assert_eq!(percentile_ns(&[], P50), 0);
        assert_eq!(percentile_ns(&[], MAX), 0);
        assert_eq!(summarize(&[]), Pcts::default());

        // Single sample -> every percentile is that sample.
        assert_eq!(percentile_ns(&[42], P50), 42);
        assert_eq!(percentile_ns(&[42], P99), 42);
        assert_eq!(percentile_ns(&[42], MAX), 42);

        // Two samples: nearest-rank puts p50 on the lower, p99/max on the upper.
        let two = [10u64, 20];
        assert_eq!(percentile_ns(&two, P50), 10);
        assert_eq!(percentile_ns(&two, P99), 20);
        assert_eq!(percentile_ns(&two, MAX), 20);

        // A permille above 1000 clamps to the maximum rather than indexing out of range.
        assert_eq!(percentile_ns(&two, 5000), 20);
    }

    #[test]
    fn stat_parse_survives_parens_and_spaces_in_comm() {
        // A synthetic stat line whose `(comm)` contains both spaces and nested parentheses. Post-`)`
        // fields (0-based): 0=state .. 11=utime .. 12=stime.
        let line = "4242 (cat (foo) bar) S 1 1 0 0 0 0 0 0 0 0 1500 300 7 8 9";
        let (utime, stime) = parse_stat_utime_stime(line).expect("well-formed stat line");
        assert_eq!(utime, 1500);
        assert_eq!(stime, 300);
    }

    #[test]
    fn stat_parse_rejects_malformed() {
        assert_eq!(parse_stat_utime_stime("no parens here"), None);
        // A `)` but too few trailing fields to reach stime.
        assert_eq!(parse_stat_utime_stime("1 (x) S 1 1"), None);
    }

    #[test]
    fn status_parse_extracts_kb_as_bytes() {
        let status = "Name:\tgraphus\nVmHWM:\t  204800 kB\nVmRSS:\t   102400 kB\nThreads:\t9\n";
        assert_eq!(parse_status_kb_bytes(status, "VmHWM"), Some(204_800 * 1024));
        assert_eq!(parse_status_kb_bytes(status, "VmRSS"), Some(102_400 * 1024));
        assert_eq!(parse_status_kb_bytes(status, "VmNope"), None);
    }

    #[test]
    fn io_parse_reads_named_counters() {
        let io = "rchar: 123\nwchar: 9\nsyscr: 4\nread_bytes: 4096\nwrite_bytes: 0\n";
        assert_eq!(parse_proc_io_bytes(io, "read_bytes"), Some(4096));
        assert_eq!(parse_proc_io_bytes(io, "rchar"), Some(123));
        assert_eq!(parse_proc_io_bytes(io, "nope"), None);
    }

    #[test]
    fn ladder_parse_accepts_valid_and_trims() {
        assert_eq!(parse_ladder("1,2,4,8").unwrap(), vec![1, 2, 4, 8]);
        assert_eq!(parse_ladder(" 1 , 2 ,16 ").unwrap(), vec![1, 2, 16]);
        assert_eq!(parse_ladder("32").unwrap(), vec![32]);
    }

    #[test]
    fn ladder_parse_rejects_empty_zero_and_garbage() {
        assert!(parse_ladder("").is_err());
        assert!(parse_ladder("   ").is_err());
        assert!(parse_ladder("1,,2").is_err());
        assert!(parse_ladder("1,0,2").is_err());
        assert!(parse_ladder("1,x").is_err());
    }

    #[test]
    fn weighted_mix_draws_every_family() {
        // Deterministic RNG => a stable statistical assertion: over many draws every read-battery
        // family is selected at least once (the weighted `pick` covers the whole battery).
        let mut rng = SplitMix64::new(0xC0FF_EE00_1234_5678);
        let mut seen = vec![false; READ_BATTERY.len()];
        for _ in 0..100_000 {
            seen[family_index(pick(rng.next_u64()))] = true;
        }
        assert!(
            seen.iter().all(|&s| s),
            "every read-battery family must be drawn at least once: {seen:?}"
        );
    }

    #[test]
    fn family_index_round_trips_every_battery_entry() {
        for (i, spec) in READ_BATTERY.iter().enumerate() {
            assert_eq!(family_index(spec), i, "family {} index", spec.name);
        }
    }

    #[test]
    fn index_seek_verdict_passes_a_genuine_seek() {
        // MEASURED shapes, all against a real index-free scan reference.
        // TEXT trigram seek on an isolated server: 23 dbHits vs an 801-dbHit index-free scan.
        assert!(index_seek_verdict(true, 23, 801, 4).is_ok());
        // rel RANGE over the 10% recent window: 2907 dbHits vs a full LIKE type scan.
        assert!(index_seek_verdict(true, 2907, 24500, 4).is_ok());
        // VECTOR ANN inline: 50 dbHits vs an 800-dbHit forced Product scan.
        assert!(index_seek_verdict(true, 50, 800, 4).is_ok());
    }

    #[test]
    fn index_seek_verdict_fails_the_rmp755_decline() {
        // The exact defect the gate exists to catch: the operator is present (the planner picked the
        // index) but the runtime dbHits are a full scan's — MEASURED in the product-recommendations
        // example, where a bulk-imported database reports the TEXT index `ONLINE` yet every `CONTAINS`
        // reads the whole label (801 dbHits == the index-free scan).
        let v = index_seek_verdict(true, 601, 601, 4);
        assert!(v.is_err(), "a seek that read the whole store must FAIL");
        assert!(v.unwrap_err().contains("#755"));
        // Even a modest over-read fails the 4× margin (seek read half the store).
        assert!(index_seek_verdict(true, 300, 601, 4).is_err());
    }

    #[test]
    fn index_seek_verdict_fails_a_missing_operator() {
        // The planner did not pick the index at all (a scan, or an unrelated plan): FAIL.
        let v = index_seek_verdict(false, 3, 601, 4);
        assert!(v.is_err());
        assert!(v.unwrap_err().contains("absent"));
    }

    #[test]
    fn index_seek_verdict_rejects_a_degenerate_scan_reference() {
        // If the "scan" reference read nothing, we cannot prove selectivity — fail closed rather than
        // pass a gate on a meaningless comparison.
        assert!(index_seek_verdict(true, 0, 0, 4).is_err());
    }
}
