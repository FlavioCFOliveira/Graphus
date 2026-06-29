//! D1 PROTOCOL RE-AUDIT (sprint-42 task #485) — PackStream **structure-recursion depth-guard bypass**.
//!
//! FINDING (CRITICAL, CWE-674 Uncontrolled Recursion → stack-overflow process abort): the
//! `MAX_DECODE_DEPTH` (256) guard that protects the recursive PackStream decoder is enforced **only**
//! on the list (`enter_nested` in `unpack_value`'s list arm) and map (map arm / `unpack_properties`)
//! recursion paths. It is **NOT** enforced on the one *other* recursive path:
//!
//! ```text
//!   unpack_value (struct marker)
//!     └─> unpack_structured_value           (packstream.rs ~1054 — NO enter_nested)
//!           └─> POINT_2D / POINT_3D arm      (~1132 — reads srid, then coordinate fields)
//!                 └─> read_float_field       (~1458 — NO enter_nested)
//!                       └─> unpack_value      (~1459 — recurses, depth NEVER incremented)
//! ```
//!
//! Because a `Point2D` (tag `0x58`) / `Point3D` (tag `0x59`) coordinate field is decoded by the FULL
//! `unpack_value`, a value whose `x` coordinate is itself another `Point2D` recurses through this
//! cycle **without ever calling `enter_nested`**. The `depth` counter stays frozen, so
//! `MAX_DECODE_DEPTH` is never hit. A modest, well-formed-looking payload of nested points
//! (`B3 58 00` repeated — three bytes per level) recurses arbitrarily deep and overflows the thread
//! stack, which Rust handles by `abort()` — taking down the WHOLE server process (every connection,
//! every database). This is far below the 64 MiB framing cap and the 512 KiB prealloc ceiling, so
//! neither of those hardenings helps.
//!
//! REACHABILITY: `Request::decode` (the server's message decoder) routes every HELLO/RUN/BEGIN field
//! through `read_fields` → `unpack_value`. HELLO is processed **pre-authentication**, so an
//! UNAUTHENTICATED remote peer can crash the server with one ~few-KB packet (`Test C`).
//!
//! Why the existing suite misses it: every depth test in `tests/security_packstream.rs`
//! (`deeply_nested_lists_are_rejected_not_stack_overflowed`, `deeply_nested_maps_are_rejected`,
//! `deeply_nested_structural_list_via_bolt_value_is_rejected`) nests `0x91` (TINY_LIST) / `0xA1`
//! (TINY_MAP) — exactly the two paths that DO call `enter_nested`. None exercises the struct/Point
//! coordinate path, the single path that bypasses the guard.
//!
//! These tests assert the SECURE behaviour (a deep nested-point chain must be rejected with a depth
//! error, symmetric with deep lists). They therefore FAIL on current HEAD, which is the proof of the
//! defect. After a fix (wrap the struct decode in `enter_nested`/`leave_nested`), they pass.

use graphus_bolt::packstream::MAX_DECODE_DEPTH;
use graphus_bolt::{BoltError, Request, Unpacker, unpack_bolt_value, unpack_value};
use graphus_core::Value;

// ---- wire builders ----------------------------------------------------------------------------

/// One level of a nested `Point2D` chain: `B3 58 00` = TINY_STRUCT(3 fields), tag `POINT_2D`
/// (`0x58`), then `srid` as the tiny-int `0`. The next bytes are the `x` coordinate — another level.
const POINT2D_LEVEL: [u8; 3] = [0xB3, 0x58, 0x00];

/// One level of a nested `Point3D` chain: `B4 59 00` = TINY_STRUCT(4 fields), tag `POINT_3D`
/// (`0x59`), then `srid` = `0`. The next bytes are the `x` coordinate — another level.
const POINT3D_LEVEL: [u8; 3] = [0xB4, 0x59, 0x00];

/// `depth` nested `Point2D` structures, each one supplying the next as its `x` coordinate field.
/// Decoding this recurses `depth`-deep through `unpack_value → unpack_structured_value →
/// read_float_field → unpack_value`, none of which increments `MAX_DECODE_DEPTH`.
fn nested_point2d(depth: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(depth * POINT2D_LEVEL.len());
    for _ in 0..depth {
        v.extend_from_slice(&POINT2D_LEVEL);
    }
    v
}

/// `depth` nested `Point3D` structures (same idea via the `x` coordinate field).
fn nested_point3d(depth: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(depth * POINT3D_LEVEL.len());
    for _ in 0..depth {
        v.extend_from_slice(&POINT3D_LEVEL);
    }
    v
}

/// `depth` nested single-element TINY_LISTs (`0x91`) then a NULL — the CONTROL shape used by the
/// existing suite. This path DOES go through `enter_nested`, so it must be depth-rejected.
fn nested_list(depth: usize) -> Vec<u8> {
    let mut v = vec![0x91u8; depth];
    v.push(0xC0); // innermost NULL
    v
}

/// Runs `f` on a thread with a deliberately *large* (512 MiB) stack and returns its result. Tests A
/// and C decode payloads nested far past `MAX_DECODE_DEPTH` to observe whether the decoder rejects at
/// the limit (secure) or recurses all the way (bypassed). On a generous stack the recursion does not
/// abort the test process, so we can inspect the returned error deterministically regardless of build
/// profile. (The actual stack-overflow ABORT is demonstrated separately, in `Test B`, on a
/// realistic 2 MiB stack via a subprocess so it cannot crash this harness.)
fn decode_on_big_stack<F, T>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    std::thread::Builder::new()
        .stack_size(512 * 1024 * 1024)
        .spawn(f)
        .expect("spawn big-stack decode thread")
        .join()
        .expect("big-stack decode thread must not panic/overflow at this depth")
}

// ---- Test A: the raw codec bypass -------------------------------------------------------------

#[test]
fn point2d_coordinate_recursion_bypasses_depth_guard() {
    // 4000 nested Point2D structures (12_000 bytes) — ~15.6x past MAX_DECODE_DEPTH (256). If the
    // depth guard covered the struct/coordinate path, this would be rejected the moment depth crosses
    // 256, exactly like a deep list. On HEAD it instead recurses all 4000 levels and only fails at
    // end-of-input, proving the guard is bypassed.
    let depth = 4000;
    assert!(depth > MAX_DECODE_DEPTH, "test must exceed the depth limit");
    let bytes = nested_point2d(depth);

    let err: BoltError = decode_on_big_stack(move || {
        let mut u = Unpacker::new(&bytes);
        unpack_value(&mut u).expect_err("a 4000-deep nested Point2D must not decode successfully")
    });

    assert!(
        format!("{err}").contains("depth"),
        "SECURITY (CWE-674): a Point2D coordinate chain {depth} levels deep was NOT rejected by the \
         MAX_DECODE_DEPTH ({MAX_DECODE_DEPTH}) guard — it recursed past the limit (error was: {err}). \
         The guard is enforced for lists/maps (enter_nested) but the struct path \
         unpack_value→unpack_structured_value→read_float_field→unpack_value never increments depth. \
         At ~3 bytes/level this overflows the session stack and aborts the whole process."
    );
}

#[test]
fn point3d_coordinate_recursion_bypasses_depth_guard() {
    // Same bypass via Point3D (tag 0x59): the x coordinate is decoded by the full unpack_value.
    let depth = 4000;
    let bytes = nested_point3d(depth);

    let err: BoltError = decode_on_big_stack(move || {
        let mut u = Unpacker::new(&bytes);
        unpack_value(&mut u).expect_err("a 4000-deep nested Point3D must not decode successfully")
    });

    assert!(
        format!("{err}").contains("depth"),
        "SECURITY (CWE-674): a Point3D coordinate chain {depth} levels deep bypassed the \
         MAX_DECODE_DEPTH guard (error was: {err})."
    );
}

#[test]
fn nested_list_is_depth_guarded_control() {
    // CONTROL: the SAME depth via the list path (which DOES call enter_nested) is correctly rejected
    // with a depth error. This isolates the defect to the struct/coordinate path: the asymmetry
    // between this (passes) and the Point tests above (fail on HEAD) IS the finding.
    let depth = 4000;
    let bytes = nested_list(depth);
    let err: BoltError = decode_on_big_stack(move || {
        let mut u = Unpacker::new(&bytes);
        unpack_value(&mut u).expect_err("a 4000-deep nested list must be rejected")
    });
    assert!(
        format!("{err}").contains("depth"),
        "control: a deep nested list must be rejected by the depth guard, got: {err}"
    );
}

#[test]
fn point_recursion_also_bypasses_the_structural_decoder() {
    // The RECORD-cell decoder unpack_bolt_value defers non-Node/Rel/Path struct tags (incl. Point) to
    // unpack_value, so it inherits the same bypass. The existing
    // `deeply_nested_structural_list_via_bolt_value_is_rejected` test only covers the list path here
    // too; the Point path is unguarded.
    let depth = 4000;
    let bytes = nested_point2d(depth);
    let err: BoltError = decode_on_big_stack(move || {
        let mut u = Unpacker::new(&bytes);
        unpack_bolt_value(&mut u)
            .expect_err("a 4000-deep nested Point2D must not decode via bolt_value")
    });
    assert!(
        format!("{err}").contains("depth"),
        "SECURITY (CWE-674): unpack_bolt_value also bypasses the depth guard on the Point path \
         (error was: {err})."
    );
}

// ---- Test C: pre-authentication reachability through the real message decoder ------------------

#[test]
fn pre_auth_hello_extra_nested_point_bypasses_depth_guard() {
    // The exact pre-auth vector. A HELLO message carries one `extra` map; the server decodes it with
    // `Request::decode` → read_fields → unpack_value BEFORE any authentication. We embed the nested
    // Point2D chain as a single map value, so a malformed HELLO from an UNAUTHENTICATED peer drives
    // the unbounded recursion.
    //
    // Wire: B1 01            -> TINY_STRUCT(1 field), opcode HELLO (0x01)
    //       A1               -> TINY_MAP(1 entry)
    //       81 61            -> TINY_STRING "a"  (the key)
    //       <nested Point2D> -> the value (the recursion)
    let depth = 4000;
    let mut payload = vec![0xB1, 0x01, 0xA1, 0x81, 0x61];
    payload.extend_from_slice(&nested_point2d(depth));

    let err: BoltError = decode_on_big_stack(move || {
        Request::decode(&payload)
            .expect_err("a HELLO carrying a 4000-deep nested Point2D must not decode successfully")
    });

    assert!(
        format!("{err}").contains("depth"),
        "SECURITY (CWE-674, pre-auth): a HELLO whose `extra` map carries a {depth}-level nested \
         Point2D chain bypassed the MAX_DECODE_DEPTH guard via Request::decode (error was: {err}). \
         This decode runs before authentication, so an unauthenticated remote peer can drive \
         unbounded recursion and crash the whole server with one small packet."
    );
}

// ---- Test C': a legitimate single Point still decodes (no false positive after a fix) ----------

#[test]
fn a_single_well_formed_point_still_decodes() {
    // Guards against an over-broad fix: one real Point2D (srid 7203 = cartesian-2d, x=1.0, y=2.0)
    // must still decode cleanly. A correct fix adds exactly one depth level per struct, so a single
    // point is nowhere near the limit.
    //   B3 58            -> TINY_STRUCT(3), POINT_2D
    //   C9 1C 23         -> INT_16 7203 (srid)
    //   C1 3F F0 00 00 00 00 00 00  -> FLOAT_64 1.0 (x)
    //   C1 40 00 00 00 00 00 00 00  -> FLOAT_64 2.0 (y)
    let bytes = [
        0xB3, 0x58, 0xC9, 0x1C, 0x23, 0xC1, 0x3F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC1,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut u = Unpacker::new(&bytes);
    let v = unpack_value(&mut u).expect("a single well-formed Point2D must decode");
    assert!(matches!(v, Value::Point(_)), "expected a Point, got {v:?}");
}

// ---- Test B: the actual impact — a realistic-stack decode ABORTS the process -------------------
//
// Runs the malicious decode in a subprocess (a re-exec of this test binary) on a 2 MiB stack — the
// faithful size of a tokio blocking-pool worker that a Bolt session runs on. On HEAD the unbounded
// recursion overflows that stack and Rust `abort()`s the process; the parent observes the abnormal
// exit. After a fix, the decode returns a clean depth error and the child exits 0. The subprocess
// isolates the crash so it can never take down THIS test harness.

/// Marker env var that switches the victim test below into "run the overflow" mode.
const VICTIM_ENV: &str = "REAUDIT_D1_POINT_VICTIM";

#[test]
fn nested_point_recursion_aborts_process_via_stack_overflow() {
    // Don't recurse: if we are already the spawned victim child, skip (the victim test does the work).
    if std::env::var_os(VICTIM_ENV).is_some() {
        return;
    }

    let exe = std::env::current_exe().expect("locate the test binary for re-exec");
    let output = std::process::Command::new(&exe)
        .args([
            "--exact",
            "point_recursion_overflow_victim",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(VICTIM_ENV, "1")
        .output()
        .expect("spawn the victim subprocess");

    // SECURE outcome (post-fix): the child survives — the decode returns a depth error, the victim
    // thread completes, and the child exits 0. On HEAD the child is killed by the stack-overflow
    // abort (SIGABRT/SIGSEGV), so `status.success()` is false. This assertion therefore FAILS on
    // HEAD, which is the proof of the remote, single-packet, whole-process DoS.
    assert!(
        output.status.success(),
        "SECURITY (CWE-674): decoding a deep nested Point2D chain on a realistic 2 MiB session stack \
         ABORTED the process (stack overflow) instead of returning a clean depth error. \
         victim exit = {:?}; stderr tail: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
            .lines()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .join(" | "),
    );
}

#[test]
fn point_recursion_overflow_victim() {
    // No-op unless invoked as the spawned child (so a normal `cargo test` run of this file does not
    // crash). The parent above re-execs this single test with VICTIM_ENV set.
    if std::env::var_os(VICTIM_ENV).is_none() {
        return;
    }

    // ~1,000,000 nested levels (~3 MB of wire — trivially under the 64 MiB framing cap) on a 2 MiB
    // stack. Whether the per-frame cost is large (debug) or small (release), a million frames vastly
    // exceeds any 2 MiB stack, so HEAD overflows and aborts before the closure returns. A
    // depth-guarded decoder instead stops at MAX_DECODE_DEPTH and returns an error immediately.
    let bytes = nested_point2d(1_000_000);
    let handle = std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            let mut u = Unpacker::new(&bytes);
            // Post-fix this returns Err(depth); on HEAD this call never returns (stack overflow).
            unpack_value(&mut u).is_err()
        })
        .expect("spawn 2 MiB victim decode thread");

    let rejected = handle
        .join()
        .expect("victim decode thread must not panic (a depth-guarded decode returns an error)");
    assert!(
        rejected,
        "a depth-guarded decoder must reject the deep nested point with an error"
    );
    // Reached only if the decode returned (i.e. the guard worked). Exit cleanly so the parent sees
    // success. On HEAD the process has already aborted before this point.
    std::process::exit(0);
}
