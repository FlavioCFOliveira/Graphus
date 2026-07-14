//! Hermetic cargo exercise of the `examples/iot-timeseries` **schema** (`rmp` #675).
//!
//! Where `crates/graphus-iot-gen/tests/churn_plateau.rs` proves the storage-reclamation *plateau* over
//! a sustained churn run, this test proves the production-realistic geo/time **schema** the example now
//! declares actually works end-to-end, hermetically (no Bolt, no server, no network): it takes the DDL
//! block `graphus_iot_gen::Generator::schema_ddl()` emits, drives it through the REAL engine via the
//! admin-DDL command path (`parse_admin_statement` → `LocalEngine::{index_ddl, constraint_ddl}` — the
//! exact seam the Bolt/REST admin surfaces submit after parsing `CREATE … INDEX` / `CREATE
//! CONSTRAINT`), loads a small seeded sensor/reading dataset **schema-first**, and asserts:
//!
//! - the new index & constraint kinds are declared and `Online` (`SHOW INDEXES` / `SHOW CONSTRAINTS`):
//!   a **POINT** (spatial) index on `Sensor.location`, a **composite** node `RANGE` index on
//!   `Reading(sensor, seq)`, the single-property retention `RANGE` index on `Reading.seq`, a `RANGE`
//!   index on the **temporal** `Reading.ts`, a **NODE KEY** on `Sensor.id`, a node **property-type**
//!   (`Reading.ts IS :: ZONED DATETIME`) and a node **existence** (`Reading.value IS NOT NULL`)
//!   constraint;
//! - the **empirical planner utilisation** (asserted honestly on the real public planner): a Cartesian
//!   `point.distance(…) <= r` proximity predicate lowers to a **`SpatialIndexSeek`** (the POINT index
//!   IS used); a per-sensor `sensor = … AND seq ∈ [a, b)` query lowers to a **`NodeIndexSeek` on the
//!   composite index** (leading-key equality served by the index, the `seq` range kept as a residual);
//!   a **temporal** `ts ∈ [t0, t1)` window lowers to a **`NodeIndexRangeSeek`** on the `Reading.ts`
//!   index; `seq IS NOT NULL` lowers to a **`NodeIndexScan`** (the existence-scan path over the
//!   retention index) while `value IS NOT NULL` — with no `RANGE` index on `value` — stays a correct
//!   label scan + residual filter;
//! - the **query correctness** against the loaded engine: the spatial proximity query returns exactly
//!   the sensors of the queried site; the composite seek returns exactly the readings the
//!   `(:Sensor)-[:EMITTED]->(:Reading)` traversal returns (a self-validating cross-check); the temporal
//!   window seek returns exactly the readings whose `seq` falls in the equivalent `seq` window (`ts` is
//!   strictly increasing in `seq`, so the two windows describe the same set — an independent oracle);
//!   and the `value IS NOT NULL` existence scan counts every reading (the constraint guarantees one);
//! - **constraint enforcement**: a duplicate `Sensor.id` (NODE KEY), a `Reading` with a missing
//!   `value` (existence), and a `Reading` whose `ts` is an **INTEGER** or a **STRING** rather than a
//!   temporal (property-type) are each rejected with the constraint-violation error class, and the
//!   rejected writes leave the counts unchanged.
//!
//! # `rmp` #745 — `ts` is a real temporal
//!
//! `Reading.ts` used to be an epoch-ms `INTEGER`, and the schema *forbade* it from being anything else
//! (`IS :: INTEGER`). A time-series example whose timestamps were integers exercised neither the
//! Bolt/PackStream temporal wire path, nor the temporal property encoding, nor a temporal index key. It
//! is now a `ZONED DATETIME`, `RANGE`-indexed, and this test is where that claim is **empirically
//! verified** against the real engine: the index is `ONLINE` over a `DATETIME` property, the range
//! predicate over it lowers to a real seek, and the seek returns exactly the right rows.
//!
//! Determining the substrate empirically (`rmp` #675 asked): `LocalEngine::run` does **not** accept DDL
//! strings (admin DDL is intercepted before the Cypher pipeline), but `LocalEngine` fully supports admin
//! DDL through its typed `index_ddl` / `constraint_ddl` methods and serves the spatial / composite /
//! existence query paths through its normal query path — so the whole exercise runs in-process against
//! the real coordinator, no booted server required. This is the string-form counterpart of the typed
//! coordinator seam the `iot_churn` driver applies (`graphus_iot_gen::churn::apply_schema`): both
//! declare the identical schema, so a drift between the two would fail here.

use std::sync::Arc;

use graphus_core::Value;
use graphus_cypher::{
    CONSTRAINT_VIOLATION_PREFIX, IndexCatalog, MaterializedValue, PhysicalPlan, analyze, lower,
    parse_tokens, plan_physical, tokenize,
};
use graphus_io::MemBlockDevice;
use graphus_iot_gen::{GenConfig, Generator, SITES};
use graphus_server::admin::{AdminParse, parse_admin_statement};
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{
    ConstraintCommand, ConstraintTypeFilter, IndexCommand, IndexDdlReply, IndexTypeFilter,
    LocalEngine,
};
use graphus_sim::SharedClock;
use graphus_wal::MemLogSink;

type Eng = LocalEngine<MemBlockDevice, MemLogSink>;

/// The hermetic dataset shape: enough sensors to spread across all four sites, a run short enough (and
/// a window large enough) that **no** reading ages out — so every inserted reading is live and the
/// counts are exactly known.
const SENSORS: u64 = 8;
const RATE: u64 = 25;
const TICKS: u64 = 4;
const READINGS: u64 = RATE * TICKS; // 100, none deleted (window is huge)

/// Builds an in-memory engine with a fixed clock — the deterministic, hermetic substrate.
fn engine() -> Eng {
    LocalEngine::in_memory(Arc::new(SharedClock::new(0)), 1024).expect("in-memory engine")
}

/// Whether `stmt` is a schema-DDL statement (any `CREATE CONSTRAINT` or any `CREATE … INDEX` form,
/// including `CREATE POINT INDEX`). Mirrors the loader splitters used by the example.
fn is_schema_ddl(stmt: &str) -> bool {
    stmt.starts_with("CREATE CONSTRAINT")
        || (stmt.starts_with("CREATE") && stmt.contains(" INDEX "))
}

/// The seeded generator config for the hermetic load — a huge window means no retention delete fires,
/// so every one of [`READINGS`] readings is live.
fn cfg() -> GenConfig {
    GenConfig {
        seed: 0xC0FF_EE15_600D_5EED,
        sensors: SENSORS,
        rate: RATE,
        window: 1_000_000,
        ticks: TICKS,
    }
}

/// Loads the seeded sensor/reading dataset **schema-first** through the real engine: every
/// `CREATE CONSTRAINT` / `CREATE … INDEX` from [`Generator::schema_ddl`] runs through the admin-DDL
/// command path (as the Bolt/REST admin seams do), then the sensor fleet and the readings load inside a
/// single write transaction. Asserts the load succeeds — i.e. **every seed value conforms to every
/// constraint** (`rmp` #675 acceptance): each `Reading` carries an integer `ts` and a `value`, and each
/// `Sensor` a unique `id`.
fn load_schema_first() -> Eng {
    let mut generator = Generator::new(cfg());
    let ddl = generator.schema_ddl();

    // NODE KEY + existence + property-type + POINT + composite + retention + temporal = seven
    // schema statements.
    assert!(
        ddl.len() >= 7,
        "expected the full schema DDL block, got {} statements: {ddl:?}",
        ddl.len()
    );
    assert!(ddl.iter().all(|s| is_schema_ddl(s)), "all DDL: {ddl:?}");

    // Assemble the data script: the sensor fleet, then every tick's reading inserts (no deletes fire).
    let mut data = generator.sensor_cypher();
    while let Some(t) = generator.tick() {
        assert!(
            t.delete.is_none(),
            "the huge window must never age a reading out"
        );
        data.extend(t.inserts);
    }

    let mut eng = engine();

    // 1. Apply the schema DDL through the admin path (each an auto-commit control command).
    for stmt in &ddl {
        match parse_admin_statement(stmt) {
            AdminParse::Index(cmd) => {
                eng.index_ddl(cmd)
                    .unwrap_or_else(|e| panic!("index DDL failed: {stmt}\n  {e}"));
            }
            AdminParse::Constraint(cmd) => {
                eng.constraint_ddl(cmd)
                    .unwrap_or_else(|e| panic!("constraint DDL failed: {stmt}\n  {e}"));
            }
            other => panic!("schema statement did not parse as admin DDL: {stmt}\n  got {other:?}"),
        }
    }

    // 2. Load the data with the schema active — every write is constraint-checked and index-maintained
    //    (so the POINT / composite / retention indexes are populated incrementally as each CREATE lands).
    let ticket = eng.begin(AccessMode::Write).expect("begin load txn");
    for stmt in &data {
        let mut reply = eng
            .run(ticket, stmt, Vec::new(), false, None)
            .unwrap_or_else(|e| {
                panic!("load statement failed (data does not conform?): {stmt}\n  {e}")
            });
        while let Ok(Some(_)) = reply.rows.next() {}
    }
    eng.commit(ticket).expect("commit load txn");

    eng
}

/// `SHOW INDEXES` (full column set), as an [`IndexDdlReply`].
fn show_indexes(eng: &mut Eng) -> IndexDdlReply {
    eng.index_ddl(IndexCommand::ShowIndexes {
        filter: IndexTypeFilter::All,
        tail: None,
    })
    .expect("show indexes")
}

/// `SHOW CONSTRAINTS` (full column set), as an [`IndexDdlReply`].
fn show_constraints(eng: &mut Eng) -> IndexDdlReply {
    eng.constraint_ddl(ConstraintCommand::Show {
        filter: ConstraintTypeFilter::All,
        tail: None,
    })
    .expect("show constraints")
}

/// The 0-based column index of `name` in an [`IndexDdlReply`]'s field list.
fn col(reply: &IndexDdlReply, name: &str) -> usize {
    reply
        .fields
        .iter()
        .position(|f| f == name)
        .unwrap_or_else(|| panic!("a `{name}` column in {:?}", reply.fields))
}

/// Finds the single row whose `name` column equals `name`, or panics.
fn row_by_name<'a>(reply: &'a IndexDdlReply, name: &str) -> &'a [Value] {
    let name_c = col(reply, "name");
    reply
        .rows
        .iter()
        .find(|r| matches!(&r[name_c], Value::String(n) if n == name))
        .unwrap_or_else(|| panic!("a row named `{name}`"))
        .as_slice()
}

/// The catalog modelling the schema this example declares — the closest hermetic equivalent of the
/// real engine's own derived catalog, used for the plan-shape (planner-utilisation) assertions.
fn schema_catalog() -> IndexCatalog {
    IndexCatalog::builder()
        .with_token_lookup("Sensor")
        .with_token_lookup("Reading")
        .with_label_spatial("Sensor", "location")
        .with_label_composite("Reading", ["sensor".to_owned(), "seq".to_owned()])
        .with_label_property("Reading", "seq")
        .with_label_property("Reading", "ts")
        .build()
}

/// The `seq` window used by the composite + temporal window assertions, and the `[t0, t1)` instants it
/// is equivalent to. `ts = EPOCH_MS + seq * TICK_MS` is strictly increasing in `seq`, so a temporal
/// window over `[ts_of(lo), ts_of(hi))` selects exactly the readings whose `seq` lies in `[lo, hi)` —
/// an independent oracle for the temporal seek that never consults the temporal query itself.
const WIN_LO: u64 = 20;
const WIN_HI: u64 = 60;

/// The Cypher literal for the instant of reading `seq` — a real `DATETIME`, built the same way the
/// generator's insert stream builds it (`datetime({epochMillis: …})`, no timezone ⇒ UTC, offset 0).
fn ts_literal(seq: u64) -> String {
    format!(
        "datetime({{epochMillis: {}}})",
        Generator::ts_millis_of(seq)
    )
}

/// Compiles `src` into a physical plan against `catalog` (the real public planner pipeline — the closest
/// hermetic equivalent of `EXPLAIN`, since Graphus exposes no `EXPLAIN` query keyword).
fn plan(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    let logical = lower(&validated);
    plan_physical(&logical, catalog)
}

/// Runs an auto-commit write that MUST be rejected by a constraint, returning the violation message.
fn expect_rejected(eng: &mut Eng, stmt: &str) -> String {
    let ticket = eng
        .begin_auto_commit(AccessMode::Write)
        .expect("begin auto-commit");
    match eng.run(ticket, stmt, Vec::new(), true, None) {
        Err(e) => e.to_string(),
        Ok(mut reply) => loop {
            match reply.rows.next() {
                Ok(Some(_)) => {}
                Ok(None) => panic!("statement was ACCEPTED but must be rejected: {stmt}"),
                Err(e) => break e.to_string(),
            }
        },
    }
}

/// Collects the single string column of a read query into a sorted, de-duplicated set.
fn collect_strings(eng: &mut Eng, query: &str) -> Vec<String> {
    let ticket = eng.begin(AccessMode::Read).expect("begin read txn");
    let mut reply = eng
        .run(ticket, query, Vec::new(), false, None)
        .expect("query runs");
    let mut out = Vec::new();
    while let Ok(Some(row)) = reply.rows.next() {
        if let Some(MaterializedValue::Value(Value::String(s))) = row.first() {
            out.push(s.clone());
        }
    }
    eng.commit(ticket).expect("commit read txn");
    out.sort();
    out.dedup();
    out
}

/// Collects the single integer column of a read query into a sorted set (composite seek: the `seq`s).
fn collect_ints(eng: &mut Eng, query: &str) -> Vec<i64> {
    let ticket = eng.begin(AccessMode::Read).expect("begin read txn");
    let mut reply = eng
        .run(ticket, query, Vec::new(), false, None)
        .expect("query runs");
    let mut out = Vec::new();
    while let Ok(Some(row)) = reply.rows.next() {
        if let Some(MaterializedValue::Value(Value::Integer(n))) = row.first() {
            out.push(*n);
        }
    }
    eng.commit(ticket).expect("commit read txn");
    out.sort_unstable();
    out
}

/// A single scalar integer (e.g. a `count(…)`).
fn scalar_int(eng: &mut Eng, query: &str) -> i64 {
    let got = collect_ints(eng, query);
    assert_eq!(got.len(), 1, "expected a single scalar row for `{query}`");
    got[0]
}

/// The sensor ids that belong to `site` (`id = s-<i>` where `i % SITES == site`), for the fleet size.
fn sensors_of_site(site: u64) -> Vec<String> {
    let mut out: Vec<String> = (0..SENSORS)
        .filter(|i| i % SITES == site)
        .map(Generator::sensor_id)
        .collect();
    out.sort();
    out
}

#[test]
fn schema_first_load_declares_new_index_and_constraint_kinds() {
    let mut eng = load_schema_first();

    // ---- SHOW INDEXES: the POINT + composite RANGE + retention RANGE indexes, all Online. ----
    let idx = show_indexes(&mut eng);
    let (type_c, entity_c, labels_c, props_c, state_c) = (
        col(&idx, "type"),
        col(&idx, "entityType"),
        col(&idx, "labelsOrTypes"),
        col(&idx, "properties"),
        col(&idx, "state"),
    );

    // POINT (spatial) index on Sensor.location — the headline geo optimisation.
    let point = row_by_name(&idx, "sensor_location_point");
    assert_eq!(
        point[type_c],
        Value::String("POINT".to_owned()),
        "POINT is a distinct native spatial index, not a RANGE synonym"
    );
    assert_eq!(point[entity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        point[labels_c],
        Value::List(vec![Value::String("Sensor".to_owned())])
    );
    assert_eq!(
        point[props_c],
        Value::List(vec![Value::String("location".to_owned())])
    );
    assert_eq!(
        point[state_c],
        Value::String("ONLINE".to_owned()),
        "the POINT index must be Online after the schema-first load"
    );

    // Composite RANGE index on Reading(sensor, seq) — the ordered two-property tuple.
    let composite = row_by_name(&idx, "reading_sensor_seq");
    assert_eq!(composite[type_c], Value::String("RANGE".to_owned()));
    assert_eq!(composite[entity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        composite[props_c],
        Value::List(vec![
            Value::String("sensor".to_owned()),
            Value::String("seq".to_owned()),
        ]),
        "the composite index covers (sensor, seq) in declared order"
    );
    assert_eq!(composite[state_c], Value::String("ONLINE".to_owned()));

    // The single-property retention RANGE index on Reading.seq is present and Online.
    let retention = row_by_name(&idx, "reading_seq");
    assert_eq!(retention[type_c], Value::String("RANGE".to_owned()));
    assert_eq!(retention[entity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        retention[props_c],
        Value::List(vec![Value::String("seq".to_owned())])
    );
    assert_eq!(retention[state_c], Value::String("ONLINE".to_owned()));

    // `rmp` #745 — the RANGE index over the TEMPORAL `Reading.ts`. This is the empirical answer to
    // "does the engine accept a RANGE index over a DATETIME property?": the index built to completion
    // over 100 readings whose `ts` is a `Value::ZonedDateTime`, and it is ONLINE.
    let temporal = row_by_name(&idx, "reading_ts");
    assert_eq!(
        temporal[type_c],
        Value::String("RANGE".to_owned()),
        "the temporal index is an ordinary RANGE index — the key codec orders temporals natively"
    );
    assert_eq!(temporal[entity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        temporal[props_c],
        Value::List(vec![Value::String("ts".to_owned())])
    );
    assert_eq!(
        temporal[state_c],
        Value::String("ONLINE".to_owned()),
        "a RANGE index over a DATETIME property must build to completion, not stall Populating"
    );

    // ---- SHOW CONSTRAINTS: the NODE KEY + property-type + existence constraints. ----
    let cons = show_constraints(&mut eng);
    let (ctype_c, centity_c, cprops_c, cptype_c) = (
        col(&cons, "type"),
        col(&cons, "entityType"),
        col(&cons, "properties"),
        col(&cons, "propertyType"),
    );

    let key = row_by_name(&cons, "sensor_id_key");
    assert_eq!(key[ctype_c], Value::String("NODE_KEY".to_owned()));
    assert_eq!(key[centity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        key[cprops_c],
        Value::List(vec![Value::String("id".to_owned())])
    );

    let ts_type = row_by_name(&cons, "reading_ts_datetime");
    assert_eq!(
        ts_type[ctype_c],
        Value::String("NODE_PROPERTY_TYPE".to_owned())
    );
    assert_eq!(ts_type[centity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        ts_type[cprops_c],
        Value::List(vec![Value::String("ts".to_owned())])
    );
    assert_eq!(
        ts_type[cptype_c],
        Value::String("ZONED DATETIME".to_owned()),
        "`rmp` #745: ts is a REAL temporal. The old `IS :: INTEGER` did not merely fail to exercise \
         the temporal path — it FORBADE it"
    );

    let value_exists = row_by_name(&cons, "reading_value_exists");
    assert_eq!(
        value_exists[ctype_c],
        Value::String("NODE_PROPERTY_EXISTENCE".to_owned())
    );
    assert_eq!(value_exists[centity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        value_exists[cprops_c],
        Value::List(vec![Value::String("value".to_owned())])
    );
}

#[test]
fn planner_uses_point_and_composite_indexes_and_the_existence_scan() {
    // The honest empirical planner findings (`rmp` #675), asserted on the real public planner against a
    // catalog modelling exactly this schema.
    let cat = schema_catalog();

    // 1. A Cartesian `point.distance(…) <= r` proximity predicate IS served by the POINT index — it
    //    lowers to a `SpatialIndexSeek` (grid candidate superset) with the exact `distance` predicate
    //    kept as a residual `Filter` above (so the index never changes the answer, only the speed).
    let spatial = plan(
        "MATCH (s:Sensor) WHERE point.distance(s.location, point({x: 0, y: 0})) <= 50 RETURN s.id",
        &cat,
    );
    let spatial_render = spatial.to_string();
    assert!(
        spatial_render.contains("SpatialIndexSeek"),
        "a Cartesian proximity predicate must lower to a SpatialIndexSeek:\n{spatial_render}"
    );
    assert!(
        spatial_render.contains("Filter"),
        "the exact distance predicate is re-checked as a residual filter:\n{spatial_render}"
    );

    // 2. A per-sensor `sensor = … AND seq ∈ [a, b)` query IS served by the COMPOSITE index — its
    //    leading-key equality (`sensor = 's-0'`) lowers to a `NodeIndexSeek` on the composite index,
    //    with the trailing `seq` range kept as a residual filter (a leading-key seek, not a full
    //    all-keys `NodeCompositeIndexSeek`).
    let composite = plan(
        "MATCH (r:Reading) WHERE r.sensor = 's-0' AND r.seq >= 20 AND r.seq < 60 RETURN r.seq",
        &cat,
    );
    let composite_render = composite.to_string();
    assert!(
        composite_render.contains("NodeIndexSeek"),
        "the leading `sensor` equality must be served by a NodeIndexSeek on the composite index:\n{composite_render}"
    );
    assert!(
        composite_render.contains("Filter"),
        "the trailing `seq` range stays a residual filter above the seek:\n{composite_render}"
    );
    assert_eq!(
        composite.index_dependencies().count(),
        1,
        "the composite query depends on exactly one (the composite) index:\n{composite_render}"
    );

    // 2b. `rmp` #745 — the TEMPORAL window read. A `ts ∈ [t0, t1)` range over the real `DATETIME`
    //     property lowers to a `NodeIndexRangeSeek` on the `Reading.ts` RANGE index. This is the query a
    //     time-series database exists to serve, and the whole reason the index exists.
    let temporal = plan(
        &format!(
            "MATCH (r:Reading) WHERE r.ts >= {} AND r.ts < {} RETURN r.seq",
            ts_literal(WIN_LO),
            ts_literal(WIN_HI)
        ),
        &cat,
    );
    let temporal_render = temporal.to_string();
    assert!(
        temporal_render.contains("NodeIndexRangeSeek"),
        "the temporal window must SEEK the Reading.ts RANGE index:\n{temporal_render}"
    );
    // Teeth: with NO index on `ts` the identical statement stays a scan — so the assertion above is
    // testing the index, not the shape of the plan renderer.
    let unindexed = IndexCatalog::builder()
        .with_token_lookup("Reading")
        .with_label_property("Reading", "seq")
        .build();
    let temporal_scan = plan(
        &format!(
            "MATCH (r:Reading) WHERE r.ts >= {} AND r.ts < {} RETURN r.seq",
            ts_literal(WIN_LO),
            ts_literal(WIN_HI)
        ),
        &unindexed,
    )
    .to_string();
    assert!(
        !temporal_scan.contains("NodeIndexRangeSeek"),
        "control: with no Reading.ts index the temporal window must NOT be index-backed:\n{temporal_scan}"
    );

    // 3. `seq IS NOT NULL` — over the indexed `Reading.seq` — lowers to a `NodeIndexScan` (Graphus's
    //    existence-scan access path: every index entry is a non-null value, so the scan enumerates them).
    let seq_exists = plan(
        "MATCH (r:Reading) WHERE r.seq IS NOT NULL RETURN count(r)",
        &cat,
    );
    let seq_exists_render = seq_exists.to_string();
    assert!(
        seq_exists_render.contains("NodeIndexScan"),
        "`seq IS NOT NULL` is served by a NodeIndexScan over the retention index:\n{seq_exists_render}"
    );

    // 4. `value IS NOT NULL` — with NO `RANGE` index on `value` (only the existence *constraint*, which
    //    is not a queryable range index) — stays a correct label scan + residual filter, never a
    //    property-index scan. Asserted honestly: the plan does NOT use a NodeIndexScan.
    let value_exists = plan(
        "MATCH (r:Reading) WHERE r.value IS NOT NULL RETURN count(r)",
        &cat,
    );
    let value_exists_render = value_exists.to_string();
    assert!(
        !value_exists_render.contains("NodeIndexScan"),
        "`value IS NOT NULL` has no property index to scan — it stays a label scan + filter:\n{value_exists_render}"
    );
    assert!(
        value_exists_render.contains("Filter"),
        "the existence predicate on the unindexed `value` is a residual filter:\n{value_exists_render}"
    );
}

#[test]
fn spatial_query_returns_exactly_the_queried_site_sensors() {
    let mut eng = load_schema_first();

    // The POINT index is really Online, and a Cartesian proximity query around a site centre returns
    // exactly that site's sensors (the residual `distance` re-check makes the answer exact).
    {
        let idx = show_indexes(&mut eng);
        let state_c = col(&idx, "state");
        assert_eq!(
            row_by_name(&idx, "sensor_location_point")[state_c],
            Value::String("ONLINE".to_owned())
        );
    }

    // Site 0's centre is (0, 0); site 3's is (1000, 1000). Each proximity query returns exactly the
    // sensors of that site — the known, enumerable ground truth (derived from the sensor ids alone).
    for (site, cx, cy) in [(0u64, 0, 0), (3u64, 1000, 1000)] {
        let got = collect_strings(
            &mut eng,
            &format!(
                "MATCH (s:Sensor) WHERE point.distance(s.location, point({{x: {cx}, y: {cy}}})) <= 50 \
                 RETURN s.id AS id"
            ),
        );
        assert_eq!(
            got,
            sensors_of_site(site),
            "the proximity query around site {site}'s centre must return exactly that site's sensors"
        );
    }

    // A radius that spans two adjacent sites (0 at (0,0) and 1 at (1000,0), 1000 apart) captures both.
    let mut both = sensors_of_site(0);
    both.extend(sensors_of_site(1));
    both.sort();
    let wide = collect_strings(
        &mut eng,
        "MATCH (s:Sensor) WHERE point.distance(s.location, point({x: 500, y: 0})) <= 600 RETURN s.id AS id",
    );
    assert_eq!(
        wide, both,
        "a radius spanning sites 0 and 1 (centre midway) returns both sites' sensors"
    );
}

#[test]
fn composite_seek_matches_the_emitted_traversal() {
    let mut eng = load_schema_first();

    // The per-sensor windowed read served by the composite index must return EXACTLY the readings the
    // `(:Sensor)-[:EMITTED]->(:Reading)` traversal returns for the same sensor + seq window — a
    // self-validating cross-check (the `Reading.sensor` property equals the emitter's id by
    // construction, so the two independent access paths must agree).
    let (lo, hi) = (20i64, 60i64);
    let via_composite = collect_ints(
        &mut eng,
        &format!(
            "MATCH (r:Reading) WHERE r.sensor = 's-0' AND r.seq >= {lo} AND r.seq < {hi} RETURN r.seq AS seq"
        ),
    );
    let via_traversal = collect_ints(
        &mut eng,
        &format!(
            "MATCH (:Sensor {{id: 's-0'}})-[:EMITTED]->(r:Reading) WHERE r.seq >= {lo} AND r.seq < {hi} \
             RETURN r.seq AS seq"
        ),
    );
    assert_eq!(
        via_composite, via_traversal,
        "the composite-index seek and the EMITTED traversal must return the same readings"
    );

    // The composite path must actually be exercised: s-0 has readings, and at least one falls in the
    // window (so the assertion above is not vacuously comparing two empty sets).
    let all_s0 = scalar_int(
        &mut eng,
        "MATCH (r:Reading) WHERE r.sensor = 's-0' RETURN count(r) AS c",
    );
    assert!(
        all_s0 > 0,
        "sensor s-0 must have emitted at least one reading"
    );
    assert!(
        !via_composite.is_empty(),
        "the seq window [{lo}, {hi}) must contain at least one s-0 reading to exercise the seek"
    );
}

/// **`rmp` #745 — the empirical proof that a temporal RANGE seek returns the RIGHT rows.**
///
/// A plan-shape assertion proves the index is *used*; it cannot prove the index is *right*. An index
/// that silently returns an empty set (or a truncated one) would satisfy every plan assertion in this
/// file and every `count(…)`-shaped check in the example — that is exactly the defect class `rmp` #738
/// exists for. So the temporal window's result set is compared, element by element, against an
/// independent oracle: `ts = EPOCH_MS + seq * TICK_MS` is strictly increasing in `seq`, so the readings
/// with `ts ∈ [ts_of(lo), ts_of(hi))` are precisely those with `seq ∈ [lo, hi)`, a set the `seq` index
/// (or a bare scan) can produce without ever consulting the temporal path.
#[test]
fn temporal_window_seek_returns_exactly_the_right_readings() {
    let mut eng = load_schema_first();

    // The temporal index is genuinely ONLINE over the DATETIME property.
    {
        let idx = show_indexes(&mut eng);
        let state_c = col(&idx, "state");
        assert_eq!(
            row_by_name(&idx, "reading_ts")[state_c],
            Value::String("ONLINE".to_owned()),
            "a RANGE index over a DATETIME property must reach ONLINE"
        );
    }

    let via_temporal = collect_ints(
        &mut eng,
        &format!(
            "MATCH (r:Reading) WHERE r.ts >= {} AND r.ts < {} RETURN r.seq AS seq",
            ts_literal(WIN_LO),
            ts_literal(WIN_HI)
        ),
    );
    let via_seq = collect_ints(
        &mut eng,
        &format!(
            "MATCH (r:Reading) WHERE r.seq >= {WIN_LO} AND r.seq < {WIN_HI} RETURN r.seq AS seq"
        ),
    );

    // Non-vacuity FIRST: two empty sets are trivially equal, and an index that returns nothing is the
    // exact failure this test exists to catch. The window is 40 readings wide, and all 100 are live.
    assert_eq!(
        via_seq.len() as u64,
        WIN_HI - WIN_LO,
        "the oracle must be non-empty, or the comparison below proves nothing"
    );
    assert_eq!(
        via_temporal, via_seq,
        "the temporal window seek must return EXACTLY the readings of the equivalent seq window"
    );

    // A half-open window is half-open at BOTH ends: the reading at `WIN_HI` is excluded and the one at
    // `WIN_LO` is included. An off-by-one in the temporal key encoding shows up precisely here.
    assert!(via_temporal.contains(&(WIN_LO as i64)));
    assert!(!via_temporal.contains(&(WIN_HI as i64)));

    // And the stored value really is a temporal — not an integer the engine coerced on the way in.
    let ticket = eng
        .begin(graphus_server::engine::command::AccessMode::Read)
        .expect("begin read");
    let mut reply = eng
        .run(
            ticket,
            "MATCH (r:Reading) WHERE r.seq = 7 RETURN r.ts AS ts",
            Vec::new(),
            false,
            None,
        )
        .expect("query runs");
    let row = reply.rows.next().expect("row").expect("a reading at seq 7");
    match row.first() {
        Some(MaterializedValue::Value(Value::ZonedDateTime(dt))) => {
            assert_eq!(
                dt.local.epoch_seconds,
                (Generator::ts_millis_of(7) / 1000) as i64,
                "the stored instant is the generated one"
            );
            assert_eq!(dt.offset_seconds, 0, "UTC");
        }
        other => panic!("Reading.ts must be stored as a ZONED DATETIME, got {other:?}"),
    }
    drop(reply);
    eng.commit(ticket).expect("commit read txn");
}

#[test]
fn existence_scan_counts_every_reading() {
    let mut eng = load_schema_first();

    // The existence constraint guarantees every reading carries a `value`, so `value IS NOT NULL`
    // counts all readings (served — per the planner test — by a correct label scan + residual filter,
    // there being no RANGE index on `value`).
    let by_value = scalar_int(
        &mut eng,
        "MATCH (r:Reading) WHERE r.value IS NOT NULL RETURN count(r) AS c",
    );
    assert_eq!(
        by_value, READINGS as i64,
        "every reading carries a value (existence constraint), so the count is all readings"
    );

    // And `seq IS NOT NULL` — served by the existence index scan over the retention index — counts the
    // same population (every reading has a seq).
    let by_seq = scalar_int(
        &mut eng,
        "MATCH (r:Reading) WHERE r.seq IS NOT NULL RETURN count(r) AS c",
    );
    assert_eq!(
        by_seq, READINGS as i64,
        "the seq existence-index scan counts the same reading population"
    );
}

#[test]
fn schema_enforces_constraints_with_negative_writes() {
    let mut eng = load_schema_first();

    // NODE KEY (uniqueness half): a duplicate Sensor.id is rejected.
    let dup = expect_rejected(
        &mut eng,
        "CREATE (:Sensor {id: 's-0', kind: 'temperature', site: 0, location: point({x: 0, y: 0})})",
    );
    assert!(
        dup.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a duplicate Sensor.id must be a constraint violation, got: {dup}"
    );

    // Node existence: a Reading without a `value` is rejected. Its `ts` is a VALID temporal, so the
    // rejection can only be the existence constraint — a malformed `ts` here would make this test pass
    // for the wrong reason.
    let missing = expect_rejected(
        &mut eng,
        &format!(
            "MATCH (s:Sensor {{id: 's-0'}}) \
             CREATE (s)-[:EMITTED]->(:Reading {{sensor: 's-0', seq: 900000, ts: {}}})",
            ts_literal(0)
        ),
    );
    assert!(
        missing.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a missing/null Reading.value must be a constraint violation, got: {missing}"
    );

    // Node property-type (`rmp` #745): `ts` is a ZONED DATETIME, so a bare epoch-ms INTEGER is now
    // REJECTED — the exact inverse of the old schema, which forbade the temporal and accepted the
    // integer. This is the negative check that keeps the temporal type meaningful.
    let int_ts = expect_rejected(
        &mut eng,
        "MATCH (s:Sensor {id: 's-0'}) \
         CREATE (s)-[:EMITTED]->(:Reading {sensor: 's-0', seq: 900001, ts: 1704067200000, value: 1})",
    );
    assert!(
        int_ts.contains(CONSTRAINT_VIOLATION_PREFIX),
        "an epoch-ms INTEGER `ts` must now be a constraint violation, got: {int_ts}"
    );

    // …and so is a string.
    let string_ts = expect_rejected(
        &mut eng,
        "MATCH (s:Sensor {id: 's-0'}) \
         CREATE (s)-[:EMITTED]->(:Reading {sensor: 's-0', seq: 900002, ts: 'noon', value: 1})",
    );
    assert!(
        string_ts.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a string Reading.ts must be a constraint violation, got: {string_ts}"
    );

    // The rejected writes all rolled back — the sensor + reading counts are unchanged from the load.
    let sensor_count = scalar_int(&mut eng, "MATCH (s:Sensor) RETURN count(s) AS c");
    assert_eq!(
        sensor_count, SENSORS as i64,
        "the rejected duplicate sensor created nothing"
    );
    let reading_count = scalar_int(&mut eng, "MATCH (r:Reading) RETURN count(r) AS c");
    assert_eq!(
        reading_count, READINGS as i64,
        "the three rejected readings created nothing"
    );
}
