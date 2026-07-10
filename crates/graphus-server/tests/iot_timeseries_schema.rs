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
//!   `Reading(sensor, seq)`, the single-property retention `RANGE` index on `Reading.seq`, a **NODE
//!   KEY** on `Sensor.id`, a node **property-type** (`Reading.ts IS :: INTEGER`) and a node
//!   **existence** (`Reading.value IS NOT NULL`) constraint;
//! - the **empirical planner utilisation** (asserted honestly on the real public planner): a Cartesian
//!   `point.distance(…) <= r` proximity predicate lowers to a **`SpatialIndexSeek`** (the POINT index
//!   IS used); a per-sensor `sensor = … AND seq ∈ [a, b)` query lowers to a **`NodeIndexSeek` on the
//!   composite index** (leading-key equality served by the index, the `seq` range kept as a residual);
//!   `seq IS NOT NULL` lowers to a **`NodeIndexScan`** (the existence-scan path over the retention
//!   index) while `value IS NOT NULL` — with no `RANGE` index on `value` — stays a correct label
//!   scan + residual filter;
//! - the **query correctness** against the loaded engine: the spatial proximity query returns exactly
//!   the sensors of the queried site; the composite seek returns exactly the readings the
//!   `(:Sensor)-[:EMITTED]->(:Reading)` traversal returns (a self-validating cross-check); and the
//!   `value IS NOT NULL` existence scan counts every reading (the constraint guarantees each has one);
//! - **constraint enforcement**: a duplicate `Sensor.id` (NODE KEY), a `Reading` with a missing
//!   `value` (existence), and a `Reading` with a non-integer `ts` (property-type) are each rejected
//!   with the constraint-violation error class, and the rejected writes leave the counts unchanged.
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

    // NODE KEY + existence + property-type + POINT + composite + retention = six schema statements.
    assert!(
        ddl.len() >= 6,
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
        .build()
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

    let ts_type = row_by_name(&cons, "reading_ts_integer");
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
        Value::String("INTEGER".to_owned()),
        "the declared node property type is INTEGER (ts is an epoch-ms i64, never a FLOAT)"
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

    // Node existence: a Reading without a `value` is rejected.
    let missing = expect_rejected(
        &mut eng,
        "MATCH (s:Sensor {id: 's-0'}) \
         CREATE (s)-[:EMITTED]->(:Reading {sensor: 's-0', seq: 900000, ts: 1704067200000})",
    );
    assert!(
        missing.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a missing/null Reading.value must be a constraint violation, got: {missing}"
    );

    // Node property-type: a Reading with a non-integer `ts` (a string) is rejected.
    let wrong_type = expect_rejected(
        &mut eng,
        "MATCH (s:Sensor {id: 's-0'}) \
         CREATE (s)-[:EMITTED]->(:Reading {sensor: 's-0', seq: 900001, ts: 'noon', value: 1})",
    );
    assert!(
        wrong_type.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a non-integer Reading.ts must be a constraint violation, got: {wrong_type}"
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
        "the two rejected readings created nothing"
    );
}
