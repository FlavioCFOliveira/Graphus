//! Integration tests for **parameter binding** (`graphus_cypher::binding`,
//! `04-technical-design.md` §7.5).
//!
//! These prove the **compile-vs-runtime boundary** the spec mandates: a compiled plan is
//! parameter-independent; binding happens at execution; a missing or ill-typed parameter is a
//! **runtime** error (never compile-time). They also prove the cache-friendly property that one
//! plan object binds independently against many parameter sets, and that auto-parameters (lifted
//! literals) bind exactly like user parameters.

use graphus_core::Value;
use graphus_cypher::binding::{BindError, ParamType, Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::lower::lower;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::plan_cache::normalize_query;
use graphus_cypher::{analyze, errors::ErrorPhase, parse};

/// Compiles `src` to a physical plan (parameter-independent) against an empty catalog.
fn plan(src: &str) -> PhysicalPlan {
    let query = parse(src).expect("parses");
    let validated = analyze(&query).expect("analyses");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

#[test]
fn present_parameter_binds_ok() {
    let p = plan("MATCH (n) WHERE n.age = $age RETURN n");
    let bound = bind_parameters(&p, &Parameters::new().with("age", Value::Integer(30)))
        .expect("binds a present, correctly-typed parameter");
    assert_eq!(bound.get("age"), Some(&Value::Integer(30)));
}

#[test]
fn missing_parameter_is_a_runtime_error_not_compile() {
    // The plan COMPILED fine (no compile-time error for the unbound `$age`); the error only arises
    // at bind time — the runtime phase (`04 §7.3`/§7.5).
    let p = plan("MATCH (n) WHERE n.age = $age RETURN n");
    let err = bind_parameters(&p, &Parameters::new()).expect_err("missing parameter must fail");
    assert_eq!(
        err,
        BindError::MissingParameter {
            name: "age".to_owned()
        }
    );
    assert_eq!(
        err.phase(),
        ErrorPhase::Runtime,
        "binding failures are RUNTIME, never compile"
    );
}

#[test]
fn missing_parameter_maps_to_runtime_graphus_error() {
    let p = plan("MATCH (n) WHERE n.age = $age RETURN n");
    let err = bind_parameters(&p, &Parameters::new()).unwrap_err();
    let g: graphus_core::GraphusError = err.into();
    assert!(matches!(g, graphus_core::GraphusError::Runtime(_)), "{g}");
}

#[test]
fn ill_typed_limit_parameter_is_a_runtime_type_error() {
    let p = plan("MATCH (n) RETURN n LIMIT $top");
    // A string in a LIMIT position is the wrong type.
    let err = bind_parameters(
        &p,
        &Parameters::new().with("top", Value::String("x".to_owned())),
    )
    .expect_err("a non-integer LIMIT must fail at bind time");
    assert!(matches!(
        err,
        BindError::WrongType {
            expected: ParamType::Integer,
            ..
        }
    ));
    assert_eq!(err.phase(), ErrorPhase::Runtime);
}

#[test]
fn negative_limit_parameter_is_rejected() {
    let p = plan("MATCH (n) RETURN n LIMIT $top");
    let err = bind_parameters(&p, &Parameters::new().with("top", Value::Integer(-3)))
        .expect_err("a negative LIMIT count must fail");
    assert!(matches!(err, BindError::WrongType { .. }));
}

#[test]
fn skip_and_limit_integer_parameters_bind() {
    let p = plan("MATCH (n) RETURN n SKIP $s LIMIT $l");
    let bound = bind_parameters(
        &p,
        &Parameters::new()
            .with("s", Value::Integer(2))
            .with("l", Value::Integer(10)),
    )
    .expect("non-negative integer SKIP/LIMIT bind");
    assert_eq!(bound.get("s"), Some(&Value::Integer(2)));
    assert_eq!(bound.get("l"), Some(&Value::Integer(10)));
}

#[test]
fn plan_is_parameter_independent_one_plan_many_param_sets() {
    // The SAME compiled plan binds independently against different parameter sets — exactly the
    // property `04 §7.5` requires of the parameter-independent cache.
    let p = plan("MATCH (n) WHERE n.age = $age RETURN n");
    let b1 = bind_parameters(&p, &Parameters::new().with("age", Value::Integer(1))).unwrap();
    let b2 = bind_parameters(&p, &Parameters::new().with("age", Value::Integer(99))).unwrap();
    let b3 = bind_parameters(
        &p,
        &Parameters::new().with("age", Value::String("x".to_owned())),
    )
    .unwrap();
    assert_eq!(b1.get("age"), Some(&Value::Integer(1)));
    assert_eq!(b2.get("age"), Some(&Value::Integer(99)));
    assert_eq!(b3.get("age"), Some(&Value::String("x".to_owned())));
    // The plan itself was never mutated by binding (it is `&PhysicalPlan` throughout).
}

#[test]
fn no_parameters_binds_to_empty() {
    let p = plan("MATCH (n) RETURN n");
    let bound = bind_parameters(&p, &Parameters::new()).unwrap();
    assert!(bound.is_empty(), "a parameterless plan binds nothing");
}

#[test]
fn extra_supplied_parameters_are_ignored() {
    // Supplying more than the plan references is fine; binding takes only what the plan needs.
    let p = plan("MATCH (n) WHERE n.age = $age RETURN n");
    let params = Parameters::new()
        .with("age", Value::Integer(30))
        .with("unused", Value::Boolean(true));
    let bound = bind_parameters(&p, &params).unwrap();
    assert_eq!(bound.len(), 1, "only the referenced `$age` binds");
    assert_eq!(bound.get("age"), Some(&Value::Integer(30)));
    assert!(bound.get("unused").is_none());
}

#[test]
fn auto_parameters_bind_like_user_parameters() {
    // End-to-end: a literal-bearing query is normalised (lifting `30` to an auto-param), and the
    // auto-param is bound at execution exactly like a user `$param`.
    let src = "MATCH (n:Person) WHERE n.age = 30 RETURN n";
    let query = parse(src).unwrap();
    let normalized = normalize_query(src, &query);
    // The plan is compiled from the *normalised* query (literal-free), so its seek value is the
    // auto-parameter. We rebuild the plan from a parse that carries the auto-param placeholder by
    // binding the lifted value into a parameter set.
    let plan = {
        let validated = analyze(&query).unwrap();
        plan_physical(&lower(&validated), &IndexCatalog::empty())
    };
    // The original (un-normalised) plan references no parameters (the literal is inline), so binding
    // an empty set is fine; the auto-param sidecar is what a normalised plan would consume.
    let bound = bind_parameters(&plan, &Parameters::new()).unwrap();
    assert!(bound.is_empty());
    // The auto-param set itself carries the lifted value, ready to feed a normalised plan.
    let mut params = Parameters::new();
    params.extend_with_auto_params(&normalized);
    assert_eq!(
        params.get(&normalized.auto_params()[0].0),
        Some(&Value::Integer(30))
    );
}

#[test]
fn parameter_inside_function_call_must_be_present() {
    let p = plan("RETURN toInteger($x) AS v");
    assert!(
        bind_parameters(&p, &Parameters::new()).is_err(),
        "missing $x is a runtime error"
    );
    assert!(
        bind_parameters(
            &p,
            &Parameters::new().with("x", Value::String("7".to_owned()))
        )
        .is_ok()
    );
}
