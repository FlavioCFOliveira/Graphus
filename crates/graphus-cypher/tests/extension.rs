//! Integration tests for the **extension mechanism** — user-defined functions/procedures (`rmp`
//! task #75).
//!
//! These exercise the **real** compile→execute pipeline end-to-end
//! (tokenize → parse → [`analyze_with_extensions`] → lower → [`plan_physical`] → bind →
//! [`execute_with_extensions`]), mirroring the procedure tests in `tests/executor.rs`, so they prove
//! the acceptance criteria over exactly the path the server uses.

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::errors::{ErrorType, SemanticError};
use graphus_cypher::eval::EvalError;
use graphus_cypher::executor::{ExecError, execute_with_extensions};
use graphus_cypher::extension::{ExtensionRegistry, function_handler};
use graphus_cypher::function_registry::{Arity, FunctionFailure};
use graphus_cypher::graph_access::MemGraph;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::procedure_registry::{FieldSpec, FieldType, ProcedureFailure, ValueClass};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze_with_extensions;
use graphus_cypher::{ProcedureSignature, RowValue};

/// A registry with `ext.double(n)` (scalar, doubles a number; rejects non-numbers at runtime),
/// `ext.boom()` (scalar, arity 0, always fails), `ext.range(a, b) YIELD value`, and `ext.fail()`
/// (a procedure whose body fails). Procedure built-ins are kept (via `ExtensionRegistry::new`).
fn sample_registry() -> ExtensionRegistry {
    let mut reg = ExtensionRegistry::new();
    reg.register_function(
        "ext.double",
        Arity::Exact(1),
        false,
        function_handler(|args| match args.first() {
            Some(Value::Integer(i)) => Ok(Value::Integer(i * 2)),
            Some(Value::Float(f)) => Ok(Value::Float(f * 2.0)),
            Some(Value::Null) | None => Ok(Value::Null),
            Some(other) => Err(FunctionFailure::new(
                "ext.double",
                format!("expected a number, got {other:?}"),
            )),
        }),
    )
    .expect("register ext.double");
    reg.register_function(
        "ext.boom",
        Arity::Exact(0),
        false,
        function_handler(|_args| Err(FunctionFailure::new("ext.boom", "always fails"))),
    )
    .expect("register ext.boom");
    reg.register_procedure(
        ProcedureSignature::new(
            "ext.range",
            vec![
                FieldSpec::new(
                    "a",
                    FieldType {
                        class: ValueClass::Integer,
                        nullable: false,
                    },
                ),
                FieldSpec::new(
                    "b",
                    FieldType {
                        class: ValueClass::Integer,
                        nullable: false,
                    },
                ),
            ],
            vec![FieldSpec::new(
                "value",
                FieldType {
                    class: ValueClass::Integer,
                    nullable: false,
                },
            )],
        ),
        Box::new(|args, _graph| {
            let (Some(Value::Integer(a)), Some(Value::Integer(b))) = (args.first(), args.get(1))
            else {
                return Err(ProcedureFailure::new("ext.range", "expected two integers"));
            };
            Ok((*a..=*b).map(|n| vec![Value::Integer(n)]).collect())
        }),
    );
    reg.register_procedure(
        ProcedureSignature::new("ext.fail", Vec::new(), Vec::new()),
        Box::new(|_args, _graph| Err(ProcedureFailure::new("ext.fail", "boom"))),
    );
    reg
}

/// Compiles `src` against `registry`, returning the [`SemanticError`] on a compile failure.
fn analyze_src(src: &str, registry: &ExtensionRegistry) -> Result<(), SemanticError> {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    analyze_with_extensions(&ast, registry.functions_dyn(), registry.procedures_dyn()).map(|_| ())
}

/// Compiles **and** executes `src` against `registry` (the same registry backs both phases — the
/// load-bearing contract), returning the result rows.
fn run(src: &str, registry: &ExtensionRegistry) -> Result<Vec<Row>, ExecError> {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated =
        analyze_with_extensions(&ast, registry.functions_dyn(), registry.procedures_dyn())
            .expect("analyze");
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = MemGraph::new();
    let mut cursor = execute_with_extensions(
        &plan,
        &bound,
        &mut graph,
        registry.functions_dyn(),
        registry.procedures_dyn(),
    )?;
    cursor.collect_all()
}

// ---- compile-time function checks (TESTS item 3) --------------------------------------------

#[test]
fn registered_udf_call_analyzes_clean() {
    // `RETURN ext.double(n.age)` over an empty registry would be UnknownFunction; registered, it is
    // accepted (no UnknownFunction).
    let reg = sample_registry();
    analyze_src("WITH 21 AS x RETURN ext.double(x) AS v", &reg).expect("registered UDF analyzes");
}

#[test]
fn unregistered_function_is_unknown_function_syntax_error() {
    // Without registration, the same call is the TCK SyntaxError/UnknownFunction (unchanged).
    let reg = ExtensionRegistry::new();
    let err = analyze_src("RETURN ext.double(1) AS v", &reg).expect_err("unknown function");
    assert_eq!(err.classification().error_type, ErrorType::SyntaxError);
}

#[test]
fn wrong_arity_udf_is_invalid_number_of_arguments_syntax_error() {
    // A registered UDF called with the wrong arity is SyntaxError/InvalidNumberOfArguments — the
    // same class as a built-in's wrong-arity error (the correct compile-time class).
    let reg = sample_registry();
    let err = analyze_src("RETURN ext.double(1, 2) AS v", &reg).expect_err("wrong arity");
    assert_eq!(err.classification().error_type, ErrorType::SyntaxError);
}

#[test]
fn builtins_still_resolve_with_a_registry_present() {
    // A registry that has UDFs does not disturb built-in resolution.
    let reg = sample_registry();
    analyze_src("RETURN abs(-5), size([1, 2, 3]) AS s", &reg).expect("built-ins analyze");
}

// ---- scalar UDF end-to-end (TESTS item 4: the primary AC) -----------------------------------

#[test]
fn scalar_udf_doubles_through_the_real_path() {
    let reg = sample_registry();
    let rows = run("RETURN ext.double(21) AS v", &reg).expect("run");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("v"), Value::Integer(42));
}

#[test]
fn scalar_udf_handles_float_and_null() {
    let reg = sample_registry();
    let rows = run("RETURN ext.double(1.5) AS v", &reg).expect("run");
    assert_eq!(rows[0].value("v"), Value::Float(3.0));
    let rows = run("RETURN ext.double(null) AS v", &reg).expect("run");
    assert_eq!(rows[0].value("v"), Value::Null);
}

#[test]
fn scalar_udf_case_insensitive_at_runtime() {
    let reg = sample_registry();
    let rows = run("RETURN EXT.Double(5) AS v", &reg).expect("run");
    assert_eq!(rows[0].value("v"), Value::Integer(10));
}

// ---- UDP end-to-end (TESTS item 4) ----------------------------------------------------------

#[test]
fn udp_range_yields_rows_through_the_real_path() {
    let reg = sample_registry();
    let rows = run("CALL ext.range(1, 3) YIELD value RETURN value", &reg).expect("run");
    let got: Vec<Value> = rows.iter().map(|r| r.value("value")).collect();
    assert_eq!(
        got,
        vec![Value::Integer(1), Value::Integer(2), Value::Integer(3)]
    );
}

// ---- runtime UDF failures (TESTS item 4) ----------------------------------------------------

#[test]
fn udf_body_error_surfaces_as_extension_function_eval_error() {
    // `ext.boom()` always returns a FunctionFailure -> EvalError::ExtensionFunction at runtime.
    let reg = sample_registry();
    let err = run("RETURN ext.boom() AS v", &reg).expect_err("body error");
    match err {
        ExecError::Eval(EvalError::ExtensionFunction { name, message }) => {
            assert_eq!(name, "ext.boom");
            assert!(message.contains("always fails"));
        }
        other => panic!("expected ExtensionFunction, got {other:?}"),
    }
    // And it maps to a runtime GraphusError (ArgumentError class at the Bolt boundary).
    let ge: graphus_core::GraphusError = err_for_double_bad_type(&reg).into();
    assert!(matches!(ge, graphus_core::GraphusError::Runtime(_)));
}

/// Helper: runs `ext.double('x')` (wrong type) and returns the resulting [`ExecError`].
fn err_for_double_bad_type(reg: &ExtensionRegistry) -> ExecError {
    run("RETURN ext.double('x') AS v", reg).expect_err("wrong type")
}

#[test]
fn udf_wrong_type_arg_is_runtime_extension_function_error() {
    // A wrong-typed argument that the handler rejects is a RUNTIME error (function argument *types*
    // are runtime, per the existing TCK design — see the function_registry module docs).
    let reg = sample_registry();
    let err = err_for_double_bad_type(&reg);
    assert!(matches!(
        err,
        ExecError::Eval(EvalError::ExtensionFunction { .. })
    ));
}

#[test]
fn udp_body_error_classifies_as_procedure_error() {
    // A UDP whose body fails surfaces as ExecError::Procedure (ProcedureError class), distinct from
    // a UDF body error (which is ExtensionFunction).
    let reg = sample_registry();
    let err = run("CALL ext.fail()", &reg).expect_err("procedure body error");
    match err {
        ExecError::Procedure(failure) => assert_eq!(failure.name, "ext.fail"),
        other => panic!("expected Procedure, got {other:?}"),
    }
}

// ---- built-ins unaffected regression (TESTS item 5) -----------------------------------------

#[test]
fn builtins_behave_identically_with_extensions_present() {
    let reg = sample_registry();
    let rows = run("RETURN abs(-5) AS a, size([1, 2, 3]) AS s", &reg).expect("run");
    assert_eq!(rows[0].value("a"), Value::Integer(5));
    assert_eq!(rows[0].value("s"), Value::Integer(3));
}

#[test]
fn builtin_procedures_still_callable_through_extension_registry() {
    let reg = sample_registry();
    // `db.labels()` is a built-in procedure kept by `ExtensionRegistry::new`.
    let toks = tokenize("CALL db.labels() YIELD label RETURN label").expect("lex");
    let ast = parse_tokens(&toks, "CALL db.labels() YIELD label RETURN label").expect("parse");
    let validated =
        analyze_with_extensions(&ast, reg.functions_dyn(), reg.procedures_dyn()).expect("analyze");
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = MemGraph::new();
    graph.add_node(["Person"], [("name", Value::String("Ada".into()))]);
    let mut cursor = execute_with_extensions(
        &plan,
        &bound,
        &mut graph,
        reg.functions_dyn(),
        reg.procedures_dyn(),
    )
    .expect("open");
    let rows = cursor.collect_all().expect("rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("label"), Value::String("Person".into()));
}

#[test]
fn udf_in_a_larger_expression_composes_with_builtins() {
    // A UDF nested inside a built-in-bearing expression evaluates correctly.
    let reg = sample_registry();
    let rows = run("RETURN ext.double(3) + abs(-4) AS v", &reg).expect("run");
    assert_eq!(rows[0].value("v"), Value::Integer(10));
}

#[test]
fn udf_yields_a_plain_value_rowvalue() {
    // Sanity: a scalar UDF result is a plain `RowValue::Value`, not a structural binding.
    let reg = sample_registry();
    let rows = run("RETURN ext.double(7) AS v", &reg).expect("run");
    assert_eq!(rows[0].get("v"), Some(&RowValue::Value(Value::Integer(14))));
}
