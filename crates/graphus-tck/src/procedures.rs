//! Parsing TCK **fixture procedures** (`Given … there exists a procedure …`) into engine
//! registrations (`tck/features/clauses/call/**`; rmp #57).
//!
//! A TCK CALL scenario declares its procedures inline:
//!
//! ```gherkin
//! And there exists a procedure test.my.proc(name :: STRING?, id :: INTEGER?) :: (city :: STRING?):
//!   | name     | id | city     |
//!   | 'Stefan' | 1  | 'Berlin' |
//! ```
//!
//! [`register`] parses the signature text — the dotted name, the typed input list, the `::`, and
//! the typed output list — plus the fixture table (header = input names then output names; cells
//! in the TCK value mini-language), and registers a table-backed procedure on a
//! [`ProcedureSet`]. The **same** set is then used to compile *and* execute the scenario's
//! queries, which is the engine's registry contract.

use graphus_core::Value;
use graphus_cypher::procedure_registry::{
    FieldSpec, FieldType, ProcedureSet, ProcedureSignature, ValueClass,
};

use crate::feature::ProcedureStep;
use crate::value::parse_expected;

/// Parses `step` and registers the procedure on `set`.
///
/// # Errors
///
/// Returns a human description if the signature text or the fixture table is malformed (a harness
/// fault for the pinned corpus — every corpus signature parses).
pub fn register(set: &mut ProcedureSet, step: &ProcedureStep) -> Result<(), String> {
    let signature = parse_signature(&step.signature)?;

    // A void / no-field signature is written with a single empty table line; ignore the table.
    if signature.inputs.is_empty() && signature.outputs.is_empty() {
        return set
            .register_table(signature, Vec::new())
            .map_err(|e| format!("register: {e}"));
    }

    // The fixture header must name the inputs then the outputs, in declaration order.
    let declared: Vec<&str> = signature
        .inputs
        .iter()
        .chain(&signature.outputs)
        .map(|f| f.name.as_str())
        .collect();
    let header: Vec<&str> = step.header.iter().map(String::as_str).collect();
    if header != declared {
        return Err(format!(
            "procedure `{}` fixture header {header:?} does not match the declared fields \
             {declared:?}",
            signature.name
        ));
    }

    let n_inputs = signature.inputs.len();
    let mut rows = Vec::with_capacity(step.rows.len());
    for raw in &step.rows {
        if raw.len() != declared.len() {
            return Err(format!(
                "procedure `{}` fixture row {raw:?} has {} cell(s), expected {}",
                signature.name,
                raw.len(),
                declared.len()
            ));
        }
        let mut cells = Vec::with_capacity(raw.len());
        for cell in raw {
            cells.push(property_value(cell)?);
        }
        let outputs = cells.split_off(n_inputs);
        rows.push((cells, outputs));
    }

    set.register_table(signature, rows)
        .map_err(|e| format!("register: {e}"))
}

/// Parses one TCK mini-language cell into a property [`Value`].
fn property_value(cell: &str) -> Result<Value, String> {
    let expected = parse_expected(cell).map_err(|e| format!("fixture cell {cell:?}: {e}"))?;
    crate::value::to_property_value(&expected)
        .ok_or_else(|| format!("fixture cell {cell:?} is a structural value, unsupported"))
}

/// Parses `name(inputs) :: (outputs)` into a [`ProcedureSignature`].
fn parse_signature(text: &str) -> Result<ProcedureSignature, String> {
    let (name, rest) = text
        .split_once('(')
        .ok_or_else(|| format!("signature `{text}` has no input list"))?;
    let (inputs_text, rest) = rest
        .split_once(')')
        .ok_or_else(|| format!("signature `{text}` has an unterminated input list"))?;
    let rest = rest
        .trim()
        .strip_prefix("::")
        .ok_or_else(|| format!("signature `{text}` is missing the `::` output separator"))?
        .trim();
    let outputs_text = rest
        .strip_prefix('(')
        .and_then(|r| r.strip_suffix(')'))
        .ok_or_else(|| format!("signature `{text}` has a malformed output list"))?;

    Ok(ProcedureSignature::new(
        name.trim(),
        parse_fields(inputs_text)?,
        parse_fields(outputs_text)?,
    ))
}

/// Parses a comma-separated field list: `name :: TYPE?` items, or empty.
fn parse_fields(text: &str) -> Result<Vec<FieldSpec>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    text.split(',').map(parse_field).collect()
}

/// Parses one `name :: TYPE[?]` field.
fn parse_field(text: &str) -> Result<FieldSpec, String> {
    let (name, ty) = text
        .split_once("::")
        .ok_or_else(|| format!("field `{text}` is missing its `:: TYPE`"))?;
    let ty = ty.trim();
    let (class_text, nullable) = match ty.strip_suffix('?') {
        Some(c) => (c.trim(), true),
        None => (ty, false),
    };
    let class = match class_text.to_ascii_uppercase().as_str() {
        "ANY" => ValueClass::Any,
        "BOOLEAN" => ValueClass::Boolean,
        "STRING" => ValueClass::String,
        "INTEGER" => ValueClass::Integer,
        "FLOAT" => ValueClass::Float,
        "NUMBER" => ValueClass::Number,
        other => return Err(format!("field `{text}` has an unsupported type `{other}`")),
    };
    Ok(FieldSpec::new(name.trim(), FieldType { class, nullable }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_cypher::procedure_registry::ProcedureRegistry;

    fn step(signature: &str, header: &[&str], rows: &[&[&str]]) -> ProcedureStep {
        ProcedureStep {
            signature: signature.to_owned(),
            header: header.iter().map(|s| (*s).to_owned()).collect(),
            rows: rows
                .iter()
                .map(|r| r.iter().map(|s| (*s).to_owned()).collect())
                .collect(),
        }
    }

    #[test]
    fn parses_the_tck_signature_shapes() {
        let sig =
            parse_signature("test.my.proc(name :: STRING?, id :: INTEGER?) :: (city :: STRING?)")
                .expect("parse");
        assert_eq!(sig.name, "test.my.proc");
        assert_eq!(sig.inputs.len(), 2);
        assert_eq!(sig.inputs[0].name, "name");
        assert_eq!(sig.inputs[0].ty.class, ValueClass::String);
        assert!(sig.inputs[0].ty.nullable);
        assert_eq!(sig.outputs.len(), 1);

        let void = parse_signature("test.doNothing() :: ()").expect("parse");
        assert!(void.inputs.is_empty());
        assert!(void.outputs.is_empty());
    }

    #[test]
    fn registers_a_fixture_procedure_end_to_end() {
        let mut set = ProcedureSet::new();
        register(
            &mut set,
            &step(
                "test.my.proc(in :: INTEGER?) :: (out :: STRING?)",
                &["in", "out"],
                &[&["null", "'nix'"], &["42", "'answer'"]],
            ),
        )
        .expect("register");
        let mut g = graphus_cypher::graph_access::MemGraph::new();
        let rows = set
            .invoke("test.my.proc", &[Value::Integer(42)], &mut g)
            .expect("invoke");
        assert_eq!(rows, vec![vec![Value::String("answer".into())]]);
    }

    #[test]
    fn rejects_a_header_that_disagrees_with_the_signature() {
        let mut set = ProcedureSet::new();
        let err = register(
            &mut set,
            &step(
                "test.my.proc(in :: INTEGER?) :: (out :: STRING?)",
                &["out", "in"],
                &[],
            ),
        )
        .expect_err("mismatched header");
        assert!(err.contains("does not match"));
    }
}
