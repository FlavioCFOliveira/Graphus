//! Loads the TCK **named graphs** (`tck/graphs/**`) as their seed Cypher (`tck/README.adoc`
//! §"Graphs for initial states").
//!
//! A `Given the <name> graph` step requires the harness to build a specific initial state before
//! running the query under test. Each named graph ships as a `.cypher` file of `CREATE` clauses; the
//! harness reads it, strips comments and the trailing `;`, and runs it as **one** query in the
//! scenario's setup transaction. (The files are a single multi-clause `CREATE` query — variables are
//! threaded across the clauses within one statement, which is exactly what Cypher's multi-`CREATE`
//! scope allows.)

use std::path::Path;

/// Returns the seed Cypher for the TCK named graph `name` (`binary-tree-1`, `binary-tree-2`,
/// `yago`), read from `graphs_root` (`tck/graphs`).
///
/// The file layout differs per graph (the yago seed lives under a differently-cased filename), so the
/// candidate paths are tried in order. Comments are stripped and the trailing statement terminator
/// removed so the result is a single runnable query.
///
/// # Errors
///
/// Returns an error string if `name` is not a known named graph or its file cannot be read.
pub fn named_graph_cypher(graphs_root: &Path, name: &str) -> Result<String, String> {
    let candidates: &[&str] = match name {
        "binary-tree-1" => &["binary-tree-1/binary-tree-1.cypher"],
        "binary-tree-2" => &["binary-tree-2/binary-tree-2.cypher"],
        // The yago seed file is checked in with mixed-case naming; try the known spellings.
        "yago" => &[
            "yago/openCypher-yago-graph.cypher",
            "yago/opencypher-yago-graph.cypher",
            "yago/yago.cypher",
        ],
        other => return Err(format!("unknown named graph `{other}`")),
    };

    for rel in candidates {
        let path = graphs_root.join(rel);
        if let Ok(text) = std::fs::read_to_string(&path) {
            return Ok(sanitize(&text));
        }
    }
    Err(format!(
        "named graph `{name}`: none of {candidates:?} found under {}",
        graphs_root.display()
    ))
}

/// Strips C-style block comments and the trailing `;`, leaving a single runnable Cypher query.
///
/// The named-graph files open with a `/* … */` licence/description block and end with `;`; neither is
/// valid inside the single query the harness feeds the parser, so both are removed. Line content is
/// otherwise preserved (newlines are insignificant to the Cypher lexer).
fn sanitize(text: &str) -> String {
    let without_block_comments = strip_block_comments(text);
    without_block_comments
        .trim()
        .trim_end_matches(';')
        .to_owned()
}

/// Removes `/* … */` block comments (the only comment form the named-graph files use).
fn strip_block_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        match rest[start..].find("*/") {
            Some(end) => rest = &rest[start + end + 2..],
            None => {
                // Unterminated comment: drop the remainder (defensive; the corpus is well-formed).
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_a_leading_block_comment_and_trailing_semicolon() {
        let src = "/* a\n comment */\nCREATE (a),\n       (b);\n";
        assert_eq!(sanitize(src), "CREATE (a),\n       (b)");
    }

    #[test]
    fn keeps_content_with_no_comments() {
        let src = "CREATE (a)-[:R]->(b)\n";
        assert_eq!(sanitize(src), "CREATE (a)-[:R]->(b)");
    }

    #[test]
    fn unknown_graph_errors() {
        let root = Path::new("/nonexistent");
        assert!(named_graph_cypher(root, "nope").is_err());
    }
}
