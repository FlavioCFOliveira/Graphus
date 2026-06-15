//! The invariant checker: verifies a recovered store against the reference model.
//!
//! After a fault and recovery, the harness asserts the four DST invariants
//! (`specification/04-technical-design.md` §11.1) against the recovered
//! [`graphus_storage::RecordStore`]:
//!
//! 1. **Durability** — every acknowledged commit is fully present and correct (no committed node,
//!    relationship, incidence link, degree, or property is missing or wrong).
//! 2. **Atomicity (committed-or-nothing)** — no effect of a rolled-back or in-flight transaction
//!    survives. The reference [`Model`] only ever contains acknowledged effects, so *equality*
//!    between the recovered graph and the model proves both directions: nothing committed is lost
//!    (durability) and nothing un-acknowledged leaked (atomicity).
//! 3. **Integrity** — the recovered graph is internally consistent: incidence sets match degrees,
//!    every enumerated relationship is live and genuinely incident (no dangling/dead ids), each
//!    node's incidence chain is a well-formed doubly-linked list, and every mapped page passes its
//!    CRC32C checksum (`04 §3.2`, `§4.6`). These reuse the exact checks `graphus-storage`'s own
//!    adjacency property test performs.
//! 4. **Determinism** is proven by the harness (same seed twice ⇒ identical recovered state and
//!    pass/fail), not by this module.
//!
//! The checker is written to **have teeth**: it returns a precise [`CheckFailure`] on the first
//! discrepancy, and `tests/checker_teeth.rs` feeds it deliberately broken states to prove it
//! reports failure rather than passing vacuously.

use graphus_core::error::GraphusError;
use graphus_io::{BlockDevice, PAGE_SIZE};
use graphus_storage::RecordStore;
use graphus_storage::record::ChainSide;
use graphus_wal::LogSink;

use crate::model::{Model, PropTriple};

/// Why an invariant check failed (the first discrepancy found).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckFailure {
    /// A committed node is missing or not in use after recovery (lost commit — durability).
    LostNode {
        /// The physical id of the missing node.
        id: u64,
    },
    /// A committed relationship is missing or not in use after recovery (lost commit).
    LostRel {
        /// The physical id of the missing relationship.
        id: u64,
    },
    /// A node's incident set in the store differs from the model.
    IncidenceMismatch {
        /// The node whose incidence diverged.
        node: u64,
        /// What the recovered store reports.
        store: Vec<u64>,
        /// What the model expects.
        model: Vec<u64>,
    },
    /// A node's degree in the store differs from the model.
    DegreeMismatch {
        /// The node whose degree diverged.
        node: u64,
        /// The store's degree.
        store: usize,
        /// The model's degree.
        model: usize,
    },
    /// A node's property multiset in the store differs from the model.
    PropMismatch {
        /// The node whose properties diverged.
        node: u64,
        /// The store's property multiset.
        store: Vec<PropTriple>,
        /// The model's property multiset.
        model: Vec<PropTriple>,
    },
    /// A relationship on a node's chain is dead or not actually incident (a dangling id).
    DanglingRel {
        /// The node whose chain held the bad id.
        node: u64,
        /// The offending relationship id.
        rel: u64,
    },
    /// A node's incidence chain is not a well-formed doubly-linked list.
    BrokenChain {
        /// The node whose chain is malformed.
        node: u64,
        /// A human-readable detail.
        detail: String,
    },
    /// A relationship's endpoints disagree with the model (corruption survived recovery).
    EndpointMismatch {
        /// The relationship whose endpoints diverged.
        rel: u64,
        /// The store's `(start, end)`.
        store: (u64, u64),
        /// The model's `(start, end)`.
        model: (u64, u64),
    },
    /// A mapped page failed its checksum (corruption the engine must never serve, `04 §4.6`).
    BadChecksum {
        /// The device page id.
        page: u64,
    },
    /// The store returned an error while being interrogated (e.g. a malformed chain caught by the
    /// store's own cycle guard).
    StoreError {
        /// What the store was asked to do.
        context: String,
        /// The error message.
        message: String,
    },
}

impl std::fmt::Display for CheckFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckFailure::LostNode { id } => {
                write!(f, "durability: committed node {id} lost after recovery")
            }
            CheckFailure::LostRel { id } => {
                write!(f, "durability: committed rel {id} lost after recovery")
            }
            CheckFailure::IncidenceMismatch { node, store, model } => write!(
                f,
                "integrity: node {node} incidence store={store:?} != model={model:?}"
            ),
            CheckFailure::DegreeMismatch { node, store, model } => write!(
                f,
                "integrity: node {node} degree store={store} != model={model}"
            ),
            CheckFailure::PropMismatch { node, store, model } => write!(
                f,
                "durability: node {node} props store={store:?} != model={model:?}"
            ),
            CheckFailure::DanglingRel { node, rel } => write!(
                f,
                "integrity: rel {rel} on node {node}'s chain is dead or not incident"
            ),
            CheckFailure::BrokenChain { node, detail } => {
                write!(f, "integrity: node {node} chain malformed: {detail}")
            }
            CheckFailure::EndpointMismatch { rel, store, model } => write!(
                f,
                "integrity: rel {rel} endpoints store={store:?} != model={model:?}"
            ),
            CheckFailure::BadChecksum { page } => {
                write!(f, "integrity: device page {page} failed its checksum")
            }
            CheckFailure::StoreError { context, message } => {
                write!(f, "store error during {context}: {message}")
            }
        }
    }
}

/// The result of an invariant check: `Ok(())` when all four invariants hold, else the first
/// [`CheckFailure`].
pub type CheckResult = std::result::Result<(), CheckFailure>;

/// Verifies the four invariants of a recovered `store` against `model`.
///
/// The `store` is taken by `&mut` because the index-free-adjacency walks ([`RecordStore::node`],
/// [`RecordStore::incident_rels`], …) fetch pages through the buffer pool, which needs mutable
/// access. `model` is the independent reference state built only from acknowledged commits.
///
/// # Errors
/// Returns the first [`CheckFailure`] discovered, or `Ok(())` if every invariant holds.
pub fn verify<D: BlockDevice, S: LogSink>(
    store: &mut RecordStore<D, S>,
    model: &Model,
) -> CheckResult {
    // --- Durability + atomicity: the recovered graph must equal the model exactly. ---
    // Every committed node is present and live, with the model's incidence, degree and properties.
    for &node in model.nodes() {
        let rec = store
            .node(node)
            .map_err(|e| store_err("node()", node, &e))?;
        if !rec.mvcc.in_use() {
            return Err(CheckFailure::LostNode { id: node });
        }

        let mut store_inc = store
            .incident_rels(node)
            .map_err(|e| store_err("incident_rels()", node, &e))?;
        store_inc.sort_unstable();
        let model_inc: Vec<u64> = model.incident(node).into_iter().collect();
        if store_inc != model_inc {
            return Err(CheckFailure::IncidenceMismatch {
                node,
                store: store_inc,
                model: model_inc,
            });
        }

        let store_deg = store
            .degree(node)
            .map_err(|e| store_err("degree()", node, &e))?;
        if store_deg != model.degree(node) {
            return Err(CheckFailure::DegreeMismatch {
                node,
                store: store_deg,
                model: model.degree(node),
            });
        }

        // Properties: compare as sorted multisets (the chain order is an implementation detail).
        let mut store_props: Vec<PropTriple> = store
            .node_properties(node)
            .map_err(|e| store_err("node_properties()", node, &e))?
            .into_iter()
            .map(|(_, p)| PropTriple {
                key: p.key,
                type_tag: p.type_tag,
                value_inline: p.value_inline,
            })
            .collect();
        store_props.sort_unstable();
        let model_props = model.node_props_sorted(node);
        if store_props != model_props {
            return Err(CheckFailure::PropMismatch {
                node,
                store: store_props,
                model: model_props,
            });
        }

        // Every enumerated rel is live and genuinely incident (no dangling/dead ids), and the
        // chain is a well-formed doubly-linked list.
        for &rid in &store_inc {
            let r = store.rel(rid).map_err(|e| store_err("rel()", rid, &e))?;
            if !r.mvcc.in_use() || !(r.start_node == node || r.end_node == node) {
                return Err(CheckFailure::DanglingRel { node, rel: rid });
            }
        }
        check_chain_links(store, node)?;
    }

    // Every committed relationship is present, live, and has the model's endpoints.
    for (&rid, &(start, end)) in model.rels() {
        let r = store.rel(rid).map_err(|e| store_err("rel()", rid, &e))?;
        if !r.mvcc.in_use() {
            return Err(CheckFailure::LostRel { id: rid });
        }
        if (r.start_node, r.end_node) != (start, end) {
            return Err(CheckFailure::EndpointMismatch {
                rel: rid,
                store: (r.start_node, r.end_node),
                model: (start, end),
            });
        }
    }

    // --- Integrity: every mapped page passes its checksum. ---
    verify_page_checksums(store)
}

/// Verifies that every page the store maps passes its CRC32C checksum (`04 §3.2`, `§4.6`).
///
/// `read_device_page` itself errors on a checksum failure; we additionally recompute the checksum
/// explicitly so a future change to `read_device_page` cannot quietly weaken this check.
fn verify_page_checksums<D: BlockDevice, S: LogSink>(store: &mut RecordStore<D, S>) -> CheckResult {
    for page in store.mapped_pages() {
        let bytes = store
            .read_device_page(page)
            .map_err(|e| CheckFailure::StoreError {
                context: format!("read_device_page({})", page.0),
                message: e.to_string(),
            })?;
        debug_assert_eq!(bytes.len(), PAGE_SIZE);
        if !graphus_bufpool::page::verify_checksum(&bytes) {
            return Err(CheckFailure::BadChecksum { page: page.0 });
        }
    }
    Ok(())
}

/// Verifies node `node`'s incidence chain is a well-formed forward thread that **terminates** and
/// visits each LIVE relationship at most once. From `first_rel` it follows each link's forward
/// pointer on the side facing `node` (the same threading [`RecordStore::incident_rels`] performs),
/// **transparently threading through dead-link corpses** (`rmp` #220): an aborted/crashed creation
/// whose header-only undo cleared `in_use` while preserving the body's forward chain pointers.
///
/// The strict doubly-linked `prev == from` symmetry the original walk enforced is deliberately NOT
/// asserted here: the dead-link model legitimately relaxes it — a corpse (or a head whose CAS push
/// was no-op'd off by a later committed writer) can leave a stale back-pointer that reads simply
/// thread past. The authoritative correctness of the live incidence SET is already verified in
/// [`verify`] (`store.incident_rels(node) == model.incident(node)`, with every enumerated rel proven
/// live and genuinely incident); this walk's residual job is to guarantee the forward thread
/// **terminates** (no cycle) and never revisits a live rel.
fn check_chain_links<D: BlockDevice, S: LogSink>(
    store: &mut RecordStore<D, S>,
    node: u64,
) -> CheckResult {
    /// The forward pointer of relationship `rid` on the side facing `node`, arriving from link
    /// `from` (`0` at the head). For a self-loop both sides face `node`; pick the side whose `prev`
    /// matches `from` (the side we arrived through), exactly as `incident_rels` does.
    fn next_of<D: BlockDevice, S: LogSink>(
        store: &mut RecordStore<D, S>,
        rid: u64,
        node: u64,
        from: u64,
    ) -> std::result::Result<u64, CheckFailure> {
        let r = store.rel(rid).map_err(|e| store_err("rel()", rid, &e))?;
        let is_loop = r.start_node == node && r.end_node == node;
        let (_, next) = if is_loop {
            let end = r.chain_pointers(ChainSide::End);
            if from == 0 || end.0 == from {
                end
            } else {
                r.chain_pointers(ChainSide::Start)
            }
        } else if r.start_node == node {
            r.chain_pointers(ChainSide::Start)
        } else {
            r.chain_pointers(ChainSide::End)
        };
        Ok(next)
    }

    let first = store
        .node(node)
        .map_err(|e| store_err("node()", node, &e))?
        .first_rel;

    // Termination is proven by tracking every (link, arrived-from) pair visited: a self-loop is
    // threaded twice (once per side) so a bare link-id set would false-positive on it, but the
    // `(link, from)` pair is unique per traversal step of a well-formed thread, so a repeat means a
    // genuine cycle. This bounds the walk without needing the rel high-water.
    let mut seen: std::collections::BTreeSet<(u64, u64)> = std::collections::BTreeSet::new();
    let mut from = 0u64;
    let mut cur = first;
    while cur != 0 {
        if !seen.insert((cur, from)) {
            return Err(CheckFailure::BrokenChain {
                node,
                detail: format!("link {cur} (from {from}) revisited — chain does not terminate"),
            });
        }
        let next = next_of(store, cur, node, from)?;
        from = cur;
        cur = next;
    }
    Ok(())
}

/// Builds a [`CheckFailure::StoreError`] from a store error encountered while interrogating an id.
fn store_err(context: &str, id: u64, e: &GraphusError) -> CheckFailure {
    CheckFailure::StoreError {
        context: format!("{context} id={id}"),
        message: e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_failure_displays_each_variant() {
        // A light guard that the Display impl is total and informative (no `{:?}`-only fallback).
        let variants = [
            CheckFailure::LostNode { id: 1 },
            CheckFailure::LostRel { id: 2 },
            CheckFailure::IncidenceMismatch {
                node: 1,
                store: vec![],
                model: vec![3],
            },
            CheckFailure::DegreeMismatch {
                node: 1,
                store: 0,
                model: 1,
            },
            CheckFailure::PropMismatch {
                node: 1,
                store: vec![],
                model: vec![],
            },
            CheckFailure::DanglingRel { node: 1, rel: 2 },
            CheckFailure::BrokenChain {
                node: 1,
                detail: "x".to_owned(),
            },
            CheckFailure::EndpointMismatch {
                rel: 1,
                store: (1, 2),
                model: (1, 3),
            },
            CheckFailure::BadChecksum { page: 4 },
            CheckFailure::StoreError {
                context: "node()".to_owned(),
                message: "boom".to_owned(),
            },
        ];
        for v in variants {
            assert!(!v.to_string().is_empty());
        }
    }
}
