//! `mix` — the seeded **LPG workload generator** shared by every VOPR driver (rmp #165).
//!
//! One generator produces the operation stream; the drivers (the direct [`crate::vopr`] path, the
//! Bolt client and the REST client in [`crate::wire`]) all execute the *same* ops, so a workload is
//! defined once and replayed identically across connection methods. A [`MixProfile`] weights the op
//! classes (write-heavy, read-heavy, OLTP-light, mixed…) and a [`LoadProfile`] shapes how arrivals
//! spread over the scheduler's logical time (steady / ramp / spike). Everything is a pure function of
//! the seeded [`SimRng`].

use graphus_core::Value;
use graphus_sim::SimRng;

/// One workload operation. Each maps to a concrete Cypher statement via [`WorkloadOp::to_cypher`], so
/// the same op runs identically over the direct engine, Bolt, or REST.
///
/// # Variant set and the determinism contract (rmp #461)
///
/// The first four variants ([`WorkloadOp::CreateNode`] … [`WorkloadOp::Neighbors`]) are the *original*
/// contended-workload vocabulary that [`WorkloadGen`] draws from. The last two
/// ([`WorkloadOp::SetProperty`] and [`WorkloadOp::DeleteNode`]) were added by rmp #461 to give the
/// reference-model oracle teeth over **property values** and **delete churn** — but they are
/// **deliberately not** produced by [`WorkloadGen::next`]. Keeping the default generator's RNG draw
/// arithmetic unchanged is what lets every existing seed replay **byte-for-byte identically** (the
/// determinism gate). The new ops are generated only by the dedicated property/index oracle driver
/// ([`crate::vopr_property`]), which mirrors them in an extended shadow model. Every field is a `Copy`
/// scalar (no `String`), so `WorkloadOp: Copy` still holds — the per-client op buffers depend on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadOp {
    /// Create a `:Person` node with a monotonic id (a write).
    CreateNode { id: i64 },
    /// Relate two existing persons with `:KNOWS` (a write; parallel edges + self-loops allowed).
    CreateEdge { a: i64, b: i64 },
    /// Count all persons (a light aggregate read).
    CountNodes,
    /// One-hop `:KNOWS` neighbourhood of a person (a traversal read).
    Neighbors { a: i64 },
    /// Set the `rank` property of **every** `:Person` carrying id `id` to `val` (a write). Mirrors the
    /// engine's `MATCH … SET` Cartesian fan-out: it updates `mult(id)` nodes. Added by rmp #461 so the
    /// oracle can catch a wrong *property value* under contention (e.g. an SSI rollback restoring a
    /// stale pre-image over a committed `SET`) — a class the id/edge multisets alone are blind to.
    SetProperty { id: i64, val: i64 },
    /// Delete **every** `:Person` carrying id `id`, detaching its incident `:KNOWS` edges
    /// (`DETACH DELETE`, a write). Added by rmp #461 so the oracle covers delete churn (multiplicity →
    /// 0, incident edges cascaded) rather than create-only growth.
    DeleteNode { id: i64 },
}

impl WorkloadOp {
    /// A stable label for the trace / distribution accounting.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            WorkloadOp::CreateNode { .. } => "create_node",
            WorkloadOp::CreateEdge { .. } => "create_edge",
            WorkloadOp::CountNodes => "count_nodes",
            WorkloadOp::Neighbors { .. } => "neighbors",
            WorkloadOp::SetProperty { .. } => "set_property",
            WorkloadOp::DeleteNode { .. } => "delete_node",
        }
    }

    /// `true` if the op writes (so a driver can pick the transaction access mode).
    #[must_use]
    pub fn is_write(self) -> bool {
        matches!(
            self,
            WorkloadOp::CreateNode { .. }
                | WorkloadOp::CreateEdge { .. }
                | WorkloadOp::SetProperty { .. }
                | WorkloadOp::DeleteNode { .. }
        )
    }

    /// The Cypher statement + bound parameters for this op.
    #[must_use]
    pub fn to_cypher(self) -> (&'static str, Vec<(String, Value)>) {
        match self {
            WorkloadOp::CreateNode { id } => (
                "CREATE (:Person {id: $id})",
                vec![("id".to_owned(), Value::Integer(id))],
            ),
            WorkloadOp::CreateEdge { a, b } => (
                "MATCH (a:Person {id: $a}), (b:Person {id: $b}) CREATE (a)-[:KNOWS]->(b)",
                vec![
                    ("a".to_owned(), Value::Integer(a)),
                    ("b".to_owned(), Value::Integer(b)),
                ],
            ),
            WorkloadOp::CountNodes => ("MATCH (n:Person) RETURN count(n) AS c", vec![]),
            WorkloadOp::Neighbors { a } => (
                "MATCH (:Person {id: $a})-[:KNOWS]->(b) RETURN b.id AS id ORDER BY b.id",
                vec![("a".to_owned(), Value::Integer(a))],
            ),
            // Set the `rank` of every `:Person` with this id. `MATCH … SET` updates every match, so
            // multiplicity > 1 sets them all to the same `val` — exactly what the shadow model mirrors.
            WorkloadOp::SetProperty { id, val } => (
                "MATCH (n:Person {id: $id}) SET n.rank = $val",
                vec![
                    ("id".to_owned(), Value::Integer(id)),
                    ("val".to_owned(), Value::Integer(val)),
                ],
            ),
            // Delete every `:Person` with this id and detach its `:KNOWS` edges (multigraph: a duplicate
            // id deletes all of them at once, cascading every incident edge).
            WorkloadOp::DeleteNode { id } => (
                "MATCH (n:Person {id: $id}) DETACH DELETE n",
                vec![("id".to_owned(), Value::Integer(id))],
            ),
        }
    }
}

/// Relative weights over the op classes. The generator draws an op class proportional to its weight;
/// a zero-weight class never occurs. Presets cover the canonical realistic mixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MixProfile {
    /// Weight of `CreateNode`.
    pub create_node: u32,
    /// Weight of `CreateEdge`.
    pub create_edge: u32,
    /// Weight of `CountNodes`.
    pub count_nodes: u32,
    /// Weight of `Neighbors`.
    pub neighbors: u32,
}

impl MixProfile {
    /// Write-dominated (bulk ingest / heavy mutation): mostly node + edge creates.
    #[must_use]
    pub fn write_heavy() -> Self {
        Self {
            create_node: 50,
            create_edge: 35,
            count_nodes: 5,
            neighbors: 10,
        }
    }

    /// Read-dominated (serving traffic): mostly reads, a trickle of writes.
    #[must_use]
    pub fn read_heavy() -> Self {
        Self {
            create_node: 8,
            create_edge: 7,
            count_nodes: 35,
            neighbors: 50,
        }
    }

    /// OLTP-light: small, balanced point operations.
    #[must_use]
    pub fn oltp_light() -> Self {
        Self {
            create_node: 25,
            create_edge: 25,
            count_nodes: 25,
            neighbors: 25,
        }
    }

    /// A balanced general mix (the default).
    #[must_use]
    pub fn mixed() -> Self {
        Self {
            create_node: 40,
            create_edge: 30,
            count_nodes: 15,
            neighbors: 15,
        }
    }

    /// The sum of all weights.
    #[must_use]
    pub fn total(self) -> u32 {
        self.create_node + self.create_edge + self.count_nodes + self.neighbors
    }
}

impl Default for MixProfile {
    fn default() -> Self {
        Self::mixed()
    }
}

/// The stateful workload generator: draws ops by [`MixProfile`] weight and allocates node ids
/// monotonically so the id space is a pure function of the op stream.
#[derive(Debug, Clone)]
pub struct WorkloadGen {
    mix: MixProfile,
    next_id: i64,
}

impl WorkloadGen {
    /// Creates a generator for `mix`, with an empty graph.
    #[must_use]
    pub fn new(mix: MixProfile) -> Self {
        Self { mix, next_id: 0 }
    }

    /// The number of nodes created so far (the id space upper bound).
    #[must_use]
    pub fn node_count(&self) -> i64 {
        self.next_id
    }

    /// Draws the next op from `rng`. While the graph is empty it always creates a node (so reads and
    /// edges have something to reference); thereafter it picks an op class by weight, falling back to
    /// `CreateNode` if a write-edge/read class is drawn against an empty id space.
    pub fn next(&mut self, rng: &mut SimRng) -> WorkloadOp {
        if self.next_id == 0 {
            return self.alloc_node();
        }
        let total = self.mix.total();
        if total == 0 {
            return self.alloc_node();
        }
        let pick = rng.below(u64::from(total)) as u32;
        let m = self.mix;
        let count = self.next_id.max(0) as u64;
        if pick < m.create_node {
            self.alloc_node()
        } else if pick < m.create_node + m.create_edge {
            let a = rng.below(count) as i64;
            let b = rng.below(count) as i64;
            WorkloadOp::CreateEdge { a, b }
        } else if pick < m.create_node + m.create_edge + m.count_nodes {
            WorkloadOp::CountNodes
        } else {
            let a = rng.below(count) as i64;
            WorkloadOp::Neighbors { a }
        }
    }

    /// Allocates the next monotonic node id and returns a `CreateNode` for it.
    fn alloc_node(&mut self) -> WorkloadOp {
        let id = self.next_id;
        self.next_id += 1;
        WorkloadOp::CreateNode { id }
    }
}

/// Shapes how operations arrive over the scheduler's logical time. The returned delay (ns from the
/// previous arrival) is what a driver passes to `SimScheduler::schedule_after`, so the load curve is
/// reproducible from the seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LoadProfile {
    /// Constant inter-arrival delay jittered within `[min, max]`.
    Steady { min: u64, max: u64 },
    /// Inter-arrival delay shrinking linearly from `start` to `end` across the run (accelerating
    /// load — a ramp). `step`/`total` locate the current arrival on the ramp.
    Ramp { start: u64, end: u64 },
    /// A steady base delay with periodic bursts: every `period` ops, `burst` ops arrive back-to-back
    /// (delay 0) to model a spike.
    Spike { base: u64, period: u64, burst: u64 },
}

impl LoadProfile {
    /// The inter-arrival delay for arrival `step` of `total`, drawn from `rng` where the profile is
    /// stochastic. Deterministic given the seed.
    pub fn arrival_delay(self, rng: &mut SimRng, step: u64, total: u64) -> u64 {
        match self {
            LoadProfile::Steady { min, max } => rng.range_inclusive(min, max),
            LoadProfile::Ramp { start, end } => {
                let total = total.max(1);
                // Linear interpolation from `start` down/up to `end` across the run.
                let (lo, hi, ascending) = if start >= end {
                    (end, start, false)
                } else {
                    (start, end, true)
                };
                let span = hi - lo;
                let frac = (step.min(total)) * span / total;
                if ascending { lo + frac } else { hi - frac }
            }
            LoadProfile::Spike {
                base,
                period,
                burst,
            } => {
                let period = period.max(1);
                let phase = step % period;
                if phase < burst { 0 } else { base }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn distribution(mix: MixProfile, seed: u64, n: usize) -> BTreeMap<&'static str, usize> {
        let mut rng = SimRng::new(seed);
        let mut wgen = WorkloadGen::new(mix);
        let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
        for _ in 0..n {
            let op = wgen.next(&mut rng);
            *counts.entry(op.label()).or_default() += 1;
        }
        counts
    }

    #[test]
    fn generator_is_deterministic() {
        let a = distribution(MixProfile::mixed(), 7, 500);
        let b = distribution(MixProfile::mixed(), 7, 500);
        assert_eq!(a, b, "same seed + mix ⇒ identical op distribution");
    }

    #[test]
    fn write_heavy_mix_creates_more_than_it_reads() {
        let d = distribution(MixProfile::write_heavy(), 3, 2000);
        let writes =
            d.get("create_node").copied().unwrap_or(0) + d.get("create_edge").copied().unwrap_or(0);
        let reads =
            d.get("count_nodes").copied().unwrap_or(0) + d.get("neighbors").copied().unwrap_or(0);
        assert!(writes > reads, "write-heavy mix is write-dominated: {d:?}");
    }

    #[test]
    fn read_heavy_mix_reads_more_than_it_writes() {
        let d = distribution(MixProfile::read_heavy(), 3, 2000);
        let writes =
            d.get("create_node").copied().unwrap_or(0) + d.get("create_edge").copied().unwrap_or(0);
        let reads =
            d.get("count_nodes").copied().unwrap_or(0) + d.get("neighbors").copied().unwrap_or(0);
        assert!(reads > writes, "read-heavy mix is read-dominated: {d:?}");
    }

    #[test]
    fn distinct_mixes_differ() {
        assert_ne!(
            distribution(MixProfile::write_heavy(), 5, 1000),
            distribution(MixProfile::read_heavy(), 5, 1000),
            "different mixes ⇒ different distributions"
        );
    }

    #[test]
    fn steady_load_is_within_bounds_and_deterministic() {
        let p = LoadProfile::Steady { min: 5, max: 15 };
        let mut r1 = SimRng::new(9);
        let mut r2 = SimRng::new(9);
        for step in 0..100 {
            let d1 = p.arrival_delay(&mut r1, step, 100);
            let d2 = p.arrival_delay(&mut r2, step, 100);
            assert_eq!(d1, d2, "same seed ⇒ same delays");
            assert!((5..=15).contains(&d1), "steady delay within bounds: {d1}");
        }
    }

    #[test]
    fn ramp_load_accelerates() {
        // Descending inter-arrival delay = accelerating load.
        let p = LoadProfile::Ramp { start: 100, end: 0 };
        let mut rng = SimRng::new(1);
        let first = p.arrival_delay(&mut rng, 0, 100);
        let last = p.arrival_delay(&mut rng, 100, 100);
        assert!(first > last, "ramp accelerates: {first} -> {last}");
    }

    #[test]
    fn spike_load_bursts_then_settles() {
        let p = LoadProfile::Spike {
            base: 50,
            period: 10,
            burst: 3,
        };
        let mut rng = SimRng::new(1);
        // Within a period: first `burst` arrivals are back-to-back (0), the rest pay `base`.
        assert_eq!(p.arrival_delay(&mut rng, 0, 100), 0);
        assert_eq!(p.arrival_delay(&mut rng, 2, 100), 0);
        assert_eq!(p.arrival_delay(&mut rng, 5, 100), 50);
    }
}
