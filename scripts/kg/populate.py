#!/usr/bin/env python3
"""Populate the `graphus` knowledge graph from extract.py's JSON.

The graph is REBUILT, never patched: a partial patch is how a graph starts
lying. This wipes every node and re-creates the whole set in one deterministic
pass, so the graph is always exactly one extractor run.

Transport: every statement is sent with `rmp graph client`, which reaches the
graph only through a live `rmp graph serve` for the roadmap (rebuild.sh starts
one when none answers). The client runs ONE statement per invocation, under a
5-second server-side time budget (a cancelled statement writes nothing) and a
1,048,576-byte statement limit. Every batch below is sized to stay well inside
both, every non-zero exit is fatal, and every write is checked against its
`counters` block and, at the end, against a read-back of the whole graph.

Usage:
    scripts/kg/extract.py --rustdoc-dir ... > kg.json
    scripts/kg/populate.py kg.json [--roadmap graphus] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterator
from typing import TypeVar

T = TypeVar("T")

# `rmp graph client` refuses (exit 6) a statement longer than this.
MAX_STATEMENT_BYTES = 1_048_576
# Rows per write statement. Measured on rmp 1.17.3 (2026-09-23, 14,333 nodes,
# 18,646 edges): slowest statement 0.18 s against the 5 s budget, largest
# statement 128,023 bytes.
BATCH = 300
# Rendered row bytes per write statement: a quarter of the hard limit, so the
# statement's fixed text can never push a batch over it.
BATCH_BYTES = MAX_STATEMENT_BYTES // 4
# Edges, then nodes, per delete statement in the wipe. Measured on rmp 1.17.3:
# 5,000 edges in 0.07 s, 5,000 nodes in 0.36 s.
WIPE_BATCH = 5000

STATS = {"statements": 0, "slowest_s": 0.0, "largest_bytes": 0}


def cypher_value(v) -> str:
    """Render a Python value as a Cypher literal.

    Property values are stored VERBATIM. `rmp graph client` does not examine a
    statement, so clause words inside string literals (`set_password`,
    `delete_all`, an uppercase `MATCH the pattern`) are plain data. Rewording a
    real value would put a false fact in the graph.
    """
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    return json.dumps(str(v))  # JSON escaping is valid Cypher double-quoted string


def cypher_map(d: dict) -> str:
    return "{" + ", ".join(f"{k}: {cypher_value(v)}" for k, v in sorted(d.items())) + "}"


def client(roadmap: str, query: str) -> dict:
    """Send ONE statement through `rmp graph client`; return its parsed JSON.

    Any refusal is fatal: a statement over the byte limit (checked here, before
    sending), a non-zero exit (no server, a parse/execution error, the 5 s
    budget exhausted -- which wrote nothing), or output that is not JSON.
    """
    size = len(query.encode("utf-8"))
    if size > MAX_STATEMENT_BYTES:
        raise SystemExit(
            f"FATAL: statement is {size} bytes; rmp graph client accepts at most "
            f"{MAX_STATEMENT_BYTES}\nquery head: {query[:300]}"
        )
    t0 = time.monotonic()
    p = subprocess.run(
        ["rmp", "graph", "client", "-r", roadmap], input=query,
        capture_output=True, text=True,
    )
    elapsed = time.monotonic() - t0
    STATS["statements"] += 1
    STATS["slowest_s"] = max(STATS["slowest_s"], elapsed)
    STATS["largest_bytes"] = max(STATS["largest_bytes"], size)
    if p.returncode != 0:
        err = "\n".join(
            ln for ln in p.stderr.split("\n")
            if ln and not ln.startswith(("Warning:", "AI agents"))
        )
        raise SystemExit(
            f"FATAL: rmp graph client failed (rc={p.returncode}, {elapsed:.2f} s)\n"
            f"stderr: {err}\nquery head: {query[:300]}"
        )
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"FATAL: rmp graph client printed non-JSON ({exc})\n"
            f"stdout head: {p.stdout[:300]}\nquery head: {query[:300]}"
        ) from exc


def write(roadmap: str, query: str, dry: bool) -> dict:
    """Run one write statement; return its `counters` ({} if nothing changed)."""
    if dry:
        print(f"--- write ---\n{query[:400]}{'...' if len(query) > 400 else ''}\n")
        return {}
    out = client(roadmap, query)
    if out.get("ok") is not True:
        raise SystemExit(
            f"FATAL: write did not report ok: {json.dumps(out)[:300]}\n"
            f"query head: {query[:300]}"
        )
    return out.get("counters", {})


def read(roadmap: str, query: str) -> list[list]:
    out = client(roadmap, query)
    if "rows" not in out:
        raise SystemExit(f"FATAL: read returned no rows: {json.dumps(out)[:300]}\n{query[:300]}")
    return out["rows"]


def expect(counters: dict, key: str, want: int, what: str, query: str) -> None:
    """A write's counters must show exactly what it was meant to do."""
    got = counters.get(key, 0)
    if got != want:
        raise SystemExit(
            f"FATAL: {what}: {key}={got}, expected {want}\n"
            f"counters: {counters}\nquery head: {query[:300]}"
        )


def batches(items: list[T], max_rows: int, max_bytes: int,
            size: Callable[[T], int]) -> Iterator[list[T]]:
    """Split items into runs of at most `max_rows` items and `max_bytes` of
    rendered text (a single item larger than `max_bytes` travels alone and is
    then checked against the hard limit in `client`)."""
    cur: list[T] = []
    cur_bytes = 0
    for it in items:
        b = size(it) + 2  # the ", " separator
        if cur and (len(cur) >= max_rows or cur_bytes + b > max_bytes):
            yield cur
            cur, cur_bytes = [], 0
        cur.append(it)
        cur_bytes += b
    if cur:
        yield cur


def wipe(roadmap: str) -> tuple[int, int]:
    """Delete every edge, then every node, in bounded batches.

    One `MATCH (n) DETACH DELETE n` over the whole graph risks the 5 s budget,
    and a cancelled statement writes nothing, so each batch is its own committed
    statement. Edges go first, and nodes then take a plain DELETE, which the
    engine refuses for a node that still has an edge. Measured on rmp 1.17.3: a
    LIMIT-batched DETACH DELETE can leave an edge of a deleted node in the store,
    invisible to MATCH, until its other endpoint is deleted. Deleting the edges
    explicitly first keeps the wipe independent of that behaviour. The deleted
    counts must equal the counts read before, and a read-back must find zero.
    """
    n_edges = read(roadmap, "MATCH ()-[e]->() RETURN count(e)")[0][0]
    n_nodes = read(roadmap, "MATCH (n) RETURN count(n)")[0][0]
    e_del = _drain(roadmap, f"MATCH ()-[e]->() WITH e LIMIT {WIPE_BATCH} DELETE e",
                   "relationshipsDeleted", n_edges)
    n_del = _drain(roadmap, f"MATCH (n) WITH n LIMIT {WIPE_BATCH} DELETE n",
                   "nodesDeleted", n_nodes)
    left_n = read(roadmap, "MATCH (n) RETURN count(n)")[0][0]
    left_e = read(roadmap, "MATCH ()-[e]->() RETURN count(e)")[0][0]
    if (e_del, n_del, left_e, left_n) != (n_edges, n_nodes, 0, 0):
        raise SystemExit(
            f"FATAL: wipe deleted {n_del}/{n_nodes} nodes and {e_del}/{n_edges} "
            f"edges, and left {left_n} nodes and {left_e} edges"
        )
    return n_del, e_del


def _drain(roadmap: str, query: str, counter: str, total: int) -> int:
    """Repeat one batched delete until it deletes nothing; return the sum."""
    done = 0
    for _ in range(total // WIPE_BATCH + 2):
        n = write(roadmap, query, False).get(counter, 0)
        if n == 0:
            return done
        done += n
    raise SystemExit(f"FATAL: wipe did not converge after {done} of {total}: {query}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("kg_json")
    ap.add_argument("--roadmap", default="graphus")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    data = json.load(open(args.kg_json))
    meta, nodes, edges = data["meta"], data["nodes"], data["edges"]
    stamp = {"gitCommit": meta["gitCommit"], "gitDate": meta["gitDate"]}

    # 1. wipe -------------------------------------------------------------
    if not args.dry_run:
        n_del, e_del = wipe(args.roadmap)
        print(f"wiped {n_del} nodes, {e_del} edges", file=sys.stderr)

    # 2. the Build node: what this graph IS a snapshot of ------------------
    build = dict(stamp)
    build["targets"] = ",".join(meta["targets"])
    q = f"CREATE (n:Build {cypher_map(build)})"
    c = write(args.roadmap, q, args.dry_run)
    if not args.dry_run:
        expect(c, "nodesCreated", 1, "CREATE :Build", q)

    # 3. nodes, batched per label ------------------------------------------
    by_label: dict[str, list] = {}
    for n in nodes:
        by_label.setdefault(n["label"], []).append(n)
    for label, items in sorted(by_label.items()):
        rows = []
        for n in items:
            props = dict(n["id"])
            props.update({k: v for k, v in n["props"].items() if v is not None})
            props.update(stamp)
            rows.append(cypher_map(props))
        done = 0
        for batch in batches(rows, BATCH, BATCH_BYTES, size=_utf8_len):
            _create_nodes(args.roadmap, label, batch, args.dry_run)
            done += len(batch)
        print(f"  {label}: {done}", file=sys.stderr)

    # 4. edges, batched per type -------------------------------------------
    by_type: dict[str, list] = {}
    for e in edges:
        by_type.setdefault(e["type"], []).append(e)
    for etype, items in sorted(by_type.items()):
        done = 0
        for batch in batches(items, BATCH, BATCH_BYTES, size=_endpoints_len):
            _create_edges(args.roadmap, etype, batch, stamp, args.dry_run)
            done += len(batch)
        print(f"  {etype}: {done}", file=sys.stderr)

    # 5. read-back: a MATCH that binds nothing reports success, so the counters
    #    alone cannot prove the graph; the census must equal the extract. ----
    if not args.dry_run:
        _verify_census(args.roadmap, nodes, edges)

    print(f"populate done: {STATS['statements']} statements, slowest "
          f"{STATS['slowest_s']:.2f} s (budget 5 s), largest "
          f"{STATS['largest_bytes']} bytes (limit {MAX_STATEMENT_BYTES})",
          file=sys.stderr)
    return 0


def _create_nodes(roadmap: str, label: str, rows: list[str], dry: bool) -> None:
    """One CREATE per batch, every property written inline in the pattern."""
    pats = ", ".join(f"(:{label} {r})" for r in rows)
    q = f"CREATE {pats}"
    c = write(roadmap, q, dry)
    if not dry:
        expect(c, "nodesCreated", len(rows), f"CREATE {len(rows)} :{label}", q)


def _utf8_len(row: str) -> int:
    return len(row.encode("utf-8"))


def _endpoints_len(e: dict) -> int:
    """Upper bound of the bytes one edge adds to its UNWIND list."""
    return len(json.dumps([e["from"], e["to"]]).encode("utf-8"))


def _create_edges(roadmap: str, etype: str, batch: list, stamp: dict, dry: bool) -> None:
    """UNWIND the endpoints + MATCH both by identity + MERGE the edge.

    Edge properties that participate in identity (DEPENDS_ON.kind / .target) go
    INSIDE the MERGE pattern: `graphus-rest -> graphus-auth` exists as both a
    normal and a dev dependency, and collapsing them would drop a true fact.

    Edge properties are written as Cypher LITERALS, never as references to an
    UNWIND row variable. Proven against the rmp binary of 2026-07-16:

        UNWIND [{f:'a',t:'b',pk:'normal'}] AS r MATCH ... MERGE (x)-[:E {kind: r.pk}]->(y)
            -> e.kind IS NULL          (silently! no error)
        ... MERGE (x)-[:E {kind: 'normal'}]->(y)
            -> e.kind = 'normal'       (correct)

    That binary did not resolve row variables in a relationship property map; it
    wrote null and reported success, and MERGE then collapsed `normal` and `dev`
    into ONE edge -- 292 real dependencies silently became 276. Re-probed on rmp
    1.17.3 (2026-09-23), the row-variable form resolves correctly (MERGE and
    CREATE alike). The literal form is kept: it is correct on both binaries. So
    rows are grouped by the property VALUES, which are emitted as literals.
    """
    groups: dict[tuple, list[str]] = {}
    for e in batch:
        f_key = next(k for k in e["from"] if k != "label")
        t_key = next(k for k in e["to"] if k != "label")
        gkey = (e["from"]["label"], f_key, e["to"]["label"], t_key,
                tuple(sorted(e["props"].items())))
        groups.setdefault(gkey, []).append(
            cypher_map({"f": e["from"][f_key], "t": e["to"][t_key]})
        )

    for (fl, fk, tl, tk, pitems), grows in groups.items():
        eprops = {k: cypher_value(v) for k, v in pitems}
        eprops.update({k: cypher_value(v) for k, v in stamp.items()})
        emap = "{" + ", ".join(f"{k}: {v}" for k, v in sorted(eprops.items())) + "}"
        q = (f"UNWIND [{', '.join(grows)}] AS r "
             f"MATCH (a:{fl} {{{fk}: r.f}}), (b:{tl} {{{tk}: r.t}}) "
             f"MERGE (a)-[:{etype} {emap}]->(b)")
        c = write(roadmap, q, dry)
        if not dry:
            # The graph was wiped, so every row must create exactly one edge: a
            # shortfall is an endpoint the MATCH did not bind, or a duplicate.
            expect(c, "relationshipsCreated", len(grows),
                   f"MERGE {len(grows)} :{etype} ({fl}->{tl})", q)


def _verify_census(roadmap: str, nodes: list, edges: list) -> None:
    want_n = Counter(n["label"] for n in nodes)
    want_n["Build"] += 1
    want_e = Counter(e["type"] for e in edges)
    got_n = Counter({r[0]: r[1] for r in read(
        roadmap, "MATCH (n) UNWIND labels(n) AS l RETURN l, count(*)")})
    got_e = Counter({r[0]: r[1] for r in read(
        roadmap, "MATCH ()-[e]->() RETURN type(e), count(*)")})
    if got_n != want_n or got_e != want_e:
        raise SystemExit(
            "FATAL: graph census differs from the extract\n"
            f"nodes  want {dict(sorted(want_n.items()))}\n"
            f"       got  {dict(sorted(got_n.items()))}\n"
            f"edges  want {dict(sorted(want_e.items()))}\n"
            f"       got  {dict(sorted(got_e.items()))}"
        )
    print(f"census: {sum(got_n.values())} nodes, {sum(got_e.values())} edges "
          "(matches the extract)", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
