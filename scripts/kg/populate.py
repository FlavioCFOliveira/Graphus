#!/usr/bin/env python3
"""Populate the `graphus` knowledge graph from extract.py's JSON.

The graph is REBUILT, never patched: a partial patch is how a graph starts
lying. This wipes every node and re-creates the whole set in one deterministic
pass, so the graph is always exactly one extractor run.

Usage:
    scripts/kg/extract.py --rustdoc-dir ... > kg.json
    scripts/kg/populate.py kg.json [--roadmap graphus] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

BATCH = 300  # measured: 500 nodes in one create = 81 ms; 300 keeps queries small


def cypher_value(v) -> str:
    """Render a Python value as a Cypher literal.

    Property values are stored VERBATIM. Re-probed 2026-07-16: the `rmp graph`
    guard-rail classifies by operation clause and does NOT trip on clause words
    inside string literals -- `set_password`, `delete_all` and even a standalone
    uppercase `MATCH the pattern` all create cleanly. Rewording a real value to
    dodge the guard-rail would put a false fact in the graph.
    """
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    return json.dumps(str(v))  # JSON escaping is valid Cypher double-quoted string


def cypher_map(d: dict) -> str:
    return "{" + ", ".join(f"{k}: {cypher_value(v)}" for k, v in sorted(d.items())) + "}"


def run(roadmap: str, sub: str, query: str, dry: bool) -> None:
    if dry:
        print(f"--- {sub} ---\n{query[:400]}{'...' if len(query) > 400 else ''}\n")
        return
    p = subprocess.run(
        ["rmp", "graph", sub, "-r", roadmap], input=query,
        capture_output=True, text=True,
    )
    if p.returncode != 0 or '"ok"' not in p.stdout:
        err = "\n".join(
            ln for ln in p.stderr.split("\n")
            if ln and not ln.startswith(("Warning:", "AI agents:"))
        )
        raise SystemExit(
            f"FATAL: rmp graph {sub} failed (rc={p.returncode})\n"
            f"stderr: {err}\nquery head: {query[:300]}"
        )


def chunks(xs: list, n: int):
    for i in range(0, len(xs), n):
        yield xs[i:i + n]


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
        p = subprocess.run(["rmp", "graph", "delete", "-r", args.roadmap],
                           input="MATCH (n) DETACH DELETE n",
                           capture_output=True, text=True)
        if p.returncode != 0:
            raise SystemExit(f"FATAL: wipe failed: {p.stderr[:300]}")
        print("wiped", file=sys.stderr)

    # 2. the Build node: what this graph IS a snapshot of ------------------
    build = dict(stamp)
    build["targets"] = ",".join(meta["targets"])
    run(args.roadmap, "create", f"CREATE (n:Build {cypher_map(build)})", args.dry_run)

    # 3. nodes, batched per label ------------------------------------------
    by_label: dict[str, list] = {}
    for n in nodes:
        by_label.setdefault(n["label"], []).append(n)
    for label, items in sorted(by_label.items()):
        done = 0
        for batch in chunks(items, BATCH):
            rows = []
            for n in batch:
                props = dict(n["id"])
                props.update({k: v for k, v in n["props"].items() if v is not None})
                props.update(stamp)
                rows.append(cypher_map(props))
            _create_nodes(args.roadmap, label, rows, args.dry_run)
            done += len(batch)
        print(f"  {label}: {done}", file=sys.stderr)

    # 4. edges, batched per type -------------------------------------------
    by_type: dict[str, list] = {}
    for e in edges:
        by_type.setdefault(e["type"], []).append(e)
    for etype, items in sorted(by_type.items()):
        done = 0
        for batch in chunks(items, BATCH):
            _create_edges(args.roadmap, etype, batch, stamp, args.dry_run)
            done += len(batch)
        print(f"  {etype}: {done}", file=sys.stderr)

    print("populate done", file=sys.stderr)
    return 0


def _create_nodes(roadmap: str, label: str, rows: list[str], dry: bool) -> None:
    """One CREATE per batch. `graph create` forbids SET, so every property is
    written inline in the CREATE pattern."""
    pats = ", ".join(f"(:{label} {r})" for r in rows)
    run(roadmap, "create", f"CREATE {pats}", dry)


def _create_edges(roadmap: str, etype: str, batch: list, stamp: dict, dry: bool) -> None:
    """UNWIND the endpoints + MATCH both by identity + MERGE the edge.

    Edge properties that participate in identity (DEPENDS_ON.kind / .target) go
    INSIDE the MERGE pattern: `graphus-rest -> graphus-auth` exists as both a
    normal and a dev dependency, and collapsing them would drop a true fact.

    Edge properties MUST be written as Cypher LITERALS, never as references to an
    UNWIND row variable. Proven against the live binary 2026-07-16:

        UNWIND [{f:'a',t:'b',pk:'normal'}] AS r MATCH ... MERGE (x)-[:E {kind: r.pk}]->(y)
            -> e.kind IS NULL          (silently! no error)
        ... MERGE (x)-[:E {kind: 'normal'}]->(y)
            -> e.kind = 'normal'       (correct)

    A relationship property map does not resolve row variables; it writes null and
    reports success. With every kind nulled, MERGE then dedups `normal` and `dev`
    into ONE edge -- 292 real dependencies silently became 276. So group by the
    property VALUES and emit them as literals. (Node property maps DO resolve row
    variables correctly, which is why only edges are affected.)
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
        run(roadmap, "create", q, dry)


if __name__ == "__main__":
    sys.exit(main())
