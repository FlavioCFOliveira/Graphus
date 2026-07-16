#!/usr/bin/env python3
"""Adversarially audit the `graphus` knowledge graph against the repository.

Fidelity is PROVEN, not asserted: every criterion computes a symmetric difference
between the graph and an authoritative source and fails on any divergence.

Two rules keep this honest:

* **Non-circular.** C3/C15-style checks that re-run the extractor and compare it
  to the graph can only prove the graph matches the extractor -- they go green on
  a graph built from a WRONG extractor. (Proven: an early extractor emitted 61
  foreign symbols from dependency blanket-impls, and an extractor-vs-graph check
  passes on every one of them.) So the criteria below anchor to git, cargo, and
  the SOURCE TEXT ITSELF wherever they can.
* **Non-vacuous.** A criterion that examines nothing passes trivially. Each one
  reports how many elements it checked and FAILS if that count is zero.

Exit code 0 = every criterion holds. Non-zero = the number of failed criteria.

Usage: scripts/kg/audit.py [--roadmap graphus]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

ENUMS = {
    ("File", "kind"): {"src", "test", "bench", "bin", "build", "fuzz"},
    ("Symbol", "kind"): {"function", "struct", "enum", "trait", "constant",
                         "type_alias", "module", "macro", "union", "static"},
    ("Test", "kind"): {"unit", "integration", "bench", "bin"},
    ("Test", "harness"): {"test", "tokio_test", "proptest"},
    ("Decision", "status"): {"ratified", "open"},
}
IDENTITY = {
    "Crate": "name", "File": "path", "Symbol": "key", "Test": "key",
    "ExternalCrate": "name", "Commit": "hash", "Release": "tag",
    "Spec": "path", "Doc": "path", "Decision": "key", "Example": "path",
    "Build": "gitCommit",
}
# The source keyword that must appear where a Symbol claims to be declared.
KIND_KEYWORD = {
    "function": "fn", "struct": "struct", "enum": "enum", "trait": "trait",
    "constant": "const", "type_alias": "type", "module": "mod",
    "macro": "macro", "union": "union", "static": "static",
}

RESULTS: list[tuple[str, bool, str, int]] = []


def sh(*a: str) -> str:
    return subprocess.run(a, cwd=REPO, check=True, capture_output=True, text=True).stdout


def q(roadmap: str, query: str) -> list[list]:
    p = subprocess.run(["rmp", "graph", "query", "-r", roadmap],
                       input=query, capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"FATAL: query failed: {p.stderr[:200]}\n{query[:200]}")
    return json.loads(p.stdout)["rows"]


def check(name: str, ok: bool, detail: str, examined: int) -> None:
    if examined == 0:
        ok, detail = False, f"VACUOUS: examined 0 elements. {detail}"
    RESULTS.append((name, ok, detail, examined))


def diff_report(a: set, b: set, a_name: str, b_name: str, limit: int = 5) -> str:
    only_a, only_b = a - b, b - a
    if not only_a and not only_b:
        return "exact match"
    parts = []
    if only_a:
        parts.append(f"in {a_name} only ({len(only_a)}): " + ", ".join(sorted(map(str, only_a))[:limit]))
    if only_b:
        parts.append(f"in {b_name} only ({len(only_b)}): " + ", ".join(sorted(map(str, only_b))[:limit]))
    return " | ".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--roadmap", default="graphus")
    args = ap.parse_args()
    R = args.roadmap

    head = sh("git", "rev-parse", "HEAD").strip()

    # C1 files: git ls-files <-> File nodes -------------------------------
    repo_files = set(sh("git", "ls-files", "*.rs").split())
    graph_files = {r[0] for r in q(R, "MATCH (f:File) RETURN f.path")}
    check("C1 File <-> git ls-files", repo_files == graph_files,
          diff_report(repo_files, graph_files, "repo", "graph"), len(repo_files))

    # C2 crates: cargo metadata <-> Crate nodes ---------------------------
    meta = json.loads(sh("cargo", "metadata", "--no-deps", "--format-version", "1"))
    repo_crates = {p["name"] for p in meta["packages"]}
    graph_crates = {r[0] for r in q(R, "MATCH (c:Crate) RETURN c.name")}
    check("C2 Crate <-> cargo metadata", repo_crates == graph_crates,
          diff_report(repo_crates, graph_crates, "cargo", "graph"), len(repo_crates))

    # C3 symbols resolve in the SOURCE TEXT (non-circular) -----------------
    # Anchored to the file bytes, NOT to rustdoc: this is what catches a wrong
    # extractor. The 61 foreign symbols and the 2403 derive-synthesized ones both
    # fail here (foreign paths are untracked; derive spans land on `#[derive(..)]`).
    syms = q(R, "MATCH (s:Symbol) RETURN s.key, s.name, s.kind, s.file, s.line, s.col")
    cache: dict[str, list[str]] = {}
    bad: list[str] = []
    for key, name, kind, f, line, col in syms:
        if f not in repo_files:
            bad.append(f"{key}: file not tracked by git")
            continue
        if f not in cache:
            cache[f] = (REPO / f).read_text(errors="replace").split("\n")
        lines = cache[f]
        if line > len(lines):
            bad.append(f"{key}: line {line} past EOF ({len(lines)})")
            continue
        window = "\n".join(lines[line - 1: line + 2])
        kw = KIND_KEYWORD.get(kind)
        if kw and not re.search(rf"\b{kw}\b", window):
            bad.append(f"{key}: no `{kw}` at {f}:{line}")
        elif name and not re.search(rf"\b{re.escape(name)}\b", window):
            bad.append(f"{key}: name `{name}` absent at {f}:{line}")
    check("C3 Symbol declared in source text", not bad,
          "all resolve" if not bad else f"{len(bad)} bad: " + "; ".join(bad[:4]), len(syms))

    # C4 identity present + unique, for EVERY label ------------------------
    prob: list[str] = []
    total = 0
    for label, idprop in IDENTITY.items():
        rows = q(R, f"MATCH (n:{label}) RETURN n.{idprop}")
        total += len(rows)
        vals = [r[0] for r in rows]
        if any(v is None for v in vals):
            prob.append(f"{label}: {sum(v is None for v in vals)} missing {idprop}")
        dups = [v for v, c in Counter(vals).items() if c > 1]
        if dups:
            prob.append(f"{label}: {len(dups)} duplicate {idprop} e.g. {dups[:2]}")
    check("C4 identity present+unique (all labels)", not prob,
          "unique" if not prob else "; ".join(prob), total)

    # C5 dependencies: cargo metadata <-> DEPENDS_ON ----------------------
    want = set()
    for p in meta["packages"]:
        for d in p["dependencies"]:
            want.add((p["name"], d["name"], d["kind"] or "normal", str(d.get("target") or "")))
    have = {(r[0], r[1], r[2], r[3] or "") for r in q(
        R, "MATCH (a:Crate)-[e:DEPENDS_ON]->(b) RETURN a.name, b.name, e.kind, e.target")}
    check("C5 DEPENDS_ON <-> cargo metadata", want == have,
          diff_report(want, have, "cargo", "graph"), len(want))

    # C6 commits resolve in git with matching date ------------------------
    git_commits = {}
    for line in sh("git", "log", "--format=%H %cs").strip().split("\n"):
        h, d = line.split(); git_commits[h] = d
    gc = q(R, "MATCH (c:Commit) RETURN c.hash, c.date")
    bad = [f"{h[:8]}" for h, d in gc if git_commits.get(h) != d]
    check("C6 Commit <-> git log", set(git_commits) == {h for h, _ in gc} and not bad,
          diff_report(set(git_commits), {h for h, _ in gc}, "git", "graph")
          + (f" | {len(bad)} date mismatches" if bad else ""), len(gc))

    # C7 releases point at the tag's real commit --------------------------
    rel = q(R, "MATCH (r:Release)-[:AT_COMMIT]->(c:Commit) RETURN r.tag, c.hash")
    tags = set(sh("git", "tag", "-l").split())
    bad = [t for t, h in rel if sh("git", "rev-list", "-n1", t).strip() != h]
    check("C7 Release -> tagged commit", tags == {t for t, _ in rel} and not bad,
          diff_report(tags, {t for t, _ in rel}, "git", "graph")
          + (f" | wrong commit: {bad}" if bad else ""), len(rel))

    # C8 enumerated vocabularies: no off-enum, no null --------------------
    viol: list[str] = []
    n_checked = 0
    for (label, prop), allowed in ENUMS.items():
        rows = q(R, f"MATCH (n:{label}) RETURN n.{prop}, count(*)")
        for val, cnt in rows:
            n_checked += cnt
            if val is None or val not in allowed:
                viol.append(f"{label}.{prop}={val!r} x{cnt}")
    dep = q(R, "MATCH ()-[e:DEPENDS_ON]->() RETURN e.kind, count(*)")
    for val, cnt in dep:
        n_checked += cnt
        if val not in {"normal", "dev", "build"}:
            viol.append(f"DEPENDS_ON.kind={val!r} x{cnt}")
    check("C8 enumerated vocabularies", not viol,
          "all in-enum" if not viol else "; ".join(viol), n_checked)

    # C9 Commit.rmp_task is an integer or absent --------------------------
    rows = q(R, "MATCH (c:Commit) WHERE c.rmp_task IS NOT NULL RETURN c.hash, c.rmp_task")
    bad = [h for h, t in rows if not isinstance(t, int)]
    check("C9 Commit.rmp_task integer-or-absent", not bad,
          f"{len(rows)} tasks, all int" if not bad else f"non-int: {bad[:3]}", len(rows))

    # C10 no label outside the model --------------------------------------
    labels = {r[0] for r in q(R, "MATCH (n) RETURN DISTINCT labels(n)[0]")}
    check("C10 no undeclared label", labels <= set(IDENTITY),
          diff_report(labels, set(IDENTITY), "graph", "model"), len(labels))

    # C11 no edge type outside the model ----------------------------------
    declared = {"DEPENDS_ON", "CONTAINS", "DEFINES", "TOUCHES", "AT_COMMIT",
                "CITED_IN", "CITES", "DRIVEN_BY"}
    etypes = {r[0] for r in q(R, "MATCH ()-[e]->() RETURN DISTINCT type(e)")}
    check("C11 no undeclared edge type", etypes <= declared,
          diff_report(etypes, declared, "graph", "model"), len(etypes))

    # C12 provenance == the Build commit (catches a PARTIAL rebuild) ------
    # "not newer than HEAD" can never fail and would be vacuous. Equality can:
    # a half-finished rebuild leaves a mix of commits, which this catches.
    build = q(R, "MATCH (b:Build) RETURN b.gitCommit, b.targets")
    stale_n = q(R, "MATCH (n) WHERE n.gitCommit <> $h OR n.gitCommit IS NULL RETURN count(n)"
                .replace("$h", json.dumps(head)))
    stale_e = q(R, "MATCH ()-[e]->() WHERE e.gitCommit <> $h OR e.gitCommit IS NULL RETURN count(e)"
                .replace("$h", json.dumps(head)))
    n_bad = (stale_n[0][0] if stale_n else 0) + (stale_e[0][0] if stale_e else 0)
    total_el = q(R, "MATCH (n) RETURN count(n)")[0][0] + q(R, "MATCH ()-[e]->() RETURN count(e)")[0][0]
    check("C12 provenance == Build commit == HEAD",
          len(build) == 1 and build[0][0] == head and n_bad == 0,
          f"Build={build[0][0][:8] if build else 'MISSING'} HEAD={head[:8]} stale={n_bad}",
          total_el)

    # C13 paths on disk ----------------------------------------------------
    paths = [r[0] for r in q(R, "MATCH (n) WHERE n:Spec OR n:Doc OR n:Example RETURN n.path")]
    missing = [p for p in paths if not (REPO / p).exists()]
    check("C13 Spec/Doc/Example paths exist", not missing,
          "all exist" if not missing else f"missing: {missing[:4]}", len(paths))

    # C14 decisions <-> the register's canonical fence ---------------------
    reg = (REPO / "specification/02-decision-register.md").read_text()
    body = reg.split("<!-- BEGIN decision-index -->")[1].split("<!-- END decision-index -->")[0]
    row_re = re.compile(r"^\| `(D-[a-z0-9-]+)` \| (ratified|open) \|")
    want_d = {m.group(1) for m in (row_re.match(l.strip()) for l in body.split("\n")) if m}
    have_d = {r[0] for r in q(R, "MATCH (d:Decision) RETURN d.key")}
    check("C14 Decision <-> register fence", want_d == have_d,
          diff_report(want_d, have_d, "register", "graph"), len(want_d))

    # C15 Symbol and Test are disjoint ------------------------------------
    # Both are DEFINES targets of a File. If a unit test ever surfaced in rustdoc
    # it would be modelled twice -- the retired graph's double-modelling defect.
    sloc = {(r[0], r[1]) for r in q(R, "MATCH (s:Symbol) RETURN s.file, s.line")}
    tloc = {(r[0], r[1]) for r in q(R, "MATCH (t:Test) RETURN t.file, t.line")}
    overlap = sloc & tloc
    check("C15 Symbol/Test disjoint", not overlap,
          "disjoint" if not overlap else f"{len(overlap)} shared locations: {list(overlap)[:3]}",
          len(sloc) + len(tloc))

    # C16 FK agrees with the edge (two mechanisms, one fact) ---------------
    rows = q(R, "MATCH (c:Crate)-[:CONTAINS]->(f:File)-[:DEFINES]->(s:Symbol) "
                "WHERE s.crate <> c.name RETURN count(*)")
    n_mismatch = rows[0][0] if rows else 0
    tot = q(R, "MATCH (:File)-[:DEFINES]->(s:Symbol) RETURN count(s)")[0][0]
    check("C16 Symbol.crate agrees with CONTAINS/DEFINES", n_mismatch == 0,
          f"{n_mismatch} disagreements of {tot}", tot)

    # C17 tests <-> source attribute census (non-circular) -----------------
    TEST_ATTR = re.compile(r"^\s*#\[(test|tokio::test)\b")
    n_src = 0
    for p in repo_files:
        n_src += sum(1 for ln in (REPO / p).read_text(errors="replace").split("\n")
                     if TEST_ATTR.match(ln))
    n_graph = q(R, "MATCH (t:Test) RETURN count(t)")[0][0]
    check("C17 Test count <-> source #[test] census", n_src == n_graph,
          f"source={n_src} graph={n_graph}", n_src)

    # ---------------------------------------------------------------------
    width = max(len(n) for n, _, _, _ in RESULTS)
    failed = 0
    print("=" * 100)
    for name, ok, detail, n in RESULTS:
        status = "PASS" if ok else "FAIL"
        if not ok:
            failed += 1
        print(f"[{status}] {name:<{width}}  (checked {n:>6})  {detail[:110]}")
    print("=" * 100)
    print(f"{len(RESULTS) - failed}/{len(RESULTS)} criteria hold")
    return failed


if __name__ == "__main__":
    sys.exit(main())
