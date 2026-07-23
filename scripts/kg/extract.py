#!/usr/bin/env python3
"""Extract the Graphus knowledge graph from authoritative sources.

The graph is DERIVED, never hand-authored: every fact this script emits comes
from the compiler (`rustdoc --output-format json`), `cargo metadata`, or `git`.
See ./knowledge-model.md for the contract this script implements.

Output: a single JSON document {"nodes": [...], "edges": [...], "meta": {...}}
on stdout, consumed by populate.py and re-derived by audit.py.

Usage:
    scripts/kg/extract.py --rustdoc-dir DIR [--rustdoc-dir DIR ...] > kg.json

Each --rustdoc-dir is a directory of <crate>.json rustdoc files for ONE target,
named  <target-triple>=<path>  so the target each symbol was observed under is
recorded rather than assumed.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# rustdoc item kinds promoted to Symbol nodes. `impl`, `struct_field`, `variant`,
# `use` and `assoc_type` are deliberately excluded (see knowledge-model.md §6).
SYMBOL_KINDS = {
    "function", "struct", "enum", "trait",
    "constant", "type_alias", "module", "macro", "union", "static",
}


def sh(*args: str) -> str:
    return subprocess.run(
        args, cwd=REPO, check=True, capture_output=True, text=True
    ).stdout


# --------------------------------------------------------------------------
# git


def git_head() -> tuple[str, str]:
    return sh("git", "rev-parse", "HEAD").strip(), sh(
        "git", "show", "-s", "--format=%cs", "HEAD"
    ).strip()


RMP_TASK_RE = re.compile(r"rmp #(\d+)")


def extract_commits() -> tuple[list[dict], list[dict]]:
    """Commit nodes + Commit-TOUCHES->File edges.

    ALL commits, merges included: `git rev-list --count HEAD` is the ground truth
    the audit compares against, and it counts merges. A merge simply has no
    TOUCHES edges, which is true rather than hidden.

    `rmp_task` is set ONLY when the summary matches `rmp #(\\d+)`, and is an
    INTEGER. The retired graph stored 'release' and 'docs' in this property.
    """
    nodes, edges = [], []
    raw = sh("git", "log", "--format=%H%x1f%cs%x1f%s")
    tracked = set(sh("git", "ls-files", "*.rs").split())
    for line in raw.strip().split("\n"):
        h, date, summary = line.split("\x1f", 2)
        m = RMP_TASK_RE.search(summary)
        node = {"label": "Commit", "id": {"hash": h},
                "props": {"date": date, "summary": summary}}
        if m:
            node["props"]["rmp_task"] = int(m.group(1))
        nodes.append(node)

    # TOUCHES: only .rs files that still exist (a File node must be on the other
    # end). Renamed/deleted paths are dropped, not invented.
    raw = sh("git", "log", "--format=%x1e%H", "--name-only", "--no-merges", "--", "*.rs")
    for chunk in raw.split("\x1e"):
        chunk = chunk.strip()
        if not chunk:
            continue
        lines = chunk.split("\n")
        h = lines[0]
        for p in lines[1:]:
            p = p.strip()
            if p and p in tracked:
                edges.append({"type": "TOUCHES", "from": {"label": "Commit", "hash": h},
                              "to": {"label": "File", "path": p}, "props": {}})
    return nodes, edges


def extract_releases() -> tuple[list[dict], list[dict]]:
    nodes, edges = [], []
    for tag in sh("git", "tag", "-l").split():
        commit = sh("git", "rev-list", "-n1", tag).strip()
        date = sh("git", "show", "-s", "--format=%cs", commit).strip()
        nodes.append({"label": "Release", "id": {"tag": tag}, "props": {"date": date}})
        edges.append({"type": "AT_COMMIT", "from": {"label": "Release", "tag": tag},
                      "to": {"label": "Commit", "hash": commit}, "props": {}})
    return nodes, edges


# --------------------------------------------------------------------------
# cargo


def classify_file(path: str) -> str:
    """File.kind. `fuzz` exists in this repo and must not be forced into `src`."""
    parts = path.split("/")
    if path.endswith("/build.rs") or parts[-1] == "build.rs":
        return "build"
    if "tests" in parts:
        return "test"
    if "benches" in parts:
        return "bench"
    if "fuzz" in parts:
        return "fuzz"
    if "bin" in parts:
        return "bin"
    return "src"


def extract_crates() -> tuple[list[dict], list[dict]]:
    meta = json.loads(sh("cargo", "metadata", "--no-deps", "--format-version", "1"))
    members = {p["name"] for p in meta["packages"]}
    nodes, edges, ext_seen = [], [], set()

    for p in sorted(meta["packages"], key=lambda x: x["name"]):
        cpath = str(Path(p["manifest_path"]).parent.relative_to(REPO))
        nodes.append({
            "label": "Crate", "id": {"name": p["name"]},
            "props": {
                "path": cpath,
                "description": (p.get("description") or "").strip(),
                "version": p["version"],
                # The FACT is `publish = false`, not the inference "dev only".
                "publish_false": p.get("publish") == [],
            },
        })
        for d in p["dependencies"]:
            kind = d["kind"] or "normal"
            target = d.get("target")
            props = {"kind": kind}
            if target:
                # 11 deps are cfg-gated (loom, macos libc, linux rustix). Asserting
                # them unconditionally would be false for every real build.
                props["target"] = str(target)
            if d["name"] in members:
                edges.append({"type": "DEPENDS_ON", "from": {"label": "Crate", "name": p["name"]},
                              "to": {"label": "Crate", "name": d["name"]}, "props": props})
            else:
                if d["name"] not in ext_seen:
                    ext_seen.add(d["name"])
                    nodes.append({"label": "ExternalCrate", "id": {"name": d["name"]}, "props": {}})
                edges.append({"type": "DEPENDS_ON", "from": {"label": "Crate", "name": p["name"]},
                              "to": {"label": "ExternalCrate", "name": d["name"]}, "props": props})
    return nodes, edges


def extract_files() -> tuple[list[dict], list[dict]]:
    """One File node per tracked .rs file; CONTAINS from its owning crate.

    Ownership is by longest matching crate path, so nested paths cannot be
    mis-assigned.
    """
    meta = json.loads(sh("cargo", "metadata", "--no-deps", "--format-version", "1"))
    crate_paths = sorted(
        ((str(Path(p["manifest_path"]).parent.relative_to(REPO)), p["name"])
         for p in meta["packages"]),
        key=lambda x: -len(x[0]),
    )
    nodes, edges = [], []
    for path in sorted(sh("git", "ls-files", "*.rs").split()):
        owner = next((n for cp, n in crate_paths if path.startswith(cp + "/")), None)
        if owner is None:
            print(f"WARN: {path} belongs to no crate", file=sys.stderr)
            continue
        # File.crate is NOT stored: it would duplicate this CONTAINS edge and the
        # two could silently diverge (knowledge-model.md principle 5).
        nodes.append({"label": "File", "id": {"path": path},
                      "props": {"kind": classify_file(path)}})
        edges.append({"type": "CONTAINS", "from": {"label": "Crate", "name": owner},
                      "to": {"label": "File", "path": path}, "props": {}})
    return nodes, edges


# --------------------------------------------------------------------------
# rustdoc -> symbols


def load_rustdoc(target: str, docdir: Path) -> dict[str, dict]:
    """Symbols observed for ONE target, keyed by file:line:col.

    Two filters are load-bearing, each proven necessary against this repo:

    1. Spans outside `crates/` are foreign. rustdoc's index carries items from
       dependencies (61 at f360da4); keeping them would assert that another
       project's code is ours.
    2. A function whose span EQUALS its parent impl's span is compiler-
       synthesized by `#[derive(...)]` (2403 at f360da4). Its span points at a
       token inside the derive attribute -- e.g. limits.rs:45:10 is the `Debug`
       in `#[derive(Debug, Clone)]`, where no function is written. Emitting them
       would put 2403 false declarations in the graph.
    """
    out: dict[str, dict] = {}
    for jf in sorted(docdir.glob("*.json")):
        try:
            doc = json.loads(jf.read_text())
        except json.JSONDecodeError:
            print(f"WARN: unreadable rustdoc JSON {jf}", file=sys.stderr)
            continue
        idx = doc["index"]
        crate_name = jf.stem.replace("_", "-")

        # impl span per member id, and the impl's self-type name, for Symbol.owner
        impl_span: dict[str, tuple] = {}
        impl_owner: dict[str, str] = {}
        for k, v in idx.items():
            inner = v.get("inner") or {}
            if "impl" not in inner or not v.get("span"):
                continue
            s = v["span"]
            key = (s["filename"], tuple(s["begin"]))
            forty = inner["impl"].get("for") or {}
            owner = None
            if isinstance(forty, dict):
                rp = forty.get("resolved_path") or forty.get("path")
                if isinstance(rp, dict):
                    owner = (rp.get("path") or rp.get("name") or "").split("::")[-1]
            for it in inner["impl"].get("items", []):
                impl_span[str(it)] = key
                if owner:
                    impl_owner[str(it)] = owner

        for k, v in idx.items():
            inner = v.get("inner") or {}
            kind = next(iter(inner), None) if inner else None
            if kind not in SYMBOL_KINDS or not v.get("span"):
                continue
            span = v["span"]
            f = span["filename"]
            if not f.startswith("crates/"):
                continue  # filter 1: foreign
            begin = tuple(span["begin"])
            if kind == "function" and impl_span.get(str(k)) == (f, begin):
                continue  # filter 2: derive-synthesized
            if kind == "module" and list(begin) == [1, 1]:
                continue  # the module IS the file; File already models it
            key = f"{f}:{begin[0]}:{begin[1]}"
            rec = out.setdefault(key, {
                "name": v.get("name"), "kind": kind, "crate": crate_name,
                "file": f, "line": begin[0], "col": begin[1],
                "owner": impl_owner.get(str(k)),
                "targets": set(),
            })
            rec["targets"].add(target)
    return out


def extract_symbols(docdirs: dict[str, Path]) -> tuple[list[dict], list[dict], dict]:
    merged: dict[str, dict] = {}
    per_target_crates: dict[str, set] = {}
    for target, d in docdirs.items():
        per_target_crates[target] = {j.stem.replace("_", "-") for j in d.glob("*.json")}
        for key, rec in load_rustdoc(target, d).items():
            if key in merged:
                merged[key]["targets"] |= rec["targets"]
            else:
                merged[key] = rec

    nodes, edges = [], []
    for key, r in sorted(merged.items()):
        props = {"name": r["name"], "kind": r["kind"], "crate": r["crate"],
                 "file": r["file"], "line": r["line"], "col": r["col"],
                 "targets": ",".join(sorted(r["targets"]))}
        if r["owner"]:
            props["owner"] = r["owner"]
        nodes.append({"label": "Symbol", "id": {"key": key}, "props": props})
        edges.append({"type": "DEFINES", "from": {"label": "File", "path": r["file"]},
                      "to": {"label": "Symbol", "key": key}, "props": {}})
    return nodes, edges, per_target_crates


# --------------------------------------------------------------------------
# tests

TEST_ATTR = re.compile(r"^\s*#\[(test|tokio::test)\b")
FN_RE = re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")
# A double-quoted Rust string literal, escapes included. Stripped before counting
# brackets so a `[` inside an attribute's message cannot unbalance the scan.
STR_LIT = re.compile(r'"(?:[^"\\]|\\.)*"')
PROPTEST_OPEN = re.compile(r"^\s*proptest!\s*\{")
MOD_OPEN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")


def test_target_and_base(path: str, crate_path: str) -> tuple[str, str, str]:
    """(kind, cargo target, base module path) for a source file.

    The base module path is what `cargo test` needs in front of a unit test's
    name, so Test.key becomes the test's runnable address:
        cargo test -p <crate> --lib <modpath>::<name>
    Without it the key collides: `new_page_is_cached_and_readable` exists in BOTH
    graphus-bufpool's concurrent.rs and pool.rs, and both live in target `lib`.
    """
    rel = path[len(crate_path) + 1:]           # e.g. src/pool.rs, tests/foo.rs
    parts = rel.split("/")
    if parts[0] == "tests":
        return "integration", Path(rel).stem, ""
    if parts[0] == "benches":
        return "bench", Path(rel).stem, ""
    if parts[:2] == ["src", "bin"]:
        return "bin", Path(rel).stem, ""
    if parts[0] == "src":
        inner = parts[1:]
        if inner == ["lib.rs"] or inner == ["main.rs"]:
            return "unit", "lib", ""
        if inner[-1] == "mod.rs":
            inner = inner[:-1]
        else:
            inner[-1] = inner[-1][:-3] if inner[-1].endswith(".rs") else inner[-1]
        return "unit", "lib", "::".join(inner)
    return "unit", "lib", ""


def mod_path_at(lines: list[str], upto: int, base: str) -> str:
    """Inline `mod X { ... }` nesting in effect at line index `upto`."""
    stack: list[tuple[str, int]] = []
    depth = 0
    for i in range(upto):
        ln = lines[i]
        m = MOD_OPEN.match(ln)
        if m:
            stack.append((m.group(1), depth))
        depth += ln.count("{") - ln.count("}")
        while stack and depth <= stack[-1][1]:
            stack.pop()
    segs = ([base] if base else []) + [s for s, _ in stack]
    return "::".join(segs)


def extract_tests() -> tuple[list[dict], list[dict]]:
    """Test nodes from a source scan.

    Covers all three harnesses this repo actually uses (measured at f360da4):
    `#[test]` (4850), `#[tokio::test]` (309), and `fn`s inside `proptest!{}`
    blocks (7 blocks) whose signatures are not valid Rust and are invisible to a
    plain item parser.

    Test.key includes the TARGET. Without it the key collides today: e.g.
    graphus-server::schema_first_load_declares_new_index_and_constraint_kinds
    exists in 5 different integration targets. A colliding key silently drops
    nodes and makes the survivor's file/line a false claim.
    """
    meta = json.loads(sh("cargo", "metadata", "--no-deps", "--format-version", "1"))
    crate_paths = sorted(
        ((str(Path(p["manifest_path"]).parent.relative_to(REPO)), p["name"])
         for p in meta["packages"]),
        key=lambda x: -len(x[0]),
    )
    nodes, edges = [], []
    seen: dict[str, str] = {}

    for path in sorted(sh("git", "ls-files", "*.rs").split()):
        crate = next((n for cp, n in crate_paths if path.startswith(cp + "/")), None)
        if crate is None:
            continue
        crate_path = next(cp for cp, n in crate_paths if path.startswith(cp + "/"))
        kind, target, base = test_target_and_base(path, crate_path)

        text = (REPO / path).read_text(errors="replace")
        lines = text.split("\n")
        cfg_loom = any(re.match(r"^\s*#!\[cfg\(loom\)\]", ln) for ln in lines[:20])

        i = 0
        while i < len(lines):
            ln = lines[i]
            m = TEST_ATTR.match(ln)
            if m:
                harness = "tokio_test" if "tokio" in m.group(1) else "test"
                # Skip whatever may sit between the attribute and the `fn`:
                # further attributes (#[ignore], #[allow(...)], #[should_panic]),
                # blank lines, and COMMENTS. Comments are not hypothetical --
                # gorilla.rs:174 has a 3-line comment between #[test] and its fn,
                # and an attributes-and-blanks-only skip loses that test.
                #
                # An attribute may also span SEVERAL lines, so matching `#[` on one
                # line is not enough: advance until its brackets balance. Skipping
                # only the opening line stops the scan on the attribute's own
                # continuation, `FN_RE` then fails to match it, and the test is
                # dropped in silence -- store.rs:8433's multi-line `#[cfg_attr(...)]`
                # is exactly that case, and it cost audit criterion C17 one test.
                # String literals are stripped before counting so a bracket inside
                # an `ignore = "..."` reason cannot unbalance the scan.
                j = i + 1
                while j < len(lines):
                    if not lines[j].strip() or re.match(r"^\s*//", lines[j]):
                        j += 1
                        continue
                    if re.match(r"^\s*#\[", lines[j]):
                        depth = 0
                        while j < len(lines):
                            bare = STR_LIT.sub("", lines[j])
                            depth += bare.count("[") - bare.count("]")
                            j += 1
                            if depth <= 0:
                                break
                        continue
                    break
                if j < len(lines):
                    fm = FN_RE.match(lines[j])
                    if fm:
                        name = fm.group(1)
                        mp = mod_path_at(lines, j, base)
                        key = f"{crate}::{target}::{mp}::{name}" if mp else f"{crate}::{target}::{name}"
                        if key in seen:
                            # A duplicate key means the identity scheme is broken.
                            # Dropping it would silently delete a real test and make
                            # the survivor's file/line a lie -- fail loudly instead.
                            raise SystemExit(
                                f"FATAL: duplicate Test.key {key!r}\n"
                                f"  first : {seen[key]}\n  second: {path}:{j + 1}"
                            )
                        seen[key] = f"{path}:{j + 1}"
                        props = {"name": name, "crate": crate, "target": target,
                                 "module_path": mp, "file": path, "line": j + 1,
                                 "kind": kind, "harness": harness}
                        if cfg_loom:
                            props["cfg"] = "loom"
                        nodes.append({"label": "Test", "id": {"key": key}, "props": props})
                        edges.append({"type": "DEFINES",
                                      "from": {"label": "File", "path": path},
                                      "to": {"label": "Test", "key": key}, "props": {}})
                i = j
            elif PROPTEST_OPEN.match(ln):
                depth = ln.count("{") - ln.count("}")
                j = i + 1
                while j < len(lines) and depth > 0:
                    fm = FN_RE.match(lines[j])
                    if fm:
                        name = fm.group(1)
                        mp = mod_path_at(lines, j, base)
                        key = f"{crate}::{target}::{mp}::{name}" if mp else f"{crate}::{target}::{name}"
                        if key in seen:
                            raise SystemExit(
                                f"FATAL: duplicate Test.key {key!r}\n"
                                f"  first : {seen[key]}\n  second: {path}:{j + 1}"
                            )
                        seen[key] = f"{path}:{j + 1}"
                        nodes.append({"label": "Test", "id": {"key": key},
                                      "props": {"name": name, "crate": crate,
                                                "target": target, "module_path": mp,
                                                "file": path, "line": j + 1,
                                                "kind": kind, "harness": "proptest"}})
                        edges.append({"type": "DEFINES",
                                      "from": {"label": "File", "path": path},
                                      "to": {"label": "Test", "key": key}, "props": {}})
                    depth += lines[j].count("{") - lines[j].count("}")
                    j += 1
                i = j
            else:
                i += 1
    return nodes, edges


# --------------------------------------------------------------------------
# docs / specs / examples


def extract_docs() -> list[dict]:
    nodes = []
    for path in sorted(sh("git", "ls-files", "specification/*.md", "docs/*.md",
                          "docs/**/*.md").split()):
        title = ""
        for ln in (REPO / path).read_text(errors="replace").split("\n"):
            if ln.startswith("# "):
                title = ln[2:].strip()
                break
        label = "Spec" if path.startswith("specification/") else "Doc"
        nodes.append({"label": label, "id": {"path": path}, "props": {"title": title}})
    return nodes


DECISION_ROW = re.compile(
    r"^\| `(D-[a-z0-9-]+)` \| (ratified|open) \| (\d{4}-\d{2}-\d{2}|—) \| (.+) \|$"
)
SPEC_CITE = re.compile(r"specification/[0-9]{2}-[a-z-]+\.md")


def extract_decisions() -> tuple[list[dict], list[dict]]:
    """Decision nodes from the register's canonical, fenced index.

    The index is machine-readable BY CONSTRUCTION (a fenced table with one row per
    decision) precisely because no text-scan rule was reproducible: a naive grep
    yields 35 keys, 3 of which are substrings of unrelated words ('SSD-vs-rotational'
    -> 'D-vs-rotational'); a backtick-or-table-row rule yields 28 and drops 4 real
    decisions. Parsing the fence is the only rule that reproduces its own count.
    """
    reg = "specification/02-decision-register.md"
    text = (REPO / reg).read_text()
    try:
        body = text.split("<!-- BEGIN decision-index -->")[1].split("<!-- END decision-index -->")[0]
    except IndexError:
        raise SystemExit(f"FATAL: canonical decision index fence missing from {reg}")

    nodes, edges = [], []
    for line in body.split("\n"):
        m = DECISION_ROW.match(line.strip())
        if not m:
            continue
        key, status, date, choice = m.groups()
        props = {"status": status, "chosen": choice.strip()}
        if date != "—":
            props["ratified_on"] = date
        nodes.append({"label": "Decision", "id": {"key": key}, "props": props})

    if not nodes:
        raise SystemExit(f"FATAL: canonical decision index in {reg} parsed to 0 rows")

    # CITED_IN is DERIVED, not curated: an edge exists iff the code actually names
    # the decision. 13 of 31 decisions are cited at f360da4.
    tracked = set(sh("git", "ls-files", "*.rs").split())
    for n in nodes:
        key = n["id"]["key"]
        for path in tracked:
            if key in (REPO / path).read_text(errors="replace"):
                edges.append({"type": "CITED_IN", "from": {"label": "Decision", "key": key},
                              "to": {"label": "File", "path": path}, "props": {}})
    return nodes, edges


def extract_spec_citations(spec_paths: set[str]) -> list[dict]:
    """File-CITES->Spec, derived from spec paths named in source comments.

    A citation of a spec that does not exist is a real defect, not a missing node:
    graphus-sysres cited `specification/01-functional-requirements.md`, a file that
    never existed in the entire git history. Fail loudly rather than silently drop
    the edge or invent a node for a phantom document.
    """
    edges, dangling = [], []
    for path in sorted(sh("git", "ls-files", "*.rs").split()):
        text = (REPO / path).read_text(errors="replace")
        for cited in sorted(set(SPEC_CITE.findall(text))):
            if cited in spec_paths:
                edges.append({"type": "CITES", "from": {"label": "File", "path": path},
                              "to": {"label": "Spec", "path": cited}, "props": {}})
            else:
                dangling.append(f"{path} -> {cited}")
    if dangling:
        raise SystemExit(
            "FATAL: source cites specification files that do not exist:\n  "
            + "\n  ".join(dangling)
        )
    return edges


def extract_examples() -> tuple[list[dict], list[dict]]:
    """An Example is a directory under examples/ that has a run.sh.

    examples/_harness/ has no run.sh and is therefore not an Example; it is the
    shared harness. 12 of 13 directories qualify (knowledge-model.md §6).
    """
    nodes, edges = [], []
    for run in sorted((REPO / "examples").glob("*/run.sh")):
        d = run.parent
        name = d.name
        rel = f"examples/{name}"
        nodes.append({"label": "Example", "id": {"path": rel},
                      "props": {"name": name,
                                "has_baseline": (d / "baseline.json").exists(),
                                "has_readme": (d / "README.md").exists()}})
        # DRIVEN_BY is derived from the crates run.sh actually invokes.
        text = run.read_text(errors="replace")
        for m in sorted(set(re.findall(r"-p\s+(graphus-[a-z0-9-]+)", text))):
            edges.append({"type": "DRIVEN_BY", "from": {"label": "Example", "path": rel},
                          "to": {"label": "Crate", "name": m}, "props": {}})
    return nodes, edges


# --------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rustdoc-dir", action="append", default=[],
                    metavar="TRIPLE=PATH",
                    help="rustdoc JSON dir for one target, as <target-triple>=<path>")
    args = ap.parse_args()

    docdirs: dict[str, Path] = {}
    for spec in args.rustdoc_dir:
        triple, _, p = spec.partition("=")
        path = Path(p)
        if not path.is_dir():
            print(f"ERROR: not a directory: {p}", file=sys.stderr)
            return 2
        docdirs[triple] = path
    if not docdirs:
        print("ERROR: at least one --rustdoc-dir is required", file=sys.stderr)
        return 2

    head, head_date = git_head()
    nodes: list[dict] = []
    edges: list[dict] = []

    cn, ce = extract_crates(); nodes += cn; edges += ce
    fn_, fe = extract_files(); nodes += fn_; edges += fe
    sn, se, per_target = extract_symbols(docdirs); nodes += sn; edges += se
    tn, te = extract_tests(); nodes += tn; edges += te
    con, coe = extract_commits(); nodes += con; edges += coe
    rn, re_ = extract_releases(); nodes += rn; edges += re_
    docnodes = extract_docs(); nodes += docnodes
    dn, de = extract_decisions(); nodes += dn; edges += de
    edges += extract_spec_citations({n["id"]["path"] for n in docnodes if n["label"] == "Spec"})
    en, ee = extract_examples(); nodes += en; edges += ee

    # Record which crates were successfully documented per target, so the graph
    # can distinguish "absent on macOS" from "never checked on macOS".
    for n in nodes:
        if n["label"] == "Crate":
            checked = sorted(t for t, cs in per_target.items() if n["id"]["name"] in cs)
            n["props"]["doc_targets"] = ",".join(checked)

    counts: dict[str, int] = defaultdict(int)
    for n in nodes:
        counts[n["label"]] += 1
    ecounts: dict[str, int] = defaultdict(int)
    for e in edges:
        ecounts[e["type"]] += 1

    json.dump({
        "meta": {"gitCommit": head, "gitDate": head_date,
                 "targets": sorted(docdirs), "node_counts": dict(counts),
                 "edge_counts": dict(ecounts)},
        "nodes": nodes, "edges": edges,
    }, sys.stdout, indent=1, sort_keys=True)
    print("", file=sys.stderr)
    print(f"nodes: {sum(counts.values())} {dict(counts)}", file=sys.stderr)
    print(f"edges: {sum(ecounts.values())} {dict(ecounts)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
