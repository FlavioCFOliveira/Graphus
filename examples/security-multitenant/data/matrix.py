#!/usr/bin/env python3
"""Multi-tenant RBAC allow/deny matrix over the Graphus REST API (security-multitenant example).

A pure-stdlib client (``urllib`` + ``ssl`` + ``json``) that drives the **REST transactional API** over
HTTPS against a live ``graphus-server`` — **local or remote** (``--base-url``) — and proves the
fine-grained RBAC authorization surface from the generator's ``manifest.json``:

1. **Login** — every principal authenticates via ``POST /auth/login`` (no client-side JWT minting): the
   bootstrap admin with the credentials passed on argv, each provisioned user with its manifest
   password. The unauthenticated probe sends no Bearer at all.
2. **Provision** (as the admin) — replays ``provision.cypher`` (``CREATE DATABASE / ROLE / USER`` +
   ``GRANT``s, all ``IF NOT EXISTS``) over the system database, then seeds each tenant's sensitive data
   (``<database>.cypher``) inside that tenant's database.
3. **Fine-grained DENY** (feature-detected) — attempts ``deny.cypher`` (``DENY READ ON PROPERTY …`` +
   ``DENY TRAVERSE ON LABEL …``). If the target's grammar predates ``DENY`` the statements are rejected
   and the demo records the *version gap* instead of asserting the DENY checks; otherwise it seeds the
   multi-label ``(:Secret:Confidential)`` node and asserts, per ``manifest.deny_checks``, that the
   denied property reads back **NULL** and the denied node is **invisible** — run once as the denied
   user (must be denied) and once as the admin (must still see it). This is the deny-precedence
   regression guard for the multi-label DENY bug (``rmp #645``).
4. **Matrix** — for every ``(user, tenant, access_mode)`` cell asserts: ``allow`` ⇒ HTTP **200**;
   ``deny`` WRITE ⇒ HTTP **403** (``Neo.ClientError.Security.Forbidden``); ``deny`` READ ⇒ **403** *or*
   200-with-zero-rows (no leak either way); ``unauthenticated`` ⇒ HTTP **401**.
5. **Broadened cross-tenant negatives** — as the tenant_a user against tenant_b, asserts each
   ``manifest.cross_tenant_probes`` (Patient.ssn, Record.secret_token, all nodes, count(n)) returns
   **no data** — 403 (REST coarse gate) *or* zero rows / count 0. Broadens the original single
   ``:Secret``-canary check to the full PII surface.
6. **Concurrency phase** (``--workers`` / ``--secs``) — *the point of the example*. Steps 1–5 prove the
   authorization decisions hold when **nothing else is happening**; tenant isolation, however, only
   fails under CONCURRENCY. This phase runs ``--workers`` threads — each on its own persistent
   keep-alive HTTPS connection, instantiated from the manifest's weighted roster — driving BOTH tenants
   at once for ``--secs``, with real concurrent WRITES mutating the tenant stores while the isolation
   oracle runs. Every cross-tenant probe, DENY-scoped read, RBAC denial and auth rejection is asserted
   on **every iteration**, never sampled. The invariant is exact: **zero** isolation violations; a
   single leaked cell fails the run.

   With ``--server-pid`` + ``--proc-watch`` the phase is bracketed against the SERVER's pid (two
   ``proc_watch --snapshot`` reads of its cumulative CPU counters, plus a ``--watch`` RSS series), so
   the report can state what the concurrent cross-tenant load cost the *server* — CPU seconds, mean
   cores busy, peak RSS — rather than what it cost this driver. In attach mode there is no co-located
   pid, so those figures are **absent** from the stats (never a zero placeholder). The driver's own CPU
   is always reported (``conc_client_*``) so a reader can see whether this python client was itself the
   limiter.

On success it prints ``GRAPHUS_RBAC_OK`` and a single machine-readable ``GRAPHUS_STATS {...}`` line.

Usage::

    matrix.py --base-url https://host:7474 --admin-user <u> --admin-password <pw> \
              --data-dir <dir> [--system-db graphus] [--insecure] \
              [--workers N --secs S [--write-budget K]] \
              [--server-pid PID --proc-watch /path/to/proc_watch]

Teardown (DROP of every database/role/user) is owned by run.sh's cleanup trap, not this client.
"""

import argparse
import http.client
import json
import os
import random
import resource
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


# --------------------------------------------------------------------------------------------------
# REST client.
# --------------------------------------------------------------------------------------------------
class RestClient:
    """A thin HTTPS REST client for the Graphus transactional API (Bearer JWT via POST /auth/login)."""

    def __init__(self, base_url, insecure):
        self.base = base_url.rstrip("/")
        if base_url.startswith("https"):
            self.ctx = ssl.create_default_context()
            if insecure:
                self.ctx.check_hostname = False
                self.ctx.verify_mode = ssl.CERT_NONE
        else:
            self.ctx = None
        # Per-request wall times (ms) of every /db/{db}/tx/commit this client issues — the REAL
        # latency of an RBAC-enforced REST request. The evidence report used to carry hardcoded
        # p50/p99/p999 = 0.000 placeholders because nothing ever measured them (rmp #699).
        self.request_ms = []

    def _open(self, req):
        if self.ctx is not None:
            return urllib.request.urlopen(req, context=self.ctx)
        return urllib.request.urlopen(req)

    def login(self, username, password):
        """POST /auth/login → the Bearer token for ``username`` (or raise on a non-200)."""
        data = json.dumps({"username": username, "password": password}).encode()
        req = urllib.request.Request(f"{self.base}/auth/login", data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        try:
            resp = self._open(req)
        except urllib.error.HTTPError as e:
            raise RuntimeError(
                f"login failed for {username!r} ({e.code}): {e.read()[:200]!r}"
            ) from None
        body = json.loads(resp.read())
        tok = body.get("token")
        if not tok:
            raise RuntimeError(f"login for {username!r} returned no token: {body}")
        return tok

    def commit(self, db, statements, token=None, access_mode=None):
        """POST /db/{db}/tx/commit. Returns ``(status, body_bytes)``. ``token=None`` => no auth
        header (the unauthenticated probe). ``access_mode`` overrides the server default (WRITE)."""
        body = {"statements": statements}
        if access_mode is not None:
            body["access_mode"] = access_mode
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            f"{self.base}/db/{db}/tx/commit", data=data, method="POST"
        )
        req.add_header("Accept", "application/json")
        req.add_header("Content-Type", "application/json")
        if token is not None:
            req.add_header("Authorization", "Bearer " + token)
        t0 = time.perf_counter()
        try:
            resp = self._open(req)
            out = (resp.status, resp.read())
        except urllib.error.HTTPError as e:
            out = (e.code, e.read())
        # Timed on BOTH paths: a 403 the RBAC gate rejects is as much a served request as a 200, and
        # excluding it would bias the percentiles towards the allowed cells only.
        self.request_ms.append((time.perf_counter() - t0) * 1000.0)
        return out


# --------------------------------------------------------------------------------------------------
# .cypher parsing + strict-Jolt cell decoding.
# --------------------------------------------------------------------------------------------------
def percentile_ms(sorted_ms, q):
    """The ``q``-quantile of an ALREADY-SORTED list of millisecond samples (nearest-rank).

    Returns ``0.0`` only for an empty sample — which honestly means "nothing was measured", never a
    stand-in for a latency that was simply never collected.
    """
    if not sorted_ms:
        return 0.0
    k = min(len(sorted_ms) - 1, max(0, int(round(q * (len(sorted_ms) - 1)))))
    return round(sorted_ms[k], 4)


def parse_statements(path):
    """Splits a .cypher file into individual statements (comment/blank lines stripped)."""
    out, buf = [], ""
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("//") or not line.strip():
                continue
            buf += line
            if buf.rstrip().endswith(";"):
                out.append(buf.rstrip()[:-1])
                buf = ""
    return out


def rows_of(body_text):
    """The list of result rows in a tx/commit response body, or [] if it carries no results."""
    try:
        doc = json.loads(body_text)
    except ValueError:
        return []
    results = doc.get("results") or []
    if not results:
        return []
    return results[0].get("data") or []


def cell_is_null(cell):
    """True iff a strict-Jolt cell is NULL (JSON ``null``). A denied property reads back NULL."""
    return cell is None


def cell_int(cell):
    """Decode a strict-Jolt integer cell (``{"Z":"<int>"}``); None if it is not an integer."""
    if isinstance(cell, dict) and "Z" in cell:
        try:
            return int(cell["Z"])
        except (TypeError, ValueError):
            return None
    return None


def cell_str(cell):
    """Decode a strict-Jolt string cell (``{"U":"<s>"}``, sigil U per crates/graphus-rest/src/value.rs);
    None if it is not a string. The concurrency reader oracle compares this against the tenant's OWN
    canary so a leaked *value* (not merely a leaked row count) is caught."""
    if isinstance(cell, dict) and "U" in cell and isinstance(cell["U"], str):
        return cell["U"]
    return None


# --------------------------------------------------------------------------------------------------
# Assertions.
# --------------------------------------------------------------------------------------------------
FAILURES = 0
FORBIDDEN_CODE = "Neo.ClientError.Security.Forbidden"


def fail(msg):
    global FAILURES
    FAILURES += 1
    print(f"  BAD {msg}")


def ok(msg):
    print(f"  OK  {msg}")


def check(name, cond, detail=""):
    if cond:
        ok(name)
    else:
        fail(f"{name}{(' :: ' + detail) if detail else ''}")
    return cond


# --------------------------------------------------------------------------------------------------
# The matrix probes.
# --------------------------------------------------------------------------------------------------
READ_PROBE = "MATCH (s:Secret) RETURN s.name AS name"
WRITE_PROBE = "CREATE (:RbacProbe {ts: 1})"


def run_matrix_cell(client, token_for, cell):
    """Drives one (user, tenant, access_mode) cell; returns (status, body_text, rows)."""
    db = cell["tenant"]
    mode = cell["access_mode"]
    token = token_for(cell["user"])
    if mode == "READ":
        st, body = client.commit(db, [{"statement": READ_PROBE}], token=token, access_mode="READ")
    else:
        st, body = client.commit(db, [{"statement": WRITE_PROBE}], token=token, access_mode="WRITE")
    text = body.decode("utf-8", "replace")
    return st, text, len(rows_of(text))


def assert_cell(cell, st, text, rows):
    """Asserts one matrix cell. Deny READ is satisfied by 403 OR 200-with-zero-rows (no leak)."""
    label = (
        f"{(cell['user'] or '<anon>'):>7} {cell['access_mode']:<5} {cell['tenant']:<24} "
        f"[{cell['outcome']}]"
    )
    outcome = cell["outcome"]
    if outcome == "allow":
        return check(label, st == 200, f"want 200 got {st}: {text[:140]}")
    if outcome == "unauthenticated":
        return check(label, st == 401, f"want 401 got {st}: {text[:140]}")
    # deny
    if cell["access_mode"] == "WRITE":
        good = st == 403 and FORBIDDEN_CODE in text
        return check(label, good, f"want 403+Forbidden got {st}: {text[:140]}")
    # deny READ: 403 (coarse gate) OR 200 with zero rows (value-level filter) — no leak either way.
    good = (st == 403) or (st == 200 and rows == 0)
    return check(label, good, f"want 403|200+0rows got {st} rows={rows}: {text[:140]}")


# --------------------------------------------------------------------------------------------------
# Provisioning + seeding (as the admin).
# --------------------------------------------------------------------------------------------------
def provision(client, admin_token, system_db, statements):
    for s in statements:
        st, body = client.commit(system_db, [{"statement": s}], token=admin_token)
        if st != 200:
            raise RuntimeError(f"provision failed ({st}): {s[:80]} :: {body[:200]}")
    return len(statements)


def seed(client, admin_token, db, statements, batch=200):
    loaded = 0
    for i in range(0, len(statements), batch):
        chunk = statements[i : i + batch]
        st, body = client.commit(
            db, [{"statement": s} for s in chunk], token=admin_token, access_mode="WRITE"
        )
        if st != 200:
            raise RuntimeError(f"seed {db} failed ({st}): {body[:200]}")
        loaded += len(chunk)
    return loaded


def try_deny_provision(client, admin_token, system_db, deny_stmts):
    """Attempts the DENY grants. Returns True if the target accepted them, False if its grammar
    predates DENY (the version gap). Raises only on an unexpected transport failure."""
    for s in deny_stmts:
        st, body = client.commit(system_db, [{"statement": s}], token=admin_token)
        if st != 200:
            txt = body.decode("utf-8", "replace")
            # A grammar that predates DENY answers a 400 SyntaxError on the leading `DENY`.
            print(f"  ·   DENY not supported by target: {s!r} -> {st} {txt[:160]}")
            return False
    return True


# --------------------------------------------------------------------------------------------------
# DENY checks + cross-tenant negatives.
# --------------------------------------------------------------------------------------------------
def run_deny_checks(client, token_for, admin_user, checks):
    """Each check: run as the denied user (must be denied) AND as admin (must still see it)."""
    asserted = 0
    for c in checks:
        db = c["tenant"]
        user_tok = token_for(c["user"])
        admin_tok = token_for(admin_user)
        st_u, body_u = client.commit(db, [{"statement": c["query"]}], token=user_tok, access_mode="READ")
        st_a, body_a = client.commit(db, [{"statement": c["query"]}], token=admin_tok, access_mode="READ")
        rows_u = rows_of(body_u.decode("utf-8", "replace"))
        rows_a = rows_of(body_a.decode("utf-8", "replace"))
        label = f"DENY {c['kind']:<14} {c['user']:>7} {db:<24} — {c['why']}"
        if c["kind"] == "property_null":
            # Denied user: 200 with rows, EVERY v NULL. Admin: rows with at least one non-NULL v.
            u_ok = st_u == 200 and len(rows_u) > 0 and all(cell_is_null(r[0]) for r in rows_u)
            a_ok = st_a == 200 and any(not cell_is_null(r[0]) for r in rows_a)
            check(label, u_ok and a_ok,
                  f"user st={st_u} rows={len(rows_u)} allnull={all(cell_is_null(r[0]) for r in rows_u) if rows_u else 'n/a'} | admin st={st_a} rows={len(rows_a)}")
        else:  # node_invisible
            # Denied user: zero rows (403 also acceptable — no leak). Admin: at least one row.
            u_ok = (st_u == 403) or (st_u == 200 and len(rows_u) == 0)
            a_ok = st_a == 200 and len(rows_a) >= 1
            check(label, u_ok and a_ok,
                  f"user st={st_u} rows={len(rows_u)} | admin st={st_a} rows={len(rows_a)}")
        asserted += 1
    return asserted


def run_cross_tenant(client, token_for, user, other_tenant, probes):
    """As ``user`` (tenant_a-scoped) against ``other_tenant``, assert every probe returns no data:
    403 (coarse gate) OR zero rows / count 0. Returns (asserted, denied_403, empty_200)."""
    tok = token_for(user)
    denied = empty = 0
    for p in probes:
        st, body = client.commit(other_tenant, [{"statement": p["query"]}], token=tok, access_mode="READ")
        text = body.decode("utf-8", "replace")
        rows = rows_of(text)
        label = f"XTENANT {user:>7} -> {other_tenant:<24} [{p['kind']}] — {p['why']}"
        if p["kind"] == "count":
            # count(n) always returns exactly one row; the VALUE must be 0 (or the whole read is 403).
            if st == 403:
                denied += 1
                check(label, True)
            else:
                val = cell_int(rows[0][0]) if rows else None
                if st == 200 and val == 0:
                    empty += 1
                check(label, st == 200 and val == 0, f"want count 0 got st={st} val={val}")
        else:
            if st == 403:
                denied += 1
                check(label, True)
            else:
                if st == 200 and len(rows) == 0:
                    empty += 1
                check(label, st == 200 and len(rows) == 0,
                      f"want 403|200+0rows got st={st} rows={len(rows)}: {text[:120]}")
    return len(probes), denied, empty


# --------------------------------------------------------------------------------------------------
# Concurrency phase — the point of the example.
#
# A serial matrix proves the RBAC decisions hold when nothing else is happening. Tenant isolation only
# FAILS under concurrency, so this phase drives N workers — each on its OWN persistent keep-alive HTTPS
# connection — issuing OVERLAPPING mixes against BOTH tenants at once for a bounded window. Every
# cross-tenant probe, DENY-scoped read, RBAC denial and auth failure is asserted on EVERY iteration
# (never sampled). The isolation invariant is exact: ZERO violations across all iterations; a single
# leaked cell fails the run.
# --------------------------------------------------------------------------------------------------
class KeepAliveClient:
    """A single, persistent HTTP/1.1 keep-alive connection to the target (one per concurrent worker).

    ``urllib`` opens a fresh TCP+TLS connection per request; a real multi-tenant client holds a pooled,
    long-lived connection, and reusing one is what puts genuine concurrent pressure on the server
    (rather than measuring connection setup). Reconnects once on a dropped connection."""

    def __init__(self, host, port, ctx, timeout=30.0):
        self.host, self.port, self.ctx, self.timeout = host, port, ctx, timeout
        self.conn = None

    def _connect(self):
        if self.ctx is not None:
            self.conn = http.client.HTTPSConnection(
                self.host, self.port, context=self.ctx, timeout=self.timeout
            )
        else:
            self.conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def request(self, method, path, body=None, headers=None):
        """Issue one request over the persistent connection; returns ``(status, body_bytes)``.
        Retries exactly once on a connection-level error (a kept-alive socket the server closed)."""
        hdrs = headers or {}
        for attempt in (0, 1):
            try:
                if self.conn is None:
                    self._connect()
                self.conn.request(method, path, body=body, headers=hdrs)
                resp = self.conn.getresponse()
                data = resp.read()  # MUST drain the body to keep the connection alive.
                return resp.status, data
            except (http.client.HTTPException, OSError):
                self.close()
                if attempt == 1:
                    raise
        raise RuntimeError("unreachable")

    def close(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:  # noqa: BLE001 — closing a broken socket must never raise
                pass
            self.conn = None


# The probe queries the concurrency oracle drives (aliased so the client reads one column uniformly).
CONC_READ_CANARY = "MATCH (s:Secret) RETURN s.name AS v"
CONC_READ_ALL = "MATCH (n) RETURN n AS v"
CONC_WRITE_PROBE = "CREATE (:RbacProbe {ts: 1})"
# The DENY-scoped property read per tenant: tenant_a denies Patient.ssn to reader_a, tenant_b denies
# Record.secret_token to reader_b. The denied value MUST read back NULL on every iteration.
CONC_DENY_READ = {
    "ssn": "MATCH (p:Patient) RETURN p.ssn AS v",
    "token": "MATCH (r:Record) RETURN r.secret_token AS v",
}


def _commit_body(statement, params=None, access_mode=None):
    stmt = {"statement": statement}
    if params is not None:
        stmt["parameters"] = params
    body = {"statements": [stmt]}
    if access_mode is not None:
        body["access_mode"] = access_mode
    return json.dumps(body).encode()


#: How many times a `writer` re-issues a write the server answered 409 (a retriable SSI abort). A
#: production OLTP client retries a retriable conflict rather than dropping the transaction, and doing
#: so here has a second, load-bearing effect: the COMMITTED write count converges on the write budget
#: instead of on "budget minus however many conflicts this machine happened to hit", which is what
#: makes the durable store delta — and therefore the committed storage baseline — reproducible.
MAX_WRITE_ATTEMPTS = 4


def _conc_worker(spec, client, deadline, ctr, stop_flag):
    """One concurrent worker's loop until ``deadline``. ``spec`` is a resolved worker (kind, tokens,
    tenants, oracle inputs); ``ctr`` is this worker's PRIVATE counter dict (merged after join, so the
    hot path takes no lock). Every decision is asserted here — a leak bumps ``isolation_violations``."""
    kind = spec["kind"]
    tenant = spec["tenant"]
    other = spec["other_tenant"]
    tok = spec.get("token")
    auth = {"Authorization": "Bearer " + tok} if tok else {}
    json_ct = {"Accept": "application/json", "Content-Type": "application/json"}
    own_canary = spec.get("own_canary")
    other_canary = spec.get("other_canary")
    # The value of the DENY-TRAVERSE'd `(:Secret:Confidential)` node (`rmp #645`). It lives in the
    # denied tenant and carries the :Secret label, so the reader's own-tenant canary scan WOULD return
    # it if deny-precedence broke — which is precisely the failure this phase exists to catch under
    # load. None for a worker the label DENY does not apply to (or when the target has no DENY).
    hidden_canary = spec.get("hidden_canary")
    deny_query = spec.get("deny_query")
    rng = random.Random(spec["rng_seed"])
    patient_ids = spec.get("patient_ids", 1)
    # Write pacing (see `write_budget` in run_concurrency_phase): a writer may hold at most its
    # time-proportional share of the budget, so the writes stay spread across the WHOLE window (the
    # readers are contended from start to finish) while the durable footprint stays bounded and
    # reproducible. 0 = unbounded (write on every iteration).
    write_budget = spec.get("write_budget", 0)
    window_secs = spec.get("window_secs", 0.0)
    started = time.perf_counter()

    def may_write():
        """True when this writer is behind its paced share of the write budget."""
        if write_budget <= 0:
            return True
        if ctr["write_committed"] >= write_budget:
            return False
        if window_secs <= 0.0:
            return True
        share = (time.perf_counter() - started) / window_secs
        return ctr["write_committed"] < write_budget * min(1.0, max(0.0, share))

    def timed(method, path, body):
        t0 = time.perf_counter()
        st, data = client.request(method, path, body=body, headers={**json_ct, **auth})
        ctr["lat_ms"].append((time.perf_counter() - t0) * 1000.0)
        ctr["ops"] += 1
        return st, data

    def rows_from(data):
        return rows_of(data.decode("utf-8", "replace"))

    while time.perf_counter() < deadline and not stop_flag[0]:
        try:
            if kind in ("reader", "writer", "analyst"):
                # (1) ALLOWED own-tenant read — must be 200 AND return this tenant's OWN canary.
                st, data = timed("POST", f"/db/{tenant}/tx/commit",
                                 _commit_body(CONC_READ_CANARY, access_mode="READ"))
                rows = rows_from(data)
                names = {cell_str(r[0]) for r in rows} if rows else set()
                if st == 200 and own_canary in names:
                    ctr["allow"] += 1
                    # Isolation at the VALUE level: the other tenant's canary must NEVER appear here.
                    if other_canary in names:
                        ctr["isolation_violations"] += 1
                        ctr["violation_notes"].append(
                            f"{kind} {tenant}: own-tenant canary read leaked {other_canary!r}")
                    # Deny-precedence at the VALUE level, on every iteration (`rmp #645`): the
                    # multi-label (:Secret:Confidential) node must stay hidden from the denied reader
                    # even though this very scan matches its OTHER label.
                    if hidden_canary is not None:
                        ctr["hidden_canary_checks"] += 1
                        if hidden_canary in names:
                            ctr["isolation_violations"] += 1
                            ctr["violation_notes"].append(
                                f"{kind} {tenant}: DENY-TRAVERSE'd label leaked {hidden_canary!r} "
                                f"through its :Secret label (#645 precedence broke under load)")
                        else:
                            ctr["hidden_canary_ok"] += 1
                else:
                    ctr["failures"] += 1
                    ctr["violation_notes"].append(
                        f"{kind} {tenant}: own read st={st} names={names} (want {own_canary!r})")

                # (2) CROSS-TENANT read — must be denied (403) or value-level-filtered (200/0 rows).
                #     ONLY for the tenant-scoped principals (reader / writer): the `analyst` holds
                #     `READ ON DATABASE` (server-wide) and is LEGITIMATELY authorized to read `other`,
                #     so a 200 with rows there is correct, not a leak. The analyst's isolation property
                #     is different — each of its reads must return exactly the tenant it targeted and
                #     never mix the two — and is asserted in its own branch below.
                if kind in ("reader", "writer"):
                    st, data = timed("POST", f"/db/{other}/tx/commit",
                                     _commit_body(CONC_READ_ALL, access_mode="READ"))
                    rows = rows_from(data)
                    ctr["xt_probes"] += 1
                    if st == 403:
                        ctr["xt_denied"] += 1
                        ctr["deny"] += 1
                    elif st == 200 and len(rows) == 0:
                        ctr["xt_empty"] += 1
                        ctr["deny"] += 1
                    else:
                        ctr["isolation_violations"] += 1
                        ctr["violation_notes"].append(
                            f"{kind} {tenant}->{other}: cross-tenant read LEAKED st={st} rows={len(rows)}")

                if kind == "reader":
                    # (3) RBAC denial: a reader attempting a WRITE in its own tenant → 403.
                    st, _ = timed("POST", f"/db/{tenant}/tx/commit",
                                  _commit_body(CONC_WRITE_PROBE, access_mode="WRITE"))
                    if st == 403:
                        ctr["deny"] += 1
                        ctr["rbac_denied"] += 1
                    else:
                        ctr["isolation_violations"] += 1
                        ctr["violation_notes"].append(
                            f"reader {tenant}: WRITE was not denied st={st}")
                    # (4) DENY-scoped property read — the sensitive value MUST read back NULL. Skipped
                    #     (and reported as such) when the target's grammar predates DENY: the grants
                    #     never landed, so this would fail a run for a version gap, not for a leak.
                    if deny_query is None:
                        continue
                    st, data = timed("POST", f"/db/{tenant}/tx/commit",
                                     _commit_body(deny_query, access_mode="READ"))
                    rows = rows_from(data)
                    ctr["deny_reads"] += 1
                    if st == 200 and rows and all(cell_is_null(r[0]) for r in rows):
                        ctr["deny_null_ok"] += 1
                    elif st == 403:
                        ctr["deny_null_ok"] += 1  # coarse-gated is also no-leak
                    else:
                        leaked = [cell_str(r[0]) for r in rows if not cell_is_null(r[0])]
                        ctr["isolation_violations"] += 1
                        ctr["violation_notes"].append(
                            f"reader {tenant}: DENY-scoped value leaked st={st} sample={leaked[:2]}")

                elif kind == "writer":
                    # (3) REAL own-tenant WRITE (contends with the readers' scans). 200 = committed,
                    #     409 = a retriable SSI abort (MEASURED, not a failure) which a production
                    #     client RETRIES. A 403 here WOULD be a failure (authorization broke under
                    #     load). Paced against the write budget so the durable footprint the evidence
                    #     report meters stays bounded and reproducible.
                    if may_write():
                        pid = rng.randrange(max(1, patient_ids))
                        params = {"pid": pid, "actor": spec["user"], "seq": ctr["ops"]}
                        for _attempt in range(MAX_WRITE_ATTEMPTS):
                            st, _ = timed("POST", f"/db/{tenant}/tx/commit",
                                          _commit_body(spec["write_query"], params=params,
                                                       access_mode="WRITE"))
                            if st == 200:
                                ctr["allow"] += 1
                                ctr["write_committed"] += 1
                                # The LOGICAL bytes this write added to `tenant`'s graph: the Cypher
                                # text plus its bound parameters, the same unit the generator's
                                # `.cypher` seed script is measured in. The evidence report's
                                # amplification denominator is the seed script PLUS this, because the
                                # store it meters holds both (rmp #711 rule 3: a ratio's two inputs
                                # must describe the same graph).
                                ctr["write_logical_bytes"] += (
                                    len(spec["write_query"])
                                    + len(json.dumps(params, separators=(",", ":")))
                                )
                                break
                            if st == 409:
                                ctr["write_aborted"] += 1
                                continue  # a retriable SSI conflict: retry, as a real client does.
                            ctr["failures"] += 1
                            ctr["violation_notes"].append(
                                f"writer {tenant}: allowed WRITE unexpectedly st={st}")
                            break
                        else:
                            ctr["write_exhausted"] += 1
                    # (4) CROSS-TENANT WRITE attempt — NO mutation may ever cross a tenant boundary.
                    st, _ = timed("POST", f"/db/{other}/tx/commit",
                                  _commit_body(CONC_WRITE_PROBE, access_mode="WRITE"))
                    ctr["xt_probes"] += 1
                    if st == 403:
                        ctr["xt_denied"] += 1
                        ctr["deny"] += 1
                    else:
                        ctr["isolation_violations"] += 1
                        ctr["violation_notes"].append(
                            f"writer {tenant}->{other}: cross-tenant WRITE not denied st={st}")

                else:  # analyst — legitimately reads BOTH tenants; each read must return ONLY its own.
                    st, data = timed("POST", f"/db/{other}/tx/commit",
                                     _commit_body(CONC_READ_CANARY, access_mode="READ"))
                    rows = rows_from(data)
                    names = {cell_str(r[0]) for r in rows} if rows else set()
                    if st == 200 and other_canary in names and own_canary not in names:
                        ctr["allow"] += 1  # correct: the OTHER tenant's canary, and only it
                    elif st == 200 and own_canary in names:
                        ctr["isolation_violations"] += 1
                        ctr["violation_notes"].append(
                            f"analyst read of {other} leaked {tenant}'s canary {own_canary!r}")
                    else:
                        ctr["failures"] += 1
                        ctr["violation_notes"].append(
                            f"analyst read of {other}: st={st} names={names}")
                    # analyst is READ-only server-wide: a WRITE must be denied.
                    st, _ = timed("POST", f"/db/{tenant}/tx/commit",
                                  _commit_body(CONC_WRITE_PROBE, access_mode="WRITE"))
                    if st == 403:
                        ctr["deny"] += 1
                        ctr["rbac_denied"] += 1
                    else:
                        ctr["isolation_violations"] += 1
                        ctr["violation_notes"].append(
                            f"analyst {tenant}: WRITE was not denied st={st}")

            else:  # rejected — its whole job is to be rejected on every path.
                # (1) Garbage Bearer on the data plane → 401 (never 200).
                bad = {"Accept": "application/json", "Content-Type": "application/json",
                       "Authorization": f"Bearer invalid-{rng.randrange(1 << 30)}"}
                t0 = time.perf_counter()
                st, _ = client.request("POST", f"/db/{tenant}/tx/commit",
                                       body=_commit_body(CONC_READ_CANARY, access_mode="READ"),
                                       headers=bad)
                ctr["lat_ms"].append((time.perf_counter() - t0) * 1000.0)
                ctr["ops"] += 1
                if st == 401:
                    ctr["unauth"] += 1
                else:
                    ctr["isolation_violations"] += 1
                    ctr["violation_notes"].append(f"rejected: data-plane bad Bearer st={st} (want 401)")
                # (2) Bad password on /auth/login → 401 (or 429 once the per-account throttle engages —
                #     both are rejections, and NEITHER yields a token). Vary the account so we exercise
                #     both the unknown-user (uniform 401) and the throttle (429) paths.
                who = spec["bad_login_user"] if rng.random() < 0.5 else f"nobody-{rng.randrange(1000)}"
                t0 = time.perf_counter()
                st, data = client.request(
                    "POST", "/auth/login",
                    body=json.dumps({"username": who, "password": "wrong-password"}).encode(),
                    headers={"Accept": "application/json", "Content-Type": "application/json"})
                ctr["lat_ms"].append((time.perf_counter() - t0) * 1000.0)
                ctr["ops"] += 1
                has_token = False
                try:
                    has_token = bool(json.loads(data).get("token"))
                except Exception:  # noqa: BLE001
                    has_token = False
                if st in (401, 429) and not has_token:
                    ctr["unauth"] += 1
                else:
                    ctr["isolation_violations"] += 1
                    ctr["violation_notes"].append(
                        f"rejected: bad-password login st={st} token={has_token} (want 401/429, no token)")
                # (3) Garbage Bearer on the /metrics gate — the path that DOES bump
                #     graphus_auth_failures_total (a REST data-plane 401 does not — see the run.sh note).
                t0 = time.perf_counter()
                st, _ = client.request("GET", "/metrics", body=None,
                                       headers={"Authorization": f"Bearer invalid-{rng.randrange(1 << 30)}"})
                ctr["lat_ms"].append((time.perf_counter() - t0) * 1000.0)
                ctr["ops"] += 1
                if st == 401:
                    ctr["unauth"] += 1
                    ctr["metrics_gate_rejections"] += 1
                else:
                    ctr["isolation_violations"] += 1
                    ctr["violation_notes"].append(f"rejected: /metrics bad Bearer st={st} (want 401)")
        except (http.client.HTTPException, OSError) as e:
            ctr["transport_errors"] += 1
            ctr["violation_notes"].append(f"{kind} {tenant}: transport error {e!r}")
            # A transport error is not an isolation leak, but a storm of them means the client could not
            # sustain the load — recorded so the report can flag the client as the limiter.


def _new_counters():
    return {
        "ops": 0, "allow": 0, "deny": 0, "unauth": 0, "failures": 0,
        "xt_probes": 0, "xt_denied": 0, "xt_empty": 0,
        "rbac_denied": 0, "deny_reads": 0, "deny_null_ok": 0,
        "hidden_canary_checks": 0, "hidden_canary_ok": 0,
        "write_committed": 0, "write_aborted": 0, "write_exhausted": 0,
        "write_logical_bytes": 0,
        "metrics_gate_rejections": 0, "transport_errors": 0,
        "isolation_violations": 0, "lat_ms": [], "violation_notes": [],
    }


class ServerWatch:
    """The SERVER-side resource bracket around the concurrency window (`rmp #717`).

    The house rule is *sample the SERVER, not the driver*. This driver is python, so it cannot read the
    server's `/proc` metering itself — it shells out to the harness's `proc_watch` binary, which is the
    shared, tested seam for exactly this:

    * two ``--snapshot`` reads of the pid's **cumulative** CPU counters bracket the window, so the
      difference IS the CPU the server burned serving this phase (and ``/`` the wall window gives the
      mean cores it kept busy);
    * a concurrent ``--watch`` samples RSS on a 20 ms cadence, so the report carries the peak the
      concurrent cross-tenant load actually drove — and the peak *delta* over the RSS the server already
      held when the window opened.

    Unavailable (no co-located pid — the attach mode — or an unreadable one) ⇒ every server-side figure
    is **absent** from the stats. Never a zero: "the server burned 0.000 CPU seconds serving 40 000
    requests" is exactly the fabricated measurement the evidence-honesty rules forbid.
    """

    def __init__(self, proc_watch, pid, max_secs):
        self.bin = proc_watch if (proc_watch and pid) else None
        self.pid = pid
        self.max_secs = max_secs
        self.tmpdir = None
        self.watch_proc = None
        self.before = None
        self.t0 = None
        self.note = None
        if self.bin and not (os.path.isfile(self.bin) and os.access(self.bin, os.X_OK)):
            self.note = f"proc_watch not executable at {self.bin!r}"
            self.bin = None

    def _snapshot(self):
        try:
            out = subprocess.run([self.bin, "--pid", str(self.pid), "--snapshot"],
                                 capture_output=True, text=True, timeout=15, check=True)
            return json.loads(out.stdout.strip())
        except (OSError, ValueError, subprocess.SubprocessError) as e:
            self.note = f"proc_watch --snapshot failed for pid {self.pid}: {e!r}"
            return None

    def start(self):
        """Take the opening snapshot and start the RSS watcher. Returns True when metering is live."""
        if self.bin is None:
            return False
        self.before = self._snapshot()
        if self.before is None:
            return False
        self.tmpdir = tempfile.mkdtemp(prefix="graphus-secmt-watch-")
        self.out_path = os.path.join(self.tmpdir, "watch.json")
        self.stop_path = os.path.join(self.tmpdir, "stop")
        try:
            self.watch_proc = subprocess.Popen(
                [self.bin, "--pid", str(self.pid), "--watch", "--out", self.out_path,
                 "--stop-file", self.stop_path, "--interval-ms", "20",
                 "--max-secs", str(self.max_secs)],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        except OSError as e:  # the RSS series is optional; the CPU bracket still stands
            self.note = f"proc_watch --watch could not start: {e!r}"
            self.watch_proc = None
        self.t0 = time.perf_counter()
        return True

    def finish(self):
        """Close the bracket. Returns the measured server-side stats dict (``{}`` if unmeasured)."""
        if self.bin is None or self.before is None:
            return {}
        wall = time.perf_counter() - self.t0
        after = self._snapshot()
        stats = {}
        if after is not None and wall > 0.0:
            user = max(0.0, after["user_secs"] - self.before["user_secs"])
            system = max(0.0, after["system_secs"] - self.before["system_secs"])
            stats = {
                "conc_server_user_secs": round(user, 4),
                "conc_server_system_secs": round(system, 4),
                "conc_server_cpu_secs": round(user + system, 4),
                "conc_server_cores": round((user + system) / wall, 4),
                "conc_server_rss_before_bytes": self.before["rss_bytes"],
                "conc_server_rss_after_bytes": after["rss_bytes"],
            }
        # Stop the RSS watcher and fold in its peak (best-effort: its absence must not lose the CPU).
        if self.watch_proc is not None:
            try:
                open(self.stop_path, "w").close()
                self.watch_proc.wait(timeout=20)
                with open(self.out_path) as f:
                    w = json.load(f)
                stats["conc_server_rss_peak_bytes"] = w["memory"]["peak_rss_bytes"]
                stats["conc_server_rss_peak_delta_bytes"] = w["memory"]["peak_delta_bytes"]
                stats["conc_server_rss_samples"] = w["sample_count"]
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as e:
                self.note = f"proc_watch --watch produced no RSS series: {e!r}"
                self.watch_proc.kill()
        if self.tmpdir:
            shutil.rmtree(self.tmpdir, ignore_errors=True)
        return stats


def run_concurrency_phase(base_url, insecure, manifest, token_for, workers, secs,
                          deny_supported=False, write_budget=0, server_watch=None):
    """Drive the concurrent multi-tenant isolation workload. Returns (stats_dict, violation_notes).

    ``token_for`` mints (and caches) each principal's Bearer once, up front; the workers then reuse it
    over their own persistent connections. Isolation is asserted on EVERY iteration.

    ``deny_supported`` gates the DENY-scoped oracles: against a target whose grammar predates DENY the
    grants never landed, so asserting that a denied value reads back NULL would fail a run for a
    *version gap* rather than an isolation leak. ``write_budget`` caps (and paces) each writer's
    committed writes. ``server_watch`` is an optional [`ServerWatch`] bracketing the window against the
    SERVER's pid."""
    roster = manifest.get("concurrency_workers", [])
    if not roster or workers < 1 or secs <= 0:
        return None, []

    parts = urllib.parse.urlsplit(base_url)
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    ctx = None
    if parts.scheme == "https":
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

    canary_of = {t["database"]: t["canary_secret"] for t in manifest["tenants"]}
    patients_per_tenant = max(1, len(manifest["tenants"][0].get("patients", []))
                              or _count_patients(manifest))
    write_query = manifest.get("concurrency_write", "")
    # The DENY-TRAVERSE'd multi-label node lives in exactly one tenant (`deny_tenant`); only a reader
    # scoped to THAT tenant is denied it, and only when the target accepted the DENY grants at all.
    deny_tenant = manifest.get("deny_tenant", "")
    label_canary = manifest.get("deny_label_canary", "")

    # Expand the weighted roster to exactly `workers` specs (cycle the weighted list).
    weighted = []
    for cls in roster:
        weighted.extend([cls] * max(1, int(cls.get("weight", 1))))
    specs = []
    for i in range(workers):
        cls = weighted[i % len(weighted)]
        spec = {
            "kind": cls["kind"],
            "user": cls.get("user", ""),
            "tenant": cls["tenant"],
            "other_tenant": cls["other_tenant"],
            "own_canary": canary_of.get(cls["tenant"]),
            "other_canary": canary_of.get(cls["other_tenant"]),
            "write_query": write_query,
            "patient_ids": patients_per_tenant,
            "write_budget": write_budget,
            "window_secs": secs,
            "rng_seed": 0x5EC0 ^ (i * 2654435761 & 0xFFFFFFFF),
            "bad_login_user": manifest["users"][0]["name"],  # a real account, wrong password
        }
        if cls["kind"] in ("reader", "writer", "analyst"):
            spec["token"] = token_for(cls["user"])
        if cls["kind"] == "reader" and deny_supported:
            # tenant_a's reader is denied ssn; tenant_b's reader is denied secret_token.
            spec["deny_query"] = (CONC_DENY_READ["token"] if "secret_token"
                                  in _deny_query_for(manifest, cls["user"]) else CONC_DENY_READ["ssn"])
            if label_canary and cls["tenant"] == deny_tenant:
                spec["hidden_canary"] = label_canary
        specs.append(spec)

    counters = [_new_counters() for _ in specs]
    clients = [KeepAliveClient(host, port, ctx) for _ in specs]
    stop_flag = [False]
    deadline = time.perf_counter() + secs

    # Bracket the SERVER's pid across the window (LOCAL only; absent in attach mode). Opened FIRST and
    # closed LAST so its snapshots straddle the whole workload — the CPU delta between them IS the
    # server CPU this phase cost.
    server_stats = {}
    if server_watch is not None:
        server_watch.start()

    # Bracket the driver's OWN CPU across the window (all worker threads share this process), so the
    # report can say whether the python client was itself the limiter (this suite has scar tissue: a
    # "server ceiling" that was really a client artifact).
    r0 = resource.getrusage(resource.RUSAGE_SELF)
    wall0 = time.perf_counter()

    threads = [threading.Thread(target=_conc_worker,
                                args=(specs[i], clients[i], deadline, counters[i], stop_flag),
                                daemon=True)
               for i in range(len(specs))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    wall_secs = time.perf_counter() - wall0
    r1 = resource.getrusage(resource.RUSAGE_SELF)
    if server_watch is not None:
        server_stats = server_watch.finish()
    for c in clients:
        c.close()

    client_user = max(0.0, r1.ru_utime - r0.ru_utime)
    client_system = max(0.0, r1.ru_stime - r0.ru_stime)

    agg = _new_counters()
    all_lat = []
    notes = []
    for c in counters:
        for k, v in c.items():
            if k == "lat_ms":
                all_lat.extend(v)
            elif k == "violation_notes":
                notes.extend(v)
            else:
                agg[k] += v
    all_lat.sort()

    committed = agg["write_committed"]
    aborted = agg["write_aborted"]
    abort_rate = (aborted / (committed + aborted)) if (committed + aborted) > 0 else 0.0
    ops_per_sec = (agg["ops"] / wall_secs) if wall_secs > 0 else 0.0

    stats = {
        "conc_workers": len(specs),
        "conc_secs": round(wall_secs, 4),
        "conc_ops": agg["ops"],
        "conc_ops_per_sec": round(ops_per_sec, 2),
        "conc_p50_ms": percentile_ms(all_lat, 0.50),
        "conc_p99_ms": percentile_ms(all_lat, 0.99),
        "conc_p999_ms": percentile_ms(all_lat, 0.999),
        "conc_allow_cells": agg["allow"],
        "conc_deny_cells": agg["deny"],
        "conc_unauth_cells": agg["unauth"],
        "conc_xt_probes": agg["xt_probes"],
        "conc_xt_denied": agg["xt_denied"],
        "conc_xt_empty": agg["xt_empty"],
        "conc_rbac_denied": agg["rbac_denied"],
        "conc_deny_reads": agg["deny_reads"],
        "conc_deny_null_ok": agg["deny_null_ok"],
        "conc_hidden_canary_checks": agg["hidden_canary_checks"],
        "conc_hidden_canary_ok": agg["hidden_canary_ok"],
        "conc_write_committed": committed,
        "conc_write_aborted": aborted,
        "conc_write_exhausted": agg["write_exhausted"],
        "conc_write_logical_bytes": agg["write_logical_bytes"],
        "conc_abort_rate": round(abort_rate, 6),
        "conc_metrics_gate_rejections": agg["metrics_gate_rejections"],
        "conc_transport_errors": agg["transport_errors"],
        "conc_failures": agg["failures"],
        "conc_isolation_violations": agg["isolation_violations"],
        "conc_client_user_secs": round(client_user, 4),
        "conc_client_system_secs": round(client_system, 4),
        "conc_client_cpu_secs": round(client_user + client_system, 4),
        "conc_client_cores": round((client_user + client_system) / wall_secs, 4) if wall_secs > 0 else 0.0,
    }
    # The SERVER-side bracket (LOCAL only). Merged as-is: present only when proc_watch metered the pid,
    # ABSENT (never a zero placeholder) when there was no co-located pid or it was unreadable.
    stats.update(server_stats)
    if server_watch is not None and server_watch.note:
        notes.append(f"server-side metering: {server_watch.note}")

    # Was the PYTHON CLIENT itself the limiter? (This suite's scar tissue: a reported "server ceiling"
    # that was really a driver artifact.) A multi-threaded CPython client is bound by the GIL on the
    # bytecode it runs — request marshalling, JSON parsing, the per-iteration oracle — even though its
    # SSL/socket syscalls release the GIL and let its measured CPU exceed one core. When its own CPU is
    # at least the server's, the client — not the server — bounded the achieved rate, and the report
    # must say so plainly rather than let a reader mistake a driver ceiling for a server one.
    client_cores = stats["conc_client_cores"]
    server_cores = server_stats.get("conc_server_cores")
    if server_cores is not None:
        if client_cores >= server_cores and client_cores >= 0.9:
            stats["conc_client_is_limiter"] = True
            notes.append(
                f"CLIENT-LIMITED: the python driver burned {client_cores:.2f} cores (GIL-bound "
                f"bytecode dispatch) vs the server's {server_cores:.2f}; the achieved "
                f"{stats['conc_ops_per_sec']:.0f} ops/sec is bounded by THIS client, not the server. "
                f"The isolation invariant (zero violations) is unaffected — it is asserted per "
                f"iteration regardless of rate.")
        else:
            stats["conc_client_is_limiter"] = False
    return stats, notes


def _count_patients(manifest):
    """Fallback patient count when the manifest carries tenants without inline patient arrays."""
    for t in manifest["tenants"]:
        ps = t.get("patients")
        if ps:
            return len(ps)
    return 40


def _deny_query_for(manifest, user):
    """The DENY-scoped query text that applies to ``user`` (used only to pick ssn vs secret_token)."""
    for c in manifest.get("deny_checks", []):
        if c.get("user") == user and c.get("kind") == "property_null":
            return c.get("query", "")
    return ""


def _mib(n):
    """Bytes → a compact MiB string (for the human-readable concurrency report)."""
    try:
        return f"{int(n) / (1024 * 1024):.1f} MiB"
    except (TypeError, ValueError):
        return "n/a"


def _print_concurrency_report(s, notes):
    """Render the concurrency-phase evidence as a human-readable block (the machine-readable copy
    rides in ``GRAPHUS_STATS``). Every figure shown was measured; a server-side vector that was not
    measured (attach mode: no co-located pid) is shown as ``absent``, never a fabricated zero."""
    if not s:
        print("  (concurrency phase drove no workers)")
        return
    ops = s.get("conc_ops", 0)
    secs = s.get("conc_secs", 0.0)
    print(f"  workers={s.get('conc_workers', 0)}  window={secs:g}s  "
          f"operations={ops}  ops/sec={s.get('conc_ops_per_sec', 0.0):.1f}")
    print(f"  latency ms:  p50={s.get('conc_p50_ms', 0.0):.3f}  "
          f"p99={s.get('conc_p99_ms', 0.0):.3f}  p999={s.get('conc_p999_ms', 0.0):.3f}")
    print(f"  cross-tenant probes={s.get('conc_xt_probes', 0)}  "
          f"denied(403)={s.get('conc_xt_denied', 0)}  empty(200/0)={s.get('conc_xt_empty', 0)}")
    print(f"  RBAC denials={s.get('conc_rbac_denied', 0)}  "
          f"DENY-scoped reads={s.get('conc_deny_reads', 0)} (null-ok={s.get('conc_deny_null_ok', 0)})  "
          f"#645 hidden-label checks={s.get('conc_hidden_canary_checks', 0)} "
          f"(ok={s.get('conc_hidden_canary_ok', 0)})")
    print(f"  auth rejections={s.get('conc_unauth_cells', 0)} "
          f"(/metrics-gate={s.get('conc_metrics_gate_rejections', 0)})")
    print(f"  writes: committed={s.get('conc_write_committed', 0)}  "
          f"SSI-aborted(retried)={s.get('conc_write_aborted', 0)}  "
          f"abort_rate={s.get('conc_abort_rate', 0.0):.4f}  "
          f"logical_bytes={s.get('conc_write_logical_bytes', 0)}")
    viol = s.get("conc_isolation_violations", 0)
    marker = "OK " if viol == 0 else "BAD"
    print(f"  {marker} isolation violations={viol}   "
          f"failures={s.get('conc_failures', 0)}  transport_errors={s.get('conc_transport_errors', 0)}")
    # The client's own CPU — this suite has scar tissue where a "server ceiling" was a CLIENT artifact.
    cc = s.get("conc_client_cores")
    if cc is not None:
        print(f"  CLIENT (python driver) cpu: {s.get('conc_client_cpu_secs', 0.0):.2f}s over {secs:g}s "
              f"=> {cc:.2f} cores busy")
    # The SERVER-side bracket (LOCAL only). ABSENT in attach mode — shown as such, never a zero.
    if "conc_server_cores" in s:
        print(f"  SERVER (pid) cpu: {s.get('conc_server_cpu_secs', 0.0):.2f}s over {secs:g}s "
              f"=> {s['conc_server_cores']:.2f} cores busy   "
              f"peak RSS={_mib(s.get('conc_server_rss_peak_bytes'))} "
              f"(+{_mib(s.get('conc_server_rss_peak_delta_bytes'))} over baseline)")
    else:
        print("  SERVER (pid) cpu/RSS: absent (attach mode has no co-located pid — measured only LOCAL)")
    for n in notes[:6]:
        print(f"  · {n}")


# --------------------------------------------------------------------------------------------------
# Main.
# --------------------------------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Graphus multi-tenant RBAC matrix over REST")
    ap.add_argument("--base-url", required=True, help="REST base URL, e.g. https://host:7474")
    ap.add_argument("--admin-user", required=True, help="bootstrap admin username")
    ap.add_argument("--admin-password", required=True, help="bootstrap admin password")
    ap.add_argument("--data-dir", required=True, help="dir with manifest.json + *.cypher")
    ap.add_argument("--system-db", default="graphus", help="DB the admin DDL is routed through")
    ap.add_argument("--insecure", action="store_true", help="accept a self-signed TLS cert")
    ap.add_argument("--workers", type=int, default=0,
                    help="concurrency-phase worker count (0 = skip the concurrency phase)")
    ap.add_argument("--secs", type=float, default=0.0,
                    help="concurrency-phase window in seconds (0 = skip)")
    ap.add_argument("--write-budget", type=int, default=0,
                    help="max committed writes per writer over the window (0 = unbounded); paced so "
                         "the writes spread across the whole window and the durable footprint is bounded")
    ap.add_argument("--server-pid", type=int, default=0,
                    help="LOCAL only: the graphus-server pid, bracketed via --proc-watch so the report "
                         "shows the SERVER's CPU/RSS during the concurrency window (absent in attach mode)")
    ap.add_argument("--proc-watch", default="",
                    help="path to the harness proc_watch binary (required to sample --server-pid)")
    args = ap.parse_args()

    with open(os.path.join(args.data_dir, "manifest.json")) as f:
        manifest = json.load(f)

    client = RestClient(args.base_url, args.insecure)

    # Per-user login (POST /auth/login), cached. The admin maps from the manifest's canonical
    # admin_user placeholder to the actual --admin-user/--admin-password of the target.
    manifest_admin = manifest["admin_user"]
    token_cache = {}

    def token_for(user):
        if user is None:
            return None  # the unauthenticated probe
        if user in token_cache:
            return token_cache[user]
        if user == manifest_admin:
            tok = client.login(args.admin_user, args.admin_password)
        else:
            u = next((x for x in manifest["users"] if x["name"] == user), None)
            if u is None:
                raise RuntimeError(f"user {user!r} not found in manifest")
            tok = client.login(u["name"], u["password"])
        token_cache[user] = tok
        return tok

    admin_token = token_for(manifest_admin)
    print(f"== authenticated admin {args.admin_user!r} via POST /auth/login")

    # ---- Provision + seed --------------------------------------------------------------------------
    print("== provision tenants / roles / users / grants (admin over REST)")
    n_provision = provision(
        client, admin_token, args.system_db,
        parse_statements(os.path.join(args.data_dir, "provision.cypher")),
    )
    print(f"  ran {n_provision} provisioning statements")

    print("== seed each tenant's sensitive data (admin, inside the tenant database)")
    total_seeded = 0
    for t in manifest["tenants"]:
        db = t["database"]
        path = os.path.join(args.data_dir, f"{db}.cypher")
        seeded = seed(client, admin_token, db, parse_statements(path))
        total_seeded += seeded
        print(f"  seeded {db}: {seeded} statements")

    # ---- Fine-grained DENY (feature-detected) ------------------------------------------------------
    print("== fine-grained DENY (property-scope + label-scope; #645 regression guard)")
    deny_stmts = manifest.get("deny_grants", [])
    deny_supported = False
    deny_asserted = 0
    if deny_stmts:
        deny_supported = try_deny_provision(client, admin_token, args.system_db, deny_stmts)
        if deny_supported:
            # Seed the multi-label node the #645 guard keys on, inside the denied tenant.
            deny_tenant = manifest.get("deny_tenant", "")
            deny_seed_stmts = manifest.get("deny_seed", [])
            if deny_seed_stmts and deny_tenant:
                seed(client, admin_token, deny_tenant, deny_seed_stmts)
            deny_asserted = run_deny_checks(
                client, token_for, manifest_admin, manifest.get("deny_checks", [])
            )
            print(f"  DENY supported: asserted {deny_asserted} fine-grained deny check(s)")
        else:
            print("  DENY NOT supported by this target (older grammar) — version gap RECORDED, "
                  "checks skipped (validate modern DENY coverage against a current server)")

    # ---- The allow/deny/unauthenticated matrix -----------------------------------------------------
    print("== RBAC allow/deny matrix")
    rows = []
    allow = deny = unauth = 0
    for cell in manifest["matrix"]:
        st, text, nrows = run_matrix_cell(client, token_for, cell)
        okk = assert_cell(cell, st, text, nrows)
        rows.append((cell["user"] or "<anon>", cell["tenant"], cell["access_mode"],
                     cell["outcome"], st, "ok" if okk else "FAIL", cell["why"]))
        allow += cell["outcome"] == "allow"
        deny += cell["outcome"] == "deny"
        unauth += cell["outcome"] == "unauthenticated"

    # ---- Broadened cross-tenant negatives ----------------------------------------------------------
    print("== broadened cross-tenant negatives (alice -> tenant_b: ssn / secret_token / all / count)")
    xt_asserted = xt_denied = xt_empty = 0
    reader = next((u["name"] for u in manifest["users"] if u["role"] == manifest["roles"][0]["name"]), None)
    other = manifest["tenants"][1]["database"]  # tenant_b
    probes = manifest.get("cross_tenant_probes", [])
    if reader and probes:
        xt_asserted, xt_denied, xt_empty = run_cross_tenant(client, token_for, reader, other, probes)

    # ---- Table -------------------------------------------------------------------------------------
    print()
    print(f"  {'USER':<9}{'TENANT':<26}{'MODE':<6}{'EXPECT':<8}{'HTTP':<6}{'RESULT':<6}WHY")
    for (user, tenant, mode, outcome, st, res, why) in rows:
        print(f"  {user:<9}{tenant:<26}{mode:<6}{outcome:<8}{st:<6}{res:<6}{why}")

    # ---- Concurrency phase -------------------------------------------------------------------------
    # The serial matrix above proves the RBAC DECISIONS. This phase proves ISOLATION HOLDS UNDER
    # GENUINELY CONCURRENT CROSS-TENANT LOAD — the property a ~46-op serial pass cannot exercise.
    conc_stats = {}
    if args.workers > 0 and args.secs > 0.0:
        print()
        print(f"== concurrency phase: {args.workers} workers x {args.secs:g}s against both tenants "
              f"(isolation asserted on EVERY iteration)")
        # A generous ceiling: the watcher stops on the stop-file the instant the window closes; the cap
        # is only a fail-safe against a hung window.
        watch = ServerWatch(args.proc_watch or None, args.server_pid or None,
                            max_secs=args.secs * 4 + 30.0)
        conc_stats, conc_notes = run_concurrency_phase(
            args.base_url, args.insecure, manifest, token_for,
            workers=args.workers, secs=args.secs,
            deny_supported=deny_supported, write_budget=args.write_budget, server_watch=watch,
        )
        if conc_stats is None:
            conc_stats = {}
        _print_concurrency_report(conc_stats, conc_notes)
        # The gates that CAN genuinely fire.
        viol = conc_stats.get("conc_isolation_violations", 0)
        ops = conc_stats.get("conc_ops", 0)
        check("concurrency: ZERO isolation violations across all cross-tenant probes",
              viol == 0, f"{viol} violation(s): {conc_notes[:4]}")
        check("concurrency: the phase actually drove operations", ops > 0,
              "no operations ran — the workers never issued a request")
        # Every cross-tenant probe issued was denied or empty (no partial-leak middle ground).
        xt = conc_stats.get("conc_xt_probes", 0)
        xt_blocked = conc_stats.get("conc_xt_denied", 0) + conc_stats.get("conc_xt_empty", 0)
        check("concurrency: every cross-tenant probe was denied or returned empty",
              xt > 0 and xt_blocked == xt, f"probes={xt} denied+empty={xt_blocked}")
        # When DENY landed, the DENY-scoped value read back NULL (or was coarse-gated) on every read.
        if deny_supported:
            dr = conc_stats.get("conc_deny_reads", 0)
            dn = conc_stats.get("conc_deny_null_ok", 0)
            check("concurrency: the DENY-scoped value read back NULL on every iteration",
                  dr > 0 and dn == dr, f"deny_reads={dr} null_ok={dn}")

    if FAILURES == 0:
        print("GRAPHUS_RBAC_OK")
        # REAL per-request latency of the RBAC-enforced REST calls this client issued (rmp #699).
        # `rest_workload_secs` is the summed wall-time of those requests: this client is serial (one
        # request at a time), so that sum IS the window they were issued in, and
        # `rest_requests / rest_workload_secs` is a real achieved rate. The report previously carried
        # p50/p99/p999 = 0.000 placeholders and an ops_per_sec of `seeded_statements / server-uptime`,
        # neither of which was ever measured.
        lat = sorted(client.request_ms)
        stats = {
            "tenants": len(manifest["tenants"]),
            "roles": len(manifest["roles"]),
            "users": len(manifest["users"]),
            "provision_statements": n_provision,
            "seeded_statements": total_seeded,
            "matrix_cells": len(manifest["matrix"]),
            "allow_cells": allow,
            "deny_cells": deny,
            "unauth_cells": unauth,
            "deny_supported": deny_supported,
            "deny_checks": deny_asserted,
            "cross_tenant_probes": xt_asserted,
            "cross_tenant_denied": xt_denied,
            "cross_tenant_empty": xt_empty,
            "rest_requests": len(lat),
            "rest_workload_secs": round(sum(lat) / 1000.0, 6),
            "p50_ms": percentile_ms(lat, 0.50),
            "p99_ms": percentile_ms(lat, 0.99),
            "p999_ms": percentile_ms(lat, 0.999),
        }
        # The concurrency-phase figures ride in the SAME machine-readable line (run.sh harvests them
        # into the evidence report). Absent when the phase was not run.
        stats.update(conc_stats)
        print("GRAPHUS_STATS " + json.dumps(stats, separators=(",", ":")))
        return 0

    print(f"GRAPHUS_RBAC_FAILED — {FAILURES} assertion(s) did not hold")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
