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

On success it prints ``GRAPHUS_RBAC_OK`` and a single machine-readable ``GRAPHUS_STATS {...}`` line.

Usage::

    matrix.py --base-url https://host:7474 --admin-user <u> --admin-password <pw> \
              --data-dir <dir> [--system-db graphus] [--insecure]

Teardown (DROP of every database/role/user) is owned by run.sh's cleanup trap, not this client.
"""

import argparse
import json
import os
import ssl
import urllib.error
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
        try:
            resp = self._open(req)
            return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()


# --------------------------------------------------------------------------------------------------
# .cypher parsing + strict-Jolt cell decoding.
# --------------------------------------------------------------------------------------------------
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

    if FAILURES == 0:
        print("GRAPHUS_RBAC_OK")
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
        }
        print("GRAPHUS_STATS " + json.dumps(stats, separators=(",", ":")))
        return 0

    print(f"GRAPHUS_RBAC_FAILED — {FAILURES} assertion(s) did not hold")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
