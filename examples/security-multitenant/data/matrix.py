#!/usr/bin/env python3
"""Multi-tenant RBAC allow/deny matrix over the Graphus REST API (security-multitenant example).

A pure-stdlib client (``urllib`` + ``ssl`` + ``hmac``/``hashlib``/``base64`` + ``json``) that drives
the **REST transactional API** over HTTPS against a live, **encrypted** ``graphus-server`` and proves
the fine-grained RBAC authorization matrix from the generator's ``manifest.json``:

1. **Provision** (as the bootstrap admin ``neo4j``) — replays the generator's ``provision.cypher``
   (``CREATE DATABASE / ROLE / USER`` + ``GRANT``s) over ``/db/graphus/tx/commit``, then seeds each
   tenant's sensitive data (``tenant_<name>.cypher``) inside that tenant's database. Admin DDL is
   database-agnostic and runs as auto-commit (it is rejected inside an explicit transaction).
2. **Matrix** — for every ``(user, tenant, access_mode)`` cell in the manifest, mints that user's own
   HS256 Bearer JWT out of band and issues a probe (``MATCH (s:Secret) RETURN s.name`` for READ, a
   harmless ``CREATE (:Probe)`` for WRITE), asserting the cell's expected outcome:
   - ``allow`` ⇒ HTTP **200**,
   - ``deny``  ⇒ HTTP **403** (``Neo.ClientError.Security.Forbidden``),
   - ``unauthenticated`` ⇒ HTTP **401** (no Bearer header at all).
   Crucially, READ probes send ``"access_mode":"READ"`` (the API defaults to WRITE, which a read-only
   user is denied), so a 403 on a READ cell is a genuine *read* denial, not a mode mismatch.
3. **Table** — prints the full matrix as a table (user × tenant × mode → expected/got).

On success it prints ``GRAPHUS_RBAC_OK`` and a single machine-readable ``GRAPHUS_STATS {...}`` line.
Any failed cell prints the mismatch and the script exits non-zero.

Usage::

    matrix.py --port <p> --secret <jwt_secret> --manifest <manifest.json> \
              --provision <provision.cypher> --tenant-dir <dir> [--admin neo4j] [--admin-pw <pw>]
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import ssl
import time
import urllib.error
import urllib.request


# --------------------------------------------------------------------------------------------------
# JWT (HS256) — minted with the stdlib only (no PyJWT). The server validates the signature, the
# iss/aud binding (both "graphus"), the required claims, that `sub` names a live catalog user, and
# that `ver` >= the user's credential epoch (a fresh user is at epoch 0). The `sub` selects the
# user's RBAC. See crates/graphus-auth/src/token.rs.
# --------------------------------------------------------------------------------------------------
def _b64u(b: bytes) -> bytes:
    return base64.urlsafe_b64encode(b).rstrip(b"=")


def mint_jwt(secret: bytes, subject: str, ttl_secs: int = 3600) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + ttl_secs,
        "iss": "graphus",
        "aud": "graphus",
        "jti": f"sec-mt-{now}-{subject}",
        "ver": 0,
    }
    signing_input = (
        _b64u(json.dumps(header, separators=(",", ":")).encode())
        + b"."
        + _b64u(json.dumps(payload, separators=(",", ":")).encode())
    )
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + _b64u(sig)).decode()


# --------------------------------------------------------------------------------------------------
# REST client.
# --------------------------------------------------------------------------------------------------
class RestClient:
    """A thin HTTPS REST client for the Graphus transactional API (self-signed TLS, Bearer JWT)."""

    def __init__(self, port):
        self.base = f"https://127.0.0.1:{port}"
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

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
            resp = urllib.request.urlopen(req, context=self.ctx)
            return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()


# --------------------------------------------------------------------------------------------------
# Provisioning + tenant seeding (as the admin).
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


FAILURES = 0


def check(name, got, want):
    global FAILURES
    ok = got == want
    if not ok:
        FAILURES += 1
    print(f"  {'OK ' if ok else 'BAD'} {name}: got {got!r} want {want!r}")
    return ok


def provision(client, admin_token, provision_path):
    """Runs the admin RBAC DDL (databases, roles, grants, users) over the `graphus` database."""
    stmts = parse_statements(provision_path)
    for s in stmts:
        st, body = client.commit("graphus", [{"statement": s}], token=admin_token)
        if st != 200:
            raise RuntimeError(f"provision failed ({st}): {s[:80]} :: {body[:200]}")
    return len(stmts)


def seed_tenant(client, admin_token, db, tenant_cypher):
    """Seeds one tenant's sensitive data inside its own database (as the admin)."""
    stmts = parse_statements(tenant_cypher)
    loaded = 0
    # Batch the data CREATEs for speed; each batch is one atomic auto-commit transaction.
    BATCH = 200
    for i in range(0, len(stmts), BATCH):
        chunk = stmts[i : i + BATCH]
        st, body = client.commit(
            db, [{"statement": s} for s in chunk], token=admin_token, access_mode="WRITE"
        )
        if st != 200:
            raise RuntimeError(f"seed {db} failed ({st}): {body[:200]}")
        loaded += len(chunk)
    return loaded


# --------------------------------------------------------------------------------------------------
# The matrix.
# --------------------------------------------------------------------------------------------------
# A READ probe (read-only; sent with access_mode=READ) and a WRITE probe (a harmless create).
READ_PROBE = "MATCH (s:Secret) RETURN s.name AS name"
WRITE_PROBE = "CREATE (:RbacProbe {ts: 1})"

# The error code a denied operation carries (the server returns it in the body).
FORBIDDEN_CODE = "Neo.ClientError.Security.Forbidden"


def run_cell(client, secret, cell):
    """Drives one matrix cell and returns ``(status, body_text)``."""
    user = cell["user"]
    db = cell["tenant"]
    mode = cell["access_mode"]
    token = None if user is None else mint_jwt(secret, user)
    if mode == "READ":
        st, body = client.commit(
            db, [{"statement": READ_PROBE}], token=token, access_mode="READ"
        )
    else:
        st, body = client.commit(
            db, [{"statement": WRITE_PROBE}], token=token, access_mode="WRITE"
        )
    return st, body.decode("utf-8", "replace")


def expected_status(outcome):
    return {"allow": 200, "deny": 403, "unauthenticated": 401}[outcome]


def main():
    ap = argparse.ArgumentParser(description="Graphus multi-tenant RBAC matrix over REST")
    ap.add_argument("--port", required=True)
    ap.add_argument("--secret", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--provision", required=True)
    ap.add_argument("--tenant-dir", required=True)
    ap.add_argument("--admin", default="neo4j")
    args = ap.parse_args()

    secret = args.secret.encode()
    with open(args.manifest) as f:
        manifest = json.load(f)

    client = RestClient(args.port)
    admin_token = mint_jwt(secret, args.admin)

    print("== provision tenants / roles / users / grants (admin over REST)")
    n_provision = provision(client, admin_token, args.provision)
    print(f"  ran {n_provision} provisioning statements")

    print("== seed each tenant's sensitive data (admin, inside the tenant database)")
    total_seeded = 0
    for t in manifest["tenants"]:
        db = t["database"]
        path = os.path.join(
            args.tenant_dir, "tenant_" + db.replace("tenant_", "") + ".cypher"
        )
        seeded = seed_tenant(client, admin_token, db, path)
        total_seeded += seeded
        print(f"  seeded {db}: {seeded} statements")

    print("== RBAC allow/deny matrix")
    rows = []
    allow = deny = unauth = 0
    for cell in manifest["matrix"]:
        st, body = run_cell(client, secret, cell)
        want = expected_status(cell["outcome"])
        ok = check(
            f"{(cell['user'] or '<anon>'):>6} {cell['access_mode']:<5} {cell['tenant']:<9} "
            f"[{cell['outcome']}]",
            st,
            want,
        )
        # On a deny, additionally confirm the Forbidden error code rode in the body.
        if cell["outcome"] == "deny" and st == 403:
            if FORBIDDEN_CODE not in body:
                global FAILURES
                FAILURES += 1
                print(f"      BAD expected {FORBIDDEN_CODE} in 403 body; got: {body[:160]}")
        rows.append((cell["user"] or "<anon>", cell["tenant"], cell["access_mode"],
                     cell["outcome"], st, "ok" if ok else "FAIL", cell["why"]))
        if cell["outcome"] == "allow":
            allow += 1
        elif cell["outcome"] == "deny":
            deny += 1
        else:
            unauth += 1

    # Pretty matrix table.
    print()
    print(f"  {'USER':<7}{'TENANT':<11}{'MODE':<6}{'EXPECT':<8}{'HTTP':<6}{'RESULT':<6}WHY")
    print(f"  {'-'*7}{'-'*11}{'-'*6}{'-'*8}{'-'*6}{'-'*6}{'-'*40}")
    for (user, tenant, mode, outcome, st, res, why) in rows:
        print(f"  {user:<7}{tenant:<11}{mode:<6}{outcome:<8}{st:<6}{res:<6}{why}")

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
        }
        print("GRAPHUS_STATS " + json.dumps(stats, separators=(",", ":")))
        return 0

    print(f"GRAPHUS_RBAC_FAILED — {FAILURES} cell(s) did not hold")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
