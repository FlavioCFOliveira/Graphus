#!/usr/bin/env python3
"""Network bulk-import (Mode A) of the influence network into a running server (``rmp`` #717).

The GDS example's default profile is a **2 400-author / 24 000-citation** network — the smallest graph
at which the server's *per-algorithm* core utilisation is a real measurement rather than clock-tick
noise (see ``examples/gds-analytics/README.md``). Getting a graph that size into the database is the
one thing that used to make such a default impractical: replaying ``graph.cypher`` as one
``MATCH … MATCH … CREATE`` per edge sustains ~3 000 edges/s, because the rule-based planner index-seeks
only the *first* anchor of a two-anchor ``CREATE`` and label-scans the second.

So the LOCAL run loads through the ratified **network bulk-import, Mode A**
(``specification/08-network-bulk-import.md``, ``rmp`` #518/#519) instead — the same path
``product-recommendations`` uses, and the path a real operator would use for a real network. Measured
on a 16-core host: **0.20 s** for 2 406 nodes + 23 962 relationships, against **~8 s** for the Cypher
replay of the identical graph (~35x). That is the difference between "the CPU battery is affordable by
default" and "nobody ever runs it".

The flow is exactly the endpoint contract the server's own ``tests/bulk_import_endpoint.rs`` pins:

1. ``POST /auth/login``                                   → the admin Bearer token;
2. ``CREATE DATABASE <db>``                               → a **fresh, empty** Mode A target;
3. ``POST /admin/db/<db>/bulk-import?phase=nodes``        (``Content-Type: text/csv``) — ``nodes.csv``;
4. ``POST /admin/db/<db>/bulk-import?phase=relationships`` — ``relationships.csv`` (endpoints resolve
   against the id-map the node phase built, in the same Loading session);
5. ``POST /admin/db/<db>/bulk-import?end=true``           → the ingest totals, which we ASSERT against
   what the generator says it emitted (a silently short load would otherwise be analysed happily);
6. ``START DATABASE <db>``                                → Mode A leaves the database offline; it must
   be brought online before a client can query it.

The schema DDL is deliberately **not** applied here: ``analyze.js`` applies it (idempotently) in both
run modes, so the constraint/index surface is exercised identically whether the graph arrived by bulk
import or by Cypher.

Pure stdlib (``http.client`` + ``ssl`` + ``json``): the example already requires ``python3``, and this
adds no dependency. On success it prints one machine-readable ``GRAPHUS_BULK_OK {...}`` line with the
ingest totals and the measured load seconds; on any failure it prints the server's status + body and
exits non-zero.

Usage::

    bulk_load.py --base-url https://127.0.0.1:7474 --user <u> --password <pw> \
                 --db <target-db> --data-dir <dir> [--system-db graphus] [--insecure] \
                 --expect-nodes N --expect-rels M
"""

import argparse
import http.client
import json
import os
import ssl
import sys
import time
import urllib.parse

# A bulk upload of a large CSV is a single request the server streams into the store: give it room.
TIMEOUT_SECS = 300.0


class Rest:
    """A single keep-alive HTTP(S) connection to the target's REST API."""

    def __init__(self, base_url, insecure):
        parts = urllib.parse.urlsplit(base_url)
        self.host = parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.https = parts.scheme == "https"
        self.ctx = None
        if self.https:
            self.ctx = ssl.create_default_context()
            if insecure:
                # A self-signed cert the example minted itself: encrypt, but do not authenticate the
                # peer. Exactly what `GRAPHUS_TARGET_TLS_INSECURE=1` means elsewhere in the suite.
                self.ctx.check_hostname = False
                self.ctx.verify_mode = ssl.CERT_NONE
        self.conn = self._connect()
        self.token = None

    def _connect(self):
        if self.https:
            return http.client.HTTPSConnection(
                self.host, self.port, context=self.ctx, timeout=TIMEOUT_SECS
            )
        return http.client.HTTPConnection(self.host, self.port, timeout=TIMEOUT_SECS)

    def request(self, method, path, body=None, headers=None):
        self.conn.request(method, path, body=body, headers=headers or {})
        resp = self.conn.getresponse()
        return resp.status, resp.read()

    def login(self, user, password):
        st, body = self.request(
            "POST",
            "/auth/login",
            json.dumps({"username": user, "password": password}).encode(),
            {"Content-Type": "application/json", "Accept": "application/json"},
        )
        if st != 200:
            die(f"POST /auth/login failed: HTTP {st}: {body[:200]!r}")
        tok = json.loads(body).get("token")
        if not tok:
            die(f"POST /auth/login returned no token: {body[:200]!r}")
        self.token = tok
        return tok

    def statement(self, db, cypher):
        """Runs one Cypher statement against ``db`` via the one-shot transactional endpoint."""
        st, body = self.request(
            "POST",
            f"/db/{db}/tx/commit",
            json.dumps({"statements": [{"statement": cypher}]}).encode(),
            {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        if st != 200:
            die(f"{cypher!r} failed: HTTP {st}: {body[:300]!r}")
        payload = json.loads(body)
        errors = payload.get("errors") or []
        if errors:
            die(f"{cypher!r} failed: {errors}")
        return payload

    def bulk(self, db, query, csv_bytes):
        """One `POST /admin/db/<db>/bulk-import?<query>` with a `text/csv` body."""
        st, body = self.request(
            "POST",
            f"/admin/db/{db}/bulk-import?{query}",
            csv_bytes,
            {"Authorization": f"Bearer {self.token}", "Content-Type": "text/csv"},
        )
        if st != 200:
            die(f"bulk-import?{query} failed: HTTP {st}: {body[:300]!r}")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            die(f"bulk-import?{query} returned a malformed body: {body[:200]!r}")


def die(msg):
    print(f"GRAPHUS_BULK_FAILED {msg}", file=sys.stderr)
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser(description="Network bulk-import (Mode A) of the GDS influence network")
    ap.add_argument("--base-url", required=True, help="REST base URL, e.g. https://127.0.0.1:7474")
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--db", required=True, help="the FRESH database to create and load into")
    ap.add_argument("--system-db", default="graphus", help="database the admin DDL is routed through")
    ap.add_argument("--data-dir", required=True, help="dir holding nodes.csv + relationships.csv")
    ap.add_argument("--insecure", action="store_true", help="accept a self-signed TLS certificate")
    ap.add_argument("--expect-nodes", type=int, required=True)
    ap.add_argument("--expect-rels", type=int, required=True)
    args = ap.parse_args()

    nodes_csv = os.path.join(args.data_dir, "nodes.csv")
    rels_csv = os.path.join(args.data_dir, "relationships.csv")
    for path in (nodes_csv, rels_csv):
        if not os.path.isfile(path):
            die(f"missing bulk-import artifact {path} (run gds_gen first)")

    rest = Rest(args.base_url, args.insecure)
    rest.login(args.user, args.password)

    # Mode A wants a fresh, empty database. `IF NOT EXISTS` keeps a re-run against the same server
    # harmless, but the run-scoped name means it is normally brand new.
    rest.statement(args.system_db, f"CREATE DATABASE {args.db} IF NOT EXISTS")

    with open(nodes_csv, "rb") as fh:
        nodes = fh.read()
    with open(rels_csv, "rb") as fh:
        rels = fh.read()

    # The load window: exactly the three uploads, nothing else. This is the figure the README quotes
    # against the Cypher path, so it must not smuggle in login, DDL or file I/O.
    t0 = time.perf_counter()
    rest.bulk(args.db, "phase=nodes", nodes)
    rest.bulk(args.db, "phase=relationships", rels)
    end = rest.bulk(args.db, "end=true", b"")
    load_secs = time.perf_counter() - t0

    got_nodes = end.get("nodes")
    got_rels = end.get("relationships")
    if got_nodes != args.expect_nodes:
        die(f"bulk end=true ingested {got_nodes} nodes, expected {args.expect_nodes}")
    if got_rels != args.expect_rels:
        die(f"bulk end=true ingested {got_rels} relationships, expected {args.expect_rels}")

    # Mode A leaves the target OFFLINE (the loading session owns the store until it ends). Bring it
    # online, or every query that follows fails with "database is not currently online".
    rest.statement(args.system_db, f"START DATABASE {args.db}")

    stats = {
        "database": args.db,
        "nodes": got_nodes,
        "relationships": got_rels,
        "properties": end.get("properties"),
        "load_secs": round(load_secs, 4),
        "nodes_per_sec": round(got_nodes / load_secs, 1) if load_secs > 0 else None,
        "rels_per_sec": round(got_rels / load_secs, 1) if load_secs > 0 else None,
    }
    print("GRAPHUS_BULK_OK " + json.dumps(stats, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
