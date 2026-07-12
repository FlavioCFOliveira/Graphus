#!/usr/bin/env python3
"""Knowledge-graph discovery workload over the Graphus REST API (rmp #280 + #281 + #692).

A pure-stdlib client (``http.client`` + ``ssl`` + ``json``) that drives the **REST transactional
API** over HTTPS against a live ``graphus-server`` — self-booted locally, or an ALREADY-RUNNING
instance (local or remote) the run attaches to:

1. **Auth** — obtains a Bearer token from ``POST /auth/login`` (username + password), and proves an
   **unauthenticated** request is rejected ``401``.
2. **Load** — replays the generator's ``graph.cypher`` over the REST one-shot ``/db/{db}/tx/commit``
   endpoint, **batching** many statements per HTTP request (the schema DDL runs as standalone
   auto-commit statements first). Each batch is one atomic auto-commit **WRITE** transaction.
3. **Transactional lifecycle** — opens an **explicit** transaction (``POST /db/{db}/tx`` → run in it
   → ``/commit``) and a **rollback**, proving begin/commit/rollback semantics over the API.
4. **Discovery** — issues the five canonical knowledge-graph discovery queries (entity lookup,
   multi-hop semantic traversal, recommendation, aggregation, concept path) and **asserts** every
   answer against the generator's ``reference.json``.
5. **NDJSON streaming** — requests a large result with ``Accept: application/x-ndjson`` and verifies
   it arrives as one JSON object per line, parsed **incrementally** client-side.
6. **Content negotiation** — requests the *same* query as JSON and as CBOR and asserts both decode to
   the **same logical result** (a minimal in-script RFC 8949 CBOR decoder), capturing the payload
   size of each encoding.
7. **Concurrency** — drives ``--clients`` concurrent HTTP clients issuing the discovery workload,
   asserting **zero errors** and reporting throughput + latency percentiles.

Every read query carries ``access_mode: "READ"`` so it dispatches to the server's **off-thread
reader pool** (rmp #527/#543) — a single-statement WRITE auto-commit would run inline on the engine
thread and would NOT scale across cores. Each client keeps a **persistent (keep-alive) HTTPS
connection** so throughput/latency reflect the server, not per-op TCP+TLS handshakes.

On success it prints ``GRAPHUS_KG_REST_OK`` and a single machine-readable ``GRAPHUS_STATS {...}`` line
(parsed by ``run.sh`` for the evidence report). Any failed assertion prints the mismatch and exits
non-zero.

Usage::

    discovery.py --base-url https://host:port --user <u> --password <p> \
                 --database <db> --cypher <graph.cypher> --reference <reference.json> \
                 [--token <bearer>] [--insecure] [--clients N] [--ops-per-client M]
"""

import argparse
import http.client
import json
import multiprocessing as mp
import os
import resource
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse


# --------------------------------------------------------------------------------------------------
# Minimal RFC 8949 CBOR decoder (the subset the Jolt-over-CBOR response uses: unsigned/negative ints,
# byte/text strings, arrays, maps, bool, null, float16/32/64). Pure stdlib — Python has no built-in
# CBOR, so we decode it ourselves to PROVE the CBOR body is logically identical to the JSON body.
# --------------------------------------------------------------------------------------------------
def cbor_decode(buf: bytes, i: int = 0):
    """Decodes one CBOR data item from ``buf`` at offset ``i``, returning ``(value, next_offset)``."""
    ib = buf[i]
    major = ib >> 5
    ai = ib & 0x1F
    i += 1

    def read_uint(ai_, i_):
        if ai_ < 24:
            return ai_, i_
        if ai_ == 24:
            return buf[i_], i_ + 1
        if ai_ == 25:
            return int.from_bytes(buf[i_ : i_ + 2], "big"), i_ + 2
        if ai_ == 26:
            return int.from_bytes(buf[i_ : i_ + 4], "big"), i_ + 4
        if ai_ == 27:
            return int.from_bytes(buf[i_ : i_ + 8], "big"), i_ + 8
        raise ValueError(f"unsupported additional-info {ai_}")

    if major == 0:  # unsigned int
        v, i = read_uint(ai, i)
        return v, i
    if major == 1:  # negative int
        v, i = read_uint(ai, i)
        return -1 - v, i
    if major == 2:  # byte string
        n, i = read_uint(ai, i)
        return bytes(buf[i : i + n]), i + n
    if major == 3:  # text string
        n, i = read_uint(ai, i)
        return buf[i : i + n].decode("utf-8"), i + n
    if major == 4:  # array
        n, i = read_uint(ai, i)
        out = []
        for _ in range(n):
            v, i = cbor_decode(buf, i)
            out.append(v)
        return out, i
    if major == 5:  # map
        n, i = read_uint(ai, i)
        out = {}
        for _ in range(n):
            k, i = cbor_decode(buf, i)
            v, i = cbor_decode(buf, i)
            out[k] = v
        return out, i
    if major == 7:  # simple / float
        if ai == 20:
            return False, i
        if ai == 21:
            return True, i
        if ai == 22:
            return None, i
        if ai == 25:
            return _float16(buf[i : i + 2]), i + 2
        if ai == 26:
            return struct.unpack(">f", buf[i : i + 4])[0], i + 4
        if ai == 27:
            return struct.unpack(">d", buf[i : i + 8])[0], i + 8
    raise ValueError(f"unsupported CBOR major={major} ai={ai}")


def _float16(b: bytes) -> float:
    """Decodes an IEEE-754 half-precision float (CBOR ai 25)."""
    (h,) = struct.unpack(">H", b)
    sign = (h >> 15) & 0x1
    exp = (h >> 10) & 0x1F
    frac = h & 0x3FF
    if exp == 0:
        val = (frac / 1024.0) * (2.0 ** -14)
    elif exp == 0x1F:
        val = float("inf") if frac == 0 else float("nan")
    else:
        val = (1 + frac / 1024.0) * (2.0 ** (exp - 15))
    return -val if sign else val


# --------------------------------------------------------------------------------------------------
# REST client — a thin HTTPS client for the Graphus transactional API over a PERSISTENT (keep-alive)
# connection. Each client owns ONE `http.client.HTTPSConnection`, reused across requests so latency
# and throughput reflect the server rather than a fresh TCP+TLS handshake per operation. The
# connection is not thread-safe, so every concurrency worker builds its OWN client (one connection
# per worker thread).
# --------------------------------------------------------------------------------------------------
class RestClient:
    """A keep-alive HTTPS REST client for the Graphus transactional API (self-signed-TLS aware,
    Bearer-JWT authenticated via ``POST /auth/login``)."""

    def __init__(self, base_url, token=None, database="graphus", insecure=True):
        parts = urllib.parse.urlsplit(base_url)
        self.scheme = parts.scheme or "https"
        self.host = parts.hostname or "127.0.0.1"
        self.port = parts.port or (443 if self.scheme == "https" else 80)
        self.base = f"{self.scheme}://{self.host}:{self.port}"
        self.token = token
        self.db = database
        self.insecure = insecure
        # Self-signed cert (local demo cert, or a remote box's self-signed cert): trust it explicitly
        # when --insecure is set. This is a demo/attach convenience, not the public web.
        self.ctx = ssl.create_default_context()
        if insecure:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self._conn = None

    def _connection(self):
        if self._conn is None:
            if self.scheme == "https":
                self._conn = http.client.HTTPSConnection(
                    self.host, self.port, context=self.ctx, timeout=120)
            else:
                self._conn = http.client.HTTPConnection(self.host, self.port, timeout=120)
        return self._conn

    def _close(self):
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def _request(self, method, path, body=None, accept="application/json",
                 content_type="application/json", token=True, stream=False):
        data = body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode()
        headers = {"Accept": accept}
        if data is not None:
            headers["Content-Type"] = content_type
        if token and self.token:
            headers["Authorization"] = "Bearer " + self.token
        # Reuse the persistent connection; on a broken/stale keep-alive socket (the server closed an
        # idle connection, or the previous response was drained) reconnect and retry EXACTLY once.
        last_exc = None
        for attempt in (0, 1):
            conn = self._connection()
            try:
                conn.request(method, path, body=data, headers=headers)
                resp = conn.getresponse()
                hdrs = {k: v for k, v in resp.getheaders()}
                if stream:
                    # The caller iterates the response line-by-line; it MUST drain it fully before
                    # the next request on this connection (http.client contract).
                    return resp.status, resp, hdrs
                return resp.status, resp.read(), hdrs
            except (http.client.HTTPException, ConnectionError, OSError) as exc:
                last_exc = exc
                self._close()
        raise last_exc

    # --- auth -----------------------------------------------------------------------------------
    def login(self, user, password):
        """Obtains a Bearer token via ``POST /auth/login`` and stores it on the client."""
        st, body, _ = self._request(
            "POST", "/auth/login", {"username": user, "password": password}, token=False)
        if st != 200:
            raise SystemExit(f"login failed: HTTP {st}: {body[:200]!r}")
        self.token = json.loads(body)["token"]
        return self.token

    # --- one-shot auto-commit -------------------------------------------------------------------
    def auto_commit(self, statements, accept="application/json", token=True, access_mode=None):
        """Runs a batch of statements as one atomic auto-commit transaction. ``access_mode`` (``READ``
        / ``WRITE``) is sent verbatim when given; absent, the server defaults to ``WRITE``."""
        body = {"statements": statements}
        if access_mode is not None:
            body["access_mode"] = access_mode
        return self._request("POST", f"/db/{self.db}/tx/commit", body, accept=accept, token=token)

    def query(self, statement, params=None, accept="application/json"):
        """Runs a single **READ** query via auto-commit, returning ``(status, body_bytes, headers)``.

        ``access_mode: "READ"`` is what makes a single-statement auto-commit dispatch to the server's
        **off-thread reader pool** (rmp #527/#543): the router runs it through the engine's own
        auto-commit READ path so reads scale across the reader threads. Without it the request
        defaults to WRITE and runs inline on the engine thread (a ~1-core ceiling under concurrency)."""
        stmt = {"statement": statement}
        if params is not None:
            stmt["parameters"] = params
        return self.auto_commit([stmt], accept=accept, access_mode="READ")

    def raw_post(self, body, accept="application/json", extra_headers=None, stream=False):
        """POSTs a hand-built transactional body with arbitrary extra headers.

        The volume phase needs this because the response SHAPE is chosen by the request's headers, and
        one of the shapes it must exercise is the one an `Idempotency-Key` forces: with that header the
        server cannot stream (it has to cache the response for replay), so it materialises the whole
        result first. That is a real production request — the header is the API's own retry-safety
        mechanism — and there is no other way to ask for it."""
        data = json.dumps(body).encode()
        headers = {"Accept": accept, "Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        headers.update(extra_headers or {})
        last_exc = None
        for attempt in (0, 1):
            conn = self._connection()
            try:
                conn.request("POST", f"/db/{self.db}/tx/commit", body=data, headers=headers)
                resp = conn.getresponse()
                hdrs = {k: v for k, v in resp.getheaders()}
                if stream:
                    return resp.status, resp, hdrs
                return resp.status, resp.read(), hdrs
            except (http.client.HTTPException, ConnectionError, OSError) as exc:
                last_exc = exc
                self._close()
        raise last_exc

    def stream(self, statement, params=None):
        """Runs a single query requesting NDJSON; returns ``(status, response_obj, headers)`` so the
        caller can iterate the body line-by-line as it arrives.

        ``access_mode: READ`` is REQUIRED for the streaming path: the router only streams a
        single-statement auto-commit when the request is a READ (rmp #527/#530 — a single-statement
        WRITE is buffered so a commit-time serialization conflict becomes a clean 409 rather than a
        dropped body). An absent ``access_mode`` defaults to WRITE, which buffers the result as JSON
        instead of streaming NDJSON."""
        stmt = {"statement": statement}
        if params is not None:
            stmt["parameters"] = params
        body = {"statements": [stmt], "access_mode": "READ"}
        return self._request(
            "POST", f"/db/{self.db}/tx/commit", body,
            accept="application/x-ndjson", stream=True,
        )

    # --- explicit transaction lifecycle ---------------------------------------------------------
    def begin(self, access_mode="WRITE"):
        body = {"statements": [], "access_mode": access_mode}
        return self._request("POST", f"/db/{self.db}/tx", body)

    def run_in_tx(self, tx_id, statements):
        body = {"statements": statements}
        return self._request("POST", f"/db/{self.db}/tx/{tx_id}", body)

    def commit_tx(self, tx_id, statements=None):
        body = {"statements": statements or []}
        return self._request("POST", f"/db/{self.db}/tx/{tx_id}/commit", body)

    def rollback_tx(self, tx_id):
        return self._request("DELETE", f"/db/{self.db}/tx/{tx_id}", None)


# --------------------------------------------------------------------------------------------------
# Jolt decoding — the REST response encodes scalars as strict-Jolt sigil objects
# (``{"Z":"1"}`` int, ``{"U":"x"}`` string, ``{"R":"1.5"}`` float, ``{"?":"true"}`` bool).
# --------------------------------------------------------------------------------------------------
def unjolt(v):
    if isinstance(v, dict) and len(v) == 1:
        (k, val), = v.items()
        if k == "Z":
            return int(val)
        if k == "R":
            return float(val)
        if k == "U":
            return val
        if k == "?":
            return val == "true"
    return v


def result_rows(body_bytes):
    """Extracts ``[[cell, ...], ...]`` rows (Jolt-decoded) from a buffered ``RunResponse``."""
    resp = json.loads(body_bytes)
    if "results" not in resp or not resp["results"]:
        raise RuntimeError(f"no results in response: {resp}")
    res = resp["results"][0]
    return res["fields"], [[unjolt(c) for c in row] for row in res["data"]]


# --------------------------------------------------------------------------------------------------
# Workload.
# --------------------------------------------------------------------------------------------------
FAILURES = 0


def check(name, got, want):
    global FAILURES
    if got == want:
        print(f"  OK  {name}: {got}")
    else:
        FAILURES += 1
        print(f"  BAD {name}: got {got!r} want {want!r}")


def parse_statements(cypher_path):
    """Splits the generator's ``graph.cypher`` into individual statements (comments/blank stripped)."""
    statements = []
    buf = ""
    with open(cypher_path) as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("//") or not line.strip():
                continue
            buf += line
            if buf.rstrip().endswith(";"):
                statements.append(buf.rstrip()[:-1])
                buf = ""
    return statements


def is_schema_ddl(stmt):
    """Whether ``stmt`` is a schema-DDL statement — any ``CREATE CONSTRAINT`` or any ``CREATE … INDEX``
    form, including ``CREATE FULLTEXT INDEX`` (and ``CREATE TEXT INDEX``). Each must run as a standalone
    auto-commit statement: Graphus rejects admin DDL inside an explicit transaction, and a DDL statement
    may not share an auto-commit batch with data writes."""
    u = stmt.lstrip().upper()
    return u.startswith("CREATE CONSTRAINT") or (u.startswith("CREATE") and " INDEX " in u)


def load_graph(client, statements, batch_size):
    """Loads the graph over REST: the schema DDL as standalone auto-commit statements (admin DDL is
    rejected inside an explicit txn), then the data in batched auto-commit transactions."""
    # The first statements are the schema DDL (CONSTRAINT / RANGE / FULLTEXT INDEX); each must run
    # standalone.
    ddl = [s for s in statements if is_schema_ddl(s)]
    data = [s for s in statements if not is_schema_ddl(s)]

    t0 = time.time()
    for stmt in ddl:
        st, body, _ = client.auto_commit([{"statement": stmt}])
        if st != 200:
            raise RuntimeError(f"DDL failed ({st}): {stmt[:80]} :: {body[:160]}")

    loaded = len(ddl)
    for i in range(0, len(data), batch_size):
        chunk = data[i : i + batch_size]
        st, body, _ = client.auto_commit([{"statement": s} for s in chunk])
        if st != 200:
            raise RuntimeError(f"batch failed ({st}): {body[:200]}")
        loaded += len(chunk)
    return loaded, time.time() - t0


def assert_auth_enforced(client):
    """An unauthenticated request to a tx endpoint must be rejected 401."""
    st, _, _ = client.auto_commit([{"statement": "RETURN 1"}], token=False)
    check("auth enforced (no Bearer => 401)", st, 401)


def demo_explicit_tx(client):
    """Demonstrates the explicit transaction lifecycle: begin → run → commit, and begin → rollback."""
    # Begin + run + commit: write a marker node, then read it back in a fresh auto-commit.
    st, body, _ = client.begin("WRITE")
    check("begin tx => 201", st, 201)
    tx_id = json.loads(body)["id"]
    st, _, _ = client.run_in_tx(tx_id, [{"statement": "CREATE (:TxMarker {id: 'committed'})"}])
    check("run in tx => 200", st, 200)
    st, _, _ = client.commit_tx(tx_id)
    check("commit tx => 200", st, 200)
    _, rows = result_rows(client.query("MATCH (m:TxMarker {id:'committed'}) RETURN count(m) AS c")[1])
    check("committed write is visible", rows[0][0], 1)

    # Begin + rollback: a write rolled back must NOT be visible.
    st, body, _ = client.begin("WRITE")
    tx_id = json.loads(body)["id"]
    client.run_in_tx(tx_id, [{"statement": "CREATE (:TxMarker {id: 'rolled-back'})"}])
    st, _, _ = client.rollback_tx(tx_id)
    check("rollback tx => 200", st, 200)
    _, rows = result_rows(client.query("MATCH (m:TxMarker {id:'rolled-back'}) RETURN count(m) AS c")[1])
    check("rolled-back write is invisible", rows[0][0], 0)


def discovery_queries(client, ref):
    """Runs the five discovery patterns and asserts each against ``reference.json``."""
    # (1) Entity lookup — a concept by its unique id.
    _, rows = result_rows(
        client.query("MATCH (c:Concept {id:$id}) RETURN c.name AS name",
                     {"id": ref["lookup_concept_id"]})[1])
    check("(1) lookup", rows[0][0] if rows else None, ref["lookup_concept_name"])

    # (2) Multi-hop semantic traversal — concepts reachable from an author via authored documents.
    _, rows = result_rows(
        client.query(
            "MATCH (a:Author {id:$id})-[:AUTHORED]->(:Document)-[:MENTIONS]->(c:Concept) "
            "RETURN DISTINCT c.id AS cid ORDER BY cid",
            {"id": ref["traversal_author_id"]})[1])
    check("(2) traversal", [r[0] for r in rows], ref["traversal_reachable_concept_ids"])

    # (3) Recommendation — documents co-mentioning concepts with the seed, ranked by shared count.
    _, rows = result_rows(
        client.query(
            "MATCH (seed:Document {id:$id})-[:MENTIONS]->(c:Concept)<-[:MENTIONS]-(other:Document) "
            "WHERE other.id <> $id "
            "RETURN other.id AS doc, count(DISTINCT c) AS shared "
            "ORDER BY shared DESC, doc ASC",
            {"id": ref["recommend_seed_document_id"]})[1])
    check("(3) recommend", [[r[0], r[1]] for r in rows],
          [list(x) for x in ref["recommend_results"]])

    # (4a) Aggregation — the author's document count.
    _, rows = result_rows(
        client.query("MATCH (a:Author {id:$id})-[:AUTHORED]->(d:Document) RETURN count(d) AS c",
                     {"id": ref["agg_author_id"]})[1])
    check("(4a) author document count", rows[0][0] if rows else None,
          ref["agg_author_document_count"])

    # (4b) Aggregation — the most-mentioned concept across the reference documents.
    _, rows = result_rows(
        client.query(
            "MATCH (d:Document)-[m:MENTIONS]->(c:Concept) "
            "WHERE d.id IN ['ref-d-0','ref-d-1','ref-d-2'] "
            "RETURN c.id AS cid, sum(m.count) AS total ORDER BY total DESC, cid ASC LIMIT 1")[1])
    check("(4b) top concept id", rows[0][0] if rows else None, ref["agg_top_concept_id"])
    check("(4b) top concept total", rows[0][1] if rows else None,
          ref["agg_top_concept_total_mentions"])

    # (5) Concept path — the shortest :RELATED_TO chain length between two concepts.
    _, rows = result_rows(
        client.query(
            "MATCH p = shortestPath((a:Concept {id:$f})-[:RELATED_TO*]->(b:Concept {id:$t})) "
            "RETURN length(p) AS len",
            {"f": ref["path_from_concept_id"], "t": ref["path_to_concept_id"]})[1])
    check("(5) concept path length", rows[0][0] if rows else None, ref["path_length"])


# The reference documents carry realistic, fixed titles (disjoint from the "Document <n>" background):
#   ref-d-0 "On Graph Storage" | ref-d-1 "Traversal Methods" | ref-d-2 "Indexed Graphs".
# The `standard` analyzer tokenizes on non-alphanumeric boundaries, lowercases and drops stop-words,
# but does NOT stem — so `graph` and `graphs` are DISTINCT terms. The known, enumerable answer set for
# each search term over the whole corpus is therefore exactly:
FULLTEXT_EXPECTATIONS = [
    ("graph", ["ref-d-0"]),      # "On Graph Storage" — NOT "Indexed Graphs" (no stemming: graph≠graphs)
    ("graphs", ["ref-d-2"]),     # "Indexed Graphs" — the no-stemming contrast to "graph"
    ("storage", ["ref-d-0"]),    # "On Graph Storage"
    ("traversal", ["ref-d-1"]),  # "Traversal Methods"
    ("on", []),                  # a stop-word-only query matches nothing
]


def fulltext_discovery(client):
    """Runs the FULLTEXT title search over the corpus and asserts each term returns exactly the known
    reference documents — including the empirically-verified no-stemming analyzer behaviour."""
    for term, expected in FULLTEXT_EXPECTATIONS:
        _, rows = result_rows(
            client.query(
                "CALL db.index.fulltext.queryNodes('document_fulltext', $q) YIELD node "
                "RETURN node.id AS id ORDER BY id",
                {"q": term})[1])
        got = sorted(r[0] for r in rows)
        check(f"fulltext '{term}'", got, sorted(expected))


def schema_evidence(client):
    """Captures SHOW INDEXES / SHOW CONSTRAINTS as evidence and asserts the new search schema is
    declared and ONLINE. Returns ``(indexes, constraints)`` — each a list of ``[name, type, entity]``
    rows — for the machine-readable ``GRAPHUS_SCHEMA`` evidence line."""
    _, idx_rows = result_rows(client.query(
        "SHOW INDEXES YIELD name, type, entityType, state "
        "RETURN name, type, entityType, state ORDER BY name")[1])
    _, con_rows = result_rows(client.query(
        "SHOW CONSTRAINTS YIELD name, type, entityType "
        "RETURN name, type, entityType ORDER BY name")[1])

    def find(rows, name):
        return next((r for r in rows if r[0] == name), None)

    ft = find(idx_rows, "document_fulltext")
    check("FULLTEXT index declared", ft[1] if ft else None, "FULLTEXT")
    check("FULLTEXT index is a NODE index", ft[2] if ft else None, "NODE")
    check("FULLTEXT index is ONLINE", ft[3] if ft else None, "ONLINE")
    rng = find(idx_rows, "document_year_range")
    check("RANGE index declared", rng[1] if rng else None, "RANGE")
    yt = find(con_rows, "document_year_integer")
    check("property-type constraint declared", yt[1] if yt else None, "NODE_PROPERTY_TYPE")
    te = find(con_rows, "document_title_exists")
    check("existence constraint declared", te[1] if te else None, "NODE_PROPERTY_EXISTENCE")

    print("  indexes:")
    for r in idx_rows:
        print(f"    {r[0]:<22} {r[1]:<10} {r[2]:<12} {r[3]}")
    print("  constraints:")
    for r in con_rows:
        print(f"    {r[0]:<22} {r[1]:<28} {r[2]}")
    return ([r[:3] for r in idx_rows], [r[:3] for r in con_rows])


def constraint_enforcement(client):
    """Asserts the node property-type + existence constraints are ENFORCED over REST: a violating write
    must be rejected with a client error (HTTP 400, an RFC 9457 problem+json), never silently accepted."""
    # Property-type: a non-integer Document.year is rejected.
    st, body, _ = client.auto_commit(
        [{"statement": "CREATE (:Document {id: 'bad-type', title: 'Bad Year', year: 'twenty-twenty'})"}])
    check("property-type violation rejected (non-integer year => 400)", st, 400)
    # Existence: a Document without a title is rejected.
    st, body, _ = client.auto_commit(
        [{"statement": "CREATE (:Document {id: 'bad-exists', year: 2020})"}])
    check("existence violation rejected (missing title => 400)", st, 400)
    # And the rejected writes created nothing (they rolled back atomically).
    _, rows = result_rows(client.query(
        "MATCH (d:Document) WHERE d.id IN ['bad-type','bad-exists'] RETURN count(d) AS c")[1])
    check("rejected writes created no Document", rows[0][0] if rows else None, 0)


def ndjson_stream(client):
    """Streams a large result as NDJSON and verifies it arrives one JSON object per line,
    parsed incrementally. Returns ``(row_count, elapsed_secs, content_type)``."""
    st, resp, headers = client.stream("MATCH (d:Document) RETURN d.id AS id, d.year AS year")
    check("ndjson status => 200", st, 200)
    ctype = headers.get("Content-Type") or headers.get("content-type")
    check("ndjson content-type", ctype, "application/x-ndjson")
    n_fields = n_rows = n_summary = n_bytes = 0
    t0 = time.time()
    # Iterating the response object yields the body line-by-line as it is read off the socket: the
    # client never materializes the whole result before processing rows. Draining it fully also
    # returns the keep-alive connection to a reusable state for the next request.
    for raw in resp:
        n_bytes += len(raw)
        raw = raw.strip()
        if not raw:
            continue
        obj = json.loads(raw)
        if "fields" in obj:
            n_fields += 1
        elif "row" in obj:
            n_rows += 1
        elif "summary" in obj:
            n_summary += 1
    elapsed = time.time() - t0
    check("ndjson framing (1 fields + N rows + 1 summary)",
          (n_fields, n_summary, n_rows > 0), (1, 1, True))
    return n_rows, n_bytes, elapsed, ctype


def content_negotiation(client):
    """Requests the same query as JSON and CBOR; asserts both decode to the same logical result and
    captures payload sizes. Returns ``(json_bytes, cbor_bytes)``."""
    query = "MATCH (d:Document) RETURN d.id AS id, d.year AS year"
    _, jbody, _ = client.query(query, accept="application/json")
    st, cbody, cheaders = client.query(query, accept="application/cbor")
    cctype = cheaders.get("Content-Type") or cheaders.get("content-type")
    check("cbor content-type", cctype, "application/cbor")

    json_doc = json.loads(jbody)
    cbor_doc, _ = cbor_decode(cbody)
    check("CBOR decodes to the SAME logical result as JSON", cbor_doc == json_doc, True)
    return len(jbody), len(cbody)


# --------------------------------------------------------------------------------------------------
# The SERVER-pid seam (rmp #717) — `proc_watch`, the shared sampler from the examples harness.
#
# The house rule is "sample the SERVER, not the driver". A python client can only reach the server over
# HTTP, so on its own it can measure precisely nothing about the server's memory. `proc_watch` closes
# that gap: `--snapshot` reads the server pid's CUMULATIVE cpu counters (bracket a phase with two to
# get the exact CPU it burned), and `--watch` samples the pid's RSS on a cadence and reports the PEAK
# DELTA over the baseline it held when the watch opened.
#
# `--watch` is the only way to see a response the server materialises in full before flushing a byte:
# that memory is freed by the time the request returns, so a before/after snapshot misses it entirely.
# --------------------------------------------------------------------------------------------------
class ServerWatch:
    """A running `proc_watch --watch` over the server pid; `stop()` returns its parsed JSON report."""

    def __init__(self, proc_watch, pid, interval_ms=10):
        self.dir = tempfile.mkdtemp(prefix="kg-watch-")
        self.out = os.path.join(self.dir, "watch.json")
        self.stop_file = os.path.join(self.dir, "stop")
        self.proc = subprocess.Popen(
            [proc_watch, "--pid", str(pid), "--watch", "--out", self.out,
             "--interval-ms", str(interval_ms), "--stop-file", self.stop_file,
             "--max-secs", "600"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        # The watcher must be sampling BEFORE the workload starts, or the peak it is there to catch
        # can happen before its first sample. One interval is enough (it samples the baseline eagerly).
        time.sleep(max(0.05, interval_ms / 1000.0 * 3))

    def stop(self):
        with open(self.stop_file, "w") as fh:
            fh.write("stop")
        try:
            _, err = self.proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            raise SystemExit("proc_watch did not exit after the stop-file was created")
        if self.proc.returncode != 0:
            raise SystemExit(f"proc_watch failed ({self.proc.returncode}): {err.decode()[:300]}")
        with open(self.out) as fh:
            return json.load(fh)


def server_snapshot(proc_watch, pid):
    """One cumulative CPU + current RSS reading of the SERVER process."""
    out = subprocess.run([proc_watch, "--pid", str(pid), "--snapshot"],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


# --------------------------------------------------------------------------------------------------
# The VOLUME phase (rmp #717) — REST-path resource behaviour under result-set VOLUME.
#
# This is the vector the example exists to expose and, at 320 tiny operations, could not. The REST
# response path has three shapes, and they do NOT cost the same:
#
#   1. NDJSON                      (`Accept: application/x-ndjson`)                → STREAMS
#   2. JSON, single statement      (`Accept: application/json`, no Idempotency-Key) → STREAMS
#   3. JSON, buffered              (the SAME query + an `Idempotency-Key` header)   → BUFFERS the whole
#      result server-side before a byte is flushed, because the response has to be cached for replay
#      (`stream_framing` in crates/graphus-rest/src/router.rs returns `None` when the header is
#      present). A multi-statement batch buffers for the same reason.
#
# Shape 3 is not a synthetic hack: `Idempotency-Key` is the retry-safety header the API *documents and
# encourages*, and a production client that sends it silently loses streaming. That is exactly the kind
# of fragility an example is for — and it is invisible at 320 operations of a handful of rows.
#
# The buffered path is bounded (`MAX_BUFFERED_RESULT_BYTES` = 16 MiB serialized, rmp #553): over the
# cap the statement is aborted with a 400 rather than OOMing the server. This phase drives all three
# shapes at the same row count, samples the SERVER's RSS through each, and then deliberately crosses
# the cap to prove it fires.
# --------------------------------------------------------------------------------------------------
# A REAL analytical query, not a row generator: co-mentioned document pairs (which documents discuss
# the same concept). It is the canonical knowledge-graph "co-occurrence export", and it produces a
# large result from a modest graph — which is the honest way to reach volume without pretending the
# graph is bigger than it is.
VOLUME_QUERY = (
    "MATCH (d:Document)-[:MENTIONS]->(c:Concept)<-[:MENTIONS]-(o:Document) "
    "WHERE d.id <> o.id "
    "RETURN d.id AS doc, c.name AS concept, o.id AS other "
    "LIMIT {rows}"
)

# The CAP probe needs a response whose SERIALIZED size crosses MAX_BUFFERED_RESULT_BYTES (16 MiB). The
# narrow export above cannot get there — the graph's co-mention join saturates at ~180 000 rows of
# ~50 B, i.e. ~9 MB — so the probe asks for the same join with the WHOLE NODES instead of three
# scalars. That is not a trick to inflate a response: "give me the objects, not just their ids" is the
# single most ordinary thing a client asks a knowledge graph for, and it is precisely the request that
# turns a comfortable export into an unbounded server-side buffer.
VOLUME_CAP_QUERY = (
    "MATCH (d:Document)-[:MENTIONS]->(c:Concept)<-[:MENTIONS]-(o:Document) "
    "WHERE d.id <> o.id "
    "RETURN d, c, o "
    "LIMIT {rows}"
)


def volume_shape(client, shape, rows, proc_watch=None, server_pid=None, query=VOLUME_QUERY):
    """Issues the co-mention export in one response ``shape`` and measures what it cost the SERVER.

    Returns a dict with the client-side facts (rows, bytes, secs) and — only when a co-located server
    pid was given — the SERVER's peak RSS delta and CPU across the request. Without a pid the server
    fields are simply ABSENT (an attach run cannot read /proc), never zero."""
    watch = ServerWatch(proc_watch, server_pid) if (proc_watch and server_pid) else None
    body = {"statements": [{"statement": query.format(rows=rows)}], "access_mode": "READ"}
    headers = {}
    if shape == "ndjson":
        accept = "application/x-ndjson"
    else:
        accept = "application/json"
    if shape == "json-buffered":
        # The retry-safety header a production client is encouraged to send. It costs it streaming.
        headers["Idempotency-Key"] = f"kg-volume-{rows}-{os.getpid()}-{int(time.time() * 1000)}"

    t0 = time.perf_counter()
    st, resp, hdrs = client.raw_post(body, accept=accept, extra_headers=headers, stream=True)
    n_bytes = 0
    n_rows = 0
    if st == 200:
        # Drain incrementally — the client must never be the thing that materialises the result, or it
        # would be measuring itself.
        if shape == "ndjson":
            for raw in resp:
                n_bytes += len(raw)
                line = raw.strip()
                if line and b'"row"' in line:
                    n_rows += 1
        else:
            # Count rows by their `],[` separators as the body streams past, WITHOUT materialising it
            # (materialising it here would measure this client, not the server). The separator can
            # straddle a chunk boundary, so carry the last 2 bytes of each chunk into the next — a
            # first cut that did not lost 4 rows in 150 000 and quietly failed its own row assertion.
            carry = b""
            while True:
                chunk = resp.read(1 << 16)
                if not chunk:
                    break
                n_bytes += len(chunk)
                n_rows += (carry + chunk).count(b"],[")
                carry = chunk[-2:]
            if n_bytes:
                n_rows += 1  # the last row has no trailing separator
    else:
        n_bytes = len(resp.read())
    secs = time.perf_counter() - t0

    out = {
        "shape": shape,
        "requested_rows": rows,
        "status": st,
        "rows": n_rows,
        "response_bytes": n_bytes,
        "wall_secs": round(secs, 4),
        "rows_per_sec": round(n_rows / secs, 1) if secs > 0 and n_rows else None,
        "mb_per_sec": round(n_bytes / secs / 1e6, 2) if secs > 0 and n_bytes else None,
    }
    if watch is not None:
        w = watch.stop()
        peak_delta = w["memory"]["peak_delta_bytes"]
        cpu = w["cpu"]["total_secs"]
        out["server_peak_rss_delta_bytes"] = peak_delta
        out["server_rss_bytes_per_row"] = round(peak_delta / n_rows, 1) if n_rows else None
        out["server_cpu_secs"] = round(cpu, 4)
        out["server_mean_cores"] = w["cpu"]["mean_core_utilisation"]
        out["server_baseline_rss_bytes"] = w["memory"]["baseline_rss_bytes"]
        out["server_final_rss_bytes"] = w["memory"]["final_rss_bytes"]
    return out


def volume_phase(client, rows, cap_rows, proc_watch=None, server_pid=None):
    """Drives the three response shapes at ``rows`` rows, then crosses the 16 MiB buffered cap.

    Returns ``(shapes, cap_probe)``. Asserts what MUST hold: every shape returns the rows it was asked
    for, the streaming shapes do not balloon the server's memory, and the buffered path is CAPPED (400)
    rather than unbounded."""
    shapes = []
    for shape in ("ndjson", "json-streamed", "json-buffered"):
        r = volume_shape(client, shape, rows, proc_watch, server_pid)
        shapes.append(r)
        rss = ""
        if r.get("server_peak_rss_delta_bytes") is not None:
            rss = (f"  server peak RSS +{r['server_peak_rss_delta_bytes'] / 1048576:7.1f} MB "
                   f"({r['server_rss_bytes_per_row']:.0f} B/row)  cpu {r['server_cpu_secs']:.2f}s "
                   f"({r['server_mean_cores']:.2f} cores)")
        print(f"  {r['shape']:<14} HTTP {r['status']}  {r['rows']:>7} rows  "
              f"{r['response_bytes'] / 1e6:6.1f} MB  {r['wall_secs'] * 1000:8.1f} ms{rss}")
        check(f"volume {shape}: HTTP 200", r["status"], 200)
        check(f"volume {shape}: returned the requested rows", r["rows"], rows)

    # The streaming shapes must NOT accumulate the result server-side. This gate genuinely fires: if a
    # future change makes the JSON single-statement path buffer again, its per-row RSS jumps by an
    # order of magnitude and this fails.
    for r in shapes:
        if r["shape"] == "json-buffered" or r.get("server_rss_bytes_per_row") is None:
            continue
        check(f"volume {r['shape']}: streams (server RSS per row < {STREAM_RSS_CEILING_B} B)",
              r["server_rss_bytes_per_row"] < STREAM_RSS_CEILING_B, True)

    # The buffered path must be CAPPED, not unbounded: a result whose serialized size crosses
    # MAX_BUFFERED_RESULT_BYTES (16 MiB) is aborted with a 400 — never OOM, never a silent truncation.
    cap = volume_shape(client, "json-buffered", cap_rows, proc_watch, server_pid,
                       query=VOLUME_CAP_QUERY)
    cap["query"] = "whole-node export (RETURN d, c, o)"
    rss = ""
    if cap.get("server_peak_rss_delta_bytes") is not None:
        rss = f"  server peak RSS +{cap['server_peak_rss_delta_bytes'] / 1048576:.1f} MB"
    print(f"  cap probe      HTTP {cap['status']}  {cap_rows} buffered WHOLE-NODE rows requested "
          f"(serialized > the 16 MiB cap){rss}")
    check("buffered result over the 16 MiB cap is REJECTED (400), not OOM/truncated",
          cap["status"], 400)
    return shapes, cap


# The per-row server-RSS ceiling a STREAMING response must stay under. The measured streaming cost on a
# 16-core Linux host is ~80 B/row (the engine's own row materialisation); the BUFFERED path costs
# ~2 400 B/row (the serde_json intermediate tree, rmp #383). 500 B/row sits an order of magnitude below
# the buffered cost and ~6x above the streaming cost: comfortably clear of noise, and it FIRES the
# moment a streaming path starts accumulating the result.
STREAM_RSS_CEILING_B = 500


def _conc_worker_proc(base_url, token, database, insecure, threads, ops_per_thread, out_q):
    """One CLIENT PROCESS of the concurrency phase: runs `threads` threads, each issuing
    `ops_per_thread` discovery queries. Returns its latencies + errors + its OWN cpu through `out_q`.

    Why a process and not just more threads: python's GIL serialises the client, so a single-process
    driver saturates at its own interpreter long before the server saturates — and the result reads as
    a SERVER ceiling. This suite has been bitten by exactly that (social-network-large's "~1 core"
    server was a harness artifact). Spreading the clients across PROCESSES removes the GIL from the
    measurement, and the report publishes the client's own CPU so a reader can check the claim rather
    than take it on faith."""
    lat = []
    errors = 0
    lock = threading.Lock()

    def worker():
        nonlocal errors
        c = RestClient(base_url, token=token, database=database, insecure=insecure)
        local = []
        for _ in range(ops_per_thread):
            t0 = time.perf_counter()
            try:
                st, _, _ = c.query(
                    "MATCH (seed:Document {id:'ref-d-0'})-[:MENTIONS]->(c:Concept)"
                    "<-[:MENTIONS]-(other:Document) WHERE other.id <> 'ref-d-0' "
                    "RETURN other.id AS doc, count(DISTINCT c) AS shared ORDER BY shared DESC, doc ASC")
                if st != 200:
                    with lock:
                        errors += 1
            except Exception:  # noqa: BLE001 — a transport failure is an error, not a crash
                with lock:
                    errors += 1
            local.append(time.perf_counter() - t0)
        c._close()
        with lock:
            lat.extend(local)

    ts = [threading.Thread(target=worker) for _ in range(threads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    r = resource.getrusage(resource.RUSAGE_SELF)
    out_q.put({"lat": lat, "errors": errors, "cpu_secs": r.ru_utime + r.ru_stime})


def concurrency(base_url, token, database, insecure, clients, ops_per_client, procs,
                proc_watch=None, server_pid=None):
    """Drives `clients` concurrent REST clients spread across `procs` OS PROCESSES.

    Asserts zero errors. Returns a stats dict including the SERVER's cores (when a pid is available)
    and the CLIENT's own cores — the two numbers a reader needs to tell a server ceiling from a client
    artifact."""
    procs = max(1, min(procs, clients))
    per_proc = max(1, clients // procs)
    threads_total = per_proc * procs

    ctx = mp.get_context("spawn")  # never fork a process holding TLS sockets
    q = ctx.Queue()
    children = [
        ctx.Process(target=_conc_worker_proc,
                    args=(base_url, token, database, insecure, per_proc, ops_per_client, q))
        for _ in range(procs)
    ]

    before = server_snapshot(proc_watch, server_pid) if (proc_watch and server_pid) else None
    t0 = time.perf_counter()
    for p in children:
        p.start()
    results = [q.get() for _ in children]
    for p in children:
        p.join()
    elapsed = time.perf_counter() - t0
    after = server_snapshot(proc_watch, server_pid) if (proc_watch and server_pid) else None

    latencies = sorted(x for r in results for x in r["lat"])
    errors = sum(r["errors"] for r in results)
    client_cpu = sum(r["cpu_secs"] for r in results)
    total = len(latencies)

    def pct(q_):
        if not latencies:
            return None
        idx = min(len(latencies) - 1, int(len(latencies) * q_))
        return latencies[idx] * 1000

    stats = {
        "clients": threads_total,
        "client_processes": procs,
        "ops": total,
        "errors": errors,
        "secs": round(elapsed, 4),
        "ops_per_sec": round(total / elapsed, 1) if elapsed > 0 else None,
        "p50_ms": round(pct(0.50), 3) if latencies else None,
        "p99_ms": round(pct(0.99), 3) if latencies else None,
        "p999_ms": round(pct(0.999), 3) if latencies else None,
        "client_cpu_secs": round(client_cpu, 3),
        "client_mean_cores": round(client_cpu / elapsed, 3) if elapsed > 0 else None,
    }
    if before and after:
        cpu = (after["user_secs"] - before["user_secs"]) + (after["system_secs"] - before["system_secs"])
        stats["server_cpu_secs"] = round(cpu, 3)
        stats["server_mean_cores"] = round(cpu / elapsed, 3) if elapsed > 0 else None
    check("concurrency: zero errors", errors, 0)
    check("concurrency: every client op completed", total, threads_total * ops_per_client)
    return stats


def main():
    ap = argparse.ArgumentParser(description="Graphus knowledge-graph discovery workload over REST")
    ap.add_argument("--base-url", help="REST base URL, e.g. https://127.0.0.1:7474 or a remote box")
    ap.add_argument("--port", help="convenience: builds --base-url as https://127.0.0.1:<port>")
    ap.add_argument("--user", default="graphus")
    ap.add_argument("--password", help="login password for POST /auth/login (unless --token is given)")
    ap.add_argument("--token", help="a pre-issued Bearer token (skips POST /auth/login)")
    ap.add_argument("--database", default="graphus")
    ap.add_argument("--insecure", action="store_true",
                    help="accept a self-signed TLS cert (curl -k equivalent)")
    ap.add_argument("--cypher", required=True)
    ap.add_argument("--reference", required=True)
    ap.add_argument("--batch-size", type=int, default=200)
    ap.add_argument("--clients", type=int, default=64)
    ap.add_argument("--ops-per-client", type=int, default=50)
    # Spread the concurrent clients across OS PROCESSES: python's GIL makes a single-process driver
    # saturate on itself and report the ceiling as if it were the SERVER's (see `_conc_worker_proc`).
    ap.add_argument("--client-processes", type=int, default=8)
    # The VOLUME phase (rmp #717): the row count each response shape is asked for, and the (larger)
    # count used to prove the buffered path's 16 MiB cap fires rather than OOMing.
    ap.add_argument("--volume-rows", type=int, default=150000)
    ap.add_argument("--cap-probe-rows", type=int, default=400000)
    # The SERVER-pid seam. Both must be given (a LOCAL run); without them the server-side vectors of
    # the volume + concurrency phases are ABSENT from the evidence rather than zero-filled.
    ap.add_argument("--server-pid", type=int)
    ap.add_argument("--proc-watch", help="path to the harness `proc_watch` binary")
    args = ap.parse_args()

    if bool(args.server_pid) != bool(args.proc_watch):
        raise SystemExit("--server-pid and --proc-watch must be given together")

    base_url = args.base_url
    if not base_url:
        if not args.port:
            raise SystemExit("one of --base-url or --port is required")
        base_url = f"https://127.0.0.1:{args.port}"

    client = RestClient(base_url, token=args.token, database=args.database, insecure=args.insecure)
    if args.token:
        print(f"== using pre-issued Bearer token ({len(args.token)} chars)")
    else:
        if args.password is None:
            raise SystemExit("--password is required unless --token is given")
        token = client.login(args.user, args.password)
        print(f"== authenticated '{args.user}' via POST /auth/login ({len(token)} chars)")
    token = client.token

    print(f"== target {base_url} database={args.database}")

    print("== auth enforcement")
    assert_auth_enforced(client)

    print("== load graph (batched auto-commit over REST)")
    statements = parse_statements(args.cypher)
    loaded, load_secs = load_graph(client, statements, args.batch_size)
    print(f"  loaded {loaded} statements in {load_secs:.2f}s")

    print("== schema evidence (SHOW INDEXES / SHOW CONSTRAINTS)")
    indexes, constraints = schema_evidence(client)

    print("== explicit transaction lifecycle (begin / commit / rollback)")
    demo_explicit_tx(client)

    print("== discovery queries vs reference.json")
    with open(args.reference) as f:
        ref = json.load(f)
    discovery_queries(client, ref)

    print("== full-text title search (db.index.fulltext.queryNodes)")
    fulltext_discovery(client)

    print("== constraint enforcement (property-type + existence negative writes)")
    constraint_enforcement(client)

    print("== NDJSON streaming")
    ndjson_rows, ndjson_bytes, ndjson_secs, _ = ndjson_stream(client)
    ndjson_throughput = ndjson_rows / ndjson_secs if ndjson_secs > 0 else 0.0
    ndjson_bytes_per_sec = ndjson_bytes / ndjson_secs if ndjson_secs > 0 else 0.0
    print(f"  streamed {ndjson_rows} rows ({ndjson_bytes} B) in {ndjson_secs * 1000:.1f}ms "
          f"({ndjson_throughput:.0f} rows/s, {ndjson_bytes_per_sec / 1e6:.1f} MB/s)")

    print("== content negotiation (JSON vs CBOR)")
    json_bytes, cbor_bytes = content_negotiation(client)
    ratio = cbor_bytes / json_bytes if json_bytes else 0.0
    print(f"  JSON={json_bytes} B  CBOR={cbor_bytes} B  (CBOR is {ratio * 100:.1f}% of JSON)")

    # ---- The VOLUME phase: what a LARGE RESULT SET costs the SERVER, in each response shape --------
    print(f"== result-set VOLUME ({args.volume_rows} rows, three response shapes) "
          f"[server RSS: {'sampled' if args.server_pid else 'NOT MEASURED — no co-located pid'}]")
    volume_shapes, cap_probe = volume_phase(
        client, args.volume_rows, args.cap_probe_rows,
        proc_watch=args.proc_watch, server_pid=args.server_pid)

    print(f"== concurrency ({args.clients} clients across {args.client_processes} client PROCESSES, "
          f"access_mode READ → off-thread reader pool)")
    conc = concurrency(base_url, token, args.database, args.insecure,
                       args.clients, args.ops_per_client, args.client_processes,
                       proc_watch=args.proc_watch, server_pid=args.server_pid)
    srv = ""
    if conc.get("server_mean_cores") is not None:
        srv = f" server={conc['server_mean_cores']:.2f} cores"
    print(f"  clients={conc['clients']} procs={conc['client_processes']} ops={conc['ops']} "
          f"errors={conc['errors']} throughput={conc['ops_per_sec']:.0f} ops/s "
          f"p50={conc['p50_ms']:.1f}ms p99={conc['p99_ms']:.1f}ms p999={conc['p999_ms']:.1f}ms"
          f"{srv} client={conc['client_mean_cores']:.2f} cores")
    # Is the CLIENT the limiter? Say so out loud rather than letting a reader assume the ceiling is the
    # server's. (social-network-large once reported a "~1 core" server that was purely a harness
    # artifact; this suite does not get to make that mistake twice.)
    if conc.get("server_mean_cores") is not None and conc["client_mean_cores"] is not None:
        if conc["client_mean_cores"] > conc["server_mean_cores"]:
            print("  ⚠ the CLIENT burned more CPU than the server: this measurement is CLIENT-BOUND, "
                  "and the throughput above is the driver's ceiling, not the server's")

    if FAILURES == 0:
        print("GRAPHUS_KG_REST_OK")
        # A machine-readable snapshot of the declared schema (the SHOW INDEXES / SHOW CONSTRAINTS
        # evidence), persisted by run.sh alongside the performance report.
        print("GRAPHUS_SCHEMA " + json.dumps(
            {"indexes": indexes, "constraints": constraints}, separators=(",", ":")))
        stats = {
            "loaded_statements": loaded,
            "load_secs": round(load_secs, 3),
            "indexes_total": len(indexes),
            "constraints_total": len(constraints),
            "ndjson_rows": ndjson_rows,
            "ndjson_bytes": ndjson_bytes,
            "ndjson_secs": round(ndjson_secs, 4),
            "ndjson_rows_per_sec": round(ndjson_throughput, 1),
            "ndjson_bytes_per_sec": round(ndjson_bytes_per_sec, 1),
            "json_bytes": json_bytes,
            "cbor_bytes": cbor_bytes,
            "cbor_ratio": round(ratio, 4),
            "concurrency_clients": conc["clients"],
            "concurrency_processes": conc["client_processes"],
            "concurrency_ops": conc["ops"],
            "concurrency_errors": conc["errors"],
            "concurrency_secs": conc["secs"],
            "ops_per_sec": conc["ops_per_sec"],
            "p50_ms": conc["p50_ms"],
            "p99_ms": conc["p99_ms"],
            "p999_ms": conc["p999_ms"],
            "concurrency_client_cores": conc["client_mean_cores"],
            "concurrency_client_cpu_secs": conc["client_cpu_secs"],
            # Absent (not zero) when there was no co-located server pid to sample.
            **({"concurrency_server_cores": conc["server_mean_cores"],
                "concurrency_server_cpu_secs": conc["server_cpu_secs"]}
               if conc.get("server_mean_cores") is not None else {}),
            "volume_rows": args.volume_rows,
            "volume_shapes": volume_shapes,
            "volume_cap_probe_rows": args.cap_probe_rows,
            "volume_cap_probe_status": cap_probe["status"],
        }
        print("GRAPHUS_STATS " + json.dumps(stats, separators=(",", ":")))
        return 0

    print(f"GRAPHUS_KG_REST_FAILED — {FAILURES} assertion(s) did not hold")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
