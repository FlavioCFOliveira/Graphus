#!/usr/bin/env python3
"""Knowledge-graph discovery workload over the Graphus REST API (rmp #280 + #281).

A pure-stdlib client (``urllib`` + ``ssl`` + ``hmac``/``hashlib``/``base64`` + ``json``) that drives
the **REST transactional API** over HTTPS against a live ``graphus-server``:

1. **Auth** — mints a Bearer JWT (HS256) out of band (the server has no login endpoint; tokens are
   minted by anyone holding the shared ``jwt_secret``), and proves an **unauthenticated** request is
   rejected ``401``.
2. **Load** — replays the generator's ``graph.cypher`` over the REST one-shot ``/db/{db}/tx/commit``
   endpoint, **batching** many statements per HTTP request (the schema DDL runs as standalone
   auto-commit statements first). Each batch is one atomic auto-commit transaction.
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

On success it prints ``GRAPHUS_KG_REST_OK`` and a single machine-readable ``GRAPHUS_STATS {...}`` line
(parsed by ``run.sh`` for the evidence report). Any failed assertion prints the mismatch and exits
non-zero.

Usage::

    discovery.py --port <p> --secret <s> --user <u> --cypher <graph.cypher> \
                 --reference <reference.json> [--clients N] [--ops-per-client M]
"""

import argparse
import json
import time
import ssl
import hmac
import hashlib
import base64
import struct
import threading
import urllib.request
import urllib.error


# --------------------------------------------------------------------------------------------------
# JWT (HS256) — minted with the stdlib only (no PyJWT dependency).
# --------------------------------------------------------------------------------------------------
def _b64u(b: bytes) -> bytes:
    return base64.urlsafe_b64encode(b).rstrip(b"=")


def mint_jwt(secret: bytes, subject: str, ttl_secs: int = 3600) -> str:
    """Mints an HS256 JWT the Graphus server accepts.

    The server validates the signature (HS256), the ``iss``/``aud`` binding (both ``"graphus"`` by
    default), required ``sub``/``exp``/``iss``/``aud`` claims, that ``sub`` names a live catalog user
    (the bootstrap admin qualifies), and that the token's ``ver`` is ``>=`` the user's credential
    epoch (a fresh admin is at epoch ``0``). See ``crates/graphus-auth/src/token.rs``.
    """
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + ttl_secs,
        "iss": "graphus",
        "aud": "graphus",
        "jti": f"kg-rest-{now}-{subject}",
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
# REST client.
# --------------------------------------------------------------------------------------------------
class RestClient:
    """A thin HTTPS REST client for the Graphus transactional API (self-signed TLS, Bearer JWT)."""

    def __init__(self, port, token, database="graphus"):
        self.base = f"https://127.0.0.1:{port}"
        self.token = token
        self.db = database
        # Self-signed cert: trust it explicitly (this is a local demo cert, not the public web).
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method, path, body=None, accept="application/json",
                 content_type="application/json", token=True, stream=False):
        data = body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Accept", accept)
        if data is not None:
            req.add_header("Content-Type", content_type)
        if token and self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        try:
            resp = urllib.request.urlopen(req, context=self.ctx)
            if stream:
                return resp.status, resp, dict(resp.headers)
            return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers)

    # --- one-shot auto-commit -------------------------------------------------------------------
    def auto_commit(self, statements, accept="application/json", token=True):
        """Runs a batch of statements as one atomic auto-commit transaction."""
        body = {"statements": statements}
        return self._request("POST", f"/db/{self.db}/tx/commit", body, accept=accept, token=token)

    def query(self, statement, params=None, accept="application/json"):
        """Runs a single read query via auto-commit, returning ``(status, body_bytes, headers)``."""
        stmt = {"statement": statement}
        if params is not None:
            stmt["parameters"] = params
        return self.auto_commit([stmt], accept=accept)

    def stream(self, statement, params=None):
        """Runs a single query requesting NDJSON; returns ``(status, response_obj, headers)`` so the
        caller can iterate the body line-by-line as it arrives."""
        stmt = {"statement": statement}
        if params is not None:
            stmt["parameters"] = params
        body = {"statements": [stmt]}
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


def load_graph(client, statements, batch_size):
    """Loads the graph over REST: the schema DDL as standalone auto-commit statements (admin DDL is
    rejected inside an explicit txn), then the data in batched auto-commit transactions."""
    # The first statements are the schema DDL (CONSTRAINT/INDEX); each must run standalone.
    ddl = [s for s in statements if s.lstrip().upper().startswith(("CREATE CONSTRAINT", "CREATE INDEX"))]
    data = [s for s in statements if s not in ddl]

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


def ndjson_stream(client):
    """Streams a large result as NDJSON and verifies it arrives one JSON object per line,
    parsed incrementally. Returns ``(row_count, elapsed_secs, content_type)``."""
    st, resp, headers = client.stream("MATCH (d:Document) RETURN d.id AS id, d.year AS year")
    check("ndjson status => 200", st, 200)
    ctype = headers.get("Content-Type") or headers.get("content-type")
    check("ndjson content-type", ctype, "application/x-ndjson")
    n_fields = n_rows = n_summary = 0
    t0 = time.time()
    # Iterating the response object yields the body line-by-line as it is read off the socket: the
    # client never materializes the whole result before processing rows.
    for raw in resp:
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
    return n_rows, elapsed, ctype


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
    return len(jbody), len(cbor_doc and cbody or cbody)


def concurrency(client_factory, clients, ops_per_client):
    """Drives ``clients`` concurrent threads, each issuing ``ops_per_client`` discovery queries.
    Asserts zero errors; returns ``(total_ops, errors, elapsed, p50_ms, p99_ms, throughput)``."""
    errors = [0]
    lock = threading.Lock()
    latencies = []
    lat_lock = threading.Lock()

    def worker():
        c = client_factory()
        local = []
        for _ in range(ops_per_client):
            t0 = time.time()
            try:
                st, _, _ = c.query(
                    "MATCH (seed:Document {id:'ref-d-0'})-[:MENTIONS]->(c:Concept)"
                    "<-[:MENTIONS]-(other:Document) WHERE other.id <> 'ref-d-0' "
                    "RETURN other.id AS doc, count(DISTINCT c) AS shared ORDER BY shared DESC, doc ASC")
                if st != 200:
                    with lock:
                        errors[0] += 1
            except Exception:
                with lock:
                    errors[0] += 1
            local.append(time.time() - t0)
        with lat_lock:
            latencies.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(clients)]
    t0 = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - t0

    total = clients * ops_per_client
    latencies.sort()
    p50 = latencies[len(latencies) // 2] * 1000 if latencies else 0.0
    p99 = latencies[min(len(latencies) - 1, int(len(latencies) * 0.99))] * 1000 if latencies else 0.0
    throughput = total / elapsed if elapsed > 0 else 0.0
    check("concurrency: zero errors", errors[0], 0)
    return total, errors[0], elapsed, p50, p99, throughput


def main():
    ap = argparse.ArgumentParser(description="Graphus knowledge-graph discovery workload over REST")
    ap.add_argument("--port", required=True)
    ap.add_argument("--secret", required=True)
    ap.add_argument("--user", default="neo4j")
    ap.add_argument("--cypher", required=True)
    ap.add_argument("--reference", required=True)
    ap.add_argument("--batch-size", type=int, default=200)
    ap.add_argument("--clients", type=int, default=16)
    ap.add_argument("--ops-per-client", type=int, default=20)
    args = ap.parse_args()

    secret = args.secret.encode()
    token = mint_jwt(secret, args.user)
    print(f"== minted HS256 JWT for '{args.user}' ({len(token)} chars)")

    client = RestClient(args.port, token)

    print("== auth enforcement")
    assert_auth_enforced(client)

    print("== load graph (batched auto-commit over REST)")
    statements = parse_statements(args.cypher)
    loaded, load_secs = load_graph(client, statements, args.batch_size)
    print(f"  loaded {loaded} statements in {load_secs:.2f}s")

    print("== explicit transaction lifecycle (begin / commit / rollback)")
    demo_explicit_tx(client)

    print("== discovery queries vs reference.json")
    with open(args.reference) as f:
        ref = json.load(f)
    discovery_queries(client, ref)

    print("== NDJSON streaming")
    ndjson_rows, ndjson_secs, _ = ndjson_stream(client)
    ndjson_throughput = ndjson_rows / ndjson_secs if ndjson_secs > 0 else 0.0
    print(f"  streamed {ndjson_rows} rows in {ndjson_secs * 1000:.1f}ms "
          f"({ndjson_throughput:.0f} rows/s)")

    print("== content negotiation (JSON vs CBOR)")
    json_bytes, cbor_bytes = content_negotiation(client)
    ratio = cbor_bytes / json_bytes if json_bytes else 0.0
    print(f"  JSON={json_bytes} B  CBOR={cbor_bytes} B  (CBOR is {ratio * 100:.1f}% of JSON)")

    print("== concurrency")
    total_ops, errors, conc_secs, p50, p99, throughput = concurrency(
        lambda: RestClient(args.port, token), args.clients, args.ops_per_client)
    print(f"  clients={args.clients} ops={total_ops} errors={errors} "
          f"throughput={throughput:.0f} ops/s p50={p50:.1f}ms p99={p99:.1f}ms")

    if FAILURES == 0:
        print("GRAPHUS_KG_REST_OK")
        stats = {
            "loaded_statements": loaded,
            "load_secs": round(load_secs, 3),
            "ndjson_rows": ndjson_rows,
            "ndjson_secs": round(ndjson_secs, 4),
            "ndjson_rows_per_sec": round(ndjson_throughput, 1),
            "json_bytes": json_bytes,
            "cbor_bytes": cbor_bytes,
            "cbor_ratio": round(ratio, 4),
            "concurrency_clients": args.clients,
            "concurrency_ops": total_ops,
            "concurrency_errors": errors,
            "concurrency_secs": round(conc_secs, 3),
            "ops_per_sec": round(throughput, 1),
            "p50_ms": round(p50, 3),
            "p99_ms": round(p99, 3),
        }
        print("GRAPHUS_STATS " + json.dumps(stats, separators=(",", ":")))
        return 0

    print(f"GRAPHUS_KG_REST_FAILED — {FAILURES} assertion(s) did not hold")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
