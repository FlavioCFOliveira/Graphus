// Command rest demonstrates using the Graphus REST WebAPI from Go with nothing but the
// standard library (net/http, crypto/tls, encoding/json).
//
// The flow is: POST /auth/login with a username + password to obtain a short-lived
// Bearer JWT, then send Cypher statements to the transactional endpoint
// POST /db/{database}/tx/commit with that token in the Authorization header.
//
// REST is served over TLS. The quickstart Docker image uses a self-signed certificate,
// so this example skips certificate verification by default (-insecure, the analogue of
// `curl -k`). With a CA-issued certificate, pass -insecure=false.
//
// Usage:
//
//	go run ./rest \
//	    -url https://localhost:7474 \
//	    -user graphus -password graphus-local -database graphus
//
// Or via environment variables: GRAPHUS_REST_URL, GRAPHUS_USER, GRAPHUS_PASSWORD,
// GRAPHUS_DATABASE.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	url := flag.String("url", env("GRAPHUS_REST_URL", "https://localhost:7474"), "base REST URL")
	user := flag.String("user", env("GRAPHUS_USER", "graphus"), "username")
	password := flag.String("password", env("GRAPHUS_PASSWORD", "graphus-local"), "password")
	database := flag.String("database", env("GRAPHUS_DATABASE", "graphus"), "target database")
	insecure := flag.Bool("insecure", true, "skip TLS certificate verification (self-signed quickstart cert)")
	flag.Parse()

	c := &client{
		base: *url,
		db:   *database,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure},
			},
		},
	}

	if err := c.run(*user, *password); err != nil {
		fmt.Fprintf(os.Stderr, "rest: %v\n", err)
		os.Exit(1)
	}
}

type client struct {
	base  string
	db    string
	token string
	http  *http.Client
}

// loginResponse is the body of POST /auth/login.
type loginResponse struct {
	Token             string `json:"token"`
	TokenType         string `json:"token_type"`
	ExpiresAtUnixSecs int64  `json:"expires_at_unix_secs"`
}

// runRequest / runResponse mirror the transactional API's request and response envelopes.
type statement struct {
	Statement  string         `json:"statement"`
	Parameters map[string]any `json:"parameters,omitempty"`
}
type runRequest struct {
	Statements []statement `json:"statements"`
}
type statementResult struct {
	Fields  []string        `json:"fields"`
	Data    [][]any         `json:"data"`
	Summary json.RawMessage `json:"summary"`
}
type runResponse struct {
	Results []statementResult `json:"results"`
}

// problem is an RFC 9457 problem+json error body: {type,title,status,detail,code}. The
// transactional endpoint returns this (with a >= 400 status) when a statement is rejected.
type problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
	Code   string `json:"code"`
}

func (c *client) run(user, password string) error {
	fmt.Printf("→ REST WebAPI at %s\n", c.base)

	// 1. Authenticate: POST /auth/login -> Bearer JWT.
	if err := c.login(user, password); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	fmt.Printf("  logged in as %q; got a Bearer token\n\n", user)

	// 2. Write a node with parameters.
	if _, err := c.query(statement{
		Statement:  "CREATE (p:Person {name: $name, role: $role})",
		Parameters: map[string]any{"name": "Grace Hopper", "role": "rear admiral"},
	}); err != nil {
		return fmt.Errorf("create: %w", err)
	}
	fmt.Println("✓ created (:Person {name:'Grace Hopper'})")

	// 3. Read it back and ASSERT the exact values written — not merely that a row exists.
	//    A server that returned the wrong name or role must fail here, before the sentinel.
	res, err := c.query(statement{
		Statement:  "MATCH (p:Person {name: $name}) RETURN p.name AS name, p.role AS role",
		Parameters: map[string]any{"name": "Grace Hopper"},
	})
	if err != nil {
		return fmt.Errorf("match: %w", err)
	}
	if len(res.Results) != 1 {
		return fmt.Errorf("read-back: expected 1 statement result, got %d", len(res.Results))
	}
	r := res.Results[0]
	if len(r.Data) != 1 {
		return fmt.Errorf("read-back: expected exactly 1 row in the isolated DB, got %d", len(r.Data))
	}
	row := r.Data[0]
	if len(row) < 2 {
		return fmt.Errorf("read-back: expected 2 columns (name, role), got %d", len(row))
	}
	if name := fmt.Sprintf("%v", jolt(row[0])); name != "Grace Hopper" {
		return fmt.Errorf("read-back: name = %q, want %q", name, "Grace Hopper")
	}
	if role := fmt.Sprintf("%v", jolt(row[1])); role != "rear admiral" {
		return fmt.Errorf("read-back: role = %q, want %q", role, "rear admiral")
	}
	fmt.Printf("✓ read back and verified %v: %s\n", r.Fields, joltRow(row))

	// 4. Aggregate and ASSERT the exact count. Scoped to this client's OWN node by name so
	//    it is deterministic in both modes (external is isolated; local shares one database
	//    across all three clients). After a single CREATE the count is exactly 1.
	people, err := c.count("Grace Hopper")
	if err != nil {
		return err
	}
	if people != 1 {
		return fmt.Errorf("aggregate: count of (:Person {name:'Grace Hopper'}) = %d, want 1 after one CREATE", people)
	}
	fmt.Printf("✓ nodes named 'Grace Hopper': %d (exactly as expected)\n", people)

	// 5. NEGATIVE path: a deliberately invalid statement MUST be rejected with a well-formed
	//    RFC 9457 problem+json (status >= 400 carrying a title/detail). This exercises the
	//    error path a real client has to handle; a 2xx or an unshaped body fails here.
	if err := c.queryExpectingProblem(statement{Statement: "THIS IS NOT VALID CYPHER"}); err != nil {
		return fmt.Errorf("negative path: %w", err)
	}
	fmt.Println("✓ server rejected invalid Cypher with a well-formed problem+json error")

	// 6. Clean up, then ASSERT the DB is empty again — proving the DETACH DELETE took effect.
	if _, err := c.query(statement{
		Statement:  "MATCH (p:Person {name: $name}) DETACH DELETE p",
		Parameters: map[string]any{"name": "Grace Hopper"},
	}); err != nil {
		return fmt.Errorf("cleanup: %w", err)
	}
	if people, err := c.count("Grace Hopper"); err != nil {
		return err
	} else if people != 0 {
		return fmt.Errorf("after cleanup: count of (:Person {name:'Grace Hopper'}) = %d, want 0", people)
	}
	fmt.Println("✓ cleaned up (count of 'Grace Hopper' back to 0)")

	fmt.Println("\nREST DEMO PASSED")
	return nil
}

// login posts credentials to /auth/login and stores the returned Bearer token.
func (c *client) login(user, password string) error {
	body, _ := json.Marshal(map[string]string{"username": user, "password": password})
	req, _ := http.NewRequest(http.MethodPost, c.base+"/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %s", resp.StatusCode, raw)
	}
	var lr loginResponse
	if err := json.Unmarshal(raw, &lr); err != nil {
		return fmt.Errorf("decoding login response: %w", err)
	}
	if lr.Token == "" {
		return fmt.Errorf("login response carried no token: %s", raw)
	}
	c.token = lr.Token
	return nil
}

// do posts one statement to the transactional endpoint and returns the HTTP status and
// raw body without interpreting them, so the success and error paths can share it.
func (c *client) do(s statement) (int, []byte, error) {
	body, _ := json.Marshal(runRequest{Statements: []statement{s}})
	url := fmt.Sprintf("%s/db/%s/tx/commit", c.base, c.db)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw, nil
}

// query runs one statement on the auto-commit endpoint and requires HTTP 200.
func (c *client) query(s statement) (*runResponse, error) {
	status, raw, err := c.do(s)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		// Errors are RFC 9457 problem+json: {type,title,status,detail,code}.
		return nil, fmt.Errorf("status %d: %s", status, raw)
	}
	var rr runResponse
	if err := json.Unmarshal(raw, &rr); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &rr, nil
}

// count returns how many :Person nodes carry the given name. Scoping the aggregate to the
// client's own node (rather than the whole label) keeps the assertion deterministic even
// in local mode, where all three clients share the one default database.
func (c *client) count(name string) (int64, error) {
	res, err := c.query(statement{
		Statement:  "MATCH (p:Person {name: $name}) RETURN count(p) AS n",
		Parameters: map[string]any{"name": name},
	})
	if err != nil {
		return 0, fmt.Errorf("aggregate: %w", err)
	}
	if len(res.Results) != 1 || len(res.Results[0].Data) != 1 || len(res.Results[0].Data[0]) != 1 {
		return 0, fmt.Errorf("aggregate: unexpected result shape %+v", res.Results)
	}
	n, err := asInt(jolt(res.Results[0].Data[0][0]))
	if err != nil {
		return 0, fmt.Errorf("aggregate: %w", err)
	}
	return n, nil
}

// queryExpectingProblem runs a statement the server MUST reject and asserts the reply is a
// well-formed RFC 9457 problem+json: a >= 400 status carrying a title or detail. A server
// that answers 2xx (or with an unshaped body) to invalid Cypher fails here.
func (c *client) queryExpectingProblem(s statement) error {
	status, raw, err := c.do(s)
	if err != nil {
		return err
	}
	if status < 400 {
		return fmt.Errorf("expected rejection (HTTP >= 400) for %q, got HTTP %d: %s", s.Statement, status, raw)
	}
	var p problem
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("error body is not JSON: %w (body: %s)", err, raw)
	}
	if strings.TrimSpace(p.Title) == "" && strings.TrimSpace(p.Detail) == "" {
		return fmt.Errorf("error body is not a well-formed problem+json (no title/detail): %s", raw)
	}
	return nil
}

// asInt coerces a decoded aggregate cell to int64. Strict Jolt encodes a 64-bit integer as
// {"Z":"<decimal string>"} — the inner value is a decimal STRING, not a JSON number, because
// JSON numbers cannot safely carry the full int64 range — so after jolt() unwraps it we get
// a string and must parse it (base 10). We also accept the float64/json.Number forms JSON
// yields for smaller numeric values, and native Go integers.
func asInt(v any) (int64, error) {
	switch n := v.(type) {
	case string:
		return strconv.ParseInt(n, 10, 64)
	case float64:
		return int64(n), nil
	case json.Number:
		return n.Int64()
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	default:
		return 0, fmt.Errorf("value %v (%T) is not an integer", v, v)
	}
}

// jolt unwraps a strict-Jolt typed cell to a readable value. REST encodes result cells as
// single-key sigil objects: {"U":s} string, {"Z":n} integer, {"R":x} float, {"?":b} bool,
// {"#":hex} bytes, {"T":iso} temporal. Lists are plain JSON arrays; {"@"}/{"{}"}/ maps are
// returned as-is. A non-sigil value passes through unchanged.
func jolt(v any) any {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return v
	}
	for k, inner := range m {
		switch k {
		case "U", "Z", "R", "?", "#", "T":
			return inner
		default:
			return v
		}
	}
	return v
}

// joltRow renders a row's cells, unwrapping each Jolt value, joined by " | ".
func joltRow(row []any) string {
	parts := make([]string, len(row))
	for i, c := range row {
		parts[i] = fmt.Sprintf("%v", jolt(c))
	}
	return strings.Join(parts, " | ")
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
