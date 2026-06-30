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

	// 3. Read it back.
	res, err := c.query(statement{
		Statement:  "MATCH (p:Person {name: $name}) RETURN p.name AS name, p.role AS role",
		Parameters: map[string]any{"name": "Grace Hopper"},
	})
	if err != nil {
		return fmt.Errorf("match: %w", err)
	}
	if len(res.Results) == 1 {
		r := res.Results[0]
		fmt.Printf("✓ query returned %d row(s) %v:\n", len(r.Data), r.Fields)
		for _, row := range r.Data {
			fmt.Printf("    %s\n", joltRow(row))
		}
	}

	// 4. Aggregate.
	res, err = c.query(statement{Statement: "MATCH (p:Person) RETURN count(p) AS people"})
	if err != nil {
		return fmt.Errorf("aggregate: %w", err)
	}
	if len(res.Results) == 1 && len(res.Results[0].Data) == 1 {
		fmt.Printf("✓ total Person nodes: %v\n", jolt(res.Results[0].Data[0][0]))
	}

	// 5. Clean up so the example is idempotent across runs.
	if _, err := c.query(statement{
		Statement:  "MATCH (p:Person {name: $name}) DETACH DELETE p",
		Parameters: map[string]any{"name": "Grace Hopper"},
	}); err != nil {
		return fmt.Errorf("cleanup: %w", err)
	}
	fmt.Println("✓ cleaned up")

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

// query runs one statement on the auto-commit endpoint and returns the decoded response.
func (c *client) query(s statement) (*runResponse, error) {
	body, _ := json.Marshal(runRequest{Statements: []statement{s}})
	url := fmt.Sprintf("%s/db/%s/tx/commit", c.base, c.db)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		// Errors are RFC 9457 problem+json: {type,title,status,detail,code}.
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, raw)
	}
	var rr runResponse
	if err := json.Unmarshal(raw, &rr); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &rr, nil
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
