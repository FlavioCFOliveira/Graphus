// Command bolt-uds demonstrates connecting to Graphus over the Bolt protocol on a
// Unix domain socket (the IPC interface) from Go, using the hand-rolled Bolt client in
// this package (the official Neo4j Go driver cannot dial a Unix socket).
//
// Usage:
//
//	go run ./bolt-uds \
//	    -socket /data/graphus.sock \
//	    -user graphus -password graphus-local
//
// Or with environment variables (GRAPHUS_UDS_SOCKET, GRAPHUS_USER, GRAPHUS_PASSWORD).
//
// UDS authentication has TWO gates (see the README): the kernel peer-credential gate
// (this process's uid must be mapped to a Graphus user via the server's `admin_uid`
// config) AND the Bolt LOGON below (username + password). If the uid is not mapped the
// server closes the socket before any Bolt bytes flow.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	socket := flag.String("socket", env("GRAPHUS_UDS_SOCKET", "/data/graphus.sock"), "path to the Graphus Unix domain socket")
	user := flag.String("user", env("GRAPHUS_USER", "graphus"), "Bolt LOGON user")
	password := flag.String("password", env("GRAPHUS_PASSWORD", "graphus-local"), "Bolt LOGON password")
	flag.Parse()

	if err := run(*socket, *user, *password); err != nil {
		fmt.Fprintf(os.Stderr, "bolt-uds: %v\n", err)
		os.Exit(1)
	}
}

func run(socket, user, password string) error {
	fmt.Printf("→ connecting to Graphus over UDS at %s\n", socket)
	s, err := Dial(socket, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer s.Close()
	fmt.Printf("  negotiated Bolt %s\n", s.Version)

	if err := s.Login("graphus-go-uds/1.0", user, password); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	fmt.Printf("  authenticated as %q against %s\n\n", user, s.Server)

	// 1) Write a node with a parameter (auto-commit).
	if _, err := s.Run(
		"CREATE (p:Person {name: $name, role: $role})",
		map[string]any{"name": "Ada Lovelace", "role": "mathematician"},
	); err != nil {
		return fmt.Errorf("create: %w", err)
	}
	fmt.Println("✓ created (:Person {name:'Ada Lovelace'})")

	// 2) Read it back and ASSERT the exact values written — not merely that a row exists.
	res, err := s.Run(
		"MATCH (p:Person {name: $name}) RETURN p.name AS name, p.role AS role",
		map[string]any{"name": "Ada Lovelace"},
	)
	if err != nil {
		return fmt.Errorf("match: %w", err)
	}
	if len(res.Rows) != 1 {
		return fmt.Errorf("read-back: expected exactly 1 row, got %d", len(res.Rows))
	}
	row := res.Rows[0]
	if len(row) < 2 {
		return fmt.Errorf("read-back: expected 2 columns (name, role), got %d", len(row))
	}
	if name, _ := row[0].(string); name != "Ada Lovelace" {
		return fmt.Errorf("read-back: name = %v, want %q", row[0], "Ada Lovelace")
	}
	if role, _ := row[1].(string); role != "mathematician" {
		return fmt.Errorf("read-back: role = %v, want %q", row[1], "mathematician")
	}
	fmt.Printf("✓ read back and verified %v: %s\n", res.Columns, formatRow(row))

	// 3) Aggregate and ASSERT the exact count. Scoped to this client's OWN node by name so
	//    it is deterministic in both modes (external is isolated; local shares one database
	//    across all three clients). After a single CREATE the count is exactly 1.
	people, err := personCount(s, "Ada Lovelace")
	if err != nil {
		return err
	}
	if people != 1 {
		return fmt.Errorf("aggregate: count of (:Person {name:'Ada Lovelace'}) = %d, want 1 after one CREATE", people)
	}
	fmt.Printf("✓ nodes named 'Ada Lovelace': %d (exactly as expected)\n", people)

	// 4) NEGATIVE path: a deliberately invalid statement makes the server return a Bolt
	//    FAILURE, which leaves the connection in the FAILED state. We observe the failure,
	//    then RESET the connection back to READY and prove it is usable with a follow-up
	//    query. Without RESET the connection would be dead after any server error.
	if _, err := s.Run("THIS IS NOT VALID CYPHER", nil); err == nil {
		return fmt.Errorf("negative path: expected a server FAILURE for an invalid statement, got none")
	} else {
		fmt.Printf("✓ server returned FAILURE as expected: %v\n", err)
	}
	if err := s.Reset(); err != nil {
		return fmt.Errorf("negative path: RESET failed: %w", err)
	}
	recheck, err := s.Run("RETURN 1 AS ok", nil)
	if err != nil {
		return fmt.Errorf("negative path: connection unusable after RESET: %w", err)
	}
	if len(recheck.Rows) != 1 || len(recheck.Rows[0]) != 1 {
		return fmt.Errorf("negative path: recovery query returned unexpected shape %+v", recheck.Rows)
	}
	if n, ok := asInt64(recheck.Rows[0][0]); !ok || n != 1 {
		return fmt.Errorf("negative path: recovery query returned %v, want 1", recheck.Rows[0][0])
	}
	fmt.Println("✓ connection recovered via RESET and answered a follow-up query")

	// 5) Clean up, then ASSERT the DB is empty again — proving the DETACH DELETE took effect.
	if _, err := s.Run("MATCH (p:Person {name: $name}) DETACH DELETE p",
		map[string]any{"name": "Ada Lovelace"}); err != nil {
		return fmt.Errorf("cleanup: %w", err)
	}
	if people, err := personCount(s, "Ada Lovelace"); err != nil {
		return err
	} else if people != 0 {
		return fmt.Errorf("after cleanup: count of (:Person {name:'Ada Lovelace'}) = %d, want 0", people)
	}
	fmt.Println("✓ cleaned up (count of 'Ada Lovelace' back to 0)")

	fmt.Println("\nBOLT-UDS DEMO PASSED")
	return nil
}

// personCount returns how many :Person nodes carry the given name. Scoping the aggregate to
// this client's own node (rather than the whole label) keeps the assertion deterministic even
// in local mode, where all three clients share the one default database.
func personCount(s *Session, name string) (int64, error) {
	res, err := s.Run("MATCH (p:Person {name: $name}) RETURN count(p) AS n",
		map[string]any{"name": name})
	if err != nil {
		return 0, fmt.Errorf("aggregate: %w", err)
	}
	if len(res.Rows) != 1 || len(res.Rows[0]) != 1 {
		return 0, fmt.Errorf("aggregate: unexpected result shape %+v", res.Rows)
	}
	n, ok := asInt64(res.Rows[0][0])
	if !ok {
		return 0, fmt.Errorf("aggregate: count is %T, not an integer", res.Rows[0][0])
	}
	return n, nil
}

// asInt64 coerces a PackStream-decoded integer cell (always int64 here) to int64.
func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
