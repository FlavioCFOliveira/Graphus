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

	// 2) Read it back.
	res, err := s.Run(
		"MATCH (p:Person {name: $name}) RETURN p.name AS name, p.role AS role",
		map[string]any{"name": "Ada Lovelace"},
	)
	if err != nil {
		return fmt.Errorf("match: %w", err)
	}
	fmt.Printf("✓ query returned %d row(s) %v:\n", len(res.Rows), res.Columns)
	for _, row := range res.Rows {
		fmt.Printf("    %s\n", formatRow(row))
	}

	// 3) Aggregate over all Person nodes.
	res, err = s.Run("MATCH (p:Person) RETURN count(p) AS people", nil)
	if err != nil {
		return fmt.Errorf("aggregate: %w", err)
	}
	if len(res.Rows) == 1 {
		fmt.Printf("✓ total Person nodes: %v\n", res.Rows[0][0])
	}

	// 4) Clean up so the example is idempotent across runs.
	if _, err := s.Run("MATCH (p:Person {name: $name}) DETACH DELETE p",
		map[string]any{"name": "Ada Lovelace"}); err != nil {
		return fmt.Errorf("cleanup: %w", err)
	}
	fmt.Println("✓ cleaned up")

	fmt.Println("\nBOLT-UDS DEMO PASSED")
	return nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
