// Command bolt-tcp demonstrates connecting to Graphus over Bolt-over-TCP from Go using
// the official Neo4j Go driver (github.com/neo4j/neo4j-go-driver/v5). Because Graphus
// speaks standards-compliant Bolt 5.x + PackStream, the unmodified Neo4j driver works
// against it directly.
//
// Bolt-over-TCP is always TLS-secured. The quickstart Docker image ships a self-signed
// certificate, so this example uses the `bolt+ssc://` scheme (TLS, self-signed
// certificate accepted without CA verification). With a CA-issued certificate use
// `bolt+s://` instead; for a plaintext loopback dev server (no TLS) use `bolt://`.
//
// Usage:
//
//	go run ./bolt-tcp \
//	    -uri bolt+ssc://localhost:7687 \
//	    -user graphus -password graphus-local -database graphus
//
// Or via environment variables: GRAPHUS_BOLT_URI, GRAPHUS_USER, GRAPHUS_PASSWORD,
// GRAPHUS_DATABASE.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func main() {
	uri := flag.String("uri", env("GRAPHUS_BOLT_URI", "bolt+ssc://localhost:7687"), "Bolt URI; TCP requires TLS — bolt+ssc:// (self-signed) or bolt+s:// (CA-verified)")
	user := flag.String("user", env("GRAPHUS_USER", "graphus"), "username")
	password := flag.String("password", env("GRAPHUS_PASSWORD", "graphus-local"), "password")
	database := flag.String("database", env("GRAPHUS_DATABASE", "graphus"), "target database")
	flag.Parse()

	if err := run(*uri, *user, *password, *database); err != nil {
		fmt.Fprintf(os.Stderr, "bolt-tcp: %v\n", err)
		os.Exit(1)
	}
}

func run(uri, user, password, database string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Printf("→ connecting to Graphus over Bolt-TCP at %s\n", uri)
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, password, ""))
	if err != nil {
		return fmt.Errorf("create driver: %w", err)
	}
	defer driver.Close(ctx)

	if err := driver.VerifyConnectivity(ctx); err != nil {
		return fmt.Errorf("verify connectivity (is the server up and is the URI/scheme right?): %w", err)
	}
	fmt.Printf("  authenticated as %q on database %q\n\n", user, database)

	onDB := neo4j.ExecuteQueryWithDatabase(database)

	// 1) Write a node with parameters (auto-commit, managed transaction with retries).
	if _, err := neo4j.ExecuteQuery(ctx, driver,
		"CREATE (p:Person {name: $name, role: $role})",
		map[string]any{"name": "Alan Turing", "role": "computer scientist"},
		neo4j.EagerResultTransformer, onDB,
	); err != nil {
		return fmt.Errorf("create: %w", err)
	}
	fmt.Println("✓ created (:Person {name:'Alan Turing'})")

	// 2) Read it back.
	res, err := neo4j.ExecuteQuery(ctx, driver,
		"MATCH (p:Person {name: $name}) RETURN p.name AS name, p.role AS role",
		map[string]any{"name": "Alan Turing"},
		neo4j.EagerResultTransformer, onDB,
	)
	if err != nil {
		return fmt.Errorf("match: %w", err)
	}
	fmt.Printf("✓ query returned %d row(s) %v:\n", len(res.Records), res.Keys)
	for _, rec := range res.Records {
		name, _ := rec.Get("name")
		role, _ := rec.Get("role")
		fmt.Printf("    name=%v role=%v\n", name, role)
	}

	// 3) Aggregate.
	res, err = neo4j.ExecuteQuery(ctx, driver,
		"MATCH (p:Person) RETURN count(p) AS people", nil,
		neo4j.EagerResultTransformer, onDB,
	)
	if err != nil {
		return fmt.Errorf("aggregate: %w", err)
	}
	if len(res.Records) == 1 {
		people, _ := res.Records[0].Get("people")
		fmt.Printf("✓ total Person nodes: %v\n", people)
	}

	// 4) Explicit transaction: demonstrate the session + managed-transaction API.
	session := driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: database})
	defer session.Close(ctx)
	committed, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, "MATCH (p:Person {name: $name}) SET p.verified = true",
			map[string]any{"name": "Alan Turing"})
		return nil, err
	})
	if err != nil {
		return fmt.Errorf("explicit write tx: %w", err)
	}
	_ = committed
	fmt.Println("✓ explicit write transaction committed")

	// 5) Clean up so the example is idempotent across runs.
	if _, err := neo4j.ExecuteQuery(ctx, driver,
		"MATCH (p:Person {name: $name}) DETACH DELETE p",
		map[string]any{"name": "Alan Turing"},
		neo4j.EagerResultTransformer, onDB,
	); err != nil {
		return fmt.Errorf("cleanup: %w", err)
	}
	fmt.Println("✓ cleaned up")

	fmt.Println("\nBOLT-TCP DEMO PASSED")
	return nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
