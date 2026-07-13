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
	"errors"
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

	// 2) Read it back and ASSERT the exact values written — not merely that a row exists.
	res, err := neo4j.ExecuteQuery(ctx, driver,
		"MATCH (p:Person {name: $name}) RETURN p.name AS name, p.role AS role",
		map[string]any{"name": "Alan Turing"},
		neo4j.EagerResultTransformer, onDB,
	)
	if err != nil {
		return fmt.Errorf("match: %w", err)
	}
	if len(res.Records) != 1 {
		return fmt.Errorf("read-back: expected exactly 1 record, got %d", len(res.Records))
	}
	if name, _ := res.Records[0].Get("name"); name != "Alan Turing" {
		return fmt.Errorf("read-back: name = %v, want %q", name, "Alan Turing")
	}
	if role, _ := res.Records[0].Get("role"); role != "computer scientist" {
		return fmt.Errorf("read-back: role = %v, want %q", role, "computer scientist")
	}
	fmt.Println("✓ read back and verified (:Person {name:'Alan Turing', role:'computer scientist'})")

	// 3) Aggregate and ASSERT the exact count. Scoped to this client's OWN node by name so
	//    it is deterministic in both modes (external is isolated; local shares one database
	//    across all three clients). After a single CREATE the count is exactly 1.
	people, err := personCount(ctx, driver, onDB, "Alan Turing")
	if err != nil {
		return err
	}
	if people != 1 {
		return fmt.Errorf("aggregate: count of (:Person {name:'Alan Turing'}) = %d, want 1 after one CREATE", people)
	}
	fmt.Printf("✓ nodes named 'Alan Turing': %d (exactly as expected)\n", people)

	// 4) Explicit write transaction: flip a flag and ASSERT the committed value that comes
	//    back — the write result is verified, not discarded.
	session := driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: database})
	defer session.Close(ctx)
	verified, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx,
			"MATCH (p:Person {name: $name}) SET p.verified = true RETURN p.verified AS verified",
			map[string]any{"name": "Alan Turing"})
		if err != nil {
			return nil, err
		}
		rec, err := r.Single(ctx)
		if err != nil {
			return nil, err
		}
		v, _ := rec.Get("verified")
		return v, nil
	})
	if err != nil {
		return fmt.Errorf("explicit write tx: %w", err)
	}
	if verified != true {
		return fmt.Errorf("explicit write tx: committed verified = %v, want true", verified)
	}
	fmt.Println("✓ explicit write transaction committed and verified (p.verified = true)")

	// 5) NEGATIVE path: a deliberately invalid statement must surface a Neo4jError, and the
	//    SAME session must remain usable afterwards — the driver issues RESET internally to
	//    recover the connection from the FAILED state.
	result, runErr := session.Run(ctx, "THIS IS NOT VALID CYPHER", nil)
	if runErr == nil {
		_, runErr = result.Consume(ctx) // force any lazily-surfaced failure to materialise
	}
	if runErr == nil {
		return fmt.Errorf("negative path: expected the server to reject an invalid statement, got no error")
	}
	var neoErr *neo4j.Neo4jError
	if !errors.As(runErr, &neoErr) {
		return fmt.Errorf("negative path: expected a Neo4jError, got %T: %v", runErr, runErr)
	}
	recheck, err := session.Run(ctx, "RETURN 1 AS ok", nil)
	if err != nil {
		return fmt.Errorf("negative path: session unusable after failure: %w", err)
	}
	rec, err := recheck.Single(ctx)
	if err != nil {
		return fmt.Errorf("negative path: reading recovery row: %w", err)
	}
	if ok, _ := rec.Get("ok"); ok != int64(1) {
		return fmt.Errorf("negative path: recovery query returned %v, want 1", ok)
	}
	fmt.Printf("✓ server rejected invalid Cypher (%s) and the session recovered\n", neoErr.Code)

	// 6) Clean up, then ASSERT the DB is empty again.
	if _, err := neo4j.ExecuteQuery(ctx, driver,
		"MATCH (p:Person {name: $name}) DETACH DELETE p",
		map[string]any{"name": "Alan Turing"},
		neo4j.EagerResultTransformer, onDB,
	); err != nil {
		return fmt.Errorf("cleanup: %w", err)
	}
	if people, err := personCount(ctx, driver, onDB, "Alan Turing"); err != nil {
		return err
	} else if people != 0 {
		return fmt.Errorf("after cleanup: count of (:Person {name:'Alan Turing'}) = %d, want 0", people)
	}
	fmt.Println("✓ cleaned up (count of 'Alan Turing' back to 0)")

	fmt.Println("\nBOLT-TCP DEMO PASSED")
	return nil
}

// personCount returns how many :Person nodes carry the given name. Scoping the aggregate to
// this client's own node (rather than the whole label) keeps the assertion deterministic even
// in local mode, where all three clients share the one default database.
func personCount(ctx context.Context, driver neo4j.DriverWithContext, onDB neo4j.ExecuteQueryConfigurationOption, name string) (int64, error) {
	res, err := neo4j.ExecuteQuery(ctx, driver,
		"MATCH (p:Person {name: $name}) RETURN count(p) AS n",
		map[string]any{"name": name},
		neo4j.EagerResultTransformer, onDB,
	)
	if err != nil {
		return 0, fmt.Errorf("aggregate: %w", err)
	}
	if len(res.Records) != 1 {
		return 0, fmt.Errorf("aggregate: expected 1 record, got %d", len(res.Records))
	}
	n, ok := res.Records[0].Get("n")
	if !ok {
		return 0, fmt.Errorf("aggregate: result has no 'n' column")
	}
	count, ok := n.(int64)
	if !ok {
		return 0, fmt.Errorf("aggregate: count is %T, not int64", n)
	}
	return count, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
