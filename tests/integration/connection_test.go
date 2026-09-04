//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avinash-1707/pg-canary/internal/database"
)

func TestDedicatedConnectionPreflight(t *testing.T) {
	if fixtureStack == nil {
		t.Skipf("set %s=1 to run Docker-backed integration tests", integrationEnvironment)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, target := range fixtureStack.targets {
		t.Run(target.service, func(t *testing.T) {
			connection, err := database.Open(ctx, database.Config{URL: target.adminURL})
			if target.major < 15 {
				if !errors.Is(err, database.ErrUnsupportedVersion) {
					t.Fatalf("Open() error = %v, want unsupported-version error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			defer connection.Close(ctx)
			if connection.Metadata.Product != "PostgreSQL" || connection.Metadata.Version == "" {
				t.Fatalf("unexpected metadata: %+v", connection.Metadata)
			}
		})
	}
}

func TestDedicatedConnectionRejectsReadOnlyAndTimesOutQueries(t *testing.T) {
	if fixtureStack == nil {
		t.Skipf("set %s=1 to run Docker-backed integration tests", integrationEnvironment)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	target := fixtureStack.targets[1] // PostgreSQL 15; index zero is the unsupported 14 fixture.
	admin := connect(t, ctx, target.adminURL)
	defer admin.Close(ctx)

	if _, err := admin.Exec(ctx, "ALTER DATABASE pg_canary_test SET default_transaction_read_only = on"); err != nil {
		t.Fatalf("make fixture read-only: %v", err)
	}
	_, err := database.Open(ctx, database.Config{URL: target.adminURL})
	if _, resetErr := admin.Exec(ctx, "ALTER DATABASE pg_canary_test RESET default_transaction_read_only"); resetErr != nil {
		t.Fatalf("reset fixture read-only mode: %v", resetErr)
	}
	if !errors.Is(err, database.ErrReadOnlyTarget) {
		t.Fatalf("Open() read-only error = %v, want ErrReadOnlyTarget", err)
	}

	connection, err := database.Open(ctx, database.Config{URL: target.adminURL, QueryTimeout: time.Millisecond})
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}
	defer connection.Close(context.Background())
	if _, err := connection.Exec(ctx, "SELECT pg_sleep(0.05)"); err == nil {
		t.Fatal("slow query unexpectedly completed")
	}
}
