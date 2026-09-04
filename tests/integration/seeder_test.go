//go:build integration

package integration

import (
	"context"
	"github.com/avinash-1707/pg-canary/internal/domain"
	"github.com/avinash-1707/pg-canary/internal/seeder"
	"github.com/avinash-1707/pg-canary/internal/session"
	"testing"
	"time"
)

func TestSeederInsertsOnlyDeclaredFixtures(t *testing.T) {
	if fixtureStack == nil {
		t.Skip("integration disabled")
	}
	ctx, c := context.WithTimeout(context.Background(), 30*time.Second)
	defer c()
	admin := connect(t, ctx, fixtureStack.targets[1].adminURL)
	defer admin.Close(ctx)
	reset(t, ctx, admin)
	runner := connect(t, ctx, fixtureStack.targets[1].runnerURL)
	defer runner.Close(ctx)
	tx, e := runner.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if e = session.Configure(ctx, tx, "secure", domain.Identity{Role: "canary_app", Settings: map[string]string{"request.jwt.claim.sub": "owner"}}); e != nil {
		t.Fatal(e)
	}
	r, e := seeder.Seed(ctx, tx, "secure", []domain.Fixture{{Table: "projects", OwnerRow: map[string]any{"id": int64(1), "tenant_id": "owner", "name": "synthetic"}}})
	if e != nil {
		t.Fatal(e)
	}
	if r.OwnerRows["projects"]["id"] != int64(1) {
		t.Fatal("owner row not retained")
	}
	var n int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM projects").Scan(&n); e != nil || n != 1 {
		t.Fatalf("count=%d err=%v", n, e)
	}
}
