//go:build integration

package integration

import (
	"context"
	"github.com/avinash-1707/pg-canary/internal/control"
	"github.com/avinash-1707/pg-canary/internal/domain"
	"github.com/avinash-1707/pg-canary/internal/seeder"
	"github.com/avinash-1707/pg-canary/internal/session"
	"testing"
	"time"
)

func TestNegativeControlRequiresOwnerFixture(t *testing.T) {
	if fixtureStack == nil {
		t.Skip("integration disabled")
	}
	ctx, c := context.WithTimeout(context.Background(), 30*time.Second)
	defer c()
	a := connect(t, ctx, fixtureStack.targets[1].adminURL)
	defer a.Close(ctx)
	reset(t, ctx, a)
	r := connect(t, ctx, fixtureStack.targets[1].runnerURL)
	defer r.Close(ctx)
	tx, e := r.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	owner := domain.Identity{Role: "canary_app", Settings: map[string]string{"request.jwt.claim.sub": "owner"}}
	if e = session.Configure(ctx, tx, "secure", owner); e != nil {
		t.Fatal(e)
	}
	attack := domain.Attack{Table: "projects", PrimaryKey: []string{"id"}}
	row := map[string]any{"id": int64(1), "tenant_id": "owner", "name": "x"}
	if _, e = seeder.Seed(ctx, tx, "secure", []domain.Fixture{{Table: "projects", OwnerRow: row}}); e != nil {
		t.Fatal(e)
	}
	if e = control.Verify(ctx, tx, "secure", attack, row); e != nil {
		t.Fatal(e)
	}
	if e = control.Verify(ctx, tx, "secure", attack, map[string]any{"id": int64(2)}); e == nil {
		t.Fatal("missing row passed control")
	}
}
