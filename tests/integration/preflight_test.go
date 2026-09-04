//go:build integration

package integration

import (
	"context"
	"github.com/avinash-1707/pg-canary/internal/catalog"
	"github.com/avinash-1707/pg-canary/internal/domain"
	"github.com/avinash-1707/pg-canary/internal/preflight"
	"testing"
	"time"
)

func TestPreflightBlocksOwnerBypass(t *testing.T) {
	if fixtureStack == nil {
		t.Skip("integration disabled")
	}
	ctx, c := context.WithTimeout(context.Background(), 30*time.Second)
	defer c()
	conn := connect(t, ctx, fixtureStack.targets[1].adminURL)
	defer conn.Close(ctx)
	reset(t, ctx, conn)
	p := domain.Profile{Database: domain.Database{Schema: "owner_bypass", RequireDisposable: true}, Identity: domain.Identities{Owner: domain.Identity{Role: "canary_app"}, Adversary: domain.Identity{Role: "canary_app"}}, Attacks: []domain.Attack{{Table: "projects"}}}
	r := preflight.Check(ctx, catalog.New(conn), p, preflight.Config{AllowWrite: true, LoginRole: "canary_runner"})
	if r.Outcome != domain.OutcomeBlocked {
		t.Fatalf("outcome=%s findings=%+v", r.Outcome, r.Findings)
	}
}
