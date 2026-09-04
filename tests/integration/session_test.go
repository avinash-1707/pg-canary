//go:build integration

package integration

import (
	"context"
	"github.com/avinash-1707/pg-canary/internal/domain"
	"github.com/avinash-1707/pg-canary/internal/session"
	"testing"
	"time"
)

func TestSessionConfigurationIsTransactionLocal(t *testing.T) {
	if fixtureStack == nil {
		t.Skip("integration disabled")
	}
	ctx, c := context.WithTimeout(context.Background(), 30*time.Second)
	defer c()
	conn := connect(t, ctx, fixtureStack.targets[1].runnerURL)
	defer conn.Close(ctx)
	admin := connect(t, ctx, fixtureStack.targets[1].adminURL)
	defer admin.Close(ctx)
	reset(t, ctx, admin)
	tx, e := conn.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	owner := domain.Identity{Role: "canary_app", Settings: map[string]string{"request.jwt.claim.sub": "owner"}}
	if e = session.Configure(ctx, tx, "secure", owner); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, "INSERT INTO projects (id,tenant_id,name) VALUES (1,'owner','fixture')"); e != nil {
		t.Fatal(e)
	}
	if e = session.Configure(ctx, tx, "secure", domain.Identity{Role: "canary_app", Settings: map[string]string{"request.jwt.claim.sub": "attacker"}}); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM projects").Scan(&count); e != nil {
		t.Fatal(e)
	}
	if count != 0 {
		t.Fatalf("adversary saw %d rows", count)
	}
	if e = tx.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	var role, claim string
	if e = conn.QueryRow(ctx, "SELECT current_user,current_setting('request.jwt.claim.sub',true)").Scan(&role, &claim); e != nil {
		t.Fatal(e)
	}
	if role != "canary_runner" || claim != "" {
		t.Fatalf("context leaked role=%s claim=%q", role, claim)
	}
}
