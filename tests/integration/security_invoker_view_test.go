//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/avinash-1707/pg-canary/internal/domain"
	"github.com/avinash-1707/pg-canary/internal/session"
	"github.com/avinash-1707/pg-canary/internal/views"
)

func TestSecurityInvokerViewAppliesCallerRLS(t *testing.T) {
	if fixtureStack == nil {
		t.Skip("integration disabled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin := connect(t, ctx, fixtureStack.targets[1].adminURL)
	defer admin.Close(ctx)
	reset(t, ctx, admin)

	enabled, err := views.SecurityInvoker(ctx, admin, "secure", "projects_invoker")
	if err != nil || !enabled {
		t.Fatalf("security-invoker metadata = %t, %v", enabled, err)
	}
	runner := connect(t, ctx, fixtureStack.targets[1].runnerURL)
	defer runner.Close(ctx)
	tx, err := runner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	owner := domain.Identity{Role: "canary_app", Settings: map[string]string{"request.jwt.claim.sub": "owner"}}
	if err := session.Configure(ctx, tx, "secure", owner); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "INSERT INTO projects (id, tenant_id, name) VALUES (9001, 'owner', 'view-fixture')"); err != nil {
		t.Fatal(err)
	}
	if err := session.Configure(ctx, tx, "secure", domain.Identity{Role: "canary_app", Settings: map[string]string{"request.jwt.claim.sub": "attacker"}}); err != nil {
		t.Fatal(err)
	}
	visible, err := views.Visible(ctx, tx, "secure", "projects_invoker", []string{"id"}, map[string]any{"id": int64(9001)})
	if err != nil {
		t.Fatal(err)
	}
	if visible {
		t.Fatal("adversary observed owner row through security-invoker view")
	}
}
