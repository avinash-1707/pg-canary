//go:build integration

package integration

import (
	"context"
	"github.com/avinash-1707/pg-canary/internal/catalog"
	"testing"
	"time"
)

func TestCatalogInspectorMatchesFixtures(t *testing.T) {
	if fixtureStack == nil {
		t.Skip("integration disabled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, target := range fixtureStack.targets {
		if target.major < 15 {
			continue
		}
		t.Run(target.service, func(t *testing.T) {
			conn := connect(t, ctx, target.adminURL)
			defer conn.Close(ctx)
			reset(t, ctx, conn)
			inspector := catalog.New(conn)
			secure, e := inspector.Table(ctx, "secure", "projects")
			if e != nil {
				t.Fatal(e)
			}
			if !secure.RLSEnabled || !secure.RLSForced || secure.Owner != "canary_table_owner" || len(secure.PrimaryKey) != 1 || secure.PrimaryKey[0] != "id" || len(secure.Policies) != 1 {
				t.Fatalf("unexpected secure metadata: %+v", secure)
			}
			owner, e := inspector.Table(ctx, "owner_bypass", "projects")
			if e != nil {
				t.Fatal(e)
			}
			if owner.RLSForced || owner.Owner != "canary_app" {
				t.Fatalf("unexpected owner fixture: %+v", owner)
			}
			role, e := inspector.Role(ctx, "canary_runner")
			if e != nil {
				t.Fatal(e)
			}
			if role.Superuser || role.BypassRLS || !role.CanLogin {
				t.Fatalf("unexpected runner: %+v", role)
			}
			members, e := inspector.Memberships(ctx, "canary_runner")
			if e != nil || len(members) != 1 || members[0].Role != "canary_app" {
				t.Fatalf("unexpected membership: %v %+v", e, members)
			}
		})
	}
}
