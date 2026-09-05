//go:build integration

package integration

import (
	"context"
	"github.com/avinash-1707/pg-canary/internal/functions"
	"testing"
	"time"
)

func TestSecurityDefinerInspection(t *testing.T) {
	if fixtureStack == nil {
		t.Skip("integration disabled")
	}
	ctx, c := context.WithTimeout(context.Background(), 30*time.Second)
	defer c()
	conn := connect(t, ctx, fixtureStack.targets[1].adminURL)
	defer conn.Close(ctx)
	reset(t, ctx, conn)
	d, e := functions.Inspect(ctx, conn, "secure", "definer_project_count")
	if e != nil || !d.SecurityDefiner || !d.SafeSearchPath || d.Owner != "canary_table_owner" {
		t.Fatalf("definition=%+v err=%v", d, e)
	}
}
