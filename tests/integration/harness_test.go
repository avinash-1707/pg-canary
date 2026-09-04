//go:build integration

package integration

import (
	"context"
	"errors"
	"github.com/avinash-1707/pg-canary/internal/harness"
	"github.com/jackc/pgx/v5"
	"testing"
	"time"
)

func TestHarnessSavepointsAndOuterRollback(t *testing.T) {
	if fixtureStack == nil {
		t.Skip("integration disabled")
	}
	ctx, c := context.WithTimeout(context.Background(), 30*time.Second)
	defer c()
	conn := connect(t, ctx, fixtureStack.targets[1].adminURL)
	defer conn.Close(ctx)
	reset(t, ctx, conn)
	result, e := harness.Run(ctx, conn, []harness.Operation{func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, "INSERT INTO secure.projects (id,tenant_id,name) VALUES (1,'owner','first')")
		return e
	}, func(context.Context, pgx.Tx) error { return errors.New("expected denial") }, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, "INSERT INTO secure.projects (id,tenant_id,name) VALUES (2,'owner','later')")
		return e
	}})
	if e != nil {
		t.Fatal(e)
	}
	if len(result.OperationErrors) != 1 {
		t.Fatalf("errors=%v", result.OperationErrors)
	}
	var count int
	if e := conn.QueryRow(ctx, "SELECT count(*) FROM secure.projects").Scan(&count); e != nil {
		t.Fatal(e)
	}
	if count != 0 {
		t.Fatalf("outer rollback left %d rows", count)
	}
}
