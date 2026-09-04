// Package control proves the owner fixture is observable before attacks run.
package control

import (
	"context"
	"fmt"
	"github.com/avinash-1707/pg-canary/internal/domain"
	"github.com/avinash-1707/pg-canary/internal/sqlsafe"
	"github.com/jackc/pgx/v5"
)

func Verify(ctx context.Context, tx pgx.Tx, schema string, attack domain.Attack, row map[string]any) error {
	s, e := sqlsafe.Select(schema, attack.Table, attack.PrimaryKey, row)
	if e != nil {
		return e
	}
	rows, e := tx.Query(ctx, s.SQL, s.Args...)
	if e != nil {
		return fmt.Errorf("negative control query: %w", e)
	}
	defer rows.Close()
	if !rows.Next() {
		return fmt.Errorf("negative control did not observe owner fixture")
	}
	return rows.Err()
}
