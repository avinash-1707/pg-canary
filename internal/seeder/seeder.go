// Package seeder inserts only explicit synthetic profile fixtures.
package seeder

import (
	"context"
	"fmt"
	"github.com/avinash-1707/pg-canary/internal/domain"
	"github.com/avinash-1707/pg-canary/internal/sqlsafe"
	"github.com/jackc/pgx/v5"
	"sort"
)

type Result struct{ OwnerRows map[string]map[string]any }

// Seed preserves profile fixture order, which is the explicit dependency order
// for v1; it never attempts relational inference.
func Seed(ctx context.Context, tx pgx.Tx, schema string, fixtures []domain.Fixture) (Result, error) {
	r := Result{OwnerRows: map[string]map[string]any{}}
	for _, f := range fixtures {
		columns := make([]string, 0, len(f.OwnerRow))
		for c := range f.OwnerRow {
			columns = append(columns, c)
		}
		sort.Strings(columns)
		s, e := sqlsafe.Insert(schema, f.Table, f.OwnerRow, columns)
		if e != nil {
			return r, e
		}
		if _, e = tx.Exec(ctx, s.SQL, s.Args...); e != nil {
			return r, fmt.Errorf("seed %s: %w", f.Table, e)
		}
		r.OwnerRows[f.Table] = f.OwnerRow
	}
	return r, nil
}
