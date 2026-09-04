// Package session configures transaction-local PostgreSQL identity context.
package session

import (
	"context"
	"fmt"
	"github.com/avinash-1707/pg-canary/internal/domain"
	"github.com/avinash-1707/pg-canary/internal/sqlsafe"
	"github.com/jackc/pgx/v5"
	"sort"
)

func Configure(ctx context.Context, tx pgx.Tx, schema string, identity domain.Identity) error {
	quotedSchema, e := sqlsafe.Identifier(schema)
	if e != nil {
		return e
	}
	quotedRole, e := sqlsafe.Identifier(identity.Role)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "SET LOCAL search_path = "+quotedSchema+", pg_catalog"); e != nil {
		return fmt.Errorf("set search path: %w", e)
	}
	if _, e = tx.Exec(ctx, "SET LOCAL ROLE "+quotedRole); e != nil {
		return fmt.Errorf("set role: %w", e)
	}
	names := make([]string, 0, len(identity.Settings))
	for n := range identity.Settings {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if _, e = tx.Exec(ctx, "SELECT set_config($1,$2,true)", n, identity.Settings[n]); e != nil {
			return fmt.Errorf("set %s: %w", n, e)
		}
	}
	return nil
}
