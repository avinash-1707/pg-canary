// Package views inspects and probes security-invoker PostgreSQL views.
package views

import (
	"context"
	"fmt"

	"github.com/avinash-1707/pg-canary/internal/sqlsafe"
	"github.com/jackc/pgx/v5"
)

// SecurityInvoker reports whether view is a PostgreSQL security-invoker view.
func SecurityInvoker(ctx context.Context, conn *pgx.Conn, schema, view string) (bool, error) {
	var enabled bool
	err := conn.QueryRow(ctx, `
SELECT COALESCE('security_invoker=true' = ANY(c.reloptions), false)
FROM pg_class AS c
JOIN pg_namespace AS n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind = 'v'`, schema, view).Scan(&enabled)
	if err != nil {
		return false, fmt.Errorf("inspect view %s.%s: %w", schema, view, err)
	}
	return enabled, nil
}

// Visible returns whether the exact primary-key row is visible through view.
func Visible(ctx context.Context, tx pgx.Tx, schema, view string, primaryKey []string, values map[string]any) (bool, error) {
	statement, err := sqlsafe.Select(schema, view, primaryKey, values)
	if err != nil {
		return false, err
	}
	rows, err := tx.Query(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return false, fmt.Errorf("query security-invoker view: %w", err)
	}
	defer rows.Close()
	return rows.Next(), rows.Err()
}
