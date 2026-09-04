// Package harness manages the transactional pg-canary execution lifecycle.
package harness

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
)

type Operation func(context.Context, pgx.Tx) error
type Result struct{ OperationErrors []error }

// Run executes every operation in one outer transaction. Every operation has a
// savepoint; its expected error is recorded and cannot abort subsequent work.
// The outer transaction is always rolled back, and rollback failure is fatal.
func Run(ctx context.Context, conn *pgx.Conn, operations []Operation) (result Result, err error) {
	tx, e := conn.Begin(ctx)
	if e != nil {
		return result, fmt.Errorf("begin outer transaction: %w", e)
	}
	defer func() {
		rollbackErr := tx.Rollback(ctx)
		if rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			err = errors.Join(err, fmt.Errorf("outer rollback failed: %w", rollbackErr))
		}
	}()
	for n, operation := range operations {
		savepoint := fmt.Sprintf("pg_canary_%d", n)
		if _, e = tx.Exec(ctx, "SAVEPOINT "+savepoint); e != nil {
			return result, fmt.Errorf("create savepoint: %w", e)
		}
		operationErr := operation(ctx, tx)
		if operationErr != nil {
			result.OperationErrors = append(result.OperationErrors, operationErr)
			if _, e = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT "+savepoint); e != nil {
				return result, fmt.Errorf("rollback savepoint: %w", e)
			}
		}
		if _, e = tx.Exec(ctx, "RELEASE SAVEPOINT "+savepoint); e != nil {
			return result, fmt.Errorf("release savepoint: %w", e)
		}
	}
	return result, nil
}
