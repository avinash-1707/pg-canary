package attacks

import (
	"context"
	"github.com/avinash-1707/pg-canary/internal/domain"
	"github.com/avinash-1707/pg-canary/internal/sqlsafe"
	"github.com/jackc/pgx/v5"
	"time"
)

func Run(ctx context.Context, tx pgx.Tx, schema string, attack domain.Attack, row map[string]any) []domain.OperationEvidence {
	var out []domain.OperationEvidence
	for _, op := range attack.Operations {
		if op == domain.OperationInsert {
			continue
		}
		started := time.Now()
		e := domain.OperationEvidence{Table: attack.Table, Operation: op, DurationMS: 0}
		switch op {
		case domain.OperationSelect:
			s, _ := sqlsafe.Select(schema, attack.Table, attack.PrimaryKey, row)
			e.Template = s.Template
			rows, err := tx.Query(ctx, s.SQL, s.Args...)
			if err != nil {
				e.Denied = true
				e.Error = err.Error()
			} else {
				for rows.Next() {
					e.RowsReturned++
				}
				rows.Close()
				e.Denied = e.RowsReturned == 0
			}
		case domain.OperationDelete:
			s, _ := sqlsafe.Delete(schema, attack.Table, attack.PrimaryKey, row)
			e.Template = s.Template
			tag, err := tx.Exec(ctx, s.SQL, s.Args...)
			if err != nil {
				e.Denied = true
				e.Error = err.Error()
			} else {
				e.RowsAffected = tag.RowsAffected()
				e.Denied = e.RowsAffected == 0
			}
		case domain.OperationUpdate:
			s, err := sqlsafe.Update(schema, attack.Table, attack.PrimaryKey, row, attack.Mutation)
			if err != nil {
				e.Denied = true
				e.Error = err.Error()
				break
			}
			e.Template = s.Template
			tag, err := tx.Exec(ctx, s.SQL, s.Args...)
			if err != nil {
				e.Denied = true
				e.Error = err.Error()
			} else {
				e.RowsAffected = tag.RowsAffected()
				e.Denied = e.RowsAffected == 0
			}
		}
		e.DurationMS = time.Since(started).Milliseconds()
		out = append(out, e)
	}
	return out
}
