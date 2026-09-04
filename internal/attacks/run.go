package attacks

import (
	"context"
	"errors"
	"github.com/avinash-1707/pg-canary/internal/domain"
	"github.com/avinash-1707/pg-canary/internal/sqlsafe"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"sort"
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
			s, buildErr := sqlsafe.Select(schema, attack.Table, attack.PrimaryKey, row)
			if buildErr != nil {
				e.Error = buildErr.Error()
				break
			}
			e.Template = s.Template
			rows, err := tx.Query(ctx, s.SQL, s.Args...)
			if err != nil {
				e.Error = err.Error()
			} else {
				for rows.Next() {
					e.RowsReturned++
				}
				rows.Close()
				e.Denied = e.RowsReturned == 0
			}
		case domain.OperationDelete:
			s, buildErr := sqlsafe.Delete(schema, attack.Table, attack.PrimaryKey, row)
			if buildErr != nil {
				e.Error = buildErr.Error()
				break
			}
			e.Template = s.Template
			tag, err := tx.Exec(ctx, s.SQL, s.Args...)
			if err != nil {
				e.Error = err.Error()
			} else {
				e.RowsAffected = tag.RowsAffected()
				e.Denied = e.RowsAffected == 0
			}
		case domain.OperationUpdate:
			s, err := sqlsafe.Update(schema, attack.Table, attack.PrimaryKey, row, attack.Mutation)
			if err != nil {
				e.Error = err.Error()
				break
			}
			e.Template = s.Template
			tag, err := tx.Exec(ctx, s.SQL, s.Args...)
			if err != nil {
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

func Insert(ctx context.Context, tx pgx.Tx, schema string, attack domain.Attack) domain.OperationEvidence {
	evidence := domain.OperationEvidence{Table: attack.Table, Operation: domain.OperationInsert}
	columns := make([]string, 0, len(attack.Insert))
	for column := range attack.Insert {
		columns = append(columns, column)
	}
	sort.Strings(columns)
	statement, err := sqlsafe.Insert(schema, attack.Table, attack.Insert, columns)
	if err != nil {
		evidence.Error = err.Error()
		return evidence
	}
	evidence.Template = statement.Template
	started := time.Now()
	tag, err := tx.Exec(ctx, statement.SQL, statement.Args...)
	evidence.DurationMS = time.Since(started).Milliseconds()
	if err == nil {
		evidence.RowsAffected = tag.RowsAffected()
		return evidence
	}
	evidence.Error = err.Error()
	evidence.Denied = true
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		evidence.SQLState = pgErr.Code
		if pgErr.Code != "42501" {
			evidence.Denied = false
		}
	}
	return evidence
}
