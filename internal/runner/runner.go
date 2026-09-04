// Package runner composes validation-ready components into one safe run.
package runner

import (
	"context"
	"fmt"
	"github.com/avinash-1707/pg-canary/internal/attacks"
	"github.com/avinash-1707/pg-canary/internal/catalog"
	"github.com/avinash-1707/pg-canary/internal/control"
	"github.com/avinash-1707/pg-canary/internal/database"
	"github.com/avinash-1707/pg-canary/internal/domain"
	"github.com/avinash-1707/pg-canary/internal/evaluate"
	"github.com/avinash-1707/pg-canary/internal/preflight"
	"github.com/avinash-1707/pg-canary/internal/seeder"
	"github.com/avinash-1707/pg-canary/internal/session"
)

func Execute(ctx context.Context, p domain.Profile, url string) (report domain.Report, err error) {
	conn, err := database.Open(ctx, database.Config{URL: url})
	if err != nil {
		return report, err
	}
	defer conn.Close(context.Background())
	var login string
	if err = conn.Raw().QueryRow(ctx, "SELECT current_user").Scan(&login); err != nil {
		return report, err
	}
	gate := preflight.Check(ctx, catalog.New(conn.Raw()), p, preflight.Config{AllowWrite: true, LoginRole: login})
	if gate.Outcome != domain.OutcomePass {
		r := domain.NewReport(gate.Outcome, "preflight did not permit execution")
		r.Server = conn.Metadata
		r.Findings = gate.Findings
		return r, nil
	}
	tx, err := conn.Raw().Begin(ctx)
	if err != nil {
		return report, err
	}
	defer func() {
		if rollbackErr := tx.Rollback(context.Background()); rollbackErr != nil {
			err = fmt.Errorf("outer rollback failed: %w", rollbackErr)
		}
	}()
	if err = session.Configure(ctx, tx, p.Database.Schema, p.Identity.Owner); err != nil {
		return report, err
	}
	ownerRows, err := seeder.Seed(ctx, tx, p.Database.Schema, p.Fixtures)
	if err != nil {
		return report, err
	}
	controlOK := true
	var evidence []domain.OperationEvidence
	for _, a := range p.Attacks {
		row := ownerRows.OwnerRows[a.Table]
		if err = session.Configure(ctx, tx, p.Database.Schema, p.Identity.Owner); err != nil {
			return report, err
		}
		if control.Verify(ctx, tx, p.Database.Schema, a, row) != nil {
			controlOK = false
			continue
		}
		if err = session.Configure(ctx, tx, p.Database.Schema, p.Identity.Adversary); err != nil {
			return report, err
		}
		evidence = append(evidence, attacks.Run(ctx, tx, p.Database.Schema, a, row)...)
		for _, op := range a.Operations {
			if op == domain.OperationInsert {
				evidence = append(evidence, attacks.Insert(ctx, tx, p.Database.Schema, a))
			}
		}
	}
	required := []domain.Operation{}
	for _, a := range p.Attacks {
		required = append(required, a.Operations...)
	}
	outcome := evaluate.Outcome(controlOK, gate.Findings, required, evidence)
	r := domain.NewReport(outcome, "attack matrix completed")
	r.Server = conn.Metadata
	r.Findings = gate.Findings
	r.Operations = evidence
	return r, nil
}
