//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/avinash-1707/pg-canary/internal/cli"
	"github.com/avinash-1707/pg-canary/internal/domain"
	"gopkg.in/yaml.v3"
)

func TestCLIEndToEndOutcomes(t *testing.T) {
	if fixtureStack == nil {
		t.Skip("integration disabled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	target := fixtureStack.targets[1]

	for _, test := range []struct {
		name    string
		profile domain.Profile
		want    domain.Outcome
	}{
		{name: "secure", profile: e2eProfile("secure", []domain.Operation{domain.OperationSelect, domain.OperationUpdate, domain.OperationDelete, domain.OperationInsert}), want: domain.OutcomePass},
		{name: "read leak", profile: e2eProfile("read_leak", []domain.Operation{domain.OperationSelect}), want: domain.OutcomeFail},
		{name: "owner bypass", profile: e2eProfile("owner_bypass", []domain.Operation{domain.OperationSelect}), want: domain.OutcomeBlocked},
		{name: "missing privilege", profile: e2eProfile("missing_privilege", []domain.Operation{domain.OperationSelect}), want: domain.OutcomeInconclusive},
	} {
		t.Run(test.name, func(t *testing.T) {
			admin := connect(t, ctx, target.adminURL)
			reset(t, ctx, admin)
			admin.Close(ctx)

			profilePath := writeE2EProfile(t, test.profile)
			var stdout bytes.Buffer
			err := cli.Run([]string{"run", "--profile", profilePath, "--db-url", target.runnerURL, "--allow-write", "--json"}, &stdout)
			if test.want == domain.OutcomePass {
				if err != nil {
					t.Fatalf("CLI returned error: %v", err)
				}
			} else {
				var exitError cli.ExitError
				if !errors.As(err, &exitError) {
					t.Fatalf("CLI error = %v, want exit error", err)
				}
			}
			var report domain.Report
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatalf("decode report: %v\n%s", err, stdout.String())
			}
			if report.Outcome != test.want {
				t.Fatalf("outcome = %s, want %s; report=%s", report.Outcome, test.want, stdout.String())
			}
		})
	}
}

func e2eProfile(schema string, operations []domain.Operation) domain.Profile {
	return domain.Profile{
		Version:  1,
		Database: domain.Database{Schema: schema, RequireDisposable: true},
		Identity: domain.Identities{
			Owner:     domain.Identity{Role: "canary_app", Settings: map[string]string{"request.jwt.claim.sub": "owner"}},
			Adversary: domain.Identity{Role: "canary_app", Settings: map[string]string{"request.jwt.claim.sub": "attacker"}},
		},
		Fixtures: []domain.Fixture{{Table: "projects", OwnerRow: map[string]any{"id": 1001, "tenant_id": "owner", "name": "canary-owner"}}},
		Attacks:  []domain.Attack{{Table: "projects", PrimaryKey: []string{"id"}, ProtectedColumns: []string{"tenant_id"}, Operations: operations, Mutation: map[string]any{"tenant_id": "attacker"}, Insert: map[string]any{"id": 1002, "tenant_id": "owner", "name": "canary-adversary"}}},
	}
}

func writeE2EProfile(t *testing.T, profile domain.Profile) string {
	t.Helper()
	contents, err := yaml.Marshal(profile)
	if err != nil {
		t.Fatalf("marshal profile: %v", err)
	}
	path := filepath.Join(t.TempDir(), "profile.yaml")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}
	return path
}
