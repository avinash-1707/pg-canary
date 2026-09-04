package domain

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportJSONGoldensRedactSecrets(t *testing.T) {
	t.Parallel()

	for _, outcome := range []Outcome{OutcomePass, OutcomeFail, OutcomeInconclusive, OutcomeBlocked} {
		t.Run(string(outcome), func(t *testing.T) {
			t.Parallel()
			report := NewReport(outcome, string(outcome)+" summary: postgres://runner:secret@db.example/test fixture-secret")
			report.Server = ServerMetadata{Product: "PostgreSQL", Version: "17.4"}
			report.Findings = []PreflightFinding{{Code: "example", Severity: SeverityInfo, Message: "fixture-secret"}}
			report.Operations = []OperationEvidence{{
				Table:      "projects",
				Operation:  OperationSelect,
				Denied:     true,
				DurationMS: 1,
				Template:   "SELECT * FROM projects WHERE tenant = 'fixture-secret'",
			}}
			report.SensitiveValues = []string{"fixture-secret"}

			encoded, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				t.Fatalf("marshal report: %v", err)
			}
			if string(encoded) == "" || containsSecret(string(encoded)) {
				t.Fatalf("report exposes sensitive content: %s", encoded)
			}

			goldenPath := filepath.Join("testdata", string(outcome)+".golden.json")
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if string(encoded)+"\n" != string(want) {
				t.Fatalf("report JSON differs from %s\nwant:\n%s\ngot:\n%s", goldenPath, want, encoded)
			}
		})
	}
}

func TestOutcomeExitCodes(t *testing.T) {
	t.Parallel()

	if OutcomePass.ExitCode() != 0 {
		t.Fatal("pass must exit zero")
	}
	if OutcomeFail.ExitCode() != 1 {
		t.Fatal("fail must exit one")
	}
	for _, outcome := range []Outcome{OutcomeInconclusive, OutcomeBlocked} {
		if outcome.ExitCode() != 2 {
			t.Fatalf("%s must exit two", outcome)
		}
	}
}

func containsSecret(value string) bool {
	return strings.Contains(value, "postgres://") ||
		strings.Contains(value, "fixture-secret") ||
		strings.Contains(value, "runner:secret")
}
