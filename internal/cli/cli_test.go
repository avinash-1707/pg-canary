package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avinash-1707/pg-canary/internal/domain"
)

func TestRunHelp(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	if err := Run([]string{"--help"}, &stdout); err != nil {
		t.Fatalf("Run(--help) returned an error: %v", err)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("help output does not contain usage: %q", stdout.String())
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	err := Run([]string{"unknown"}, &stdout)
	if err == nil {
		t.Fatal("Run(unknown) returned nil error")
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunValidate(t *testing.T) {
	t.Parallel()

	profilePath := filepath.Join(t.TempDir(), "profile.yaml")
	contents := `version: 1
database:
  schema: public
  require_disposable: true
identity:
  owner:
    role: owner_role
  adversary:
    role: adversary_role
fixtures:
  - table: projects
    owner_row:
      id: 1
attacks:
  - table: projects
    primary_key: [id]
    operations: [select]
`
	if err := os.WriteFile(profilePath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}
	var stdout bytes.Buffer
	if err := Run([]string{"validate", "--profile", profilePath}, &stdout); err != nil {
		t.Fatalf("Run(validate) returned an error: %v", err)
	}
	if got := stdout.String(); got != "profile is valid\n" {
		t.Fatalf("validate output = %q", got)
	}
}

func TestRunProfileJSONRedactsURLAndWritesOutput(t *testing.T) {
	t.Parallel()

	profilePath := writeValidProfile(t)
	outputPath := filepath.Join(t.TempDir(), "report.json")
	var stdout bytes.Buffer
	err := run([]string{
		"run", "--profile", profilePath, "--db-url", "postgres://runner:password@db.example/test",
		"--allow-write", "--json", "--output", outputPath,
	}, &stdout, func(_ context.Context, _ domain.Profile, _ RunOptions) (domain.Report, error) {
		report := domain.NewReport(domain.OutcomePass, "connected to postgres://runner:password@db.example/test")
		return report, nil
	})
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if strings.Contains(stdout.String(), "runner:password") || strings.Contains(stdout.String(), "postgres://") {
		t.Fatalf("JSON output exposes database credentials: %s", stdout.String())
	}
	written, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if string(written) != stdout.String() {
		t.Fatal("output file differs from stdout")
	}
}

func TestRunProfileRequiresExplicitEnvironmentOptIn(t *testing.T) {
	profilePath := writeValidProfile(t)
	t.Setenv("PG_CANARY_TEST_URL", "postgres://runner:password@db.example/test")

	var stdout bytes.Buffer
	err := run([]string{"run", "--profile", profilePath, "--allow-write"}, &stdout, unavailableExecutor)
	if err == nil || !strings.Contains(err.Error(), "--db-url is required") {
		t.Fatalf("run without URL error = %v", err)
	}
	err = run([]string{"run", "--profile", profilePath, "--db-url-env", "PG_CANARY_TEST_URL", "--allow-write"}, &stdout, func(_ context.Context, _ domain.Profile, options RunOptions) (domain.Report, error) {
		if options.DatabaseURL == "" {
			t.Fatal("environment URL was not passed to executor")
		}
		return domain.NewReport(domain.OutcomePass, "ok"), nil
	})
	if err != nil {
		t.Fatalf("run with explicit environment opt-in error = %v", err)
	}
}

func TestRunProfileRedactsExecutorErrors(t *testing.T) {
	t.Parallel()

	profilePath := writeValidProfile(t)
	var stdout bytes.Buffer
	err := run([]string{"run", "--profile", profilePath, "--db-url", "postgres://runner:password@db.example/test", "--allow-write"}, &stdout, func(context.Context, domain.Profile, RunOptions) (domain.Report, error) {
		return domain.Report{}, errors.New("failed postgres://runner:password@db.example/test")
	})
	if err == nil || strings.Contains(err.Error(), "runner:password") || strings.Contains(err.Error(), "postgres://") {
		t.Fatalf("executor error exposes URL: %v", err)
	}
}

func writeValidProfile(t *testing.T) string {
	t.Helper()
	profilePath := filepath.Join(t.TempDir(), "profile.yaml")
	contents := `version: 1
database:
  schema: public
  require_disposable: true
identity:
  owner:
    role: owner_role
  adversary:
    role: adversary_role
fixtures:
  - table: projects
    owner_row:
      id: 1
attacks:
  - table: projects
    primary_key: [id]
    operations: [select]
`
	if err := os.WriteFile(profilePath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}
	return profilePath
}
