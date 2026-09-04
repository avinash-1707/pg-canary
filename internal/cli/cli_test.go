package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
