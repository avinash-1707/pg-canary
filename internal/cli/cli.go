// Package cli owns command parsing and command-specific presentation.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/avinash-1707/pg-canary/internal/domain"
	"github.com/avinash-1707/pg-canary/internal/profile"
	"github.com/avinash-1707/pg-canary/internal/runner"
)

const usage = `pg-canary verifies configured PostgreSQL row-level-security invariants.

Usage:
  pg-canary [command]

Commands:
  help    Show this help message
  validate Validate a YAML profile without connecting to a database
  run     Run a profile against an explicitly approved database

Run "pg-canary help" for usage information.
`

// Run executes the command selected by args and writes normal output to stdout.
// ExitError carries a deliberate command exit code without exposing internal
// implementation errors to shell callers.
type ExitError struct {
	Code int
	err  error
}

func (exitError ExitError) Error() string { return exitError.err.Error() }
func (exitError ExitError) Unwrap() error { return exitError.err }

// RunOptions are the public run-command inputs after flag parsing.
type RunOptions struct {
	ProfilePath string
	DatabaseURL string
	AllowWrite  bool
	JSON        bool
	OutputPath  string
}

// Executor runs a validated profile. The concrete database executor is wired
// in by the connection and harness units; keeping it injectable makes the CLI
// contract independently testable.
type Executor func(context.Context, domain.Profile, RunOptions) (domain.Report, error)

// Run executes a command using the default executor.
func Run(args []string, stdout io.Writer) error {
	return run(args, stdout, unavailableExecutor)
}

func run(args []string, stdout io.Writer, executor Executor) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		_, err := fmt.Fprint(stdout, usage)
		return err
	}
	if args[0] == "validate" {
		return validate(args[1:], stdout)
	}
	if args[0] == "run" {
		return runProfile(args[1:], stdout, executor)
	}

	return fmt.Errorf("pg-canary: unknown command %q (run \"pg-canary --help\" for usage)", args[0])
}

func validate(args []string, stdout io.Writer) error {
	if len(args) != 2 || args[0] != "--profile" || strings.TrimSpace(args[1]) == "" {
		return fmt.Errorf("usage: pg-canary validate --profile FILE")
	}
	if _, err := profile.LoadFile(args[1]); err != nil {
		return err
	}
	_, err := fmt.Fprintln(stdout, "profile is valid")
	return err
}

func runProfile(args []string, stdout io.Writer, executor Executor) error {
	options, err := parseRunOptions(args)
	if err != nil {
		return err
	}
	profileValue, err := profile.LoadFile(options.ProfilePath)
	if err != nil {
		return err
	}
	report, err := executor(context.Background(), profileValue, options)
	if err != nil {
		return ExitError{Code: 2, err: fmt.Errorf("run failed: %s", redactDatabaseURLs(err.Error()))}
	}
	report.SensitiveValues = append(report.SensitiveValues, profileSensitiveValues(profileValue)...)
	if err := report.Validate(); err != nil {
		return ExitError{Code: 2, err: fmt.Errorf("invalid execution report: %w", err)}
	}
	encoded, err := formatReport(report, options.JSON)
	if err != nil {
		return ExitError{Code: 2, err: fmt.Errorf("render report: %w", err)}
	}
	if options.OutputPath != "" {
		if err := os.WriteFile(options.OutputPath, encoded, 0o600); err != nil {
			return ExitError{Code: 2, err: fmt.Errorf("write output: %w", err)}
		}
	}
	if _, err := stdout.Write(encoded); err != nil {
		return err
	}
	if report.Outcome.ExitCode() != 0 {
		return ExitError{Code: report.Outcome.ExitCode(), err: errors.New("pg-canary did not pass")}
	}
	return nil
}

func parseRunOptions(args []string) (RunOptions, error) {
	var options RunOptions
	var databaseURLEnvironment string
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--profile", "--db-url", "--db-url-env", "--output":
			if index+1 == len(args) {
				return RunOptions{}, fmt.Errorf("%s requires a value", args[index])
			}
			value := args[index+1]
			index++
			switch args[index-1] {
			case "--profile":
				options.ProfilePath = value
			case "--db-url":
				options.DatabaseURL = value
			case "--db-url-env":
				databaseURLEnvironment = value
			case "--output":
				options.OutputPath = value
			}
		case "--allow-write":
			options.AllowWrite = true
		case "--json":
			options.JSON = true
		default:
			return RunOptions{}, fmt.Errorf("unknown run flag %q", args[index])
		}
	}
	if strings.TrimSpace(options.ProfilePath) == "" {
		return RunOptions{}, errors.New("--profile is required")
	}
	if options.DatabaseURL != "" && databaseURLEnvironment != "" {
		return RunOptions{}, errors.New("--db-url and --db-url-env cannot be used together")
	}
	if databaseURLEnvironment != "" {
		value, exists := os.LookupEnv(databaseURLEnvironment)
		if !exists || strings.TrimSpace(value) == "" {
			return RunOptions{}, fmt.Errorf("database URL environment variable %q is not set", databaseURLEnvironment)
		}
		options.DatabaseURL = value
	}
	if options.DatabaseURL == "" {
		return RunOptions{}, errors.New("--db-url is required (or explicitly use --db-url-env NAME)")
	}
	if !options.AllowWrite {
		return RunOptions{}, errors.New("--allow-write is required")
	}
	return options, nil
}

func unavailableExecutor(ctx context.Context, profile domain.Profile, options RunOptions) (domain.Report, error) {
	return runner.Execute(ctx, profile, options.DatabaseURL)
}

func formatReport(report domain.Report, asJSON bool) ([]byte, error) {
	if asJSON {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(encoded, '\n'), nil
	}
	return []byte(fmt.Sprintf("%s: %s\n", report.Outcome, report.Summary)), nil
}

func profileSensitiveValues(profileValue domain.Profile) []string {
	var values []string
	for _, fixture := range profileValue.Fixtures {
		for _, column := range fixture.SensitiveColumns {
			if value, exists := fixture.OwnerRow[column]; exists {
				values = append(values, fmt.Sprint(value))
			}
		}
	}
	return values
}

var databaseURLPattern = regexp.MustCompile(`(?i)postgres(?:ql)?://[^\s"']+`)

func redactDatabaseURLs(value string) string {
	return databaseURLPattern.ReplaceAllString(value, "[REDACTED_DATABASE_URL]")
}
