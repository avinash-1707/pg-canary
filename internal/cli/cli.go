// Package cli owns command parsing and command-specific presentation.
package cli

import (
	"fmt"
	"io"
)

const usage = `pg-canary verifies configured PostgreSQL row-level-security invariants.

Usage:
  pg-canary [command]

Commands:
  help    Show this help message

Run "pg-canary help" for usage information.
`

// Run executes the command selected by args and writes normal output to stdout.
func Run(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		_, err := fmt.Fprint(stdout, usage)
		return err
	}

	return fmt.Errorf("pg-canary: unknown command %q (run \"pg-canary --help\" for usage)", args[0])
}
