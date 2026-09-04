// pg-canary verifies configured PostgreSQL row-level-security invariants.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/avinash-1707/pg-canary/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		var exitError cli.ExitError
		if errors.As(err, &exitError) {
			os.Exit(exitError.Code)
		}
		os.Exit(2)
	}
}
