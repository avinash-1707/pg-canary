// pg-canary verifies configured PostgreSQL row-level-security invariants.
package main

import (
	"fmt"
	"os"

	"github.com/avinash-1707/pg-canary/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
