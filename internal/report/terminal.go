// Package report renders public pg-canary results.
package report

import (
	"fmt"
	"strings"

	"github.com/avinash-1707/pg-canary/internal/domain"
)

// Terminal returns a concise, credential-free human-readable report.
func Terminal(value domain.Report) string {
	var output strings.Builder
	fmt.Fprintf(&output, "%s: %s\n", value.Outcome, value.Summary)
	if value.Server.Product != "" {
		fmt.Fprintf(&output, "server: %s %s\n", value.Server.Product, value.Server.Version)
	}
	for _, finding := range value.Findings {
		fmt.Fprintf(&output, "preflight [%s] %s: %s\n", finding.Severity, finding.Code, finding.Message)
	}
	for _, evidence := range value.Operations {
		result := "denied"
		if !evidence.Denied {
			result = "exposed"
		}
		fmt.Fprintf(&output, "%s %s: %s", evidence.Table, evidence.Operation, result)
		if evidence.RowsReturned > 0 {
			fmt.Fprintf(&output, " rows_returned=%d", evidence.RowsReturned)
		}
		if evidence.RowsAffected > 0 {
			fmt.Fprintf(&output, " rows_affected=%d", evidence.RowsAffected)
		}
		if evidence.SQLState != "" {
			fmt.Fprintf(&output, " sqlstate=%s", evidence.SQLState)
		}
		output.WriteByte('\n')
	}
	return output.String()
}
