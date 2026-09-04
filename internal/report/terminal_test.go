package report

import (
	"strings"
	"testing"

	"github.com/avinash-1707/pg-canary/internal/domain"
)

func TestTerminalIsConciseAndDoesNotExposeSensitiveValues(t *testing.T) {
	t.Parallel()
	value := domain.NewReport(domain.OutcomeFail, "attack matrix completed")
	value.Server = domain.ServerMetadata{Product: "PostgreSQL", Version: "17"}
	value.Operations = []domain.OperationEvidence{{Table: "projects", Operation: domain.OperationSelect, RowsReturned: 1}}
	output := Terminal(value)
	for _, expected := range []string{"fail: attack matrix completed", "server: PostgreSQL 17", "projects select: exposed rows_returned=1"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("terminal output missing %q: %s", expected, output)
		}
	}
}
