package ci

import (
	"github.com/avinash-1707/pg-canary/internal/domain"
	"strings"
	"testing"
)

func TestArtifactsAreRedactedAndActionable(t *testing.T) {
	r := domain.NewReport(domain.OutcomeFail, "x")
	r.Findings = []domain.PreflightFinding{{Code: "blocked", Severity: domain.SeverityBlocking, Message: "unsafe"}}
	r.Operations = []domain.OperationEvidence{{Table: "projects", Operation: domain.OperationSelect, Denied: false}}
	a := GitHubAnnotations(r)
	if len(a) != 2 || !strings.Contains(a[0], "::error") {
		t.Fatalf("annotations=%v", a)
	}
	s, e := SARIF(r)
	if e != nil || !strings.Contains(string(s), "pg-canary.select") {
		t.Fatalf("sarif=%s err=%v", s, e)
	}
}
