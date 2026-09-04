package evaluate

import (
	"github.com/avinash-1707/pg-canary/internal/domain"
	"testing"
)

func TestOutcomePrecedence(t *testing.T) {
	e := []domain.OperationEvidence{{Denied: false}}
	if Outcome(true, []domain.PreflightFinding{{Severity: domain.SeverityBlocking}}, e) != domain.OutcomeBlocked {
		t.Fatal("blocked")
	}
	if Outcome(false, nil, e) != domain.OutcomeInconclusive {
		t.Fatal("inconclusive")
	}
	if Outcome(true, nil, e) != domain.OutcomeFail {
		t.Fatal("fail")
	}
	if Outcome(true, nil, []domain.OperationEvidence{{Denied: true}}) != domain.OutcomePass {
		t.Fatal("pass")
	}
}
