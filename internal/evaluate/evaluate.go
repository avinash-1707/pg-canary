package evaluate

import "github.com/avinash-1707/pg-canary/internal/domain"

func Outcome(controlOK bool, findings []domain.PreflightFinding, required []domain.Operation, evidence []domain.OperationEvidence) domain.Outcome {
	for _, f := range findings {
		if f.Severity == domain.SeverityBlocking {
			return domain.OutcomeBlocked
		}
	}
	if !controlOK {
		return domain.OutcomeInconclusive
	}
	for _, f := range findings {
		if f.Severity == domain.SeverityInconclusive {
			return domain.OutcomeInconclusive
		}
	}
	if len(evidence) == 0 {
		return domain.OutcomeInconclusive
	}
	seen := map[domain.Operation]bool{}
	for _, evidence := range evidence {
		seen[evidence.Operation] = true
	}
	for _, operation := range required {
		if !seen[operation] {
			return domain.OutcomeInconclusive
		}
	}
	for _, e := range evidence {
		if e.Error != "" && !e.Denied {
			return domain.OutcomeInconclusive
		}
	}
	for _, e := range evidence {
		if !e.Denied {
			return domain.OutcomeFail
		}
	}
	return domain.OutcomePass
}
