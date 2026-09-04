package domain

import (
	"encoding/json"
	"regexp"
	"strings"
)

var databaseURLPattern = regexp.MustCompile(`(?i)postgres(?:ql)?://[^\s"']+`)

// MarshalJSON serializes a report while removing connection URLs and every
// fixture value registered in SensitiveValues from user-facing text fields.
func (report Report) MarshalJSON() ([]byte, error) {
	type reportJSON struct {
		SchemaVersion int                 `json:"schema_version"`
		Outcome       Outcome             `json:"outcome"`
		Summary       string              `json:"summary"`
		Server        ServerMetadata      `json:"server"`
		Findings      []PreflightFinding  `json:"findings,omitempty"`
		Operations    []OperationEvidence `json:"operations,omitempty"`
	}

	redact := report.redact
	findings := make([]PreflightFinding, len(report.Findings))
	for index, finding := range report.Findings {
		finding.Target = redact(finding.Target)
		finding.Message = redact(finding.Message)
		finding.Detail = redact(finding.Detail)
		findings[index] = finding
	}
	operations := make([]OperationEvidence, len(report.Operations))
	for index, operation := range report.Operations {
		operation.Table = redact(operation.Table)
		operation.Template = redact(operation.Template)
		operation.Error = redact(operation.Error)
		operations[index] = operation
	}

	return json.Marshal(reportJSON{
		SchemaVersion: report.SchemaVersion,
		Outcome:       report.Outcome,
		Summary:       redact(report.Summary),
		Server: ServerMetadata{
			Product: redact(report.Server.Product),
			Version: redact(report.Server.Version),
		},
		Findings:   findings,
		Operations: operations,
	})
}

func (report Report) redact(value string) string {
	value = databaseURLPattern.ReplaceAllString(value, "[REDACTED_DATABASE_URL]")
	for _, sensitive := range report.SensitiveValues {
		if sensitive != "" {
			value = strings.ReplaceAll(value, sensitive, "[REDACTED]")
		}
	}
	return value
}
