// Package ci converts redacted reports into CI-native artifacts.
package ci

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/avinash-1707/pg-canary/internal/domain"
)

// GitHubAnnotations returns workflow-command annotations without untrusted
// details that could expose a database URL or fixture values.
func GitHubAnnotations(report domain.Report) []string {
	var annotations []string
	for _, finding := range report.Findings {
		level := "notice"
		if finding.Severity == domain.SeverityBlocking || finding.Severity == domain.SeverityInconclusive {
			level = "error"
		}
		annotations = append(annotations, fmt.Sprintf("::%s title=pg-canary %s::%s", level, escape(finding.Code), escape(finding.Message)))
	}
	for _, evidence := range report.Operations {
		if !evidence.Denied {
			annotations = append(annotations, fmt.Sprintf("::error title=pg-canary %s %s::adversary access was observed", escape(evidence.Table), evidence.Operation))
		}
	}
	return annotations
}

// SARIF serializes a minimal SARIF 2.1.0 log for code-scanning consumers.
func SARIF(report domain.Report) ([]byte, error) {
	type result struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
	}
	results := []result{}
	for _, finding := range report.Findings {
		var item result
		item.RuleID = finding.Code
		item.Level = "warning"
		if finding.Severity == domain.SeverityBlocking || finding.Severity == domain.SeverityInconclusive {
			item.Level = "error"
		}
		item.Message.Text = finding.Message
		results = append(results, item)
	}
	for _, evidence := range report.Operations {
		if !evidence.Denied {
			var item result
			item.RuleID = "pg-canary." + string(evidence.Operation)
			item.Level = "error"
			item.Message.Text = "adversary access was observed on " + evidence.Table
			results = append(results, item)
		}
	}
	return json.MarshalIndent(map[string]any{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "pg-canary"}}, "results": results}}}, "", "  ")
}
func escape(value string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(value)
}
