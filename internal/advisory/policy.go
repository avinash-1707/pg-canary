// Package advisory provides non-authoritative policy hints.
package advisory

import (
	"github.com/avinash-1707/pg-canary/internal/catalog"
	"strings"
)

type Finding struct{ Code, Message string }

func Analyze(policy catalog.Policy) []Finding {
	var out []Finding
	if strings.TrimSpace(policy.Using) == "true" {
		out = append(out, Finding{"permissive_using", "USING expression is unconditionally true"})
	}
	if strings.TrimSpace(policy.WithCheck) == "true" {
		out = append(out, Finding{"permissive_with_check", "WITH CHECK expression is unconditionally true"})
	}
	if len(policy.Roles) == 0 {
		out = append(out, Finding{"no_policy_roles", "policy role scope could not be determined"})
	}
	return out
}
