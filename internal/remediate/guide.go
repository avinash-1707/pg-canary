// Package remediate maps evidence to concise next steps.
package remediate

import "github.com/avinash-1707/pg-canary/internal/domain"

func Guidance(report domain.Report) []string {
	var out []string
	for _, f := range report.Findings {
		switch f.Code {
		case "login_role_bypass", "unforced_owner":
			out = append(out, "Use a non-superuser, non-BYPASSRLS test role and force RLS for owner access paths.")
		case "missing_privilege":
			out = append(out, "Grant only the required table privilege, then rerun to distinguish privilege failures from RLS denials.")
		}
	}
	for _, e := range report.Operations {
		if !e.Denied {
			out = append(out, "Review the applicable RLS policy and add a tenant predicate for "+e.Table+" "+string(e.Operation)+".")
		}
	}
	return out
}
