// Package preflight enforces the non-mutating safety gate before a run.
package preflight

import (
	"context"
	"github.com/avinash-1707/pg-canary/internal/catalog"
	"github.com/avinash-1707/pg-canary/internal/domain"
)

type Config struct {
	AllowWrite, AcknowledgeEffects bool
	LoginRole                      string
}
type Result struct {
	Findings []domain.PreflightFinding
	Outcome  domain.Outcome
}

func Check(ctx context.Context, inspector catalog.Inspector, profile domain.Profile, config Config) Result {
	r := Result{Outcome: domain.OutcomePass}
	add := func(code string, severity domain.FindingSeverity, target, message string) {
		r.Findings = append(r.Findings, domain.PreflightFinding{Code: code, Severity: severity, Target: target, Message: message})
		if severity == domain.SeverityBlocking {
			r.Outcome = domain.OutcomeBlocked
		} else if severity == domain.SeverityInconclusive && r.Outcome == domain.OutcomePass {
			r.Outcome = domain.OutcomeInconclusive
		}
	}
	if !config.AllowWrite {
		add("allow_write_required", domain.SeverityBlocking, "", "--allow-write is required")
	}
	if !profile.Database.RequireDisposable {
		add("disposable_required", domain.SeverityBlocking, "", "profile must declare a disposable target")
	}
	login, e := inspector.Role(ctx, config.LoginRole)
	if e != nil {
		add("login_role_unknown", domain.SeverityBlocking, config.LoginRole, "login role cannot be inspected")
	} else if login.Superuser || login.BypassRLS {
		add("login_role_bypass", domain.SeverityBlocking, config.LoginRole, "login role bypasses row-level security")
	}
	members, _ := inspector.Memberships(ctx, config.LoginRole)
	member := map[string]bool{}
	for _, m := range members {
		member[m.Role] = true
	}
	for _, identity := range []domain.Identity{profile.Identity.Owner, profile.Identity.Adversary} {
		if !member[identity.Role] && identity.Role != config.LoginRole {
			add("role_not_assumable", domain.SeverityBlocking, identity.Role, "login role cannot assume configured test role")
		}
	}
	for _, attack := range profile.Attacks {
		t, e := inspector.Table(ctx, profile.Database.Schema, attack.Table)
		if e != nil {
			add("table_unavailable", domain.SeverityInconclusive, attack.Table, "table metadata cannot be read")
			continue
		}
		for _, identity := range []domain.Identity{profile.Identity.Owner, profile.Identity.Adversary} {
			if t.Owner == identity.Role && !t.RLSForced {
				add("unforced_owner", domain.SeverityBlocking, attack.Table, "configured role owns an unforced RLS table")
			}
		}
		if len(t.Triggers) > 0 || len(t.Rules) > 0 {
			if !config.AcknowledgeEffects {
				add("external_effect_acknowledgement_required", domain.SeverityBlocking, attack.Table, "triggers or rules require explicit acknowledgement")
			}
		}
		for _, requirement := range requiredPrivileges(attack, profile.Identity.Owner.Role, profile.Identity.Adversary.Role) {
			allowed, privilegeErr := inspector.HasTablePrivilege(ctx, requirement.role, profile.Database.Schema, attack.Table, requirement.privilege)
			if privilegeErr != nil || !allowed {
				add("missing_privilege", domain.SeverityInconclusive, attack.Table, requirement.role+" lacks "+requirement.privilege+" privilege")
			}
		}
	}
	return r
}

type privilegeRequirement struct{ role, privilege string }

func requiredPrivileges(attack domain.Attack, ownerRole, adversaryRole string) []privilegeRequirement {
	requirements := []privilegeRequirement{{role: ownerRole, privilege: "INSERT"}, {role: ownerRole, privilege: "SELECT"}}
	for _, operation := range attack.Operations {
		switch operation {
		case domain.OperationSelect:
			requirements = append(requirements, privilegeRequirement{role: adversaryRole, privilege: "SELECT"})
		case domain.OperationUpdate:
			requirements = append(requirements, privilegeRequirement{role: adversaryRole, privilege: "UPDATE"})
		case domain.OperationDelete:
			requirements = append(requirements, privilegeRequirement{role: adversaryRole, privilege: "DELETE"})
		case domain.OperationInsert:
			requirements = append(requirements, privilegeRequirement{role: adversaryRole, privilege: "INSERT"})
		}
	}
	return requirements
}
