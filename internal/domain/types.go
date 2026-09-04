// Package domain contains the stable data contracts shared by pg-canary.
package domain

import (
	"fmt"
	"strings"
)

// Outcome is the public verdict for a pg-canary run.
type Outcome string

const (
	OutcomePass         Outcome = "pass"
	OutcomeFail         Outcome = "fail"
	OutcomeInconclusive Outcome = "inconclusive"
	OutcomeBlocked      Outcome = "blocked"
)

// Valid reports whether outcome is part of the public result contract.
func (outcome Outcome) Valid() bool {
	switch outcome {
	case OutcomePass, OutcomeFail, OutcomeInconclusive, OutcomeBlocked:
		return true
	default:
		return false
	}
}

// ExitCode maps an outcome to its CI process exit code.
func (outcome Outcome) ExitCode() int {
	if outcome == OutcomePass {
		return 0
	}
	return 1
}

// Database declares the database-level safety properties required by a profile.
type Database struct {
	Schema            string `yaml:"schema" json:"schema"`
	RequireDisposable bool   `yaml:"require_disposable" json:"require_disposable"`
}

// Identity configures a role and transaction-local session settings.
type Identity struct {
	Role     string            `yaml:"role" json:"role"`
	Settings map[string]string `yaml:"settings,omitempty" json:"settings,omitempty"`
}

// Identities holds the owner and adversary contexts for a profile.
type Identities struct {
	Owner     Identity `yaml:"owner" json:"owner"`
	Adversary Identity `yaml:"adversary" json:"adversary"`
}

// Fixture is a synthetic row used during a test run.
type Fixture struct {
	Table            string         `yaml:"table" json:"table"`
	OwnerRow         map[string]any `yaml:"owner_row" json:"owner_row"`
	SensitiveColumns []string       `yaml:"sensitive_columns,omitempty" json:"sensitive_columns,omitempty"`
}

// Operation is an adversarial database operation supported by v1.
type Operation string

const (
	OperationSelect Operation = "select"
	OperationUpdate Operation = "update"
	OperationDelete Operation = "delete"
	OperationInsert Operation = "insert"
)

// Valid reports whether operation is supported by the v1 attack matrix.
func (operation Operation) Valid() bool {
	switch operation {
	case OperationSelect, OperationUpdate, OperationDelete, OperationInsert:
		return true
	default:
		return false
	}
}

// Attack declares the protected row and operations to attempt against it.
type Attack struct {
	Table            string         `yaml:"table" json:"table"`
	PrimaryKey       []string       `yaml:"primary_key" json:"primary_key"`
	ProtectedColumns []string       `yaml:"protected_columns,omitempty" json:"protected_columns,omitempty"`
	Operations       []Operation    `yaml:"operations" json:"operations"`
	Mutation         map[string]any `yaml:"mutation,omitempty" json:"mutation,omitempty"`
	Insert           map[string]any `yaml:"insert,omitempty" json:"insert,omitempty"`
}

// Profile is the versioned input contract for pg-canary.
type Profile struct {
	Version  int        `yaml:"version" json:"version"`
	Database Database   `yaml:"database" json:"database"`
	Identity Identities `yaml:"identity" json:"identity"`
	Fixtures []Fixture  `yaml:"fixtures" json:"fixtures"`
	Attacks  []Attack   `yaml:"attacks" json:"attacks"`
}

// FindingSeverity describes the effect a preflight finding has on a run.
type FindingSeverity string

const (
	SeverityInfo         FindingSeverity = "info"
	SeverityWarning      FindingSeverity = "warning"
	SeverityInconclusive FindingSeverity = "inconclusive"
	SeverityBlocking     FindingSeverity = "blocked"
)

// PreflightFinding records a catalog or safety-gate observation.
type PreflightFinding struct {
	Code     string          `json:"code"`
	Severity FindingSeverity `json:"severity"`
	Target   string          `json:"target,omitempty"`
	Message  string          `json:"message"`
	Detail   string          `json:"detail,omitempty"`
}

// OperationEvidence records the observable outcome of one adversarial query.
type OperationEvidence struct {
	Table        string    `json:"table"`
	Operation    Operation `json:"operation"`
	Denied       bool      `json:"denied"`
	RowsAffected int64     `json:"rows_affected,omitempty"`
	RowsReturned int64     `json:"rows_returned,omitempty"`
	SQLState     string    `json:"sqlstate,omitempty"`
	DurationMS   int64     `json:"duration_ms"`
	Template     string    `json:"template"`
	Error        string    `json:"error,omitempty"`
}

// ServerMetadata contains only non-secret target information.
type ServerMetadata struct {
	Product string `json:"product"`
	Version string `json:"version"`
}

// ReportSchemaVersion is the current stable JSON report schema version.
const ReportSchemaVersion = 1

// Report is the versioned, public result document. SensitiveValues is used
// only during serialization and is never emitted.
type Report struct {
	SchemaVersion   int                 `json:"schema_version"`
	Outcome         Outcome             `json:"outcome"`
	Summary         string              `json:"summary"`
	Server          ServerMetadata      `json:"server"`
	Findings        []PreflightFinding  `json:"findings,omitempty"`
	Operations      []OperationEvidence `json:"operations,omitempty"`
	SensitiveValues []string            `json:"-"`
}

// NewReport creates a report with the current schema version.
func NewReport(outcome Outcome, summary string) Report {
	return Report{SchemaVersion: ReportSchemaVersion, Outcome: outcome, Summary: summary}
}

// Validate ensures the public report can be interpreted by CI consumers.
func (report Report) Validate() error {
	if report.SchemaVersion != ReportSchemaVersion {
		return fmt.Errorf("unsupported report schema version %d", report.SchemaVersion)
	}
	if !report.Outcome.Valid() {
		return fmt.Errorf("invalid outcome %q", report.Outcome)
	}
	if strings.TrimSpace(report.Summary) == "" {
		return fmt.Errorf("report summary is required")
	}
	return nil
}
