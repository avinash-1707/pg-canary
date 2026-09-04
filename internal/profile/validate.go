package profile

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/avinash-1707/pg-canary/internal/domain"
)

// SupportedVersion is the only profile version accepted by v1.
const SupportedVersion = 1

// Diagnostic is one stable, user-actionable validation failure.
type Diagnostic struct {
	Path    string
	Message string
}

func (diagnostic Diagnostic) String() string {
	return diagnostic.Path + ": " + diagnostic.Message
}

// ValidationError groups all diagnostics so users can correct a profile in one
// pass. Diagnostics are sorted by path and message for stable CLI output.
type ValidationError struct {
	Diagnostics []Diagnostic
}

func (validation ValidationError) Error() string {
	if len(validation.Diagnostics) == 0 {
		return "invalid profile"
	}
	lines := make([]string, len(validation.Diagnostics))
	for index, diagnostic := range validation.Diagnostics {
		lines[index] = diagnostic.String()
	}
	return "invalid profile:\n- " + strings.Join(lines, "\n- ")
}

// Validate checks the profile shape without connecting to PostgreSQL.
func Validate(value domain.Profile) error {
	var diagnostics []Diagnostic
	add := func(path, message string) {
		diagnostics = append(diagnostics, Diagnostic{Path: path, Message: message})
	}

	if value.Version != SupportedVersion {
		add("version", fmt.Sprintf("must be %d", SupportedVersion))
	}
	if !isIdentifier(value.Database.Schema) {
		add("database.schema", "must be a lowercase PostgreSQL identifier")
	}
	if !value.Database.RequireDisposable {
		add("database.require_disposable", "must be true")
	}
	validateIdentity(add, "identity.owner", value.Identity.Owner)
	validateIdentity(add, "identity.adversary", value.Identity.Adversary)

	fixturesByTable := make(map[string][]int)
	for index, fixture := range value.Fixtures {
		path := fmt.Sprintf("fixtures[%d]", index)
		if !isIdentifier(fixture.Table) {
			add(path+".table", "must be a lowercase PostgreSQL identifier")
		}
		if len(fixture.OwnerRow) == 0 {
			add(path+".owner_row", "must contain at least one column")
		}
		for column := range fixture.OwnerRow {
			if !isIdentifier(column) {
				add(path+".owner_row."+column, "must be a lowercase PostgreSQL identifier")
			}
		}
		for _, column := range fixture.SensitiveColumns {
			if !isIdentifier(column) {
				add(path+".sensitive_columns", "contains an invalid identifier")
			}
		}
		fixturesByTable[fixture.Table] = append(fixturesByTable[fixture.Table], index)
	}
	if len(value.Fixtures) == 0 {
		add("fixtures", "must contain at least one fixture")
	}

	attacksByTable := make(map[string]int)
	for index, attack := range value.Attacks {
		path := fmt.Sprintf("attacks[%d]", index)
		if !isIdentifier(attack.Table) {
			add(path+".table", "must be a lowercase PostgreSQL identifier")
		}
		if prior, found := attacksByTable[attack.Table]; found {
			add(path+".table", fmt.Sprintf("duplicates attacks[%d].table", prior))
		} else {
			attacksByTable[attack.Table] = index
		}
		if len(attack.PrimaryKey) == 0 {
			add(path+".primary_key", "must contain at least one column")
		}
		validateColumns(add, path+".primary_key", attack.PrimaryKey)
		validateColumns(add, path+".protected_columns", attack.ProtectedColumns)
		if len(attack.Operations) == 0 {
			add(path+".operations", "must contain at least one operation")
		}
		for operationIndex, operation := range attack.Operations {
			if !operation.Valid() {
				add(fmt.Sprintf("%s.operations[%d]", path, operationIndex), "is not supported")
			}
		}
		if len(fixturesByTable[attack.Table]) == 0 {
			add(path+".table", "must reference a fixture table")
		}
	}
	if len(value.Attacks) == 0 {
		add("attacks", "must contain at least one attack")
	}

	for table, fixtureIndexes := range fixturesByTable {
		attackIndex, exists := attacksByTable[table]
		if !exists {
			for _, fixtureIndex := range fixtureIndexes {
				add(fmt.Sprintf("fixtures[%d].table", fixtureIndex), "must have a matching attack target")
			}
			continue
		}
		attack := value.Attacks[attackIndex]
		seenKeys := make(map[string]int)
		for _, fixtureIndex := range fixtureIndexes {
			fixture := value.Fixtures[fixtureIndex]
			key, ok := fixtureKey(fixture.OwnerRow, attack.PrimaryKey)
			if !ok {
				add(fmt.Sprintf("fixtures[%d].owner_row", fixtureIndex), "must include every attack primary-key column")
				continue
			}
			if prior, exists := seenKeys[key]; exists {
				add(fmt.Sprintf("fixtures[%d].owner_row", fixtureIndex), fmt.Sprintf("duplicates fixture key in fixtures[%d]", prior))
			} else {
				seenKeys[key] = fixtureIndex
			}
		}
	}

	if len(diagnostics) == 0 {
		return nil
	}
	sort.Slice(diagnostics, func(left, right int) bool {
		if diagnostics[left].Path == diagnostics[right].Path {
			return diagnostics[left].Message < diagnostics[right].Message
		}
		return diagnostics[left].Path < diagnostics[right].Path
	})
	return ValidationError{Diagnostics: diagnostics}
}

func validateIdentity(add func(string, string), path string, identity domain.Identity) {
	if !isIdentifier(identity.Role) {
		add(path+".role", "must be a lowercase PostgreSQL identifier")
	}
	for name := range identity.Settings {
		if !isSettingName(name) {
			add(path+".settings."+name, "must be a valid setting name")
		}
	}
}

func validateColumns(add func(string, string), path string, columns []string) {
	seen := make(map[string]bool)
	for index, column := range columns {
		if !isIdentifier(column) {
			add(fmt.Sprintf("%s[%d]", path, index), "must be a lowercase PostgreSQL identifier")
		}
		if seen[column] {
			add(fmt.Sprintf("%s[%d]", path, index), "duplicates a previous column")
		}
		seen[column] = true
	}
}

func fixtureKey(row map[string]any, columns []string) (string, bool) {
	parts := make([]string, len(columns))
	for index, column := range columns {
		value, exists := row[column]
		if !exists {
			return "", false
		}
		parts[index] = fmt.Sprintf("%T:%v", value, value)
	}
	return strings.Join(parts, "\x00"), true
}

func isIdentifier(value string) bool {
	if value == "" || len(value) > 63 {
		return false
	}
	for index, character := range value {
		if index == 0 {
			if character != '_' && !unicode.IsLower(character) {
				return false
			}
			continue
		}
		if character != '_' && !unicode.IsLower(character) && !unicode.IsDigit(character) {
			return false
		}
	}
	return true
}

func isSettingName(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if !isIdentifier(part) {
			return false
		}
	}
	return true
}
