package profile

import (
	"strings"
	"testing"

	"github.com/avinash-1707/pg-canary/internal/domain"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		edit func(*domain.Profile)
		want string
	}{
		{name: "valid", edit: func(*domain.Profile) {}, want: ""},
		{name: "unknown version", edit: func(profile *domain.Profile) { profile.Version = 2 }, want: "version: must be 1"},
		{name: "malformed table", edit: func(profile *domain.Profile) { profile.Fixtures[0].Table = "public.projects" }, want: "fixtures[0].table: must be a lowercase PostgreSQL identifier"},
		{name: "missing primary key", edit: func(profile *domain.Profile) { profile.Attacks[0].PrimaryKey = nil }, want: "attacks[0].primary_key: must contain at least one column"},
		{name: "unsupported operation", edit: func(profile *domain.Profile) { profile.Attacks[0].Operations = []domain.Operation{"merge"} }, want: "attacks[0].operations[0]: is not supported"},
		{name: "empty attacks", edit: func(profile *domain.Profile) { profile.Attacks = nil }, want: "attacks: must contain at least one attack"},
		{name: "duplicate fixture key", edit: func(profile *domain.Profile) { profile.Fixtures = append(profile.Fixtures, profile.Fixtures[0]) }, want: "fixtures[1].owner_row: duplicates fixture key in fixtures[0]"},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile := testProfile()
			test.edit(&profile)
			err := Validate(profile)
			if test.want == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	_, err := Load([]byte("version: 1\nunknown: true\n"))
	if err == nil || !strings.Contains(err.Error(), "field unknown not found") {
		t.Fatalf("Load() error = %v, want unknown-field diagnostic", err)
	}
}

func testProfile() domain.Profile {
	return domain.Profile{
		Version:  1,
		Database: domain.Database{Schema: "public", RequireDisposable: true},
		Identity: domain.Identities{
			Owner:     domain.Identity{Role: "owner_role"},
			Adversary: domain.Identity{Role: "adversary_role"},
		},
		Fixtures: []domain.Fixture{{Table: "projects", OwnerRow: map[string]any{"id": 1, "tenant_id": "owner"}}},
		Attacks: []domain.Attack{{
			Table:            "projects",
			PrimaryKey:       []string{"id"},
			ProtectedColumns: []string{"tenant_id"},
			Operations:       []domain.Operation{domain.OperationSelect},
		}},
	}
}
