package advisory

import (
	"github.com/avinash-1707/pg-canary/internal/catalog"
	"testing"
)

func TestAnalyzeHintsOnly(t *testing.T) {
	f := Analyze(catalog.Policy{Using: "true", WithCheck: "true", Roles: []string{"app"}})
	if len(f) != 2 {
		t.Fatalf("findings=%+v", f)
	}
}
