package fixtures

import (
	"testing"
)

func TestPlanDeterministic(t *testing.T) {
	out, e := Plan([]Node{{Name: "projects", DependsOn: []string{"organizations"}}, {Name: "users"}, {Name: "organizations"}})
	if e != nil || out[0].Name != "organizations" || out[1].Name != "projects" || out[2].Name != "users" {
		t.Fatalf("plan=%+v err=%v", out, e)
	}
}
