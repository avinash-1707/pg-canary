package sqlsafe

import (
	"strings"
	"testing"
)

func TestValuesAreBoundAndIdentifiersRejected(t *testing.T) {
	value := "x'; DROP TABLE projects; --"
	s, e := Select("public", "projects", []string{"id"}, map[string]any{"id": value})
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(s.SQL, value) || len(s.Args) != 1 || s.Args[0] != value {
		t.Fatalf("unsafe statement: %+v", s)
	}
	for _, bad := range []string{"projects;drop", "public.projects", "X"} {
		if _, e := Qualified("public", bad); e == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
