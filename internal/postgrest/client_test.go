package postgrest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/avinash-1707/pg-canary/internal/domain"
)

func TestExecuteUsesProfileHeadersAndDoesNotExposeToken(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/rest/v1/projects" || request.URL.Query().Get("id") != "eq.1" {
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL)
		}
		if request.Header.Get("Accept-Profile") != "public" || request.Header.Get("Authorization") != "Bearer secret-token" {
			t.Fatal("missing profile or authorization header")
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`[{"id":1}]`))
	}))
	defer server.Close()
	evidence, err := (Client{BaseURL: server.URL + "/rest/v1", Schema: "public"}).Execute(context.Background(), Identity{BearerToken: "secret-token"}, domain.OperationSelect, "projects", url.Values{"id": {"eq.1"}}, nil)
	if err != nil || evidence.RowsReturned != 1 || evidence.Denied {
		t.Fatalf("evidence=%+v err=%v", evidence, err)
	}
}

func TestExecuteClassifiesForbiddenWithoutLeakingToken(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Error(writer, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()
	evidence, err := (Client{BaseURL: server.URL}).Execute(context.Background(), Identity{BearerToken: "secret-token"}, domain.OperationSelect, "projects", nil, nil)
	if err != nil || !evidence.Denied || evidence.Error != "HTTP 403" {
		t.Fatalf("evidence=%+v err=%v", evidence, err)
	}
}
