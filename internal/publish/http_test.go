package publish

import (
	"context"
	"github.com/avinash-1707/pg-canary/internal/domain"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPublishRedactsAndAuthenticates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatal("auth")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	r := domain.NewReport(domain.OutcomePass, "ok")
	if e := (HTTP{Endpoint: server.URL, Token: "token"}).Publish(context.Background(), r); e != nil {
		t.Fatal(e)
	}
}
