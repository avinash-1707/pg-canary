// Package postgrest executes explicit RLS probes through a PostgREST endpoint.
package postgrest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/avinash-1707/pg-canary/internal/domain"
	"github.com/avinash-1707/pg-canary/internal/sqlsafe"
)

// Client is an explicit PostgREST transport. It never includes a bearer token
// in returned evidence or errors.
type Client struct {
	BaseURL    string
	Schema     string
	HTTPClient *http.Client
}

// Identity is the bearer credential supplied by the caller's secret store.
type Identity struct{ BearerToken string }

// Execute performs one PostgREST table operation. Filters are sent as query
// parameters, and payload is encoded as JSON rather than concatenated.
func (client Client) Execute(ctx context.Context, identity Identity, operation domain.Operation, table string, filters url.Values, payload map[string]any) (domain.OperationEvidence, error) {
	evidence := domain.OperationEvidence{Table: table, Operation: operation}
	if _, err := sqlsafe.Identifier(table); err != nil {
		return evidence, err
	}
	endpoint, err := url.Parse(client.BaseURL)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return evidence, fmt.Errorf("invalid PostgREST base URL")
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/" + table
	endpoint.RawQuery = filters.Encode()
	method := map[domain.Operation]string{domain.OperationSelect: http.MethodGet, domain.OperationUpdate: http.MethodPatch, domain.OperationDelete: http.MethodDelete, domain.OperationInsert: http.MethodPost}[operation]
	if method == "" {
		return evidence, fmt.Errorf("unsupported operation %q", operation)
	}
	var body io.Reader
	if operation == domain.OperationUpdate || operation == domain.OperationInsert {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return evidence, err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return evidence, err
	}
	req.Header.Set("Accept", "application/json")
	if client.Schema != "" {
		if method == http.MethodGet || method == http.MethodDelete {
			req.Header.Set("Accept-Profile", client.Schema)
		} else {
			req.Header.Set("Content-Profile", client.Schema)
		}
	}
	if identity.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+identity.BearerToken)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Prefer", "return=representation")
	}
	started := time.Now()
	response, err := client.httpClient().Do(req)
	evidence.DurationMS = time.Since(started).Milliseconds()
	evidence.Template = method + " /" + table
	if err != nil {
		return evidence, fmt.Errorf("PostgREST request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		evidence.Error = fmt.Sprintf("HTTP %d", response.StatusCode)
		evidence.Denied = response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden
		return evidence, nil
	}
	var rows []json.RawMessage
	_ = json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&rows)
	if operation == domain.OperationSelect {
		evidence.RowsReturned = int64(len(rows))
		evidence.Denied = evidence.RowsReturned == 0
	} else {
		evidence.RowsAffected = int64(len(rows))
		evidence.Denied = evidence.RowsAffected == 0
	}
	return evidence, nil
}
func (client Client) httpClient() *http.Client {
	if client.HTTPClient != nil {
		return client.HTTPClient
	}
	return http.DefaultClient
}
