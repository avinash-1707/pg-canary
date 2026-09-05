// Package publish sends already-redacted report artifacts to an opted-in endpoint.
package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/avinash-1707/pg-canary/internal/domain"
	"net/http"
	"net/url"
)

type HTTP struct {
	Endpoint, Token string
	Client          *http.Client
}

func (publisher HTTP) Publish(ctx context.Context, report domain.Report) error {
	endpoint, err := url.Parse(publisher.Endpoint)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return fmt.Errorf("invalid report endpoint")
	}
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if publisher.Token != "" {
		request.Header.Set("Authorization", "Bearer "+publisher.Token)
	}
	client := publisher.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("report publish failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("report endpoint returned HTTP %d", response.StatusCode)
	}
	return nil
}
