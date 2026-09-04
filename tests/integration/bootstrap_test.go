//go:build integration

package integration

import "testing"

func TestIntegrationEnvironmentIsAvailable(t *testing.T) {
	t.Skip("PostgreSQL fixtures are introduced in implementation unit 2")
}
