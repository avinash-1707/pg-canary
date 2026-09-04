package profile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/avinash-1707/pg-canary/internal/domain"
	"gopkg.in/yaml.v3"
)

// LoadFile reads, decodes, and validates a versioned profile file.
func LoadFile(path string) (domain.Profile, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return domain.Profile{}, fmt.Errorf("read profile: %w", err)
	}
	return Load(contents)
}

// Load decodes and validates one versioned YAML profile document.
func Load(contents []byte) (domain.Profile, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	decoder.KnownFields(true)

	var result domain.Profile
	if err := decoder.Decode(&result); err != nil {
		return domain.Profile{}, fmt.Errorf("decode profile: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return domain.Profile{}, fmt.Errorf("decode profile: multiple YAML documents are not supported")
	} else if !errors.Is(err, io.EOF) {
		return domain.Profile{}, fmt.Errorf("decode profile: %w", err)
	}
	if err := Validate(result); err != nil {
		return domain.Profile{}, err
	}
	return result, nil
}
