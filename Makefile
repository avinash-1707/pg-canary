.PHONY: build format format-check test lint integration ci

GO_FILES := $(shell find . -type f -name '*.go' -not -path './vendor/*')
BINARY := bin/pg-canary

build:
	@mkdir -p $(dir $(BINARY))
	go build -o $(BINARY) ./cmd/pg-canary

format:
	gofmt -w $(GO_FILES)

format-check:
	@test -z "$$(gofmt -l $(GO_FILES))" || (echo "Run 'make format' to format Go files." && exit 1)

test:
	go test ./...

lint:
	go vet ./...

integration:
	go test -tags=integration ./tests/integration/...

ci: format-check test lint integration
