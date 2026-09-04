# pg-canary

`pg-canary` is a local-first command-line verifier for PostgreSQL row-level
security (RLS). It will execute a profile-declared adversarial test matrix
against a disposable or explicitly approved database.

The current bootstrap provides the build, test, lint, integration-test, and CI
foundation. The RLS runner is implemented incrementally in the units described
in [docs/todo.md](docs/todo.md).

## Requirements

- Go 1.26 or later

## Development

```sh
make format
make test
make lint
make integration
make build
./bin/pg-canary --help
```

Run all CI checks locally with `make ci`.

## Layout

```text
cmd/pg-canary/       Executable entry point
internal/cli/        Command parsing and presentation
internal/{profile,catalog,harness,attacks,evaluate,report}/
                     Planned application boundaries
tests/integration/   Integration-test suite and database fixtures
docs/                Product, architecture, and implementation notes
.github/workflows/   Continuous-integration definitions
```

## Safety

The completed tool will require an explicit profile and write opt-in. It is
not intended for production targets. See [docs/project-overview.md](docs/project-overview.md)
for the product boundary and guarantees.
