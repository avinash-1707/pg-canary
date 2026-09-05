# Advanced execution

Fixture dependencies are explicit and deterministic through `internal/fixtures`.
The package does not infer relationships from schema metadata or fixture values.

`internal/concurrency` provides an opt-in synchronized worker primitive for
future race probes. Concurrent probes require a separate profile contract and
threat model before they are wired into the CLI runner.
