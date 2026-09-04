# pg-canary

`pg-canary` is a local-first command-line verifier for PostgreSQL row-level
security (RLS). Given an explicit YAML profile and a disposable PostgreSQL
database, it seeds synthetic rows, assumes the configured database identities,
attempts cross-tenant access, and reports whether the selected isolation
invariant held.

It is a focused RLS test runner. It does not prove that an application has no
authorization flaws, and it must not be pointed at a production database.

## What it verifies

For each configured table, `pg-canary` can verify that an adversary cannot:

- read the owner's row;
- update or delete the owner's row; or
- insert a row into the owner's protected tenant context.

The tool only reports `pass` after it can observe the seeded owner fixture
under the owner identity and every requested adversarial operation is denied.

```mermaid
flowchart LR
    P[Versioned YAML profile] --> V[Validate profile]
    V --> G[Catalog safety gate]
    G -->|safe| T[One transaction]
    G -->|unsafe or incomplete| B[blocked or inconclusive]
    T --> S[Seed owner fixtures]
    S --> C[Negative control]
    C --> A[Adversarial CRUD matrix]
    A --> R[Redacted terminal or JSON report]
    R --> X[Always roll back]
```

## Safety model

The command requires both a profile that declares the target disposable and an
explicit `--allow-write` flag. It opens one dedicated PostgreSQL connection,
uses transaction-local role and setting changes, and rolls back the outer
transaction at the end of every run.

Rollback is not a complete safety mechanism. Sequences and external effects
reached through triggers, rules, or functions can survive or escape a
transaction. Use a database that is disposable and isolated from production.

```mermaid
flowchart TD
    A[CLI input] --> B{Profile valid?}
    B -->|no| I[inconclusive]
    B -->|yes| C{allow-write and disposable?}
    C -->|no| D[blocked]
    C -->|yes| E{Role, ownership, RLS, grants safe?}
    E -->|no| F[blocked or inconclusive]
    E -->|yes| G[Run transaction]
    G --> H{All required attacks denied?}
    H -->|yes| P[pass]
    H -->|no| Q[fail or inconclusive]
```

## Requirements

- Go 1.26 or later for local development
- Docker with a running daemon for the PostgreSQL fixture matrix
- PostgreSQL 15 or later for a target database

## Quick start

Clone the repository and run the release checks:

```sh
make release-check
```

Validate the included example profile without connecting to a database:

```sh
go run ./cmd/pg-canary validate --profile docs/examples/secure-profile.yaml
```

Run against a disposable PostgreSQL target with a restricted runner role:

```sh
go run ./cmd/pg-canary run \
  --profile docs/examples/secure-profile.yaml \
  --db-url 'postgres://canary_runner:SECRET@HOST:5432/DATABASE?sslmode=require' \
  --allow-write \
  --json \
  --output report.json
```

To intentionally read the database URL from the environment, opt in with its
variable name:

```sh
pg-canary run \
  --profile profile.yaml \
  --db-url-env PG_CANARY_DB_URL \
  --allow-write \
  --json
```

The command does not intentionally print the connection URL or credentials.

## Outcomes and exit codes

| Outcome | Meaning | Exit code |
| --- | --- | ---: |
| `pass` | The negative control succeeded and every requested attack was denied. | 0 |
| `fail` | An adversary observed or changed a protected row, or inserted a forbidden row. | 1 |
| `inconclusive` | The tool could not establish a trustworthy test condition. | 2 |
| `blocked` | Preconditions make the target or identity unsafe RLS evidence. | 2 |

`blocked` and `inconclusive` are failures in CI. Neither is a green security
result.

## Profile overview

Profiles are versioned YAML documents that name a database schema, owner and
adversary identities, synthetic fixtures, and attacks. Values are bound as
query parameters, and table or column identifiers are validated before use.

```yaml
version: 1
database:
  schema: secure
  require_disposable: true
identity:
  owner:
    role: canary_app
    settings:
      request.jwt.claim.sub: owner
  adversary:
    role: canary_app
    settings:
      request.jwt.claim.sub: attacker
fixtures:
  - table: projects
    owner_row:
      id: 1001
      tenant_id: owner
      name: canary-owner-project
attacks:
  - table: projects
    primary_key: [id]
    protected_columns: [tenant_id]
    operations: [select, update, delete, insert]
    mutation:
      tenant_id: attacker
    insert:
      id: 1002
      tenant_id: owner
      name: canary-adversary-project
```

See [docs/examples/secure-profile.yaml](docs/examples/secure-profile.yaml) for
the complete example and [docs/usage.md](docs/usage.md) for runner-role
provisioning and operating guidance.

## Development and verification

| Command | Purpose |
| --- | --- |
| `make format` | Format Go source files. |
| `make test` | Run unit tests. |
| `make lint` | Run `go vet`. |
| `make integration` | Run the Docker-backed PostgreSQL integration suite. |
| `make build` | Build `bin/pg-canary`. |
| `make ci` | Run the standard CI checks. |
| `make release-check` | Run formatting, tests, lint, race detection, dependency verification, and integration tests. |

The integration suite starts isolated PostgreSQL 15, 16, and 17 containers,
plus PostgreSQL 14 solely to verify version rejection. Every Compose run uses a
unique project name and removes its containers and volumes afterward.

## Architecture

```mermaid
flowchart TB
    CLI[cmd/pg-canary] --> Profile[internal/profile]
    CLI --> Runner[internal/runner]
    Runner --> DB[internal/database]
    Runner --> Catalog[internal/catalog]
    Runner --> Gate[internal/preflight]
    Runner --> Session[internal/session]
    Runner --> Seeder[internal/seeder]
    Runner --> Control[internal/control]
    Runner --> Attacks[internal/attacks]
    Runner --> Evaluate[internal/evaluate]
    CLI --> Report[internal/report]
    Attacks --> SQL[internal/sqlsafe]
```

The repository also contains Docker fixtures and integration coverage under
`tests/integration/`, product and design documents under `docs/`, and the
GitHub Actions workflow under `.github/workflows/`.

## Limitations

- The profile must explicitly provide fixtures, keys, and attack payloads.
- v1 tests direct table access only. It does not test views, functions,
  PostgREST, application endpoints, HTTP adapters, or concurrency behavior.
- Catalog policy text is evidence, not a static proof of policy semantics.
- External effects from triggers, rules, foreign tables, or called functions
  require special review before running the tool.

Read [docs/project-overview.md](docs/project-overview.md) for the intended
product boundary, [docs/architecture.md](docs/architecture.md) for design
details, and [docs/ci.md](docs/ci.md) for CI and release guidance.
