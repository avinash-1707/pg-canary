# pg-canary v1 — Implementation Units

Build these units in order. Each unit must meet its completion condition before
the next dependent unit begins. Units 1–5 establish the contracts and safety
boundary; no fixture mutation should be implemented before they are complete.

## Unit 1 — Project Bootstrap

Create the Go module, add `pgx/v5` and a YAML parser, and create the
`cmd/pg-canary` entry point. Add repeatable commands for formatting, unit
tests, linting, and integration tests, with CI running them on every change.

**Complete when:** a fresh checkout passes `go test ./...` and
`pg-canary --help` exits successfully.

## Unit 2 — Integration Test Environment

Create Docker-backed PostgreSQL 15, 16, and 17 fixtures. Provision a dedicated
non-superuser runner role that can assume the application test role. Include
secure, read-leak, write-leak, owner-bypass, and missing-privilege schemas.

**Complete when:** every supported PostgreSQL container can be started and
reset deterministically by the test suite.

## Unit 3 — Domain and Result Contracts

Define types for profiles, identities, fixtures, attacks, preflight findings,
operation evidence, and reports. Establish the versioned JSON schema and the
four outcomes: `pass`, `fail`, `inconclusive`, and `blocked`, including their
exit codes and redaction rules.

**Complete when:** golden tests serialize all outcome types without exposing a
connection URL or sensitive fixture value.

## Unit 4 — Profile Loader and Validator

Implement the versioned YAML profile loader and a profile-only `validate`
command. Require a schema, two identities, fixture rows, attack targets, and
primary keys. Reject unknown versions, malformed identifiers, duplicate fixture
keys, unsupported operations, and empty attack lists.

**Complete when:** table-driven tests cover valid and invalid profiles, and
`pg-canary validate --profile FILE` has stable diagnostics.

## Unit 5 — Command-Line Interface

Implement `pg-canary run --profile FILE --db-url URL --allow-write`, with
terminal or JSON output and an optional output file. Require explicit opt-in to
read a URL from an environment variable and never print credentials.

**Complete when:** CLI tests cover flags, exit codes, JSON output, and URL
redaction.

## Unit 6 — Dedicated Connection

Open one dedicated `pgx.Conn`, require PostgreSQL 15 or later, reject a
read-only target, and apply timeouts to connection and query operations. Record
only non-secret server metadata in the report.

**Complete when:** connection, unsupported-version, read-only, and timeout
paths are integration tested without database mutation.

## Unit 7 — Catalog Inspector

Read selected-table metadata from PostgreSQL catalogs: ownership, RLS enabled
and forced state, columns, keys, defaults, foreign keys, triggers, rules,
grants, policies, role attributes, and membership paths. Return typed findings,
not scattered SQL string decisions.

**Complete when:** integration assertions match known metadata across the
secure and insecure fixtures on PostgreSQL 15–17.

## Unit 8 — Preflight Safety Gate

Require `--allow-write` and a profile that declares the target disposable.
Block superusers, `BYPASSRLS` roles, and unforced table owners. Verify that the
login role can assume every configured test role, distinguish missing grants
from RLS denials, and require acknowledgement for triggers, rules, foreign
tables, or other potentially external effects.

**Complete when:** invalid identities are `blocked` before fixture DML and
missing privileges are `inconclusive`, never `pass`.

## Unit 9 — Safe SQL Construction

Implement strict identifier validation and quoting after catalog validation.
Bind every profile value as a query parameter, provide schema-qualified names
and primary-key predicates, and produce redacted SQL templates for evidence.

**Complete when:** tests demonstrate that malformed identifiers and
malicious-looking values cannot be converted into executable SQL.

## Unit 10 — Transaction and Savepoint Harness

Run one outer transaction on the dedicated connection. Use a savepoint around
every seed and attack operation, roll back to the savepoint after expected
errors, and always attempt the outer rollback. Treat outer rollback failure as
fatal.

**Complete when:** an expected rejected write does not stop later attacks and
no fixture row remains after the run.

## Unit 11 — Transaction-Local Identity Context

Set a trusted `search_path`, apply the approved role with `SET LOCAL ROLE`, and
apply allowlisted session settings with transaction-local semantics, including
Supabase-compatible JWT claim GUCs. Never issue session-scoped role or setting
changes.

**Complete when:** an integration policy sees the configured role and JWT
subject, and the connection retains neither after rollback.

## Unit 12 — Fixture Seeder

Insert only profile-declared synthetic rows in deterministic dependency order.
Validate required columns, defaults, and foreign keys before execution; capture
owner-row keys for later predicates. Do not attempt automatic relational
fixture inference in v1.

**Complete when:** a valid multi-table fixture seeds, while invalid fixture
requirements result in a complete rollback and `inconclusive`.

## Unit 13 — Negative Control

Implement the configured control that proves the harness can observe the owner
fixture under its valid test condition. Run it before granting a pass and mark a
missing or unexpected result as inconclusive.

**Complete when:** an empty or incorrectly seeded table can never generate a
`pass` result.

## Unit 14 — Read, Update, and Delete Attacks

Under the adversary identity, select, update, and delete the exact owner
primary key. Treat visible rows or affected rows as failures; record SQLSTATE,
duration, counts, and a redacted reproduction template. Support a
protected-column transfer only when the profile provides a valid mutation.

**Complete when:** secure fixtures pass and each intentional read, update, or
delete weakness produces a reproducible failure.

## Unit 15 — Insert Attack and Verdict Evaluation

Build an insert only from a complete profile payload, attempting to place a row
in the protected owner tenant. A successful insert fails the run; an expected
RLS rejection is denied; unrelated constraint or setup errors are inconclusive.
Combine all evidence with the precedence `blocked`, `inconclusive`, `fail`,
then `pass` only when all required evidence exists.

**Complete when:** `WITH CHECK`-protected inserts pass, permissive inserts
fail, mixed outcomes preserve all evidence, and non-pass outcomes fail CI.

## Unit 16 — Reporting and Release Gate

Finish concise terminal output and the stable JSON report. Add minimal
PostgreSQL and Supabase-style examples, runner-role provisioning instructions,
CI examples, safety guidance, limitations, and troubleshooting. Run formatting,
tests, static analysis, race detection, dependency review, and the full
PostgreSQL 15–17 matrix before release.

**Complete when:** a new contributor can run the documented secure fixture
end-to-end from a clean checkout, and every acceptance criterion in
`docs/project-overview.md` passes.

## Deferred Work

AST-based advisory analysis, automatic fixture synthesis, pgTAP export, GitHub
annotations, HTTP/PostgREST adapters, views/functions as access paths,
concurrency testing, and hosted reporting need a separate design review after
v1 is proven.
