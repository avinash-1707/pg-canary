# pg-canary — Product Definition

## Purpose

`pg-canary` is a local-first command-line verifier for PostgreSQL row-level
security (RLS). Given an **explicit test profile** and a disposable or approved
test database, it creates two synthetic principals, attempts cross-tenant
reads and writes, and reports whether the configured isolation invariant held.

It is a test runner, not a static security scanner and not a proof that an
application has no authorization flaws. A passing result means only that the
operations in the selected profile were denied under the database role and
session context tested.

## Problem

RLS tests are frequently run from the migration-owner or an administrative
connection. Those roles can bypass RLS, making a green test meaningless.
Teams also tend to test successful access but omit adversarial attempts to
read, update, delete, or insert another tenant's rows.

pg-canary makes the negative cases repeatable in local development and CI.

## v1: Deliberately Narrow

v1 supports direct PostgreSQL connections and one invariant:

> A configured adversary must not read, update, or delete the configured
> owner's fixture, nor insert or transfer a row into the owner's tenant when
> the profile declares that operation forbidden.

Included:

- PostgreSQL 15+ direct-wire execution using `pgx`.
- A transactional, sequential CRUD attack matrix for explicitly configured
  tables.
- Profiles for database roles and session settings (including Supabase-style
  JWT claim GUCs).
- Catalog preflight for RLS state, applicable policies, grants, role
  attributes, table ownership, and relevant constraints.
- JSON and human-readable reports with `pass`, `fail`, `inconclusive`, or
  `blocked` outcomes.
- A built-in negative control that must demonstrate the runner can observe a
  deliberately exposed owner row before it may issue a `pass`.

Not included in v1:

- Automatic reverse-predicate fixture generation for arbitrary schemas.
- AST-based policy interpretation as a pass/fail authority.
- HTTP/PostgREST/Edge Function execution, concurrency/race probes, hosted
  reporting, remediation PRs, PDF signing, or npm distribution.
- Testing arbitrary `SECURITY DEFINER` functions or views as an access path.

Those are separate future milestones, because each needs an explicit threat
model and reproducible test setup.

## Required Test Profile

Zero configuration is unsafe and not credible for relational schemas: only the
application knows which tenant column, seed shape, and client identity model
are meaningful. Every v1 run therefore consumes a versioned profile, for
example:

```yaml
version: 1
database:
  schema: public
  require_disposable: true
identity:
  owner:
    role: authenticated
    settings:
      request.jwt.claim.sub: 11111111-1111-1111-1111-111111111111
  adversary:
    role: authenticated
    settings:
      request.jwt.claim.sub: 22222222-2222-2222-2222-222222222222
fixtures:
  - table: projects
    owner_row:
      id: 1001
      organization_id: 00000000-0000-0000-0000-000000000001
      name: canary-owner-project
attacks:
  - table: projects
    primary_key: [id]
    protected_columns: [organization_id]
    operations: [select, update, delete, insert]
```

The profile is intentionally data-free apart from synthetic fixture values.
Secrets belong in the connection string or CI secret store, never in the
profile or report.

## Execution Contract

1. Validate the target and profile. Refuse production-like targets by default;
   `--allow-write` is required even though execution uses a rollback.
2. Establish one dedicated connection and begin a transaction. The v1 matrix is
   sequential, which keeps `SET LOCAL` state and evidence deterministic.
3. Set a trusted, explicit `search_path`; seed profile fixtures; then switch to
   the configured role and session settings using `SET LOCAL`.
4. Run the negative control, then the adversarial matrix. Each attack receives
   a savepoint so an expected RLS error does not abort the enclosing
   transaction.
5. Roll back the entire transaction and emit a report. Failure to roll back is
   a fatal outcome.

The tool must quote all identifiers and bind values; profile content is never
concatenated into executable SQL.

## Result Semantics

| Outcome | Meaning | CI exit |
|---|---|---|
| `pass` | Negative control ran and every configured attack was denied. | 0 |
| `fail` | An adversary observed, changed, deleted, or inserted a protected row. | 1 |
| `inconclusive` | The harness could not establish a valid test condition. | 2 |
| `blocked` | Preconditions make execution unsafe or invalid (for example RLS bypass). | 2 |

`inconclusive` and `blocked` fail CI by default. They must never be displayed
as a green security result.

## Non-Goals and Claims Discipline

pg-canary does not claim zero false positives or a mathematical proof of all
tenant isolation. Policy composition, triggers, views, functions, application
endpoints, and untested values remain outside a single profile run. The report
records exact SQL templates, role, GUC names, PostgreSQL version, and result
counts so a finding can be reproduced.

## Acceptance Criteria for the First Release

- A secure fixture schema produces `pass` for all four CRUD attacks.
- A selectable owner row produces a reproducible `fail` with evidence.
- A policy that denies fixture creation, an unavailable role, or an invalid
  negative control produces `inconclusive`, never `pass`.
- A superuser, a `BYPASSRLS` role, or an unforced table owner produces
  `blocked` before any fixture DML.
- Integration tests run against PostgreSQL 15, 16, and 17 containers.
