# pg-canary — v1 Architecture

## Design Decisions

| Decision | v1 choice | Reason |
|---|---|---|
| Product boundary | Profile-driven RLS verifier | Generic fixture inference cannot safely model arbitrary application schemas. |
| Connection model | One dedicated `pgx.Conn`, one transaction | `SET LOCAL` state is connection- and transaction-scoped. |
| Execution | Sequential CRUD matrix | Deterministic evidence; concurrency is a distinct future threat model. |
| SQL parser | Defer from critical path | PostgreSQL catalog text is useful evidence, but parsing does not prove runtime authorization. |
| Output | Terminal and JSON | Keeps CI integration simple and testable. |
| Safety | Rollback plus explicit write opt-in | Rollback does not undo every database side effect. |

## Preconditions and Safety Gate

The runner performs all checks before it mutates a target:

- Require PostgreSQL 15 or later and a reachable, read-write database.
- Require an explicit profile and `--allow-write`.
- Verify the connection role is not a superuser and does not have `BYPASSRLS`.
- Reject a target table when the effective test role is its owner unless the
  table has `FORCE ROW LEVEL SECURITY`.
- Verify the login role may `SET ROLE` to every configured role. PostgreSQL
  requires membership (or equivalent authorization); the tool cannot impersonate
  arbitrary application roles merely by naming them.
- Verify required table privileges and report missing grants as
  `inconclusive`/`blocked`, not as denied attacks.
- Warn and require an explicit acknowledgement for volatile triggers, rules,
  foreign data wrappers, or function calls that may cause external effects.

RLS supplements ordinary privileges; it does not grant them. RLS is bypassed
by superusers and `BYPASSRLS` roles, and normally by table owners. These facts
make such runs invalid as RLS evidence.

## Components

```
cmd/pg-canary
  └── run command
       ├── profile loader + validator
       ├── catalog preflight
       ├── transaction harness
       │    ├── fixture seeder
       │    ├── session configurator
       │    ├── negative control
       │    └── CRUD attack runner
       └── result evaluator + reporters
```

### `internal/profile`

Owns the versioned YAML schema, validation, redaction rules, and the mapping
between attack targets and fixture rows. It validates identifiers against
catalog metadata before use.

### `internal/catalog`

Queries `pg_class`, `pg_namespace`, `pg_policy`, `pg_roles`, `pg_auth_members`,
`pg_attribute`, and `pg_constraint`. It reports, rather than guesses:

- RLS enabled/forced state, owner, policies, policy roles, and permissive vs.
  restrictive composition.
- Effective role properties and whether `SET ROLE` is possible.
- Columns, primary keys, defaults, not-null columns, foreign keys, and grants
  needed to seed and attack each selected table.

Policy expression text is stored for evidence. A future parser may classify
expressions as advisory hints only; its classifications must not alter the
security verdict.

### `internal/harness`

Owns the dedicated connection and a strict state machine:

```
preflight → BEGIN → seed → SAVEPOINT per attack → SET LOCAL identity
         → execute → evaluate → ROLLBACK
```

Expected authorization errors are contained with `ROLLBACK TO SAVEPOINT`.
The session configurator uses only profile-allowlisted GUC names and parameter
binding where PostgreSQL permits it. It resets context naturally at transaction
end; it never uses session-scoped role/settings changes.

### `internal/attacks`

Builds parameterized queries for four operations against a profile-supplied
owner primary key:

- `SELECT`: returns zero owner rows.
- `UPDATE`: affects zero owner rows and attempts a protected-column transfer
  only when the profile declares a valid mutation value.
- `DELETE`: affects zero owner rows.
- `INSERT`: rejects an owner-tenant row when the profile defines a valid insert
  payload and expects rejection.

The runner records SQLSTATE, rows returned/affected, duration, and a redacted
query template. An RLS denial is not assumed to be SQLSTATE `42501`: access to
an invisible existing row commonly yields zero rows for `SELECT`, `UPDATE`, or
`DELETE`; `WITH CHECK` failures commonly raise an error.

### `internal/evaluate` and `internal/report`

Maps evidence to the four public outcomes. JSON is a stable, versioned schema;
terminal output is a presentation layer. Reports redact connection strings,
fixture values marked sensitive, and untrusted error details.

## Policy Semantics the Runner Must Preserve

- Multiple permissive policies combine with OR; restrictive policies combine
  with AND, and at least one applicable permissive policy is needed.
- No applicable policy on an RLS-enabled table is default deny.
- For `ALL` and `UPDATE` policies, omitting `WITH CHECK` reuses `USING`.
  Therefore absence alone is not a finding.
- `UPDATE` can require `SELECT` privileges/policies when it reads target rows;
  the report records this to explain apparent denials.
- Constraints and referential integrity can reveal existence independently of
  RLS. v1 reports such errors as evidence, but does not claim to test every
  side channel.

## Storage and Failure Isolation

The outer transaction is always rolled back. However, sequence values, external
side effects reached by functions/triggers, and some nontransactional behavior
are not necessarily undone. v1 is intended for disposable databases. A future
production-read-only inspection mode may collect catalog information only; it
will never run fixture DML.

## Directory Layout

```
cmd/pg-canary/main.go
internal/profile/
internal/catalog/
internal/harness/
internal/attacks/
internal/evaluate/
internal/report/
tests/integration/fixtures/
docs/
```

## Implementation Sequence

1. Define the profile schema and JSON report contract, with unit tests.
2. Implement catalog preflight and blocked/inconclusive outcomes.
3. Build transaction/savepoint/session handling and a secure/unsafe fixture
   schema integration suite.
4. Add the CRUD matrix and negative control.
5. Add terminal/JSON UX and CI examples after the core results are stable.

AST analysis, automatic fixtures, pgTAP export, GitHub annotations, and
protocol adapters are candidates only after this contract is proven.
