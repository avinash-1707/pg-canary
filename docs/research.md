# Research Notes and Design Evidence

Research completed: 2026-09-04. These sources informed the v1 boundary and
should be rechecked when changing PostgreSQL-version support.

| Finding | Product consequence | Source |
|---|---|---|
| Superusers and `BYPASSRLS` roles bypass RLS; owners normally do too unless the table is forced. | Preflight blocks invalid RLS test identities. | [PostgreSQL row security](https://www.postgresql.org/docs/17/ddl-rowsecurity.html) |
| RLS adds filtering to ordinary grants; it does not create table privileges. | Distinguish missing grants from a successful security denial. | [PostgreSQL row security](https://www.postgresql.org/docs/17/ddl-rowsecurity.html) |
| Permissive policies compose with OR; restrictive policies compose with AND; absent applicable policies are default deny. | Capture all applicable policies and never judge one policy in isolation. | [CREATE POLICY](https://www.postgresql.org/docs/current/sql-createpolicy.html) |
| An `ALL`/`UPDATE` policy without `WITH CHECK` reuses its `USING` expression. | Do not flag missing `WITH CHECK` as a standalone defect. Test the actual mutation instead. | [CREATE POLICY](https://www.postgresql.org/docs/current/sql-createpolicy.html) |
| `SET ROLE` needs authorization to assume the target role. | Require a runner role deliberately provisioned for each profile role. | [SET ROLE](https://www.postgresql.org/docs/current/sql-set-role.html) |
| Supabase tests use transaction-local role and JWT-claim settings. | Provide configurable GUC settings; do not hard-code a single JWT layout. | [Supabase testing overview](https://supabase.com/docs/guides/local-development/testing/overview) |
| `SECURITY DEFINER` executes with owner privileges and must use a safe `search_path`; execute is public by default for new functions. | Exclude function-path testing from v1 and add it only with its own threat model. | [CREATE FUNCTION](https://www.postgresql.org/docs/current/sql-createfunction.html) |
| A `security_invoker` view (PostgreSQL 15+) checks underlying relations as the current user. | Views are a future access-path module, not table-policy evidence. | [CREATE VIEW](https://www.postgresql.org/docs/current/sql-createview.html) |
| `wasilibs/go-pgquery` is a CGo-free, wazero/WASM-compatible replacement returning pg_query_go tree types. | It remains a viable advisory-parser dependency, but is deferred from v1’s verdict path. | [go-pgquery](https://github.com/wasilibs/go-pgquery) |
| A `pgx.Conn` is a single connection; pools are for concurrent use. | Use one dedicated connection for transaction-local identity state in v1. | [pgx getting started](https://github.com/jackc/pgx/wiki/Getting-started-with-pgx) |

## Rejected Assumptions

- “Zero-config fixtures” — rejected: schema semantics and valid insert paths
  cannot be safely inferred for arbitrary applications.
- “Missing `WITH CHECK` is always vulnerable” — rejected by PostgreSQL’s
  fallback semantics.
- “A rollback makes every target safe” — rejected: sequence allocation and
  external behavior reached through database code can survive or escape a
  rollback.
- “A green run proves all tenant isolation” — rejected: it proves the selected
  profile’s operations under one tested identity/session model.
