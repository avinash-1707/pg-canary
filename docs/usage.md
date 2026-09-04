# Running pg-canary

`pg-canary` is intended only for a disposable database. It runs fixture DML in
one transaction and rolls that transaction back, but rollback cannot undo every
possible PostgreSQL side effect.

## Fixture database

The repository's test fixture provisions a restricted login role and an
application role:

```sql
CREATE ROLE canary_runner LOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT PASSWORD 'use-a-secret-manager';
CREATE ROLE canary_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT;
GRANT canary_app TO canary_runner;
```

The login role must not be a superuser or have `BYPASSRLS`; it must be allowed
to `SET ROLE` to each profile role. A table owner is only a valid test identity
when the table uses `FORCE ROW LEVEL SECURITY`.

## Example

Start the disposable fixture matrix with `make integration`, then validate a
profile:

```sh
go run ./cmd/pg-canary validate --profile docs/examples/secure-profile.yaml
```

Run only with an explicit URL and write acknowledgement:

```sh
go run ./cmd/pg-canary run \
  --profile docs/examples/secure-profile.yaml \
  --db-url 'postgres://canary_runner:runner-password@127.0.0.1:PORT/pg_canary_test?sslmode=disable' \
  --allow-write --json --output report.json
```

To deliberately read a URL from CI environment state, opt in explicitly:

```sh
pg-canary run --profile profile.yaml --db-url-env PG_CANARY_DB_URL --allow-write --json
```

The tool never intentionally prints a connection URL. `pass` exits 0, `fail`
exits 1, and `blocked` or `inconclusive` exit 2.

## Limitations and troubleshooting

- The profile must describe every fixture, key, and attack; v1 does not infer
  relational fixtures.
- Views, functions, HTTP adapters, concurrency, and external trigger effects
  are outside v1's authority.
- `blocked` means the target or identity is unsafe evidence; correct the role,
  owner, or acknowledgement condition before retrying.
- `inconclusive` means setup or database behavior prevented a trustworthy
  verdict; it is not a pass.
