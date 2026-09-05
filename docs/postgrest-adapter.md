# PostgREST and Supabase HTTP adapter

`internal/postgrest` is an explicit HTTP transport for running a selected table
operation through PostgREST. It validates table identifiers, sends filters as
URL parameters, serializes payloads as JSON, uses the configured PostgREST
schema headers, and does not place bearer tokens in returned evidence.

The adapter is intentionally separate from the direct PostgreSQL CLI runner.
HTTP authentication, JWT issuance, endpoint exposure, and error semantics are
a distinct threat model. Callers supply a short-lived bearer token from their
secret store and should use adapter evidence alongside, not as a replacement
for, direct database checks.
