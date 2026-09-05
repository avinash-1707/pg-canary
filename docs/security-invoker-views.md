# Security-invoker views

PostgreSQL 15 and later can create a view with `security_invoker = true`.
Underlying table privileges and RLS policies are then evaluated as the caller,
not as the view owner. This makes the view a distinct access path worth testing.

The `internal/views` package verifies that a selected view has this option and
probes exact primary-key visibility through it. The integration fixture includes
`secure.projects_invoker`, which proves that an attacker cannot see an owner row
through a security-invoker view when the underlying RLS policy denies it.

This is intentionally separate from testing `SECURITY DEFINER` functions.
Those functions run with owner privileges and require their own threat model.
