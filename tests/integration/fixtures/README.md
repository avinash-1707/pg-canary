# PostgreSQL fixture matrix

The integration suite starts disposable PostgreSQL 15, 16, and 17 containers
from `docker-compose.yml`. Each service binds its PostgreSQL port to an
ephemeral host port, so the suite does not depend on a particular local port.

`reset.sql` is idempotent and is applied before every fixture assertion. It
creates a restricted login role, grants it membership in the application test
role, and recreates five purpose-built schemas:

- `secure`: forced RLS with a tenant-setting policy;
- `read_leak`: a permissive read policy;
- `write_leak`: a permissive insert policy;
- `owner_bypass`: an unforced RLS table owned by the application role; and
- `missing_privilege`: an RLS table without application table grants.

Run the matrix with `make integration`. The test creates a unique Compose
project per process and removes all containers and volumes afterward.
