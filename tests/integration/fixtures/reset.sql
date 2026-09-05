-- This script is intentionally idempotent. The integration suite runs it before
-- every fixture assertion so each PostgreSQL version begins from the same state.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'canary_runner') THEN
    CREATE ROLE canary_runner LOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT PASSWORD 'runner-password';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'canary_app') THEN
    CREATE ROLE canary_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'canary_table_owner') THEN
    CREATE ROLE canary_table_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT;
  END IF;
END
$$;

ALTER ROLE canary_runner LOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT PASSWORD 'runner-password';
ALTER ROLE canary_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT;
ALTER ROLE canary_table_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT;
GRANT canary_app TO canary_runner;

DROP SCHEMA IF EXISTS secure CASCADE;
DROP SCHEMA IF EXISTS read_leak CASCADE;
DROP SCHEMA IF EXISTS write_leak CASCADE;
DROP SCHEMA IF EXISTS owner_bypass CASCADE;
DROP SCHEMA IF EXISTS missing_privilege CASCADE;

CREATE SCHEMA secure AUTHORIZATION canary_table_owner;
CREATE TABLE secure.projects (
  id bigint PRIMARY KEY,
  tenant_id text NOT NULL,
  name text NOT NULL
);
ALTER TABLE secure.projects OWNER TO canary_table_owner;
ALTER TABLE secure.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE secure.projects FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON secure.projects
  FOR ALL TO canary_app
  USING (tenant_id = current_setting('request.jwt.claim.sub', true))
  WITH CHECK (tenant_id = current_setting('request.jwt.claim.sub', true));
GRANT USAGE ON SCHEMA secure TO canary_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON secure.projects TO canary_app;

CREATE SCHEMA read_leak AUTHORIZATION canary_table_owner;
CREATE TABLE read_leak.projects (
  id bigint PRIMARY KEY,
  tenant_id text NOT NULL,
  name text NOT NULL
);
ALTER TABLE read_leak.projects OWNER TO canary_table_owner;
ALTER TABLE read_leak.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE read_leak.projects FORCE ROW LEVEL SECURITY;
CREATE POLICY all_rows_visible ON read_leak.projects
  FOR SELECT TO canary_app
  USING (true);
CREATE POLICY fixture_insert ON read_leak.projects
  FOR INSERT TO canary_app
  WITH CHECK (true);
GRANT USAGE ON SCHEMA read_leak TO canary_app;
GRANT SELECT, INSERT ON read_leak.projects TO canary_app;

CREATE SCHEMA write_leak AUTHORIZATION canary_table_owner;
CREATE TABLE write_leak.projects (
  id bigint PRIMARY KEY,
  tenant_id text NOT NULL,
  name text NOT NULL
);
ALTER TABLE write_leak.projects OWNER TO canary_table_owner;
ALTER TABLE write_leak.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE write_leak.projects FORCE ROW LEVEL SECURITY;
CREATE POLICY insert_any_tenant ON write_leak.projects
  FOR INSERT TO canary_app
  WITH CHECK (true);
GRANT USAGE ON SCHEMA write_leak TO canary_app;
GRANT INSERT ON write_leak.projects TO canary_app;

CREATE SCHEMA owner_bypass AUTHORIZATION canary_app;
CREATE TABLE owner_bypass.projects (
  id bigint PRIMARY KEY,
  tenant_id text NOT NULL,
  name text NOT NULL
);
ALTER TABLE owner_bypass.projects OWNER TO canary_app;
ALTER TABLE owner_bypass.projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY deny_everything ON owner_bypass.projects
  FOR ALL TO canary_app
  USING (false)
  WITH CHECK (false);

CREATE SCHEMA missing_privilege AUTHORIZATION canary_table_owner;
CREATE TABLE missing_privilege.projects (
  id bigint PRIMARY KEY,
  tenant_id text NOT NULL,
  name text NOT NULL
);
ALTER TABLE missing_privilege.projects OWNER TO canary_table_owner;
ALTER TABLE missing_privilege.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE missing_privilege.projects FORCE ROW LEVEL SECURITY;
CREATE POLICY deny_everything ON missing_privilege.projects
  FOR ALL TO canary_app
  USING (false)
  WITH CHECK (false);
GRANT USAGE ON SCHEMA missing_privilege TO canary_app;
