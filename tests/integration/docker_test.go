//go:build integration

package integration

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const integrationEnvironment = "PG_CANARY_INTEGRATION"

//go:embed fixtures/reset.sql
var resetSQL string

type postgresTarget struct {
	service   string
	major     int
	adminURL  string
	runnerURL string
}

type postgresStack struct {
	composeFile string
	project     string
	targets     []postgresTarget
}

var fixtureStack *postgresStack

func TestMain(m *testing.M) {
	if os.Getenv(integrationEnvironment) != "1" {
		os.Exit(m.Run())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	stack, err := startPostgresStack(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start integration PostgreSQL stack:", err)
		os.Exit(1)
	}
	fixtureStack = stack

	code := m.Run()
	if err := stack.stop(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "stop integration PostgreSQL stack:", err)
		code = 1
	}
	os.Exit(code)
}

func TestPostgresFixturesStartAndResetDeterministically(t *testing.T) {
	if fixtureStack == nil {
		t.Skipf("set %s=1 to run Docker-backed integration tests", integrationEnvironment)
	}

	for _, target := range fixtureStack.targets {
		t.Run(fmt.Sprintf("postgres-%d", target.major), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			admin := connect(t, ctx, target.adminURL)
			defer admin.Close(ctx)

			reset(t, ctx, admin)
			assertServerMajor(t, ctx, admin, target.major)
			assertFixtureContract(t, ctx, admin)

			if _, err := admin.Exec(ctx, "CREATE TABLE secure.reset_probe (id integer PRIMARY KEY)"); err != nil {
				t.Fatalf("create transient fixture object: %v", err)
			}
			reset(t, ctx, admin)

			var exists bool
			if err := admin.QueryRow(ctx, "SELECT to_regclass('secure.reset_probe') IS NOT NULL").Scan(&exists); err != nil {
				t.Fatalf("check reset probe: %v", err)
			}
			if exists {
				t.Fatal("reset left a transient fixture object behind")
			}
			assertFixtureContract(t, ctx, admin)
			assertRunnerCanAssumeApplicationRole(t, ctx, target.runnerURL)
		})
	}
}

func startPostgresStack(ctx context.Context) (*postgresStack, error) {
	root := projectRoot()
	stack := &postgresStack{
		composeFile: filepath.Join(root, "tests", "integration", "fixtures", "docker-compose.yml"),
		project:     fmt.Sprintf("pg-canary-integration-%d", os.Getpid()),
	}

	if err := runDockerCompose(ctx, stack.composeFile, stack.project, "up", "--detach", "--wait"); err != nil {
		return nil, err
	}

	for _, config := range []struct {
		service string
		major   int
	}{
		{service: "postgres14", major: 14},
		{service: "postgres15", major: 15},
		{service: "postgres16", major: 16},
		{service: "postgres17", major: 17},
	} {
		address, err := publishedAddress(ctx, stack.composeFile, stack.project, config.service)
		if err != nil {
			_ = stack.stop(context.Background())
			return nil, fmt.Errorf("find %s port: %w", config.service, err)
		}
		stack.targets = append(stack.targets, postgresTarget{
			service:   config.service,
			major:     config.major,
			adminURL:  fmt.Sprintf("postgres://postgres:postgres@%s/pg_canary_test?sslmode=disable", address),
			runnerURL: fmt.Sprintf("postgres://canary_runner:runner-password@%s/pg_canary_test?sslmode=disable", address),
		})
	}

	return stack, nil
}

func (s *postgresStack) stop(ctx context.Context) error {
	return runDockerCompose(ctx, s.composeFile, s.project, "down", "--volumes", "--remove-orphans")
}

func reset(t *testing.T, ctx context.Context, conn *pgx.Conn) {
	t.Helper()
	results, err := conn.PgConn().Exec(ctx, resetSQL).ReadAll()
	if err != nil {
		t.Fatalf("reset fixtures: %v", err)
	}
	for _, result := range results {
		if result.Err != nil {
			t.Fatalf("reset fixtures: %v", result.Err)
		}
	}
}

func assertServerMajor(t *testing.T, ctx context.Context, conn *pgx.Conn, want int) {
	t.Helper()

	var versionNumText string
	if err := conn.QueryRow(ctx, "SHOW server_version_num").Scan(&versionNumText); err != nil {
		t.Fatalf("read server version: %v", err)
	}
	versionNum, err := strconv.Atoi(versionNumText)
	if err != nil {
		t.Fatalf("parse server version %q: %v", versionNumText, err)
	}
	if versionNum/10000 != want {
		t.Fatalf("PostgreSQL major version = %d, want %d (version number %d)", versionNum/10000, want, versionNum)
	}
}

func assertFixtureContract(t *testing.T, ctx context.Context, conn *pgx.Conn) {
	t.Helper()

	var canLogin, isSuperuser, bypassRLS, canSetRole bool
	err := conn.QueryRow(ctx, `
SELECT runner.rolcanlogin,
       runner.rolsuper,
       runner.rolbypassrls,
       pg_has_role('canary_runner', 'canary_app', 'member')
FROM pg_roles AS runner
WHERE runner.rolname = 'canary_runner'`).Scan(&canLogin, &isSuperuser, &bypassRLS, &canSetRole)
	if err != nil {
		t.Fatalf("read runner role: %v", err)
	}
	if !canLogin || isSuperuser || bypassRLS || !canSetRole {
		t.Fatalf("unexpected runner role contract: login=%t superuser=%t bypassrls=%t set-role=%t", canLogin, isSuperuser, bypassRLS, canSetRole)
	}

	for _, want := range []struct {
		schema string
		forced bool
		owner  string
	}{
		{schema: "secure", forced: true, owner: "canary_table_owner"},
		{schema: "read_leak", forced: true, owner: "canary_table_owner"},
		{schema: "write_leak", forced: true, owner: "canary_table_owner"},
		{schema: "owner_bypass", forced: false, owner: "canary_app"},
		{schema: "missing_privilege", forced: true, owner: "canary_table_owner"},
	} {
		var rlsEnabled, rlsForced bool
		var owner string
		err := conn.QueryRow(ctx, `
SELECT c.relrowsecurity, c.relforcerowsecurity, pg_get_userbyid(c.relowner)
FROM pg_class AS c
JOIN pg_namespace AS n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relname = 'projects'`, want.schema).Scan(&rlsEnabled, &rlsForced, &owner)
		if err != nil {
			t.Fatalf("read %s fixture metadata: %v", want.schema, err)
		}
		if !rlsEnabled || rlsForced != want.forced || owner != want.owner {
			t.Fatalf("unexpected %s fixture: rls=%t forced=%t owner=%q", want.schema, rlsEnabled, rlsForced, owner)
		}
	}

	var hasSelect bool
	if err := conn.QueryRow(ctx, "SELECT has_table_privilege('canary_app', 'missing_privilege.projects', 'SELECT')").Scan(&hasSelect); err != nil {
		t.Fatalf("check missing-privilege fixture grant: %v", err)
	}
	if hasSelect {
		t.Fatal("missing-privilege fixture unexpectedly grants SELECT to canary_app")
	}
}

func assertRunnerCanAssumeApplicationRole(t *testing.T, ctx context.Context, url string) {
	t.Helper()

	runner := connect(t, ctx, url)
	defer runner.Close(ctx)
	if _, err := runner.Exec(ctx, "SET ROLE canary_app"); err != nil {
		t.Fatalf("runner cannot assume application role: %v", err)
	}
	var currentRole string
	if err := runner.QueryRow(ctx, "SELECT current_user").Scan(&currentRole); err != nil {
		t.Fatalf("read effective role: %v", err)
	}
	if currentRole != "canary_app" {
		t.Fatalf("effective role = %q, want canary_app", currentRole)
	}
}

func connect(t *testing.T, ctx context.Context, url string) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect to fixture: %v", err)
	}
	return conn
}

func publishedAddress(ctx context.Context, composeFile, project, service string) (string, error) {
	output, err := dockerComposeOutput(ctx, composeFile, project, "port", service, "5432")
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(strings.Split(output, "\n")[0])
	_, port, err := net.SplitHostPort(line)
	if err != nil {
		return "", fmt.Errorf("parse published address %q: %w", line, err)
	}
	return net.JoinHostPort("127.0.0.1", port), nil
}

func runDockerCompose(ctx context.Context, composeFile, project string, args ...string) error {
	_, err := dockerComposeOutput(ctx, composeFile, project, args...)
	return err
}

func dockerComposeOutput(ctx context.Context, composeFile, project string, args ...string) (string, error) {
	base := []string{"compose", "--file", composeFile, "--project-name", project}
	command := exec.CommandContext(ctx, "docker", append(base, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return "", errors.New("docker is required; install Docker and start its daemon")
		}
		return "", fmt.Errorf("docker compose %s: %w\n%s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func projectRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("locate integration test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
