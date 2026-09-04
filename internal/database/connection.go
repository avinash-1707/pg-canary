// Package database owns the dedicated PostgreSQL connection boundary.
package database

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/avinash-1707/pg-canary/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrUnsupportedVersion = errors.New("PostgreSQL 15 or later is required")
	ErrReadOnlyTarget     = errors.New("target database is read-only")
)

// Config controls a single dedicated connection and its operation deadlines.
type Config struct {
	URL            string
	ConnectTimeout time.Duration
	QueryTimeout   time.Duration
}

// Connection is the one connection used for a pg-canary run.
type Connection struct {
	conn         *pgx.Conn
	queryTimeout time.Duration
	Metadata     domain.ServerMetadata
}

// Open connects, verifies a supported read-write PostgreSQL target, and
// returns only non-secret target metadata.
func Open(ctx context.Context, config Config) (*Connection, error) {
	if config.ConnectTimeout <= 0 {
		config.ConnectTimeout = 10 * time.Second
	}
	if config.QueryTimeout <= 0 {
		config.QueryTimeout = 10 * time.Second
	}
	connectContext, cancel := context.WithTimeout(ctx, config.ConnectTimeout)
	defer cancel()
	conn, err := pgx.Connect(connectContext, config.URL)
	if err != nil {
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	connection := &Connection{conn: conn, queryTimeout: config.QueryTimeout}
	if err := connection.verify(ctx); err != nil {
		_ = conn.Close(context.Background())
		return nil, err
	}
	return connection, nil
}

func (connection *Connection) verify(ctx context.Context) error {
	var versionText string
	if err := connection.QueryRow(ctx, "SHOW server_version_num").Scan(&versionText); err != nil {
		return fmt.Errorf("read PostgreSQL version: %w", err)
	}
	version, err := strconv.Atoi(versionText)
	if err != nil {
		return fmt.Errorf("parse PostgreSQL version: %w", err)
	}
	if version/10000 < 15 {
		return fmt.Errorf("%w (server version %s)", ErrUnsupportedVersion, versionText)
	}
	var readOnly string
	if err := connection.QueryRow(ctx, "SHOW transaction_read_only").Scan(&readOnly); err != nil {
		return fmt.Errorf("read target transaction mode: %w", err)
	}
	if readOnly == "on" {
		return ErrReadOnlyTarget
	}
	var versionString string
	if err := connection.QueryRow(ctx, "SHOW server_version").Scan(&versionString); err != nil {
		return fmt.Errorf("read PostgreSQL server metadata: %w", err)
	}
	connection.Metadata = domain.ServerMetadata{Product: "PostgreSQL", Version: versionString}
	return nil
}

// Exec executes one query under the configured query timeout.
func (connection *Connection) Exec(ctx context.Context, query string, arguments ...any) (pgconn.CommandTag, error) {
	queryContext, cancel := connection.queryContext(ctx)
	defer cancel()
	return connection.conn.Exec(queryContext, query, arguments...)
}

// QueryRow starts one query under the configured query timeout.
func (connection *Connection) QueryRow(ctx context.Context, query string, arguments ...any) pgx.Row {
	queryContext, cancel := connection.queryContext(ctx)
	return timeoutRow{row: connection.conn.QueryRow(queryContext, query, arguments...), cancel: cancel}
}

// Raw exposes the dedicated pgx connection to the transaction harness. Callers
// must apply their own context deadline before issuing multi-row queries.
func (connection *Connection) Raw() *pgx.Conn { return connection.conn }

// Close closes the dedicated connection.
func (connection *Connection) Close(ctx context.Context) error { return connection.conn.Close(ctx) }

func (connection *Connection) queryContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, connection.queryTimeout)
}

type timeoutRow struct {
	row    pgx.Row
	cancel context.CancelFunc
}

func (row timeoutRow) Scan(destinations ...any) error {
	defer row.cancel()
	return row.row.Scan(destinations...)
}
