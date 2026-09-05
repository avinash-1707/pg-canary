// Package functions inspects SECURITY DEFINER functions without executing them.
package functions

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

type Definition struct {
	Name, Owner                     string
	SecurityDefiner, SafeSearchPath bool
}

func Inspect(ctx context.Context, conn *pgx.Conn, schema, name string) (Definition, error) {
	var d Definition
	var config []string
	d.Name = name
	err := conn.QueryRow(ctx, `SELECT pg_get_userbyid(p.proowner),p.prosecdef,COALESCE(p.proconfig,'{}') FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1 AND p.proname=$2`, schema, name).Scan(&d.Owner, &d.SecurityDefiner, &config)
	if err != nil {
		return d, fmt.Errorf("inspect function %s.%s: %w", schema, name, err)
	}
	for _, setting := range config {
		if strings.HasPrefix(setting, "search_path=") {
			path := strings.TrimPrefix(setting, "search_path=")
			d.SafeSearchPath = strings.Contains(path, "pg_catalog") && !strings.Contains(path, "public")
			break
		}
	}
	return d, nil
}
