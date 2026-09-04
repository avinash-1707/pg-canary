// Package catalog reads PostgreSQL authorization metadata into typed findings.
package catalog

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

type Table struct {
	Schema      string
	Name        string
	Owner       string
	RLSEnabled  bool
	RLSForced   bool
	Columns     []Column
	PrimaryKey  []string
	ForeignKeys []ForeignKey
	Triggers    []string
	Rules       []string
	Grants      []Grant
	Policies    []Policy
}
type Column struct {
	Name, DataType, Default string
	NotNull                 bool
}
type ForeignKey struct{ Name, Definition string }
type Grant struct{ Grantee, Privilege string }
type Policy struct {
	Name, Command    string
	Roles            []string
	Using, WithCheck string
	Permissive       bool
}
type Role struct {
	Name                           string
	Superuser, BypassRLS, CanLogin bool
}
type Membership struct{ Member, Role string }
type Inspector struct{ conn *pgx.Conn }

func New(conn *pgx.Conn) Inspector { return Inspector{conn: conn} }

func (i Inspector) Table(ctx context.Context, schema, name string) (Table, error) {
	t := Table{Schema: schema, Name: name}
	err := i.conn.QueryRow(ctx, `SELECT pg_get_userbyid(c.relowner),c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname=$2 AND c.relkind IN ('r','p','f')`, schema, name).Scan(&t.Owner, &t.RLSEnabled, &t.RLSForced)
	if err != nil {
		return Table{}, fmt.Errorf("table %s.%s: %w", schema, name, err)
	}
	rows, err := i.conn.Query(ctx, `SELECT a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod),a.attnotnull,COALESCE(pg_get_expr(ad.adbin,ad.adrelid),'') FROM pg_attribute a LEFT JOIN pg_attrdef ad ON ad.adrelid=a.attrelid AND ad.adnum=a.attnum JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname=$2 AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum`, schema, name)
	if err != nil {
		return Table{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var c Column
		if err := rows.Scan(&c.Name, &c.DataType, &c.NotNull, &c.Default); err != nil {
			return Table{}, err
		}
		t.Columns = append(t.Columns, c)
	}
	if err := rows.Err(); err != nil {
		return Table{}, err
	}
	rows, err = i.conn.Query(ctx, `SELECT a.attname FROM pg_index x JOIN pg_class c ON c.oid=x.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace JOIN unnest(x.indkey) WITH ORDINALITY k(attnum,ord) ON true JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=k.attnum WHERE n.nspname=$1 AND c.relname=$2 AND x.indisprimary ORDER BY k.ord`, schema, name)
	if err != nil {
		return Table{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return Table{}, err
		}
		t.PrimaryKey = append(t.PrimaryKey, n)
	}
	if err := rows.Err(); err != nil {
		return Table{}, err
	}
	if err := i.listPolicies(ctx, &t); err != nil {
		return Table{}, err
	}
	if err := i.listGrants(ctx, &t); err != nil {
		return Table{}, err
	}
	if err := i.listConstraints(ctx, &t); err != nil {
		return Table{}, err
	}
	if err := i.listEffects(ctx, &t); err != nil {
		return Table{}, err
	}
	return t, nil
}
func (i Inspector) listPolicies(ctx context.Context, t *Table) error {
	rows, e := i.conn.Query(ctx, `SELECT policyname,cmd,roles,COALESCE(qual,''),COALESCE(with_check,''),permissive FROM pg_policies WHERE schemaname=$1 AND tablename=$2 ORDER BY policyname`, t.Schema, t.Name)
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var p Policy
		var permissive string
		if e := rows.Scan(&p.Name, &p.Command, &p.Roles, &p.Using, &p.WithCheck, &permissive); e != nil {
			return e
		}
		p.Permissive = permissive == "PERMISSIVE"
		t.Policies = append(t.Policies, p)
	}
	return rows.Err()
}
func (i Inspector) listGrants(ctx context.Context, t *Table) error {
	rows, e := i.conn.Query(ctx, `SELECT grantee,privilege_type FROM information_schema.role_table_grants WHERE table_schema=$1 AND table_name=$2 ORDER BY grantee,privilege_type`, t.Schema, t.Name)
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var g Grant
		if e := rows.Scan(&g.Grantee, &g.Privilege); e != nil {
			return e
		}
		t.Grants = append(t.Grants, g)
	}
	return rows.Err()
}
func (i Inspector) listConstraints(ctx context.Context, t *Table) error {
	rows, e := i.conn.Query(ctx, `SELECT conname,pg_get_constraintdef(con.oid) FROM pg_constraint con JOIN pg_class c ON c.oid=con.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname=$2 AND con.contype='f' ORDER BY conname`, t.Schema, t.Name)
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var f ForeignKey
		if e := rows.Scan(&f.Name, &f.Definition); e != nil {
			return e
		}
		t.ForeignKeys = append(t.ForeignKeys, f)
	}
	return rows.Err()
}
func (i Inspector) listEffects(ctx context.Context, t *Table) error {
	rows, e := i.conn.Query(ctx, `SELECT tgname FROM pg_trigger tg JOIN pg_class c ON c.oid=tg.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname=$2 AND NOT tgisinternal ORDER BY tgname`, t.Schema, t.Name)
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if e := rows.Scan(&n); e != nil {
			return e
		}
		t.Triggers = append(t.Triggers, n)
	}
	if e = rows.Err(); e != nil {
		return e
	}
	rows, e = i.conn.Query(ctx, `SELECT rulename FROM pg_rules WHERE schemaname=$1 AND tablename=$2 ORDER BY rulename`, t.Schema, t.Name)
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if e := rows.Scan(&n); e != nil {
			return e
		}
		t.Rules = append(t.Rules, n)
	}
	return rows.Err()
}
func (i Inspector) Role(ctx context.Context, name string) (Role, error) {
	var r Role
	r.Name = name
	e := i.conn.QueryRow(ctx, `SELECT rolsuper,rolbypassrls,rolcanlogin FROM pg_roles WHERE rolname=$1`, name).Scan(&r.Superuser, &r.BypassRLS, &r.CanLogin)
	return r, e
}
func (i Inspector) Memberships(ctx context.Context, member string) ([]Membership, error) {
	rows, e := i.conn.Query(ctx, `SELECT member.rolname,role.rolname FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member JOIN pg_roles role ON role.oid=m.roleid WHERE member.rolname=$1 ORDER BY role.rolname`, member)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var result []Membership
	for rows.Next() {
		var m Membership
		if e := rows.Scan(&m.Member, &m.Role); e != nil {
			return nil, e
		}
		result = append(result, m)
	}
	return result, rows.Err()
}
