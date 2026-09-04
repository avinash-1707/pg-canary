// Package sqlsafe constructs validated, parameterized PostgreSQL statements.
package sqlsafe

import (
	"fmt"
	"strings"
	"unicode"
)

type Statement struct {
	SQL, Template string
	Args          []any
}

func Identifier(value string) (string, error) {
	if value == "" || len(value) > 63 {
		return "", fmt.Errorf("invalid identifier %q", value)
	}
	for n, r := range value {
		if (n == 0 && r != '_' && !unicode.IsLower(r)) || (n > 0 && r != '_' && !unicode.IsLower(r) && !unicode.IsDigit(r)) {
			return "", fmt.Errorf("invalid identifier %q", value)
		}
	}
	return `"` + value + `"`, nil
}
func Qualified(schema, table string) (string, error) {
	s, e := Identifier(schema)
	if e != nil {
		return "", e
	}
	t, e := Identifier(table)
	if e != nil {
		return "", e
	}
	return s + "." + t, nil
}
func Select(schema, table string, keys []string, values map[string]any) (Statement, error) {
	q, e := Qualified(schema, table)
	if e != nil {
		return Statement{}, e
	}
	where, args, e := predicate(keys, values)
	if e != nil {
		return Statement{}, e
	}
	sql := "SELECT * FROM " + q + " WHERE " + where
	return Statement{SQL: sql, Template: sql, Args: args}, nil
}
func Delete(schema, table string, keys []string, values map[string]any) (Statement, error) {
	q, e := Qualified(schema, table)
	if e != nil {
		return Statement{}, e
	}
	where, args, e := predicate(keys, values)
	if e != nil {
		return Statement{}, e
	}
	sql := "DELETE FROM " + q + " WHERE " + where
	return Statement{SQL: sql, Template: sql, Args: args}, nil
}
func Insert(schema, table string, values map[string]any, columns []string) (Statement, error) {
	q, e := Qualified(schema, table)
	if e != nil {
		return Statement{}, e
	}
	if len(columns) == 0 {
		return Statement{}, fmt.Errorf("insert requires columns")
	}
	names := make([]string, len(columns))
	marks := make([]string, len(columns))
	args := make([]any, len(columns))
	for n, c := range columns {
		names[n], e = Identifier(c)
		if e != nil {
			return Statement{}, e
		}
		v, ok := values[c]
		if !ok {
			return Statement{}, fmt.Errorf("missing value for %s", c)
		}
		args[n] = v
		marks[n] = fmt.Sprintf("$%d", n+1)
	}
	sql := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", q, strings.Join(names, ","), strings.Join(marks, ","))
	return Statement{SQL: sql, Template: sql, Args: args}, nil
}
func predicate(keys []string, values map[string]any) (string, []any, error) {
	if len(keys) == 0 {
		return "", nil, fmt.Errorf("primary key required")
	}
	parts := make([]string, len(keys))
	args := make([]any, len(keys))
	for n, k := range keys {
		quoted, e := Identifier(k)
		if e != nil {
			return "", nil, e
		}
		v, ok := values[k]
		if !ok {
			return "", nil, fmt.Errorf("missing primary-key value for %s", k)
		}
		parts[n] = fmt.Sprintf("%s = $%d", quoted, n+1)
		args[n] = v
	}
	return strings.Join(parts, " AND "), args, nil
}
