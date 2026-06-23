package pgsql

import (
	"encoding/json"
	"errors"
	"net/url"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/initial-commit-hq/go-fosite-mongo"
)

// isDuplicateKey reports whether err is a PostgreSQL unique-violation error.
func isDuplicateKey(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

// marshalJSON marshals v to JSON bytes for JSONB columns.
func marshalJSON(v interface{}) ([]byte, error) {
	if v == nil {
		return []byte("null"), nil
	}
	return json.Marshal(v)
}

// marshalStringSlice marshals a string slice for JSONB array columns.
func marshalStringSlice(s []string) ([]byte, error) {
	if s == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(s)
}

// unmarshalStringSlice unmarshals a JSONB array into a string slice.
func unmarshalStringSlice(data []byte, dest *[]string) error {
	if len(data) == 0 {
		*dest = nil
		return nil
	}
	return json.Unmarshal(data, dest)
}

// marshalURLValues marshals url.Values for JSONB storage.
func marshalURLValues(v url.Values) ([]byte, error) {
	if v == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(v)
}

// unmarshalURLValues unmarshals JSONB into url.Values.
func unmarshalURLValues(data []byte, dest *url.Values) error {
	if len(data) == 0 {
		*dest = make(url.Values)
		return nil
	}
	return json.Unmarshal(data, dest)
}

// jsonbContains builds a JSONB containment fragment for array membership filters.
func jsonbContainsSingle(value string) ([]byte, error) {
	return json.Marshal([]string{value})
}

// jsonbOverlap checks overlap between two JSONB arrays in SQL via && operator.
func jsonbOverlapSQL(column string, values []string) (string, []byte, bool) {
	if len(values) == 0 {
		return "", nil, false
	}
	data, err := marshalStringSlice(values)
	if err != nil {
		return "", nil, false
	}
	return column + " && $", data, true
}

// jsonbContainsAll checks that a JSONB array column contains all values.
func jsonbContainsAllSQL(column string, values []string) (string, []byte, bool) {
	if len(values) == 0 {
		return "", nil, false
	}
	data, err := marshalStringSlice(values)
	if err != nil {
		return "", nil, false
	}
	return column + " @> $", data, true
}

// jsonbContainsSingleSQL checks a single string value inside a JSONB array column.
func jsonbContainsSingleSQL(column string, value string) (string, []byte, bool) {
	if value == "" {
		return "", nil, false
	}
	data, err := jsonbContainsSingle(value)
	if err != nil {
		return "", nil, false
	}
	return column + " @> $", data, true
}

// duplicateKeyErr maps unique violations to storage.ErrResourceExists.
func duplicateKeyErr(err error) error {
	if isDuplicateKey(err) {
		return storage.ErrResourceExists
	}
	return err
}
