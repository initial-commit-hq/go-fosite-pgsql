package pgsql

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/initial-commit-hq/go-fosite-mongo"
)

// DB wraps a PostgreSQL connection pool.
type DB struct {
	Pool     *pgxpool.Pool
	ownsPool bool
}

// Table maps a storage entity constant to its PostgreSQL table name.
// Entity constants already match collection/table names (e.g. oauth2_client).
func (d *DB) Table(entityName string) string {
	switch entityName {
	case storage.EntityClients,
		storage.EntityUsers,
		storage.EntityAccessTokens,
		storage.EntityRefreshTokens,
		storage.EntityAuthorizationCodes,
		storage.EntityPKCESessions,
		storage.EntityOpenIDSessions,
		storage.EntityJtiDenylist:
		return entityName
	default:
		return entityName
	}
}
