# go-fosite-pgsql

PostgreSQL storage backend for [ORY Fosite](https://github.com/ory/fosite), companion to [go-fosite-mongo](https://github.com/initial-commit-hq/go-fosite-mongo).

## Usage

```go
import (
    fPgSQL "github.com/initial-commit-hq/go-fosite-pgsql/pgsql"
)

store, err := fPgSQL.New(&fPgSQL.Config{
    Host:     "localhost",
    Port:     5432,
    Database: "sts",
    Username: "sts",
    Password: "secret",
}, nil)
```

Or reuse an existing `pgxpool.Pool`:

```go
store, err := fPgSQL.NewWithPool(pool, nil)
```

## Tables

OAuth2 entities are stored in `oauth2_*` tables (see STS migration `0046_oauth2.up.sql`).
