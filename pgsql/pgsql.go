package pgsql

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ory/fosite"

	"github.com/initial-commit-hq/go-fosite-mongo"
)

// Store provides a PostgreSQL storage driver compatible with fosite's required
// storage interfaces.
type Store struct {
	DB      *DB
	timeout time.Duration
	Hasher  fosite.Hasher
	storage.Store
}

// Config defines PostgreSQL connection parameters.
type Config struct {
	Host         string `default:"localhost" envconfig:"CONNECTIONS_PGSQL_HOST"`
	Port         uint16 `default:"5432"      envconfig:"CONNECTIONS_PGSQL_PORT"`
	Database     string `default:""          envconfig:"CONNECTIONS_PGSQL_DATABASE"`
	Username     string `default:""          envconfig:"CONNECTIONS_PGSQL_USERNAME"`
	Password     string `default:""          envconfig:"CONNECTIONS_PGSQL_PASSWORD"`
	SSLMode      string `default:"disable"   envconfig:"CONNECTIONS_PGSQL_SSLMODE"`
	Timeout      uint   `default:"10"        envconfig:"CONNECTIONS_PGSQL_TIMEOUT"`
	PoolMinSize  int32  `default:"0"         envconfig:"CONNECTIONS_PGSQL_POOL_MIN_SIZE"`
	PoolMaxSize  int32  `default:"100"       envconfig:"CONNECTIONS_PGSQL_POOL_MAX_SIZE"`
	TokenTTL     uint32 `default:"0"         envconfig:"CONNECTIONS_PGSQL_TOKEN_TTL"`
}

// NewSession returns the context unchanged; PostgreSQL does not use mongo-style sessions.
func (s *Store) NewSession(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return ctx, func() {}, nil
}

// Close closes the connection pool when this store owns it.
func (s *Store) Close() {
	if s.DB != nil && s.DB.ownsPool && s.DB.Pool != nil {
		s.DB.Pool.Close()
	}
}

// Connect establishes a PostgreSQL connection pool.
func Connect(cfg *Config) (*pgxpool.Pool, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 1
	}
	if cfg.SSLMode == "" {
		cfg.SSLMode = "disable"
	}

	connURL := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.Username,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Database,
		cfg.SSLMode,
	)

	poolCfg, err := pgxpool.ParseConfig(connURL)
	if err != nil {
		return nil, err
	}

	if cfg.PoolMinSize > 0 {
		poolCfg.MinConns = cfg.PoolMinSize
	}
	if cfg.PoolMaxSize > 0 {
		poolCfg.MaxConns = cfg.PoolMaxSize
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(cfg.Timeout))
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, err
	}

	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	return pool, nil
}

// New creates a PostgreSQL-backed fosite store.
func New(cfg *Config, hash fosite.Hasher) (*Store, error) {
	pool, err := Connect(cfg)
	if err != nil {
		return nil, err
	}
	return newStore(pool, hash, true, cfg)
}

// NewWithPool creates a store using an existing connection pool.
func NewWithPool(pool *pgxpool.Pool, hash fosite.Hasher) (*Store, error) {
	if pool == nil {
		return nil, fmt.Errorf("pool cannot be nil")
	}
	return newStore(pool, hash, false, &Config{Timeout: 10})
}

func newStore(pool *pgxpool.Pool, hash fosite.Hasher, ownsPool bool, cfg *Config) (*Store, error) {
	db := &DB{Pool: pool, ownsPool: ownsPool}

	if hash == nil {
		hash = &fosite.BCrypt{Config: &fosite.Config{HashCost: 8}}
	}

	deniedJTIs := &DeniedJtiManager{
		DB:              db,
		BlacklistedJTIs: make(map[string]time.Time),
	}
	clients := &ClientManager{
		DB:         db,
		Hasher:     hash,
		DeniedJTIs: deniedJTIs,
	}
	users := &UserManager{
		DB:     db,
		Hasher: hash,
	}
	requests := &RequestManager{
		DB:      db,
		Clients: clients,
		Users:   users,
	}

	ctx := context.Background()
	if err := configureDatabases(ctx, clients, deniedJTIs, users, requests); err != nil {
		if ownsPool {
			pool.Close()
		}
		return nil, err
	}
	if cfg.TokenTTL > 0 {
		if err := configureExpiry(ctx, int(cfg.TokenTTL), requests); err != nil {
			if ownsPool {
				pool.Close()
			}
			return nil, err
		}
	}

	timeout := time.Second * 10
	if cfg.Timeout > 0 {
		timeout = time.Second * time.Duration(cfg.Timeout)
	}

	return &Store{
		DB:      db,
		timeout: timeout,
		Hasher:  hash,
		Store: storage.Store{
			ClientManager:    clients,
			DeniedJTIManager: deniedJTIs,
			RequestManager:   requests,
			UserManager:      users,
		},
	}, nil
}

func configureDatabases(ctx context.Context, cfgs ...storage.Configure) error {
	for _, cfg := range cfgs {
		if err := cfg.Configure(ctx); err != nil {
			return err
		}
	}
	return nil
}

func configureExpiry(ctx context.Context, ttl int, expires ...storage.Expire) error {
	for _, expire := range expires {
		if err := expire.ConfigureExpiryWithTTL(ctx, ttl); err != nil {
			return err
		}
	}
	return nil
}
