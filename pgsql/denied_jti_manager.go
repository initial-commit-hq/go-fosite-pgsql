package pgsql

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ory/fosite"

	"github.com/initial-commit-hq/go-fosite-mongo"
)

// DeniedJtiManager provides PostgreSQL-backed JTI deny list storage.
type DeniedJtiManager struct {
	DB *DB

	BlacklistedJTIs        map[string]time.Time
	AccessTokenRequestIDs  map[string]string
	RefreshTokenRequestIDs map[string]string

	blacklistedJTIsMutex        sync.RWMutex
	accessTokenRequestIDsMutex  sync.RWMutex
	refreshTokenRequestIDsMutex sync.RWMutex
}

// Configure creates indexes for the oauth2_jti_deny_list table.
func (d *DeniedJtiManager) Configure(ctx context.Context) error {
	table := d.DB.Table(storage.EntityJtiDenylist)
	_, err := d.DB.Pool.Exec(ctx, fmt.Sprintf(
		"CREATE UNIQUE INDEX IF NOT EXISTS %s ON %s (signature)",
		IdxSignatureID, table,
	))
	if err != nil {
		return err
	}
	_, err = d.DB.Pool.Exec(ctx, fmt.Sprintf(
		"CREATE INDEX IF NOT EXISTS %s ON %s (exp)",
		IdxExpires, table,
	))
	return err
}

func (d *DeniedJtiManager) getConcrete(ctx context.Context, signature string) (storage.DeniedJTI, error) {
	table := d.DB.Table(storage.EntityJtiDenylist)
	row := d.DB.Pool.QueryRow(ctx,
		fmt.Sprintf("SELECT signature, exp FROM %s WHERE signature = $1", table),
		signature,
	)

	var denied storage.DeniedJTI
	err := row.Scan(&denied.Signature, &denied.Expiry)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.DeniedJTI{}, fosite.ErrNotFound
		}
		return storage.DeniedJTI{}, err
	}
	return denied, nil
}

// Create inserts a denied JTI record.
func (d *DeniedJtiManager) Create(ctx context.Context, deniedJTI storage.DeniedJTI) (storage.DeniedJTI, error) {
	table := d.DB.Table(storage.EntityJtiDenylist)
	_, err := d.DB.Pool.Exec(ctx,
		fmt.Sprintf("INSERT INTO %s (signature, exp) VALUES ($1, $2)", table),
		deniedJTI.Signature, deniedJTI.Expiry,
	)
	if err != nil {
		return storage.DeniedJTI{}, duplicateKeyErr(err)
	}
	return deniedJTI, nil
}

// Get returns a denied JTI by JTI string.
func (d *DeniedJtiManager) Get(ctx context.Context, jti string) (storage.DeniedJTI, error) {
	return d.getConcrete(ctx, storage.SignatureFromJTI(jti))
}

// Delete removes a denied JTI by JTI string.
func (d *DeniedJtiManager) Delete(ctx context.Context, jti string) error {
	table := d.DB.Table(storage.EntityJtiDenylist)
	cmd, err := d.DB.Pool.Exec(ctx,
		fmt.Sprintf("DELETE FROM %s WHERE signature = $1", table),
		storage.SignatureFromJTI(jti),
	)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return fosite.ErrNotFound
	}
	return nil
}

// DeleteBefore removes expired JTIs before the given time.
func (d *DeniedJtiManager) DeleteBefore(ctx context.Context, expBefore int64) error {
	table := d.DB.Table(storage.EntityJtiDenylist)
	cmd, err := d.DB.Pool.Exec(ctx,
		fmt.Sprintf("DELETE FROM %s WHERE exp < $1", table),
		expBefore,
	)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return fosite.ErrNotFound
	}
	return nil
}

// ClientAssertionJWTValid checks in-memory blacklisted JTIs.
func (d *DeniedJtiManager) ClientAssertionJWTValid(_ context.Context, jti string) error {
	d.blacklistedJTIsMutex.RLock()
	defer d.blacklistedJTIsMutex.RUnlock()

	if exp, exists := d.BlacklistedJTIs[jti]; exists && exp.After(time.Now()) {
		return fosite.ErrJTIKnown
	}
	return nil
}

// SetClientAssertionJWT marks a JTI as known in memory.
func (d *DeniedJtiManager) SetClientAssertionJWT(_ context.Context, jti string, exp time.Time) error {
	d.blacklistedJTIsMutex.Lock()
	defer d.blacklistedJTIsMutex.Unlock()

	for j, e := range d.BlacklistedJTIs {
		if e.Before(time.Now()) {
			delete(d.BlacklistedJTIs, j)
		}
	}

	if _, exists := d.BlacklistedJTIs[jti]; exists {
		return fosite.ErrJTIKnown
	}
	d.BlacklistedJTIs[jti] = exp
	return nil
}
