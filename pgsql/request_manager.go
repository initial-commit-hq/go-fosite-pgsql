package pgsql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ory/fosite"

	"github.com/initial-commit-hq/go-fosite-mongo"
)

type IssuerPublicKeys struct {
	Issuer    string
	KeysBySub map[string]SubjectPublicKeys
}

type SubjectPublicKeys struct {
	Subject string
	Keys    map[string]PublicKeyScopes
}

type PublicKeyScopes struct {
	Key    *jose.JSONWebKey
	Scopes []string
}

// RequestManager manages OAuth2 request session storage in PostgreSQL.
type RequestManager struct {
	DB *DB

	Clients storage.ClientStore
	Users   storage.UserStorer

	IssuerPublicKeys map[string]IssuerPublicKeys

	clientsMutex          sync.RWMutex
	authorizeCodesMutex   sync.RWMutex
	idSessionsMutex       sync.RWMutex
	accessTokensMutex     sync.RWMutex
	refreshTokensMutex    sync.RWMutex
	pkcesMutex            sync.RWMutex
	usersMutex            sync.RWMutex
	issuerPublicKeysMutex sync.RWMutex
}

const requestColumns = `id, created_at, updated_at, requested_at, signature, client_id, user_id,
scopes, granted_scopes, requested_audience, granted_audience, form_data, active, session_data`

var requestEntityTables = []string{
	storage.EntityAccessTokens,
	storage.EntityAuthorizationCodes,
	storage.EntityOpenIDSessions,
	storage.EntityPKCESessions,
	storage.EntityRefreshTokens,
}

// Configure creates indexes for all request session tables.
func (r *RequestManager) Configure(ctx context.Context) error {
	for _, entityName := range requestEntityTables {
		table := r.DB.Table(entityName)
		indexPrefix := strings.TrimPrefix(entityName, storage.CollectionPrefix)

		if _, err := r.DB.Pool.Exec(ctx, fmt.Sprintf(
			"CREATE UNIQUE INDEX IF NOT EXISTS %s_%s ON %s (id)",
			IdxSessionID, indexPrefix, table,
		)); err != nil {
			return err
		}

		if _, err := r.DB.Pool.Exec(ctx, fmt.Sprintf(
			"CREATE INDEX IF NOT EXISTS %s_%s ON %s (client_id, user_id)",
			IdxCompoundRequester, indexPrefix, table,
		)); err != nil {
			return err
		}

		if entityName == storage.EntityAccessTokens {
			if _, err := r.DB.Pool.Exec(ctx, fmt.Sprintf(
				"CREATE INDEX IF NOT EXISTS %s_%s ON %s (signature)",
				IdxSignatureID+"Hashed", indexPrefix, table,
			)); err != nil {
				return err
			}
		} else {
			if _, err := r.DB.Pool.Exec(ctx, fmt.Sprintf(
				"CREATE UNIQUE INDEX IF NOT EXISTS %s_%s ON %s (signature)",
				IdxSignatureID, indexPrefix, table,
			)); err != nil {
				return err
			}
		}
	}
	return nil
}

// ConfigureExpiryWithTTL creates btree indexes on requested_at for expiry queries.
func (r *RequestManager) ConfigureExpiryWithTTL(ctx context.Context, ttl int) error {
	for _, entityName := range requestEntityTables {
		table := r.DB.Table(entityName)
		indexPrefix := strings.TrimPrefix(entityName, storage.CollectionPrefix)
		_, err := r.DB.Pool.Exec(ctx, fmt.Sprintf(
			"CREATE INDEX IF NOT EXISTS %s_%s ON %s (requested_at)",
			IdxExpiry, indexPrefix, table,
		))
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *RequestManager) scanRequest(row pgx.Row) (storage.Request, error) {
	var req storage.Request
	var scopes, grantedScopes, requestedAudience, grantedAudience, formData []byte

	err := row.Scan(
		&req.ID,
		&req.CreateTime,
		&req.UpdateTime,
		&req.RequestedAt,
		&req.Signature,
		&req.ClientID,
		&req.UserID,
		&scopes,
		&grantedScopes,
		&requestedAudience,
		&grantedAudience,
		&formData,
		&req.Active,
		&req.Session,
	)
	if err != nil {
		return req, err
	}

	if err = json.Unmarshal(scopes, &req.RequestedScope); err != nil {
		return req, err
	}
	if err = json.Unmarshal(grantedScopes, &req.GrantedScope); err != nil {
		return req, err
	}
	if err = json.Unmarshal(requestedAudience, &req.RequestedAudience); err != nil {
		return req, err
	}
	if err = json.Unmarshal(grantedAudience, &req.GrantedAudience); err != nil {
		return req, err
	}
	if err = unmarshalURLValues(formData, &req.Form); err != nil {
		return req, err
	}
	return req, nil
}

func (r *RequestManager) requestValues(req storage.Request) ([]interface{}, error) {
	scopes, err := marshalStringSlice(req.RequestedScope)
	if err != nil {
		return nil, err
	}
	grantedScopes, err := marshalStringSlice(req.GrantedScope)
	if err != nil {
		return nil, err
	}
	requestedAudience, err := marshalStringSlice(req.RequestedAudience)
	if err != nil {
		return nil, err
	}
	grantedAudience, err := marshalStringSlice(req.GrantedAudience)
	if err != nil {
		return nil, err
	}
	formData, err := marshalURLValues(req.Form)
	if err != nil {
		return nil, err
	}

	return []interface{}{
		req.ID,
		req.CreateTime,
		req.UpdateTime,
		req.RequestedAt,
		req.Signature,
		req.ClientID,
		req.UserID,
		scopes,
		grantedScopes,
		requestedAudience,
		grantedAudience,
		formData,
		req.Active,
		req.Session,
	}, nil
}

func (r *RequestManager) getConcrete(ctx context.Context, entityName, requestID string) (storage.Request, error) {
	table := r.DB.Table(entityName)
	query := fmt.Sprintf("SELECT %s FROM %s WHERE id = $1", requestColumns, table)

	row := r.DB.Pool.QueryRow(ctx, query, requestID)
	req, err := r.scanRequest(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.Request{}, fosite.ErrNotFound
		}
		return storage.Request{}, err
	}
	return req, nil
}

// List returns request resources matching the filter.
func (r *RequestManager) List(ctx context.Context, entityName string, filter storage.ListRequestsRequest) ([]storage.Request, error) {
	table := r.DB.Table(entityName)
	var (
		conditions []string
		args       []interface{}
		argNum     = 1
	)

	if filter.ClientID != "" {
		conditions = append(conditions, fmt.Sprintf("client_id = $%d", argNum))
		args = append(args, filter.ClientID)
		argNum++
	}
	if filter.UserID != "" {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argNum))
		args = append(args, filter.UserID)
		argNum++
	}
	if len(filter.ScopesIntersection) > 0 {
		cond, data, ok := jsonbContainsAllSQL("scopes", filter.ScopesIntersection)
		if ok {
			conditions = append(conditions, fmt.Sprintf(cond+"::jsonb", argNum))
			args = append(args, data)
			argNum++
		}
	}
	if len(filter.ScopesUnion) > 0 {
		cond, data, ok := jsonbOverlapSQL("scopes", filter.ScopesUnion)
		if ok {
			conditions = append(conditions, fmt.Sprintf(cond+"::jsonb", argNum))
			args = append(args, data)
			argNum++
		}
	}
	if len(filter.GrantedScopesIntersection) > 0 {
		cond, data, ok := jsonbContainsAllSQL("granted_scopes", filter.GrantedScopesIntersection)
		if ok {
			conditions = append(conditions, fmt.Sprintf(cond+"::jsonb", argNum))
			args = append(args, data)
			argNum++
		}
	}
	if len(filter.GrantedScopesUnion) > 0 {
		cond, data, ok := jsonbOverlapSQL("granted_scopes", filter.GrantedScopesUnion)
		if ok {
			conditions = append(conditions, fmt.Sprintf(cond+"::jsonb", argNum))
			args = append(args, data)
			argNum++
		}
	}

	query := fmt.Sprintf("SELECT %s FROM %s", requestColumns, table)
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	rows, err := r.DB.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var requests []storage.Request
	for rows.Next() {
		req, err := r.scanRequest(rows)
		if err != nil {
			return nil, err
		}
		requests = append(requests, req)
	}
	return requests, rows.Err()
}

// Create creates a new Request resource.
func (r *RequestManager) Create(ctx context.Context, entityName string, request storage.Request) (storage.Request, error) {
	if request.ID == "" {
		request.ID = uuid.NewString()
	}
	if request.CreateTime == 0 {
		request.CreateTime = time.Now().Unix()
	}
	if request.RequestedAt.IsZero() {
		request.RequestedAt = time.Now()
	}

	values, err := r.requestValues(request)
	if err != nil {
		return storage.Request{}, err
	}

	table := r.DB.Table(entityName)
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
		table, requestColumns)

	_, err = r.DB.Pool.Exec(ctx, query, values...)
	if err != nil {
		return storage.Request{}, duplicateKeyErr(err)
	}
	return request, nil
}

// Get returns the specified Request resource.
func (r *RequestManager) Get(ctx context.Context, entityName, requestID string) (storage.Request, error) {
	return r.getConcrete(ctx, entityName, requestID)
}

// GetBySignature returns a Request resource by signature.
func (r *RequestManager) GetBySignature(ctx context.Context, entityName, signature string) (storage.Request, error) {
	table := r.DB.Table(entityName)
	query := fmt.Sprintf("SELECT %s FROM %s WHERE signature = $1", requestColumns, table)

	row := r.DB.Pool.QueryRow(ctx, query, signature)
	req, err := r.scanRequest(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.Request{}, fosite.ErrNotFound
		}
		return storage.Request{}, err
	}
	return req, nil
}

// Update updates a Request resource.
func (r *RequestManager) Update(ctx context.Context, entityName, requestID string, updatedRequest storage.Request) (storage.Request, error) {
	updatedRequest.ID = requestID
	updatedRequest.UpdateTime = time.Now().Unix()

	values, err := r.requestValues(updatedRequest)
	if err != nil {
		return storage.Request{}, err
	}

	table := r.DB.Table(entityName)
	query := fmt.Sprintf(
		"UPDATE %s SET created_at=$2, updated_at=$3, requested_at=$4, signature=$5, client_id=$6, "+
			"user_id=$7, scopes=$8, granted_scopes=$9, requested_audience=$10, granted_audience=$11, "+
			"form_data=$12, active=$13, session_data=$14 WHERE id=$1",
		table,
	)

	cmd, err := r.DB.Pool.Exec(ctx, query, values...)
	if err != nil {
		return storage.Request{}, duplicateKeyErr(err)
	}
	if cmd.RowsAffected() == 0 {
		return storage.Request{}, fosite.ErrNotFound
	}
	return updatedRequest, nil
}

// Delete deletes a Request resource.
func (r *RequestManager) Delete(ctx context.Context, entityName, requestID string) error {
	table := r.DB.Table(entityName)
	cmd, err := r.DB.Pool.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE id = $1", table), requestID)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return fosite.ErrNotFound
	}
	return nil
}

// DeleteBySignature deletes a Request resource by signature.
func (r *RequestManager) DeleteBySignature(ctx context.Context, entityName, signature string) error {
	table := r.DB.Table(entityName)
	cmd, err := r.DB.Pool.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE signature = $1", table), signature)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return fosite.ErrNotFound
	}
	return nil
}

// RevokeRefreshToken deletes the refresh token session.
func (r *RequestManager) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return r.revokeToken(ctx, storage.EntityRefreshTokens, requestID)
}

// RevokeAccessToken deletes the access token session.
func (r *RequestManager) RevokeAccessToken(ctx context.Context, requestID string) error {
	return r.revokeToken(ctx, storage.EntityAccessTokens, requestID)
}

// RevokeRefreshTokenMaybeGracePeriod revokes a refresh token without grace period support.
func (r *RequestManager) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, signature string) error {
	return r.RevokeRefreshToken(ctx, requestID)
}

// GetPublicKey returns a public key for JWT assertion validation.
func (r *RequestManager) GetPublicKey(ctx context.Context, issuer, subject, keyID string) (*jose.JSONWebKey, error) {
	r.issuerPublicKeysMutex.RLock()
	defer r.issuerPublicKeysMutex.RUnlock()

	if issuerKeys, ok := r.IssuerPublicKeys[issuer]; ok {
		if subKeys, ok := issuerKeys.KeysBySub[subject]; ok {
			if keyScopes, ok := subKeys.Keys[keyID]; ok {
				return keyScopes.Key, nil
			}
		}
	}
	return nil, fosite.ErrNotFound
}

// GetPublicKeys returns all public keys for an issuer subject.
func (r *RequestManager) GetPublicKeys(ctx context.Context, issuer, subject string) (*jose.JSONWebKeySet, error) {
	r.issuerPublicKeysMutex.RLock()
	defer r.issuerPublicKeysMutex.RUnlock()

	if issuerKeys, ok := r.IssuerPublicKeys[issuer]; ok {
		if subKeys, ok := issuerKeys.KeysBySub[subject]; ok {
			if len(subKeys.Keys) == 0 {
				return nil, fosite.ErrNotFound
			}
			keys := make([]jose.JSONWebKey, 0, len(subKeys.Keys))
			for _, keyScopes := range subKeys.Keys {
				keys = append(keys, *keyScopes.Key)
			}
			return &jose.JSONWebKeySet{Keys: keys}, nil
		}
	}
	return nil, fosite.ErrNotFound
}

// GetPublicKeyScopes returns scopes associated with a public key.
func (r *RequestManager) GetPublicKeyScopes(ctx context.Context, issuer, subject, keyID string) ([]string, error) {
	r.issuerPublicKeysMutex.RLock()
	defer r.issuerPublicKeysMutex.RUnlock()

	if issuerKeys, ok := r.IssuerPublicKeys[issuer]; ok {
		if subKeys, ok := issuerKeys.KeysBySub[subject]; ok {
			if keyScopes, ok := subKeys.Keys[keyID]; ok {
				return keyScopes.Scopes, nil
			}
		}
	}
	return nil, fosite.ErrNotFound
}

func (r *RequestManager) revokeToken(ctx context.Context, entityName, requestID string) error {
	err := r.Delete(ctx, entityName, requestID)
	if err != nil && !errors.Is(err, fosite.ErrNotFound) {
		return err
	}
	return nil
}

// RotateRefreshToken rotates the refresh token (no-op).
func (r *RequestManager) RotateRefreshToken(ctx context.Context, entityName, requestID string) error {
	return nil
}

// toRequest transforms a fosite.Requester to storage.Request.
func toRequest(signature string, req fosite.Requester) storage.Request {
	session, _ := json.Marshal(req.GetSession())
	return storage.Request{
		ID:                req.GetID(),
		RequestedAt:       req.GetRequestedAt(),
		Signature:         signature,
		ClientID:          req.GetClient().GetID(),
		UserID:            req.GetSession().GetSubject(),
		RequestedScope:    req.GetRequestedScopes(),
		GrantedScope:      req.GetGrantedScopes(),
		RequestedAudience: req.GetRequestedAudience(),
		GrantedAudience:   req.GetGrantedAudience(),
		Form:              req.GetRequestForm(),
		Active:            true,
		Session:           session,
	}
}
