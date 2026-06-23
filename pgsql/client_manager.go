package pgsql

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ory/fosite"

	"github.com/initial-commit-hq/go-fosite-mongo"
)

// ClientManager provides a PostgreSQL storage implementation for Clients.
type ClientManager struct {
	DB     *DB
	Hasher fosite.Hasher

	DeniedJTIs storage.DeniedJTIStore
}

const clientColumns = `id, created_at, updated_at, allowed_audiences, allowed_regions,
allowed_tenant_access, grant_types, response_types, scopes, public, disabled,
name, secret, redirect_uris, owner, policy_uri, terms_of_service_uri, client_uri,
logo_uri, contacts, published, provider`

// Configure creates indexes for the oauth2_client table.
func (c *ClientManager) Configure(ctx context.Context) error {
	table := c.DB.Table(storage.EntityClients)
	_, err := c.DB.Pool.Exec(ctx, fmt.Sprintf(
		"CREATE UNIQUE INDEX IF NOT EXISTS %s ON %s (id)",
		IdxClientID, table,
	))
	return err
}

func (c *ClientManager) scanClient(row pgx.Row) (storage.Client, error) {
	var client storage.Client
	var allowedAudiences, allowedRegions, allowedTenantAccess, grantTypes, responseTypes, scopes, redirectURIs, contacts []byte

	err := row.Scan(
		&client.ID,
		&client.CreateTime,
		&client.UpdateTime,
		&allowedAudiences,
		&allowedRegions,
		&allowedTenantAccess,
		&grantTypes,
		&responseTypes,
		&scopes,
		&client.Public,
		&client.Disabled,
		&client.Name,
		&client.Secret,
		&redirectURIs,
		&client.Owner,
		&client.PolicyURI,
		&client.TermsOfServiceURI,
		&client.ClientURI,
		&client.LogoURI,
		&contacts,
		&client.Published,
		&client.Provider,
	)
	if err != nil {
		return client, err
	}

	if err = unmarshalStringSlice(allowedAudiences, &client.AllowedAudiences); err != nil {
		return client, err
	}
	if err = unmarshalStringSlice(allowedRegions, &client.AllowedRegions); err != nil {
		return client, err
	}
	if err = unmarshalStringSlice(allowedTenantAccess, &client.AllowedTenantAccess); err != nil {
		return client, err
	}
	if err = unmarshalStringSlice(grantTypes, &client.GrantTypes); err != nil {
		return client, err
	}
	if err = unmarshalStringSlice(responseTypes, &client.ResponseTypes); err != nil {
		return client, err
	}
	if err = unmarshalStringSlice(scopes, &client.Scopes); err != nil {
		return client, err
	}
	if err = unmarshalStringSlice(redirectURIs, &client.RedirectURIs); err != nil {
		return client, err
	}
	if err = unmarshalStringSlice(contacts, &client.Contacts); err != nil {
		return client, err
	}

	return client, nil
}

func (c *ClientManager) clientValues(client storage.Client) ([]interface{}, error) {
	allowedAudiences, err := marshalStringSlice(client.AllowedAudiences)
	if err != nil {
		return nil, err
	}
	allowedRegions, err := marshalStringSlice(client.AllowedRegions)
	if err != nil {
		return nil, err
	}
	allowedTenantAccess, err := marshalStringSlice(client.AllowedTenantAccess)
	if err != nil {
		return nil, err
	}
	grantTypes, err := marshalStringSlice(client.GrantTypes)
	if err != nil {
		return nil, err
	}
	responseTypes, err := marshalStringSlice(client.ResponseTypes)
	if err != nil {
		return nil, err
	}
	scopes, err := marshalStringSlice(client.Scopes)
	if err != nil {
		return nil, err
	}
	redirectURIs, err := marshalStringSlice(client.RedirectURIs)
	if err != nil {
		return nil, err
	}
	contacts, err := marshalStringSlice(client.Contacts)
	if err != nil {
		return nil, err
	}

	return []interface{}{
		client.ID,
		client.CreateTime,
		client.UpdateTime,
		allowedAudiences,
		allowedRegions,
		allowedTenantAccess,
		grantTypes,
		responseTypes,
		scopes,
		client.Public,
		client.Disabled,
		client.Name,
		client.Secret,
		redirectURIs,
		client.Owner,
		client.PolicyURI,
		client.TermsOfServiceURI,
		client.ClientURI,
		client.LogoURI,
		contacts,
		client.Published,
		client.Provider,
	}, nil
}

func (c *ClientManager) getConcrete(ctx context.Context, clientID string) (storage.Client, error) {
	table := c.DB.Table(storage.EntityClients)
	query := fmt.Sprintf("SELECT %s FROM %s WHERE id = $1", clientColumns, table)

	row := c.DB.Pool.QueryRow(ctx, query, clientID)
	client, err := c.scanClient(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.Client{}, fosite.ErrNotFound
		}
		return storage.Client{}, err
	}
	return client, nil
}

// List filters resources to return OAuth 2.0 client resources.
func (c *ClientManager) List(ctx context.Context, filter storage.ListClientsRequest) ([]storage.Client, error) {
	table := c.DB.Table(storage.EntityClients)
	var (
		conditions []string
		args       []interface{}
		argNum     = 1
	)

	if filter.AllowedTenantAccess != "" {
		cond, data, ok := jsonbContainsSingleSQL("allowed_tenant_access", filter.AllowedTenantAccess)
		if ok {
			conditions = append(conditions, fmt.Sprintf(cond+"::jsonb", argNum))
			args = append(args, data)
			argNum++
		}
	}
	if filter.AllowedRegion != "" {
		cond, data, ok := jsonbContainsSingleSQL("allowed_regions", filter.AllowedRegion)
		if ok {
			conditions = append(conditions, fmt.Sprintf(cond+"::jsonb", argNum))
			args = append(args, data)
			argNum++
		}
	}
	if filter.RedirectURI != "" {
		cond, data, ok := jsonbContainsSingleSQL("redirect_uris", filter.RedirectURI)
		if ok {
			conditions = append(conditions, fmt.Sprintf(cond+"::jsonb", argNum))
			args = append(args, data)
			argNum++
		}
	}
	if filter.GrantType != "" {
		cond, data, ok := jsonbContainsSingleSQL("grant_types", filter.GrantType)
		if ok {
			conditions = append(conditions, fmt.Sprintf(cond+"::jsonb", argNum))
			args = append(args, data)
			argNum++
		}
	}
	if filter.ResponseType != "" {
		cond, data, ok := jsonbContainsSingleSQL("response_types", filter.ResponseType)
		if ok {
			conditions = append(conditions, fmt.Sprintf(cond+"::jsonb", argNum))
			args = append(args, data)
			argNum++
		}
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
	if filter.Contact != "" {
		cond, data, ok := jsonbContainsSingleSQL("contacts", filter.Contact)
		if ok {
			conditions = append(conditions, fmt.Sprintf(cond+"::jsonb", argNum))
			args = append(args, data)
			argNum++
		}
	}
	if filter.Public {
		conditions = append(conditions, fmt.Sprintf("public = $%d", argNum))
		args = append(args, filter.Public)
		argNum++
	}
	if filter.Disabled {
		conditions = append(conditions, fmt.Sprintf("disabled = $%d", argNum))
		args = append(args, filter.Disabled)
		argNum++
	}
	if filter.Published {
		conditions = append(conditions, fmt.Sprintf("published = $%d", argNum))
		args = append(args, filter.Published)
		argNum++
	}

	query := fmt.Sprintf("SELECT %s FROM %s", clientColumns, table)
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	rows, err := c.DB.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []storage.Client
	for rows.Next() {
		client, err := c.scanClient(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	return clients, rows.Err()
}

// Create stores a new OAuth2.0 Client resource.
func (c *ClientManager) Create(ctx context.Context, client storage.Client) (storage.Client, error) {
	if client.ID == "" {
		client.ID = uuid.NewString()
	}
	if client.CreateTime == 0 {
		client.CreateTime = time.Now().Unix()
	}

	hash, err := c.Hasher.Hash(ctx, []byte(client.Secret))
	if err != nil {
		return storage.Client{}, err
	}
	client.Secret = string(hash)

	values, err := c.clientValues(client)
	if err != nil {
		return storage.Client{}, err
	}

	table := c.DB.Table(storage.EntityClients)
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)",
		table, clientColumns)

	_, err = c.DB.Pool.Exec(ctx, query, values...)
	if err != nil {
		return storage.Client{}, duplicateKeyErr(err)
	}
	return client, nil
}

// Get finds and returns an OAuth 2.0 client resource.
func (c *ClientManager) Get(ctx context.Context, clientID string) (storage.Client, error) {
	return c.getConcrete(ctx, clientID)
}

// GetClient finds and returns an OAuth 2.0 client resource as fosite.Client.
func (c *ClientManager) GetClient(ctx context.Context, clientID string) (fosite.Client, error) {
	client, err := c.getConcrete(ctx, clientID)
	if err != nil {
		return nil, err
	}
	return &client, nil
}

// ClientAssertionJWTValid returns an error if the JTI is known or the DB check failed.
func (c *ClientManager) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	deniedJti, err := c.DeniedJTIs.Get(ctx, jti)
	if err != nil {
		if errors.Is(err, fosite.ErrNotFound) {
			return nil
		}
		return err
	}

	if time.Unix(deniedJti.Expiry, 0).After(time.Now()) {
		return fosite.ErrJTIKnown
	}
	return nil
}

// SetClientAssertionJWT marks a JTI as known for the given expiry time.
func (c *ClientManager) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	if err := c.DeniedJTIs.DeleteBefore(ctx, time.Now().Unix()); err != nil {
		if !errors.Is(err, fosite.ErrNotFound) {
			return err
		}
	}

	_, err := c.DeniedJTIs.Create(ctx, storage.NewDeniedJTI(jti, exp))
	if err != nil {
		if errors.Is(err, storage.ErrResourceExists) {
			return fosite.ErrJTIKnown
		}
		return err
	}
	return nil
}

// Update updates an OAuth 2.0 client resource.
func (c *ClientManager) Update(ctx context.Context, clientID string, updatedClient storage.Client) (storage.Client, error) {
	currentResource, err := c.getConcrete(ctx, clientID)
	if err != nil {
		return storage.Client{}, err
	}

	updatedClient.ID = clientID
	updatedClient.UpdateTime = time.Now().Unix()

	if currentResource.Secret == updatedClient.Secret || updatedClient.Secret == "" {
		updatedClient.Secret = currentResource.Secret
	}

	values, err := c.clientValues(updatedClient)
	if err != nil {
		return storage.Client{}, err
	}

	table := c.DB.Table(storage.EntityClients)
	query := fmt.Sprintf(
		"UPDATE %s SET created_at=$2, updated_at=$3, allowed_audiences=$4, allowed_regions=$5, "+
			"allowed_tenant_access=$6, grant_types=$7, response_types=$8, scopes=$9, public=$10, disabled=$11, "+
			"name=$12, secret=$13, redirect_uris=$14, owner=$15, policy_uri=$16, terms_of_service_uri=$17, "+
			"client_uri=$18, logo_uri=$19, contacts=$20, published=$21, provider=$22 WHERE id=$1",
		table,
	)

	cmd, err := c.DB.Pool.Exec(ctx, query, values...)
	if err != nil {
		return storage.Client{}, duplicateKeyErr(err)
	}
	if cmd.RowsAffected() == 0 {
		return storage.Client{}, fosite.ErrNotFound
	}
	return updatedClient, nil
}

// Migrate upserts a client record for hash migration workflows.
func (c *ClientManager) Migrate(ctx context.Context, migratedClient storage.Client) (storage.Client, error) {
	if migratedClient.ID == "" {
		migratedClient.ID = uuid.NewString()
	}
	if migratedClient.CreateTime == 0 {
		migratedClient.CreateTime = time.Now().Unix()
	} else {
		migratedClient.UpdateTime = time.Now().Unix()
	}

	values, err := c.clientValues(migratedClient)
	if err != nil {
		return storage.Client{}, err
	}

	table := c.DB.Table(storage.EntityClients)
	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22) "+
			"ON CONFLICT (id) DO UPDATE SET created_at=EXCLUDED.created_at, updated_at=EXCLUDED.updated_at, "+
			"allowed_audiences=EXCLUDED.allowed_audiences, allowed_regions=EXCLUDED.allowed_regions, "+
			"allowed_tenant_access=EXCLUDED.allowed_tenant_access, grant_types=EXCLUDED.grant_types, "+
			"response_types=EXCLUDED.response_types, scopes=EXCLUDED.scopes, public=EXCLUDED.public, "+
			"disabled=EXCLUDED.disabled, name=EXCLUDED.name, secret=EXCLUDED.secret, redirect_uris=EXCLUDED.redirect_uris, "+
			"owner=EXCLUDED.owner, policy_uri=EXCLUDED.policy_uri, terms_of_service_uri=EXCLUDED.terms_of_service_uri, "+
			"client_uri=EXCLUDED.client_uri, logo_uri=EXCLUDED.logo_uri, contacts=EXCLUDED.contacts, "+
			"published=EXCLUDED.published, provider=EXCLUDED.provider",
		table, clientColumns,
	)

	_, err = c.DB.Pool.Exec(ctx, query, values...)
	if err != nil {
		return storage.Client{}, duplicateKeyErr(err)
	}
	return migratedClient, nil
}

// Delete removes an OAuth 2.0 Client resource.
func (c *ClientManager) Delete(ctx context.Context, clientID string) error {
	table := c.DB.Table(storage.EntityClients)
	cmd, err := c.DB.Pool.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE id = $1", table), clientID)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return fosite.ErrNotFound
	}
	return nil
}

// Authenticate verifies the identity of a client resource.
func (c *ClientManager) Authenticate(ctx context.Context, clientID string, secret string) (storage.Client, error) {
	client, err := c.getConcrete(ctx, clientID)
	if err != nil {
		return storage.Client{}, err
	}

	if client.Public {
		return client, nil
	}
	if client.Disabled {
		return storage.Client{}, fosite.ErrAccessDenied
	}

	if err = c.Hasher.Compare(ctx, client.GetHashedSecret(), []byte(secret)); err != nil {
		return storage.Client{}, err
	}
	return client, nil
}

// AuthenticateMigration authenticates and migrates client hashes.
func (c *ClientManager) AuthenticateMigration(ctx context.Context, currentAuth storage.AuthClientFunc, clientID string, secret string) (storage.Client, error) {
	client, authenticated := currentAuth(ctx)

	if client.IsEmpty() && !authenticated {
		return storage.Client{}, fosite.ErrNotFound
	}
	if client.Public {
		return client, nil
	}
	if client.Disabled {
		return storage.Client{}, fosite.ErrAccessDenied
	}

	if !authenticated {
		if err := c.Hasher.Compare(ctx, client.GetHashedSecret(), []byte(secret)); err != nil {
			return storage.Client{}, err
		}
		return client, nil
	}

	newHash, err := c.Hasher.Hash(ctx, []byte(secret))
	if err != nil {
		return storage.Client{}, err
	}
	client.UpdateTime = time.Now().Unix()
	client.Secret = string(newHash)
	return c.Update(ctx, clientID, client)
}

// GrantScopes grants scopes to the specified client.
func (c *ClientManager) GrantScopes(ctx context.Context, clientID string, scopes []string) (storage.Client, error) {
	client, err := c.getConcrete(ctx, clientID)
	if err != nil {
		return storage.Client{}, err
	}
	client.UpdateTime = time.Now().Unix()
	client.EnableScopeAccess(scopes...)
	return c.Update(ctx, client.ID, client)
}

// RemoveScopes revokes scopes from the specified client.
func (c *ClientManager) RemoveScopes(ctx context.Context, clientID string, scopes []string) (storage.Client, error) {
	client, err := c.getConcrete(ctx, clientID)
	if err != nil {
		return storage.Client{}, err
	}
	client.UpdateTime = time.Now().Unix()
	client.DisableScopeAccess(scopes...)
	return c.Update(ctx, client.ID, client)
}

// IsJWTUsed reports whether a JWT has already been used.
func (c *ClientManager) IsJWTUsed(ctx context.Context, jti string) (bool, error) {
	err := c.ClientAssertionJWTValid(ctx, jti)
	if err != nil {
		return true, nil
	}
	return false, nil
}

// MarkJWTUsedForTime marks a JWT as used until the given expiry.
func (c *ClientManager) MarkJWTUsedForTime(ctx context.Context, jti string, exp time.Time) error {
	return c.SetClientAssertionJWT(ctx, jti, exp)
}
