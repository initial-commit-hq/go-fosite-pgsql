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

// UserManager provides a PostgreSQL-backed implementation for user resources.
type UserManager struct {
	DB     *DB
	Hasher fosite.Hasher
}

const userColumns = `id, created_at, updated_at, allowed_tenant_access, allowed_person_access,
scopes, roles, person_id, disabled, username, password, first_name, last_name, profile_uri`

// Configure creates indexes for the oauth2_user table.
func (u *UserManager) Configure(ctx context.Context) error {
	table := u.DB.Table(storage.EntityUsers)
	_, err := u.DB.Pool.Exec(ctx, fmt.Sprintf(
		"CREATE UNIQUE INDEX IF NOT EXISTS %s ON %s (id)",
		IdxUserID, table,
	))
	if err != nil {
		return err
	}
	_, err = u.DB.Pool.Exec(ctx, fmt.Sprintf(
		"CREATE UNIQUE INDEX IF NOT EXISTS %s ON %s (username)",
		IdxUsername, table,
	))
	return err
}

func (u *UserManager) scanUser(row pgx.Row) (storage.User, error) {
	var user storage.User
	var allowedTenantAccess, allowedPersonAccess, scopes, roles []byte

	err := row.Scan(
		&user.ID,
		&user.CreateTime,
		&user.UpdateTime,
		&allowedTenantAccess,
		&allowedPersonAccess,
		&scopes,
		&roles,
		&user.PersonID,
		&user.Disabled,
		&user.Username,
		&user.Password,
		&user.FirstName,
		&user.LastName,
		&user.ProfileURI,
	)
	if err != nil {
		return user, err
	}

	if err = unmarshalStringSlice(allowedTenantAccess, &user.AllowedTenantAccess); err != nil {
		return user, err
	}
	if err = unmarshalStringSlice(allowedPersonAccess, &user.AllowedPersonAccess); err != nil {
		return user, err
	}
	if err = unmarshalStringSlice(scopes, &user.Scopes); err != nil {
		return user, err
	}
	if err = unmarshalStringSlice(roles, &user.Roles); err != nil {
		return user, err
	}
	return user, nil
}

func (u *UserManager) userValues(user storage.User) ([]interface{}, error) {
	allowedTenantAccess, err := marshalStringSlice(user.AllowedTenantAccess)
	if err != nil {
		return nil, err
	}
	allowedPersonAccess, err := marshalStringSlice(user.AllowedPersonAccess)
	if err != nil {
		return nil, err
	}
	scopes, err := marshalStringSlice(user.Scopes)
	if err != nil {
		return nil, err
	}
	roles, err := marshalStringSlice(user.Roles)
	if err != nil {
		return nil, err
	}

	return []interface{}{
		user.ID,
		user.CreateTime,
		user.UpdateTime,
		allowedTenantAccess,
		allowedPersonAccess,
		scopes,
		roles,
		user.PersonID,
		user.Disabled,
		user.Username,
		user.Password,
		user.FirstName,
		user.LastName,
		user.ProfileURI,
	}, nil
}

func (u *UserManager) getConcrete(ctx context.Context, userID string) (storage.User, error) {
	table := u.DB.Table(storage.EntityUsers)
	query := fmt.Sprintf("SELECT %s FROM %s WHERE id = $1", userColumns, table)

	row := u.DB.Pool.QueryRow(ctx, query, userID)
	user, err := u.scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.User{}, fosite.ErrNotFound
		}
		return storage.User{}, err
	}
	return user, nil
}

// List returns users matching the filter.
func (u *UserManager) List(ctx context.Context, filter storage.ListUsersRequest) ([]storage.User, error) {
	table := u.DB.Table(storage.EntityUsers)
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
	if filter.AllowedPersonAccess != "" {
		cond, data, ok := jsonbContainsSingleSQL("allowed_person_access", filter.AllowedPersonAccess)
		if ok {
			conditions = append(conditions, fmt.Sprintf(cond+"::jsonb", argNum))
			args = append(args, data)
			argNum++
		}
	}
	if filter.PersonID != "" {
		conditions = append(conditions, fmt.Sprintf("person_id = $%d", argNum))
		args = append(args, filter.PersonID)
		argNum++
	}
	if filter.Username != "" {
		conditions = append(conditions, fmt.Sprintf("username = $%d", argNum))
		args = append(args, filter.Username)
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
	if filter.FirstName != "" {
		conditions = append(conditions, fmt.Sprintf("first_name = $%d", argNum))
		args = append(args, filter.FirstName)
		argNum++
	}
	if filter.LastName != "" {
		conditions = append(conditions, fmt.Sprintf("last_name = $%d", argNum))
		args = append(args, filter.LastName)
		argNum++
	}
	if filter.Disabled {
		conditions = append(conditions, fmt.Sprintf("disabled = $%d", argNum))
		args = append(args, filter.Disabled)
		argNum++
	}

	query := fmt.Sprintf("SELECT %s FROM %s", userColumns, table)
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	rows, err := u.DB.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []storage.User
	for rows.Next() {
		user, err := u.scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

// Create creates a new User resource.
func (u *UserManager) Create(ctx context.Context, user storage.User) (storage.User, error) {
	if user.ID == "" {
		user.ID = uuid.NewString()
	}
	if user.CreateTime == 0 {
		user.CreateTime = time.Now().Unix()
	}

	hash, err := u.Hasher.Hash(ctx, []byte(user.Password))
	if err != nil {
		return storage.User{}, err
	}
	user.Password = string(hash)

	values, err := u.userValues(user)
	if err != nil {
		return storage.User{}, err
	}

	table := u.DB.Table(storage.EntityUsers)
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
		table, userColumns)

	_, err = u.DB.Pool.Exec(ctx, query, values...)
	if err != nil {
		return storage.User{}, duplicateKeyErr(err)
	}
	return user, nil
}

// Get returns the specified User resource.
func (u *UserManager) Get(ctx context.Context, userID string) (storage.User, error) {
	return u.getConcrete(ctx, userID)
}

// GetByUsername returns a user by username.
func (u *UserManager) GetByUsername(ctx context.Context, username string) (storage.User, error) {
	table := u.DB.Table(storage.EntityUsers)
	query := fmt.Sprintf("SELECT %s FROM %s WHERE username = $1", userColumns, table)

	row := u.DB.Pool.QueryRow(ctx, query, username)
	user, err := u.scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.User{}, fosite.ErrNotFound
		}
		return storage.User{}, err
	}
	return user, nil
}

// Update updates a User resource.
func (u *UserManager) Update(ctx context.Context, userID string, updatedUser storage.User) (storage.User, error) {
	currentResource, err := u.getConcrete(ctx, userID)
	if err != nil {
		return storage.User{}, err
	}

	updatedUser.ID = userID
	updatedUser.UpdateTime = time.Now().Unix()

	if currentResource.Password == updatedUser.Password || updatedUser.Password == "" {
		updatedUser.Password = currentResource.Password
	} else {
		newHash, err := u.Hasher.Hash(ctx, []byte(updatedUser.Password))
		if err != nil {
			return storage.User{}, err
		}
		updatedUser.Password = string(newHash)
	}

	values, err := u.userValues(updatedUser)
	if err != nil {
		return storage.User{}, err
	}

	table := u.DB.Table(storage.EntityUsers)
	query := fmt.Sprintf(
		"UPDATE %s SET created_at=$2, updated_at=$3, allowed_tenant_access=$4, allowed_person_access=$5, "+
			"scopes=$6, roles=$7, person_id=$8, disabled=$9, username=$10, password=$11, first_name=$12, "+
			"last_name=$13, profile_uri=$14 WHERE id=$1",
		table,
	)

	cmd, err := u.DB.Pool.Exec(ctx, query, values...)
	if err != nil {
		return storage.User{}, duplicateKeyErr(err)
	}
	if cmd.RowsAffected() == 0 {
		return storage.User{}, fosite.ErrNotFound
	}
	return updatedUser, nil
}

// Migrate upserts a user record for hash migration workflows.
func (u *UserManager) Migrate(ctx context.Context, migratedUser storage.User) (storage.User, error) {
	if migratedUser.ID == "" {
		migratedUser.ID = uuid.NewString()
	}
	if migratedUser.CreateTime == 0 {
		migratedUser.CreateTime = time.Now().Unix()
	}
	migratedUser.UpdateTime = time.Now().Unix()

	values, err := u.userValues(migratedUser)
	if err != nil {
		return storage.User{}, err
	}

	table := u.DB.Table(storage.EntityUsers)
	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) "+
			"ON CONFLICT (id) DO UPDATE SET created_at=EXCLUDED.created_at, updated_at=EXCLUDED.updated_at, "+
			"allowed_tenant_access=EXCLUDED.allowed_tenant_access, allowed_person_access=EXCLUDED.allowed_person_access, "+
			"scopes=EXCLUDED.scopes, roles=EXCLUDED.roles, person_id=EXCLUDED.person_id, disabled=EXCLUDED.disabled, "+
			"username=EXCLUDED.username, password=EXCLUDED.password, first_name=EXCLUDED.first_name, "+
			"last_name=EXCLUDED.last_name, profile_uri=EXCLUDED.profile_uri",
		table, userColumns,
	)

	_, err = u.DB.Pool.Exec(ctx, query, values...)
	if err != nil {
		return storage.User{}, duplicateKeyErr(err)
	}
	return migratedUser, nil
}

// Delete deletes the specified User resource.
func (u *UserManager) Delete(ctx context.Context, userID string) error {
	table := u.DB.Table(storage.EntityUsers)
	cmd, err := u.DB.Pool.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE id = $1", table), userID)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return fosite.ErrNotFound
	}
	return nil
}

// Authenticate confirms password for a user matched by username.
func (u *UserManager) Authenticate(ctx context.Context, username string, password string) (storage.User, error) {
	return u.AuthenticateByUsername(ctx, username, password)
}

// AuthenticateByID confirms password for a user matched by ID.
func (u *UserManager) AuthenticateByID(ctx context.Context, userID string, password string) (storage.User, error) {
	user, err := u.getConcrete(ctx, userID)
	if err != nil {
		return storage.User{}, err
	}
	if user.Disabled {
		return storage.User{}, fosite.ErrAccessDenied
	}
	if err = u.Hasher.Compare(ctx, []byte(user.Password), []byte(password)); err != nil {
		return storage.User{}, err
	}
	return user, nil
}

// AuthenticateByUsername confirms password for a user matched by username.
func (u *UserManager) AuthenticateByUsername(ctx context.Context, username string, password string) (storage.User, error) {
	user, err := u.GetByUsername(ctx, username)
	if err != nil {
		return storage.User{}, err
	}
	if user.Disabled {
		return storage.User{}, fosite.ErrAccessDenied
	}
	if err = u.Hasher.Compare(ctx, []byte(user.Password), []byte(password)); err != nil {
		return storage.User{}, err
	}
	return user, nil
}

// AuthenticateMigration authenticates and migrates user hashes.
func (u *UserManager) AuthenticateMigration(ctx context.Context, currentAuth storage.AuthUserFunc, userID string, password string) (storage.User, error) {
	user, authenticated := currentAuth(ctx)

	if user.IsEmpty() && !authenticated {
		return storage.User{}, fosite.ErrNotFound
	}
	if user.Disabled {
		return storage.User{}, fosite.ErrAccessDenied
	}

	if !authenticated {
		if err := u.Hasher.Compare(ctx, user.GetHashedSecret(), []byte(password)); err != nil {
			return storage.User{}, err
		}
		return user, nil
	}

	newHash, err := u.Hasher.Hash(ctx, []byte(password))
	if err != nil {
		return storage.User{}, err
	}
	user.UpdateTime = time.Now().Unix()
	user.Password = string(newHash)
	return u.Update(ctx, userID, user)
}

// GrantScopes grants scopes to the specified user.
func (u *UserManager) GrantScopes(ctx context.Context, userID string, scopes []string) (storage.User, error) {
	user, err := u.getConcrete(ctx, userID)
	if err != nil {
		return storage.User{}, err
	}
	user.UpdateTime = time.Now().Unix()
	user.EnableScopeAccess(scopes...)
	return u.Update(ctx, user.ID, user)
}

// RemoveScopes revokes scopes from the specified user.
func (u *UserManager) RemoveScopes(ctx context.Context, userID string, scopes []string) (storage.User, error) {
	user, err := u.getConcrete(ctx, userID)
	if err != nil {
		return storage.User{}, err
	}
	user.UpdateTime = time.Now().Unix()
	user.DisableScopeAccess(scopes...)
	return u.Update(ctx, user.ID, user)
}
