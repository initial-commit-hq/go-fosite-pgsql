package pgsql

import (
	"context"
	"errors"

	"github.com/ory/fosite"
)

// Authenticate confirms password for a user found by username.
func (r *RequestManager) Authenticate(ctx context.Context, username string, secret string) (string, error) {
	user, err := r.Users.Authenticate(ctx, username, secret)
	if err != nil {
		if errors.Is(err, fosite.ErrNotFound) {
			return "", err
		}
		return "", err
	}
	return user.GetID(), nil
}
