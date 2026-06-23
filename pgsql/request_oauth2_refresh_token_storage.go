package pgsql

import (
	"context"
	"errors"

	"github.com/ory/fosite"

	"github.com/initial-commit-hq/go-fosite-mongo"
)

// CreateRefreshTokenSession implements fosite.RefreshTokenStorage.
func (r *RequestManager) CreateRefreshTokenSession(ctx context.Context, signature string, assignsignature string, request fosite.Requester) error {
	_, err := r.Create(ctx, storage.EntityRefreshTokens, toRequest(signature, request))
	if err != nil {
		if errors.Is(err, storage.ErrResourceExists) {
			return err
		}
		return err
	}
	return nil
}

// GetRefreshTokenSession implements fosite.RefreshTokenStorage.
func (r *RequestManager) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	req, err := r.GetBySignature(ctx, storage.EntityRefreshTokens, signature)
	if err != nil {
		return nil, err
	}
	return req.ToRequest(ctx, session, r.Clients)
}

// DeleteRefreshTokenSession implements fosite.RefreshTokenStorage.
func (r *RequestManager) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return r.DeleteBySignature(ctx, storage.EntityRefreshTokens, signature)
}
