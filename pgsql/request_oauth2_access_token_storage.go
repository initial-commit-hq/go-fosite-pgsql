package pgsql

import (
	"context"
	"errors"

	"github.com/ory/fosite"

	"github.com/initial-commit-hq/go-fosite-mongo"
)

// CreateAccessTokenSession creates a new session for an Access Token.
func (r *RequestManager) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	_, err := r.Create(ctx, storage.EntityAccessTokens, toRequest(signature, request))
	if err != nil {
		if errors.Is(err, storage.ErrResourceExists) {
			return err
		}
		return err
	}
	return nil
}

// GetAccessTokenSession returns a session if it can be found by signature.
func (r *RequestManager) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	req, err := r.GetBySignature(ctx, storage.EntityAccessTokens, signature)
	if err != nil {
		return nil, err
	}
	return req.ToRequest(ctx, session, r.Clients)
}

// DeleteAccessTokenSession removes an Access Token's session.
func (r *RequestManager) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return r.DeleteBySignature(ctx, storage.EntityAccessTokens, signature)
}
