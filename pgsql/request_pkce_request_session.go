package pgsql

import (
	"context"
	"errors"

	"github.com/ory/fosite"

	"github.com/initial-commit-hq/go-fosite-mongo"
)

// CreatePKCERequestSession implements fosite.PKCERequestStorage.
func (r *RequestManager) CreatePKCERequestSession(ctx context.Context, signature string, request fosite.Requester) error {
	_, err := r.Create(ctx, storage.EntityPKCESessions, toRequest(signature, request))
	if err != nil {
		if errors.Is(err, storage.ErrResourceExists) {
			return err
		}
		return err
	}
	return nil
}

// GetPKCERequestSession implements fosite.PKCERequestStorage.
func (r *RequestManager) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	req, err := r.GetBySignature(ctx, storage.EntityPKCESessions, signature)
	if err != nil {
		return nil, err
	}
	return req.ToRequest(ctx, session, r.Clients)
}

// DeletePKCERequestSession implements fosite.PKCERequestStorage.
func (r *RequestManager) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return r.DeleteBySignature(ctx, storage.EntityPKCESessions, signature)
}
