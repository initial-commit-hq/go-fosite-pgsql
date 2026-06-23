package pgsql

import (
	"context"
	"errors"
	"time"

	"github.com/ory/fosite"

	"github.com/initial-commit-hq/go-fosite-mongo"
)

// CreateAuthorizeCodeSession stores the authorization request for a given authorization code.
func (r *RequestManager) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	_, err := r.Create(ctx, storage.EntityAuthorizationCodes, toRequest(code, request))
	if err != nil {
		if errors.Is(err, storage.ErrResourceExists) {
			return err
		}
		return err
	}
	return nil
}

// GetAuthorizeCodeSession hydrates the session based on the given code.
func (r *RequestManager) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	req, err := r.GetBySignature(ctx, storage.EntityAuthorizationCodes, code)
	if err != nil {
		return nil, err
	}

	request, err := req.ToRequest(ctx, session, r.Clients)
	if err != nil {
		return nil, err
	}
	if !req.Active {
		return request, fosite.ErrInvalidatedAuthorizeCode
	}
	return request, nil
}

// InvalidateAuthorizeCodeSession marks an authorize code as invalid.
func (r *RequestManager) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	req, err := r.GetBySignature(ctx, storage.EntityAuthorizationCodes, code)
	if err != nil {
		return err
	}

	req.UpdateTime = time.Now().Unix()
	req.Active = false

	_, err = r.Update(ctx, storage.EntityAuthorizationCodes, req.ID, req)
	return err
}
