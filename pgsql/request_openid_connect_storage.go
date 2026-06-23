package pgsql

import (
	"context"

	"github.com/ory/fosite"

	"github.com/initial-commit-hq/go-fosite-mongo"
)

// CreateOpenIDConnectSession creates an open id connect session for a given authorize code.
func (r *RequestManager) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, request fosite.Requester) error {
	_, err := r.Create(ctx, storage.EntityOpenIDSessions, toRequest(authorizeCode, request))
	if err != nil {
		if err == storage.ErrResourceExists {
			return err
		}
		return err
	}
	return nil
}

// GetOpenIDConnectSession gets a session resource based on the authorize code.
func (r *RequestManager) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	req, err := r.GetBySignature(ctx, storage.EntityOpenIDSessions, authorizeCode)
	if err != nil {
		return nil, err
	}

	session := requester.GetSession()
	if session == nil {
		return nil, fosite.ErrNotFound
	}

	return req.ToRequest(ctx, session, r.Clients)
}

// DeleteOpenIDConnectSession removes an open id connect session.
func (r *RequestManager) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	return r.DeleteBySignature(ctx, storage.EntityOpenIDSessions, authorizeCode)
}
