package pgsql

const (
	// IdxClientID provides an index based on client id.
	IdxClientID = "idx_oauth2_client_id"

	// IdxExpires provides an index based on expires.
	IdxExpires = "idx_oauth2_jti_exp"

	// IdxExpiry provides an index for requested_at expiry queries.
	IdxExpiry = "idx_oauth2_requested_at"

	// IdxUserID provides an index based on user id.
	IdxUserID = "idx_oauth2_user_id"

	// IdxUsername provides an index based on username.
	IdxUsername = "idx_oauth2_username"

	// IdxSessionID provides an index based on session id.
	IdxSessionID = "idx_oauth2_session_id"

	// IdxSignatureID provides an index based on signature.
	IdxSignatureID = "idx_oauth2_signature"

	// IdxCompoundRequester provides a compound index on client_id and user_id.
	IdxCompoundRequester = "idx_oauth2_compound_requester"
)
