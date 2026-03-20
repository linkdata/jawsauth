package jawsauth

import "errors"

// ErrOIDCDiscovery means OIDC provider discovery failed.
var ErrOIDCDiscovery = errors.New("oidc discovery failed")

// ErrOIDCProviderMetadata means discovered OIDC metadata was invalid.
var ErrOIDCProviderMetadata = errors.New("oidc provider metadata invalid")

// ErrOIDCMissingIDToken means the token response did not include an id_token.
var ErrOIDCMissingIDToken = errors.New("oidc missing id_token")

// ErrOIDCInvalidIDToken means id_token verification failed.
var ErrOIDCInvalidIDToken = errors.New("oidc invalid id_token")

// ErrOIDCMissingNonce means the login request did not include a nonce.
var ErrOIDCMissingNonce = errors.New("oidc missing nonce")

// ErrOIDCNonceMismatch means the id_token nonce did not match the stored session nonce.
var ErrOIDCNonceMismatch = errors.New("oidc nonce mismatch")

type errOIDC struct {
	kind  error
	cause error
}

func (e errOIDC) Error() string {
	return e.kind.Error() + ": " + e.cause.Error()
}

func (e errOIDC) Unwrap() error {
	return e.cause
}

func (e errOIDC) Is(target error) bool {
	return target == e.kind
}

func wrapOIDC(kind error, perr *error) (err error) {
	if err = *perr; err != nil {
		err = errOIDC{kind: kind, cause: *perr}
		*perr = err
	}
	return
}
