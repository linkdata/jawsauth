package jawsauth

import (
	"errors"
	"net/http"
)

// ErrOAuth2MissingIssuer means the callback did not include the required "iss" parameter.
// Deprecated: kept for compatibility, callback "iss" is now optional.
var ErrOAuth2MissingIssuer = errors.New("oauth2 missing issuer")

// ErrOAuth2WrongIssuer means the callback "iss" parameter does not match the expected issuer.
var ErrOAuth2WrongIssuer = errors.New("oauth2 wrong issuer")

func (srv *Server) validateIssuer(hr *http.Request, statusCode int) (nextStatusCode int, err error) {
	nextStatusCode = statusCode
	if srv.issuer != "" {
		gotIssuer := hr.FormValue("iss")
		if gotIssuer != "" && gotIssuer != srv.issuer {
			nextStatusCode = http.StatusBadRequest
			err = ErrOAuth2WrongIssuer
		}
	}
	return
}
