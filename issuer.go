package jawsauth

import (
	"errors"
	"net/http"
	"strings"
)

// ErrOAuth2MissingIssuer means the callback did not include the required "iss" parameter.
var ErrOAuth2MissingIssuer = errors.New("oauth2 missing issuer")

// ErrOAuth2WrongIssuer means the callback "iss" parameter does not match the expected issuer.
var ErrOAuth2WrongIssuer = errors.New("oauth2 wrong issuer")

func (srv *Server) validateIssuer(hr *http.Request, statusCode int) (nextStatusCode int, err error) {
	nextStatusCode = statusCode
	if srv.issuer != "" {
		gotIssuer := strings.TrimSpace(hr.FormValue("iss"))
		if gotIssuer != srv.issuer {
			nextStatusCode = http.StatusBadRequest
			err = ErrOAuth2WrongIssuer
			if gotIssuer == "" {
				err = ErrOAuth2MissingIssuer
			}
		}
	}
	return
}
