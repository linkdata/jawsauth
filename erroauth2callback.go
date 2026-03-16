package jawsauth

import (
	"errors"
	"net/http"
	"strings"
)

// ErrOAuth2Callback matches OAuth2 callback errors returned by the identity provider.
var ErrOAuth2Callback = errors.New("oauth2 callback error")

// OAuth2CallbackError describes an OAuth2 callback error response.
type OAuth2CallbackError struct {
	Code        string // OAuth2 error code from the callback.
	Description string // Optional error description from the callback.
	URI         string // Optional URI with details about the callback error.
}

func (err *OAuth2CallbackError) Error() string {
	if err == nil {
		return ErrOAuth2Callback.Error()
	}
	var sb strings.Builder
	sb.WriteString(ErrOAuth2Callback.Error())
	if s := strings.TrimSpace(err.Code); s != "" {
		sb.WriteString(": ")
		sb.WriteString(s)
	}
	if s := strings.TrimSpace(err.Description); s != "" {
		sb.WriteString(": ")
		sb.WriteString(s)
	}
	if s := strings.TrimSpace(err.URI); s != "" {
		sb.WriteString(" (")
		sb.WriteString(s)
		sb.WriteString(")")
	}
	return sb.String()
}

func (err *OAuth2CallbackError) Is(target error) bool {
	return target == ErrOAuth2Callback
}

func oauth2CallbackError(statusCode int, hr *http.Request) (nextStatusCode int, err error) {
	nextStatusCode = statusCode
	if s := strings.TrimSpace(hr.FormValue("error")); s != "" {
		callbackErr := &OAuth2CallbackError{
			Code:        s,
			Description: strings.TrimSpace(hr.FormValue("error_description")),
			URI:         strings.TrimSpace(hr.FormValue("error_uri")),
		}
		nextStatusCode = http.StatusBadRequest
		switch callbackErr.Code {
		case "access_denied":
			nextStatusCode = http.StatusForbidden
		}
		err = callbackErr
	}
	return
}
