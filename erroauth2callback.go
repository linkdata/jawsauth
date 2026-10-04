package jawsauth

import (
	"errors"
	"net/http"
	"strings"
	"unicode"
)

// ErrOAuth2Callback matches OAuth2 error-redirect parameters relayed by the browser.
// These values are untrusted: any client can supply them, regardless of the provider.
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

func callbackParam(hr *http.Request, key string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return ' '
		}
		return r
	}, hr.FormValue(key)))
}

func oauth2CallbackError(statusCode int, hr *http.Request) (nextStatusCode int, err error) {
	nextStatusCode = statusCode
	if s := callbackParam(hr, "error"); s != "" {
		callbackErr := &OAuth2CallbackError{
			Code:        s,
			Description: callbackParam(hr, "error_description"),
			URI:         callbackParam(hr, "error_uri"),
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
