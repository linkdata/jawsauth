package jawsauth

import (
	"errors"
	"fmt"
)

// ErrConfigURLNotAbsolute means a configured URL is not absolute.
var ErrConfigURLNotAbsolute = errors.New("url is not absolute")

// ErrConfigURLMissingHost means a configured URL does not include a host.
var ErrConfigURLMissingHost = errors.New("url host is missing")

// ErrConfigIssuerMustBeHTTPS means Issuer must use the https scheme unless AllowInsecureIssuer is enabled.
var ErrConfigIssuerMustBeHTTPS = errors.New("issuer url must use https")

var ErrConfig errConfig

type errConfig struct {
	field string
	cause error
}

func (e errConfig) Error() (s string) {
	if e.cause != nil {
		s = fmt.Sprintf("invalid %q: %v", e.field, e.cause)
	}
	return
}

func (e errConfig) Unwrap() error {
	return e.cause
}

func (e errConfig) Is(target error) (matches bool) {
	return target == ErrConfig
}
