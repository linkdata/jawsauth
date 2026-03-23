package jawsauth

import (
	"errors"
)

// ErrConfig matches all configuration validation errors.
var ErrConfig errConfig

// ErrConfigMissingValue means a required configuration value is missing.
var ErrConfigMissingValue = errors.New("config value is missing")

// ErrConfigURLNotAbsolute means a configured URL is not absolute.
var ErrConfigURLNotAbsolute = errors.New("url is not absolute")

// ErrConfigURLMissingHost means a configured URL does not include a host.
var ErrConfigURLMissingHost = errors.New("url host is missing")

// ErrConfigIssuerMustBeHTTPS means Issuer must use the https scheme unless AllowInsecureIssuer is enabled.
var ErrConfigIssuerMustBeHTTPS = errors.New("issuer url must use https")

type errConfig struct {
	field string
	cause error
}

func (e errConfig) Error() (s string) {
	s = "invalid config"
	if e.field != "" {
		s = "invalid " + e.field
	}
	if e.cause != nil {
		s += ": " + e.cause.Error()
	}
	return
}

func (e errConfig) Unwrap() error {
	return e.cause
}

func (e errConfig) Is(target error) (matches bool) {
	return target == ErrConfig
}
