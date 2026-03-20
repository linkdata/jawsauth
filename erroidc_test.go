package jawsauth

import (
	"errors"
	"testing"
)

func TestErrOIDCMethods(t *testing.T) {
	cause := errors.New("cause")
	err := errOIDC{
		kind:  ErrOIDCDiscovery,
		cause: cause,
	}

	if got := err.Unwrap(); got != cause {
		t.Fatalf("Unwrap() = %v, want %v", got, cause)
	}
	if !err.Is(ErrOIDCDiscovery) {
		t.Fatal("expected Is(ErrOIDCDiscovery) to be true")
	}
	if err.Is(ErrOIDCInvalidIDToken) {
		t.Fatal("expected Is(ErrOIDCInvalidIDToken) to be false")
	}
}
