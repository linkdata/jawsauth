package jawsauth

import (
	"net/http"
	"strings"
	"testing"
)

func Test_errtext(t *testing.T) {
	s := errtext(http.StatusForbidden, ErrOAuth2WrongState)
	if !strings.Contains(s, "403 Forbidden") {
		t.Fatal()
	}
	if !strings.Contains(s, ErrOAuth2WrongState.Error()) {
		t.Fatal()
	}
}
