package jawsauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/linkdata/jaws"
)

func TestJawsAuthEmailVerified(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	srv := &Server{
		SessionEmailVerifiedKey: "email_verified",
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	rec := httptest.NewRecorder()
	sess := jw.NewSession(rec, req)
	sess.Set(srv.SessionEmailVerifiedKey, true)

	auth := &JawsAuth{
		server: srv,
		sess:   sess,
	}
	if !auth.EmailVerified() {
		t.Fatal("expected EmailVerified() to be true")
	}
}
