package jawsauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/linkdata/jaws"
)

func TestJawsAuthSessionValues(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	srv := &Server{
		SessionKey:              "claims",
		SessionEmailKey:         "email",
		SessionEmailVerifiedKey: "email_verified",
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	rec := httptest.NewRecorder()
	sess := jw.NewSession(rec, req)
	sess.Set(srv.SessionKey, map[string]any{"sub": "subject"})
	sess.Set(srv.SessionEmailKey, "user@example.com")
	sess.Set(srv.SessionEmailVerifiedKey, true)

	auth := &JawsAuth{
		server: srv,
		sess:   sess,
	}
	if !auth.EmailVerified() {
		t.Fatal("expected EmailVerified() to be true")
	}
	if data := auth.Data(); data["sub"] != "subject" {
		t.Fatal(data)
	}
	if email := auth.Email(); email != "user@example.com" {
		t.Fatal(email)
	}
}

func TestJawsAuthZeroValueSafe(t *testing.T) {
	var auth JawsAuth
	if data := auth.Data(); data != nil {
		t.Fatal(data)
	}
	if email := auth.Email(); email != "" {
		t.Fatal(email)
	}
	if auth.EmailVerified() {
		t.Fatal("zero-value auth reported verified email")
	}
	if !auth.IsAdmin() {
		t.Fatal("zero-value auth should follow nil-server admin behavior")
	}

	auth = JawsAuth{server: &Server{admins: map[string]struct{}{"admin@example.com": {}}}}
	if data := auth.Data(); data != nil {
		t.Fatal(data)
	}
	if email := auth.Email(); email != "" {
		t.Fatal(email)
	}
	if auth.EmailVerified() {
		t.Fatal("auth without a session reported verified email")
	}
	if auth.IsAdmin() {
		t.Fatal("auth without a session should not match a non-empty admin list")
	}
}
