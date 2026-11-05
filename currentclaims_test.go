package jawsauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestServerCurrentClaimsChecksExpiryAndJaWSSession(t *testing.T) {
	jw := newTestJaws(t)
	srv := &Server{Jaws: jw, SessionKey: "claims", namespace: "github"}
	sess := jw.NewSession(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://app.example/", nil))
	if sess == nil {
		t.Fatal("missing session")
	}
	if (*Server)(nil).CurrentClaims(sess) != nil || srv.CurrentClaims(nil) != nil || srv.CurrentClaims(sess) != nil {
		t.Fatal("nil or unauthenticated session returned claims")
	}
	claims := map[string]any{"iss": "https://github.com", "sub": "42"}
	sess.Set(srv.SessionKey, claims)
	if srv.CurrentClaims(sess) != nil {
		t.Fatal("claims without verified expiry were accepted")
	}
	sess.Set(srv.sessionKey(oauth2AuthExpiryKey), time.Now().Add(time.Hour))
	if got := srv.CurrentClaims(sess); got["sub"] != "42" {
		t.Fatalf("live claims: %v", got)
	}
	other := newTestJaws(t)
	if (&Server{Jaws: other, SessionKey: srv.SessionKey, namespace: srv.namespace}).CurrentClaims(sess) != nil {
		t.Fatal("another JaWS instance accepted session")
	}
	sess.Set(srv.sessionKey(oauth2AuthExpiryKey), time.Now().Add(-time.Second))
	if srv.CurrentClaims(sess) != nil {
		t.Fatal("expired authentication returned claims")
	}
	sess.Set(srv.sessionKey(oauth2AuthExpiryKey), time.Now().Add(time.Hour))
	sess.Close()
	if srv.CurrentClaims(sess) != nil {
		t.Fatal("closed session returned claims")
	}
}

func TestCurrentClaimsRejectsOtherIssuerWithSameNamespace(t *testing.T) {
	jw := newTestJaws(t)
	social, err := New(jw, &Config{Namespace: "shared", Issuer: "https://social.example"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	corp, err := New(jw, &Config{Namespace: "shared", Issuer: "https://corp.example"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if social.SessionKey != corp.SessionKey {
		t.Fatal("test providers do not share session keys")
	}
	sess := jw.NewSession(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://app.example/", nil))
	sess.Set(social.SessionKey, map[string]any{"iss": social.issuer, "sub": "person"})
	sess.Set(social.sessionKey(oauth2AuthExpiryKey), time.Now().Add(time.Hour))
	if social.CurrentClaims(sess) == nil || corp.CurrentClaims(sess) != nil {
		t.Fatal("another provider accepted claims from the shared namespace")
	}
	sess.Set(social.SessionKey, "not claims")
	if social.CurrentClaims(sess) != nil {
		t.Fatal("non-map claims were accepted")
	}
}

func TestCurrentClaimsAcceptsGoogleIssuerAlias(t *testing.T) {
	jw := newTestJaws(t)
	srv, err := New(jw, &Config{Issuer: "https://accounts.google.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sess := jw.NewSession(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://app.example/", nil))
	sess.Set(srv.SessionKey, map[string]any{"iss": "accounts.google.com", "sub": "person"})
	sess.Set(srv.sessionKey(oauth2AuthExpiryKey), time.Now().Add(time.Hour))
	if srv.CurrentClaims(sess) == nil {
		t.Fatal("go-oidc Google issuer alias was rejected")
	}
}
