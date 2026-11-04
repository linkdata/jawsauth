package jawsauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/linkdata/jaws"
)

func TestServerCurrentClaimsChecksExpiryAndJaWSSession(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
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
	other, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
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
