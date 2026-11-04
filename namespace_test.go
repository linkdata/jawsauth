package jawsauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

func TestOAuthFlowNamespacesShareSessionWithoutSharingState(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	newServer := func(namespace string) *Server {
		srv, err := New(jw, &Config{Namespace: namespace}, nil)
		if err != nil {
			t.Fatal(err)
		}
		srv.oauth2cfg = &oauth2.Config{ClientID: namespace, RedirectURL: "https://app.example/auth/callback",
			Endpoint: oauth2.Endpoint{AuthURL: "https://provider.example/authorize", TokenURL: "https://provider.example/token"}}
		return srv
	}
	github, gitlab := newServer("github"), newServer("gitlab")
	if github.SessionKey == gitlab.SessionKey || github.SessionTokenKey == gitlab.SessionTokenKey ||
		github.SessionEmailKey == gitlab.SessionEmailKey || github.SessionEmailVerifiedKey == gitlab.SessionEmailVerifiedKey {
		t.Fatal("provider auth keys overlap")
	}
	r := httptest.NewRequest(http.MethodGet, "https://app.example/auth/login", nil)
	for _, srv := range []*Server{github, gitlab} {
		response := httptest.NewRecorder()
		srv.HandleLogin(response, r)
		if response.Code != http.StatusFound {
			t.Fatalf("%s start: %d", srv.namespace, response.Code)
		}
	}
	sess := jw.GetSession(r)
	if sess == nil {
		t.Fatal("shared session missing")
	}
	first, _ := sess.Get(github.sessionKey(oauth2StateKey)).(string)
	second, _ := sess.Get(gitlab.sessionKey(oauth2StateKey)).(string)
	if first == "" || second == "" || first == second {
		t.Fatalf("provider states overlap: first=%q second=%q", first, second)
	}
	github.clearSessionOAuthFlow(sess)
	if sess.Get(github.sessionKey(oauth2StateKey)) != nil || sess.Get(gitlab.sessionKey(oauth2StateKey)) != second {
		t.Fatal("clearing one provider's flow cleared the other")
	}
}
