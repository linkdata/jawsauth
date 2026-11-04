package jawsauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

func testOAuthFlow(sess *jaws.Session, srv *Server) pendingOAuthFlow {
	key := oauth2FlowKey
	if srv != nil {
		key = srv.sessionKey(key)
	}
	flow, _ := sess.Get(key).(pendingOAuthFlow)
	return flow
}

func setTestOAuthFlow(sess *jaws.Session, srv *Server, flow pendingOAuthFlow) {
	key := oauth2FlowKey
	if srv != nil {
		key = srv.sessionKey(key)
	}
	sess.Set(key, flow)
}

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
		srv.oauth2cfg = &oauth2.Config{ClientID: namespace, RedirectURL: "https://app.example/auth/" + namespace + "/callback",
			Endpoint: oauth2.Endpoint{AuthURL: "https://provider.example/authorize", TokenURL: "https://provider.example/token"}}
		return srv
	}
	github, gitlab := newServer("github"), newServer("gitlab")
	if github.SessionKey == gitlab.SessionKey || github.SessionTokenKey == gitlab.SessionTokenKey ||
		github.SessionEmailKey == gitlab.SessionEmailKey || github.SessionEmailVerifiedKey == gitlab.SessionEmailVerifiedKey {
		t.Fatal("provider auth keys overlap")
	}
	r := httptest.NewRequest(http.MethodGet, "https://app.example/auth/github/login", nil)
	login := httptest.NewRecorder()
	github.HandleLogin(login, r)
	if login.Code != http.StatusFound {
		t.Fatalf("github start: %d", login.Code)
	}
	gitlab.LinkEvent = func(*jaws.Session, *http.Request, map[string]any) (int, error) { return 0, nil }
	linkRequest := httptest.NewRequest(http.MethodPost, "https://app.example/auth/gitlab/link", nil)
	for _, cookie := range login.Result().Cookies() {
		linkRequest.AddCookie(cookie)
	}
	link := httptest.NewRecorder()
	gitlab.HandleLink(link, linkRequest)
	if link.Code != http.StatusFound {
		t.Fatalf("gitlab link start: %d", link.Code)
	}
	sess := jw.GetSession(r)
	if sess == nil || jw.GetSession(linkRequest) != sess {
		t.Fatal("shared session missing")
	}
	read := func(srv *Server) pendingOAuthFlow { return testOAuthFlow(sess, srv) }
	githubState, gitlabState := read(github), read(gitlab)
	if githubState.state == "" || githubState.verifier == "" || githubState.nonce == "" ||
		gitlabState.state == "" || gitlabState.verifier == "" || gitlabState.nonce == "" ||
		githubState.state == gitlabState.state || githubState.verifier == gitlabState.verifier || githubState.nonce == gitlabState.nonce ||
		githubState.link || !gitlabState.link {
		t.Fatal("provider flows overlap or lack proof")
	}
	if _, err := github.takeOAuthFlow(sess, gitlabState.state); !errors.Is(err, ErrOAuth2WrongState) {
		t.Fatalf("github accepted gitlab state: %v", err)
	}
	if _, err := gitlab.takeOAuthFlow(sess, githubState.state); !errors.Is(err, ErrOAuth2WrongState) {
		t.Fatalf("gitlab accepted github state: %v", err)
	}
	if read(github) != githubState || read(gitlab) != gitlabState {
		t.Fatal("wrong-provider state changed a pending flow")
	}
	gotGitlab, err := gitlab.takeOAuthFlow(sess, gitlabState.state)
	if err != nil || gotGitlab.verifier != gitlabState.verifier || gotGitlab.nonce != gitlabState.nonce || !gotGitlab.link {
		t.Fatalf("gitlab link flow mismatch: %v", err)
	}
	if read(github) != githubState || read(gitlab).state != "" {
		t.Fatal("consuming gitlab flow changed github flow")
	}
	gotGithub, err := github.takeOAuthFlow(sess, githubState.state)
	if err != nil || gotGithub.verifier != githubState.verifier || gotGithub.nonce != githubState.nonce || gotGithub.link {
		t.Fatalf("github login flow mismatch: %v", err)
	}
	if read(github).state != "" {
		t.Fatal("github flow remained after consumption")
	}
}
