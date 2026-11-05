package jawsauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
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
	flow.owner = srv
	sess.Set(srv.sessionKey(oauth2FlowKey), flow)
}

func TestOAuthFlowNamespacesShareSessionWithoutSharingState(t *testing.T) {
	jw := newTestJaws(t)
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
	if link.Code != http.StatusSeeOther {
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

func TestOAuthFlowDefaultNamespaceRejectsForeignServer(t *testing.T) {
	jw := newTestJaws(t)
	newServer := func(clientID string) *Server {
		srv, err := New(jw, &Config{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		srv.oauth2cfg = &oauth2.Config{
			ClientID:    clientID,
			RedirectURL: "https://app.example/auth/" + clientID + "/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://" + clientID + ".example/authorize",
				TokenURL: "https://" + clientID + ".example/token",
			},
		}
		return srv
	}
	github, gitlab := newServer("github"), newServer("gitlab")
	loginRequest := httptest.NewRequest(http.MethodGet, "https://app.example/auth/gitlab/login", nil)
	login := httptest.NewRecorder()
	gitlab.HandleLogin(login, loginRequest)
	if login.Code != http.StatusFound {
		t.Fatalf("gitlab start: %d", login.Code)
	}
	sess := jw.GetSession(loginRequest)
	flow := testOAuthFlow(sess, gitlab)
	if flow.state == "" {
		t.Fatal("gitlab state missing")
	}
	exchanges := 0
	github.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		exchanges++
		return nil, errors.New("unexpected token exchange")
	})}
	callbackRequest := httptest.NewRequest(http.MethodGet, "https://app.example/auth/github/callback?code=foreign&state="+flow.state, nil)
	for _, cookie := range login.Result().Cookies() {
		callbackRequest.AddCookie(cookie)
	}
	callback := httptest.NewRecorder()
	github.HandleAuthResponse(callback, callbackRequest)
	if callback.Code != http.StatusBadRequest || exchanges != 0 {
		t.Fatalf("foreign callback: status %d, token exchanges %d", callback.Code, exchanges)
	}
	if got := testOAuthFlow(sess, gitlab); got != flow {
		t.Fatal("foreign callback changed gitlab flow")
	}
	if _, err := gitlab.takeOAuthFlow(sess, flow.state); err != nil {
		t.Fatalf("gitlab lost its own state: %v", err)
	}
}

func TestOAuthFlowDefaultNamespaceWrapperDoesNotReissueForeignFlow(t *testing.T) {
	for _, inFlight := range []bool{false, true} {
		name := "pending"
		if inFlight {
			name = "callback_in_flight"
		}
		t.Run(name, func(t *testing.T) {
			jw := newTestJaws(t)
			newServer := func(clientID string) *Server {
				srv, err := New(jw, &Config{}, nil)
				if err != nil {
					t.Fatal(err)
				}
				srv.oauth2cfg = &oauth2.Config{
					ClientID: clientID, RedirectURL: "https://app.example/auth/" + clientID + "/callback",
					Endpoint: oauth2.Endpoint{AuthURL: "https://" + clientID + ".example/authorize", TokenURL: "https://" + clientID + ".example/token"},
				}
				srv.idTokenVerifier = oidc.NewVerifier("https://"+clientID+".example", passthroughKeySet{}, &oidc.Config{ClientID: clientID})
				return srv
			}
			github, gitlab := newServer("github"), newServer("gitlab")
			sessionResponse := httptest.NewRecorder()
			sess := jw.NewSession(sessionResponse, httptest.NewRequest(http.MethodGet, "https://app.example/", nil))
			cookie := sessionResponse.Result().Cookies()[0]
			start := func(srv *Server, path string) *httptest.ResponseRecorder {
				request := httptest.NewRequest(http.MethodGet, "https://app.example"+path, nil)
				request.AddCookie(cookie)
				response := httptest.NewRecorder()
				srv.HandleLogin(response, request)
				if response.Code != http.StatusFound {
					t.Fatalf("%s login: %d", path, response.Code)
				}
				return response
			}
			if inFlight {
				start(github, "/auth/github/login")
				flow := testOAuthFlow(sess, github)
				if _, err := github.takeOAuthFlow(sess, flow.state); err != nil {
					t.Fatalf("github callback start: %v", err)
				}
			}
			gitlabLogin := start(gitlab, "/auth/gitlab/login")
			gitlabFlow := testOAuthFlow(sess, gitlab)
			gitlabURL, err := url.Parse(gitlabLogin.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "https://app.example/protected", nil)
			request.AddCookie(cookie)
			response := httptest.NewRecorder()
			github.Wrap(testStatusHandler{statusCode: http.StatusOK}).ServeHTTP(response, request)
			if response.Code != http.StatusConflict || response.Header().Get("Location") != "" {
				t.Fatalf("foreign flow reissued: status %d, location %q", response.Code, response.Header().Get("Location"))
			}
			for _, key := range []string{"state", "nonce", "code_challenge"} {
				value := gitlabURL.Query().Get(key)
				if value == "" || strings.Contains(response.Body.String(), value) {
					t.Fatalf("foreign %s missing or exposed in response body", key)
				}
			}
			if got := testOAuthFlow(sess, gitlab); got != gitlabFlow {
				t.Fatal("foreign wrapper changed gitlab flow")
			}
			if _, err := gitlab.takeOAuthFlow(sess, gitlabFlow.state); err != nil {
				t.Fatalf("gitlab lost its own state: %v", err)
			}
		})
	}
}
