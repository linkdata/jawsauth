package jawsauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

func TestOAuthTokenRequestsDoNotFollowRedirect(t *testing.T) {
	for _, grant := range []string{"exchange", "refresh"} {
		for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
			t.Run(fmt.Sprintf("%s/%d", grant, status), func(t *testing.T) {
				var secondHop atomic.Int32
				target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					secondHop.Add(1)
				}))
				defer target.Close()
				var firstHop atomic.Int32
				provider := httptest.NewTLSServer(http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
					firstHop.Add(1)
					if hr.URL.Path != "/token" || hr.Method != http.MethodPost {
						t.Errorf("token request: %s %s", hr.Method, hr.URL.Path)
					}
					if err := hr.ParseForm(); err != nil {
						t.Error(err)
					}
					if hr.PostForm.Get("client_secret") != "client-secret" {
						t.Errorf("first hop client secret = %q", hr.PostForm.Get("client_secret"))
					}
					if grant == "exchange" {
						if hr.PostForm.Get("grant_type") != "authorization_code" ||
							hr.PostForm.Get("code") != "auth-code" || hr.PostForm.Get("code_verifier") != "pkce-verifier" {
							t.Errorf("first hop exchange form = %v", hr.PostForm)
						}
					} else if hr.PostForm.Get("grant_type") != "refresh_token" || hr.PostForm.Get("refresh_token") != "refresh-secret" {
						t.Errorf("first hop refresh form = %v", hr.PostForm)
					}
					hw.Header().Set("Location", target.URL+"/leak")
					hw.WriteHeader(status)
				}))
				defer provider.Close()

				client := provider.Client()
				client.Timeout = 3 * time.Second
				client.CheckRedirect = func(*http.Request, []*http.Request) error {
					t.Error("original redirect policy was used")
					return nil
				}
				logger := &testAuthDebugLogger{}
				srv := &Server{httpClient: client}
				if grant == "refresh" && status == http.StatusPermanentRedirect {
					srv.Jaws = &jaws.Jaws{Debug: true, Logger: logger}
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if grant == "exchange" {
					// The request context's client takes precedence over Server.httpClient.
					srv.httpClient = nil
					ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
				}
				authctx := srv.oauth2Context(ctx)
				cfg := oauth2.Config{ClientID: "client", ClientSecret: "client-secret",
					Endpoint: oauth2.Endpoint{TokenURL: provider.URL + "/token", AuthStyle: oauth2.AuthStyleInParams}}
				var err error
				if grant == "exchange" {
					_, err = cfg.Exchange(authctx, "auth-code", oauth2.SetAuthURLParam("code_verifier", "pkce-verifier"))
				} else {
					_, err = cfg.TokenSource(authctx, &oauth2.Token{RefreshToken: "refresh-secret"}).Token()
				}
				var retrieve *oauth2.RetrieveError
				if !errors.As(err, &retrieve) || retrieve.Response == nil || retrieve.Response.StatusCode != status {
					t.Fatalf("redirect response = %v, want HTTP %d", err, status)
				}
				if firstHop.Load() != 1 || secondHop.Load() != 0 {
					t.Fatalf("token request hops: first=%d second=%d", firstHop.Load(), secondHop.Load())
				}
				if srv.Jaws != nil && !logger.hasInfo("jawsauth: oauth2 request") {
					t.Fatal("debug wrapper did not observe token request")
				}
			})
		}
	}
}
