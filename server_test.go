package jawsauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/linkdata/deadlock"
	"github.com/linkdata/jaws"
	"github.com/linkdata/jaws/lib/ui"
)

func getOpenIDConfig(baseURL, realm string) (openidcfg map[string]any, err error) {
	openIdConfigURL := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", baseURL, realm)
	var hr *http.Response
	if hr, err = http.Get(openIdConfigURL); err == nil {
		defer func() {
			if closeErr := hr.Body.Close(); err == nil && closeErr != nil {
				err = closeErr
			}
		}()
		var b []byte
		if b, err = io.ReadAll(hr.Body); err == nil {
			err = json.Unmarshal(b, &openidcfg)
		}
	}
	return
}

type testJar struct {
	cookies []*http.Cookie
}

func (tj *testJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	tj.cookies = append(tj.cookies, cookies...)
}

func (tj *testJar) Cookies(u *url.URL) []*http.Cookie {
	return tj.cookies
}

func serverHandlerTest(t *testing.T, baseURL, realm, clientID, clientSecret string) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	client := &http.Client{Jar: &testJar{}}

	openidcfg, err := getOpenIDConfig(baseURL, realm)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	hsrv := httptest.NewServer(mux)
	defer hsrv.Close()

	jw, err := jaws.New() // create a default JaWS instance
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close() // ensure we clean up

	const indexTemplate = `<html>{{with .Auth}}{{.Email}} {{.IsAdmin}} {{.Data}}{{end}}</html>`

	if err := jw.AddTemplateLookuper(template.Must(template.New("index.html").Parse(indexTemplate))); err != nil {
		t.Fatal(err)
	}
	jw.Logger = slog.Default()               // optionally set the logger to use
	jw.Debug = deadlock.Debug                // optionally set the debug flag
	go jw.Serve()                            // start the JaWS processing loop
	mux.Handle(http.MethodGet+" /jaws/", jw) // ensure the JaWS routes are handled

	cfg := Config{
		RedirectURL:         hsrv.URL + "/oauth2/callback",
		Issuer:              openidcfg["issuer"].(string),
		AllowInsecureIssuer: true,
		Scopes:              []string{"profile"},
		ClientID:            clientID,
		ClientSecret:        clientSecret,
	}

	handleGet := func(uri string, handler http.Handler) {
		mux.Handle(http.MethodGet+" "+uri, handler)
	}
	asrv, err := New(jw, &cfg, handleGet)
	if err != nil {
		t.Fatal(err)
	}
	var logincount int
	asrv.LoginEvent = func(sess *jaws.Session, hr *http.Request) { logincount++ }
	asrv.LogoutEvent = func(sess *jaws.Session, hr *http.Request) { logincount-- }

	if !asrv.Valid() {
		t.Fatal()
	}

	asrv.Set403Handler(nil)

	mux.Handle(http.MethodGet+" /needauth", asrv.Handler("index.html", nil))
	mux.Handle(http.MethodGet+" /needadmin", asrv.HandlerAdmin("index.html", nil))
	mux.Handle(http.MethodGet+" /", ui.Handler(jw, "index.html", nil))

	asrv.Wrap(http.NotFoundHandler())
	asrv.WrapAdmin(http.NotFoundHandler())

	initialresp, err := client.Get(hsrv.URL + "/needauth")
	if err != nil {
		t.Fatal(err)
	}

	if initialresp.StatusCode != http.StatusOK {
		_ = initialresp.Body.Close()
		t.Fatal(initialresp.Status)
	}

	if logincount != 0 {
		t.Error(logincount)
	}

	b, err := io.ReadAll(initialresp.Body)
	_ = initialresp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	re := regexp.MustCompile(`action="http[^"]+"`)
	p := re.Find(b)
	if p == nil {
		t.Log(string(b))
		t.Fatal("did not find action")
	}
	action := html.UnescapeString(string(p[8 : len(p)-1]))
	params := url.Values{}
	params.Add("username", "testuser")
	params.Add("password", "password123")
	params.Add("credentialId", "")

	postreq, err := http.NewRequestWithContext(ctx, http.MethodPost, action, strings.NewReader(params.Encode()))
	if err != nil {
		t.Fatal(err)
	}

	postreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(postreq)

	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		t.Fatal(resp.Status)
	}

	if logincount != 1 {
		t.Error(logincount)
	}

	b, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	resphtml := html.UnescapeString(string(b))
	invalidpass := "Invalid username or password."
	if strings.Contains(resphtml, invalidpass) {
		t.Log(resp.Status)
		t.Log(resp.Header)
		t.Log(resphtml)
		t.Fatal(invalidpass)
	}

	if !strings.HasPrefix(resphtml, "<html>testuser@example.com true map[") {
		t.Fatal(resphtml)
	}
	if !strings.Contains(resphtml, "email:testuser@example.com") {
		t.Fatal(resphtml)
	}
	if !strings.Contains(resphtml, "email_verified:false") {
		t.Fatal(resphtml)
	}
	if !strings.Contains(resphtml, "sub:") {
		t.Fatal(resphtml)
	}

	resp, err = client.Get(hsrv.URL + "/needauth")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Log(resp.Header)
		t.Fatal(resp.Status)
	}

	if logincount != 1 {
		t.Error(logincount)
	}

	resp, err = client.Get(hsrv.URL + "/oauth2/logout")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Log(resp.Header)
		t.Fatal(resp.Status)
	}

	if logincount != 0 {
		t.Error(logincount)
	}

	if !asrv.IsAdmin("testuser@example.com") {
		t.Error("empty admin list, all should be admins")
	}

	asrv.SetAdmins([]string{"admin@example.com"})

	if asrv.IsAdmin("testuser@example.com") {
		t.Error("testuser was admin")
	}

	if !asrv.IsAdmin("admin@example.com") {
		t.Error("was not admin")
	}

	resp, err = client.Get(hsrv.URL + "/needadmin")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Log(resp.Header)
		t.Fatal(resp.Status)
	}

	asrv.SetAdmins([]string{"Test User <testuser@example.com>", "admin@example.com"})

	admins := strings.Join(asrv.GetAdmins(), ",")
	if admins != "admin@example.com,testuser@example.com" {
		t.Error(admins)
	}

	resp, err = client.Get(hsrv.URL + "/needadmin")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Log(resp.Header)
		t.Fatal(resp.Status)
	}
}

func TestNewDebugFailureDoesNotReplaceMakeAuth(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	jw.MakeAuth = func(*jaws.Request) jaws.Auth {
		return &jaws.DefaultAuth{}
	}
	wantMakeAuth := reflect.ValueOf(jw.MakeAuth).Pointer()
	var handled []string
	cfg := &Config{
		RedirectURL: "https://application.example.com/oauth2/callback",
		ClientID:    "the-client-id",
	}

	srv, err := New(jw, cfg, func(uri string, handler http.Handler) {
		_ = handler
		handled = append(handled, uri)
	})
	if err == nil {
		t.Fatal("expected config error")
	}
	if srv == nil {
		t.Fatal("expected server value")
	}
	if gotMakeAuth := reflect.ValueOf(jw.MakeAuth).Pointer(); gotMakeAuth != wantMakeAuth {
		t.Fatal("MakeAuth was replaced after failed setup")
	}
	if len(handled) != 0 {
		t.Fatal(handled)
	}
}

func TestNewDebugPreservesCallbackTrailingSlash(t *testing.T) {
	discovery := newOIDCDiscoveryServer(t)
	defer discovery.Close()

	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	handled := make(map[string]http.Handler)
	cfg := &Config{
		RedirectURL:         "https://application.example.com/oauth2/callback/",
		Issuer:              discovery.URL,
		AllowInsecureIssuer: true,
		ClientID:            "the-client-id",
	}

	srv, err := New(jw, cfg, func(uri string, handler http.Handler) {
		handled[uri] = handler
	})
	if err != nil {
		t.Fatal(err)
	}
	if !srv.Valid() {
		t.Fatal("server was not valid")
	}
	for _, want := range []string{"/oauth2/callback/", "/oauth2/login", "/oauth2/logout"} {
		if handled[want] == nil {
			t.Fatalf("missing handled path %s: %#v", want, handled)
		}
	}
	if handled["/oauth2/callback"] != nil {
		t.Fatal("registered cleaned callback path without trailing slash")
	}
	if jw.MakeAuth == nil {
		t.Fatal("MakeAuth was not installed after successful setup")
	}
}

func TestCallbackPathFromURL(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "empty",
			want: "/",
		},
		{
			name: "root",
			path: "/",
			want: "/",
		},
		{
			name: "cleaned",
			path: "/oauth2/./callback",
			want: "/oauth2/callback",
		},
		{
			name: "trailingSlash",
			path: "/oauth2/callback/",
			want: "/oauth2/callback/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := callbackPathFromURL(&url.URL{Path: tt.path})
			if got != tt.want {
				t.Fatalf("callbackPathFromURL(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestSetAdminsInitializesZeroValueMap(t *testing.T) {
	srv := &Server{}
	srv.SetAdmins([]string{"Admin <admin@example.com>"})

	if got := strings.Join(srv.GetAdmins(), ","); got != "admin@example.com" {
		t.Fatal(got)
	}
	if !srv.IsAdmin("admin@example.com") {
		t.Fatal("admin was not accepted")
	}
	if !srv.IsAdmin("Admin <ADMIN@example.com>") {
		t.Fatal("admin check was not normalized")
	}
	if srv.IsAdmin("user@example.com") {
		t.Fatal("unexpected admin")
	}
}

func TestNew_NilJawsReturnsError(t *testing.T) {
	discovery := newOIDCDiscoveryServer(t)
	defer discovery.Close()

	cfg := &Config{
		RedirectURL:         "https://application.example.com/oauth2/callback",
		Issuer:              discovery.URL,
		AllowInsecureIssuer: true,
		ClientID:            "the-client-id",
	}
	handleFn := func(uri string, h http.Handler) {
		_, _ = uri, h
	}

	srv, err := New(nil, cfg, handleFn)
	if !errors.Is(err, ErrServerNilJaws) {
		t.Fatalf("expected ErrServerNilJaws, got %v", err)
	}
	if srv != nil {
		t.Fatalf("expected nil server, got %#v", srv)
	}
}

func TestServer_IsAdmin_TableCases(t *testing.T) {
	type want struct {
		email string
		admin bool
	}
	for _, tc := range []struct {
		name   string
		admins []string
		cases  []want
	}{
		{
			name:   "empty list allows everyone",
			admins: nil,
			cases: []want{
				{email: "anyone@example.com", admin: true},
				{email: "", admin: true},
			},
		},
		{
			name:   "non-empty list only allows listed",
			admins: []string{"admin@example.com"},
			cases: []want{
				{email: "admin@example.com", admin: true},
				{email: "user@example.com", admin: false},
				{email: "", admin: false},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := &Server{}
			srv.SetAdmins(tc.admins)
			for _, c := range tc.cases {
				if got := srv.IsAdmin(c.email); got != c.admin {
					t.Errorf("IsAdmin(%q) = %v, want %v", c.email, got, c.admin)
				}
			}
		})
	}

	var nilSrv *Server
	if !nilSrv.IsAdmin("anyone@example.com") {
		t.Fatal("nil receiver should report admin")
	}
}

func TestServer_SetAdmins_NormalizesAndDeduplicates(t *testing.T) {
	srv := &Server{}
	srv.SetAdmins([]string{
		"  Admin@Example.COM  ",
		"admin@example.com",
		"Display Name <Other@Example.com>",
		"   ",
		"",
	})

	got := srv.GetAdmins()
	want := []string{"admin@example.com", "other@example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GetAdmins() = %#v, want %#v", got, want)
	}
	if !srv.IsAdmin("ADMIN@example.com") {
		t.Fatal("case-insensitive lookup failed")
	}
	if !srv.IsAdmin("  other@example.com  ") {
		t.Fatal("whitespace lookup failed")
	}
}
