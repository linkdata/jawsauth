package jawsauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/linkdata/jaws"
)

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

	req := httptest.NewRequest(http.MethodGet, "https://application.example.com/", nil)
	rec := httptest.NewRecorder()
	sess := jw.NewSession(rec, req)
	auth, ok := jw.MakeAuth(jw.NewRequest(rec, req)).(*JawsAuth)
	if !ok {
		t.Fatal("MakeAuth did not return *JawsAuth")
	}
	if auth.server != srv {
		t.Fatal("MakeAuth returned auth for another server")
	}
	if auth.sess != sess {
		t.Fatal("MakeAuth returned auth for another session")
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

func TestServerSet403HandlerNilRestoresDefault(t *testing.T) {
	srv := &Server{handle403: testStatusHandler{statusCode: http.StatusTeapot}}
	srv.Set403Handler(nil)

	rec := httptest.NewRecorder()
	srv.get403Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://example.com/", nil))

	if rec.Code != http.StatusForbidden {
		t.Fatal(rec.Code)
	}
	if got := rec.Body.String(); got != `<html><body><h1>403 Forbidden</h1></body></html>` {
		t.Fatal(got)
	}
}
