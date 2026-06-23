package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/linkdata/jaws"
	"github.com/linkdata/jawsauth"
)

type demoTestAddr string

func (a demoTestAddr) Network() string { return "tcp" }
func (a demoTestAddr) String() string  { return string(a) }

func TestDemoOptionsWithDefaults(t *testing.T) {
	got := demoOptions{}.withDefaults()
	if got.ListenAddr != "0.0.0.0:8443" {
		t.Fatal(got.ListenAddr)
	}
	if got.PasswordFile != "demo-password.txt" {
		t.Fatal(got.PasswordFile)
	}
	if got.Realm != "jawsauth-demo" {
		t.Fatal(got.Realm)
	}
	if got.ClientID != "jawsauth-demo-client" {
		t.Fatal(got.ClientID)
	}
	if got.Username != "demo" {
		t.Fatal(got.Username)
	}
	if got.UserEmail != "demo@example.com" {
		t.Fatal(got.UserEmail)
	}
	if got.KeycloakImage != "quay.io/keycloak/keycloak:latest" {
		t.Fatal(got.KeycloakImage)
	}

	custom := demoOptions{
		ListenAddr:    "127.0.0.1:9443",
		PublicHost:    "public.example",
		PasswordFile:  "password.txt",
		Realm:         "realm",
		ClientID:      "client",
		Username:      "user",
		UserEmail:     "user@example.com",
		KeycloakImage: "keycloak:test",
	}
	if got = custom.withDefaults(); got != custom {
		t.Fatalf("custom options changed: %#v", got)
	}
}

func TestDemoLoginFailedDefaultsAndPlainHTTP(t *testing.T) {
	rr := httptest.NewRecorder()
	if !demoLoginFailed(rr, nil, http.StatusOK, errors.New("boom"), "") {
		t.Fatal("handler returned false")
	}
	resp := rr.Result()
	defer closeResponseBody(t, resp)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatal(resp.StatusCode)
	}
	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Fatal("plain HTTP response set HSTS")
	}
}

func TestResolvePublicHost(t *testing.T) {
	host, err := resolvePublicHost(" public.example ", &net.TCPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	if host != "public.example" {
		t.Fatal(host)
	}

	host, err = resolvePublicHost("", &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 8443})
	if err != nil {
		t.Fatal(err)
	}
	if host != "192.0.2.10" {
		t.Fatal(host)
	}

	host, err = resolvePublicHost("", demoTestAddr("demo.example:9443"))
	if err != nil {
		t.Fatal(err)
	}
	if host != "demo.example" {
		t.Fatal(host)
	}

	if _, err = resolvePublicHost("", demoTestAddr("not hostport")); err == nil {
		t.Fatal("expected invalid address error")
	}

	host, err = resolvePublicHost("", &net.TCPAddr{IP: net.IPv4zero, Port: 8443})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(host) == "" {
		t.Fatal("empty wildcard TCP host")
	}

	host, err = resolvePublicHost("", demoTestAddr("0.0.0.0:8443"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(host) == "" {
		t.Fatal("empty wildcard hostport host")
	}
}

func TestDefaultInterfaceAddress(t *testing.T) {
	addr, err := defaultInterfaceAddress()
	if err != nil {
		t.Skipf("default interface unavailable: %v", err)
	}
	if net.ParseIP(addr) == nil {
		t.Fatal(addr)
	}
}

func TestWaitForHTTPSReady(t *testing.T) {
	ready := httptest.NewTLSServer(http.HandlerFunc(func(hw http.ResponseWriter, _ *http.Request) {
		hw.WriteHeader(http.StatusNoContent)
	}))
	defer ready.Close()
	if err := waitForHTTPSReady(t.Context(), ready.URL); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := waitForHTTPSReady(ctx, "https://127.0.0.1:1"); err == nil {
		t.Fatal("expected cancellation error")
	}

	if err := waitForHTTPSReady(t.Context(), "http://[::1"); err == nil {
		t.Fatal("expected invalid URL error")
	}
}

func TestRandomPassword(t *testing.T) {
	password := randomPassword(18)
	if password == "" {
		t.Fatal("empty password")
	}
}

func TestWritePasswordFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password.txt")
	if err := writePasswordFile(path, "secret"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "secret\n" {
		t.Fatal(string(data))
	}
	if err = writePasswordFile(filepath.Join(t.TempDir(), "missing", "password.txt"), "secret"); err == nil {
		t.Fatal("expected write error")
	}
}

func TestWriteTLSCertDirAndGenerateCertificate(t *testing.T) {
	certDir, err := writeTLSCertDir("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(certDir)
	})
	for _, name := range []string{"fullchain.pem", "privkey.pem"} {
		if _, err := os.Stat(filepath.Join(certDir, name)); err != nil {
			t.Fatal(err)
		}
	}

	certPEM, keyPEM, err := generateSelfSignedCertificatePEM("demo.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("missing pem data")
	}
	cert, err := parseFirstCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !stringSliceContains(cert.DNSNames, "demo.example") {
		t.Fatal(cert.DNSNames)
	}
	if !stringSliceContains(cert.DNSNames, "localhost") {
		t.Fatal(cert.DNSNames)
	}
	if !containsIP(cert.IPAddresses, net.IPv4(127, 0, 0, 1)) {
		t.Fatal(cert.IPAddresses)
	}

	certPEM, _, err = generateSelfSignedCertificatePEM("localhost")
	if err != nil {
		t.Fatal(err)
	}
	cert, err = parseFirstCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !stringSliceContains(cert.DNSNames, "localhost") {
		t.Fatal(cert.DNSNames)
	}
}

func TestWriteTLSCertDirTempDirError(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	if _, err := writeTLSCertDir("localhost"); err == nil {
		t.Fatal("expected temp dir error")
	}
}

func TestDemoServerCloseRemovesResources(t *testing.T) {
	certDir := t.TempDir()
	keycloakDir := t.TempDir()
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}

	demo := &demoServer{
		httpServer: &http.Server{},
		jaws:       jw,
		keycloak:   &keycloakServer{certTempDir: keycloakDir},
		certDir:    certDir,
	}
	if err = demo.close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = demo.close(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{certDir, keycloakDir} {
		if _, err = os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stat %s: %v", dir, err)
		}
	}
}

func TestDemoLogoutHandlerRedirects(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(jw.Close)

	authServer := &jawsauth.Server{SessionTokenKey: "tokens"}
	for _, tc := range []struct {
		name          string
		endSessionURL string
		wantLocation  string
	}{
		{name: "empty end session", wantLocation: "/logged-out"},
		{name: "invalid end session", endSessionURL: "http://[::1", wantLocation: "/logged-out"},
		{name: "valid end session", endSessionURL: "https://issuer.example/logout"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "https://app.example/logout", nil)
			handler := demoLogoutHandler(jw, authServer, "https://app.example", "client-id", tc.endSessionURL)

			handler(rr, req)

			resp := rr.Result()
			defer closeResponseBody(t, resp)
			if resp.StatusCode != http.StatusFound {
				t.Fatal(resp.Status)
			}
			location := resp.Header.Get("Location")
			if tc.wantLocation != "" {
				if location != tc.wantLocation {
					t.Fatalf("location = %q, want %q", location, tc.wantLocation)
				}
				return
			}

			u, err := url.Parse(location)
			if err != nil {
				t.Fatal(err)
			}
			if u.Scheme != "https" || u.Host != "issuer.example" || u.Path != "/logout" {
				t.Fatal(location)
			}
			q := u.Query()
			if q.Get("client_id") != "client-id" {
				t.Fatal(location)
			}
			if q.Get("post_logout_redirect_uri") != "https://app.example/logged-out" {
				t.Fatal(location)
			}
			if q.Get("id_token_hint") != "" {
				t.Fatal(location)
			}
		})
	}
}

func TestStartDemoInvalidListenAddress(t *testing.T) {
	_, err := startDemo(t.Context(), demoOptions{ListenAddr: "not a tcp address"})
	if err == nil || !strings.Contains(err.Error(), "resolve listen address") {
		t.Fatalf("error = %v, want listen address error", err)
	}
}

func TestAppOriginFromRedirectURI(t *testing.T) {
	origin, err := appOriginFromRedirectURI("https://demo.example:8443/oauth2/callback?x=1")
	if err != nil {
		t.Fatal(err)
	}
	if origin != "https://demo.example:8443" {
		t.Fatal(origin)
	}
	if _, err = appOriginFromRedirectURI("http://[::1"); err == nil {
		t.Fatal("expected parse error")
	}
	if _, err = appOriginFromRedirectURI("/oauth2/callback"); err == nil {
		t.Fatal("expected invalid redirect URI")
	}
}

func TestExtractLoginActionErrors(t *testing.T) {
	if _, err := extractLoginAction(nil, []byte(`<html></html>`)); err == nil {
		t.Fatal("expected missing form error")
	}
	if _, err := extractLoginAction(&urlForTest, []byte(`action="http://[::1"`)); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestIsDockerUnavailableError(t *testing.T) {
	if isDockerUnavailableError(nil) {
		t.Fatal("nil error matched")
	}
	if isDockerUnavailableError(errors.New("ordinary failure")) {
		t.Fatal("ordinary error matched")
	}
	for _, msg := range []string{
		"Cannot connect to the Docker daemon",
		"is the docker daemon running",
		"failed to create Docker client",
		"permission denied while trying to connect to the Docker daemon socket",
		"open /var/run/docker.sock: permission denied",
	} {
		if !isDockerUnavailableError(errors.New(msg)) {
			t.Fatalf("did not match %q", msg)
		}
	}
}

var urlForTest = *mustParseURL("https://demo.example/")

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

func parseFirstCertificate(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("missing certificate block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}

func TestListenerPort(t *testing.T) {
	if port := listenerPort(demoTestAddr("127.0.0.1:12345")); port != "12345" {
		t.Fatal(port)
	}
}

func TestWaitForHTTPSReadyContextDuringRetry(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(hw http.ResponseWriter, _ *http.Request) {
		hw.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(t.Context())
	timer := time.AfterFunc(20*time.Millisecond, cancel)
	defer timer.Stop()
	if err := waitForHTTPSReady(ctx, server.URL); err == nil {
		t.Fatal("expected cancellation")
	}
}
