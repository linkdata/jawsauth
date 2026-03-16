package main

import (
	"context"
	"crypto/tls"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestIntegrationLoginWorks(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()

	passwordFile := filepath.Join(t.TempDir(), "password.txt")
	demo, err := startDemo(ctx, demoOptions{
		ListenAddr:   "127.0.0.1:0",
		PasswordFile: passwordFile,
		Realm:        "jawsauth-demo-it",
		ClientID:     "jawsauth-demo-it-client",
		Username:     "demouser",
		UserEmail:    "demouser@example.com",
	})
	if err != nil {
		if isDockerUnavailableError(err) {
			t.Skipf("docker unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer shutdownCancel()
		if closeErr := demo.close(shutdownCtx); closeErr != nil {
			t.Errorf("shutdown demo: %v", closeErr)
		}
	})

	passwordBytes, err := os.ReadFile(passwordFile)
	if err != nil {
		t.Fatal(err)
	}
	passwordFromFile := strings.TrimSpace(string(passwordBytes))
	if passwordFromFile == "" {
		t.Fatal("password file is empty")
	}
	if passwordFromFile != demo.password {
		t.Fatalf("password file mismatch: got %q want %q", passwordFromFile, demo.password)
	}

	adminToken, err := getAdminToken(ctx, demo.keycloak.httpClient, demo.keycloak.baseURL, defaultKeycloakAdminUser, demo.password)
	if err != nil {
		t.Fatalf("admin password check failed: %v", err)
	}
	if adminToken == "" {
		t.Fatal("empty admin token")
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		Jar: jar,
		Transport: &http.Transport{ //nolint:gosec
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true},
		},
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(demo.appURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	page, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initial status: %s", resp.Status)
	}

	loginAction, err := extractLoginAction(resp.Request.URL, page)
	if err != nil {
		t.Fatalf("extract login action: %v", err)
	}

	form := url.Values{}
	form.Set("username", demo.username)
	form.Set("password", demo.password)
	form.Set("credentialId", "")

	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, loginAction, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	loginResp, err := client.Do(postReq)
	if err != nil {
		t.Fatal(err)
	}
	loginBody, err := io.ReadAll(loginResp.Body)
	_ = loginResp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("post-login status: %s", loginResp.Status)
	}
	if !strings.Contains(string(loginBody), "JaWS OAuth2 Demo") {
		t.Fatalf("unexpected post-login body: %s", string(loginBody))
	}
	if !strings.Contains(string(loginBody), "Signed in as "+demo.userEmail) {
		t.Fatalf("missing signed-in marker in body: %s", string(loginBody))
	}

	logoutResp, err := client.Get(demo.appURL + "/logout")
	if err != nil {
		t.Fatal(err)
	}
	logoutBody, err := io.ReadAll(logoutResp.Body)
	_ = logoutResp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if logoutResp.StatusCode != http.StatusOK {
		body := string(logoutBody)
		if len(body) > 512 {
			body = body[:512]
		}
		t.Fatalf("logout status: %s url=%s body=%s", logoutResp.Status, logoutResp.Request.URL.String(), body)
	}
	if !strings.Contains(string(logoutBody), "Signed out") {
		t.Fatalf("unexpected logout body: %s", string(logoutBody))
	}

	reloginResp, err := client.Get(demo.appURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	reloginBody, err := io.ReadAll(reloginResp.Body)
	_ = reloginResp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if reloginResp.StatusCode != http.StatusOK {
		t.Fatalf("relogin status: %s", reloginResp.Status)
	}
	if strings.Contains(string(reloginBody), "Signed in as "+demo.userEmail) {
		t.Fatalf("user should not remain signed in after logout: %s", string(reloginBody))
	}
	if _, err = extractLoginAction(reloginResp.Request.URL, reloginBody); err != nil {
		t.Fatalf("expected login form after logout: %v", err)
	}
}

func extractLoginAction(baseURL *url.URL, body []byte) (string, error) {
	re := regexp.MustCompile(`action="([^"]+)"`)
	parts := re.FindSubmatch(body)
	if len(parts) != 2 {
		return "", errors.New("login form action not found")
	}
	action := html.UnescapeString(string(parts[1]))
	u, err := baseURL.Parse(action)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}
