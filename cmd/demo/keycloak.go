package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	defaultKeycloakAdminUser = "admin"
)

type keycloakServer struct {
	container   testcontainers.Container
	baseURL     string
	httpClient  *http.Client
	certTempDir string
	adminPass   string
}

type keycloakRealmSetup struct {
	Realm       string
	ClientID    string
	RedirectURI string
	Username    string
	Email       string
	Password    string
}

type keycloakOIDC struct {
	AuthURL       string
	TokenURL      string
	UserInfoURL   string
	EndSessionURL string
	ClientSecret  string
}

func startKeycloakServer(ctx context.Context, image, adminPassword string) (*keycloakServer, error) {
	if strings.TrimSpace(adminPassword) == "" {
		return nil, errors.New("empty keycloak admin password")
	}

	certTempDir, err := os.MkdirTemp("", "jawsauth-keycloak-cert-*")
	if err != nil {
		return nil, fmt.Errorf("create keycloak cert temp dir: %w", err)
	}
	cleanupTempDir := func() {
		_ = os.RemoveAll(certTempDir)
	}

	certPEM, keyPEM, err := generateSelfSignedCertificatePEM("localhost")
	if err != nil {
		cleanupTempDir()
		return nil, err
	}

	certPath := filepath.Join(certTempDir, "server.crt")
	keyPath := filepath.Join(certTempDir, "server.key")
	if err = os.WriteFile(certPath, certPEM, 0o644); err != nil {
		cleanupTempDir()
		return nil, fmt.Errorf("write keycloak cert: %w", err)
	}
	if err = os.WriteFile(keyPath, keyPEM, 0o644); err != nil {
		cleanupTempDir()
		return nil, fmt.Errorf("write keycloak key: %w", err)
	}

	req := testcontainers.ContainerRequest{
		Image:        image,
		ExposedPorts: []string{"8443/tcp"},
		Env: map[string]string{
			"KC_BOOTSTRAP_ADMIN_USERNAME":   defaultKeycloakAdminUser,
			"KC_BOOTSTRAP_ADMIN_PASSWORD":   adminPassword,
			"KC_HTTP_ENABLED":               "false",
			"KC_HTTPS_PORT":                 "8443",
			"KC_HTTPS_CERTIFICATE_FILE":     "/opt/keycloak/conf/server.crt",
			"KC_HTTPS_CERTIFICATE_KEY_FILE": "/opt/keycloak/conf/server.key",
			"KC_HOSTNAME_STRICT":            "false",
		},
		Cmd: []string{"start-dev", "--https-port=8443", "--http-enabled=false"},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: certPath, ContainerFilePath: "/opt/keycloak/conf/server.crt", FileMode: 0o644},
			{HostFilePath: keyPath, ContainerFilePath: "/opt/keycloak/conf/server.key", FileMode: 0o644},
		},
		WaitingFor: wait.ForHTTP("/").
			WithPort("8443/tcp").
			WithTLS(true).
			WithAllowInsecure(true).
			WithStartupTimeout(2 * time.Minute),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		cleanupTempDir()
		return nil, fmt.Errorf("start keycloak container: %w", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		cleanupTempDir()
		return nil, fmt.Errorf("resolve keycloak host: %w", err)
	}

	port, err := container.MappedPort(ctx, "8443/tcp")
	if err != nil {
		_ = container.Terminate(ctx)
		cleanupTempDir()
		return nil, fmt.Errorf("resolve keycloak port: %w", err)
	}

	publicHost := host
	switch strings.TrimSpace(strings.ToLower(publicHost)) {
	case "", "localhost", "127.0.0.1", "::1", "0.0.0.0", "::":
		if s, e := defaultInterfaceAddress(); e == nil {
			publicHost = s
		}
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{ //nolint:gosec
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}

	return &keycloakServer{
		container:   container,
		baseURL:     fmt.Sprintf("https://%s:%s", publicHost, port.Port()),
		httpClient:  &http.Client{Transport: transport, Timeout: 30 * time.Second},
		certTempDir: certTempDir,
		adminPass:   adminPassword,
	}, nil
}

func (ks *keycloakServer) Close(ctx context.Context) error {
	if ks == nil {
		return nil
	}
	var errs []error
	if ks.container != nil {
		errs = append(errs, ks.container.Terminate(ctx))
	}
	if ks.certTempDir != "" {
		errs = append(errs, os.RemoveAll(ks.certTempDir))
	}
	return errors.Join(errs...)
}

func (ks *keycloakServer) SetupRealm(ctx context.Context, setup keycloakRealmSetup) (oidc keycloakOIDC, err error) {
	adminToken, err := getAdminToken(ctx, ks.httpClient, ks.baseURL, defaultKeycloakAdminUser, ks.adminPass)
	if err != nil {
		return oidc, fmt.Errorf("get admin token: %w", err)
	}

	if err = createRealm(ctx, ks.httpClient, ks.baseURL, adminToken, setup.Realm); err != nil {
		return oidc, fmt.Errorf("create realm: %w", err)
	}

	clientUUID, err := createClient(ctx, ks.httpClient, ks.baseURL, adminToken, setup.Realm, setup.ClientID, setup.RedirectURI)
	if err != nil {
		return oidc, fmt.Errorf("create client: %w", err)
	}

	clientSecret, err := randomPassword(18)
	if err != nil {
		return oidc, fmt.Errorf("generate client secret: %w", err)
	}

	clientSecret, err = setClientSecret(ctx, ks.httpClient, ks.baseURL, adminToken, setup.Realm, clientUUID, clientSecret)
	if err != nil {
		return oidc, fmt.Errorf("set client secret: %w", err)
	}

	if err = assignEmailScopeAndEnableDirectAccess(ctx, ks.httpClient, ks.baseURL, adminToken, setup.Realm, clientUUID); err != nil {
		return oidc, fmt.Errorf("configure client scopes: %w", err)
	}

	userID, err := createUser(ctx, ks.httpClient, ks.baseURL, adminToken, setup.Realm, setup.Username, setup.Email, "Demo", "User")
	if err != nil {
		return oidc, fmt.Errorf("create user: %w", err)
	}

	if err = setUserPassword(ctx, ks.httpClient, ks.baseURL, adminToken, setup.Realm, userID, setup.Password); err != nil {
		return oidc, fmt.Errorf("set user password: %w", err)
	}

	openidcfg, err := getOpenIDConfig(ctx, ks.httpClient, ks.baseURL, setup.Realm)
	if err != nil {
		return oidc, fmt.Errorf("fetch openid config: %w", err)
	}

	oidc = keycloakOIDC{
		AuthURL:       openidcfg.AuthorizationEndpoint,
		TokenURL:      openidcfg.TokenEndpoint,
		UserInfoURL:   openidcfg.UserInfoEndpoint,
		EndSessionURL: openidcfg.EndSessionEndpoint,
		ClientSecret:  clientSecret,
	}
	return
}

type openIDConfig struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

func getOpenIDConfig(ctx context.Context, client *http.Client, baseURL, realm string) (cfg openIDConfig, err error) {
	url := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", baseURL, realm)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return cfg, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return cfg, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return cfg, fmt.Errorf("openid config status %s: %s", resp.Status, string(body))
	}
	if err = json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return cfg, err
	}
	if cfg.AuthorizationEndpoint == "" || cfg.TokenEndpoint == "" || cfg.UserInfoEndpoint == "" {
		return cfg, errors.New("openid configuration missing endpoints")
	}
	return cfg, nil
}

func getAdminToken(ctx context.Context, client *http.Client, baseURL, username, password string) (string, error) {
	url := fmt.Sprintf("%s/realms/master/protocol/openid-connect/token", baseURL)
	data := "client_id=admin-cli&grant_type=password&username=" + username + "&password=" + password

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBufferString(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("admin token status %s: %s", resp.Status, string(body))
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.AccessToken == "" {
		return "", errors.New("missing admin access token")
	}
	return result.AccessToken, nil
}

func createRealm(ctx context.Context, client *http.Client, baseURL, token, realm string) error {
	url := fmt.Sprintf("%s/admin/realms", baseURL)
	payload := map[string]any{"realm": realm, "enabled": true}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create realm status %s: %s", resp.Status, string(body))
	}
	return nil
}

func createClient(ctx context.Context, client *http.Client, baseURL, token, realm, clientID, redirectURI string) (string, error) {
	url := fmt.Sprintf("%s/admin/realms/%s/clients", baseURL, realm)

	origin, err := appOriginFromRedirectURI(redirectURI)
	if err != nil {
		return "", err
	}

	clientData := map[string]any{
		"clientId":                  clientID,
		"enabled":                   true,
		"protocol":                  "openid-connect",
		"publicClient":              false,
		"standardFlowEnabled":       true,
		"directAccessGrantsEnabled": true,
		"redirectUris":              []string{redirectURI, origin + "/*"},
		"webOrigins":                []string{origin},
		"attributes": map[string]any{
			"post.logout.redirect.uris": origin + "/*",
		},
	}
	data, err := json.Marshal(clientData)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("create client status %s: %s", resp.Status, string(body))
	}

	location := resp.Header.Get("Location")
	idx := strings.LastIndex(location, "/")
	if idx < 0 || idx+1 >= len(location) {
		return "", errors.New("missing client location header")
	}
	return location[idx+1:], nil
}

func setClientSecret(ctx context.Context, client *http.Client, baseURL, token, realm, clientUUID, secret string) (string, error) {
	url := fmt.Sprintf("%s/admin/realms/%s/clients/%s/client-secret", baseURL, realm, clientUUID)
	payload := map[string]any{"value": secret}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("set client secret status %s: %s", resp.Status, string(body))
	}

	var result struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.Value == "" {
		return "", errors.New("missing client secret value")
	}
	return result.Value, nil
}

func createUser(ctx context.Context, client *http.Client, baseURL, token, realm, username, email, firstName, lastName string) (string, error) {
	url := fmt.Sprintf("%s/admin/realms/%s/users", baseURL, realm)
	userData := map[string]any{
		"username":      username,
		"email":         email,
		"firstName":     firstName,
		"lastName":      lastName,
		"emailVerified": true,
		"enabled":       true,
	}
	data, err := json.Marshal(userData)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("create user status %s: %s", resp.Status, string(body))
	}

	location := resp.Header.Get("Location")
	idx := strings.LastIndex(location, "/")
	if idx < 0 || idx+1 >= len(location) {
		return "", errors.New("missing user location header")
	}
	return location[idx+1:], nil
}

func setUserPassword(ctx context.Context, client *http.Client, baseURL, token, realm, userID, password string) error {
	url := fmt.Sprintf("%s/admin/realms/%s/users/%s/reset-password", baseURL, realm, userID)
	payload := map[string]any{
		"type":      "password",
		"value":     password,
		"temporary": false,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("set user password status %s: %s", resp.Status, string(body))
	}
	return nil
}

func getScopeID(ctx context.Context, client *http.Client, baseURL, token, realm, scopeName string) (string, error) {
	url := fmt.Sprintf("%s/admin/realms/%s/client-scopes", baseURL, realm)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("get scope list status %s: %s", resp.Status, string(body))
	}

	var scopes []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&scopes); err != nil {
		return "", err
	}
	for _, scope := range scopes {
		if scope["name"] == scopeName {
			if id, ok := scope["id"].(string); ok && id != "" {
				return id, nil
			}
		}
	}
	return "", fmt.Errorf("scope not found: %s", scopeName)
}

func ensureEmailScope(ctx context.Context, client *http.Client, baseURL, token, realm string) error {
	url := fmt.Sprintf("%s/admin/realms/%s/client-scopes", baseURL, realm)
	scopeData := map[string]any{
		"name":        "email",
		"description": "Access user email",
		"protocol":    "openid-connect",
	}
	scopeJSON, err := json.Marshal(scopeData)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(scopeJSON))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ensure email scope status %s: %s", resp.Status, string(body))
	}
	return nil
}

func assignEmailScopeToClient(ctx context.Context, client *http.Client, baseURL, token, realm, clientID string) error {
	if err := ensureEmailScope(ctx, client, baseURL, token, realm); err != nil {
		return err
	}
	scopeID, err := getScopeID(ctx, client, baseURL, token, realm, "email")
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/admin/realms/%s/clients/%s/default-client-scopes/%s", baseURL, realm, clientID, scopeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("assign email scope status %s: %s", resp.Status, string(body))
	}
	return nil
}

func enableDirectAccessGrants(ctx context.Context, client *http.Client, baseURL, token, realm, clientID string) error {
	url := fmt.Sprintf("%s/admin/realms/%s/clients/%s", baseURL, realm, clientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("get client details status %s: %s", resp.Status, string(body))
	}

	var clientConfig map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&clientConfig); err != nil {
		return err
	}
	clientConfig["directAccessGrantsEnabled"] = true

	data, err := json.Marshal(clientConfig)
	if err != nil {
		return err
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("enable direct access grants status %s: %s", resp.Status, string(body))
	}
	return nil
}

func assignEmailScopeAndEnableDirectAccess(ctx context.Context, client *http.Client, baseURL, token, realm, clientID string) error {
	if err := enableDirectAccessGrants(ctx, client, baseURL, token, realm, clientID); err != nil {
		return err
	}
	if err := assignEmailScopeToClient(ctx, client, baseURL, token, realm, clientID); err != nil {
		return err
	}
	return nil
}

func isDockerUnavailableError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	markers := []string{
		"cannot connect to the docker daemon",
		"is the docker daemon running",
		"failed to create docker client",
		"permission denied while trying to connect to the docker daemon socket",
		"/var/run/docker.sock",
	}
	for _, marker := range markers {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}
