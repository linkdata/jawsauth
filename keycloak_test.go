package jawsauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
)

func TestKeycloakFlow(t *testing.T) {
	ctx := context.Background()

	// Start Keycloak container
	keycloakContainer, err := startKeycloakContainer(t, ctx)
	defer func() {
		if keycloakContainer != nil {
			if t.Failed() {
				printLogs(ctx, keycloakContainer)
			}
			keycloakContainer.Terminate(ctx)
		}
	}()

	if err != nil {
		t.Fatalf("Failed to start Keycloak container: %v", err)
	}

	host, err := keycloakContainer.Host(ctx)
	if err != nil {
		t.Fatalf("Failed to get container host: %v", err)
	}

	port, err := keycloakContainer.MappedPort(ctx, "8080")
	if err != nil {
		t.Fatalf("Failed to get container port: %v", err)
	}

	baseURL := fmt.Sprintf("http://%s:%s", host, port.Port())
	adminToken, err := getAdminToken(ctx, baseURL, "admin", "admin")
	if err != nil {
		t.Fatalf("Failed to get admin token: %v", err)
	}

	realm := "testrealm"
	if err := createRealm(ctx, baseURL, adminToken, realm); err != nil {
		t.Fatalf("Failed to create realm: %v", err)
	}

	clientID, err := createClient(ctx, baseURL, adminToken, realm, "testclient")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	clientSecret, err := setClientSecret(ctx, baseURL, adminToken, realm, clientID, "MySuperSecret")
	if err != nil {
		t.Fatalf("Failed to set client secret: %v", err)
	}

	if err := assignEmailScopeAndEnableDirectAccess(ctx, baseURL, adminToken, realm, clientID); err != nil {
		t.Fatalf("Failed to configure client: %v", err)
	}

	userID, err := createUser(ctx, baseURL, adminToken, realm, "testuser", "testuser@example.com", "Test", "User")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	if err := setUserPassword(ctx, baseURL, adminToken, realm, userID, "password123"); err != nil {
		t.Fatalf("Failed to set user password: %v", err)
	}

	accessToken, err := getUserAccessToken(ctx, baseURL, realm, "testclient", clientSecret, "testuser", "password123")
	if err != nil {
		t.Fatalf("Failed to get user access token: %v", err)
	}

	email, err := getUserInfoEmail(ctx, baseURL, realm, accessToken)
	if err != nil {
		t.Fatalf("Failed to get userinfo email: %v", err)
	}

	if email != "testuser@example.com" {
		t.Fatal(email)
	}

	serverHandlerTest(t, baseURL, realm, "testclient", clientSecret)
}

func startKeycloakContainer(t *testing.T, ctx context.Context) (testcontainers.Container, error) {
	t.Helper()
	defer func() {
		if x := recover(); x != nil {
			t.Skip("failed to start keycloak container", x)
		}
	}()
	req := testcontainers.ContainerRequest{
		Image:        "quay.io/keycloak/keycloak:latest",
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
			"KC_BOOTSTRAP_ADMIN_PASSWORD": "admin",
		},
		Cmd: []string{"start-dev"},
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	port, _ := nat.NewPort("tcp", "8080")
	return container, waitForKeycloak(ctx, container, port)
}

func printLogs(ctx context.Context, container testcontainers.Container) {
	if logs, err := container.Logs(ctx); err == nil {
		if b, err := io.ReadAll(logs); err == nil {
			fmt.Println(string(b))
		}
	}
}

func getAdminToken(ctx context.Context, baseURL, username, password string) (string, error) {
	url := fmt.Sprintf("%s/realms/master/protocol/openid-connect/token", baseURL) // Correct endpoint
	data := "client_id=admin-cli&grant_type=password&username=" + username + "&password=" + password

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBufferString(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get admin token, status: %s, body: %s", resp.Status, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result["access_token"].(string), nil
}

func createRealm(ctx context.Context, baseURL, token, realm string) error {
	url := fmt.Sprintf("%s/admin/realms", baseURL)
	realmData := map[string]interface{}{
		"realm":   realm,
		"enabled": true,
	}

	data, err := json.Marshal(realmData)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create realm, status: %s, body: %s", resp.Status, string(body))
	}

	return nil
}

func createClient(ctx context.Context, baseURL, token, realm, clientName string) (string, error) {
	url := fmt.Sprintf("%s/admin/realms/%s/clients", baseURL, realm)
	clientData := map[string]interface{}{
		"clientId":     clientName,
		"enabled":      true,
		"publicClient": false, // Ensures client secret is used
		"redirectUris": []string{"*"},
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

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create client, status: %s, body: %s", resp.Status, string(body))
	}

	location := resp.Header.Get("Location")
	clientID := location[strings.LastIndex(location, "/")+1:]

	return clientID, nil
}

func setClientSecret(ctx context.Context, baseURL, token, realm, clientID, secret string) (string, error) {
	url := fmt.Sprintf("%s/admin/realms/%s/clients/%s/client-secret", baseURL, realm, clientID)

	secretData := map[string]interface{}{
		"value": secret,
	}

	data, err := json.Marshal(secretData)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to set client secret, status: %s, body: %s", resp.Status, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result["value"].(string), nil
}

func createUser(ctx context.Context, baseURL, token, realm, username, email, firstName, lastName string) (string, error) {
	url := fmt.Sprintf("%s/admin/realms/%s/users", baseURL, realm)
	userData := map[string]interface{}{
		"username":  username,
		"email":     email,
		"firstName": firstName,
		"lastName":  lastName,
		"enabled":   true,
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

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create user, status: %s, body: %s", resp.Status, string(body))
	}

	location := resp.Header.Get("Location")
	userID := location[strings.LastIndex(location, "/")+1:]

	return userID, nil
}

func setUserPassword(ctx context.Context, baseURL, token, realm, userID, password string) error {
	url := fmt.Sprintf("%s/admin/realms/%s/users/%s/reset-password", baseURL, realm, userID)
	passwordData := map[string]interface{}{
		"type":      "password",
		"value":     password,
		"temporary": false,
	}

	data, err := json.Marshal(passwordData)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to set user password, status: %s, body: %s", resp.Status, string(body))
	}

	return nil
}

func getUserAccessToken(ctx context.Context, baseURL, realm, clientID, clientSecret, username, password string) (string, error) {
	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", baseURL, realm)
	data := fmt.Sprintf("client_id=%s&client_secret=%s&username=%s&password=%s&grant_type=password&scope=openid email", clientID, clientSecret, username, password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBufferString(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get user access token, status: %s, body: %s", resp.Status, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result["access_token"].(string), nil
}

func getUserInfoEmail(ctx context.Context, baseURL, realm, accessToken string) (string, error) {
	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", baseURL, realm)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get userinfo, status: %s, body: %s", resp.Status, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	email, ok := result["email"].(string)
	if !ok {
		return "", fmt.Errorf("email not found in userinfo response")
	}

	return email, nil
}

func waitForKeycloak(ctx context.Context, container testcontainers.Container, port nat.Port) error {
	host, err := container.Host(ctx)
	if err != nil {
		return fmt.Errorf("failed to get container host: %w", err)
	}

	mappedPort, err := container.MappedPort(ctx, port)
	if err != nil {
		return fmt.Errorf("failed to get mapped port: %w", err)
	}

	url := fmt.Sprintf("http://%s:%s/", host, mappedPort.Port())

	for i := 0; i < 20; i++ { // Retry for ~60 seconds (20 attempts, 3 seconds each)
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			return nil
		}
		time.Sleep(3 * time.Second)
	}

	return fmt.Errorf("Keycloak did not become ready in time at %s", url)
}

func getScopeID(ctx context.Context, baseURL, token, realm, scopeName string) (string, error) {
	url := fmt.Sprintf("%s/admin/realms/%s/client-scopes", baseURL, realm)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get scope list, status: %s, body: %s", resp.Status, string(body))
	}

	var scopes []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&scopes); err != nil {
		return "", err
	}

	for _, scope := range scopes {
		if scope["name"] == scopeName {
			return scope["id"].(string), nil
		}
	}

	return "", fmt.Errorf("scope not found: %s", scopeName)
}

func assignEmailScopeToClient(ctx context.Context, baseURL, token, realm, clientID string) error {
	// Ensure the "email" scope exists first
	if err := ensureEmailScope(ctx, baseURL, token, realm); err != nil {
		return err
	}

	scopeID, err := getScopeID(ctx, baseURL, token, realm, "email")
	if err != nil {
		return fmt.Errorf("failed to get scope ID: %w", err)
	}

	// Assign email scope to the client
	url := fmt.Sprintf("%s/admin/realms/%s/clients/%s/default-client-scopes/%s", baseURL, realm, clientID, scopeID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to assign email scope to client, status: %s, body: %s", resp.Status, string(body))
	}

	return nil
}

func ensureEmailScope(ctx context.Context, baseURL, token, realm string) error {
	url := fmt.Sprintf("%s/admin/realms/%s/client-scopes", baseURL, realm)
	scopeData := map[string]interface{}{
		"name":        "email",
		"description": "Access user's email information",
		"protocol":    "openid-connect",
		"attributes": map[string]interface{}{
			"include.in.token.scope":          "true",
			"display.on.consent.screen":       "true",
			"consent.screen.text":             "Access your email",
			"gui.order":                       "1",
			"protocol.mapper.create.value":    "oidc-protocol-mapper",
			"mapper.claim.address.field.name": "email",
		},
	}

	scopeJson, err := json.Marshal(scopeData)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(scopeJson))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch email scope existence, Error assigning default scopes")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ensure-email-scope: %s -- Check failed-body result[%s].", resp.Status, string(body))
	}

	return nil
}

func enableDirectAccessGrants(ctx context.Context, baseURL, token, realm, clientID string) error {
	url := fmt.Sprintf("%s/admin/realms/%s/clients/%s", baseURL, realm, clientID)

	// Fetch the current client configuration
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to get client details, status: %s, body: %s", resp.Status, string(body))
	}

	var clientConfig map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&clientConfig); err != nil {
		return err
	}

	// Enable direct access grants
	clientConfig["directAccessGrantsEnabled"] = true

	data, err := json.Marshal(clientConfig)
	if err != nil {
		return err
	}

	// Update the client configuration
	req, err = http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to enable direct access grants, status: %s, body: %s", resp.Status, string(body))
	}

	return nil
}

func assignEmailScopeAndEnableDirectAccess(ctx context.Context, baseURL, token, realm, clientID string) error {
	// Enable direct access grants for the client
	if err := enableDirectAccessGrants(ctx, baseURL, token, realm, clientID); err != nil {
		return fmt.Errorf("failed to enable direct access grants: %w", err)
	}

	// Assign the email scope
	if err := assignEmailScopeToClient(ctx, baseURL, token, realm, clientID); err != nil {
		return fmt.Errorf("failed to assign email scope: %w", err)
	}

	return nil
}
