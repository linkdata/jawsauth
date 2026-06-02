package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func demoResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func errorHTTPClient(err error) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, err
	})}
}

func TestKeycloakServerClose(t *testing.T) {
	if err := (*keycloakServer)(nil).Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ks := &keycloakServer{certTempDir: dir}
	if err := ks.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

type fakeContainer struct {
	testcontainers.Container
	host         string
	hostErr      error
	portErr      error
	terminateErr error
}

func (container fakeContainer) Host(context.Context) (string, error) {
	return container.host, container.hostErr
}

func (container fakeContainer) MappedPort(context.Context, string) (network.Port, error) {
	if container.portErr != nil {
		return network.Port{}, container.portErr
	}
	return network.MustParsePort("18443/tcp"), nil
}

func (container fakeContainer) Terminate(context.Context, ...testcontainers.TerminateOption) error {
	return container.terminateErr
}

func resetKeycloakDeps(t *testing.T) {
	t.Helper()
	oldMkdirTemp := keycloakMkdirTemp
	oldWriteFile := keycloakWriteFile
	oldRemoveAll := keycloakRemoveAll
	oldGeneratePEM := keycloakGeneratePEM
	oldContainer := keycloakContainer
	oldDefaultHost := keycloakDefaultHost
	t.Cleanup(func() {
		keycloakMkdirTemp = oldMkdirTemp
		keycloakWriteFile = oldWriteFile
		keycloakRemoveAll = oldRemoveAll
		keycloakGeneratePEM = oldGeneratePEM
		keycloakContainer = oldContainer
		keycloakDefaultHost = oldDefaultHost
	})
}

func TestStartKeycloakServerErrorsAndSuccess(t *testing.T) {
	_, err := startKeycloakServer(t.Context(), "image", " ")
	if err == nil || !strings.Contains(err.Error(), "empty keycloak admin password") {
		t.Fatalf("error = %v", err)
	}

	for _, tc := range []struct {
		name string
		edit func(error)
		want string
	}{
		{name: "mkdir", edit: func(err error) {
			keycloakMkdirTemp = func(string, string) (string, error) { return "", err }
		}, want: "create keycloak cert temp dir"},
		{name: "generate", edit: func(err error) {
			keycloakGeneratePEM = func(string) ([]byte, []byte, error) { return nil, nil, err }
		}, want: "test error"},
		{name: "cert write", edit: func(err error) {
			keycloakWriteFile = func(string, []byte, os.FileMode) error { return err }
		}, want: "write keycloak cert"},
		{name: "key write", edit: func(err error) {
			var count int
			keycloakWriteFile = func(string, []byte, os.FileMode) error {
				count++
				if count == 2 {
					return err
				}
				return nil
			}
		}, want: "write keycloak key"},
		{name: "container", edit: func(err error) {
			keycloakContainer = func(context.Context, testcontainers.GenericContainerRequest) (testcontainers.Container, error) {
				return nil, err
			}
		}, want: "start keycloak container"},
		{name: "host", edit: func(err error) {
			keycloakContainer = func(context.Context, testcontainers.GenericContainerRequest) (testcontainers.Container, error) {
				return fakeContainer{hostErr: err}, nil
			}
		}, want: "resolve keycloak host"},
		{name: "port", edit: func(err error) {
			keycloakContainer = func(context.Context, testcontainers.GenericContainerRequest) (testcontainers.Container, error) {
				return fakeContainer{host: "localhost", portErr: err}, nil
			}
		}, want: "resolve keycloak port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetKeycloakDeps(t)
			tc.edit(errors.New("test error"))
			_, err := startKeycloakServer(t.Context(), "image", "admin-pass")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}

	t.Run("success", func(t *testing.T) {
		resetKeycloakDeps(t)
		keycloakContainer = func(context.Context, testcontainers.GenericContainerRequest) (testcontainers.Container, error) {
			return fakeContainer{host: "localhost"}, nil
		}
		keycloakDefaultHost = func() (string, error) {
			return "198.51.100.11", nil
		}
		ks, err := startKeycloakServer(t.Context(), "image", "admin-pass")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(ks.baseURL, "https://198.51.100.11:") {
			t.Fatal(ks.baseURL)
		}
		if err := ks.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestKeycloakSetupRealmSuccess(t *testing.T) {
	server := newKeycloakAPIServer(t, "")
	defer server.Close()

	ks := &keycloakServer{
		baseURL:    server.URL,
		httpClient: server.Client(),
		adminPass:  "admin-pass",
	}
	oidc, err := ks.SetupRealm(t.Context(), keycloakRealmSetup{
		Realm:       "demo",
		ClientID:    "client",
		RedirectURI: "https://app.example/oauth2/callback",
		Username:    "demo",
		Email:       "demo@example.com",
		Password:    "password",
	})
	if err != nil {
		t.Fatal(err)
	}
	if oidc.AuthURL != server.URL+"/realms/demo/protocol/openid-connect/auth" {
		t.Fatal(oidc.AuthURL)
	}
	if oidc.ClientSecret != "client-secret" {
		t.Fatal(oidc.ClientSecret)
	}
}

func TestKeycloakSetupRealmErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail string
		want string
	}{
		{name: "admin", fail: "admin-token", want: "get admin token"},
		{name: "realm", fail: "create-realm", want: "create realm"},
		{name: "client", fail: "create-client", want: "create client"},
		{name: "secret", fail: "client-secret", want: "set client secret"},
		{name: "scopes", fail: "direct-get", want: "configure client scopes"},
		{name: "user", fail: "create-user", want: "create user"},
		{name: "password", fail: "set-password", want: "set user password"},
		{name: "openid", fail: "openid", want: "fetch openid config"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newKeycloakAPIServer(t, tc.fail)
			defer server.Close()
			ks := &keycloakServer{
				baseURL:    server.URL,
				httpClient: server.Client(),
				adminPass:  "admin-pass",
			}
			_, err := ks.SetupRealm(t.Context(), keycloakRealmSetup{
				Realm:       "demo",
				ClientID:    "client",
				RedirectURI: "https://app.example/oauth2/callback",
				Username:    "demo",
				Email:       "demo@example.com",
				Password:    "password",
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestKeycloakHTTPHelpersRequestAndTransportErrors(t *testing.T) {
	ctx := t.Context()
	transportErr := errors.New("transport failed")
	client := errorHTTPClient(transportErr)
	baseURL := "http://provider.example"

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{name: "openid transport", call: func() error {
			_, err := getOpenIDConfig(ctx, client, baseURL, "demo")
			return err
		}},
		{name: "admin token transport", call: func() error {
			_, err := getAdminToken(ctx, client, baseURL, "admin", "password")
			return err
		}},
		{name: "create realm transport", call: func() error {
			return createRealm(ctx, client, baseURL, "token", "demo")
		}},
		{name: "create client transport", call: func() error {
			_, err := createClient(ctx, client, baseURL, "token", "demo", "client", "https://app.example/callback")
			return err
		}},
		{name: "set secret transport", call: func() error {
			_, err := setClientSecret(ctx, client, baseURL, "token", "demo", "client-uuid", "secret")
			return err
		}},
		{name: "create user transport", call: func() error {
			_, err := createUser(ctx, client, baseURL, "token", "demo", "user", "user@example.com", "Test", "User")
			return err
		}},
		{name: "set password transport", call: func() error {
			return setUserPassword(ctx, client, baseURL, "token", "demo", "user-id", "password")
		}},
		{name: "get scope transport", call: func() error {
			_, err := getScopeID(ctx, client, baseURL, "token", "demo", "email")
			return err
		}},
		{name: "ensure scope transport", call: func() error {
			return ensureEmailScope(ctx, client, baseURL, "token", "demo")
		}},
		{name: "enable direct transport", call: func() error {
			return enableDirectAccessGrants(ctx, client, baseURL, "token", "demo", "client-uuid")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, transportErr) {
				t.Fatalf("error = %v, want transport error", err)
			}
		})
	}

	invalidBase := "http://[::1"
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{name: "openid request", call: func() error {
			_, err := getOpenIDConfig(ctx, http.DefaultClient, invalidBase, "demo")
			return err
		}},
		{name: "admin token request", call: func() error {
			_, err := getAdminToken(ctx, http.DefaultClient, invalidBase, "admin", "password")
			return err
		}},
		{name: "create realm request", call: func() error {
			return createRealm(ctx, http.DefaultClient, invalidBase, "token", "demo")
		}},
		{name: "create client request", call: func() error {
			_, err := createClient(ctx, http.DefaultClient, invalidBase, "token", "demo", "client", "https://app.example/callback")
			return err
		}},
		{name: "set secret request", call: func() error {
			_, err := setClientSecret(ctx, http.DefaultClient, invalidBase, "token", "demo", "client-uuid", "secret")
			return err
		}},
		{name: "create user request", call: func() error {
			_, err := createUser(ctx, http.DefaultClient, invalidBase, "token", "demo", "user", "user@example.com", "Test", "User")
			return err
		}},
		{name: "set password request", call: func() error {
			return setUserPassword(ctx, http.DefaultClient, invalidBase, "token", "demo", "user-id", "password")
		}},
		{name: "get scope request", call: func() error {
			_, err := getScopeID(ctx, http.DefaultClient, invalidBase, "token", "demo", "email")
			return err
		}},
		{name: "ensure scope request", call: func() error {
			return ensureEmailScope(ctx, http.DefaultClient, invalidBase, "token", "demo")
		}},
		{name: "enable direct request", call: func() error {
			return enableDirectAccessGrants(ctx, http.DefaultClient, invalidBase, "token", "demo", "client-uuid")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err == nil {
				t.Fatal("expected request creation error")
			}
		})
	}
}

func TestKeycloakHTTPHelpersResponseErrors(t *testing.T) {
	ctx := t.Context()
	for _, tc := range []struct {
		name string
		body string
		call func(*http.Client, string) error
	}{
		{name: "openid bad json", body: `{`, call: func(client *http.Client, baseURL string) error {
			_, err := getOpenIDConfig(ctx, client, baseURL, "demo")
			return err
		}},
		{name: "openid missing endpoints", body: `{}`, call: func(client *http.Client, baseURL string) error {
			_, err := getOpenIDConfig(ctx, client, baseURL, "demo")
			return err
		}},
		{name: "admin bad json", body: `{`, call: func(client *http.Client, baseURL string) error {
			_, err := getAdminToken(ctx, client, baseURL, "admin", "password")
			return err
		}},
		{name: "admin missing token", body: `{}`, call: func(client *http.Client, baseURL string) error {
			_, err := getAdminToken(ctx, client, baseURL, "admin", "password")
			return err
		}},
		{name: "secret bad json", body: `{`, call: func(client *http.Client, baseURL string) error {
			_, err := setClientSecret(ctx, client, baseURL, "token", "demo", "client-uuid", "secret")
			return err
		}},
		{name: "secret missing value", body: `{}`, call: func(client *http.Client, baseURL string) error {
			_, err := setClientSecret(ctx, client, baseURL, "token", "demo", "client-uuid", "secret")
			return err
		}},
		{name: "scope bad json", body: `{`, call: func(client *http.Client, baseURL string) error {
			_, err := getScopeID(ctx, client, baseURL, "token", "demo", "email")
			return err
		}},
		{name: "scope not found", body: `[{"name":"profile","id":"scope-id"}]`, call: func(client *http.Client, baseURL string) error {
			_, err := getScopeID(ctx, client, baseURL, "token", "demo", "email")
			return err
		}},
		{name: "direct bad json", body: `{`, call: func(client *http.Client, baseURL string) error {
			return enableDirectAccessGrants(ctx, client, baseURL, "token", "demo", "client-uuid")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return demoResponse(http.StatusOK, tc.body), nil
			})}
			if err := tc.call(client, "http://provider.example"); err == nil {
				t.Fatal("expected response error")
			}
		})
	}

	for _, tc := range []struct {
		name string
		call func(*http.Client, string) error
	}{
		{name: "openid status", call: func(client *http.Client, baseURL string) error {
			_, err := getOpenIDConfig(ctx, client, baseURL, "demo")
			return err
		}},
		{name: "admin token status", call: func(client *http.Client, baseURL string) error {
			_, err := getAdminToken(ctx, client, baseURL, "admin", "password")
			return err
		}},
		{name: "create realm status", call: func(client *http.Client, baseURL string) error {
			return createRealm(ctx, client, baseURL, "token", "demo")
		}},
		{name: "create client status", call: func(client *http.Client, baseURL string) error {
			_, err := createClient(ctx, client, baseURL, "token", "demo", "client", "https://app.example/callback")
			return err
		}},
		{name: "set secret status", call: func(client *http.Client, baseURL string) error {
			_, err := setClientSecret(ctx, client, baseURL, "token", "demo", "client-uuid", "secret")
			return err
		}},
		{name: "create user status", call: func(client *http.Client, baseURL string) error {
			_, err := createUser(ctx, client, baseURL, "token", "demo", "user", "user@example.com", "Test", "User")
			return err
		}},
		{name: "set password status", call: func(client *http.Client, baseURL string) error {
			return setUserPassword(ctx, client, baseURL, "token", "demo", "user-id", "password")
		}},
		{name: "get scope status", call: func(client *http.Client, baseURL string) error {
			_, err := getScopeID(ctx, client, baseURL, "token", "demo", "email")
			return err
		}},
		{name: "ensure scope status", call: func(client *http.Client, baseURL string) error {
			return ensureEmailScope(ctx, client, baseURL, "token", "demo")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return demoResponse(http.StatusInternalServerError, "boom"), nil
			})}
			if err := tc.call(client, "http://provider.example"); err == nil {
				t.Fatal("expected status error")
			}
		})
	}
}

func TestCreateClientAndUserMissingLocation(t *testing.T) {
	if _, err := createClient(t.Context(), http.DefaultClient, "http://provider.example", "token", "demo", "client", "/callback"); err == nil {
		t.Fatal("expected invalid redirect URI")
	}

	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return demoResponse(http.StatusCreated, ""), nil
	})}
	if _, err := createClient(t.Context(), client, "http://provider.example", "token", "demo", "client", "https://app.example/callback"); err == nil {
		t.Fatal("expected missing client location error")
	}
	if _, err := createUser(t.Context(), client, "http://provider.example", "token", "demo", "user", "user@example.com", "Test", "User"); err == nil {
		t.Fatal("expected missing user location error")
	}
}

func TestAssignEmailScopeAndDirectAccessErrors(t *testing.T) {
	ctx := t.Context()
	t.Run("assign scope request fails after setup", func(t *testing.T) {
		var count int
		client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			count++
			switch count {
			case 1:
				return demoResponse(http.StatusCreated, ""), nil
			case 2:
				return demoResponse(http.StatusOK, `[{"name":"email","id":"scope-id"}]`), nil
			default:
				return nil, errors.New("assign failed")
			}
		})}
		if err := assignEmailScopeToClient(ctx, client, "http://provider.example", "token", "demo", "client-uuid"); err == nil {
			t.Fatal("expected assign transport error")
		}
	})

	t.Run("assign scope lookup fails", func(t *testing.T) {
		var count int
		client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			count++
			switch count {
			case 1:
				return demoResponse(http.StatusCreated, ""), nil
			default:
				return demoResponse(http.StatusOK, `[{"name":"profile","id":"scope-id"}]`), nil
			}
		})}
		if err := assignEmailScopeToClient(ctx, client, "http://provider.example", "token", "demo", "client-uuid"); err == nil {
			t.Fatal("expected scope lookup error")
		}
	})

	t.Run("assign scope request creation fails", func(t *testing.T) {
		var count int
		client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			count++
			switch count {
			case 1:
				return demoResponse(http.StatusCreated, ""), nil
			default:
				return demoResponse(http.StatusOK, `[{"name":"email","id":"scope-id"}]`), nil
			}
		})}
		if err := assignEmailScopeToClient(ctx, client, "http://provider.example", "token", "demo", "bad\nclient"); err == nil {
			t.Fatal("expected request creation error")
		}
	})

	t.Run("assign scope status fails after setup", func(t *testing.T) {
		var count int
		client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			count++
			switch count {
			case 1:
				return demoResponse(http.StatusCreated, ""), nil
			case 2:
				return demoResponse(http.StatusOK, `[{"name":"email","id":"scope-id"}]`), nil
			default:
				return demoResponse(http.StatusInternalServerError, "boom"), nil
			}
		})}
		if err := assignEmailScopeToClient(ctx, client, "http://provider.example", "token", "demo", "client-uuid"); err == nil {
			t.Fatal("expected assign status error")
		}
	})

	t.Run("direct access update fails", func(t *testing.T) {
		var count int
		client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			count++
			if count == 1 {
				return demoResponse(http.StatusOK, `{}`), nil
			}
			return nil, errors.New("update failed")
		})}
		if err := enableDirectAccessGrants(ctx, client, "http://provider.example", "token", "demo", "client-uuid"); err == nil {
			t.Fatal("expected update transport error")
		}
	})

	t.Run("direct access update status fails", func(t *testing.T) {
		var count int
		client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			count++
			if count == 1 {
				return demoResponse(http.StatusOK, `{}`), nil
			}
			return demoResponse(http.StatusInternalServerError, "boom"), nil
		})}
		if err := enableDirectAccessGrants(ctx, client, "http://provider.example", "token", "demo", "client-uuid"); err == nil {
			t.Fatal("expected update status error")
		}
	})

	t.Run("composite direct error", func(t *testing.T) {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return demoResponse(http.StatusInternalServerError, "boom"), nil
		})}
		if err := assignEmailScopeAndEnableDirectAccess(ctx, client, "http://provider.example", "token", "demo", "client-uuid"); err == nil {
			t.Fatal("expected direct access error")
		}
	})

	t.Run("composite scope error", func(t *testing.T) {
		var count int
		client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			count++
			switch count {
			case 1:
				return demoResponse(http.StatusOK, `{}`), nil
			case 2:
				return demoResponse(http.StatusNoContent, ""), nil
			default:
				return demoResponse(http.StatusInternalServerError, "boom"), nil
			}
		})}
		if err := assignEmailScopeAndEnableDirectAccess(ctx, client, "http://provider.example", "token", "demo", "client-uuid"); err == nil {
			t.Fatal("expected scope error")
		}
	})
}

func newKeycloakAPIServer(t *testing.T, fail string) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
		key := routeKey(hr)
		if fail == key {
			hw.WriteHeader(http.StatusInternalServerError)
			_, _ = hw.Write([]byte("boom"))
			return
		}
		switch key {
		case "admin-token":
			hw.Header().Set("Content-Type", "application/json")
			_, _ = hw.Write([]byte(`{"access_token":"admin-token"}`))
		case "create-realm":
			hw.WriteHeader(http.StatusCreated)
		case "create-client":
			hw.Header().Set("Location", server.URL+"/admin/realms/demo/clients/client-uuid")
			hw.WriteHeader(http.StatusCreated)
		case "client-secret":
			hw.Header().Set("Content-Type", "application/json")
			_, _ = hw.Write([]byte(`{"value":"client-secret"}`))
		case "direct-get":
			hw.Header().Set("Content-Type", "application/json")
			_, _ = hw.Write([]byte(`{"clientId":"client"}`))
		case "direct-put":
			hw.WriteHeader(http.StatusNoContent)
		case "scope-create":
			hw.WriteHeader(http.StatusCreated)
		case "scope-list":
			hw.Header().Set("Content-Type", "application/json")
			_, _ = hw.Write([]byte(`[{"name":"email","id":"scope-id"}]`))
		case "assign-scope":
			hw.WriteHeader(http.StatusNoContent)
		case "create-user":
			hw.Header().Set("Location", server.URL+"/admin/realms/demo/users/user-id")
			hw.WriteHeader(http.StatusCreated)
		case "set-password":
			hw.WriteHeader(http.StatusNoContent)
		case "openid":
			hw.Header().Set("Content-Type", "application/json")
			_, _ = hw.Write([]byte(`{
				"issuer":"` + server.URL + `/realms/demo",
				"authorization_endpoint":"` + server.URL + `/realms/demo/protocol/openid-connect/auth",
				"token_endpoint":"` + server.URL + `/realms/demo/protocol/openid-connect/token",
				"userinfo_endpoint":"` + server.URL + `/realms/demo/protocol/openid-connect/userinfo",
				"end_session_endpoint":"` + server.URL + `/realms/demo/protocol/openid-connect/logout"
			}`))
		default:
			t.Errorf("unexpected request: %s %s", hr.Method, hr.URL.Path)
			hw.WriteHeader(http.StatusNotFound)
		}
	}))
	return server
}

func routeKey(hr *http.Request) string {
	switch {
	case hr.Method == http.MethodPost && hr.URL.Path == "/realms/master/protocol/openid-connect/token":
		return "admin-token"
	case hr.Method == http.MethodPost && hr.URL.Path == "/admin/realms":
		return "create-realm"
	case hr.Method == http.MethodPost && hr.URL.Path == "/admin/realms/demo/clients":
		return "create-client"
	case hr.Method == http.MethodPost && hr.URL.Path == "/admin/realms/demo/clients/client-uuid/client-secret":
		return "client-secret"
	case hr.Method == http.MethodGet && hr.URL.Path == "/admin/realms/demo/clients/client-uuid":
		return "direct-get"
	case hr.Method == http.MethodPut && hr.URL.Path == "/admin/realms/demo/clients/client-uuid":
		return "direct-put"
	case hr.Method == http.MethodPost && hr.URL.Path == "/admin/realms/demo/client-scopes":
		return "scope-create"
	case hr.Method == http.MethodGet && hr.URL.Path == "/admin/realms/demo/client-scopes":
		return "scope-list"
	case hr.Method == http.MethodPut && strings.Contains(hr.URL.Path, "/default-client-scopes/"):
		return "assign-scope"
	case hr.Method == http.MethodPost && hr.URL.Path == "/admin/realms/demo/users":
		return "create-user"
	case hr.Method == http.MethodPut && hr.URL.Path == "/admin/realms/demo/users/user-id/reset-password":
		return "set-password"
	case hr.Method == http.MethodGet && hr.URL.Path == "/realms/demo/.well-known/openid-configuration":
		return "openid"
	default:
		return ""
	}
}
