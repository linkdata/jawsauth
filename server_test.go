package jawsauth

import (
	"context"
	"testing"

	keycloak "github.com/stillya/testcontainers-keycloak"
)

func RunContainer(ctx context.Context) (*keycloak.KeycloakContainer, error) {
	return keycloak.Run(ctx,
		"quay.io/keycloak/keycloak:26.0",
		keycloak.WithContextPath("/auth"),
		keycloak.WithRealmImportFile("testdata/realm-export.json"),
		keycloak.WithAdminUsername("admin"),
		keycloak.WithAdminPassword("admin"),
	)
}

func TestServer_Handler(t *testing.T) {
	ctx := context.Background()
	keycloakContainer, err := RunContainer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := keycloakContainer.Terminate(ctx)
		if err != nil {
			panic(err)
		}
	}()
}
