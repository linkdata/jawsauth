package testdocker

import (
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
)

const KeycloakImage = "quay.io/keycloak/keycloak:26.7.4@sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c"

// HostNetworkAvailable checks that the test process and Docker host share a network namespace.
func HostNetworkAvailable(ctx context.Context, image string) bool {
	if os.Getenv("JAWSAUTH_TEST_FORCE_BRIDGE") == "1" {
		return false
	}
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return false
	}
	netNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return false
	}
	probe, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:              image,
			Entrypoint:         []string{"/bin/sh", "-c"},
			Cmd:                []string{"sleep 300"},
			HostConfigModifier: func(hc *container.HostConfig) { hc.NetworkMode = "host" },
		},
		Started: true,
	})
	if probe != nil {
		defer func() {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			_ = probe.Terminate(cleanupCtx, testcontainers.StopTimeout(0))
		}()
	}
	if err != nil {
		return false
	}
	host, err := probe.Host(ctx)
	if err != nil || (host != "localhost" && host != "127.0.0.1" && host != "::1") {
		return false
	}
	exitCode, output, err := probe.Exec(ctx, []string{"/bin/sh", "-c", "cat /proc/sys/kernel/random/boot_id; readlink /proc/self/ns/net"}, tcexec.Multiplexed())
	if err != nil || exitCode != 0 {
		return false
	}
	actual, err := io.ReadAll(output)
	return err == nil && strings.TrimSpace(string(actual)) == strings.TrimSpace(string(bootID))+"\n"+netNS
}

func FreePort() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer func() { _ = listener.Close() }()
	return strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), nil
}

func PortInUse(ctx context.Context, c testcontainers.Container) bool {
	if c == nil {
		return false
	}
	logs, err := c.Logs(ctx)
	if err != nil {
		return false
	}
	defer func() { _ = logs.Close() }()
	output, err := io.ReadAll(logs)
	return err == nil && strings.Contains(strings.ToLower(string(output)), "already in use")
}
