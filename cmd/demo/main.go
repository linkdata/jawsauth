package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	var opts demoOptions
	flag.StringVar(&opts.ListenAddr, "addr", "0.0.0.0:8443", "HTTPS listen address")
	flag.StringVar(&opts.PublicHost, "public-host", "", "public hostname used in redirect URIs and self-signed certificate")
	flag.StringVar(&opts.PasswordFile, "password-file", "demo-password.txt", "file path where generated login password is written")
	flag.StringVar(&opts.Realm, "realm", "jawsauth-demo", "Keycloak realm name")
	flag.StringVar(&opts.ClientID, "client-id", "jawsauth-demo-client", "Keycloak OAuth2 client ID")
	flag.StringVar(&opts.Username, "username", "demo", "demo login username")
	flag.StringVar(&opts.UserEmail, "user-email", "demo@example.com", "demo login user email")
	flag.StringVar(&opts.KeycloakImage, "keycloak-image", "quay.io/keycloak/keycloak:latest", "Keycloak Docker image")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	demo, err := startDemo(ctx, opts)
	if err != nil {
		log.Fatalf("start demo: %v", err)
	}

	log.Printf("demo app url: %s", demo.appURL)
	log.Printf("keycloak url: %s", demo.keycloakURL)
	log.Printf("username: %s", demo.username)
	log.Printf("password file: %s", demo.passwordFile)

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := demo.close(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}
