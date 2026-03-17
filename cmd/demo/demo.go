package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/linkdata/jaws"
	"github.com/linkdata/jawsauth"
	"golang.org/x/oauth2"
)

const indexTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>JaWS OAuth2 Demo</title>
  {{$.HeadHTML}}
  <style>
    body { font-family: sans-serif; margin: 2rem; background: #f4f8fb; color: #1f2a37; }
    main { max-width: 42rem; margin: 0 auto; background: #fff; padding: 2rem; border-radius: 12px; box-shadow: 0 8px 24px rgba(15,23,42,0.08); }
    h1 { margin-top: 0; }
    #email { font-weight: 700; }
    a { color: #0a62c9; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <main>
    <h1>JaWS OAuth2 Demo</h1>
    {{with .Auth}}
      <p id="email">Signed in as {{.Email}}</p>
    {{end}}
    <p>This page is protected by OAuth2 via Keycloak and rendered with JaWS.</p>
    <p>Move the slider below to update state on the server without a full page reload.</p>
    {{$.Range .Dot}}
    <p><a href="/logout">Sign out</a></p>
  </main>
  {{$.TailHTML}}
</body>
</html>
`

type demoOptions struct {
	ListenAddr    string
	PublicHost    string
	PasswordFile  string
	Realm         string
	ClientID      string
	Username      string
	UserEmail     string
	KeycloakImage string
}

func (o demoOptions) withDefaults() demoOptions {
	if o.ListenAddr == "" {
		o.ListenAddr = "0.0.0.0:8443"
	}
	if o.PasswordFile == "" {
		o.PasswordFile = "demo-password.txt"
	}
	if o.Realm == "" {
		o.Realm = "jawsauth-demo"
	}
	if o.ClientID == "" {
		o.ClientID = "jawsauth-demo-client"
	}
	if o.Username == "" {
		o.Username = "demo"
	}
	if o.UserEmail == "" {
		o.UserEmail = "demo@example.com"
	}
	if o.KeycloakImage == "" {
		o.KeycloakImage = "quay.io/keycloak/keycloak:latest"
	}
	return o
}

type demoServer struct {
	appURL       string
	keycloakURL  string
	username     string
	password     string
	userEmail    string
	passwordFile string

	httpServer *http.Server
	jaws       *jaws.Jaws
	keycloak   *keycloakServer

	closeOnce sync.Once
}

func (d *demoServer) close(ctx context.Context) (err error) {
	d.closeOnce.Do(func() {
		var errs []error
		if d.httpServer != nil {
			errs = append(errs, d.httpServer.Shutdown(ctx))
		}
		if d.jaws != nil {
			d.jaws.Close()
		}
		if d.keycloak != nil {
			errs = append(errs, d.keycloak.Close(ctx))
		}
		err = errors.Join(errs...)
	})
	return
}

func startDemo(ctx context.Context, opts demoOptions) (demo *demoServer, err error) {
	opts = opts.withDefaults()

	listener, err := net.Listen("tcp", opts.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	defer func() {
		if err != nil {
			_ = listener.Close()
		}
	}()

	publicHost, err := resolvePublicHost(opts.PublicHost, listener.Addr())
	if err != nil {
		return nil, err
	}

	appURL := "https://" + net.JoinHostPort(publicHost, listenerPort(listener.Addr()))

	password, err := randomPassword(18)
	if err != nil {
		return nil, fmt.Errorf("generate demo password: %w", err)
	}

	keycloak, err := startKeycloakServer(ctx, opts.KeycloakImage, password)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = keycloak.Close(context.Background())
		}
	}()

	oidc, err := keycloak.SetupRealm(ctx, keycloakRealmSetup{
		Realm:       opts.Realm,
		ClientID:    opts.ClientID,
		RedirectURI: appURL + "/oauth2/callback",
		Username:    opts.Username,
		Email:       opts.UserEmail,
		Password:    password,
	})
	if err != nil {
		return nil, err
	}

	if err = writePasswordFile(opts.PasswordFile, password); err != nil {
		return nil, err
	}

	jw, err := jaws.New()
	if err != nil {
		return nil, fmt.Errorf("create jaws instance: %w", err)
	}
	defer func() {
		if err != nil {
			jw.Close()
		}
	}()

	if err = jw.AddTemplateLookuper(template.Must(template.New("index.html").Parse(indexTemplate))); err != nil {
		return nil, fmt.Errorf("add template lookuper: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/jaws/", jw)

	cfg := jawsauth.Config{
		RedirectURL:  appURL + "/oauth2/callback",
		AuthURL:      oidc.AuthURL,
		TokenURL:     oidc.TokenURL,
		UserInfoURL:  oidc.UserInfoURL,
		Issuer:       oidc.Issuer,
		Scopes:       []string{"openid", "profile", "email"},
		ClientID:     opts.ClientID,
		ClientSecret: oidc.ClientSecret,
	}

	handleWithOAuthClient := func(uri string, handler http.Handler) {
		mux.Handle(uri, http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
			oauthCtx := context.WithValue(hr.Context(), oauth2.HTTPClient, keycloak.httpClient)
			handler.ServeHTTP(hw, hr.WithContext(oauthCtx))
		}))
	}

	authServer, err := jawsauth.New(jw, &cfg, handleWithOAuthClient)
	if err != nil {
		return nil, fmt.Errorf("create auth server: %w", err)
	}

	var sliderMu sync.Mutex
	var slider float64
	mux.Handle("/", authServer.Handler("index.html", jaws.Bind(&sliderMu, &slider)))
	mux.HandleFunc("/logged-out", func(hw http.ResponseWriter, hr *http.Request) {
		hw.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = hw.Write([]byte(`<!doctype html><html lang="en"><body><h1>Signed out</h1><p><a href="/">Sign in again</a></p></body></html>`))
	})
	mux.HandleFunc("/logout", func(hw http.ResponseWriter, hr *http.Request) {
		var idTokenHint string
		if sess := jw.GetSession(hr); sess != nil {
			if tokenSource, ok := sess.Get(authServer.SessionTokenKey).(oauth2.TokenSource); ok && tokenSource != nil {
				if token, e := tokenSource.Token(); e == nil && token != nil {
					if value, ok := token.Extra("id_token").(string); ok {
						idTokenHint = value
					}
				}
			}
			if authServer.LogoutEvent != nil {
				authServer.LogoutEvent(sess, hr)
			}
			sess.Set(authServer.SessionKey, nil)
			sess.Set(authServer.SessionTokenKey, nil)
			sess.Set(authServer.SessionEmailKey, nil)
			jw.Dirty(sess)
		}

		target := appURL + "/logged-out"
		if oidc.EndSessionURL != "" {
			if u, e := url.Parse(oidc.EndSessionURL); e == nil {
				q := u.Query()
				q.Set("client_id", opts.ClientID)
				q.Set("post_logout_redirect_uri", target)
				if idTokenHint != "" {
					q.Set("id_token_hint", idTokenHint)
				}
				u.RawQuery = q.Encode()
				http.Redirect(hw, hr, u.String(), http.StatusFound)
				return
			}
		}
		http.Redirect(hw, hr, "/logged-out", http.StatusFound)
	})

	cert, err := generateSelfSignedCertificate(publicHost)
	if err != nil {
		return nil, err
	}

	httpServer := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{ //nolint:gosec
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		},
	}

	go jw.Serve()

	go func() {
		_ = httpServer.Serve(tls.NewListener(listener, httpServer.TLSConfig))
	}()

	if err = waitForHTTPSReady(ctx, appURL+"/jaws/.ping"); err != nil {
		_ = httpServer.Shutdown(context.Background())
		return nil, err
	}

	absPasswordFile, pathErr := filepath.Abs(opts.PasswordFile)
	if pathErr != nil {
		absPasswordFile = opts.PasswordFile
	}

	return &demoServer{
		appURL:       appURL,
		keycloakURL:  keycloak.baseURL,
		username:     opts.Username,
		password:     password,
		userEmail:    opts.UserEmail,
		passwordFile: absPasswordFile,
		httpServer:   httpServer,
		jaws:         jw,
		keycloak:     keycloak,
	}, nil
}

func resolvePublicHost(publicHost string, addr net.Addr) (host string, err error) {
	host = strings.TrimSpace(publicHost)
	if host != "" {
		return host, nil
	}
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		if ip := tcpAddr.IP; ip != nil {
			s := ip.String()
			switch s {
			case "", "::", "0.0.0.0":
				if s, e := defaultInterfaceAddress(); e == nil {
					return s, nil
				}
				return "localhost", nil
			default:
				return s, nil
			}
		}
	}
	host, _, err = net.SplitHostPort(addr.String())
	if err != nil {
		return "", fmt.Errorf("determine public host: %w", err)
	}
	host = strings.TrimSpace(host)
	switch host {
	case "", "::", "0.0.0.0":
		if s, e := defaultInterfaceAddress(); e == nil {
			host = s
		} else {
			host = "localhost"
		}
	}
	return host, nil
}

func defaultInterfaceAddress() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || udpAddr.IP == nil {
		return "", errors.New("resolve default interface address")
	}
	if udpAddr.IP.IsUnspecified() {
		return "", errors.New("default interface address is unspecified")
	}
	return udpAddr.IP.String(), nil
}

func listenerPort(addr net.Addr) string {
	_, port, _ := net.SplitHostPort(addr.String())
	return port
}

func waitForHTTPSReady(ctx context.Context, pingURL string) error {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{ //nolint:gosec
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true},
		},
	}

	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error
	var lastStatus int
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pingURL, nil)
		if err != nil {
			return fmt.Errorf("create ping request: %w", err)
		}
		resp, err := client.Do(req)
		if err == nil {
			lastStatus = resp.StatusCode
			_ = resp.Body.Close()
			if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusBadRequest {
				return nil
			}
			lastErr = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		} else {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for https ready: %w", ctx.Err())
		case <-deadline.C:
			if lastErr != nil {
				return fmt.Errorf("https server not ready: %s (last status=%d, last error=%v)", pingURL, lastStatus, lastErr)
			}
			return fmt.Errorf("https server not ready: %s", pingURL)
		case <-ticker.C:
		}
	}
}

func randomPassword(bytesLen int) (string, error) {
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func writePasswordFile(path, password string) error {
	if err := os.WriteFile(path, []byte(password+"\n"), 0o600); err != nil {
		return fmt.Errorf("write password file %s: %w", path, err)
	}
	return nil
}

func generateSelfSignedCertificate(host string) (tls.Certificate, error) {
	certPEM, keyPEM, err := generateSelfSignedCertificatePEM(host)
	if err != nil {
		return tls.Certificate{}, err
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load key pair: %w", err)
	}
	return certificate, nil
}

func generateSelfSignedCertificatePEM(host string) (certPEM, keyPEM []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate private key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now().UTC()
	certTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(7 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		certTemplate.IPAddresses = append(certTemplate.IPAddresses, ip)
	} else {
		certTemplate.DNSNames = append(certTemplate.DNSNames, host)
	}

	if host != "localhost" {
		certTemplate.DNSNames = append(certTemplate.DNSNames, "localhost")
	}
	if !containsIP(certTemplate.IPAddresses, net.IPv4(127, 0, 0, 1)) {
		certTemplate.IPAddresses = append(certTemplate.IPAddresses, net.IPv4(127, 0, 0, 1))
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create self-signed certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if certPEM == nil || keyPEM == nil {
		return nil, nil, errors.New("encode certificate PEM")
	}
	return certPEM, keyPEM, nil
}

func containsIP(ips []net.IP, target net.IP) bool {
	for _, ip := range ips {
		if ip.Equal(target) {
			return true
		}
	}
	return false
}

func appOriginFromRedirectURI(redirectURI string) (string, error) {
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("parse redirect uri: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid redirect uri: %s", redirectURI)
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}
