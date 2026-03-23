package jawsauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/linkdata/jaws/secureheaders"
	"golang.org/x/oauth2"
)

const oauth2ReferrerKey = "oauth2referrer"
const oauth2StateKey = "oauth2state"
const oauth2PKCEVerifierKey = "oauth2pkceverifier"
const oauth2NonceKey = "oauth2nonce"

func normalizeHost(hostport string) (normalized string) {
	normalized = strings.TrimSpace(hostport)
	if normalized != "" {
		normalized = strings.TrimSuffix(normalized, ".")
		normalized = strings.ToLower(normalized)
		if strings.Contains(normalized, ":") {
			if h, _, err := net.SplitHostPort(normalized); err == nil {
				normalized = h
			}
		}
	}
	return
}

func sanitizeRedirectTarget(requestHost, location string) (sanitized string) {
	if trimmed := strings.TrimSpace(location); trimmed != "" {
		if u, err := url.Parse(trimmed); err == nil {
			if u.IsAbs() {
				if host := normalizeHost(requestHost); host != "" {
					if normalizeHost(u.Host) == host {
						sanitized = u.RequestURI()
					}
				}
			} else {
				sanitized = trimmed
			}
		}
	}
	sanitized = strings.TrimSpace(sanitized)
	if sanitized != "" {
		if !strings.HasPrefix(sanitized, "/") {
			sanitized = "/" + sanitized
		}
		for strings.HasPrefix(sanitized, "//") {
			sanitized = "/" + strings.TrimLeft(sanitized, "/")
		}
	}
	if sanitized == "" {
		sanitized = "/"
	}
	return
}

func (srv *Server) begin(hr *http.Request) (oauth2cfg *oauth2.Config, userinfourl, location string) {
	oauth2cfg = srv.oauth2cfg
	userinfourl = srv.userinfoUrl
	if location = strings.TrimSpace(hr.Referer()); location == "" {
		location = hr.RequestURI
	}
	location = sanitizeRedirectTarget(hr.Host, location)
	for s := range srv.HandledPaths {
		if strings.HasSuffix(location, s) {
			location = strings.TrimSuffix(location, s)
			break
		}
	}
	if location == "" {
		location = "/"
	}
	return
}

func (srv *Server) HandleLogin(hw http.ResponseWriter, hr *http.Request) {
	statusCode := http.StatusMethodNotAllowed
	if hr.Method == http.MethodGet {
		oauth2cfg, _, location := srv.begin(hr)
		if oauth2cfg != nil {
			if sess := srv.Jaws.GetSession(hr); sess != nil {
				authOptions := append([]oauth2.AuthCodeOption{}, srv.Options...)
				state, _ := sess.Get(oauth2StateKey).(string)
				if state == "" {
					state = randomHexString()
					sess.Set(oauth2StateKey, state)
				}
				nonce := randomHexString()
				sess.Set(oauth2NonceKey, nonce)
				authOptions = append(authOptions, oidc.Nonce(nonce))
				verifier := oauth2.GenerateVerifier()
				sess.Set(oauth2PKCEVerifierKey, verifier)
				authOptions = append(authOptions, oauth2.S256ChallengeOption(verifier))
				sess.Set(oauth2ReferrerKey, location)
				location = oauth2cfg.AuthCodeURL(state, authOptions...)
			}
		}
		hw.Header().Add("Location", location)
		statusCode = http.StatusFound
	}
	SetHeaders(hw, srv.ishttps)
	hw.WriteHeader(statusCode)
}

func (srv *Server) HandleLogout(hw http.ResponseWriter, hr *http.Request) {
	statusCode := http.StatusMethodNotAllowed
	if hr.Method == http.MethodGet {
		_, _, location := srv.begin(hr)
		if sess := srv.Jaws.GetSession(hr); sess != nil {
			if srv.LogoutEvent != nil {
				srv.LogoutEvent(sess, hr)
			}
			sess.Set(srv.SessionKey, nil)
			sess.Set(srv.SessionTokenKey, nil)
			sess.Set(srv.SessionEmailKey, nil)
			sess.Set(srv.SessionEmailVerifiedKey, nil)
			srv.Jaws.Dirty(sess)
		}
		hw.Header().Add("Location", location)
		statusCode = http.StatusFound
	}
	SetHeaders(hw, srv.ishttps)
	hw.WriteHeader(statusCode)
}

func writeBody(w io.Writer, statusCode int, err error, body []byte) {
	const tmpl = `<html><body><h2>%03d %s</h2><p>%s</p></body></html>`
	if body == nil {
		if err != nil {
			body = []byte(fmt.Sprintf(tmpl, statusCode, http.StatusText(statusCode), html.EscapeString(err.Error())))
		}
	}
	_, _ = w.Write(body)
}

// SetHeaders is called to write HTTP headers for all OAuth endpoint responses
var SetHeaders = DefaultSetHeaders

// DefaultSetHeaders writes response headers for OAuth endpoint responses.
func DefaultSetHeaders(hw http.ResponseWriter, ishttps bool) {
	secureheaders.SetHeaders(secureheaders.DefaultHeaders, hw, ishttps)
	hw.Header().Set("Cache-Control", "no-store")
}

func (srv *Server) writeResult(hw http.ResponseWriter, statusCode int, err error, body []byte) {
	SetHeaders(hw, srv.ishttps)
	hw.WriteHeader(statusCode)
	writeBody(hw, statusCode, err, body)
}

var ErrOAuth2NotConfigured = errors.New("oauth2 not configured")
var ErrOAuth2MissingSession = errors.New("oauth2 missing session")
var ErrOAuth2MissingState = errors.New("oauth2 missing state")
var ErrOAuth2WrongState = errors.New("oauth2 wrong state")

// ErrOAuth2MissingPKCEVerifier means the callback session did not contain the required PKCE verifier.
var ErrOAuth2MissingPKCEVerifier = errors.New("oauth2 missing pkce verifier")

func randomHexString() string {
	b := [32]byte{}
	_, _ = rand.Read(b[:]) // never returns an error, always fills all of b
	return hex.EncodeToString(b[:])
}

func mergeMissingClaims(dst, src map[string]any) {
	if dst != nil {
		for k, v := range src {
			if _, ok := dst[k]; !ok {
				dst[k] = v
			}
		}
	}
}

func (srv *Server) extractEmail(claims map[string]any) (sessEmailValue any) {
	for _, k := range []string{"email", "mail", "public_email"} {
		if s, ok := claims[k].(string); ok {
			if m, e := mail.ParseAddress(s); e == nil {
				s = m.Address
			}
			return strings.ToLower(strings.TrimSpace(s))
		}
	}
	if l := srv.Jaws.Logger; l != nil {
		l.Warn("jawsauth: no email found", "userinfo", claims)
	}
	return
}

func extractEmailVerified(claims map[string]any) (verified bool) {
	if claims != nil {
		switch value := claims["email_verified"].(type) {
		case bool:
			verified = value
		case string:
			verified, _ = strconv.ParseBool(value)
		case float64:
			verified = value != 0
		}
	}
	return
}

func (srv *Server) fetchUserInfo(ctx context.Context, userinfoURL string, tokenSource oauth2.TokenSource) (userinfo map[string]any, err error) {
	if userinfoURL != "" && tokenSource != nil {
		client := oauth2.NewClient(ctx, tokenSource)
		var resp *http.Response
		if resp, err = client.Get(userinfoURL); err == nil {
			defer resp.Body.Close()
			var body []byte
			if body, err = io.ReadAll(io.LimitReader(resp.Body, 32768)); err == nil {
				if resp.StatusCode == http.StatusOK {
					err = json.Unmarshal(body, &userinfo)
				} else {
					err = fmt.Errorf("userinfo status %s", resp.Status)
				}
			}
		}
	}
	return
}

func (srv *Server) HandleAuthResponse(hw http.ResponseWriter, hr *http.Request) {
	statusCode := http.StatusMethodNotAllowed
	err := ErrOAuth2Callback

	if hr.Method == http.MethodGet {
		oauth2Config, userinfourl, location := srv.begin(hr)
		var sessValue any
		var sessEmailValue any
		var sessEmailVerifiedValue any
		var sessTokenValue any
		authctx := hr.Context()
		if srv.httpClient != nil {
			if _, ok := authctx.Value(oauth2.HTTPClient).(*http.Client); !ok {
				authctx = context.WithValue(authctx, oauth2.HTTPClient, srv.httpClient)
			}
		}
		sess := srv.Jaws.GetSession(hr)
		err = ErrOAuth2NotConfigured
		statusCode = http.StatusInternalServerError

		if oauth2Config != nil {
			err = ErrOAuth2MissingSession
			statusCode = http.StatusBadRequest
			if sess != nil {
				gotState := hr.FormValue("state")
				wantState, _ := sess.Get(oauth2StateKey).(string)
				verifier, _ := sess.Get(oauth2PKCEVerifierKey).(string)
				wantNonce, _ := sess.Get(oauth2NonceKey).(string)
				sess.Set(oauth2StateKey, nil)
				sess.Set(oauth2PKCEVerifierKey, nil)
				sess.Set(oauth2NonceKey, nil)
				err = ErrOAuth2MissingState
				if wantState != "" {
					err = ErrOAuth2WrongState
					if wantState == gotState {
						if statusCode, err = oauth2CallbackError(statusCode, hr); err == nil {
							err = ErrOAuth2MissingPKCEVerifier
							if verifier != "" {
								var token *oauth2.Token
								exchangeOptions := []oauth2.AuthCodeOption{
									oauth2.AccessTypeOffline,
									oauth2.VerifierOption(verifier),
								}
								if token, err = oauth2Config.Exchange(authctx, hr.FormValue("code"), exchangeOptions...); srv.Jaws.Log(err) == nil {
									err = ErrOAuth2NotConfigured
									statusCode = http.StatusInternalServerError
									if srv.idTokenVerifier != nil {
										rawIDToken, _ := token.Extra("id_token").(string)
										statusCode = http.StatusUnauthorized
										err = ErrOIDCMissingIDToken
										if rawIDToken != "" {
											var idToken *oidc.IDToken
											if idToken, err = srv.idTokenVerifier.Verify(authctx, rawIDToken); wrapOIDC(ErrOIDCInvalidIDToken, &err) == nil {
												err = ErrOIDCMissingNonce
												if wantNonce != "" {
													err = ErrOIDCNonceMismatch
													if idToken.Nonce == wantNonce {
														var claims map[string]any
														if err = idToken.Claims(&claims); wrapOIDC(ErrOIDCInvalidIDToken, &err) == nil {
															tokenSource := oauth2Config.TokenSource(authctx, token)
															sessTokenValue = tokenSource
															sessValue = claims
															if fallback, e := srv.fetchUserInfo(authctx, userinfourl, tokenSource); srv.Jaws.Log(e) == nil {
																mergeMissingClaims(claims, fallback)
															}
															verified := extractEmailVerified(claims)
															claims["email_verified"] = verified
															sessEmailValue = srv.extractEmail(claims)
															sessEmailVerifiedValue = verified
															if s, ok := sess.Get(oauth2ReferrerKey).(string); ok {
																location = sanitizeRedirectTarget(hr.Host, s)
															}
															sess.Set(oauth2ReferrerKey, nil)
															hw.Header().Add("Location", location)
															statusCode = http.StatusFound
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		if sess != nil {
			sess.Set(srv.SessionKey, sessValue)
			sess.Set(srv.SessionTokenKey, sessTokenValue)
			sess.Set(srv.SessionEmailKey, sessEmailValue)
			sess.Set(srv.SessionEmailVerifiedKey, sessEmailVerifiedValue)
			if srv.LoginEvent != nil && sessValue != nil {
				srv.LoginEvent(sess, hr)
			}
			srv.Jaws.Dirty(sess)
		}
		if err != nil && srv.LoginFailed != nil {
			sessEmailValue, _ := sessEmailValue.(string)
			if srv.LoginFailed(hw, hr, statusCode, err, sessEmailValue) {
				return
			}
		}
	}
	srv.writeResult(hw, statusCode, err, nil)
}
