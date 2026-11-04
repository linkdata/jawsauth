package jawsauth

import (
	"bytes"
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
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/linkdata/jaws"
	"github.com/linkdata/secureheaders"
	"golang.org/x/oauth2"
)

const oauth2ReferrerKey = "oauth2referrer"
const oauth2StateKey = "oauth2state"
const oauth2PKCEVerifierKey = "oauth2pkceverifier"
const oauth2NonceKey = "oauth2nonce"
const oauth2IDTokenExpiryKey = "oauth2idtokenexpiry" // #nosec G101
const oauth2FlowExpiryKey = "oauth2flowexpiry"
const oauth2LinkKey = "oauth2link"

const oauth2FlowLifetime = 10 * time.Minute
const oauth2ProviderTimeout = 15 * time.Second

type pendingOAuthFlow struct {
	verifier string
	nonce    string
	referrer string
	link     bool
	canceled chan struct{}
}

func (flow pendingOAuthFlow) revoked() bool {
	select {
	case <-flow.canceled:
		return true
	default:
		return false
	}
}

func (srv *Server) takeOAuthFlow(sess *jaws.Session, gotState string) (flow pendingOAuthFlow, err error) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	wantState, _ := sess.Get(srv.sessionKey(oauth2StateKey)).(string)
	if wantState == "" {
		return flow, ErrOAuth2MissingState
	}
	if gotState != wantState {
		return flow, ErrOAuth2WrongState
	}
	flow.verifier, _ = sess.Get(srv.sessionKey(oauth2PKCEVerifierKey)).(string)
	flow.nonce, _ = sess.Get(srv.sessionKey(oauth2NonceKey)).(string)
	flow.referrer, _ = sess.Get(srv.sessionKey(oauth2ReferrerKey)).(string)
	flow.link, _ = sess.Get(srv.sessionKey(oauth2LinkKey)).(bool)
	expiry, _ := sess.Get(srv.sessionKey(oauth2FlowExpiryKey)).(time.Time)
	srv.clearSessionOAuthFlow(sess)
	if !time.Now().Before(expiry) {
		return flow, ErrOAuth2ExpiredState
	}
	flow.canceled = make(chan struct{})
	if srv.oauthCallbacks == nil {
		srv.oauthCallbacks = make(map[*jaws.Session]chan struct{})
	}
	srv.oauthCallbacks[sess] = flow.canceled
	return flow, nil
}

func (srv *Server) finishOAuthFlow(sess *jaws.Session, flow pendingOAuthFlow) {
	if flow.canceled == nil {
		return
	}
	srv.mu.Lock()
	if srv.oauthCallbacks[sess] == flow.canceled {
		delete(srv.oauthCallbacks, sess)
	}
	srv.mu.Unlock()
}

// maxRedirectTargetLen bounds return targets retained in pre-auth sessions.
const maxRedirectTargetLen = 8192

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
	sanitized = "/" + strings.TrimLeft(sanitized, "/\\")
	if len(sanitized) > maxRedirectTargetLen {
		sanitized = "/"
	}
	return
}

func (srv *Server) begin(hr *http.Request) (oauth2cfg *oauth2.Config, location string) {
	oauth2cfg = srv.oauth2cfg
	if location = strings.TrimSpace(hr.Referer()); location == "" {
		location = hr.RequestURI
	}
	location = sanitizeRedirectTarget(hr.Host, location)
	if _, handled := srv.HandledPaths[location]; handled {
		location = "/"
	}
	return
}

// HandleLogin begins the configured OIDC or OAuth2 profile login flow.
//
// For GET requests it generates and stores the state, nonce and PKCE verifier in the
// session, then responds with a 302 redirect to the provider's authorization URL.
// If no session can be created, it returns 503 with Retry-After instead.
// Non-GET requests receive 405.
func (srv *Server) HandleLogin(hw http.ResponseWriter, hr *http.Request) {
	srv.startOAuth(hw, hr, false)
}

// HandleLink begins a provider flow for linking to the caller's existing
// identity. The application must authorize this POST before calling it and
// recheck that identity in LinkEvent when the provider returns.
func (srv *Server) HandleLink(hw http.ResponseWriter, hr *http.Request) {
	srv.startOAuth(hw, hr, true)
}

func (srv *Server) startOAuth(hw http.ResponseWriter, hr *http.Request, link bool) {
	statusCode := http.StatusMethodNotAllowed
	if (!link && hr.Method == http.MethodGet) || (link && hr.Method == http.MethodPost) {
		if link && http.NewCrossOriginProtection().Check(hr) != nil {
			srv.writeResult(hw, http.StatusForbidden, ErrOAuth2LinkRejected, nil)
			return
		}
		oauth2cfg, location := srv.begin(hr)
		if oauth2cfg != nil {
			sess := srv.Jaws.GetSession(hr)
			if sess == nil && !link {
				sess = srv.Jaws.NewSession(hw, hr)
			}
			if link && sess == nil {
				srv.writeResult(hw, http.StatusForbidden, ErrOAuth2MissingSession, nil)
				return
			}
			if link && srv.LinkEvent == nil {
				srv.writeResult(hw, http.StatusInternalServerError, ErrOAuth2NotConfigured, nil)
				return
			}
			if sess == nil {
				hw.Header().Set("Retry-After", "60")
				srv.writeResult(hw, http.StatusServiceUnavailable, ErrOAuth2MissingSession, nil)
				return
			}
			flowExpiry := time.Now().Add(oauth2FlowLifetime)
			if !sess.ExtendGrace(oauth2FlowLifetime + oauth2ProviderTimeout + time.Second) {
				srv.writeResult(hw, http.StatusServiceUnavailable, ErrOAuth2MissingSession, nil)
				return
			}
			authOptions := append([]oauth2.AuthCodeOption{}, srv.Options...)
			state := randomHexString()
			var nonce string
			if srv.profileSubject == nil {
				nonce = randomHexString()
				authOptions = append(authOptions, oidc.Nonce(nonce))
			}
			verifier := oauth2.GenerateVerifier()
			authOptions = append(authOptions, oauth2.S256ChallengeOption(verifier))
			if link && location == hr.RequestURI {
				location = "/"
			}
			srv.mu.Lock()
			srv.clearSessionOAuthFlow(sess)
			sess.Set(srv.sessionKey(oauth2StateKey), state)
			sess.Set(srv.sessionKey(oauth2FlowExpiryKey), flowExpiry)
			sess.Set(srv.sessionKey(oauth2LinkKey), link)
			sess.Set(srv.sessionKey(oauth2NonceKey), nonce)
			sess.Set(srv.sessionKey(oauth2PKCEVerifierKey), verifier)
			sess.Set(srv.sessionKey(oauth2ReferrerKey), location)
			srv.mu.Unlock()
			location = oauth2cfg.AuthCodeURL(state, authOptions...)
		}
		hw.Header().Set("Location", location)
		statusCode = http.StatusFound
	}
	SetHeaders(hw, srv.ishttps)
	hw.WriteHeader(statusCode)
}

// HandleLogout clears the session's stored authentication and redirects.
//
// For GET requests it clears the auth (firing LogoutEvent if set) and responds with a
// 302 redirect back to the sanitized referrer (or "/"). Non-GET requests receive 405.
func (srv *Server) HandleLogout(hw http.ResponseWriter, hr *http.Request) {
	statusCode := http.StatusMethodNotAllowed
	if hr.Method == http.MethodGet {
		_, location := srv.begin(hr)
		if sess := srv.Jaws.GetSession(hr); sess != nil {
			srv.clearSessionAuth(sess, hr, nil)
		}
		hw.Header().Set("Location", location)
		statusCode = http.StatusFound
	}
	SetHeaders(hw, srv.ishttps)
	hw.WriteHeader(statusCode)
}

func writeBody(w io.Writer, statusCode int, err error, body []byte) {
	const tmpl = `<html><body><h2>%03d %s</h2><p>%s</p></body></html>`
	if body == nil {
		if err != nil {
			body = fmt.Appendf(nil, tmpl, statusCode, http.StatusText(statusCode), html.EscapeString(err.Error()))
		}
	}
	_, _ = w.Write(body)
}

// SetHeaders writes the HTTP response headers for all OAuth endpoint responses.
//
// It defaults to DefaultSetHeaders and may be reassigned at startup to customize
// headers; it must not be reassigned concurrently with serving requests.
var SetHeaders = DefaultSetHeaders

// DefaultSetHeaders writes response headers for OAuth endpoint responses.
func DefaultSetHeaders(hw http.ResponseWriter, ishttps bool) {
	secureheaders.SetHeaders(secureheaders.DefaultHeaders(), hw, ishttps)
	hw.Header().Set("Cache-Control", "no-store")
}

func (srv *Server) writeResult(hw http.ResponseWriter, statusCode int, err error, body []byte) {
	SetHeaders(hw, srv.ishttps)
	hw.WriteHeader(statusCode)
	writeBody(hw, statusCode, err, body)
}

// ErrOAuth2NotConfigured means OAuth2/OIDC is not configured on the Server.
var ErrOAuth2NotConfigured = errors.New("oauth2 not configured")

// ErrOAuth2MissingSession means no jaws session was available to carry the OAuth2 flow state.
var ErrOAuth2MissingSession = errors.New("oauth2 missing session")

// ErrOAuth2MissingState means the callback session did not contain the expected state value.
var ErrOAuth2MissingState = errors.New("oauth2 missing state")

// ErrOAuth2WrongState means the callback state value did not match the stored session state.
var ErrOAuth2WrongState = errors.New("oauth2 wrong state")

// ErrOAuth2ExpiredState means the provider returned after the flow lifetime.
var ErrOAuth2ExpiredState = errors.New("oauth2 expired state")

// ErrOAuth2MissingPKCEVerifier means the callback session did not contain the required PKCE verifier.
var ErrOAuth2MissingPKCEVerifier = errors.New("oauth2 missing pkce verifier")

// ErrUserInfoStatus means the UserInfo endpoint returned a non-200 HTTP status.
var ErrUserInfoStatus = errors.New("userinfo status")

// ErrUserInfoTooLarge means the authenticated profile exceeded the response limit.
var ErrUserInfoTooLarge = errors.New("userinfo response too large")

// ErrOAuth2InvalidProfile means an authenticated profile lacked a stable subject.
var ErrOAuth2InvalidProfile = errors.New("oauth2 invalid profile")

// ErrOAuth2LinkRejected means the application did not accept a proven link.
var ErrOAuth2LinkRejected = errors.New("oauth2 link rejected")

func randomHexString() string {
	b := [32]byte{}
	_, _ = rand.Read(b[:]) // never returns an error, always fills all of b
	return hex.EncodeToString(b[:])
}

// mergeUserInfoClaims accepts fallback claims only for the verified subject.
// Email verification stays paired with the email from the same response.
func mergeUserInfoClaims(dst, src map[string]any) {
	subject, _ := dst["sub"].(string)
	if other, _ := src["sub"].(string); subject == "" || other != subject {
		return
	}
	_, hasEmail := dst["email"]
	if !hasEmail {
		if email, ok := src["email"]; ok {
			dst["email"] = email
			dst["email_verified"] = src["email_verified"]
		}
	} else if _, hasVerified := dst["email_verified"]; !hasVerified {
		email, _ := dst["email"].(string)
		other, _ := src["email"].(string)
		if email != "" && email == other {
			dst["email_verified"] = src["email_verified"]
		}
	}
	for k, v := range src {
		if k != "email_verified" {
			if _, ok := dst[k]; !ok {
				dst[k] = v
			}
		}
	}
}

func (srv *Server) extractEmail(claims map[string]any) (sessEmailValue any, verified bool) {
	for _, k := range []string{"email", "mail", "public_email"} {
		if s, ok := claims[k].(string); ok {
			if s = strings.TrimSpace(s); s != "" {
				if m, err := mail.ParseAddress(s); err == nil {
					return foldEmailCase(m.Address), k == "email" && extractEmailVerified(claims)
				}
			}
		}
	}
	if l := srv.Jaws.Logger; l != nil {
		l.Warn("jawsauth: no email found")
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
		case json.Number:
			if number, err := value.Float64(); err == nil {
				verified = number != 0
			}
		}
	}
	return
}

func (srv *Server) fetchUserInfo(ctx context.Context, userinfoURL string, tokenSource oauth2.TokenSource) (userinfo map[string]any, err error) {
	if userinfoURL != "" && tokenSource != nil {
		client := oauth2.NewClient(ctx, tokenSource)
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		var resp *http.Response
		if resp, err = client.Get(userinfoURL); /*#nosec G704*/ err == nil {
			defer func() {
				if closeErr := resp.Body.Close(); err == nil && closeErr != nil {
					err = closeErr
				}
			}()
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("%w %s", ErrUserInfoStatus, resp.Status)
			}
			var body []byte
			if body, err = io.ReadAll(io.LimitReader(resp.Body, 32769)); err == nil {
				if len(body) > 32768 {
					err = ErrUserInfoTooLarge
				} else {
					decoder := json.NewDecoder(bytes.NewReader(body))
					if srv.profileSubject != nil {
						decoder.UseNumber()
					}
					err = decoder.Decode(&userinfo)
					if err == nil {
						var extra any
						if trailingErr := decoder.Decode(&extra); trailingErr != io.EOF {
							err = ErrOAuth2InvalidProfile
						}
					}
				}
			}
		}
	}
	return
}

func (srv *Server) addUserInfoClaims(ctx context.Context, claims map[string]any, tokenSource oauth2.TokenSource) {
	if fallback, err := srv.fetchUserInfo(ctx, srv.userinfoUrl, tokenSource); srv.Jaws.Log(err) == nil {
		mergeUserInfoClaims(claims, fallback)
	}
}

func (srv *Server) verifyOAuthIdentity(ctx context.Context, token *oauth2.Token, nonce string) (claims map[string]any, tokenSource oauth2.TokenSource, expiry time.Time, status int, err error) {
	status = http.StatusUnauthorized
	if srv.idTokenVerifier != nil {
		err = ErrOIDCMissingIDToken
		raw, _ := token.Extra("id_token").(string)
		if raw == "" {
			return
		}
		var idToken *oidc.IDToken
		idToken, err = srv.idTokenVerifier.Verify(ctx, raw)
		if wrapOIDC(ErrOIDCInvalidIDToken, &err) != nil {
			return
		}
		err = ErrOIDCMissingNonce
		if nonce == "" {
			return
		}
		err = ErrOIDCNonceMismatch
		if idToken.Nonce != nonce {
			return
		}
		err = idToken.Claims(&claims)
		if wrapOIDC(ErrOIDCInvalidIDToken, &err) != nil {
			return
		}
		tokenSource = srv.oauth2cfg.TokenSource(srv.oauth2Context(context.Background()), token)
		srv.addUserInfoClaims(ctx, claims, oauth2.StaticTokenSource(token))
		return claims, tokenSource, idToken.Expiry, status, nil
	}
	if srv.profileSubject == nil || token.AccessToken == "" || !token.Valid() {
		return nil, nil, time.Time{}, status, ErrOAuth2InvalidProfile
	}
	status = http.StatusBadGateway
	claims, err = srv.fetchUserInfo(ctx, srv.userinfoUrl, oauth2.StaticTokenSource(token))
	if err != nil {
		return
	}
	if !token.Valid() {
		return nil, nil, time.Time{}, http.StatusUnauthorized, ErrOAuth2InvalidProfile
	}
	status = http.StatusUnauthorized
	if claims == nil {
		return nil, nil, time.Time{}, status, ErrOAuth2InvalidProfile
	}
	var subject string
	subject, err = srv.profileSubject(claims)
	if err != nil || subject == "" {
		return nil, nil, time.Time{}, status, ErrOAuth2InvalidProfile
	}
	claims["iss"] = srv.issuer
	claims["sub"] = subject
	expiry = time.Now().Add(24 * time.Hour)
	if !token.Expiry.IsZero() && token.Expiry.Before(expiry) {
		expiry = token.Expiry
	}
	return claims, nil, expiry, status, nil
}

// HandleAuthResponse handles the OIDC or OAuth2 profile callback endpoint.
//
// For GET requests it validates the state, exchanges the authorization code using the
// stored PKCE verifier, verifies the ID token or authenticated profile, and stores
// claims in a new session. A link flow instead invokes [Server.LinkEvent] before
// rotation and keeps the original session. It invokes [Server.LoginEvent] after a
// new sign-in or [Server.LoginFailed] on failure. Non-GET requests receive 405.
//
// Rotation discards pre-login application data and requires a free JaWS session slot.
// If no slot is available, existing authentication is preserved and the default
// response is 503. The user must restart login after capacity becomes available.
func (srv *Server) HandleAuthResponse(hw http.ResponseWriter, hr *http.Request) {
	statusCode := http.StatusMethodNotAllowed
	err := ErrOAuth2Callback

	if hr.Method == http.MethodGet {
		oauth2Config, location := srv.begin(hr)
		var sessValue any
		var sessEmail string
		var linked bool
		providerCtx, cancel := context.WithTimeout(hr.Context(), oauth2ProviderTimeout)
		defer cancel()
		authctx := srv.oauth2Context(providerCtx)
		sess := srv.Jaws.GetSession(hr)
		if sess != nil {
			sessEmail, _ = sess.Get(srv.SessionEmailKey).(string)
		}
		err = ErrOAuth2NotConfigured
		statusCode = http.StatusInternalServerError

		if oauth2Config != nil {
			err = ErrOAuth2MissingSession
			statusCode = http.StatusBadRequest
			if sess != nil {
				gotState := hr.FormValue("state") // #nosec G120
				flow, flowErr := srv.takeOAuthFlow(sess, gotState)
				err = flowErr
				if err == nil {
					defer srv.finishOAuthFlow(sess, flow)
					if statusCode, err = oauth2CallbackError(statusCode, hr); err == nil {
						err = ErrOAuth2MissingPKCEVerifier
						if flow.verifier != "" {
							var token *oauth2.Token
							exchangeOptions := []oauth2.AuthCodeOption{
								oauth2.VerifierOption(flow.verifier),
							}
							if srv.profileSubject == nil {
								exchangeOptions = append(exchangeOptions, oauth2.AccessTypeOffline)
							}
							if token, err = oauth2Config.Exchange(authctx, hr.FormValue("code") /* #nosec G120 */, exchangeOptions...); srv.Jaws.Log(err) == nil {
								var claims map[string]any
								var tokenSource oauth2.TokenSource
								var expiry time.Time
								claims, tokenSource, expiry, statusCode, err = srv.verifyOAuthIdentity(authctx, token, flow.nonce)
								if err == nil {
									if flow.revoked() || srv.Jaws.GetSession(hr) != sess {
										err = ErrOAuth2MissingSession
										statusCode = http.StatusForbidden
									} else if flow.link {
										statusCode = http.StatusForbidden
										err = ErrOAuth2MissingSession
										if srv.LinkEvent != nil && !flow.revoked() && srv.Jaws.GetSession(hr) == sess {
											var linkErr error
											statusCode, linkErr = srv.LinkEvent(sess, hr, claims)
											if linkErr == nil && statusCode == 0 {
												err = nil
												sessValue = claims
												linked = true
											} else {
												_ = srv.Jaws.Log(linkErr)
												err = ErrOAuth2LinkRejected
											}
										}
										if err != nil && (statusCode < 400 || statusCode > 599) {
											statusCode = http.StatusForbidden
										}
										if err == nil {
											if flow.referrer != "" {
												location = sanitizeRedirectTarget(hr.Host, flow.referrer)
											}
											hw.Header().Set("Location", location)
											statusCode = http.StatusFound
										}
									} else {
										requests := sess.Requests()
										_, hadAuth := srv.sessionAuthStatus(sess, nil)
										err = ErrOAuth2MissingSession
										statusCode = http.StatusServiceUnavailable
										if rotated := srv.Jaws.NewSession(hw, hr); rotated != nil {
											if flow.revoked() {
												http.SetCookie(hw, rotated.Close())
												err = ErrOAuth2MissingSession
												statusCode = http.StatusForbidden
											} else {
												srv.mu.Lock()
												hadTimer := srv.authTimers[sess.ID()] != nil
												srv.stopSessionAuthTimerLocked(sess, nil)
												srv.mu.Unlock()
												reloadAuthRequests(requests)
												if hadAuth && hadTimer && srv.LogoutEvent != nil {
													srv.LogoutEvent(sess, hr)
												}
												sess = rotated
												err = srv.storeSessionAuthClaimsIfActive(sess, claims, tokenSource, expiry, nil, flow.canceled)
												if errors.Is(err, ErrOAuth2MissingSession) {
													http.SetCookie(hw, rotated.Close())
													statusCode = http.StatusForbidden
												}
											}
										} else {
											hw.Header().Set("Retry-After", "60")
										}
										if err == nil {
											sessValue = claims
											sessEmail, _ = sess.Get(srv.SessionEmailKey).(string)
											if flow.referrer != "" {
												location = sanitizeRedirectTarget(hr.Host, flow.referrer)
											}
											hw.Header().Set("Location", location)
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
		if sess != nil {
			if sessValue == nil {
				srv.Jaws.Dirty(sess)
			} else if !linked && srv.LoginEvent != nil {
				srv.LoginEvent(sess, hr)
			}
		}
		if err != nil && srv.LoginFailed != nil {
			if srv.LoginFailed(hw, hr, statusCode, err, sessEmail) {
				return
			}
		}
	}
	srv.writeResult(hw, statusCode, err, nil)
}
