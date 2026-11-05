package jawsauth

import (
	"bytes"
	"context"
	"crypto/rand"
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

const oauth2FlowKey = "oauth2flow"
const oauth2AuthExpiryKey = "oauth2authexpiry"

const oauth2FlowLifetime = 10 * time.Minute
const oauth2ProviderTimeout = 15 * time.Second
const profileAuthLifetime = 24 * time.Hour
const maxUserInfoBytes = 32 << 10

// Allow provider I/O after the flow lifetime, with one second of extra grace.
const oauth2FlowGrace = oauth2FlowLifetime + oauth2ProviderTimeout + time.Second

type pendingOAuthFlow struct {
	state    string
	expiry   time.Time
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
	flow, _ = sess.Get(srv.sessionKey(oauth2FlowKey)).(pendingOAuthFlow)
	if flow.state == "" {
		return flow, ErrOAuth2MissingState
	}
	if gotState != flow.state {
		return flow, ErrOAuth2WrongState
	}
	srv.clearSessionOAuthFlowLocked(sess)
	if !time.Now().Before(flow.expiry) {
		return flow, ErrOAuth2ExpiredState
	}
	flow.canceled = make(chan struct{})
	if srv.oauthCallbacks == nil {
		srv.oauthCallbacks = make(map[*jaws.Session]pendingOAuthFlow)
	}
	srv.oauthCallbacks[sess] = flow
	return flow, nil
}

func (srv *Server) finishOAuthFlow(sess *jaws.Session, flow pendingOAuthFlow) {
	srv.mu.Lock()
	if srv.oauthCallbacks[sess].canceled == flow.canceled {
		delete(srv.oauthCallbacks, sess)
	}
	srv.mu.Unlock()
}

// maxRedirectTargetLen bounds return targets retained in pre-auth sessions.
const maxRedirectTargetLen = 8192

func normalizeHost(hostport string) (normalized string) {
	normalized = strings.TrimSpace(hostport)
	if normalized != "" {
		if strings.HasPrefix(normalized, "[") && strings.HasSuffix(normalized, "]") {
			normalized += ":0"
		}
		if strings.Contains(normalized, ":") {
			h, _, err := net.SplitHostPort(normalized)
			if err != nil {
				return ""
			}
			normalized = h
		}
		normalized = strings.ToLower(strings.TrimSuffix(normalized, "."))
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

func (srv *Server) begin(hr *http.Request) (location string) {
	if location = strings.TrimSpace(hr.Referer()); location == "" {
		location = hr.RequestURI
	}
	location = srv.returnTarget(hr, location)
	return
}

func (srv *Server) returnTarget(hr *http.Request, location string) string {
	location = sanitizeRedirectTarget(hr.Host, location)
	if target, err := url.Parse(location); err == nil {
		if _, handled := srv.HandledPaths[callbackPathFromURL(target)]; handled {
			location = "/"
		}
	}
	return location
}

// HandleLogin begins the configured OIDC or OAuth2 profile login flow.
//
// For GET requests it stores the state, PKCE verifier and, for OIDC, nonce in the
// session, then responds with a 302 redirect to the provider's authorization URL.
// It replaces any pending flow on this server, canceling a running callback or link.
// If no usable session is available, it returns 503 with Retry-After instead.
// Non-GET requests receive 405 with Allow: GET.
func (srv *Server) HandleLogin(hw http.ResponseWriter, hr *http.Request) {
	if hr.Method != http.MethodGet {
		hw.Header().Set("Allow", http.MethodGet)
		srv.writeResult(hw, http.StatusMethodNotAllowed, nil)
		return
	}
	srv.startOAuth(hw, hr, false, false)
}

// HandleLink begins a provider flow for linking to the caller's existing
// identity. The application must authorize this POST before calling it and
// recheck that identity in LinkEvent when the provider returns. On success it
// responds with a 303 redirect to the provider. It returns 405 with Allow: POST
// for other methods, 403 for a cross-origin or missing session, and 500 when
// linking is not configured. Starting a link replaces any pending flow on this
// server, including a running login callback.
func (srv *Server) HandleLink(hw http.ResponseWriter, hr *http.Request) {
	switch {
	case hr.Method != http.MethodPost:
		hw.Header().Set("Allow", http.MethodPost)
		srv.writeResult(hw, http.StatusMethodNotAllowed, nil)
	case linkOriginCheck.Check(hr) != nil:
		srv.writeResult(hw, http.StatusForbidden, ErrOAuth2InvalidOrigin)
	case srv.oauth2cfg == nil || srv.LinkEvent == nil:
		srv.writeResult(hw, http.StatusInternalServerError, ErrOAuth2NotConfigured)
	default:
		srv.startOAuth(hw, hr, true, false)
	}
}

var linkOriginCheck = http.NewCrossOriginProtection()

func (srv *Server) startOAuth(hw http.ResponseWriter, hr *http.Request, link, fromWrapper bool) {
	oauth2cfg := srv.oauth2cfg
	var location string
	switch {
	case fromWrapper:
		location = srv.returnTarget(hr, hr.RequestURI)
	case link && strings.TrimSpace(hr.Referer()) == "":
		location = "/"
	default:
		location = srv.begin(hr)
	}
	if oauth2cfg != nil {
		flow, sess, status := srv.prepareOAuthFlow(hw, hr, link, fromWrapper, location)
		if status != 0 {
			failure := ErrOAuth2MissingSession
			switch status {
			case http.StatusConflict:
				failure = ErrOAuth2LoginInProgress
				if srv.LoginFailed != nil {
					email, _ := sess.Get(srv.SessionEmailKey).(string)
					if srv.LoginFailed(hw, hr, status, failure, email) {
						return
					}
				}
			case http.StatusServiceUnavailable:
				hw.Header().Set("Retry-After", "60")
			}
			srv.writeResult(hw, status, failure)
			return
		}
		authOptions := append([]oauth2.AuthCodeOption{}, srv.Options...)
		if flow.nonce != "" {
			authOptions = append(authOptions, oidc.Nonce(flow.nonce))
		}
		authOptions = append(authOptions, oauth2.S256ChallengeOption(flow.verifier))
		location = oauth2cfg.AuthCodeURL(flow.state, authOptions...)
	}
	hw.Header().Set("Location", location)
	statusCode := http.StatusFound
	if link {
		statusCode = http.StatusSeeOther
	}
	SetHeaders(hw, srv.ishttps)
	hw.WriteHeader(statusCode)
}

func (srv *Server) prepareOAuthFlow(hw http.ResponseWriter, hr *http.Request, link, fromWrapper bool, location string) (flow pendingOAuthFlow, sess *jaws.Session, status int) {
	failStatus := http.StatusServiceUnavailable
	if link {
		failStatus = http.StatusForbidden
	}
	rotationLock := srv.SessionRotationLock
	if rotationLock != nil {
		rotationLock.Lock()
		defer rotationLock.Unlock()
	}
	sess = srv.Jaws.GetSession(hr)
	if sess == nil && !link {
		sess = srv.Jaws.NewSession(hw, hr)
	}
	if sess == nil {
		return flow, nil, failStatus
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if fromWrapper && srv.pendingOrdinaryLoginLocked(sess, 2*time.Minute) {
		// Reissue one pending transaction without replacing the first tab's state.
		flow, _ = sess.Get(srv.sessionKey(oauth2FlowKey)).(pendingOAuthFlow)
		if flow.state == "" {
			status = http.StatusConflict
		}
		return
	}
	flow = pendingOAuthFlow{
		state: rand.Text(), expiry: time.Now().Add(oauth2FlowLifetime),
		link: link, verifier: oauth2.GenerateVerifier(), referrer: location,
	}
	if srv.profileSubject == nil {
		flow.nonce = rand.Text()
	}
	if !sess.ExtendGrace(oauth2FlowGrace) {
		status = failStatus
		return
	}
	srv.clearSessionOAuthFlowLocked(sess)
	sess.Set(srv.sessionKey(oauth2FlowKey), flow)
	return
}

// HandleLogout clears this server's authentication in the session and redirects.
//
// For GET requests it clears auth and responds with a 302 redirect to the
// sanitized referrer (or "/"). LogoutEvent follows [EventFunc]'s ordering rules.
// Non-GET requests receive 405 with Allow: GET.
func (srv *Server) HandleLogout(hw http.ResponseWriter, hr *http.Request) {
	statusCode := http.StatusMethodNotAllowed
	if hr.Method == http.MethodGet {
		location := srv.begin(hr)
		if sess := srv.Jaws.GetSession(hr); sess != nil {
			srv.clearSessionAuth(sess, hr, nil, false)
		}
		hw.Header().Set("Location", location)
		statusCode = http.StatusFound
	} else {
		hw.Header().Set("Allow", http.MethodGet)
	}
	SetHeaders(hw, srv.ishttps)
	hw.WriteHeader(statusCode)
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

func (srv *Server) writeResult(hw http.ResponseWriter, statusCode int, err error) {
	SetHeaders(hw, srv.ishttps)
	hw.WriteHeader(statusCode)
	if err != nil {
		const tmpl = `<html><body><h2>%03d %s</h2><p>%s</p></body></html>`
		_, _ = fmt.Fprintf(hw, tmpl, statusCode, http.StatusText(statusCode), html.EscapeString(err.Error()))
	}
}

// ErrOAuth2NotConfigured means OAuth2/OIDC is not configured on the Server.
var ErrOAuth2NotConfigured = errors.New("oauth2 not configured")

// ErrOAuth2MissingSession means the session or its pending flow is no longer usable.
var ErrOAuth2MissingSession = errors.New("oauth2 missing session")

// ErrOAuth2MissingState means the callback session did not contain the expected state value.
var ErrOAuth2MissingState = errors.New("oauth2 missing state")

// ErrOAuth2WrongState means the callback state value did not match the stored session state.
var ErrOAuth2WrongState = errors.New("oauth2 wrong state")

// ErrOAuth2ExpiredState means the provider returned after the flow lifetime.
var ErrOAuth2ExpiredState = errors.New("oauth2 expired state")

// ErrOAuth2MissingPKCEVerifier means the callback session did not contain the required PKCE verifier.
var ErrOAuth2MissingPKCEVerifier = errors.New("oauth2 missing pkce verifier")

// ErrOAuth2LoginInProgress means a callback has consumed the pending login state.
var ErrOAuth2LoginInProgress = errors.New("oauth2 login already in progress")

// ErrOAuth2InvalidOrigin means a link start request failed the same-origin check.
var ErrOAuth2InvalidOrigin = errors.New("oauth2 invalid origin")

// ErrUserInfoStatus means the UserInfo endpoint returned a non-200 HTTP status.
var ErrUserInfoStatus = errors.New("userinfo status")

// ErrUserInfoTooLarge means the authenticated profile exceeded the response limit.
var ErrUserInfoTooLarge = errors.New("userinfo response too large")

// ErrUserInfoInvalidResponse means the UserInfo response was not one JSON object.
var ErrUserInfoInvalidResponse = errors.New("userinfo invalid response")

// ErrOAuth2InvalidProfile means the profile or access token could not prove a stable subject.
var ErrOAuth2InvalidProfile = errors.New("oauth2 invalid profile")

// ErrOAuth2LinkRejected means the application did not accept a proven link.
var ErrOAuth2LinkRejected = errors.New("oauth2 link rejected")

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
		timeout := boundedProviderClient(client).Timeout
		requestCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		// oauth2.Transport logs from its deprecated CancelRequest; use the request context.
		client.Timeout = 0
		var request *http.Request
		if request, err = http.NewRequestWithContext(requestCtx, http.MethodGet, userinfoURL, nil); err != nil {
			return nil, err
		}
		var resp *http.Response
		if resp, err = client.Do(request); /*#nosec G704*/ err == nil {
			defer func() {
				if closeErr := resp.Body.Close(); err == nil && closeErr != nil {
					err = closeErr
				}
			}()
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("%w %s", ErrUserInfoStatus, resp.Status)
			}
			var body []byte
			if body, err = io.ReadAll(io.LimitReader(resp.Body, maxUserInfoBytes+1)); err == nil {
				if len(body) > maxUserInfoBytes {
					err = ErrUserInfoTooLarge
				} else if !json.Valid(body) {
					err = ErrUserInfoInvalidResponse
				} else {
					decoder := json.NewDecoder(bytes.NewReader(body))
					if srv.profileSubject != nil {
						decoder.UseNumber()
					}
					err = decoder.Decode(&userinfo)
					if err != nil || userinfo == nil {
						userinfo, err = nil, ErrUserInfoInvalidResponse
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
		var raw string
		if token != nil {
			raw, _ = token.Extra("id_token").(string)
		}
		idToken, verifiedClaims, verifyErr := srv.verifyIDToken(ctx, raw)
		if verifyErr != nil {
			return nil, nil, time.Time{}, status, verifyErr
		}
		if nonce == "" {
			return nil, nil, time.Time{}, status, ErrOIDCMissingNonce
		}
		if idToken.Nonce != nonce {
			return nil, nil, time.Time{}, status, ErrOIDCNonceMismatch
		}
		claims = verifiedClaims
		tokenSource = srv.oauth2cfg.TokenSource(srv.oauth2Context(context.Background()), token)
		srv.addUserInfoClaims(ctx, claims, oauth2.StaticTokenSource(token))
		if err = srv.identityExpiryError(idToken.Expiry); err != nil {
			return nil, nil, time.Time{}, status, err
		}
		return claims, tokenSource, idToken.Expiry, 0, nil
	}
	if srv.profileSubject == nil || !profileTokenUnexpired(token) {
		return nil, nil, time.Time{}, status, ErrOAuth2InvalidProfile
	}
	claims, err = srv.fetchUserInfo(ctx, srv.userinfoUrl, oauth2.StaticTokenSource(token))
	if err != nil {
		return nil, nil, time.Time{}, http.StatusBadGateway, err
	}
	// UserInfo can outlive the token; reject it before calling application code.
	if !profileTokenUnexpired(token) {
		return nil, nil, time.Time{}, http.StatusUnauthorized, ErrOAuth2InvalidProfile
	}
	var subject string
	subject, err = srv.profileSubject(claims)
	if srv.Jaws.Log(err) != nil || subject == "" {
		return nil, nil, time.Time{}, status, ErrOAuth2InvalidProfile
	}
	claims["iss"] = srv.issuer
	claims["sub"] = subject
	expiry = time.Now().Add(profileAuthLifetime)
	if !token.Expiry.IsZero() && token.Expiry.Before(expiry) {
		expiry = token.Expiry
	}
	if err = srv.identityExpiryError(expiry); err != nil {
		return nil, nil, time.Time{}, status, err
	}
	return claims, nil, expiry, 0, nil
}

func profileTokenUnexpired(token *oauth2.Token) bool {
	if token == nil || token.AccessToken == "" {
		return false
	}
	if token.Expiry.IsZero() {
		// oauth2 uses zero Expiry for both omitted and explicit zero expires_in.
		switch expiresIn := token.Extra("expires_in").(type) {
		case nil:
			return true
		case string:
			return expiresIn == "" // omitted in a form-encoded token response
		}
		return false
	}
	return token.Expiry.After(time.Now())
}

func (srv *Server) rotateOAuthSession(hw http.ResponseWriter, hr *http.Request, old *jaws.Session, flow pendingOAuthFlow) (rotated *jaws.Session, hadTimer, stale bool) {
	rotationLock := srv.SessionRotationLock
	if rotationLock != nil {
		rotationLock.Lock()
		defer rotationLock.Unlock()
	}
	if flow.revoked() || srv.Jaws.GetSession(hr) != old {
		return nil, false, true
	}
	if rotated = srv.Jaws.NewSession(hw, hr); rotated != nil {
		srv.mu.Lock()
		hadTimer = srv.authTimers[old.ID()] != nil
		srv.stopSessionAuthTimerLocked(old, nil)
		srv.mu.Unlock()
	}
	return
}

func (srv *Server) completeLink(sess *jaws.Session, hr *http.Request, claims map[string]any, expiry time.Time, flow pendingOAuthFlow) (status int, err error) {
	rotationLock := srv.SessionRotationLock
	if rotationLock != nil {
		rotationLock.Lock()
		defer rotationLock.Unlock()
	}
	if flow.revoked() || srv.Jaws.GetSession(hr) != sess {
		return http.StatusForbidden, ErrOAuth2MissingSession
	}
	if err = srv.identityExpiryError(expiry); err != nil {
		return http.StatusUnauthorized, err
	}
	status, err = srv.LinkEvent(sess, hr, claims)
	if srv.Jaws.Log(err) != nil || status != 0 {
		if status < 400 || status > 599 {
			status = http.StatusForbidden
		}
		return status, ErrOAuth2LinkRejected
	}
	return http.StatusFound, nil
}

func (srv *Server) completeLogin(hw http.ResponseWriter, hr *http.Request, old *jaws.Session, flow pendingOAuthFlow, claims map[string]any, tokenSource oauth2.TokenSource, expiry time.Time) (sess *jaws.Session, status int, err error) {
	sess, status, err = old, http.StatusServiceUnavailable, ErrOAuth2MissingSession
	rotated, hadTimer, stale := srv.rotateOAuthSession(hw, hr, old, flow)
	if rotated == nil {
		if stale {
			status = http.StatusForbidden
		} else {
			hw.Header().Set("Retry-After", "60")
		}
		return
	}
	if hadTimer && srv.LogoutEvent != nil {
		srv.LogoutEvent(old, hr)
	}
	sess = rotated
	err = srv.storeSessionAuthClaimsIfActive(sess, claims, tokenSource, expiry, nil, flow.canceled)
	if err != nil {
		http.SetCookie(hw, rotated.Close())
		if errors.Is(err, ErrOAuth2MissingSession) {
			status = http.StatusForbidden
		} else {
			status = http.StatusUnauthorized
		}
		return
	}
	return sess, http.StatusFound, nil
}

func (srv *Server) completeOAuthCallback(ctx context.Context, hw http.ResponseWriter, hr *http.Request, sess *jaws.Session, flow pendingOAuthFlow) (*jaws.Session, int, error) {
	status, err := oauth2CallbackError(http.StatusBadRequest, hr)
	if err != nil {
		return sess, status, err
	}
	if flow.verifier == "" {
		return sess, http.StatusBadRequest, ErrOAuth2MissingPKCEVerifier
	}
	token, err := srv.oauth2cfg.Exchange(ctx, hr.FormValue("code") /* #nosec G120 */, oauth2.VerifierOption(flow.verifier))
	if srv.Jaws.Log(err) != nil {
		status := http.StatusBadGateway
		var retrieveErr *oauth2.RetrieveError
		if errors.As(err, &retrieveErr) && retrieveErr.Response != nil &&
			retrieveErr.Response.StatusCode == http.StatusBadRequest {
			status = http.StatusBadRequest
		}
		return sess, status, err
	}
	claims, tokenSource, expiry, status, err := srv.verifyOAuthIdentity(ctx, token, flow.nonce)
	if err != nil {
		return sess, status, err
	}
	if flow.link {
		status, err = srv.completeLink(sess, hr, claims, expiry, flow)
	} else {
		sess, status, err = srv.completeLogin(hw, hr, sess, flow, claims, tokenSource, expiry)
	}
	return sess, status, err
}

// HandleAuthResponse handles the OIDC or OAuth2 profile callback endpoint.
//
// For GET requests it validates the state, exchanges the authorization code using the
// stored PKCE verifier, verifies the ID token or authenticated profile, and stores
// claims in a new session. A link flow instead invokes [Server.LinkEvent]
// and keeps the original session. It invokes [Server.LoginEvent] after a
// new sign-in or [Server.LoginFailed] on login or link failure. Non-GET requests receive 405.
//
// Rotation discards pre-login application data and requires a free JaWS session slot.
// If no slot is available, existing authentication is preserved and the default
// response is 503. The user must restart login after capacity becomes available.
func (srv *Server) HandleAuthResponse(hw http.ResponseWriter, hr *http.Request) {
	if hr.Method != http.MethodGet {
		hw.Header().Set("Allow", http.MethodGet)
		srv.writeResult(hw, http.StatusMethodNotAllowed, ErrOAuth2Callback)
		return
	}
	providerCtx, cancel := context.WithTimeout(hr.Context(), oauth2ProviderTimeout)
	defer cancel()
	authctx := srv.oauth2Context(providerCtx)
	sess := srv.Jaws.GetSession(hr)
	var sessEmail string
	if sess != nil {
		sessEmail, _ = sess.Get(srv.SessionEmailKey).(string)
	}
	statusCode, err := http.StatusInternalServerError, ErrOAuth2NotConfigured
	var flow pendingOAuthFlow
	if srv.oauth2cfg != nil {
		statusCode, err = http.StatusBadRequest, ErrOAuth2MissingSession
		if sess != nil {
			flow, err = srv.takeOAuthFlow(sess, hr.FormValue("state") /* #nosec G120 */)
			if err == nil {
				defer srv.finishOAuthFlow(sess, flow)
				sess, statusCode, err = srv.completeOAuthCallback(authctx, hw, hr, sess, flow)
				if err == nil && !flow.link {
					sessEmail, _ = sess.Get(srv.SessionEmailKey).(string)
				}
			}
		}
	}
	if err == nil && !flow.link {
		srv.emitLoginEvent(sess, hr)
		current, _ := srv.sessionAuthStatus(sess, time.Now)
		if flow.revoked() || !current || !sessionAlive(sess) {
			srv.clearSessionAuth(sess, hr, nil, false)
			http.SetCookie(hw, sess.Close())
			err = ErrOAuth2MissingSession
			statusCode = http.StatusForbidden
		}
	}
	if err == nil {
		hw.Header().Set("Location", flow.referrer)
	}
	if err != nil && srv.LoginFailed != nil {
		if srv.LoginFailed(hw, hr, statusCode, err, sessEmail) {
			return
		}
	}
	srv.writeResult(hw, statusCode, err)
}
