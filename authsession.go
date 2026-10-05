package jawsauth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

const authRefreshSkew = 10 * time.Second

var errOIDCStaleIDToken = errors.New("oidc stale id_token")
var errAuthTimerStale = errors.New("auth timer stale")
var errOIDCInvalidExpiry = errors.New("oidc invalid exp")

type authTimer interface {
	Stop() bool
}

type authTimerAfterFunc func(time.Duration, func()) authTimer

type authTimerState struct {
	timer  authTimer
	expiry time.Time
}

func authTimerEntryExpiry(entry *authTimerState) (expiry time.Time) {
	if entry != nil {
		expiry = entry.expiry
	}
	return
}

// debugSessionPrefix returns a short cookie prefix for log correlation.
func debugSessionPrefix(sess *jaws.Session) string {
	value := sess.CookieValue()
	// Keep at least eight base-32 characters out of logs.
	if len(value) >= 12 {
		return value[:4]
	}
	return ""
}

func tokenDebugAttrs(token *oauth2.Token) []any {
	attrs := []any{"token_nil", token == nil}
	if token != nil {
		rawIDToken, _ := token.Extra("id_token").(string)
		attrs = append(attrs,
			"access_token_present", token.AccessToken != "",
			"refresh_token_present", token.RefreshToken != "",
			"token_expiry", token.Expiry,
			"token_valid", token.Valid(),
			"id_token_present", rawIDToken != "",
			"id_token_len", len(rawIDToken),
		)
	}
	return attrs
}

func realAuthTimerAfterFunc(delay time.Duration, callback func()) authTimer {
	return time.AfterFunc(delay, callback)
}

func (srv *Server) oauth2Context(ctx context.Context) (authctx context.Context) {
	authctx = ctx
	if srv != nil {
		client, ok := authctx.Value(oauth2.HTTPClient).(*http.Client)
		if !ok {
			client = srv.httpClient
		}
		if logger := srv.debugLogger(); logger != nil {
			authctx = context.WithValue(authctx, oauth2.HTTPClient, srv.debugHTTPClient(client, logger))
		} else if !ok && client != nil {
			authctx = context.WithValue(authctx, oauth2.HTTPClient, client)
		}
	}
	return
}

func (srv *Server) sessionAuthStatus(sess *jaws.Session, now func() time.Time) (current, present bool) {
	if srv != nil && sess != nil {
		expiryValue := sess.Get(oauth2IDTokenExpiryKey)
		authValue := sess.Get(srv.SessionKey)
		present = authValue != nil || expiryValue != nil
		if authValue != nil && now != nil {
			if expiry, _ := expiryValue.(time.Time); !expiry.IsZero() {
				current = expiry.After(now())
			}
		}
	}
	return
}

func sessionAlive(sess *jaws.Session) bool {
	cookie := sess.Cookie()
	return cookie != nil && cookie.MaxAge >= 0
}

func (srv *Server) storeSessionAuthClaims(sess *jaws.Session, claims map[string]any, tokenSource oauth2.TokenSource, expiry time.Time, entry *authTimerState) error {
	if srv == nil {
		return ErrOAuth2NotConfigured
	}
	if sess == nil {
		return ErrOAuth2MissingSession
	}
	if expiry.IsZero() {
		return errOIDC{kind: ErrOIDCInvalidIDToken, cause: errOIDCInvalidExpiry}
	}
	email, verified := srv.extractEmail(claims) // Logger callbacks must run outside srv.mu.
	claims["email_verified"] = verified
	srv.mu.Lock()
	if entry != nil && srv.authTimers[sess.ID()] != entry {
		srv.mu.Unlock()
		return errAuthTimerStale
	}
	if !sessionAlive(sess) {
		srv.mu.Unlock()
		if entry == nil {
			return ErrOAuth2MissingSession
		}
		srv.clearSessionAuth(sess, nil, entry)
		return errAuthTimerStale
	}
	sess.Set(srv.SessionKey, claims)
	sess.Set(srv.SessionTokenKey, tokenSource)
	sess.Set(oauth2IDTokenExpiryKey, expiry)
	sess.Set(srv.SessionEmailKey, email)
	sess.Set(srv.SessionEmailVerifiedKey, verified)
	delay, replaced := srv.scheduleSessionAuthTimerLocked(sess, expiry)
	srv.mu.Unlock()
	srv.Jaws.Dirty(sess)
	srv.debugLog("jawsauth: scheduled auth refresh timer",
		"session_prefix", debugSessionPrefix(sess),
		"expiry", expiry,
		"delay", delay,
		"refresh_skew", authRefreshSkew,
		"replaced_existing", replaced,
	)
	return nil
}

func (srv *Server) setSessionAuthFromToken(ctx context.Context, sess *jaws.Session, tokenSource oauth2.TokenSource, token *oauth2.Token, minExpiry time.Time, entry *authTimerState) (err error) {
	err = ErrOAuth2NotConfigured
	if srv != nil && srv.idTokenVerifier != nil {
		err = ErrOIDCMissingIDToken
		if token != nil {
			rawIDToken, _ := token.Extra("id_token").(string)
			if rawIDToken != "" {
				var idToken *oidc.IDToken
				if idToken, err = srv.idTokenVerifier.Verify(ctx, rawIDToken); wrapOIDC(ErrOIDCInvalidIDToken, &err) == nil {
					var claims map[string]any
					if err = idToken.Claims(&claims); wrapOIDC(ErrOIDCInvalidIDToken, &err) == nil {
						if idToken.Expiry.IsZero() {
							err = errOIDC{kind: ErrOIDCInvalidIDToken, cause: errOIDCInvalidExpiry}
						} else if !minExpiry.IsZero() && !idToken.Expiry.After(minExpiry) {
							err = errOIDC{kind: ErrOIDCInvalidIDToken, cause: errOIDCStaleIDToken}
						} else {
							srv.addUserInfoClaims(ctx, claims, tokenSource)
							err = srv.storeSessionAuthClaims(sess, claims, tokenSource, idToken.Expiry, entry)
						}
					}
				}
			}
		}
	}
	return
}

func (srv *Server) refreshSessionAuth(ctx context.Context, sess *jaws.Session, minExpiry time.Time, entry *authTimerState) (err error) {
	sessionPrefix := debugSessionPrefix(sess)
	srv.debugLog("jawsauth: refresh session auth started",
		"session_prefix", sessionPrefix,
		"min_expiry", minExpiry,
		"timer_entry", entry != nil,
		"entry_expiry", authTimerEntryExpiry(entry),
	)
	err = ErrOAuth2NotConfigured
	if srv != nil && sess != nil && srv.oauth2cfg != nil && srv.idTokenVerifier != nil {
		tokenSource, _ := sess.Get(srv.SessionTokenKey).(oauth2.TokenSource)
		err = ErrOIDCMissingIDToken
		if tokenSource != nil {
			authctx := srv.oauth2Context(ctx)
			var token *oauth2.Token
			srv.debugLog("jawsauth: requesting token from stored token source", "session_prefix", sessionPrefix)
			if token, err = tokenSource.Token(); err == nil {
				srv.debugLog("jawsauth: stored token source returned token", append([]any{"session_prefix", sessionPrefix}, tokenDebugAttrs(token)...)...)
				err = srv.setSessionAuthFromToken(authctx, sess, tokenSource, token, minExpiry, entry)
				if err == nil {
					srv.debugLog("jawsauth: stored token refreshed session auth", "session_prefix", sessionPrefix)
				} else {
					srv.debugErrorLog("jawsauth: stored token did not refresh session auth", err, "session_prefix", sessionPrefix)
				}
				if err != nil && token != nil && token.RefreshToken != "" && !errors.Is(err, errAuthTimerStale) {
					srv.debugErrorLog("jawsauth: forcing refresh with refresh token", err, "session_prefix", sessionPrefix)
					tokenSource = srv.oauth2cfg.TokenSource(authctx, &oauth2.Token{
						RefreshToken: token.RefreshToken,
					})
					if token, err = tokenSource.Token(); err == nil {
						srv.debugLog("jawsauth: forced refresh returned token", append([]any{"session_prefix", sessionPrefix}, tokenDebugAttrs(token)...)...)
						err = srv.setSessionAuthFromToken(authctx, sess, tokenSource, token, minExpiry, entry)
						if err == nil {
							srv.debugLog("jawsauth: forced refresh updated session auth", "session_prefix", sessionPrefix)
						} else {
							srv.debugErrorLog("jawsauth: forced refresh did not update session auth", err, "session_prefix", sessionPrefix)
						}
					} else {
						srv.debugErrorLog("jawsauth: forced refresh token source failed", err, "session_prefix", sessionPrefix)
					}
				}
			} else {
				srv.debugErrorLog("jawsauth: stored token source failed", err, "session_prefix", sessionPrefix)
			}
		} else {
			srv.debugLog("jawsauth: refresh session auth missing token source", "session_prefix", sessionPrefix)
		}
	} else {
		srv.debugLog("jawsauth: refresh session auth not configured",
			"session_prefix", sessionPrefix,
			"server_nil", srv == nil,
			"session_nil", sess == nil,
			"oauth2_configured", srv != nil && srv.oauth2cfg != nil,
			"id_token_verifier_configured", srv != nil && srv.idTokenVerifier != nil,
		)
	}
	return
}

// Caller holds srv.mu across the auth writes and timer replacement.
func (srv *Server) scheduleSessionAuthTimerLocked(sess *jaws.Session, expiry time.Time) (delay time.Duration, replaced bool) {
	delay = max(time.Until(expiry.Add(-authRefreshSkew)), 0)
	entry := &authTimerState{expiry: expiry}
	if srv.authTimers == nil {
		srv.authTimers = make(map[uint64]*authTimerState)
	}
	if srv.authTimerAfterFunc == nil {
		srv.authTimerAfterFunc = realAuthTimerAfterFunc
	}
	if old := srv.authTimers[sess.ID()]; old != nil && old.timer != nil {
		replaced = true
		old.timer.Stop()
	}
	srv.authTimers[sess.ID()] = entry
	entry.timer = srv.authTimerAfterFunc(delay, func() {
		srv.handleSessionAuthTimer(sess, entry)
	})
	return
}

func (srv *Server) sessionAuthTimerCurrent(sess *jaws.Session, entry *authTimerState) (current bool) {
	if srv != nil && sess != nil && entry != nil {
		srv.mu.Lock()
		current = srv.authTimers[sess.ID()] == entry
		srv.mu.Unlock()
	}
	return
}

func (srv *Server) stopSessionAuthTimerLocked(sess *jaws.Session, entry *authTimerState) bool {
	old := srv.authTimers[sess.ID()]
	if entry != nil && old != entry {
		return false
	}
	delete(srv.authTimers, sess.ID())
	if old != nil && old.timer != nil {
		old.timer.Stop()
	}
	return true
}

func (srv *Server) handleSessionAuthTimer(sess *jaws.Session, entry *authTimerState) {
	if srv.sessionAuthTimerCurrent(sess, entry) {
		if !sessionAlive(sess) {
			srv.clearSessionAuth(sess, nil, entry)
			return
		}
		current, present := srv.sessionAuthStatus(sess, time.Now)
		srv.debugLog("jawsauth: auth refresh timer fired",
			"session_prefix", debugSessionPrefix(sess),
			"entry_expiry", authTimerEntryExpiry(entry),
			"session_current", current,
			"session_present", present,
		)
		err := srv.refreshSessionAuth(context.Background(), sess, entry.expiry, entry)
		if err != nil {
			if errors.Is(err, errAuthTimerStale) {
				srv.debugErrorLog("jawsauth: auth refresh timer became stale", err, "session_prefix", debugSessionPrefix(sess))
				return
			}
			current, present = srv.sessionAuthStatus(sess, time.Now)
			if current && present {
				retryDelay := max(time.Until(entry.expiry), 0)
				retryScheduled := false
				srv.mu.Lock()
				if srv.authTimers[sess.ID()] == entry {
					if entry.timer != nil {
						entry.timer.Stop()
					}
					entry.timer = srv.authTimerAfterFunc(retryDelay, func() {
						srv.handleSessionAuthTimer(sess, entry)
					})
					retryScheduled = true
				}
				srv.mu.Unlock()
				if retryScheduled {
					srv.debugErrorLog("jawsauth: auth refresh timer failed; keeping current auth", err,
						"session_prefix", debugSessionPrefix(sess),
						"entry_expiry", authTimerEntryExpiry(entry),
						"session_current", current,
						"session_present", present,
						"retry_delay", retryDelay,
					)
					return
				}
			}
			srv.debugErrorLog("jawsauth: auth refresh timer failed; clearing auth", err,
				"session_prefix", debugSessionPrefix(sess),
				"entry_expiry", authTimerEntryExpiry(entry),
				"session_current", current,
				"session_present", present,
			)
			_ = srv.Jaws.Log(err)
			srv.clearSessionAuth(sess, nil, entry)
		} else {
			srv.debugLog("jawsauth: auth refresh timer completed", "session_prefix", debugSessionPrefix(sess))
		}
	} else if sess != nil {
		srv.debugLog("jawsauth: stale auth refresh timer ignored",
			"session_prefix", debugSessionPrefix(sess),
			"entry_expiry", authTimerEntryExpiry(entry),
		)
	}
}

func clearSessionOAuthFlow(sess *jaws.Session) {
	sess.Set(oauth2StateKey, nil)
	sess.Set(oauth2PKCEVerifierKey, nil)
	sess.Set(oauth2NonceKey, nil)
	sess.Set(oauth2ReferrerKey, nil)
}

// Logout clears all authentication state for sess.
//
// It stops the auth-refresh timer, clears the OIDC claims, token source, email, expiry
// and any in-flight OAuth flow keys, then cancels live JaWS requests, calls
// [Server.LogoutEvent] (if set), and marks the session dirty. It returns false for a
// nil receiver or nil session, and true otherwise. The hr argument may be nil.
//
// It performs no HTTP redirect. An HTTP handler can build its own post-logout
// response. A JaWS event handler cannot use [jaws.Request.Redirect] after Logout
// cancels its request; use an HTTP logout endpoint instead.
func (srv *Server) Logout(sess *jaws.Session, hr *http.Request) (cleared bool) {
	return srv.clearSessionAuth(sess, hr, nil)
}

func (srv *Server) clearSessionAuth(sess *jaws.Session, hr *http.Request, entry *authTimerState) (cleared bool) {
	if srv == nil || sess == nil {
		return
	}
	srv.mu.Lock()
	cleared = srv.stopSessionAuthTimerLocked(sess, entry)
	var requests []*jaws.Request
	if cleared {
		clearSessionOAuthFlow(sess)
		sess.Set(srv.SessionKey, nil)
		sess.Set(srv.SessionTokenKey, nil)
		sess.Set(oauth2IDTokenExpiryKey, nil)
		sess.Set(srv.SessionEmailKey, nil)
		sess.Set(srv.SessionEmailVerifiedKey, nil)
		requests = sess.Requests()
	}
	srv.mu.Unlock()
	if cleared {
		cancelAuthRequests(requests)
		if srv.LogoutEvent != nil {
			srv.LogoutEvent(sess, hr)
		}
		srv.Jaws.Dirty(sess)
		srv.debugLog("jawsauth: cleared session auth",
			"session_prefix", debugSessionPrefix(sess),
			"request_present", hr != nil,
			"timer_entry", entry != nil,
			"entry_expiry", authTimerEntryExpiry(entry),
		)
	}
	return
}

func cancelAuthRequests(requests []*jaws.Request) {
	// ponytail: JaWS v0.805.0 never reuses Request identities; replace this snapshot
	// cancellation with a Session-level API when JaWS provides one.
	for _, rq := range requests {
		rq.Cancel(nil)
	}
}
