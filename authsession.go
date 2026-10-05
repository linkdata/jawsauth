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

func (srv *Server) storeSessionAuthClaims(ctx context.Context, sess *jaws.Session, claims map[string]any, tokenSource oauth2.TokenSource, expiry time.Time, entry *authTimerState) (err error) {
	err = ErrOAuth2NotConfigured
	if srv != nil {
		err = ErrOAuth2MissingSession
		if sess != nil {
			err = errOIDC{kind: ErrOIDCInvalidIDToken, cause: errOIDCInvalidExpiry}
			if !expiry.IsZero() {
				if fallback, e := srv.fetchUserInfo(ctx, srv.userinfoUrl, tokenSource); srv.Jaws.Log(e) == nil {
					mergeUserInfoClaims(claims, fallback)
				}
				if entry != nil {
					if !srv.sessionAuthTimerCurrent(sess, entry) {
						err = errAuthTimerStale
						return
					}
				}
				email, verified := srv.extractEmail(claims)
				claims["email_verified"] = verified
				// Publish the email and its verification together for admin checks.
				srv.mu.Lock()
				sess.Set(srv.SessionKey, claims)
				sess.Set(srv.SessionTokenKey, tokenSource)
				sess.Set(oauth2IDTokenExpiryKey, expiry)
				sess.Set(srv.SessionEmailKey, email)
				sess.Set(srv.SessionEmailVerifiedKey, verified)
				srv.mu.Unlock()
				srv.Jaws.Dirty(sess)
				srv.scheduleSessionAuthTimer(sess, expiry)
				err = nil
			}
		}
	}
	return
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
							err = srv.storeSessionAuthClaims(ctx, sess, claims, tokenSource, idToken.Expiry, entry)
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

func (srv *Server) scheduleSessionAuthTimer(sess *jaws.Session, expiry time.Time) {
	if srv != nil && sess != nil && !expiry.IsZero() {
		delay := max(time.Until(expiry.Add(-authRefreshSkew)), 0)
		entry := &authTimerState{expiry: expiry}
		srv.mu.Lock()
		if srv.authTimers == nil {
			srv.authTimers = make(map[uint64]*authTimerState)
		}
		if srv.authTimerAfterFunc == nil {
			srv.authTimerAfterFunc = realAuthTimerAfterFunc
		}
		replaced := false
		if old := srv.authTimers[sess.ID()]; old != nil && old.timer != nil {
			replaced = true
			old.timer.Stop()
		}
		srv.authTimers[sess.ID()] = entry
		entry.timer = srv.authTimerAfterFunc(delay, func() {
			srv.handleSessionAuthTimer(sess, entry)
		})
		srv.mu.Unlock()
		srv.debugLog("jawsauth: scheduled auth refresh timer",
			"session_prefix", debugSessionPrefix(sess),
			"expiry", expiry,
			"delay", delay,
			"refresh_skew", authRefreshSkew,
			"replaced_existing", replaced,
		)
	}
}

func (srv *Server) sessionAuthTimerCurrent(sess *jaws.Session, entry *authTimerState) (current bool) {
	if srv != nil && sess != nil && entry != nil {
		srv.mu.Lock()
		current = srv.authTimers[sess.ID()] == entry
		srv.mu.Unlock()
	}
	return
}

func (srv *Server) stopSessionAuthTimer(sess *jaws.Session, entry *authTimerState) (stopped bool) {
	if srv != nil && sess != nil {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		if entry == nil {
			if old := srv.authTimers[sess.ID()]; old != nil {
				delete(srv.authTimers, sess.ID())
				if old.timer != nil {
					old.timer.Stop()
				}
			}
			stopped = true
		} else if srv.authTimers[sess.ID()] == entry {
			delete(srv.authTimers, sess.ID())
			if entry.timer != nil {
				entry.timer.Stop()
			}
			stopped = true
		}
	}
	return
}

func (srv *Server) handleSessionAuthTimer(sess *jaws.Session, entry *authTimerState) {
	if srv.sessionAuthTimerCurrent(sess, entry) {
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
			srv.clearSessionAuth(sess, nil, true, true, entry)
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

// Logout clears all authentication state for the session and returns true if anything
// was cleared.
//
// It stops the auth-refresh timer, clears the OIDC claims, token source, email, expiry
// and any in-flight OAuth flow keys, calls LogoutEvent (if set), and marks the session
// dirty. It performs no HTTP redirect, so the caller can build its own post-logout
// response (for example an RP-initiated end-session redirect). It is safe to call with
// a nil receiver or nil session.
func (srv *Server) Logout(sess *jaws.Session, hr *http.Request) (cleared bool) {
	return srv.clearSessionAuth(sess, hr, true, false, nil)
}

func (srv *Server) clearSessionAuth(sess *jaws.Session, hr *http.Request, callLogout, reload bool, entry *authTimerState) (cleared bool) {
	if srv != nil && sess != nil {
		if srv.stopSessionAuthTimer(sess, entry) {
			clearSessionOAuthFlow(sess)
			srv.mu.Lock()
			sess.Set(srv.SessionKey, nil)
			sess.Set(srv.SessionTokenKey, nil)
			sess.Set(oauth2IDTokenExpiryKey, nil)
			sess.Set(srv.SessionEmailKey, nil)
			sess.Set(srv.SessionEmailVerifiedKey, nil)
			srv.mu.Unlock()
			if callLogout && srv.LogoutEvent != nil {
				srv.LogoutEvent(sess, hr)
			}
			srv.Jaws.Dirty(sess)
			if reload {
				sess.Reload()
			}
			cleared = true
			srv.debugLog("jawsauth: cleared session auth",
				"session_prefix", debugSessionPrefix(sess),
				"request_present", hr != nil,
				"call_logout", callLogout,
				"reload", reload,
				"timer_entry", entry != nil,
				"entry_expiry", authTimerEntryExpiry(entry),
			)
		}
	}
	return
}
