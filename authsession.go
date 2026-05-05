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

func realAuthTimerAfterFunc(delay time.Duration, callback func()) authTimer {
	return time.AfterFunc(delay, callback)
}

func (srv *Server) oauth2Context(ctx context.Context) (authctx context.Context) {
	authctx = ctx
	if srv != nil && srv.httpClient != nil {
		if _, ok := authctx.Value(oauth2.HTTPClient).(*http.Client); !ok {
			authctx = context.WithValue(authctx, oauth2.HTTPClient, srv.httpClient)
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
					mergeMissingClaims(claims, fallback)
				}
				if entry != nil {
					if !srv.sessionAuthTimerCurrent(sess, entry) {
						err = errAuthTimerStale
						return
					}
				}
				verified := extractEmailVerified(claims)
				claims["email_verified"] = verified
				sess.Set(srv.SessionKey, claims)
				sess.Set(srv.SessionTokenKey, tokenSource)
				sess.Set(oauth2IDTokenExpiryKey, expiry)
				sess.Set(srv.SessionEmailKey, srv.extractEmail(claims))
				sess.Set(srv.SessionEmailVerifiedKey, verified)
				if srv.Jaws != nil {
					srv.Jaws.Dirty(sess)
				}
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
	err = ErrOAuth2NotConfigured
	if srv != nil && sess != nil && srv.oauth2cfg != nil && srv.idTokenVerifier != nil {
		tokenSource, _ := sess.Get(srv.SessionTokenKey).(oauth2.TokenSource)
		err = ErrOIDCMissingIDToken
		if tokenSource != nil {
			authctx := srv.oauth2Context(ctx)
			var token *oauth2.Token
			if token, err = tokenSource.Token(); err == nil {
				err = srv.setSessionAuthFromToken(authctx, sess, tokenSource, token, minExpiry, entry)
				if err != nil && token != nil && token.RefreshToken != "" && !errors.Is(err, errAuthTimerStale) {
					tokenSource = srv.oauth2cfg.TokenSource(authctx, &oauth2.Token{
						RefreshToken: token.RefreshToken,
					})
					if token, err = tokenSource.Token(); err == nil {
						err = srv.setSessionAuthFromToken(authctx, sess, tokenSource, token, minExpiry, entry)
					}
				}
			}
		}
	}
	return
}

func (srv *Server) scheduleSessionAuthTimer(sess *jaws.Session, expiry time.Time) {
	if srv != nil && sess != nil && !expiry.IsZero() {
		delay := max(time.Until(expiry.Add(-authRefreshSkew)), 0)
		entry := &authTimerState{expiry: expiry}
		srv.mu.Lock()
		defer srv.mu.Unlock()
		if srv.authTimers == nil {
			srv.authTimers = make(map[uint64]*authTimerState)
		}
		if srv.authTimerAfterFunc == nil {
			srv.authTimerAfterFunc = realAuthTimerAfterFunc
		}
		if old := srv.authTimers[sess.ID()]; old != nil && old.timer != nil {
			old.timer.Stop()
		}
		srv.authTimers[sess.ID()] = entry
		entry.timer = srv.authTimerAfterFunc(delay, func() {
			srv.handleSessionAuthTimer(sess, entry)
		})
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
		err := srv.refreshSessionAuth(context.Background(), sess, entry.expiry, entry)
		if err != nil {
			if errors.Is(err, errAuthTimerStale) {
				return
			}
			if srv.Jaws != nil {
				_ = srv.Jaws.Log(err)
			}
			srv.clearSessionAuth(sess, nil, true, true, entry)
		}
	}
}

func clearSessionOAuthFlow(sess *jaws.Session) {
	sess.Set(oauth2StateKey, nil)
	sess.Set(oauth2PKCEVerifierKey, nil)
	sess.Set(oauth2NonceKey, nil)
	sess.Set(oauth2ReferrerKey, nil)
}

func (srv *Server) clearSessionAuth(sess *jaws.Session, hr *http.Request, callLogout, reload bool, entry *authTimerState) (cleared bool) {
	if srv != nil && sess != nil {
		if srv.stopSessionAuthTimer(sess, entry) {
			clearSessionOAuthFlow(sess)
			sess.Set(srv.SessionKey, nil)
			sess.Set(srv.SessionTokenKey, nil)
			sess.Set(oauth2IDTokenExpiryKey, nil)
			sess.Set(srv.SessionEmailKey, nil)
			sess.Set(srv.SessionEmailVerifiedKey, nil)
			if callLogout && srv.LogoutEvent != nil {
				srv.LogoutEvent(sess, hr)
			}
			if srv.Jaws != nil {
				srv.Jaws.Dirty(sess)
			}
			if reload {
				sess.Reload()
			}
			cleared = true
		}
	}
	return
}
