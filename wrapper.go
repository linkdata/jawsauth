package jawsauth

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

type wrapper struct {
	server  *Server
	handler http.Handler
	admin   bool
}

func (w wrapper) ServeHTTP(hw http.ResponseWriter, hr *http.Request) {
	h := w.handler
	sess := w.server.Jaws.GetSession(hr)
	if sess == nil {
		sess = w.server.Jaws.NewSession(hw, hr)
	}
	if !w.server.sessionAuthenticated(hr.Context(), sess, hr) {
		w.server.HandleLogin(hw, hr)
		return
	}

	if w.admin {
		email, _ := sess.Get(w.server.SessionEmailKey).(string)
		if !w.server.IsAdmin(email) {
			h = w.server.get403Handler()
		}
	}
	h.ServeHTTP(hw, hr)
}

func (srv *Server) sessionAuthenticated(ctx context.Context, sess *jaws.Session, hr *http.Request) (authenticated bool) {
	if srv != nil && sess != nil {
		sessValue := sess.Get(srv.SessionKey)
		if claims, ok := sessValue.(map[string]any); ok && claims != nil {
			if !oidcClaimsExpired(claims, time.Now()) {
				authenticated = true
				return
			}
			if authenticated = srv.refreshSessionAuth(ctx, sess); authenticated {
				return
			}
			if authenticated = srv.clearExpiredSessionAuth(sess, hr); authenticated {
				return
			}
		} else if sessValue != nil {
			authenticated = srv.clearExpiredSessionAuth(sess, hr)
		}
	}
	return
}

func (srv *Server) refreshSessionAuth(ctx context.Context, sess *jaws.Session) (refreshed bool) {
	if srv != nil && sess != nil && srv.oauth2cfg != nil && srv.idTokenVerifier != nil {
		tokenSource, _ := sess.Get(srv.SessionTokenKey).(oauth2.TokenSource)
		if tokenSource != nil {
			authctx := srv.oauth2Context(ctx)
			var token *oauth2.Token
			var err error
			if token, err = tokenSource.Token(); err == nil {
				err = srv.setSessionAuthFromToken(authctx, sess, tokenSource, token)
				if err != nil && token != nil && token.RefreshToken != "" {
					tokenSource = srv.oauth2cfg.TokenSource(authctx, &oauth2.Token{
						RefreshToken: token.RefreshToken,
					})
					if token, err = tokenSource.Token(); err == nil {
						err = srv.setSessionAuthFromToken(authctx, sess, tokenSource, token)
					}
				}
			}
			if srv.Jaws.Log(err) == nil {
				refreshed = true
			}
		}
	}
	return
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

func (srv *Server) setSessionAuthFromToken(ctx context.Context, sess *jaws.Session, tokenSource oauth2.TokenSource, token *oauth2.Token) (err error) {
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
						if fallback, e := srv.fetchUserInfo(ctx, srv.userinfoUrl, tokenSource); srv.Jaws.Log(e) == nil {
							mergeMissingClaims(claims, fallback)
						}
						verified := extractEmailVerified(claims)
						claims["email_verified"] = verified
						sess.Set(srv.SessionKey, claims)
						sess.Set(srv.SessionTokenKey, tokenSource)
						sess.Set(srv.SessionEmailKey, srv.extractEmail(claims))
						sess.Set(srv.SessionEmailVerifiedKey, verified)
						srv.Jaws.Dirty(sess)
					}
				}
			}
		}
	}
	return
}

func (srv *Server) clearExpiredSessionAuth(sess *jaws.Session, hr *http.Request) (authenticated bool) {
	if srv != nil && sess != nil {
		var callLogout bool
		srv.mu.Lock()
		sessValue := sess.Get(srv.SessionKey)
		if claims, ok := sessValue.(map[string]any); ok && claims != nil {
			if !oidcClaimsExpired(claims, time.Now()) {
				authenticated = true
				srv.mu.Unlock()
				return
			}
		}
		callLogout = sessValue != nil
		sess.Set(srv.SessionKey, nil)
		sess.Set(srv.SessionTokenKey, nil)
		sess.Set(srv.SessionEmailKey, nil)
		sess.Set(srv.SessionEmailVerifiedKey, nil)
		srv.mu.Unlock()
		if callLogout && srv.LogoutEvent != nil {
			srv.LogoutEvent(sess, hr)
		}
		srv.Jaws.Dirty(sess)
	}
	return
}

func oidcClaimsExpired(claims map[string]any, now time.Time) (expired bool) {
	expired = true
	if claims != nil {
		if expiry, ok := oidcClaimExpiry(claims["exp"]); ok {
			expired = expiry.Before(now)
		}
	}
	return
}

func oidcClaimExpiry(value any) (expiry time.Time, ok bool) {
	var seconds int64
	switch v := value.(type) {
	case json.Number:
		seconds, ok = int64FromString(v.String())
	case float64:
		seconds, ok = int64FromFloat(v)
	case float32:
		seconds, ok = int64FromFloat(float64(v))
	case int:
		seconds, ok = int64(v), true
	case int8:
		seconds, ok = int64(v), true
	case int16:
		seconds, ok = int64(v), true
	case int32:
		seconds, ok = int64(v), true
	case int64:
		seconds, ok = v, true
	case uint:
		seconds, ok = int64FromUint(uint64(v))
	case uint8:
		seconds, ok = int64(v), true
	case uint16:
		seconds, ok = int64(v), true
	case uint32:
		seconds, ok = int64(v), true
	case uint64:
		seconds, ok = int64FromUint(v)
	case string:
		seconds, ok = int64FromString(v)
	default:
		ok = false
	}
	if ok {
		expiry = time.Unix(seconds, 0)
	}
	return
}

func int64FromFloat(value float64) (seconds int64, ok bool) {
	if !math.IsNaN(value) && !math.IsInf(value, 0) {
		if value >= math.MinInt64 && value <= math.MaxInt64 {
			seconds = int64(value)
			ok = true
		}
	}
	return
}

func int64FromString(value string) (seconds int64, ok bool) {
	value = strings.TrimSpace(value)
	if value != "" {
		if n, err := strconv.ParseInt(value, 10, 64); err == nil {
			seconds, ok = n, true
		} else if f, err := strconv.ParseFloat(value, 64); err == nil {
			seconds, ok = int64FromFloat(f)
		}
	}
	return
}

func int64FromUint(value uint64) (seconds int64, ok bool) {
	if value <= math.MaxInt64 {
		seconds, ok = int64(value), true
	}
	return
}
