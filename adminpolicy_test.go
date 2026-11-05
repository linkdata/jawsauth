package jawsauth

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestAdminEmailPolicy(t *testing.T) {
	for _, tc := range []struct {
		name             string
		claims           map[string]any
		listed, verified bool
	}{
		{"verified", map[string]any{"email": "Admin@Example.COM", "email_verified": true}, true, true},
		{"unverified", map[string]any{"email": "admin@example.com", "email_verified": false}, true, false},
		{"entra", map[string]any{"email": "admin@example.com"}, true, false},
		{"mail", map[string]any{"mail": "admin@example.com", "email_verified": true}, true, false},
		{"publicEmail", map[string]any{"email": "invalid", "public_email": "admin@example.com", "email_verified": true}, true, false},
		{"unicode", map[string]any{"email": "Kate@example.com", "email_verified": true}, false, true},
		{"unicodeListed", map[string]any{"email": "ÅSA@example.com", "email_verified": true}, true, true},
		{"unicodeDifferentCase", map[string]any{"email": "åsa@example.com", "email_verified": true}, false, true},
		{"quotedLocalPart", map[string]any{"email": `"\"quoted\""@example.com`, "email_verified": true}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jw := newTestJaws(t)
			srv := newTimerTestServer(t, jw, "https://issuer.example", &testAuthTimerFactory{})
			srv.SetAdmins([]string{"admin@example.com", "kate@example.com", "Åsa@example.com", `"\"quoted\""@example.com`})
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			sess := jw.NewSession(httptest.NewRecorder(), req)
			if err := srv.storeSessionAuthClaims(sess, tc.claims, nil, time.Now().Add(time.Hour), nil); err != nil {
				t.Fatal(err)
			}
			auth := &JawsAuth{server: srv, sess: sess}
			if auth.EmailVerified() != tc.verified {
				t.Fatal("incorrect verification provenance")
			}
			for _, strict := range []bool{false, true} {
				srv.RequireVerifiedAdminEmail = strict
				want := tc.listed && (!strict || tc.verified)
				if auth.IsAdmin() != want {
					t.Fatalf("strict=%v: template admin=%v", strict, auth.IsAdmin())
				}
				rec := httptest.NewRecorder()
				srv.WrapAdmin(testStatusHandler{http.StatusOK}).ServeHTTP(rec, req)
				if (rec.Code == http.StatusOK) != want {
					t.Fatalf("strict=%v: status=%d", strict, rec.Code)
				}
				rec = httptest.NewRecorder()
				srv.Wrap(testStatusHandler{http.StatusOK}).ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatal("ordinary authentication was restricted")
				}
			}
			srv.SetAdmins(nil)
			if !auth.IsAdmin() {
				t.Fatal("empty list should allow authenticated users")
			}
		})
	}
}

func TestProfileAdminRequiresVerifiedEmailByDefault(t *testing.T) {
	for _, tc := range []struct {
		name             string
		verified, optOut bool
		want             int
	}{
		{"default", false, false, http.StatusForbidden},
		{"verified by profile", true, false, http.StatusOK},
		{"explicit opt-out", false, true, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jw := newTestJaws(t)
			srv := newProfileTestServer(t, jw, nil)
			originalSubject := srv.profileSubject
			srv.profileSubject = func(claims map[string]any) (string, error) {
				if tc.verified {
					claims["email_verified"] = true
				}
				return originalSubject(claims)
			}
			if !srv.RequireVerifiedAdminEmail {
				t.Fatal("profile mode did not require verified admin email by default")
			}
			if tc.optOut {
				srv.RequireVerifiedAdminEmail = false
			}
			srv.SetAdmins([]string{"first@example.com"})
			cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
			login := profileCallback(srv, cookie, state, "first")
			cookies := login.Result().Cookies()
			if login.Code != http.StatusFound || len(cookies) != 1 {
				t.Fatalf("profile login: status=%d cookies=%v", login.Code, cookies)
			}
			r := httptest.NewRequest(http.MethodGet, "https://app.example/protected", nil)
			r.AddCookie(cookies[0])
			sess := jw.GetSession(r)
			if sess == nil {
				t.Fatal("missing profile session")
			}
			if sess.Get(srv.SessionEmailVerifiedKey) != tc.verified {
				t.Fatalf("profile verification = %v, want %t", sess.Get(srv.SessionEmailVerifiedKey), tc.verified)
			}
			w := httptest.NewRecorder()
			srv.WrapAdmin(testStatusHandler{http.StatusOK}).ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("profile admin email: status=%d, want %d", w.Code, tc.want)
			}
		})
	}
}

func TestUserInfoClaimProvenance(t *testing.T) {
	for _, tc := range []struct {
		name     string
		id, info map[string]any
		email    string
		verified bool
	}{
		{"matching", map[string]any{"sub": "one"}, map[string]any{"sub": "one", "email": "user@example.com", "email_verified": true}, "user@example.com", true},
		{"differentSubject", map[string]any{"sub": "one"}, map[string]any{"sub": "two", "email": "user@example.com", "email_verified": true}, "", false},
		{"missingSubject", map[string]any{"sub": "one"}, map[string]any{"email": "user@example.com", "email_verified": true}, "", false},
		{"missingIDSubject", map[string]any{}, map[string]any{"sub": "one", "email": "user@example.com", "email_verified": true}, "", false},
		{"sameEmail", map[string]any{"sub": "one", "email": "User@Example.com"}, map[string]any{"sub": "one", "email": "User@Example.com", "email_verified": true}, "User@Example.com", true},
		{"differentLocalCase", map[string]any{"sub": "one", "email": "User@example.com"}, map[string]any{"sub": "one", "email": "user@example.com", "email_verified": true}, "User@example.com", false},
		{"differentDomainCase", map[string]any{"sub": "one", "email": "user@Example.com"}, map[string]any{"sub": "one", "email": "user@example.com", "email_verified": true}, "user@Example.com", false},
		{"differentFormatting", map[string]any{"sub": "one", "email": "User <user@example.com>"}, map[string]any{"sub": "one", "email": "user@example.com", "email_verified": true}, "User <user@example.com>", false},
		{"differentWhitespace", map[string]any{"sub": "one", "email": " user@example.com"}, map[string]any{"sub": "one", "email": "user@example.com", "email_verified": true}, " user@example.com", false},
		{"differentEmail", map[string]any{"sub": "one", "email": "id@example.com"}, map[string]any{"sub": "one", "email": "info@example.com", "email_verified": true}, "id@example.com", false},
		{"unpairedFlag", map[string]any{"sub": "one", "email_verified": true}, map[string]any{"sub": "one", "email": "info@example.com"}, "info@example.com", false},
		{"IDWins", map[string]any{"sub": "one", "email": "id@example.com", "email_verified": true}, map[string]any{"sub": "one", "email": "info@example.com", "email_verified": false}, "id@example.com", true},
		{"IDUnverified", map[string]any{"sub": "one", "email": "user@example.com", "email_verified": false}, map[string]any{"sub": "one", "email": "user@example.com", "email_verified": true}, "user@example.com", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mergeUserInfoClaims(tc.id, tc.info)
			email, _ := tc.id["email"].(string)
			if email != tc.email || extractEmailVerified(tc.id) != tc.verified {
				t.Fatalf("unexpected merged claims: %v", tc.id)
			}
		})
	}
}

func TestAdminEmailPolicyConcurrentUpdates(t *testing.T) {
	// Exercise real concurrent updates and reads without forcing an interleaving.
	jw := newTestJaws(t)
	srv, err := New(jw, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv.RequireVerifiedAdminEmail = true
	srv.SetAdmins([]string{"admin@example.com"})
	sess := jw.NewSession(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	defer srv.Logout(sess, nil)
	auth := &JawsAuth{server: srv, sess: sess}
	expiry := time.Now().Add(time.Hour)
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Go(func() {
		<-start
		for range 1000 {
			for _, state := range []struct {
				email    string
				verified bool
			}{{"user@example.com", true}, {"admin@example.com", false}} {
				claims := map[string]any{"sub": "user", "email": state.email, "email_verified": state.verified}
				if err := srv.storeSessionAuthClaims(sess, claims, nil, expiry, nil); err != nil {
					t.Error(err)
					return
				}
			}
		}
	})
	workers.Go(func() {
		<-start
		for range 1000 {
			if auth.IsAdmin() {
				t.Error("admin check combined email and verification from different updates")
				return
			}
		}
	})
	close(start)
	workers.Wait()
}
