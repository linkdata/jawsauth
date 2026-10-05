package jawsauth

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/linkdata/jaws"
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
			jw, err := jaws.New()
			if err != nil {
				t.Fatal(err)
			}
			defer jw.Close()
			srv := newTimerTestServer(t, jw, "https://issuer.example", &testAuthTimerFactory{})
			srv.SetAdmins([]string{"admin@example.com", "kate@example.com", "Åsa@example.com", `"\"quoted\""@example.com`})
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			sess := jw.NewSession(httptest.NewRecorder(), req)
			if err = srv.storeSessionAuthClaims(t.Context(), sess, tc.claims, nil, time.Now().Add(time.Hour), nil); err != nil {
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
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
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
				if err := srv.storeSessionAuthClaims(t.Context(), sess, claims, nil, expiry, nil); err != nil {
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
