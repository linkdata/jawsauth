package jawsauth

import (
	"net/http"
	"net/http/httptest"
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			jw, err := jaws.New()
			if err != nil {
				t.Fatal(err)
			}
			defer jw.Close()
			srv := newTimerTestServer(t, jw, "https://issuer.example", &testAuthTimerFactory{})
			srv.SetAdmins([]string{"admin@example.com", "kate@example.com"})
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
		{"sameEmail", map[string]any{"sub": "one", "email": "User@Example.com"}, map[string]any{"sub": "one", "email": "user@example.com", "email_verified": true}, "User@Example.com", true},
		{"differentEmail", map[string]any{"sub": "one", "email": "id@example.com"}, map[string]any{"sub": "one", "email": "info@example.com", "email_verified": true}, "id@example.com", false},
		{"unpairedFlag", map[string]any{"sub": "one", "email_verified": true}, map[string]any{"sub": "one", "email": "info@example.com"}, "info@example.com", false},
		{"IDWins", map[string]any{"sub": "one", "email": "id@example.com", "email_verified": true}, map[string]any{"sub": "one", "email": "info@example.com", "email_verified": false}, "id@example.com", true},
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
