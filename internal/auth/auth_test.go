package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireReader(t *testing.T) {
	h := Require(RoleReader)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Reader allowed.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = WithRolesContext(req, RoleSet{RoleReader: true})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("reader allowed: %d", rec.Code)
	}

	// Admin implies reader.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req = WithRolesContext(req, RoleSet{RoleAdmin: true})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("admin implies reader: %d", rec.Code)
	}

	// No role forbidden.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("no role: %d", rec.Code)
	}

	// Wrong role forbidden.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req = WithRolesContext(req, RoleSet{Role("other"): true})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("wrong role: %d", rec.Code)
	}
}

func TestRequireAdmin(t *testing.T) {
	h := Require(RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// Reader cannot access admin.
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req = WithRolesContext(req, RoleSet{RoleReader: true})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("reader forbidden on admin: %d", rec.Code)
	}
	// Admin allowed.
	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req = WithRolesContext(req, RoleSet{RoleAdmin: true, RoleReader: true})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("admin allowed: %d", rec.Code)
	}
}

func TestIssueAndVerify(t *testing.T) {
	const secret = "s3cret"
	tok, err := Issue("audit-admin", secret)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	claims, err := verify(tok, secret)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Sub != "audit-admin" {
		t.Errorf("sub: %s", claims.Sub)
	}
}