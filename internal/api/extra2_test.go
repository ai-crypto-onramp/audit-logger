package api

import (
	"net/http"
	"testing"

	"github.com/ai-crypto-onramp/audit-logger/internal/auth"
)

func TestGetEventNotFoundByUUID(t *testing.T) {
	// A valid UUID that does not exist in the store exercises the
	// IsNotFound branch of handleGetEvent (returns 404 from store.Get).
	h, _, _ := newRouter(t)
	rec := do(t, h, "GET", "/v1/events/00000000-0000-4000-8000-000000000099", nil, auth.RoleReader)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestVerifyEventNotFoundByUUID(t *testing.T) {
	// A valid UUID absent from the store exercises the IsNotFound branch
	// of handleVerifyEvent.
	h, _, _ := newRouter(t)
	rec := do(t, h, "GET", "/v1/events/00000000-0000-4000-8000-000000000099/verify-chain", nil, auth.RoleReader)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestGetExportNotFoundByUUID(t *testing.T) {
	// A valid UUID absent from the export store exercises the IsNotFound
	// branch of handleGetExport.
	h, _, _ := newRouter(t)
	rec := do(t, h, "GET", "/v1/exports/00000000-0000-4000-8000-000000000099", nil, auth.RoleReader)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestLegalHoldNotFoundByUUID(t *testing.T) {
	// A valid UUID absent from the store exercises the IsNotFound branch
	// of handleLegalHold.
	h, _, _ := newRouter(t)
	rec := do(t, h, "POST", "/v1/admin/legal-hold/00000000-0000-4000-8000-000000000099", []byte(`{"hold":true}`), auth.RoleAdmin)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestVerifyEventPrevSameIDContinue(t *testing.T) {
	// When the preceding-event scan encounters the queried event's own id
	// (it appears in the List window because the filter is To: e.TS
	// inclusive of the event itself), the `cand.ID == id` continue branch
	// is exercised.
	h, _, _ := newRouter(t)
	rec := do(t, h, "GET", "/v1/events/00000000-0000-4000-8000-000000000003/verify-chain", nil, auth.RoleReader)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body.String())
	}
}