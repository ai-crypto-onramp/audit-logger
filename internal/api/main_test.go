package api

import (
	"os"
	"testing"
)

const testSecret = "audit-test-secret"

// TestMain sets a shared SERVICE_TOKEN_SECRET and AUDIT_ADMIN_SERVICES so the
// auth.JWT middleware enforces signed-token auth in tests. do() mints tokens
// with sub "audit-admin" (admin) or "audit-reader-svc" (reader).
func TestMain(m *testing.M) {
	os.Setenv("SERVICE_TOKEN_SECRET", testSecret)
	os.Setenv("AUDIT_ADMIN_SERVICES", "audit-admin")
	os.Exit(m.Run())
}