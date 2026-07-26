package app

import (
	"os"
	"testing"
)

// TestMain sets DEV_MODE=1 so the auth.JWT middleware bypasses auth (granting
// audit-admin) when no SERVICE_TOKEN_SECRET is configured. The api package
// tests exercise the signed-token path with a real secret.
func TestMain(m *testing.M) {
	if os.Getenv("DEV_MODE") == "" {
		os.Setenv("DEV_MODE", "1")
	}
	os.Exit(m.Run())
}