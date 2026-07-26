// Package auth implements the authentication / authorization middleware for
// the REST API. The service-token JWT middleware validates the shared
// HS256 SERVICE_TOKEN_SECRET and derives the principal's roles from the
// token's `sub` claim against the AUDIT_ADMIN_SERVICES allowlist
// (audit-admin implies audit-reader). Health/readiness/metrics bypass auth.
//
// Two roles are recognized:
//   - audit-reader: required for read endpoints (GET /v1/events*).
//   - audit-admin: required for admin endpoints (POST /v1/admin/*,
//     POST /v1/exports). audit-admin implies audit-reader.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Role is a principal role.
type Role string

const (
	RoleReader Role = "audit-reader"
	RoleAdmin  Role = "audit-admin"
	RoleSystem Role = "audit-system" // internal service accounts, e.g. Kafka ingest
)

// adminServicesEnv is the env var carrying the comma-separated list of
// service `sub` values granted audit-admin. Defaults to a single entry.
const adminServicesEnv = "AUDIT_ADMIN_SERVICES"

// RolesHeader is retained for source compatibility only; it is no longer
// read by this package (roles are derived from the signed token's `sub`).
const RolesHeader = "X-Audit-Roles"

type rolesKey struct{}

// withRoles stores the principal's roles in the request context.
func withRoles(ctx context.Context, rs RoleSet) context.Context {
	return context.WithValue(ctx, rolesKey{}, rs)
}

// rolesFromContext returns the roles stored by the JWT middleware, or nil.
func rolesFromContext(ctx context.Context) RoleSet {
	if v, ok := ctx.Value(rolesKey{}).(RoleSet); ok {
		return v
	}
	return nil
}

// adminServices returns the configured audit-admin service allowlist.
func adminServices() map[string]bool {
	raw := os.Getenv(adminServicesEnv)
	if raw == "" {
		raw = "audit-admin"
	}
	out := make(map[string]bool)
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out[s] = true
		}
	}
	return out
}

// Require returns middleware that allows the request only if the caller
// holds any of the required roles. Roles are read from the request context
// (populated by the JWT middleware). audit-admin implies audit-reader.
func Require(required ...Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if HasAny(r, required...) {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "forbidden", http.StatusForbidden)
		})
	}
}

// HasAny reports whether the request carries any of the required roles.
// audit-admin implies audit-reader.
func HasAny(r *http.Request, required ...Role) bool {
	granted := Roles(r)
	for _, want := range required {
		if granted.Has(want) {
			return true
		}
		if want == RoleReader && granted.Has(RoleAdmin) {
			return true
		}
	}
	return false
}

// Roles returns the principal's role set, read from the request context
// (populated by the JWT middleware). Returns an empty set when no token
// was validated (the JWT middleware denies such requests first).
func Roles(r *http.Request) RoleSet {
	if rs := rolesFromContext(r.Context()); rs != nil {
		return rs
	}
	return make(RoleSet)
}

// RoleSet is a set of roles.
type RoleSet map[Role]bool

// Has reports whether the set contains role.
func (s RoleSet) Has(role Role) bool { return s[role] }

// authSkipPaths bypass auth.
var authSkipPaths = map[string]bool{
	"/healthz": true,
	"/readyz":  true,
	"/metrics": true,
}

// jwtClaims are the JWT body used for service-to-service auth.
type jwtClaims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// SecretFromEnv returns the shared secret from SERVICE_TOKEN_SECRET. In
// DEV_MODE=1 with an unset secret it returns ("", true) to signal the caller
// to bypass auth. In prod an unset secret is fatal at startup.
func SecretFromEnv() (string, bool) {
	s := os.Getenv("SERVICE_TOKEN_SECRET")
	if s != "" {
		return s, false
	}
	if os.Getenv("DEV_MODE") == "1" {
		log.Printf("warn: SERVICE_TOKEN_SECRET unset and DEV_MODE=1; service-token auth disabled (NOT FOR PRODUCTION)")
		return "", true
	}
	log.Fatal("SERVICE_TOKEN_SECRET not set and DEV_MODE!=1; refusing to start in production mode")
	return "", false
}

// Middleware wraps h with HS256 Bearer-token auth and populates the request
// context with the principal's derived RoleSet. When bypass is true the
// middleware is a no-op (DEV_MODE with no secret configured) and grants
// audit-admin (dev convenience so existing tests keep passing).
func Middleware(secret string, bypass bool) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if bypass || authSkipPaths[r.URL.Path] {
				rs := RoleSet{RoleAdmin: true, RoleReader: true}
				h.ServeHTTP(w, r.WithContext(withRoles(r.Context(), rs)))
				return
			}
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				writeUnauthorized(w, "missing or malformed Authorization header")
				return
			}
			token := strings.TrimPrefix(auth, "Bearer ")
			claims, err := verify(token, secret)
			if err != nil {
				writeUnauthorized(w, err.Error())
				return
			}
			if time.Now().Unix() > claims.Exp {
				writeUnauthorized(w, "token expired")
				return
			}
			rs := RoleSet{RoleReader: true}
			if adminServices()[claims.Sub] {
				rs[RoleAdmin] = true
			}
			h.ServeHTTP(w, r.WithContext(withRoles(r.Context(), rs)))
		})
	}
}

func verify(token, secret string) (*jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := encode(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return nil, errors.New("invalid signature")
	}
	body, err := decode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var c jwtClaims
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	return &c, nil
}

func encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func writeUnauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": "unauthorized", "message": msg},
	})
}

// Issue mints a 24h HS256 JWT for the named service. Used by internal callers
// when invoking the audit REST API and by tests.
func Issue(serviceName, secret string) (string, error) {
	if secret == "" {
		return "", errors.New("auth: secret is required to issue a token")
	}
	now := time.Now().UTC()
	claims := jwtClaims{
		Sub: serviceName,
		Iat: now.Unix(),
		Exp: now.Add(24 * time.Hour).Unix(),
	}
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	head := encode(hb)
	body := encode(cb)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(head + "." + body))
	sig := encode(mac.Sum(nil))
	return head + "." + body + "." + sig, nil
}

// WithRolesContext is a test helper that stores the given roles in the
// request context so Require/HasAny enforce them as if a valid token had
// been validated. Production code should use Middleware instead.
func WithRolesContext(r *http.Request, rs RoleSet) *http.Request {
	return r.WithContext(withRoles(r.Context(), rs))
}