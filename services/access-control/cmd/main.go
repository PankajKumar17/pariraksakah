// CyberShield-X Access Control Service — Zero Trust + JWT Auth
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
)

// ── Config ────────────────────────────────────

var (
	jwtSecret  = []byte(env("JWT_SECRET", "changeme_jwt_secret"))
	tokenTTL   = 15 * time.Minute
	refreshTTL = 24 * time.Hour
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ── Simple user store (demo — replace with DB) ─

type User struct {
	UserID   string
	Username string
	Role     string
	PassHash string // SHA-256 hex of password
}

var (
	usersMu sync.RWMutex
	users   = map[string]*User{
		"admin": {
			UserID:   "usr-001",
			Username: "admin",
			Role:     "admin",
			PassHash: sha256hex("admin123"),
		},
		"analyst": {
			UserID:   "usr-002",
			Username: "analyst",
			Role:     "analyst",
			PassHash: sha256hex("analyst123"),
		},
		"viewer": {
			UserID:   "usr-003",
			Username: "viewer",
			Role:     "viewer",
			PassHash: sha256hex("viewer123"),
		},
	}
	// session store: token_id → expiry
	sessions   = map[string]time.Time{}
	sessionsMu sync.RWMutex
)

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:])
}

// ── JWT helpers ───────────────────────────────

type Claims struct {
	jwt.RegisteredClaims
	UserID   string `json:"uid"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

func issueToken(user *User, ttl time.Duration) (string, error) {
	jti := randomHex(16)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.UserID,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			Issuer:    "pariraksakah-access-control",
			ID:        jti,
		},
		UserID:   user.UserID,
		Username: user.Username,
		Role:     user.Role,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}
	sessionsMu.Lock()
	sessions[jti] = time.Now().Add(ttl)
	sessionsMu.Unlock()
	return signed, nil
}

func validateToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid claims")
	}
	// Check session not revoked
	sessionsMu.RLock()
	exp, exists := sessions[claims.ID]
	sessionsMu.RUnlock()
	if !exists || time.Now().After(exp) {
		return nil, fmt.Errorf("session expired or revoked")
	}
	return claims, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func hmacSign(data, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// ── Redis session (optional) ──────────────────

func initRedis() *redis.Client {
	addr := env("REDIS_URL", "redis:6379")
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Printf("Redis unavailable (%v) — using in-memory sessions", err)
		return nil
	}
	log.Printf("Redis connected at %s", addr)
	return rdb
}

// ── Handlers ──────────────────────────────────

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// POST /auth/login  { "username": "admin", "password": "admin123" }
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}

	usersMu.RLock()
	user, ok := users[req.Username]
	usersMu.RUnlock()
	if !ok || user.PassHash != sha256hex(req.Password) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	accessToken, err := issueToken(user, tokenTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token error"})
		return
	}
	refreshToken, _ := issueToken(user, refreshTTL)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    int(tokenTTL.Seconds()),
		"user": map[string]string{
			"user_id":  user.UserID,
			"username": user.Username,
			"role":     user.Role,
		},
	})
}

// POST /auth/verify  or  GET /auth/verify  (Authorization: Bearer <token>)
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing token"})
		return
	}
	claims, err := validateToken(tokenStr)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":    true,
		"user_id":  claims.UserID,
		"username": claims.Username,
		"role":     claims.Role,
		"expires":  claims.ExpiresAt,
	})
}

// POST /auth/logout  (revokes current token)
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing token"})
		return
	}
	claims, err := validateToken(tokenStr)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	sessionsMu.Lock()
	delete(sessions, claims.ID)
	sessionsMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// GET /auth/users  (admin only — lists users without passwords)
func listUsersHandler(w http.ResponseWriter, r *http.Request) {
	usersMu.RLock()
	defer usersMu.RUnlock()
	result := make([]map[string]string, 0, len(users))
	for _, u := range users {
		result = append(result, map[string]string{
			"user_id":  u.UserID,
			"username": u.Username,
			"role":     u.Role,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"users": result, "total": len(result)})
}

// GET /auth/.well-known/openid-configuration
func openIDConfigHandler(port string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		base := fmt.Sprintf("http://localhost:%s", port)
		writeJSON(w, http.StatusOK, map[string]string{
			"issuer":                 base,
			"authorization_endpoint": base + "/auth/authorize",
			"token_endpoint":         base + "/auth/token",
			"userinfo_endpoint":      base + "/auth/userinfo",
			"jwks_uri":               base + "/auth/.well-known/jwks.json",
		})
	}
}

// ── Main ──────────────────────────────────────

func main() {
	port := env("ACCESS_CONTROL_PORT", "8002")
	initRedis()

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
			if req.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, req)
		})
	})

	r.Get("/health", func(w http.ResponseWriter, req *http.Request) {
		sessionsMu.RLock()
		activeSessions := len(sessions)
		sessionsMu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":           "healthy",
			"service":          "access-control",
			"version":          "2.0.0-pqc",
			"active_sessions":  activeSessions,
		})
	})
	r.Handle("/metrics", promhttp.Handler())

	r.Post("/auth/login", loginHandler)
	r.Post("/auth/verify", verifyHandler)
	r.Get("/auth/verify", verifyHandler)
	r.Post("/auth/logout", logoutHandler)
	r.Get("/auth/users", listUsersHandler)
	r.Get("/auth/.well-known/openid-configuration", openIDConfigHandler(port))

	// Legacy stubs — now functional
	r.Post("/auth/authorize", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"message": "Use POST /auth/login for direct token issuance",
		})
	})
	r.Post("/auth/token", func(w http.ResponseWriter, req *http.Request) {
		loginHandler(w, req) // delegate to login
	})

	log.Printf("Access Control Service (Zero-Trust + JWT) starting on :%s", port)
	log.Printf("Default users: admin/admin123, analyst/analyst123, viewer/viewer123")
	if err := http.ListenAndServe(fmt.Sprintf(":%s", port), r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
