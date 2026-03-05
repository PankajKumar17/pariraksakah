// Package auth implements a custom OIDC/OAuth2 identity provider with
// FIDO2/WebAuthn support, short-lived JWTs (Ed25519-signed), and
// risk-based continuous re-authentication.
package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

// ──────────────────────────────────────────────
// Configuration
// ──────────────────────────────────────────────

const (
	AccessTokenTTL   = 15 * time.Minute
	RefreshTokenTTL  = 24 * time.Hour
	ReAuthInterval   = 4 * time.Hour
	StepUpRiskThresh = 0.7
)

// ──────────────────────────────────────────────
// Session & Token models
// ──────────────────────────────────────────────

// Session represents an active user session stored in Redis.
type Session struct {
	UserID        string    `json:"user_id"`
	SessionID     string    `json:"session_id"`
	CreatedAt     time.Time `json:"created_at"`
	LastAuthAt    time.Time `json:"last_auth_at"`
	RiskScore     float64   `json:"risk_score"`
	MFAVerified   bool      `json:"mfa_verified"`
	WebAuthnCred  string    `json:"webauthn_cred,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// Claims used in JWT tokens.
type Claims struct {
	jwt.RegisteredClaims
	UserID    string  `json:"uid"`
	SessionID string  `json:"sid"`
	RiskScore float64 `json:"risk,omitempty"`
	Scope     string  `json:"scope,omitempty"`
}

// AuthCodeEntry stores an in-flight authorization code + PKCE verifier.
type AuthCodeEntry struct {
	Code            string
	UserID          string
	CodeChallenge   string
	ChallengeMethod string
	RedirectURI     string
	ExpiresAt       time.Time
}

// ──────────────────────────────────────────────
// OIDC Provider
// ──────────────────────────────────────────────

// OIDCProvider implements Authorization Code Flow with PKCE,
// FIDO2/WebAuthn passwordless, and continuous re-auth.
type OIDCProvider struct {
	mu         sync.RWMutex
	privKey    ed25519.PrivateKey
	pubKey     ed25519.PublicKey
	rdb        *redis.Client
	authCodes  map[string]*AuthCodeEntry // in-memory for dev; use Redis in prod
	issuer     string
}

// NewOIDCProvider creates a new provider, generating Ed25519 signing keys.
func NewOIDCProvider(redisClient *redis.Client, issuer string) (*OIDCProvider, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keygen: %w", err)
	}
	return &OIDCProvider{
		privKey:   priv,
		pubKey:    pub,
		rdb:       redisClient,
		authCodes: make(map[string]*AuthCodeEntry),
		issuer:    issuer,
	}, nil
}

// ── JWT helpers ────────────────────────────────

// IssueAccessToken returns a short-lived JWT.
func (p *OIDCProvider) IssueAccessToken(userID, sessionID string, riskScore float64) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(AccessTokenTTL)),
			ID:        generateID(),
		},
		UserID:    userID,
		SessionID: sessionID,
		RiskScore: riskScore,
		Scope:     "openid profile email",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(p.privKey)
}

// IssueRefreshToken returns a 24-hour refresh token.
func (p *OIDCProvider) IssueRefreshToken(userID, sessionID string) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(RefreshTokenTTL)),
			ID:        generateID(),
		},
		UserID:    userID,
		SessionID: sessionID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(p.privKey)
}

// VerifyToken validates a JWT and returns claims.
func (p *OIDCProvider) VerifyToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return p.pubKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

// ── Session management (Redis) ─────────────────

func (p *OIDCProvider) storeSession(ctx context.Context, s *Session) error {
	data, _ := json.Marshal(s)
	return p.rdb.Set(ctx, "session:"+s.SessionID, data, RefreshTokenTTL).Err()
}

func (p *OIDCProvider) getSession(ctx context.Context, sid string) (*Session, error) {
	raw, err := p.rdb.Get(ctx, "session:"+sid).Bytes()
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// NeedsReAuth returns true if session is older than ReAuthInterval.
func (p *OIDCProvider) NeedsReAuth(s *Session) bool {
	return time.Since(s.LastAuthAt) > ReAuthInterval
}

// NeedsStepUp returns true if current risk score exceeds threshold.
func (p *OIDCProvider) NeedsStepUp(s *Session) bool {
	return s.RiskScore > StepUpRiskThresh
}

// ── PKCE Authorization Code Flow ───────────────

// StartAuthCodeFlow initiates an auth code flow with PKCE.
func (p *OIDCProvider) StartAuthCodeFlow(userID, codeChallenge, challengeMethod, redirectURI string) string {
	code := generateID()
	p.mu.Lock()
	p.authCodes[code] = &AuthCodeEntry{
		Code:            code,
		UserID:          userID,
		CodeChallenge:   codeChallenge,
		ChallengeMethod: challengeMethod,
		RedirectURI:     redirectURI,
		ExpiresAt:       time.Now().Add(10 * time.Minute),
	}
	p.mu.Unlock()
	return code
}

// ExchangeCode exchanges an authorization code for tokens.
func (p *OIDCProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (accessToken, refreshToken string, err error) {
	p.mu.Lock()
	entry, ok := p.authCodes[code]
	if ok {
		delete(p.authCodes, code)
	}
	p.mu.Unlock()

	if !ok || time.Now().After(entry.ExpiresAt) {
		return "", "", fmt.Errorf("invalid or expired auth code")
	}

	// Verify PKCE
	if !verifyPKCE(codeVerifier, entry.CodeChallenge, entry.ChallengeMethod) {
		return "", "", fmt.Errorf("PKCE verification failed")
	}

	sessionID := generateID()
	sess := &Session{
		UserID:    entry.UserID,
		SessionID: sessionID,
		CreatedAt: time.Now(),
		LastAuthAt: time.Now(),
		ExpiresAt: time.Now().Add(RefreshTokenTTL),
	}
	if err := p.storeSession(ctx, sess); err != nil {
		return "", "", fmt.Errorf("session store: %w", err)
	}

	at, err := p.IssueAccessToken(entry.UserID, sessionID, 0)
	if err != nil {
		return "", "", err
	}
	rt, err := p.IssueRefreshToken(entry.UserID, sessionID)
	if err != nil {
		return "", "", err
	}
	return at, rt, nil
}

// ── HTTP Handlers ──────────────────────────────

// RegisterRoutes mounts OIDC endpoints on a Chi router.
func (p *OIDCProvider) RegisterRoutes(r chi.Router) {
	r.Post("/auth/authorize", p.handleAuthorize)
	r.Post("/auth/token", p.handleTokenExchange)
	r.Post("/auth/refresh", p.handleRefresh)
	r.Get("/auth/.well-known/openid-configuration", p.handleDiscovery)
	r.Get("/auth/jwks", p.handleJWKS)
}

func (p *OIDCProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	userID := r.FormValue("user_id")
	challenge := r.FormValue("code_challenge")
	method := r.FormValue("code_challenge_method")
	redirect := r.FormValue("redirect_uri")

	if userID == "" || challenge == "" {
		http.Error(w, "missing params", http.StatusBadRequest)
		return
	}

	code := p.StartAuthCodeFlow(userID, challenge, method, redirect)
	json.NewEncoder(w).Encode(map[string]string{"code": code, "redirect_uri": redirect})
}

func (p *OIDCProvider) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	verifier := r.FormValue("code_verifier")

	at, rt, err := p.ExchangeCode(r.Context(), code, verifier)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  at,
		"refresh_token": rt,
		"token_type":    "Bearer",
		"expires_in":    fmt.Sprintf("%d", int(AccessTokenTTL.Seconds())),
	})
}

func (p *OIDCProvider) handleRefresh(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.FormValue("refresh_token")
	claims, err := p.VerifyToken(refreshToken)
	if err != nil {
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}

	sess, err := p.getSession(r.Context(), claims.SessionID)
	if err != nil {
		http.Error(w, "session not found", http.StatusUnauthorized)
		return
	}

	// Continuous re-auth check
	if p.NeedsReAuth(sess) {
		http.Error(w, "re-authentication required", http.StatusForbidden)
		return
	}

	at, err := p.IssueAccessToken(claims.UserID, claims.SessionID, sess.RiskScore)
	if err != nil {
		http.Error(w, "token issue failed", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"access_token": at,
		"token_type":   "Bearer",
		"expires_in":   fmt.Sprintf("%d", int(AccessTokenTTL.Seconds())),
	})
}

func (p *OIDCProvider) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"issuer":                 p.issuer,
		"authorization_endpoint": p.issuer + "/auth/authorize",
		"token_endpoint":         p.issuer + "/auth/token",
		"jwks_uri":               p.issuer + "/auth/jwks",
	})
}

func (p *OIDCProvider) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	pubB64 := base64.RawURLEncoding.EncodeToString(p.pubKey)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"keys": []map[string]string{
			{"kty": "OKP", "crv": "Ed25519", "x": pubB64, "use": "sig"},
		},
	})
}

// ── Helpers ────────────────────────────────────

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func verifyPKCE(verifier, challenge, method string) bool {
	if method == "S256" {
		h := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		return computed == challenge
	}
	// plain
	return verifier == challenge
}
