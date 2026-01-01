// Core/security_enhanced.go
// Enhanced Security Module - Argon2id, CSRF, Advanced Rate Limiting
// Production-grade security improvements

package core

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// ====================================================================================
// ARGON2ID PASSWORD HASHING (replaces weak PBKDF2)
// ====================================================================================

const (
	// Argon2id parameters (OWASP recommended)
	Argon2Time      = 2      // Number of iterations
	Argon2Memory    = 64 * 1024 // 64 MB
	Argon2Threads   = 4      // Number of threads
	Argon2KeyLength = 32     // 32 bytes output
	Argon2SaltSize  = 16     // 16 bytes salt
)

// Argon2Params holds parameters for Argon2id
type Argon2Params struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

// DefaultArgon2Params returns OWASP-recommended parameters
func DefaultArgon2Params() *Argon2Params {
	return &Argon2Params{
		Time:    Argon2Time,
		Memory:  Argon2Memory,
		Threads: Argon2Threads,
		KeyLen:  Argon2KeyLength,
		SaltLen: Argon2SaltSize,
	}
}

// HashPasswordArgon2id hashes password using Argon2id
func HashPasswordArgon2id(password string) (string, error) {
	params := DefaultArgon2Params()

	// Generate random salt
	salt := make([]byte, params.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash password
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Time,
		params.Memory,
		params.Threads,
		params.KeyLen,
	)

	// Encode: $argon2id$v=19$m=memory,t=time,p=threads$salt$hash
	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		params.Memory,
		params.Time,
		params.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return encoded, nil
}

// VerifyPasswordArgon2id verifies password against Argon2id hash
func VerifyPasswordArgon2id(password, encodedHash string) (bool, error) {
	// Parse encoded hash
	params, salt, hash, err := decodeArgon2Hash(encodedHash)
	if err != nil {
		return false, err
	}

	// Hash the input password with same parameters
	inputHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Time,
		params.Memory,
		params.Threads,
		params.KeyLen,
	)

	// Constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(hash, inputHash) == 1, nil
}

// decodeArgon2Hash parses encoded Argon2id hash
func decodeArgon2Hash(encoded string) (*Argon2Params, []byte, []byte, error) {
	var version int
	var params Argon2Params
	var saltB64, hashB64 string

	// Parse format: $argon2id$v=19$m=65536,t=2,p=4$salt$hash
	_, err := fmt.Sscanf(
		encoded,
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		&version,
		&params.Memory,
		&params.Time,
		&params.Threads,
		&saltB64,
		&hashB64,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid hash format: %w", err)
	}

	if version != argon2.Version {
		return nil, nil, nil, fmt.Errorf("incompatible argon2 version")
	}

	// Decode salt
	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	// Decode hash
	hash, err := base64.RawStdEncoding.DecodeString(hashB64)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode hash: %w", err)
	}

	params.KeyLen = uint32(len(hash))
	params.SaltLen = uint32(len(salt))

	return &params, salt, hash, nil
}

// ====================================================================================
// CSRF PROTECTION
// ====================================================================================

const (
	CSRFTokenLength = 32
	CSRFTokenTTL    = 24 * time.Hour
)

// CSRFManager manages CSRF tokens
type CSRFManager struct {
	mu     sync.RWMutex
	tokens map[string]*CSRFToken // sessionID -> token
}

// CSRFToken represents a CSRF token
type CSRFToken struct {
	Token     string
	ExpiresAt time.Time
}

// NewCSRFManager creates a new CSRF manager
func NewCSRFManager() *CSRFManager {
	cm := &CSRFManager{
		tokens: make(map[string]*CSRFToken),
	}

	// Start cleanup goroutine
	go cm.cleanup()

	return cm
}

// GenerateToken generates a new CSRF token for session
func (cm *CSRFManager) GenerateToken(sessionID string) (string, error) {
	// Generate random token
	tokenBytes := make([]byte, CSRFTokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate CSRF token: %w", err)
	}

	token := hex.EncodeToString(tokenBytes)

	// Store token
	cm.mu.Lock()
	cm.tokens[sessionID] = &CSRFToken{
		Token:     token,
		ExpiresAt: time.Now().Add(CSRFTokenTTL),
	}
	cm.mu.Unlock()

	return token, nil
}

// ValidateToken validates CSRF token for session
func (cm *CSRFManager) ValidateToken(sessionID, token string) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	csrfToken, exists := cm.tokens[sessionID]
	if !exists {
		return false
	}

	// Check expiration
	if time.Now().After(csrfToken.ExpiresAt) {
		return false
	}

	// Constant-time comparison
	return subtle.ConstantTimeCompare([]byte(csrfToken.Token), []byte(token)) == 1
}

// DeleteToken removes CSRF token for session
func (cm *CSRFManager) DeleteToken(sessionID string) {
	cm.mu.Lock()
	delete(cm.tokens, sessionID)
	cm.mu.Unlock()
}

// cleanup removes expired tokens
func (cm *CSRFManager) cleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		cm.mu.Lock()
		now := time.Now()
		for sessionID, token := range cm.tokens {
			if now.After(token.ExpiresAt) {
				delete(cm.tokens, sessionID)
			}
		}
		cm.mu.Unlock()
	}
}

// ====================================================================================
// DISTRIBUTED RATE LIMITING (Redis-backed)
// ====================================================================================

// SecurityRateLimitRule defines rate limiting rule
type SecurityRateLimitRule struct {
	Name     string
	Limit    int           // Max requests
	Window   time.Duration // Time window
	BanTime  time.Duration // Ban duration on exceed
}

// Common rate limit rules
var (
	RateLimitLogin = &SecurityRateLimitRule{
		Name:    "login",
		Limit:   5,
		Window:  15 * time.Minute,
		BanTime: 1 * time.Hour,
	}

	RateLimitAPI = &SecurityRateLimitRule{
		Name:    "api",
		Limit:   100,
		Window:  1 * time.Minute,
		BanTime: 5 * time.Minute,
	}

	RateLimitRegistration = &SecurityRateLimitRule{
		Name:    "registration",
		Limit:   3,
		Window:  1 * time.Hour,
		BanTime: 24 * time.Hour,
	}
)

// DistributedRateLimiter handles rate limiting with Redis
type DistributedRateLimiter struct {
	// TODO: Add Redis client when Redis integration is added
	// For now, use in-memory (will be replaced)
	mu      sync.RWMutex
	buckets map[string]*rateLimitBucket
}

type rateLimitBucket struct {
	Count      int
	WindowEnd  time.Time
	BannedUntil time.Time
}

// NewDistributedRateLimiter creates a new distributed rate limiter
func NewDistributedRateLimiter() *DistributedRateLimiter {
	rl := &DistributedRateLimiter{
		buckets: make(map[string]*rateLimitBucket),
	}

	// Start cleanup
	go rl.cleanup()

	return rl
}

// CheckLimit checks if request is within rate limit
func (rl *DistributedRateLimiter) CheckLimit(key string, rule *SecurityRateLimitRule) (bool, error) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucketKey := fmt.Sprintf("%s:%s", rule.Name, key)

	bucket, exists := rl.buckets[bucketKey]
	if !exists {
		// First request
		rl.buckets[bucketKey] = &rateLimitBucket{
			Count:     1,
			WindowEnd: now.Add(rule.Window),
		}
		return true, nil
	}

	// Check if banned
	if !bucket.BannedUntil.IsZero() && now.Before(bucket.BannedUntil) {
		return false, fmt.Errorf("rate limit exceeded, banned until %s", bucket.BannedUntil.Format(time.RFC3339))
	}

	// Check if window expired
	if now.After(bucket.WindowEnd) {
		// Reset window
		bucket.Count = 1
		bucket.WindowEnd = now.Add(rule.Window)
		bucket.BannedUntil = time.Time{} // Clear ban
		return true, nil
	}

	// Increment counter
	bucket.Count++

	// Check limit
	if bucket.Count > rule.Limit {
		// Ban the key
		bucket.BannedUntil = now.Add(rule.BanTime)
		LogWarn("SECURITY", "Rate limit exceeded for %s (rule: %s)", key, rule.Name)
		return false, fmt.Errorf("rate limit exceeded")
	}

	return true, nil
}

// ResetLimit resets rate limit for key
func (rl *DistributedRateLimiter) ResetLimit(key string, rule *SecurityRateLimitRule) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucketKey := fmt.Sprintf("%s:%s", rule.Name, key)
	delete(rl.buckets, bucketKey)
}

// cleanup removes expired buckets
func (rl *DistributedRateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, bucket := range rl.buckets {
			// Remove if window expired and not banned
			if now.After(bucket.WindowEnd) && (bucket.BannedUntil.IsZero() || now.After(bucket.BannedUntil)) {
				delete(rl.buckets, key)
			}
		}
		rl.mu.Unlock()
	}
}

// ====================================================================================
// ENHANCED SESSION MANAGEMENT
// ====================================================================================

// SessionManager manages user sessions with enhanced security
type EnhancedSessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*EnhancedSession
}

// EnhancedSession represents a user session
type EnhancedSession struct {
	SessionID      string
	UserID         int64
	IPAddress      string
	UserAgent      string
	DeviceFingerprint string
	CreatedAt      time.Time
	LastActivity   time.Time
	ExpiresAt      time.Time
	CSRFToken      string
}

// NewEnhancedSessionManager creates enhanced session manager
func NewEnhancedSessionManager() *EnhancedSessionManager {
	return &EnhancedSessionManager{
		sessions: make(map[string]*EnhancedSession),
	}
}

// CreateSession creates a new session with device fingerprinting
func (esm *EnhancedSessionManager) CreateSession(userID int64, ip, userAgent, fingerprint string) (*EnhancedSession, error) {
	// Generate session ID
	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		return nil, err
	}
	sessionID := hex.EncodeToString(sessionIDBytes)

	// Generate CSRF token
	csrfBytes := make([]byte, 32)
	if _, err := rand.Read(csrfBytes); err != nil {
		return nil, err
	}
	csrfToken := hex.EncodeToString(csrfBytes)

	session := &EnhancedSession{
		SessionID:         sessionID,
		UserID:            userID,
		IPAddress:         ip,
		UserAgent:         userAgent,
		DeviceFingerprint: fingerprint,
		CreatedAt:         time.Now(),
		LastActivity:      time.Now(),
		ExpiresAt:         time.Now().Add(24 * time.Hour),
		CSRFToken:         csrfToken,
	}

	esm.mu.Lock()
	esm.sessions[sessionID] = session
	esm.mu.Unlock()

	return session, nil
}

// ValidateSession validates session and checks for anomalies
func (esm *EnhancedSessionManager) ValidateSession(sessionID, ip, userAgent string) (*EnhancedSession, error) {
	esm.mu.RLock()
	session, exists := esm.sessions[sessionID]
	esm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	// Check expiration
	if time.Now().After(session.ExpiresAt) {
		esm.DeleteSession(sessionID)
		return nil, fmt.Errorf("session expired")
	}

	// Anomaly detection: IP change
	if session.IPAddress != ip {
		LogWarn("SECURITY", "Session %s: IP changed from %s to %s", sessionID, session.IPAddress, ip)
		// In production, you might want to require re-authentication
	}

	// Anomaly detection: User-Agent change
	if session.UserAgent != userAgent {
		LogWarn("SECURITY", "Session %s: User-Agent changed", sessionID)
	}

	// Update last activity
	esm.mu.Lock()
	session.LastActivity = time.Now()
	esm.mu.Unlock()

	return session, nil
}

// DeleteSession removes a session
func (esm *EnhancedSessionManager) DeleteSession(sessionID string) {
	esm.mu.Lock()
	delete(esm.sessions, sessionID)
	esm.mu.Unlock()
}

// ====================================================================================
// GLOBAL SECURITY MANAGER
// ====================================================================================

var (
	GlobalCSRFManager      *CSRFManager
	GlobalRateLimiter      *DistributedRateLimiter
	GlobalSessionManager   *EnhancedSessionManager
)

// InitEnhancedSecurity initializes enhanced security components
func InitEnhancedSecurity() {
	GlobalCSRFManager = NewCSRFManager()
	GlobalRateLimiter = NewDistributedRateLimiter()
	GlobalSessionManager = NewEnhancedSessionManager()

	LogInfo("SECURITY", "Enhanced security initialized (Argon2id, CSRF, Rate Limiting)")
}

// InitSessionManager initializes the session manager
func InitSessionManager() {
	if GlobalSessionManager == nil {
		GlobalSessionManager = NewEnhancedSessionManager()
	}
}
