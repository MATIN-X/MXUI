// MXUI VPN Panel
// Core/security.go
// Security Layer: JWT, 2FA, Auth, Brute-force Protection, Encryption, Whitelist, Decoy

package core

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

// Decoy templates
var decoyTemplates = map[string]string{
	"nginx":  "Welcome to nginx!",
	"apache": "It works!",
	"blank":  "",
}

// ============================================================================
// CONSTANTS
// ============================================================================

const (
	// JWT
	JWTIssuer          = "mxui-panel"
	JWTAccessTokenExp  = 24 * time.Hour
	JWTRefreshTokenExp = 7 * 24 * time.Hour

	// 2FA
	TOTPPeriod    = 30 // seconds
	TOTPDigits    = 6
	TOTPSecretLen = 20
	TOTPWindow    = 1 // Allow 1 period before/after

	// Brute Force
	MaxLoginAttempts   = 5
	LockoutDuration    = 15 * time.Minute
	AttemptResetPeriod = 1 * time.Hour

	// Rate Limit
	DefaultRateLimit      = 100 // requests per minute
	DefaultRateLimitBurst = 20

	// Session
	SessionCookieName = "mxui_session"
	CSRFTokenName     = "mxui_csrf"
	CSRFHeaderName    = "X-CSRF-Token"
)

// ============================================================================
// SECURITY MANAGER
// ============================================================================
// AnomalyDetector detects unusual traffic
type AnomalyDetector struct {
	thresholds map[string]int64
	alerts     chan Alert
}

func (ad *AnomalyDetector) CheckTraffic(userID int64, bytes int64) bool {
	// If traffic > threshold in short time, flag it
	threshold := ad.thresholds["burst"]
	if bytes > threshold {
		ad.alerts <- Alert{UserID: userID, Type: "burst_traffic"}
		return false
	}
	return true
}

// SecurityManager handles all security operations
type SecurityManager struct {
	config         *SecurityConfig
	jwtSecret      []byte
	loginAttempts  map[string]*LoginAttempt
	blockedIPs     map[string]time.Time
	activeSessions map[string]*Session
	rateLimiters   map[string]*rate.Limiter
	ipWhitelist    map[string]bool
	mu             sync.RWMutex
	attemptsMu     sync.RWMutex
	sessionsMu     sync.RWMutex
	rateMu         sync.RWMutex
}

// LoginAttempt tracks failed login attempts
type LoginAttempt struct {
	Count     int
	FirstTry  time.Time
	LastTry   time.Time
	IsLocked  bool
	LockUntil time.Time
}

// Session represents an active user session
type Session struct {
	ID            string    `json:"id"`
	AdminID       int64     `json:"admin_id"`
	Username      string    `json:"username"`
	Role          string    `json:"role"`
	IP            string    `json:"ip"`
	UserAgent     string    `json:"user_agent"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	LastActivity  time.Time `json:"last_activity"`
	Is2FAVerified bool      `json:"is_2fa_verified"`
}

// Global security instance
var Security *SecurityManager

// InitSecurity initializes the security manager
func InitSecurity(config *SecurityConfig) error {
	Security = &SecurityManager{
		config:         config,
		jwtSecret:      []byte(config.JWTSecret),
		loginAttempts:  make(map[string]*LoginAttempt),
		blockedIPs:     make(map[string]time.Time),
		activeSessions: make(map[string]*Session),
		rateLimiters:   make(map[string]*rate.Limiter),
		ipWhitelist:    make(map[string]bool),
	}

	// Load IP whitelist
	for _, ip := range config.IPWhitelist {
		Security.ipWhitelist[ip] = true
	}

	// Start cleanup goroutine
	go Security.cleanupRoutine()

	return nil
}

// cleanupRoutine periodically cleans up expired data
func (sm *SecurityManager) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sm.cleanupExpiredAttempts()
		sm.cleanupExpiredSessions()
		sm.cleanupExpiredBlocks()
	}
}

// ============================================================================
// JWT TOKEN MANAGEMENT
// ============================================================================

// JWTClaims represents JWT token claims
type JWTClaims struct {
	AdminID   int64  `json:"admin_id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	SessionID string `json:"session_id"`
	TokenType string `json:"token_type"` // access, refresh
	jwt.RegisteredClaims
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

// GenerateTokenPair generates access and refresh tokens
func (sm *SecurityManager) GenerateTokenPair(admin *Admin, sessionID string) (*TokenPair, error) {
	now := time.Now()

	// Access Token
	accessClaims := JWTClaims{
		AdminID:   admin.ID,
		Username:  admin.Username,
		Role:      admin.Role,
		SessionID: sessionID,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    JWTIssuer,
			Subject:   fmt.Sprintf("%d", admin.ID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(JWTAccessTokenExp)),
			ID:        generateSecureToken(16),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(sm.jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Refresh Token
	refreshClaims := JWTClaims{
		AdminID:   admin.ID,
		Username:  admin.Username,
		Role:      admin.Role,
		SessionID: sessionID,
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    JWTIssuer,
			Subject:   fmt.Sprintf("%d", admin.ID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(JWTRefreshTokenExp)),
			ID:        generateSecureToken(16),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(sm.jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		ExpiresAt:    now.Add(JWTAccessTokenExp),
		TokenType:    "Bearer",
	}, nil
}

// ValidateToken validates a JWT token and returns claims
func (sm *SecurityManager) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return sm.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	// Check if session is still valid
	sm.sessionsMu.RLock()
	session, exists := sm.activeSessions[claims.SessionID]
	sm.sessionsMu.RUnlock()

	if !exists {
		return nil, errors.New("session expired or invalidated")
	}

	if time.Now().After(session.ExpiresAt) {
		sm.InvalidateSession(claims.SessionID)
		return nil, errors.New("session expired")
	}

	return claims, nil
}

// RefreshAccessToken refreshes an access token using refresh token
func (sm *SecurityManager) RefreshAccessToken(refreshTokenString string) (*TokenPair, error) {
	claims, err := sm.ValidateToken(refreshTokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != "refresh" {
		return nil, errors.New("invalid token type")
	}

	// Get admin from database
	admin, err := sm.getAdminByID(claims.AdminID)
	if err != nil {
		return nil, err
	}

	if !admin.IsActive {
		return nil, errors.New("admin account is disabled")
	}

	return sm.GenerateTokenPair(admin, claims.SessionID)
}

// getAdminByID retrieves admin from database
func (sm *SecurityManager) getAdminByID(id int64) (*Admin, error) {
	var admin Admin
	err := DB.db.QueryRow(`
		SELECT id, username, password, email, role, is_active, 
		       telegram_id, telegram_username, parent_admin_id,
		       traffic_limit, user_limit, traffic_used, users_created,
		       last_login, last_ip, created_at, updated_at
		FROM admins WHERE id = ?
	`, id).Scan(
		&admin.ID, &admin.Username, &admin.Password, &admin.Email,
		&admin.Role, &admin.IsActive, &admin.TelegramID, &admin.TelegramUsername,
		&admin.ParentAdminID, &admin.TrafficLimit, &admin.UserLimit,
		&admin.TrafficUsed, &admin.UsersCreated, &admin.LastLogin,
		&admin.LastIP, &admin.CreatedAt, &admin.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &admin, nil
}

// ============================================================================
// SESSION MANAGEMENT
// ============================================================================

// CreateSession creates a new session for an admin
func (sm *SecurityManager) CreateSession(admin *Admin, ip, userAgent string) (*Session, error) {
	sessionID := generateSecureToken(32)
	now := time.Now()

	session := &Session{
		ID:            sessionID,
		AdminID:       admin.ID,
		Username:      admin.Username,
		Role:          admin.Role,
		IP:            ip,
		UserAgent:     userAgent,
		CreatedAt:     now,
		ExpiresAt:     now.Add(time.Duration(sm.config.JWTExpiration) * time.Hour),
		LastActivity:  now,
		Is2FAVerified: !sm.config.Enable2FA, // If 2FA disabled, consider verified
	}

	sm.sessionsMu.Lock()
	sm.activeSessions[sessionID] = session
	sm.sessionsMu.Unlock()

	return session, nil
}

// GetSession retrieves a session by ID
func (sm *SecurityManager) GetSession(sessionID string) (*Session, bool) {
	sm.sessionsMu.RLock()
	defer sm.sessionsMu.RUnlock()

	session, exists := sm.activeSessions[sessionID]
	return session, exists
}

// UpdateSessionActivity updates session last activity time
func (sm *SecurityManager) UpdateSessionActivity(sessionID string) {
	sm.sessionsMu.Lock()
	defer sm.sessionsMu.Unlock()

	if session, exists := sm.activeSessions[sessionID]; exists {
		session.LastActivity = time.Now()
	}
}

// InvalidateSession removes a session
func (sm *SecurityManager) InvalidateSession(sessionID string) {
	sm.sessionsMu.Lock()
	defer sm.sessionsMu.Unlock()

	delete(sm.activeSessions, sessionID)
}

// InvalidateAllSessions removes all sessions for an admin
func (sm *SecurityManager) InvalidateAllSessions(adminID int64) {
	sm.sessionsMu.Lock()
	defer sm.sessionsMu.Unlock()

	for id, session := range sm.activeSessions {
		if session.AdminID == adminID {
			delete(sm.activeSessions, id)
		}
	}
}

// GetActiveSessions returns all active sessions for an admin
func (sm *SecurityManager) GetActiveSessions(adminID int64) []*Session {
	sm.sessionsMu.RLock()
	defer sm.sessionsMu.RUnlock()

	var sessions []*Session
	for _, session := range sm.activeSessions {
		if session.AdminID == adminID {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

// cleanupExpiredSessions removes expired sessions
func (sm *SecurityManager) cleanupExpiredSessions() {
	sm.sessionsMu.Lock()
	defer sm.sessionsMu.Unlock()

	now := time.Now()
	for id, session := range sm.activeSessions {
		if now.After(session.ExpiresAt) {
			delete(sm.activeSessions, id)
		}
	}
}

// ============================================================================
// TWO-FACTOR AUTHENTICATION (TOTP)
// ============================================================================

// TOTPSecret represents a TOTP secret for 2FA
type TOTPSecret struct {
	Secret    string `json:"secret"`
	URL       string `json:"url"`
	QRCode    string `json:"qr_code"` // Base64 encoded QR image
	Issuer    string `json:"issuer"`
	Account   string `json:"account"`
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
}

// Generate2FASecret generates a new TOTP secret
func (sm *SecurityManager) Generate2FASecret(username string) (*TOTPSecret, error) {
	// Generate random secret
	secret := make([]byte, TOTPSecretLen)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}

	secretBase32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)

	// Build otpauth URL
	issuer := "MXUI Panel"
	url := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		issuer, username, secretBase32, issuer, TOTPDigits, TOTPPeriod)

	return &TOTPSecret{
		Secret:    secretBase32,
		URL:       url,
		Issuer:    issuer,
		Account:   username,
		Algorithm: "SHA1",
		Digits:    TOTPDigits,
		Period:    TOTPPeriod,
	}, nil
}

// Verify2FACode verifies a TOTP code
func (sm *SecurityManager) Verify2FACode(secret, code string) bool {
	// Decode secret
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return false
	}

	// Get current time counter
	now := time.Now().Unix()
	counter := now / TOTPPeriod

	// Check current and adjacent time windows
	for i := -TOTPWindow; i <= TOTPWindow; i++ {
		expectedCode := sm.generateTOTP(secretBytes, counter+int64(i))
		if subtle.ConstantTimeCompare([]byte(expectedCode), []byte(code)) == 1 {
			return true
		}
	}

	return false
}

// generateTOTP generates a TOTP code for a given counter
func (sm *SecurityManager) generateTOTP(secret []byte, counter int64) string {
	// Convert counter to big-endian bytes
	counterBytes := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		counterBytes[i] = byte(counter & 0xff)
		counter >>= 8
	}

	// Calculate HMAC-SHA1
	h := hmac.New(sha256.New, secret)
	h.Write(counterBytes)
	hash := h.Sum(nil)

	// Dynamic truncation
	offset := hash[len(hash)-1] & 0x0f
	binary := (int(hash[offset]&0x7f) << 24) |
		(int(hash[offset+1]) << 16) |
		(int(hash[offset+2]) << 8) |
		int(hash[offset+3])

	// Generate digits
	otp := binary % 1000000
	return fmt.Sprintf("%06d", otp)
}

// Enable2FA enables 2FA for an admin
func (sm *SecurityManager) Enable2FA(adminID int64, secret string) error {
	encryptedSecret, err := DB.Encrypt(secret)
	if err != nil {
		return err
	}

	_, err = DB.db.Exec(`
		INSERT INTO settings (key, value, type, category, is_encrypted)
		VALUES (?, ?, 'string', '2fa', 1)
		ON CONFLICT(key) DO UPDATE SET value = ?, is_encrypted = 1
	`, fmt.Sprintf("2fa_secret_%d", adminID), encryptedSecret, encryptedSecret)

	return err
}

// Disable2FA disables 2FA for an admin
func (sm *SecurityManager) Disable2FA(adminID int64) error {
	_, err := DB.db.Exec(`
		DELETE FROM settings WHERE key = ?
	`, fmt.Sprintf("2fa_secret_%d", adminID))
	return err
}

// Get2FASecret retrieves 2FA secret for an admin
func (sm *SecurityManager) Get2FASecret(adminID int64) (string, error) {
	return DB.GetSetting(fmt.Sprintf("2fa_secret_%d", adminID))
}

// Is2FAEnabled checks if 2FA is enabled for an admin
func (sm *SecurityManager) Is2FAEnabled(adminID int64) bool {
	secret, err := sm.Get2FASecret(adminID)
	return err == nil && secret != ""
}

// Verify2FAForAdmin verifies 2FA code for an admin
func (sm *SecurityManager) Verify2FAForAdmin(adminID int64, code string) bool {
	secret, err := sm.Get2FASecret(adminID)
	if err != nil || secret == "" {
		return false
	}
	return sm.Verify2FACode(secret, code)
}

// Mark2FAVerified marks session as 2FA verified
func (sm *SecurityManager) Mark2FAVerified(sessionID string) {
	sm.sessionsMu.Lock()
	defer sm.sessionsMu.Unlock()

	if session, exists := sm.activeSessions[sessionID]; exists {
		session.Is2FAVerified = true
	}
}

// ============================================================================
// BRUTE FORCE PROTECTION
// ============================================================================

// RecordLoginAttempt records a login attempt
func (sm *SecurityManager) RecordLoginAttempt(identifier string, success bool) {
	sm.attemptsMu.Lock()
	defer sm.attemptsMu.Unlock()

	now := time.Now()

	if success {
		// Clear attempts on successful login
		delete(sm.loginAttempts, identifier)
		return
	}

	attempt, exists := sm.loginAttempts[identifier]
	if !exists {
		attempt = &LoginAttempt{
			FirstTry: now,
		}
		sm.loginAttempts[identifier] = attempt
	}

	// Reset if first attempt was too long ago
	if now.Sub(attempt.FirstTry) > AttemptResetPeriod {
		attempt.Count = 0
		attempt.FirstTry = now
		attempt.IsLocked = false
	}

	attempt.Count++
	attempt.LastTry = now

	// Check if should lock
	maxAttempts := sm.config.MaxLoginAttempts
	if maxAttempts == 0 {
		maxAttempts = MaxLoginAttempts
	}

	if attempt.Count >= maxAttempts {
		lockDuration := time.Duration(sm.config.LoginLockoutDuration) * time.Minute
		if lockDuration == 0 {
			lockDuration = LockoutDuration
		}
		attempt.IsLocked = true
		attempt.LockUntil = now.Add(lockDuration)
	}
}

// IsLoginBlocked checks if login is blocked for an identifier
func (sm *SecurityManager) IsLoginBlocked(identifier string) (bool, time.Duration) {
	sm.attemptsMu.RLock()
	defer sm.attemptsMu.RUnlock()

	attempt, exists := sm.loginAttempts[identifier]
	if !exists {
		return false, 0
	}

	if !attempt.IsLocked {
		return false, 0
	}

	now := time.Now()
	if now.After(attempt.LockUntil) {
		return false, 0
	}

	return true, attempt.LockUntil.Sub(now)
}

// GetLoginAttempts returns number of failed attempts
func (sm *SecurityManager) GetLoginAttempts(identifier string) int {
	sm.attemptsMu.RLock()
	defer sm.attemptsMu.RUnlock()

	if attempt, exists := sm.loginAttempts[identifier]; exists {
		return attempt.Count
	}
	return 0
}

// cleanupExpiredAttempts removes old login attempts
func (sm *SecurityManager) cleanupExpiredAttempts() {
	sm.attemptsMu.Lock()
	defer sm.attemptsMu.Unlock()

	now := time.Now()
	for id, attempt := range sm.loginAttempts {
		if now.Sub(attempt.LastTry) > AttemptResetPeriod {
			delete(sm.loginAttempts, id)
		}
	}
}

// ============================================================================
// IP BLOCKING & WHITELIST
// ============================================================================

// BlockIP blocks an IP address
func (sm *SecurityManager) BlockIP(ip string, duration time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.blockedIPs[ip] = time.Now().Add(duration)
}

// UnblockIP unblocks an IP address
func (sm *SecurityManager) UnblockIP(ip string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	delete(sm.blockedIPs, ip)
}

// IsIPBlocked checks if an IP is blocked
func (sm *SecurityManager) IsIPBlocked(ip string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	blockUntil, exists := sm.blockedIPs[ip]
	if !exists {
		return false
	}

	if time.Now().After(blockUntil) {
		return false
	}

	return true
}

// IsIPWhitelisted checks if an IP is in whitelist
func (sm *SecurityManager) IsIPWhitelisted(ip string) bool {
	if !sm.config.EnableIPWhitelist {
		return true // Whitelist disabled, all IPs allowed
	}

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Check exact match
	if sm.ipWhitelist[ip] {
		return true
	}

	// Check CIDR ranges
	for whiteIP := range sm.ipWhitelist {
		if strings.Contains(whiteIP, "/") {
			_, network, err := net.ParseCIDR(whiteIP)
			if err == nil && network.Contains(net.ParseIP(ip)) {
				return true
			}
		}
	}

	return false
}

// AddIPToWhitelist adds an IP to whitelist
func (sm *SecurityManager) AddIPToWhitelist(ip string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.ipWhitelist[ip] = true
}

// RemoveIPFromWhitelist removes an IP from whitelist
func (sm *SecurityManager) RemoveIPFromWhitelist(ip string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	delete(sm.ipWhitelist, ip)
}

// GetWhitelistedIPs returns all whitelisted IPs
func (sm *SecurityManager) GetWhitelistedIPs() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	ips := make([]string, 0, len(sm.ipWhitelist))
	for ip := range sm.ipWhitelist {
		ips = append(ips, ip)
	}
	return ips
}

// cleanupExpiredBlocks removes expired IP blocks
func (sm *SecurityManager) cleanupExpiredBlocks() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	for ip, blockUntil := range sm.blockedIPs {
		if now.After(blockUntil) {
			delete(sm.blockedIPs, ip)
		}
	}
}

// ============================================================================
// RATE LIMITING
// ============================================================================

// GetRateLimiter returns a rate limiter for an identifier
func (sm *SecurityManager) GetRateLimiter(identifier string) *rate.Limiter {
	sm.rateMu.Lock()
	defer sm.rateMu.Unlock()

	limiter, exists := sm.rateLimiters[identifier]
	if !exists {
		rateLimit := rate.Limit(DefaultRateLimit / 60.0) // Convert to per-second
		limiter = rate.NewLimiter(rateLimit, DefaultRateLimitBurst)
		sm.rateLimiters[identifier] = limiter
	}

	return limiter
}

// IsRateLimited checks if a request should be rate limited
func (sm *SecurityManager) IsRateLimited(identifier string) bool {
	limiter := sm.GetRateLimiter(identifier)
	return !limiter.Allow()
}

// ============================================================================
// CSRF PROTECTION
// ============================================================================

// GenerateCSRFToken generates a CSRF token
func (sm *SecurityManager) GenerateCSRFToken(sessionID string) string {
	data := fmt.Sprintf("%s:%d", sessionID, time.Now().UnixNano())
	h := hmac.New(sha256.New, sm.jwtSecret)
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// ValidateCSRFToken validates a CSRF token
func (sm *SecurityManager) ValidateCSRFToken(sessionID, token string) bool {
	// For simplicity, we're using a time-window approach
	// In production, store tokens and verify against stored values
	return len(token) == 64 // Basic validation
}

// ============================================================================
// ENCRYPTION UTILITIES
// ============================================================================

// EncryptAES encrypts data using AES-GCM
func EncryptAES(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAES decrypts data using AES-GCM
func DecryptAES(ciphertext string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(data) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// HashPasswordBcrypt hashes password using bcrypt
func HashPasswordBcrypt(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// VerifyPasswordBcrypt verifies password against bcrypt hash
func VerifyPasswordBcrypt(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateAPIKey generates a secure API key
func GenerateAPIKey() string {
	return "mxui_" + generateSecureToken(32)
}

// ============================================================================
// DECOY SYSTEM (CAMOUFLAGE)
// ============================================================================

// DecoyHandler returns a decoy HTTP handler
func (sm *SecurityManager) DecoyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch sm.config.DecoyType {
		case "nginx":
			sm.serveNginxDecoy(w, r)
		case "apache":
			sm.serveApacheDecoy(w, r)
		case "iis":
			sm.serveIISDecoy(w, r)
		default:
			sm.serveNginxDecoy(w, r)
		}
	})
}

// serveNginxDecoy serves a fake nginx page
func (sm *SecurityManager) serveNginxDecoy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "nginx/1.24.0")
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusNotFound)

	html := `<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.24.0</center>
</body>
</html>`
	w.Write([]byte(html))
}

// serveApacheDecoy serves a fake apache page
func (sm *SecurityManager) serveApacheDecoy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "Apache/2.4.54 (Ubuntu)")
	w.Header().Set("Content-Type", "text/html; charset=iso-8859-1")
	w.WriteHeader(http.StatusNotFound)

	html := `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.54 (Ubuntu) Server at %s Port %s</address>
</body></html>`
	host, port, _ := net.SplitHostPort(r.Host)
	if port == "" {
		port = "80"
	}
	if host == "" {
		host = r.Host
	}
	w.Write([]byte(fmt.Sprintf(html, host, port)))
}

// serveIISDecoy serves a fake IIS page
func (sm *SecurityManager) serveIISDecoy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "Microsoft-IIS/10.0")
	w.Header().Set("X-Powered-By", "ASP.NET")
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusNotFound)

	html := `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
<title>404 - File or directory not found.</title>
</head>
<body>
<div id="header"><h1>Server Error</h1></div>
<div id="content">
<div class="content-container"><fieldset>
<h2>404 - File or directory not found.</h2>
<h3>The resource you are looking for might have been removed, had its name changed, or is temporarily unavailable.</h3>
</fieldset></div>
</div>
</body>
</html>`
	w.Write([]byte(html))
}

// ============================================================================
// INPUT VALIDATION & SANITIZATION
// ============================================================================

// ValidateUsername validates username format
func ValidateUsername(username string) error {
	if len(username) < 3 || len(username) > 32 {
		return errors.New("username must be 3-32 characters")
	}

	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, username)
	if !matched {
		return errors.New("username can only contain letters, numbers, underscore and hyphen")
	}

	return nil
}

// ValidatePassword validates password strength
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasNumber = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasNumber {
		return errors.New("password must contain uppercase, lowercase and number")
	}

	_ = hasSpecial // Optional requirement
	return nil
}

// ValidateEmail validates email format
func ValidateEmail(email string) error {
	if email == "" {
		return nil // Email is optional
	}

	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(pattern, email)
	if !matched {
		return errors.New("invalid email format")
	}

	return nil
}

// SanitizeInput sanitizes user input to prevent XSS
func SanitizeInput(input string) string {
	return template.HTMLEscapeString(input)
}

// ValidateIP validates IP address format
func ValidateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// ValidateCIDR validates CIDR notation
func ValidateCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// ============================================================================
// HTTP MIDDLEWARE
// ============================================================================

// AuthMiddleware creates authentication middleware
func (sm *SecurityManager) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get token from header or cookie
		token := sm.extractToken(r)
		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Validate token
		claims, err := sm.ValidateToken(token)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Check 2FA if required
		if sm.config.Enable2FA {
			session, _ := sm.GetSession(claims.SessionID)
			if session != nil && !session.Is2FAVerified {
				http.Error(w, "2FA verification required", http.StatusForbidden)
				return
			}
		}

		// Add claims to context
		ctx := r.Context()
		ctx = ContextWithClaims(ctx, claims)
		r = r.WithContext(ctx)

		// Update session activity
		sm.UpdateSessionActivity(claims.SessionID)

		next.ServeHTTP(w, r)
	})
}

// RateLimitMiddleware creates rate limiting middleware
func (sm *SecurityManager) RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := GetClientIP(r)

		if sm.IsRateLimited(ip) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// IPFilterMiddleware creates IP filtering middleware
func (sm *SecurityManager) IPFilterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := GetClientIP(r)

		// Check if IP is blocked
		if sm.IsIPBlocked(ip) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Check whitelist if enabled
		if !sm.IsIPWhitelisted(ip) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// CSRFMiddleware creates CSRF protection middleware
func (sm *SecurityManager) CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip for GET, HEAD, OPTIONS
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		// Get CSRF token from header
		token := r.Header.Get(CSRFHeaderName)
		if token == "" {
			token = r.FormValue(CSRFTokenName)
		}

		// Get session ID from token
		claims := ClaimsFromContext(r.Context())
		if claims == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if !sm.ValidateCSRFToken(claims.SessionID, token) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// OwnerOnlyMiddleware restricts access to owner admin only
func (sm *SecurityManager) OwnerOnlyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := ClaimsFromContext(r.Context())
		if claims == nil || claims.Role != AdminRoleOwner {
			http.Error(w, "Forbidden: Owner access required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// extractToken extracts JWT token from request
func (sm *SecurityManager) extractToken(r *http.Request) string {
	// From Authorization header
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	// From cookie
	cookie, err := r.Cookie(SessionCookieName)
	if err == nil {
		return cookie.Value
	}

	// From query parameter (for subscription links)
	return r.URL.Query().Get("token")
}

// ============================================================================
// CONTEXT HELPERS
// ============================================================================

type contextKey string

const claimsContextKey contextKey = "jwt_claims"

// ContextWithClaims adds claims to context
func ContextWithClaims(ctx context.Context, claims *JWTClaims) context.Context {
	return context.WithValue(ctx, claimsContextKey, claims)
}

// ClaimsFromContext extracts claims from context
func ClaimsFromContext(ctx context.Context) *JWTClaims {
	claims, _ := ctx.Value(claimsContextKey).(*JWTClaims)
	return claims
}

// ============================================================================
// IP UTILITIES
// ============================================================================

// GetClientIP extracts client IP from request
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if ValidateIP(ip) {
				return ip
			}
		}
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" && ValidateIP(xri) {
		return xri
	}

	// Check CF-Connecting-IP (Cloudflare)
	cfip := r.Header.Get("CF-Connecting-IP")
	if cfip != "" && ValidateIP(cfip) {
		return cfip
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// GetIPLocation returns approximate location for an IP (placeholder)
func GetIPLocation(ip string) string {
	// In production, use a GeoIP database
	// This is a placeholder that returns empty string
	return ""
}

// ============================================================================
// AUDIT LOGGING
// ============================================================================

// LogAuditEvent logs an admin action
func (sm *SecurityManager) LogAuditEvent(adminID int64, adminUsername, action, resource string, resourceID int64, oldValue, newValue interface{}, r *http.Request) error {
	var oldJSON, newJSON string

	if oldValue != nil {
		data, _ := json.Marshal(oldValue)
		oldJSON = string(data)
	}
	if newValue != nil {
		data, _ := json.Marshal(newValue)
		newJSON = string(data)
	}

	ip := GetClientIP(r)
	userAgent := r.UserAgent()

	_, err := DB.db.Exec(`
		INSERT INTO audit_logs (admin_id, admin_username, action, resource, resource_id, old_value, new_value, ip, user_agent)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, adminID, adminUsername, action, resource, resourceID, oldJSON, newJSON, ip, userAgent)

	return err
}

// GetAuditLogs retrieves audit logs with pagination
func (sm *SecurityManager) GetAuditLogs(adminID int64, limit, offset int) ([]AuditLog, int, error) {
	var total int
	countQuery := "SELECT COUNT(*) FROM audit_logs"
	args := []interface{}{}

	if adminID > 0 {
		countQuery += " WHERE admin_id = ?"
		args = append(args, adminID)
	}

	DB.db.QueryRow(countQuery, args...).Scan(&total)

	query := `
		SELECT id, admin_id, admin_username, action, resource, resource_id,
		       old_value, new_value, ip, user_agent, created_at
		FROM audit_logs
	`
	if adminID > 0 {
		query += " WHERE admin_id = ?"
	}
	query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := DB.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []AuditLog
	for rows.Next() {
		var log AuditLog
		err := rows.Scan(
			&log.ID, &log.AdminID, &log.AdminUsername, &log.Action,
			&log.Resource, &log.ResourceID, &log.OldValue, &log.NewValue,
			&log.IP, &log.UserAgent, &log.CreatedAt,
		)
		if err != nil {
			continue
		}
		logs = append(logs, log)
	}

	return logs, total, nil
}

// CORSMiddleware handles CORS headers
func CORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Check if origin is allowed
			allowed := false
			for _, o := range allowedOrigins {
				if o == "*" || o == origin {
					allowed = true
					break
				}
			}

			if allowed && origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}

			// Handle preflight
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetDecoyPage returns decoy HTML
func GetDecoyPage(decoyType string) string {
	if html, ok := decoyTemplates[decoyType]; ok {
		return html
	}
	return decoyTemplates["nginx"]
}
