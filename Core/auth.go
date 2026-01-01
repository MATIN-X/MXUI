package core

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ============================================================================
// AUTH MANAGER
// ============================================================================

// AuthManager handles authentication
type AuthManager struct {
	jwtSecret     []byte
	tokenDuration time.Duration
	mu            sync.RWMutex
}

// Global auth manager
var Auth *AuthManager

// AuthClaims represents JWT claims
type AuthClaims struct {
	AdminID  int64  `json:"admin_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	UserID   int64  `json:"user_id,omitempty"`
	jwt.RegisteredClaims
}

// InitAuthManager initializes the auth manager
func InitAuthManager() error {
	secret := AppConfig.Security.JWTSecret
	if secret == "" {
		// Generate random secret if not configured
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		secret = hex.EncodeToString(b)
	}

	Auth = &AuthManager{
		jwtSecret:     []byte(secret),
		tokenDuration: 24 * time.Hour,
	}

	log.Println("✓ Auth manager initialized")
	return nil
}

// GenerateToken generates a new JWT token for an admin
func (am *AuthManager) GenerateToken(admin *Admin) (string, error) {
	if am == nil {
		return "", errors.New("auth manager not initialized")
	}

	claims := AuthClaims{
		AdminID:  admin.ID,
		Username: admin.Username,
		Role:     admin.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(am.tokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "mxui",
			Subject:   admin.Username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(am.jwtSecret)
}

// ValidateToken validates a JWT token and returns claims
func (am *AuthManager) ValidateToken(tokenString string) (*AuthClaims, error) {
	if am == nil {
		return nil, errors.New("auth manager not initialized")
	}

	token, err := jwt.ParseWithClaims(tokenString, &AuthClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return am.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*AuthClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// RefreshToken refreshes a JWT token
func (am *AuthManager) RefreshToken(tokenString string) (string, error) {
	claims, err := am.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	// Get admin to ensure still valid
	admin, err := Admins.GetAdminByID(claims.AdminID)
	if err != nil || admin == nil {
		return "", errors.New("admin not found")
	}

	if !admin.IsActive {
		return "", errors.New("admin is disabled")
	}

	return am.GenerateToken(admin)
}

