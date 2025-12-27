package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Minimal HS256 JWT implementation (no external dependency)
// This is enough for Web auth flow: login -> token + refresh_token, verify, refresh.

var (
	refreshStoreMu sync.RWMutex
	refreshStore   = map[string]refreshEntry{}
)

type refreshEntry struct {
	Username string
	Expires  time.Time
}

func jwtSecret() []byte {
	if AppConfig != nil && AppConfig.Security.JWTSecret != "" {
		return []byte(AppConfig.Security.JWTSecret)
	}
	// fallback (should never happen in production)
	return []byte("mxui-default-insecure-secret")
}

func base64urlEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func base64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func signHS256(data string, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(data))
	return base64urlEncode(h.Sum(nil))
}

func makeJWT(username string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	payload := map[string]interface{}{
		"sub": username,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(ttl).Unix(),
		"iss": "mxui",
	}

	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)

	hEnc := base64urlEncode(hb)
	pEnc := base64urlEncode(pb)
	unsigned := hEnc + "." + pEnc
	sig := signHS256(unsigned, jwtSecret())
	return unsigned + "." + sig, nil
}

type jwtClaims struct {
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
	Iss string `json:"iss"`
}

func parseAndValidateJWT(token string) (*jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}
	unsigned := parts[0] + "." + parts[1]
	expected := signHS256(unsigned, jwtSecret())
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return nil, errors.New("invalid signature")
	}

	pb, err := base64urlDecode(parts[1])
	if err != nil {
		return nil, errors.New("invalid payload encoding")
	}
	var c jwtClaims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, errors.New("invalid payload")
	}
	if c.Sub == "" {
		return nil, errors.New("missing sub")
	}
	if c.Exp > 0 && time.Now().Unix() > c.Exp {
		return nil, errors.New("token expired")
	}
	return &c, nil
}

func issueRefreshToken(username string, ttl time.Duration) string {
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	// Simple opaque token, signed-like format
	raw := fmt.Sprintf("%s:%d", username, time.Now().UnixNano())
	sig := signHS256(raw, jwtSecret())
	token := base64urlEncode([]byte(raw)) + "." + sig

	refreshStoreMu.Lock()
	refreshStore[token] = refreshEntry{Username: username, Expires: time.Now().Add(ttl)}
	refreshStoreMu.Unlock()

	return token
}

func validateRefreshToken(token string) (string, error) {
	refreshStoreMu.RLock()
	e, ok := refreshStore[token]
	refreshStoreMu.RUnlock()
	if !ok {
		return "", errors.New("refresh token not found")
	}
	if time.Now().After(e.Expires) {
		refreshStoreMu.Lock()
		delete(refreshStore, token)
		refreshStoreMu.Unlock()
		return "", errors.New("refresh token expired")
	}
	return e.Username, nil
}

func revokeRefreshToken(token string) {
	refreshStoreMu.Lock()
	delete(refreshStore, token)
	refreshStoreMu.Unlock()
}
