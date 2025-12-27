// Core/transport.go
// MXUI VPN Panel - Transport Layer
// Part 1: TLS, Reality, WebSocket, Base Transport

package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// ==================== Constants ====================

const (
	// Transport types
	TransportTypeTCP       TransportType = "tcp"
	TransportTypeWS        TransportType = "ws"
	TransportTypeWSS       TransportType = "wss"
	TransportTypeHTTP2     TransportType = "h2"
	TransportTypeGRPC      TransportType = "grpc"
	TransportTypeQUIC      TransportType = "quic"
	TransportTypeKCP       TransportType = "kcp"
	TransportTypeMKCP      TransportType = "mkcp"
	TransportTypeHTTPU     TransportType = "httpupgrade"
	TransportTypeSplitHTTP TransportType = "splithttp"

	// Security types
	SecurityNone    SecurityType = "none"
	SecurityTLS     SecurityType = "tls"
	SecurityReality SecurityType = "reality"
	SecurityXTLS    SecurityType = "xtls"

	// TLS versions
	TLSVersion12 = "1.2"
	TLSVersion13 = "1.3"

	// ALPN protocols
	ALPNH2      = "h2"
	ALPNHTTP11  = "http/1.1"
	ALPNGRPCExp = "grpc-exp"

	// Buffer sizes
	DefaultBufferSize = 32 * 1024
	MaxBufferSize     = 256 * 1024
	MinBufferSize     = 4 * 1024

	// Reality constants
	RealityMaxTimeDiff = 120 // seconds
	RealityShortIDLen  = 8
)

// ==================== Types ====================

type TransportType string
type SecurityType string

// ==================== Transport Config ====================

// TransportConfig holds transport layer configuration
type TransportConfig struct {
	Type     TransportType `json:"type"`
	Security SecurityType  `json:"security"`

	// TLS settings
	TLS *TLSConfig `json:"tls,omitempty"`

	// Reality settings
	Reality *RealityTransportConfig `json:"reality,omitempty"`

	// WebSocket settings
	WebSocket *WebSocketConfig `json:"websocket,omitempty"`

	// HTTP/2 settings
	HTTP2 *HTTP2Config `json:"http2,omitempty"`

	// gRPC settings
	GRPC *GRPCConfig `json:"grpc,omitempty"`

	// QUIC settings
	QUIC *QUICConfig `json:"quic,omitempty"`

	// HTTPUpgrade settings
	HTTPUpgrade *HTTPUpgradeConfig `json:"httpupgrade,omitempty"`

	// SplitHTTP settings
	SplitHTTP *SplitHTTPConfig `json:"splithttp,omitempty"`

	// TCP settings
	TCP *TCPConfig `json:"tcp,omitempty"`

	// Fragment settings
	Fragment *FragmentConfig `json:"fragment,omitempty"`

	// Mux settings
	Mux *MuxConfig `json:"mux,omitempty"`

	// General settings
	Host            string            `json:"host,omitempty"`
	Port            int               `json:"port,omitempty"`
	Path            string            `json:"path,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	MaxEarlyData    int               `json:"max_early_data,omitempty"`
	EarlyDataHeader string            `json:"early_data_header,omitempty"`
}

// ==================== TLS Configuration ====================

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled         bool     `json:"enabled"`
	ServerName      string   `json:"server_name"`
	ALPN            []string `json:"alpn,omitempty"`
	MinVersion      string   `json:"min_version,omitempty"`
	MaxVersion      string   `json:"max_version,omitempty"`
	CipherSuites    []string `json:"cipher_suites,omitempty"`
	Fingerprint     string   `json:"fingerprint,omitempty"`
	AllowInsecure   bool     `json:"allow_insecure"`
	DisableSNI      bool     `json:"disable_sni"`
	CertFile        string   `json:"cert_file,omitempty"`
	KeyFile         string   `json:"key_file,omitempty"`
	CAFile          string   `json:"ca_file,omitempty"`
	Certificate     string   `json:"certificate,omitempty"`
	PrivateKey      string   `json:"private_key,omitempty"`
	PinnedPeerCerts []string `json:"pinned_peer_certs,omitempty"`
	SessionTicket   bool     `json:"session_ticket"`
	ReuseSession    bool     `json:"reuse_session"`
}

// TLSManager manages TLS configurations
type TLSManager struct {
	configs     map[string]*tls.Config
	certs       map[string]*tls.Certificate
	mu          sync.RWMutex
	certWatcher *CertWatcher
}

// NewTLSManager creates new TLS manager
func NewTLSManager() *TLSManager {
	return &TLSManager{
		configs: make(map[string]*tls.Config),
		certs:   make(map[string]*tls.Certificate),
	}
}

// BuildServerConfig builds TLS config for server
func (tm *TLSManager) BuildServerConfig(cfg *TLSConfig) (*tls.Config, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		MinVersion:         tm.parseTLSVersion(cfg.MinVersion),
		MaxVersion:         tm.parseTLSVersion(cfg.MaxVersion),
		NextProtos:         cfg.ALPN,
		InsecureSkipVerify: cfg.AllowInsecure,
	}

	// Load certificate
	cert, err := tm.loadCertificate(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	if cert != nil {
		tlsConfig.Certificates = []tls.Certificate{*cert}
	}

	// Load CA if specified
	if cfg.CAFile != "" {
		caPool, err := tm.loadCAPool(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.ClientCAs = caPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	// Set cipher suites if specified
	if len(cfg.CipherSuites) > 0 {
		tlsConfig.CipherSuites = tm.parseCipherSuites(cfg.CipherSuites)
	}

	// Session tickets
	if !cfg.SessionTicket {
		tlsConfig.SessionTicketsDisabled = true
	}

	return tlsConfig, nil
}

// BuildClientConfig builds TLS config for client
func (tm *TLSManager) BuildClientConfig(cfg *TLSConfig) (*tls.Config, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		ServerName:         cfg.ServerName,
		MinVersion:         tm.parseTLSVersion(cfg.MinVersion),
		MaxVersion:         tm.parseTLSVersion(cfg.MaxVersion),
		NextProtos:         cfg.ALPN,
		InsecureSkipVerify: cfg.AllowInsecure,
	}

	// Disable SNI if requested
	if cfg.DisableSNI {
		tlsConfig.ServerName = ""
	}

	// Load client certificate if specified
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA pool
	if cfg.CAFile != "" {
		caPool, err := tm.loadCAPool(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = caPool
	}

	// Pinned certificates
	if len(cfg.PinnedPeerCerts) > 0 {
		tlsConfig.VerifyPeerCertificate = tm.createPinVerifier(cfg.PinnedPeerCerts)
	}

	// Apply fingerprint
	if cfg.Fingerprint != "" {
		tm.applyFingerprint(tlsConfig, cfg.Fingerprint)
	}

	return tlsConfig, nil
}

// loadCertificate loads certificate from config
func (tm *TLSManager) loadCertificate(cfg *TLSConfig) (*tls.Certificate, error) {
	var certPEM, keyPEM []byte
	var err error

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		certPEM, err = os.ReadFile(cfg.CertFile)
		if err != nil {
			return nil, err
		}
		keyPEM, err = os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, err
		}
	} else if cfg.Certificate != "" && cfg.PrivateKey != "" {
		certPEM = []byte(cfg.Certificate)
		keyPEM = []byte(cfg.PrivateKey)
	} else {
		return nil, nil
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

// loadCAPool loads CA certificate pool
func (tm *TLSManager) loadCAPool(caFile string) (*x509.CertPool, error) {
	caData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return nil, errors.New("failed to parse CA certificate")
	}

	return pool, nil
}

// parseTLSVersion parses TLS version string
func (tm *TLSManager) parseTLSVersion(version string) uint16 {
	switch version {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12 // Default to TLS 1.2
	}
}

// parseCipherSuites parses cipher suite names
func (tm *TLSManager) parseCipherSuites(names []string) []uint16 {
	suites := make([]uint16, 0, len(names))

	cipherMap := map[string]uint16{
		"TLS_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		"TLS_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		"TLS_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"TLS_CHACHA20_POLY1305_SHA256":            tls.TLS_CHACHA20_POLY1305_SHA256,
		"TLS_AES_128_GCM_SHA256":                  tls.TLS_AES_128_GCM_SHA256,
		"TLS_AES_256_GCM_SHA384":                  tls.TLS_AES_256_GCM_SHA384,
	}

	for _, name := range names {
		if suite, ok := cipherMap[name]; ok {
			suites = append(suites, suite)
		}
	}

	return suites
}

// createPinVerifier creates certificate pinning verifier
func (tm *TLSManager) createPinVerifier(pins []string) func([][]byte, [][]*x509.Certificate) error {
	pinnedHashes := make(map[string]bool)
	for _, pin := range pins {
		pinnedHashes[pin] = true
	}

	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		for _, rawCert := range rawCerts {
			hash := sha256.Sum256(rawCert)
			hashStr := base64.StdEncoding.EncodeToString(hash[:])
			if pinnedHashes[hashStr] {
				return nil
			}
		}
		return errors.New("certificate pin verification failed")
	}
}

// applyFingerprint applies browser TLS fingerprint
func (tm *TLSManager) applyFingerprint(config *tls.Config, fingerprint string) {
	// Fingerprint emulation settings
	fingerprints := map[string]struct {
		cipherSuites []uint16
		curves       []tls.CurveID
		extensions   []uint16
	}{
		"chrome": {
			cipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
			curves: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			},
		},
		"firefox": {
			cipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			curves: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
				tls.CurveP521,
			},
		},
		"safari": {
			cipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
			curves: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			},
		},
		"edge": {
			cipherSuites: []uint16{
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			curves: []tls.CurveID{
				tls.CurveP384,
				tls.CurveP256,
				tls.X25519,
			},
		},
		"random": {
			// Randomized fingerprint
		},
		"randomized": {
			// Randomized fingerprint
		},
	}

	fp, exists := fingerprints[strings.ToLower(fingerprint)]
	if exists && len(fp.cipherSuites) > 0 {
		config.CipherSuites = fp.cipherSuites
		config.CurvePreferences = fp.curves
	}
}

// CertWatcher watches certificate files for changes
type CertWatcher struct {
	certFile string
	keyFile  string
	callback func(*tls.Certificate)
	stopChan chan struct{}
}

// NewCertWatcher creates new certificate watcher
func NewCertWatcher(certFile, keyFile string, callback func(*tls.Certificate)) *CertWatcher {
	return &CertWatcher{
		certFile: certFile,
		keyFile:  keyFile,
		callback: callback,
		stopChan: make(chan struct{}),
	}
}

// Start starts watching certificates
func (cw *CertWatcher) Start() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		var lastModTime time.Time

		for {
			select {
			case <-cw.stopChan:
				return
			case <-ticker.C:
				info, err := os.Stat(cw.certFile)
				if err != nil {
					continue
				}

				if info.ModTime().After(lastModTime) {
					cert, err := tls.LoadX509KeyPair(cw.certFile, cw.keyFile)
					if err == nil {
						cw.callback(&cert)
						lastModTime = info.ModTime()
					}
				}
			}
		}
	}()
}

// Stop stops watching
func (cw *CertWatcher) Stop() {
	close(cw.stopChan)
}

// ==================== Reality Protocol ====================

// RealityTransportConfig holds Reality protocol configuration for transport layer
type RealityTransportConfig struct {
	Enabled      bool     `json:"enabled"`
	Show         bool     `json:"show"`
	Dest         string   `json:"dest"`
	Port         int      `json:"port"`
	ServerNames  []string `json:"server_names"`
	PrivateKey   string   `json:"private_key"`
	PublicKey    string   `json:"public_key"`
	ShortIDs     []string `json:"short_ids"`
	SpiderX      string   `json:"spider_x,omitempty"`
	Fingerprint  string   `json:"fingerprint,omitempty"`
	ServerName   string   `json:"server_name,omitempty"`
	MinClientVer string   `json:"min_client_ver,omitempty"`
	MaxClientVer string   `json:"max_client_ver,omitempty"`
	MaxTimeDiff  int64    `json:"max_time_diff,omitempty"`
}

// RealityServer handles Reality protocol server-side
type RealityServer struct {
	config     *RealityTransportConfig
	privateKey []byte
	publicKey  []byte
	shortIDs   map[string]bool
	destDialer *net.Dialer
	mu         sync.RWMutex
	stats      RealityStats
}

// RealityStats holds Reality server statistics
type RealityStats struct {
	TotalConnections  int64
	ActiveConnections int64
	AuthFailures      int64
	SuccessfulAuths   int64
	BytesSent         int64
	BytesReceived     int64
}

// NewRealityServer creates new Reality server
func NewRealityServer(config *RealityTransportConfig) (*RealityServer, error) {
	if config == nil || !config.Enabled {
		return nil, nil
	}

	// Decode private key
	privateKey, err := base64.RawURLEncoding.DecodeString(config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	if len(privateKey) != 32 {
		return nil, errors.New("private key must be 32 bytes")
	}

	// Compute public key if not provided
	var publicKey []byte
	if config.PublicKey != "" {
		publicKey, err = base64.RawURLEncoding.DecodeString(config.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid public key: %w", err)
		}
	} else {
		publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
		if err != nil {
			return nil, err
		}
	}

	// Parse short IDs
	shortIDs := make(map[string]bool)
	for _, sid := range config.ShortIDs {
		shortIDs[sid] = true
	}

	return &RealityServer{
		config:     config,
		privateKey: privateKey,
		publicKey:  publicKey,
		shortIDs:   shortIDs,
		destDialer: &net.Dialer{Timeout: 10 * time.Second},
	}, nil
}

// HandleConnection handles incoming Reality connection
func (rs *RealityServer) HandleConnection(conn net.Conn) (net.Conn, error) {
	atomic.AddInt64(&rs.stats.TotalConnections, 1)
	atomic.AddInt64(&rs.stats.ActiveConnections, 1)
	defer atomic.AddInt64(&rs.stats.ActiveConnections, -1)

	// Read ClientHello
	clientHello, err := rs.readClientHello(conn)
	if err != nil {
		atomic.AddInt64(&rs.stats.AuthFailures, 1)
		return rs.fallbackToDest(conn, nil)
	}

	// Validate ServerName
	if !rs.isValidServerName(clientHello.ServerName) {
		atomic.AddInt64(&rs.stats.AuthFailures, 1)
		return rs.fallbackToDest(conn, clientHello.Raw)
	}

	// Perform Reality handshake
	authData, err := rs.performHandshake(conn, clientHello)
	if err != nil {
		atomic.AddInt64(&rs.stats.AuthFailures, 1)
		return rs.fallbackToDest(conn, clientHello.Raw)
	}

	// Validate short ID
	if !rs.validateShortID(authData.ShortID) {
		atomic.AddInt64(&rs.stats.AuthFailures, 1)
		return rs.fallbackToDest(conn, clientHello.Raw)
	}

	// Validate timestamp
	if !rs.validateTimestamp(authData.Timestamp) {
		atomic.AddInt64(&rs.stats.AuthFailures, 1)
		return rs.fallbackToDest(conn, clientHello.Raw)
	}

	atomic.AddInt64(&rs.stats.SuccessfulAuths, 1)

	// Return authenticated connection
	return &RealityConn{
		Conn:       conn,
		authData:   authData,
		readBuffer: bytes.NewBuffer(nil),
	}, nil
}

// ClientHelloInfo holds parsed ClientHello information
type ClientHelloInfo struct {
	Raw             []byte
	ServerName      string
	SupportedProtos []string
	SessionID       []byte
	Random          []byte
}

// RealityAuthData holds authentication data
type RealityAuthData struct {
	ShortID   string
	Timestamp int64
	PublicKey []byte
	SharedKey []byte
}

// readClientHello reads and parses TLS ClientHello
func (rs *RealityServer) readClientHello(conn net.Conn) (*ClientHelloInfo, error) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	// Read record header (5 bytes)
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	// Check record type (handshake = 22)
	if header[0] != 22 {
		return nil, errors.New("not a handshake record")
	}

	// Get record length
	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length > 16384 {
		return nil, errors.New("record too large")
	}

	// Read record body
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}

	// Check handshake type (ClientHello = 1)
	if body[0] != 1 {
		return nil, errors.New("not a ClientHello")
	}

	info := &ClientHelloInfo{
		Raw: append(header, body...),
	}

	// Parse ClientHello
	if err := rs.parseClientHello(body, info); err != nil {
		return nil, err
	}

	return info, nil
}

// parseClientHello parses ClientHello message
func (rs *RealityServer) parseClientHello(data []byte, info *ClientHelloInfo) error {
	if len(data) < 38 {
		return errors.New("ClientHello too short")
	}

	// Skip handshake type (1) and length (3)
	pos := 4

	// Skip version (2)
	pos += 2

	// Random (32 bytes)
	info.Random = make([]byte, 32)
	copy(info.Random, data[pos:pos+32])
	pos += 32

	// Session ID length
	if pos >= len(data) {
		return errors.New("invalid ClientHello")
	}
	sessionIDLen := int(data[pos])
	pos++

	// Session ID
	if pos+sessionIDLen > len(data) {
		return errors.New("invalid session ID")
	}
	info.SessionID = make([]byte, sessionIDLen)
	copy(info.SessionID, data[pos:pos+sessionIDLen])
	pos += sessionIDLen

	// Skip cipher suites
	if pos+2 > len(data) {
		return nil
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen

	// Skip compression methods
	if pos >= len(data) {
		return nil
	}
	compressionLen := int(data[pos])
	pos += 1 + compressionLen

	// Parse extensions
	if pos+2 > len(data) {
		return nil
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	endPos := pos + extensionsLen
	if endPos > len(data) {
		endPos = len(data)
	}

	for pos+4 <= endPos {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if pos+extLen > endPos {
			break
		}

		extData := data[pos : pos+extLen]
		pos += extLen

		// SNI extension (type 0)
		if extType == 0 && len(extData) > 5 {
			nameLen := int(binary.BigEndian.Uint16(extData[3:5]))
			if 5+nameLen <= len(extData) {
				info.ServerName = string(extData[5 : 5+nameLen])
			}
		}

		// ALPN extension (type 16)
		if extType == 16 && len(extData) > 2 {
			alpnLen := int(binary.BigEndian.Uint16(extData[0:2]))
			alpnData := extData[2:]
			for i := 0; i < alpnLen && i < len(alpnData); {
				protoLen := int(alpnData[i])
				i++
				if i+protoLen <= len(alpnData) {
					info.SupportedProtos = append(info.SupportedProtos, string(alpnData[i:i+protoLen]))
				}
				i += protoLen
			}
		}
	}

	return nil
}

// isValidServerName checks if ServerName is allowed
func (rs *RealityServer) isValidServerName(sni string) bool {
	for _, name := range rs.config.ServerNames {
		if name == sni {
			return true
		}
		// Wildcard matching
		if strings.HasPrefix(name, "*.") {
			suffix := name[1:] // Remove *
			if strings.HasSuffix(sni, suffix) {
				return true
			}
		}
	}
	return false
}

// performHandshake performs Reality authentication handshake
func (rs *RealityServer) performHandshake(conn net.Conn, hello *ClientHelloInfo) (*RealityAuthData, error) {
	// Extract client's ephemeral public key from ClientHello random
	if len(hello.Random) < 32 {
		return nil, errors.New("invalid random")
	}

	clientPublic := hello.Random[:32]

	// Compute shared secret
	sharedSecret, err := curve25519.X25519(rs.privateKey, clientPublic)
	if err != nil {
		return nil, err
	}

	// Derive authentication key
	authKey := rs.deriveKey(sharedSecret, []byte("reality-auth"))

	// Extract auth data from session ID
	if len(hello.SessionID) < 16 {
		return nil, errors.New("invalid session ID")
	}

	// Decrypt auth data
	authData, err := rs.decryptAuthData(hello.SessionID, authKey)
	if err != nil {
		return nil, err
	}

	authData.PublicKey = clientPublic
	authData.SharedKey = sharedSecret

	return authData, nil
}

// deriveKey derives key using HKDF
func (rs *RealityServer) deriveKey(secret, info []byte) []byte {
	reader := hkdf.New(sha256.New, secret, nil, info)
	key := make([]byte, 32)
	io.ReadFull(reader, key)
	return key
}

// decryptAuthData decrypts authentication data from session ID
func (rs *RealityServer) decryptAuthData(sessionID, key []byte) (*RealityAuthData, error) {
	if len(sessionID) < 16 {
		return nil, errors.New("session ID too short")
	}

	// First 8 bytes: encrypted short ID
	// Next 8 bytes: encrypted timestamp
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, 16)
	block.Decrypt(decrypted[:8], sessionID[:8])
	block.Decrypt(decrypted[8:], sessionID[8:16])

	authData := &RealityAuthData{
		ShortID:   hex.EncodeToString(decrypted[:8]),
		Timestamp: int64(binary.BigEndian.Uint64(decrypted[8:])),
	}

	return authData, nil
}

// validateShortID validates short ID
func (rs *RealityServer) validateShortID(shortID string) bool {
	// Truncate to configured length
	for sid := range rs.shortIDs {
		if strings.HasPrefix(shortID, sid) || strings.HasPrefix(sid, shortID) {
			return true
		}
	}
	return false
}

// validateTimestamp validates timestamp
func (rs *RealityServer) validateTimestamp(timestamp int64) bool {
	now := time.Now().Unix()
	diff := now - timestamp
	if diff < 0 {
		diff = -diff
	}

	maxDiff := rs.config.MaxTimeDiff
	if maxDiff == 0 {
		maxDiff = RealityMaxTimeDiff
	}

	return diff <= maxDiff
}

// fallbackToDest forwards connection to destination
func (rs *RealityServer) fallbackToDest(conn net.Conn, initialData []byte) (net.Conn, error) {
	dest := fmt.Sprintf("%s:%d", rs.config.Dest, rs.config.Port)

	destConn, err := rs.destDialer.Dial("tcp", dest)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Send initial data to destination
	if len(initialData) > 0 {
		destConn.Write(initialData)
	}

	// Bidirectional copy
	go func() {
		io.Copy(destConn, conn)
		destConn.Close()
	}()
	go func() {
		io.Copy(conn, destConn)
		conn.Close()
	}()

	return nil, errors.New("fallback to destination")
}

// GetStats returns Reality server statistics
func (rs *RealityServer) GetStats() RealityStats {
	return RealityStats{
		TotalConnections:  atomic.LoadInt64(&rs.stats.TotalConnections),
		ActiveConnections: atomic.LoadInt64(&rs.stats.ActiveConnections),
		AuthFailures:      atomic.LoadInt64(&rs.stats.AuthFailures),
		SuccessfulAuths:   atomic.LoadInt64(&rs.stats.SuccessfulAuths),
	}
}

// RealityConn wraps authenticated Reality connection
type RealityConn struct {
	net.Conn
	authData   *RealityAuthData
	readBuffer *bytes.Buffer
	mu         sync.Mutex
}

// Read reads from Reality connection
func (rc *RealityConn) Read(b []byte) (int, error) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if rc.readBuffer.Len() > 0 {
		return rc.readBuffer.Read(b)
	}

	return rc.Conn.Read(b)
}

// RealityClient handles Reality protocol client-side
type RealityClient struct {
	config    *RealityTransportConfig
	publicKey []byte
	shortID   []byte
	dialer    *net.Dialer
}

// NewRealityClient creates new Reality client
func NewRealityClient(config *RealityTransportConfig) (*RealityClient, error) {
	if config == nil {
		return nil, errors.New("config is nil")
	}

	// Decode public key
	publicKey, err := base64.RawURLEncoding.DecodeString(config.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	// Decode short ID
	var shortID []byte
	if len(config.ShortIDs) > 0 {
		shortID, err = hex.DecodeString(config.ShortIDs[0])
		if err != nil {
			return nil, fmt.Errorf("invalid short ID: %w", err)
		}
	}

	return &RealityClient{
		config:    config,
		publicKey: publicKey,
		shortID:   shortID,
		dialer:    &net.Dialer{Timeout: 30 * time.Second},
	}, nil
}

// Connect establishes Reality connection
func (rc *RealityClient) Connect(ctx context.Context, address string) (net.Conn, error) {
	// Generate ephemeral key pair
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, err
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	// Compute shared secret
	sharedSecret, err := curve25519.X25519(privateKey, rc.publicKey)
	if err != nil {
		return nil, err
	}

	// Derive auth key
	authKey := rc.deriveKey(sharedSecret, []byte("reality-auth"))

	// Create auth data
	authData := rc.createAuthData(authKey)

	// Build ClientHello
	serverName := rc.config.ServerName
	if serverName == "" && len(rc.config.ServerNames) > 0 {
		serverName = rc.config.ServerNames[mrand.Intn(len(rc.config.ServerNames))]
	}

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}

	// Dial TCP connection
	conn, err := rc.dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}

	// Wrap with custom ClientHello
	tlsConn := &realityClientConn{
		Conn:      conn,
		config:    tlsConfig,
		publicKey: publicKey,
		authData:  authData,
	}

	// Perform handshake
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	return tlsConn, nil
}

func (rc *RealityClient) deriveKey(secret, info []byte) []byte {
	reader := hkdf.New(sha256.New, secret, nil, info)
	key := make([]byte, 32)
	io.ReadFull(reader, key)
	return key
}

func (rc *RealityClient) createAuthData(key []byte) []byte {
	data := make([]byte, 16)

	// Copy short ID (first 8 bytes)
	copy(data[:8], rc.shortID)

	// Set timestamp (last 8 bytes)
	binary.BigEndian.PutUint64(data[8:], uint64(time.Now().Unix()))

	// Encrypt
	block, _ := aes.NewCipher(key)
	encrypted := make([]byte, 16)
	block.Encrypt(encrypted[:8], data[:8])
	block.Encrypt(encrypted[8:], data[8:])

	return encrypted
}

type realityClientConn struct {
	net.Conn
	config    *tls.Config
	publicKey []byte
	authData  []byte
	tlsConn   *tls.Conn
}

func (rcc *realityClientConn) Handshake() error {
	// This is simplified - real implementation needs custom ClientHello builder
	rcc.tlsConn = tls.Client(rcc.Conn, rcc.config)
	return rcc.tlsConn.Handshake()
}

func (rcc *realityClientConn) Read(b []byte) (int, error) {
	if rcc.tlsConn != nil {
		return rcc.tlsConn.Read(b)
	}
	return rcc.Conn.Read(b)
}

func (rcc *realityClientConn) Write(b []byte) (int, error) {
	if rcc.tlsConn != nil {
		return rcc.tlsConn.Write(b)
	}
	return rcc.Conn.Write(b)
}

// ==================== WebSocket Transport ====================

// WebSocketConfig holds WebSocket configuration
type WebSocketConfig struct {
	Path                string            `json:"path"`
	Host                string            `json:"host,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	MaxEarlyData        int               `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string            `json:"early_data_header_name,omitempty"`
	UseBrowserForwarder bool              `json:"use_browser_forwarder,omitempty"`
	AcceptProxyProtocol bool              `json:"accept_proxy_protocol,omitempty"`
}

// WebSocketServer handles WebSocket server connections
type WebSocketServer struct {
	config     *WebSocketConfig
	tlsConfig  *tls.Config
	httpServer *http.Server
	upgrader   ws.HTTPUpgrader
	handler    func(net.Conn)
	mu         sync.RWMutex
	stats      WebSocketStats
}

// WebSocketStats holds WebSocket server statistics
type WebSocketStats struct {
	TotalConnections  int64
	ActiveConnections int64
	BytesSent         int64
	BytesReceived     int64
	UpgradeErrors     int64
}

// NewWebSocketServer creates new WebSocket server
func NewWebSocketServer(config *WebSocketConfig, tlsConfig *tls.Config, handler func(net.Conn)) *WebSocketServer {
	wss := &WebSocketServer{
		config:    config,
		tlsConfig: tlsConfig,
		handler:   handler,
	}

	wss.upgrader = ws.HTTPUpgrader{
		Timeout: 10 * time.Second,
		Header: http.Header{
			"Server": []string{"nginx/1.20.0"},
		},
	}

	return wss
}

// ServeHTTP handles HTTP requests and upgrades to WebSocket
func (wss *WebSocketServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check path
	if wss.config.Path != "" && r.URL.Path != wss.config.Path {
		http.NotFound(w, r)
		return
	}

	// Check host header if configured
	if wss.config.Host != "" {
		host := r.Host
		if colonIdx := strings.Index(host, ":"); colonIdx > 0 {
			host = host[:colonIdx]
		}
		if host != wss.config.Host {
			http.NotFound(w, r)
			return
		}
	}

	// Handle early data
	var earlyData []byte
	if wss.config.MaxEarlyData > 0 && wss.config.EarlyDataHeaderName != "" {
		edHeader := r.Header.Get(wss.config.EarlyDataHeaderName)
		if edHeader != "" {
			var err error
			earlyData, err = base64.RawURLEncoding.DecodeString(edHeader)
			if err != nil {
				earlyData = nil
			}
		}
	}

	// Upgrade to WebSocket
	conn, _, _, err := wss.upgrader.Upgrade(r, w)
	if err != nil {
		atomic.AddInt64(&wss.stats.UpgradeErrors, 1)
		return
	}

	atomic.AddInt64(&wss.stats.TotalConnections, 1)
	atomic.AddInt64(&wss.stats.ActiveConnections, 1)
	defer atomic.AddInt64(&wss.stats.ActiveConnections, -1)

	// Wrap connection
	wsConn := &WebSocketConn{
		Conn:      conn,
		earlyData: earlyData,
		server:    wss,
	}

	// Handle connection
	if wss.handler != nil {
		wss.handler(wsConn)
	}
}

// Listen starts WebSocket server
func (wss *WebSocketServer) Listen(address string) error {
	mux := http.NewServeMux()
	mux.Handle("/", wss)

	wss.httpServer = &http.Server{
		Addr:    address,
		Handler: mux,
	}

	if wss.tlsConfig != nil {
		wss.httpServer.TLSConfig = wss.tlsConfig
		return wss.httpServer.ListenAndServeTLS("", "")
	}

	return wss.httpServer.ListenAndServe()
}

// Close closes the server
func (wss *WebSocketServer) Close() error {
	if wss.httpServer != nil {
		return wss.httpServer.Close()
	}
	return nil
}

// GetStats returns WebSocket server statistics
func (wss *WebSocketServer) GetStats() WebSocketStats {
	return WebSocketStats{
		TotalConnections:  atomic.LoadInt64(&wss.stats.TotalConnections),
		ActiveConnections: atomic.LoadInt64(&wss.stats.ActiveConnections),
		BytesSent:         atomic.LoadInt64(&wss.stats.BytesSent),
		BytesReceived:     atomic.LoadInt64(&wss.stats.BytesReceived),
		UpgradeErrors:     atomic.LoadInt64(&wss.stats.UpgradeErrors),
	}
}

// WebSocketConn wraps WebSocket connection as net.Conn
type WebSocketConn struct {
	net.Conn
	earlyData     []byte
	earlyDataRead bool
	server        *WebSocketServer
	readBuffer    bytes.Buffer
	mu            sync.Mutex
}

// Read reads from WebSocket connection
func (wsc *WebSocketConn) Read(b []byte) (int, error) {
	wsc.mu.Lock()
	defer wsc.mu.Unlock()

	// Return early data first
	if !wsc.earlyDataRead && len(wsc.earlyData) > 0 {
		n := copy(b, wsc.earlyData)
		wsc.earlyData = wsc.earlyData[n:]
		if len(wsc.earlyData) == 0 {
			wsc.earlyDataRead = true
		}
		return n, nil
	}

	// Read from buffer first
	if wsc.readBuffer.Len() > 0 {
		return wsc.readBuffer.Read(b)
	}

	// Read WebSocket frame
	data, op, err := wsutil.ReadClientData(wsc.Conn)
	if err != nil {
		return 0, err
	}

	if op == ws.OpClose {
		return 0, io.EOF
	}

	if wsc.server != nil {
		atomic.AddInt64(&wsc.server.stats.BytesReceived, int64(len(data)))
	}

	// Copy to output buffer
	n := copy(b, data)
	if n < len(data) {
		wsc.readBuffer.Write(data[n:])
	}

	return n, nil
}

// Write writes to WebSocket connection
func (wsc *WebSocketConn) Write(b []byte) (int, error) {
	err := wsutil.WriteServerBinary(wsc.Conn, b)
	if err != nil {
		return 0, err
	}

	if wsc.server != nil {
		atomic.AddInt64(&wsc.server.stats.BytesSent, int64(len(b)))
	}

	return len(b), nil
}

// WebSocketClient handles WebSocket client connections
type WebSocketClient struct {
	config    *WebSocketConfig
	tlsConfig *tls.Config
	dialer    ws.Dialer
}

// NewWebSocketClient creates new WebSocket client
func NewWebSocketClient(config *WebSocketConfig, tlsConfig *tls.Config) *WebSocketClient {
	client := &WebSocketClient{
		config:    config,
		tlsConfig: tlsConfig,
	}

	// Configure dialer
	client.dialer = ws.Dialer{
		Timeout: 30 * time.Second,
		Header: ws.HandshakeHeaderHTTP(http.Header{
			"User-Agent": []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
		}),
	}

	if tlsConfig != nil {
		client.dialer.TLSConfig = tlsConfig
	}

	return client
}

// Connect establishes WebSocket connection
func (wsc *WebSocketClient) Connect(ctx context.Context, address string) (net.Conn, error) {
	// Build URL
	scheme := "ws"
	if wsc.tlsConfig != nil {
		scheme = "wss"
	}

	path := wsc.config.Path
	if path == "" {
		path = "/"
	}

	host := wsc.config.Host
	if host == "" {
		host = address
	}

	wsURL := fmt.Sprintf("%s://%s%s", scheme, host, path)

	// Add headers
	if len(wsc.config.Headers) > 0 {
		header := make(http.Header)
		for k, v := range wsc.config.Headers {
			header.Set(k, v)
		}
		wsc.dialer.Header = ws.HandshakeHeaderHTTP(header)
	}

	// Prepare early data
	var earlyData []byte
	if wsc.config.MaxEarlyData > 0 {
		// Early data will be set by caller
	}

	// Dial TCP first
	netDialer := &net.Dialer{Timeout: 30 * time.Second}
	tcpConn, err := netDialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}

	// Upgrade to WebSocket
	wsc.dialer.NetDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return tcpConn, nil
	}

	conn, _, _, err := wsc.dialer.Dial(ctx, wsURL)
	if err != nil {
		tcpConn.Close()
		return nil, err
	}

	return &WebSocketClientConn{
		Conn:      conn,
		earlyData: earlyData,
	}, nil
}

// ConnectWithEarlyData connects with early data
func (wsc *WebSocketClient) ConnectWithEarlyData(ctx context.Context, address string, earlyData []byte) (net.Conn, error) {
	if wsc.config.MaxEarlyData > 0 && len(earlyData) > 0 && wsc.config.EarlyDataHeaderName != "" {
		if len(earlyData) > wsc.config.MaxEarlyData {
			earlyData = earlyData[:wsc.config.MaxEarlyData]
		}

		if wsc.dialer.Header == nil {
			wsc.dialer.Header = ws.HandshakeHeaderHTTP(http.Header{})
		}

		// Add early data header
		encoded := base64.RawURLEncoding.EncodeToString(earlyData)
		header := wsc.dialer.Header.(ws.HandshakeHeaderHTTP)
		header[wsc.config.EarlyDataHeaderName] = []string{encoded}
	}

	return wsc.Connect(ctx, address)
}

// WebSocketClientConn wraps WebSocket client connection
type WebSocketClientConn struct {
	net.Conn
	earlyData  []byte
	readBuffer bytes.Buffer
	mu         sync.Mutex
}

// Read reads from WebSocket connection
func (wscc *WebSocketClientConn) Read(b []byte) (int, error) {
	wscc.mu.Lock()
	defer wscc.mu.Unlock()

	if wscc.readBuffer.Len() > 0 {
		return wscc.readBuffer.Read(b)
	}

	data, op, err := wsutil.ReadServerData(wscc.Conn)
	if err != nil {
		return 0, err
	}

	if op == ws.OpClose {
		return 0, io.EOF
	}

	n := copy(b, data)
	if n < len(data) {
		wscc.readBuffer.Write(data[n:])
	}

	return n, nil
}

// Write writes to WebSocket connection
func (wscc *WebSocketClientConn) Write(b []byte) (int, error) {
	err := wsutil.WriteClientBinary(wscc.Conn, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// Core/transport.go
// MXUI VPN Panel - Transport Layer
// Part 2: gRPC, HTTP/2, QUIC, HTTPUpgrade, SplitHTTP, Fragment, Mux

// ==================== gRPC Transport ====================

// GRPCConfig holds gRPC configuration
type GRPCConfig struct {
	ServiceName         string            `json:"service_name"`
	Host                string            `json:"host,omitempty"`
	MultiMode           bool              `json:"multi_mode"`
	IdleTimeout         int               `json:"idle_timeout,omitempty"`
	HealthCheckTimeout  int               `json:"health_check_timeout,omitempty"`
	PermitWithoutStream bool              `json:"permit_without_stream,omitempty"`
	InitialWindowSize   int               `json:"initial_window_size,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	UserAgent           string            `json:"user_agent,omitempty"`
}

// GRPCServer handles gRPC server connections
type GRPCServer struct {
	config     *GRPCConfig
	tlsConfig  *tls.Config
	grpcServer *grpc.Server
	handler    func(net.Conn)
	listener   net.Listener
	mu         sync.RWMutex
	stats      GRPCStats
	stopChan   chan struct{}
}

// GRPCStats holds gRPC server statistics
type GRPCStats struct {
	TotalConnections  int64
	ActiveConnections int64
	TotalStreams      int64
	ActiveStreams     int64
	BytesSent         int64
	BytesReceived     int64
}

// NewGRPCServer creates new gRPC server
func NewGRPCServer(config *GRPCConfig, tlsConfig *tls.Config, handler func(net.Conn)) *GRPCServer {
	gs := &GRPCServer{
		config:    config,
		tlsConfig: tlsConfig,
		handler:   handler,
		stopChan:  make(chan struct{}),
	}

	// Build gRPC server options
	var opts []grpc.ServerOption

	if tlsConfig != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	// Set window size
	if config.InitialWindowSize > 0 {
		opts = append(opts, grpc.InitialWindowSize(int32(config.InitialWindowSize)))
		opts = append(opts, grpc.InitialConnWindowSize(int32(config.InitialWindowSize)))
	}

	// Create gRPC server
	gs.grpcServer = grpc.NewServer(opts...)

	// Register service
	gs.registerService()

	return gs
}

// GRPCTunnelService implements gRPC tunnel service
type GRPCTunnelService struct {
	server *GRPCServer
}

// Tun handles bidirectional tunnel stream
func (gts *GRPCTunnelService) Tun(stream grpc.ServerStream) error {
	atomic.AddInt64(&gts.server.stats.TotalStreams, 1)
	atomic.AddInt64(&gts.server.stats.ActiveStreams, 1)
	defer atomic.AddInt64(&gts.server.stats.ActiveStreams, -1)

	// Wrap stream as net.Conn
	conn := &GRPCStreamConn{
		stream:     stream,
		server:     gts.server,
		readBuffer: bytes.NewBuffer(nil),
	}

	// Handle connection
	if gts.server.handler != nil {
		gts.server.handler(conn)
	}

	return nil
}

// registerService registers gRPC service
func (gs *GRPCServer) registerService() {
	// Register custom service
	serviceName := gs.config.ServiceName
	if serviceName == "" {
		serviceName = "GunService"
	}

	// Note: In real implementation, you'd use protobuf-generated code
	// This is a simplified version
}

// Listen starts gRPC server
func (gs *GRPCServer) Listen(address string) error {
	var err error
	gs.listener, err = net.Listen("tcp", address)
	if err != nil {
		return err
	}

	return gs.grpcServer.Serve(gs.listener)
}

// Close closes the server
func (gs *GRPCServer) Close() error {
	close(gs.stopChan)
	gs.grpcServer.GracefulStop()
	if gs.listener != nil {
		return gs.listener.Close()
	}
	return nil
}

// GetStats returns gRPC server statistics
func (gs *GRPCServer) GetStats() GRPCStats {
	return GRPCStats{
		TotalConnections:  atomic.LoadInt64(&gs.stats.TotalConnections),
		ActiveConnections: atomic.LoadInt64(&gs.stats.ActiveConnections),
		TotalStreams:      atomic.LoadInt64(&gs.stats.TotalStreams),
		ActiveStreams:     atomic.LoadInt64(&gs.stats.ActiveStreams),
		BytesSent:         atomic.LoadInt64(&gs.stats.BytesSent),
		BytesReceived:     atomic.LoadInt64(&gs.stats.BytesReceived),
	}
}

// GRPCStreamConn wraps gRPC stream as net.Conn
type GRPCStreamConn struct {
	stream        grpc.ServerStream
	server        *GRPCServer
	readBuffer    *bytes.Buffer
	localAddr     net.Addr
	remoteAddr    net.Addr
	mu            sync.Mutex
	closed        bool
	readDeadline  time.Time
	writeDeadline time.Time
}

// Read reads from gRPC stream
func (gsc *GRPCStreamConn) Read(b []byte) (int, error) {
	gsc.mu.Lock()
	defer gsc.mu.Unlock()

	if gsc.closed {
		return 0, io.EOF
	}

	// Read from buffer first
	if gsc.readBuffer.Len() > 0 {
		return gsc.readBuffer.Read(b)
	}

	// Read from stream
	var msg []byte
	if err := gsc.stream.RecvMsg(&msg); err != nil {
		return 0, err
	}

	if gsc.server != nil {
		atomic.AddInt64(&gsc.server.stats.BytesReceived, int64(len(msg)))
	}

	n := copy(b, msg)
	if n < len(msg) {
		gsc.readBuffer.Write(msg[n:])
	}

	return n, nil
}

// Write writes to gRPC stream
func (gsc *GRPCStreamConn) Write(b []byte) (int, error) {
	gsc.mu.Lock()
	defer gsc.mu.Unlock()

	if gsc.closed {
		return 0, errors.New("connection closed")
	}

	if err := gsc.stream.SendMsg(b); err != nil {
		return 0, err
	}

	if gsc.server != nil {
		atomic.AddInt64(&gsc.server.stats.BytesSent, int64(len(b)))
	}

	return len(b), nil
}

// Close closes the connection
func (gsc *GRPCStreamConn) Close() error {
	gsc.mu.Lock()
	defer gsc.mu.Unlock()
	gsc.closed = true
	return nil
}

// LocalAddr returns local address
func (gsc *GRPCStreamConn) LocalAddr() net.Addr {
	if gsc.localAddr != nil {
		return gsc.localAddr
	}
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// RemoteAddr returns remote address
func (gsc *GRPCStreamConn) RemoteAddr() net.Addr {
	if gsc.remoteAddr != nil {
		return gsc.remoteAddr
	}
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// SetDeadline sets read and write deadlines
func (gsc *GRPCStreamConn) SetDeadline(t time.Time) error {
	gsc.readDeadline = t
	gsc.writeDeadline = t
	return nil
}

// SetReadDeadline sets read deadline
func (gsc *GRPCStreamConn) SetReadDeadline(t time.Time) error {
	gsc.readDeadline = t
	return nil
}

// SetWriteDeadline sets write deadline
func (gsc *GRPCStreamConn) SetWriteDeadline(t time.Time) error {
	gsc.writeDeadline = t
	return nil
}

// GRPCClient handles gRPC client connections
type GRPCClient struct {
	config    *GRPCConfig
	tlsConfig *tls.Config
	conn      *grpc.ClientConn
	mu        sync.Mutex
}

// NewGRPCClient creates new gRPC client
func NewGRPCClient(config *GRPCConfig, tlsConfig *tls.Config) *GRPCClient {
	return &GRPCClient{
		config:    config,
		tlsConfig: tlsConfig,
	}
}

// Connect establishes gRPC connection
func (gc *GRPCClient) Connect(ctx context.Context, address string) (net.Conn, error) {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	// Build dial options
	var opts []grpc.DialOption

	if gc.tlsConfig != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(gc.tlsConfig)))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}

	// User agent
	userAgent := gc.config.UserAgent
	if userAgent == "" {
		userAgent = "grpc-go/1.50.0"
	}
	opts = append(opts, grpc.WithUserAgent(userAgent))

	// Window size
	if gc.config.InitialWindowSize > 0 {
		opts = append(opts, grpc.WithInitialWindowSize(int32(gc.config.InitialWindowSize)))
		opts = append(opts, grpc.WithInitialConnWindowSize(int32(gc.config.InitialWindowSize)))
	}

	// Dial
	conn, err := grpc.DialContext(ctx, address, opts...)
	if err != nil {
		return nil, err
	}

	gc.conn = conn

	// Create stream
	serviceName := gc.config.ServiceName
	if serviceName == "" {
		serviceName = "GunService"
	}

	streamDesc := &grpc.StreamDesc{
		StreamName:    "Tun",
		ServerStreams: true,
		ClientStreams: true,
	}

	stream, err := conn.NewStream(ctx, streamDesc, "/"+serviceName+"/Tun")
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &GRPCClientConn{
		stream:     stream,
		conn:       conn,
		readBuffer: bytes.NewBuffer(nil),
	}, nil
}

// Close closes the client
func (gc *GRPCClient) Close() error {
	gc.mu.Lock()
	defer gc.mu.Unlock()
	if gc.conn != nil {
		return gc.conn.Close()
	}
	return nil
}

// GRPCClientConn wraps gRPC client stream as net.Conn
type GRPCClientConn struct {
	stream     grpc.ClientStream
	conn       *grpc.ClientConn
	readBuffer *bytes.Buffer
	mu         sync.Mutex
	closed     bool
}

// Read reads from gRPC stream
func (gcc *GRPCClientConn) Read(b []byte) (int, error) {
	gcc.mu.Lock()
	defer gcc.mu.Unlock()

	if gcc.closed {
		return 0, io.EOF
	}

	if gcc.readBuffer.Len() > 0 {
		return gcc.readBuffer.Read(b)
	}

	var msg []byte
	if err := gcc.stream.RecvMsg(&msg); err != nil {
		return 0, err
	}

	n := copy(b, msg)
	if n < len(msg) {
		gcc.readBuffer.Write(msg[n:])
	}

	return n, nil
}

// Write writes to gRPC stream
func (gcc *GRPCClientConn) Write(b []byte) (int, error) {
	gcc.mu.Lock()
	defer gcc.mu.Unlock()

	if gcc.closed {
		return 0, errors.New("connection closed")
	}

	if err := gcc.stream.SendMsg(b); err != nil {
		return 0, err
	}

	return len(b), nil
}

// Close closes the connection
func (gcc *GRPCClientConn) Close() error {
	gcc.mu.Lock()
	defer gcc.mu.Unlock()
	gcc.closed = true
	gcc.stream.CloseSend()
	return gcc.conn.Close()
}

// LocalAddr returns local address
func (gcc *GRPCClientConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// RemoteAddr returns remote address
func (gcc *GRPCClientConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// SetDeadline sets deadlines
func (gcc *GRPCClientConn) SetDeadline(t time.Time) error      { return nil }
func (gcc *GRPCClientConn) SetReadDeadline(t time.Time) error  { return nil }
func (gcc *GRPCClientConn) SetWriteDeadline(t time.Time) error { return nil }

// ==================== HTTP/2 Transport ====================

// HTTP2Config holds HTTP/2 configuration
type HTTP2Config struct {
	Host               string            `json:"host,omitempty"`
	Path               string            `json:"path,omitempty"`
	Method             string            `json:"method,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
	ReadIdleTimeout    int               `json:"read_idle_timeout,omitempty"`
	HealthCheckTimeout int               `json:"health_check_timeout,omitempty"`
	NoGRPCWeb          bool              `json:"no_grpc_web,omitempty"`
	InitialWindowSize  uint32            `json:"initial_window_size,omitempty"`
	MaxFrameSize       uint32            `json:"max_frame_size,omitempty"`
	MaxHeaderListSize  uint32            `json:"max_header_list_size,omitempty"`
}

// HTTP2Server handles HTTP/2 server connections
type HTTP2Server struct {
	config     *HTTP2Config
	tlsConfig  *tls.Config
	handler    func(net.Conn)
	httpServer *http.Server
	mu         sync.RWMutex
	stats      HTTP2Stats
}

// HTTP2Stats holds HTTP/2 server statistics
type HTTP2Stats struct {
	TotalConnections  int64
	ActiveConnections int64
	TotalRequests     int64
	BytesSent         int64
	BytesReceived     int64
}

// NewHTTP2Server creates new HTTP/2 server
func NewHTTP2Server(config *HTTP2Config, tlsConfig *tls.Config, handler func(net.Conn)) *HTTP2Server {
	h2s := &HTTP2Server{
		config:    config,
		tlsConfig: tlsConfig,
		handler:   handler,
	}

	return h2s
}

// ServeHTTP handles HTTP/2 requests
func (h2s *HTTP2Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check path
	if h2s.config.Path != "" && r.URL.Path != h2s.config.Path {
		http.NotFound(w, r)
		return
	}

	// Check method
	method := h2s.config.Method
	if method == "" {
		method = "PUT"
	}
	if r.Method != method && method != "*" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	atomic.AddInt64(&h2s.stats.TotalConnections, 1)
	atomic.AddInt64(&h2s.stats.ActiveConnections, 1)
	atomic.AddInt64(&h2s.stats.TotalRequests, 1)
	defer atomic.AddInt64(&h2s.stats.ActiveConnections, -1)

	// Hijack connection for bidirectional streaming
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		// Use streaming approach instead
		h2s.handleStreaming(w, r)
		return
	}

	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	// Wrap connection
	h2Conn := &HTTP2Conn{
		Conn:   conn,
		bufrw:  bufrw,
		server: h2s,
	}

	if h2s.handler != nil {
		h2s.handler(h2Conn)
	}
}

// handleStreaming handles HTTP/2 streaming without hijacking
func (h2s *HTTP2Server) handleStreaming(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Set headers for streaming
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Create streaming connection
	conn := &HTTP2StreamConn{
		request:  r,
		response: w,
		flusher:  flusher,
		server:   h2s,
		done:     make(chan struct{}),
	}

	if h2s.handler != nil {
		h2s.handler(conn)
	}
}

// Listen starts HTTP/2 server
func (h2s *HTTP2Server) Listen(address string) error {
	mux := http.NewServeMux()
	path := h2s.config.Path
	if path == "" {
		path = "/"
	}
	mux.Handle(path, h2s)

	h2s.httpServer = &http.Server{
		Addr:    address,
		Handler: mux,
	}

	// Configure HTTP/2
	if h2s.tlsConfig != nil {
		h2s.tlsConfig.NextProtos = []string{"h2", "http/1.1"}
		h2s.httpServer.TLSConfig = h2s.tlsConfig

		http2.ConfigureServer(h2s.httpServer, &http2.Server{
			MaxReadFrameSize: h2s.config.MaxFrameSize,
			IdleTimeout:      time.Duration(h2s.config.ReadIdleTimeout) * time.Second,
		})

		return h2s.httpServer.ListenAndServeTLS("", "")
	}

	// HTTP/2 cleartext (h2c) - simplified handler
	h2Server := &http2.Server{}
	_ = h2Server // h2c handler would use this
	h2s.httpServer.Handler = mux

	return h2s.httpServer.ListenAndServe()
}

// Close closes the server
func (h2s *HTTP2Server) Close() error {
	if h2s.httpServer != nil {
		return h2s.httpServer.Close()
	}
	return nil
}

// GetStats returns HTTP/2 server statistics
func (h2s *HTTP2Server) GetStats() HTTP2Stats {
	return HTTP2Stats{
		TotalConnections:  atomic.LoadInt64(&h2s.stats.TotalConnections),
		ActiveConnections: atomic.LoadInt64(&h2s.stats.ActiveConnections),
		TotalRequests:     atomic.LoadInt64(&h2s.stats.TotalRequests),
		BytesSent:         atomic.LoadInt64(&h2s.stats.BytesSent),
		BytesReceived:     atomic.LoadInt64(&h2s.stats.BytesReceived),
	}
}

// HTTP2Conn wraps HTTP/2 hijacked connection
type HTTP2Conn struct {
	net.Conn
	bufrw  *bufio.ReadWriter
	server *HTTP2Server
}

// Read reads from HTTP/2 connection
func (h2c *HTTP2Conn) Read(b []byte) (int, error) {
	n, err := h2c.bufrw.Read(b)
	if h2c.server != nil && n > 0 {
		atomic.AddInt64(&h2c.server.stats.BytesReceived, int64(n))
	}
	return n, err
}

// Write writes to HTTP/2 connection
func (h2c *HTTP2Conn) Write(b []byte) (int, error) {
	n, err := h2c.bufrw.Write(b)
	if err != nil {
		return n, err
	}
	err = h2c.bufrw.Flush()
	if h2c.server != nil && n > 0 {
		atomic.AddInt64(&h2c.server.stats.BytesSent, int64(n))
	}
	return n, err
}

// HTTP2StreamConn wraps HTTP/2 streaming connection
type HTTP2StreamConn struct {
	request    *http.Request
	response   http.ResponseWriter
	flusher    http.Flusher
	server     *HTTP2Server
	readBuffer bytes.Buffer
	done       chan struct{}
	mu         sync.Mutex
	closed     bool
}

// Read reads from HTTP/2 stream
func (h2sc *HTTP2StreamConn) Read(b []byte) (int, error) {
	h2sc.mu.Lock()
	defer h2sc.mu.Unlock()

	if h2sc.closed {
		return 0, io.EOF
	}

	if h2sc.readBuffer.Len() > 0 {
		return h2sc.readBuffer.Read(b)
	}

	n, err := h2sc.request.Body.Read(b)
	if h2sc.server != nil && n > 0 {
		atomic.AddInt64(&h2sc.server.stats.BytesReceived, int64(n))
	}
	return n, err
}

// Write writes to HTTP/2 stream
func (h2sc *HTTP2StreamConn) Write(b []byte) (int, error) {
	h2sc.mu.Lock()
	defer h2sc.mu.Unlock()

	if h2sc.closed {
		return 0, errors.New("connection closed")
	}

	n, err := h2sc.response.Write(b)
	if err != nil {
		return n, err
	}
	h2sc.flusher.Flush()

	if h2sc.server != nil && n > 0 {
		atomic.AddInt64(&h2sc.server.stats.BytesSent, int64(n))
	}
	return n, nil
}

// Close closes the connection
func (h2sc *HTTP2StreamConn) Close() error {
	h2sc.mu.Lock()
	defer h2sc.mu.Unlock()
	h2sc.closed = true
	close(h2sc.done)
	return h2sc.request.Body.Close()
}

// LocalAddr returns local address
func (h2sc *HTTP2StreamConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// RemoteAddr returns remote address
func (h2sc *HTTP2StreamConn) RemoteAddr() net.Addr {
	addr := h2sc.request.RemoteAddr
	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	return &net.TCPAddr{IP: net.ParseIP(host), Port: p}
}

// SetDeadline sets deadlines
func (h2sc *HTTP2StreamConn) SetDeadline(t time.Time) error      { return nil }
func (h2sc *HTTP2StreamConn) SetReadDeadline(t time.Time) error  { return nil }
func (h2sc *HTTP2StreamConn) SetWriteDeadline(t time.Time) error { return nil }

// HTTP2Client handles HTTP/2 client connections
type HTTP2Client struct {
	config     *HTTP2Config
	tlsConfig  *tls.Config
	httpClient *http.Client
	transport  *http2.Transport
}

// NewHTTP2Client creates new HTTP/2 client
func NewHTTP2Client(config *HTTP2Config, tlsConfig *tls.Config) *HTTP2Client {
	h2c := &HTTP2Client{
		config:    config,
		tlsConfig: tlsConfig,
	}

	h2c.transport = &http2.Transport{
		TLSClientConfig: tlsConfig,
		AllowHTTP:       tlsConfig == nil,
	}

	h2c.httpClient = &http.Client{
		Transport: h2c.transport,
		Timeout:   0, // No timeout for streaming
	}

	return h2c
}

// Connect establishes HTTP/2 connection
func (h2c *HTTP2Client) Connect(ctx context.Context, address string) (net.Conn, error) {
	// Build URL
	scheme := "https"
	if h2c.tlsConfig == nil {
		scheme = "http"
	}

	path := h2c.config.Path
	if path == "" {
		path = "/"
	}

	host := h2c.config.Host
	if host == "" {
		host = address
	}

	urlStr := fmt.Sprintf("%s://%s%s", scheme, host, path)

	// Create pipe for bidirectional communication
	clientReader, clientWriter := io.Pipe()
	serverReader, serverWriter := io.Pipe()

	// Build request
	method := h2c.config.Method
	if method == "" {
		method = "PUT"
	}

	req, err := http.NewRequestWithContext(ctx, method, urlStr, clientReader)
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/grpc")
	for k, v := range h2c.config.Headers {
		req.Header.Set(k, v)
	}

	// Start request in goroutine
	go func() {
		resp, err := h2c.httpClient.Do(req)
		if err != nil {
			serverWriter.CloseWithError(err)
			return
		}
		defer resp.Body.Close()

		io.Copy(serverWriter, resp.Body)
		serverWriter.Close()
	}()

	return &HTTP2ClientConn{
		reader: serverReader,
		writer: clientWriter,
	}, nil
}

// Close closes the client
func (h2c *HTTP2Client) Close() error {
	h2c.httpClient.CloseIdleConnections()
	return nil
}

// HTTP2ClientConn wraps HTTP/2 client connection
type HTTP2ClientConn struct {
	reader *io.PipeReader
	writer *io.PipeWriter
	mu     sync.Mutex
	closed bool
}

// Read reads from HTTP/2 connection
func (h2cc *HTTP2ClientConn) Read(b []byte) (int, error) {
	return h2cc.reader.Read(b)
}

// Write writes to HTTP/2 connection
func (h2cc *HTTP2ClientConn) Write(b []byte) (int, error) {
	return h2cc.writer.Write(b)
}

// Close closes the connection
func (h2cc *HTTP2ClientConn) Close() error {
	h2cc.mu.Lock()
	defer h2cc.mu.Unlock()
	h2cc.closed = true
	h2cc.reader.Close()
	h2cc.writer.Close()
	return nil
}

// LocalAddr returns local address
func (h2cc *HTTP2ClientConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// RemoteAddr returns remote address
func (h2cc *HTTP2ClientConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// SetDeadline sets deadlines
func (h2cc *HTTP2ClientConn) SetDeadline(t time.Time) error      { return nil }
func (h2cc *HTTP2ClientConn) SetReadDeadline(t time.Time) error  { return nil }
func (h2cc *HTTP2ClientConn) SetWriteDeadline(t time.Time) error { return nil }

// h2c package placeholder for HTTP/2 cleartext
type h2c struct{}

func (h2c) NewHandler(h http.Handler, s *http2.Server) http.Handler {
	return h // Simplified - real implementation handles h2c upgrade
}

// ==================== QUIC Transport ====================

// QUICConfig holds QUIC configuration
type QUICConfig struct {
	Header              map[string]string `json:"header,omitempty"`
	Security            string            `json:"security,omitempty"`
	Key                 string            `json:"key,omitempty"`
	MaxIdleTimeout      int               `json:"max_idle_timeout,omitempty"`
	MaxIncomingStreams  int               `json:"max_incoming_streams,omitempty"`
	DisablePathMTU      bool              `json:"disable_path_mtu,omitempty"`
	InitialStreamWindow uint64            `json:"initial_stream_window,omitempty"`
	InitialConnWindow   uint64            `json:"initial_conn_window,omitempty"`
}

// QUICServer handles QUIC server connections
type QUICServer struct {
	config    *QUICConfig
	tlsConfig *tls.Config
	handler   func(net.Conn)
	listener  interface{} // quic.Listener
	mu        sync.RWMutex
	stats     QUICStats
	stopChan  chan struct{}
}

// QUICStats holds QUIC server statistics
type QUICStats struct {
	TotalConnections  int64
	ActiveConnections int64
	TotalStreams      int64
	ActiveStreams     int64
	BytesSent         int64
	BytesReceived     int64
	PacketsLost       int64
	RTT               int64 // microseconds
}

// NewQUICServer creates new QUIC server
func NewQUICServer(config *QUICConfig, tlsConfig *tls.Config, handler func(net.Conn)) *QUICServer {
	return &QUICServer{
		config:    config,
		tlsConfig: tlsConfig,
		handler:   handler,
		stopChan:  make(chan struct{}),
	}
}

// Listen starts QUIC server
func (qs *QUICServer) Listen(address string) error {
	// Note: This requires github.com/quic-go/quic-go
	// This is a placeholder implementation

	/*
		quicConfig := &quic.Config{
			MaxIdleTimeout:        time.Duration(qs.config.MaxIdleTimeout) * time.Second,
			MaxIncomingStreams:    int64(qs.config.MaxIncomingStreams),
			DisablePathMTUDiscovery: qs.config.DisablePathMTU,
			InitialStreamReceiveWindow: qs.config.InitialStreamWindow,
			InitialConnectionReceiveWindow: qs.config.InitialConnWindow,
		}

		listener, err := quic.ListenAddr(address, qs.tlsConfig, quicConfig)
		if err != nil {
			return err
		}
		qs.listener = listener

		for {
			select {
			case <-qs.stopChan:
				return nil
			default:
				conn, err := listener.Accept(context.Background())
				if err != nil {
					continue
				}

				go qs.handleConnection(conn)
			}
		}
	*/

	return errors.New("QUIC not implemented - requires quic-go")
}

// Close closes the server
func (qs *QUICServer) Close() error {
	close(qs.stopChan)
	return nil
}

// GetStats returns QUIC server statistics
func (qs *QUICServer) GetStats() QUICStats {
	return QUICStats{
		TotalConnections:  atomic.LoadInt64(&qs.stats.TotalConnections),
		ActiveConnections: atomic.LoadInt64(&qs.stats.ActiveConnections),
		TotalStreams:      atomic.LoadInt64(&qs.stats.TotalStreams),
		ActiveStreams:     atomic.LoadInt64(&qs.stats.ActiveStreams),
		BytesSent:         atomic.LoadInt64(&qs.stats.BytesSent),
		BytesReceived:     atomic.LoadInt64(&qs.stats.BytesReceived),
	}
}

// QUICClient handles QUIC client connections
type QUICClient struct {
	config    *QUICConfig
	tlsConfig *tls.Config
}

// NewQUICClient creates new QUIC client
func NewQUICClient(config *QUICConfig, tlsConfig *tls.Config) *QUICClient {
	return &QUICClient{
		config:    config,
		tlsConfig: tlsConfig,
	}
}

// Connect establishes QUIC connection
func (qc *QUICClient) Connect(ctx context.Context, address string) (net.Conn, error) {
	// Placeholder - requires quic-go implementation
	return nil, errors.New("QUIC not implemented - requires quic-go")
}

// ==================== HTTPUpgrade Transport ====================

// HTTPUpgradeConfig holds HTTPUpgrade configuration
type HTTPUpgradeConfig struct {
	Host                string            `json:"host,omitempty"`
	Path                string            `json:"path,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	AcceptProxyProtocol bool              `json:"accept_proxy_protocol,omitempty"`
}

// HTTPUpgradeServer handles HTTPUpgrade server connections
type HTTPUpgradeServer struct {
	config     *HTTPUpgradeConfig
	tlsConfig  *tls.Config
	handler    func(net.Conn)
	httpServer *http.Server
	mu         sync.RWMutex
	stats      HTTPUpgradeStats
}

// HTTPUpgradeStats holds HTTPUpgrade server statistics
type HTTPUpgradeStats struct {
	TotalConnections  int64
	ActiveConnections int64
	UpgradeErrors     int64
	BytesSent         int64
	BytesReceived     int64
}

// NewHTTPUpgradeServer creates new HTTPUpgrade server
func NewHTTPUpgradeServer(config *HTTPUpgradeConfig, tlsConfig *tls.Config, handler func(net.Conn)) *HTTPUpgradeServer {
	return &HTTPUpgradeServer{
		config:    config,
		tlsConfig: tlsConfig,
		handler:   handler,
	}
}

// ServeHTTP handles HTTP requests and upgrades
func (hus *HTTPUpgradeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check path
	if hus.config.Path != "" && r.URL.Path != hus.config.Path {
		http.NotFound(w, r)
		return
	}

	// Check for upgrade header
	if r.Header.Get("Upgrade") != "websocket" && r.Header.Get("Connection") != "Upgrade" {
		// Return as regular HTTP for camouflage
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!DOCTYPE html><html><body><h1>Welcome</h1></body></html>"))
		return
	}

	// Hijack connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		atomic.AddInt64(&hus.stats.UpgradeErrors, 1)
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		atomic.AddInt64(&hus.stats.UpgradeErrors, 1)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	atomic.AddInt64(&hus.stats.TotalConnections, 1)
	atomic.AddInt64(&hus.stats.ActiveConnections, 1)

	// Send upgrade response
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n\r\n"

	bufrw.WriteString(response)
	bufrw.Flush()

	// Wrap connection
	upgradeConn := &HTTPUpgradeConn{
		Conn:   conn,
		bufrw:  bufrw,
		server: hus,
	}

	// Handle connection
	go func() {
		defer atomic.AddInt64(&hus.stats.ActiveConnections, -1)
		defer conn.Close()
		if hus.handler != nil {
			hus.handler(upgradeConn)
		}
	}()
}

// Listen starts HTTPUpgrade server
func (hus *HTTPUpgradeServer) Listen(address string) error {
	mux := http.NewServeMux()
	path := hus.config.Path
	if path == "" {
		path = "/"
	}
	mux.Handle(path, hus)

	hus.httpServer = &http.Server{
		Addr:    address,
		Handler: mux,
	}

	if hus.tlsConfig != nil {
		hus.httpServer.TLSConfig = hus.tlsConfig
		return hus.httpServer.ListenAndServeTLS("", "")
	}

	return hus.httpServer.ListenAndServe()
}

// Close closes the server
func (hus *HTTPUpgradeServer) Close() error {
	if hus.httpServer != nil {
		return hus.httpServer.Close()
	}
	return nil
}

// GetStats returns HTTPUpgrade server statistics
func (hus *HTTPUpgradeServer) GetStats() HTTPUpgradeStats {
	return HTTPUpgradeStats{
		TotalConnections:  atomic.LoadInt64(&hus.stats.TotalConnections),
		ActiveConnections: atomic.LoadInt64(&hus.stats.ActiveConnections),
		UpgradeErrors:     atomic.LoadInt64(&hus.stats.UpgradeErrors),
		BytesSent:         atomic.LoadInt64(&hus.stats.BytesSent),
		BytesReceived:     atomic.LoadInt64(&hus.stats.BytesReceived),
	}
}

// HTTPUpgradeConn wraps HTTPUpgrade connection
type HTTPUpgradeConn struct {
	net.Conn
	bufrw  *bufio.ReadWriter
	server *HTTPUpgradeServer
}

// Read reads from connection
func (huc *HTTPUpgradeConn) Read(b []byte) (int, error) {
	n, err := huc.bufrw.Read(b)
	if huc.server != nil && n > 0 {
		atomic.AddInt64(&huc.server.stats.BytesReceived, int64(n))
	}
	return n, err
}

// Write writes to connection
func (huc *HTTPUpgradeConn) Write(b []byte) (int, error) {
	n, err := huc.bufrw.Write(b)
	if err != nil {
		return n, err
	}
	err = huc.bufrw.Flush()
	if huc.server != nil && n > 0 {
		atomic.AddInt64(&huc.server.stats.BytesSent, int64(n))
	}
	return n, err
}

// HTTPUpgradeClient handles HTTPUpgrade client connections
type HTTPUpgradeClient struct {
	config    *HTTPUpgradeConfig
	tlsConfig *tls.Config
}

// NewHTTPUpgradeClient creates new HTTPUpgrade client
func NewHTTPUpgradeClient(config *HTTPUpgradeConfig, tlsConfig *tls.Config) *HTTPUpgradeClient {
	return &HTTPUpgradeClient{
		config:    config,
		tlsConfig: tlsConfig,
	}
}

// Connect establishes HTTPUpgrade connection
func (huc *HTTPUpgradeClient) Connect(ctx context.Context, address string) (net.Conn, error) {
	// Dial TCP
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}

	// Wrap with TLS if configured
	if huc.tlsConfig != nil {
		tlsConn := tls.Client(conn, huc.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tlsConn
	}

	// Build upgrade request
	host := huc.config.Host
	if host == "" {
		host = address
	}

	path := huc.config.Path
	if path == "" {
		path = "/"
	}

	request := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n",
		path, host, generateWebSocketKey())

	// Add custom headers
	for k, v := range huc.config.Headers {
		request += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	request += "\r\n"

	// Send request
	if _, err := conn.Write([]byte(request)); err != nil {
		conn.Close()
		return nil, err
	}

	// Read response
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}

	if !strings.Contains(statusLine, "101") {
		conn.Close()
		return nil, fmt.Errorf("upgrade failed: %s", statusLine)
	}

	// Read headers until empty line
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	return &HTTPUpgradeClientConn{
		Conn:   conn,
		reader: reader,
	}, nil
}

// HTTPUpgradeClientConn wraps HTTPUpgrade client connection
type HTTPUpgradeClientConn struct {
	net.Conn
	reader *bufio.Reader
}

// Read reads from connection
func (hucc *HTTPUpgradeClientConn) Read(b []byte) (int, error) {
	return hucc.reader.Read(b)
}

// generateWebSocketKey generates random WebSocket key
func generateWebSocketKey() string {
	key := make([]byte, 16)
	rand.Read(key)
	return base64.StdEncoding.EncodeToString(key)
}

// ==================== SplitHTTP Transport ====================

// SplitHTTPConfig holds SplitHTTP configuration
type SplitHTTPConfig struct {
	Host                 string            `json:"host,omitempty"`
	Path                 string            `json:"path,omitempty"`
	Headers              map[string]string `json:"headers,omitempty"`
	MaxUploadSize        int               `json:"max_upload_size,omitempty"`
	MaxConcurrentUploads int               `json:"max_concurrent_uploads,omitempty"`
	MinUploadInterval    int               `json:"min_upload_interval,omitempty"`
	MaxUploadInterval    int               `json:"max_upload_interval,omitempty"`
	DownloadBufferSize   int               `json:"download_buffer_size,omitempty"`
	NoGRPCWeb            bool              `json:"no_grpc_web,omitempty"`
	XPaddingBytes        *RangeConfig      `json:"x_padding_bytes,omitempty"`
	XRealPath            *RangeConfig      `json:"x_real_path,omitempty"`
}

// RangeConfig holds range configuration
type RangeConfig struct {
	From int `json:"from"`
	To   int `json:"to"`
}

// SplitHTTPServer handles SplitHTTP server connections
type SplitHTTPServer struct {
	config     *SplitHTTPConfig
	tlsConfig  *tls.Config
	handler    func(net.Conn)
	httpServer *http.Server
	sessions   sync.Map // sessionID -> *SplitHTTPSession
	mu         sync.RWMutex
	stats      SplitHTTPStats
}

// SplitHTTPStats holds SplitHTTP server statistics
type SplitHTTPStats struct {
	TotalSessions   int64
	ActiveSessions  int64
	TotalUploads    int64
	TotalDownloads  int64
	BytesUploaded   int64
	BytesDownloaded int64
}

// SplitHTTPSession represents a SplitHTTP session
type SplitHTTPSession struct {
	ID           string
	uploadChan   chan []byte
	downloadChan chan []byte
	readBuffer   bytes.Buffer
	writeBuffer  bytes.Buffer
	mu           sync.Mutex
	created      time.Time
	lastActivity time.Time
	closed       bool
}

// NewSplitHTTPServer creates new SplitHTTP server
func NewSplitHTTPServer(config *SplitHTTPConfig, tlsConfig *tls.Config, handler func(net.Conn)) *SplitHTTPServer {
	return &SplitHTTPServer{
		config:    config,
		tlsConfig: tlsConfig,
		handler:   handler,
	}
}

// ServeHTTP handles SplitHTTP requests
func (shs *SplitHTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check path prefix
	path := shs.config.Path
	if path == "" {
		path = "/"
	}

	if !strings.HasPrefix(r.URL.Path, path) {
		http.NotFound(w, r)
		return
	}

	// Extract session ID and request type from path
	subPath := strings.TrimPrefix(r.URL.Path, path)
	parts := strings.Split(strings.Trim(subPath, "/"), "/")

	if len(parts) < 1 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	sessionID := parts[0]

	switch r.Method {
	case "POST":
		// Upload request
		shs.handleUpload(w, r, sessionID)
	case "GET":
		// Download request
		shs.handleDownload(w, r, sessionID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleUpload handles upload requests
func (shs *SplitHTTPServer) handleUpload(w http.ResponseWriter, r *http.Request, sessionID string) {
	atomic.AddInt64(&shs.stats.TotalUploads, 1)

	// Get or create session
	session := shs.getOrCreateSession(sessionID)

	// Read body
	maxSize := shs.config.MaxUploadSize
	if maxSize <= 0 {
		maxSize = 1024 * 1024 // 1MB default
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, int64(maxSize)))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	atomic.AddInt64(&shs.stats.BytesUploaded, int64(len(body)))

	// Add to session buffer
	session.mu.Lock()
	session.readBuffer.Write(body)
	session.lastActivity = time.Now()
	session.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

// handleDownload handles download requests
func (shs *SplitHTTPServer) handleDownload(w http.ResponseWriter, r *http.Request, sessionID string) {
	atomic.AddInt64(&shs.stats.TotalDownloads, 1)

	// Get session
	sessionI, exists := shs.sessions.Load(sessionID)
	if !exists {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	session := sessionI.(*SplitHTTPSession)

	// Set headers for streaming
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Transfer-Encoding", "chunked")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Stream data
	for {
		session.mu.Lock()
		if session.closed {
			session.mu.Unlock()
			return
		}

		data := session.writeBuffer.Bytes()
		if len(data) > 0 {
			session.writeBuffer.Reset()
			session.mu.Unlock()

			w.Write(data)
			flusher.Flush()
			atomic.AddInt64(&shs.stats.BytesDownloaded, int64(len(data)))
		} else {
			session.mu.Unlock()
			time.Sleep(10 * time.Millisecond)
		}

		// Check for client disconnect
		select {
		case <-r.Context().Done():
			return
		default:
		}
	}
}

// getOrCreateSession gets or creates a session
func (shs *SplitHTTPServer) getOrCreateSession(sessionID string) *SplitHTTPSession {
	if sessionI, exists := shs.sessions.Load(sessionID); exists {
		return sessionI.(*SplitHTTPSession)
	}

	session := &SplitHTTPSession{
		ID:           sessionID,
		uploadChan:   make(chan []byte, 100),
		downloadChan: make(chan []byte, 100),
		created:      time.Now(),
		lastActivity: time.Now(),
	}

	actual, loaded := shs.sessions.LoadOrStore(sessionID, session)
	if loaded {
		return actual.(*SplitHTTPSession)
	}

	atomic.AddInt64(&shs.stats.TotalSessions, 1)
	atomic.AddInt64(&shs.stats.ActiveSessions, 1)

	// Start handler for new session
	go func() {
		defer atomic.AddInt64(&shs.stats.ActiveSessions, -1)
		defer shs.sessions.Delete(sessionID)

		conn := &SplitHTTPConn{
			session: session,
			server:  shs,
		}

		if shs.handler != nil {
			shs.handler(conn)
		}
	}()

	return session
}

// Listen starts SplitHTTP server
func (shs *SplitHTTPServer) Listen(address string) error {
	mux := http.NewServeMux()
	path := shs.config.Path
	if path == "" {
		path = "/"
	}
	mux.Handle(path, shs)

	shs.httpServer = &http.Server{
		Addr:    address,
		Handler: mux,
	}

	if shs.tlsConfig != nil {
		shs.httpServer.TLSConfig = shs.tlsConfig
		return shs.httpServer.ListenAndServeTLS("", "")
	}

	return shs.httpServer.ListenAndServe()
}

// Close closes the server
func (shs *SplitHTTPServer) Close() error {
	// Close all sessions
	shs.sessions.Range(func(key, value interface{}) bool {
		session := value.(*SplitHTTPSession)
		session.mu.Lock()
		session.closed = true
		session.mu.Unlock()
		return true
	})

	if shs.httpServer != nil {
		return shs.httpServer.Close()
	}
	return nil
}

// GetStats returns SplitHTTP server statistics
func (shs *SplitHTTPServer) GetStats() SplitHTTPStats {
	return SplitHTTPStats{
		TotalSessions:   atomic.LoadInt64(&shs.stats.TotalSessions),
		ActiveSessions:  atomic.LoadInt64(&shs.stats.ActiveSessions),
		TotalUploads:    atomic.LoadInt64(&shs.stats.TotalUploads),
		TotalDownloads:  atomic.LoadInt64(&shs.stats.TotalDownloads),
		BytesUploaded:   atomic.LoadInt64(&shs.stats.BytesUploaded),
		BytesDownloaded: atomic.LoadInt64(&shs.stats.BytesDownloaded),
	}
}

// SplitHTTPConn wraps SplitHTTP session as net.Conn
type SplitHTTPConn struct {
	session *SplitHTTPSession
	server  *SplitHTTPServer
}

// Read reads from session
func (shc *SplitHTTPConn) Read(b []byte) (int, error) {
	for {
		shc.session.mu.Lock()
		if shc.session.closed {
			shc.session.mu.Unlock()
			return 0, io.EOF
		}

		if shc.session.readBuffer.Len() > 0 {
			n, _ := shc.session.readBuffer.Read(b)
			shc.session.mu.Unlock()
			return n, nil
		}
		shc.session.mu.Unlock()

		time.Sleep(10 * time.Millisecond)
	}
}

// Write writes to session
func (shc *SplitHTTPConn) Write(b []byte) (int, error) {
	shc.session.mu.Lock()
	defer shc.session.mu.Unlock()

	if shc.session.closed {
		return 0, errors.New("session closed")
	}

	return shc.session.writeBuffer.Write(b)
}

// Close closes the connection
func (shc *SplitHTTPConn) Close() error {
	shc.session.mu.Lock()
	shc.session.closed = true
	shc.session.mu.Unlock()
	return nil
}

// LocalAddr returns local address
func (shc *SplitHTTPConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// RemoteAddr returns remote address
func (shc *SplitHTTPConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// SetDeadline sets deadlines
func (shc *SplitHTTPConn) SetDeadline(t time.Time) error      { return nil }
func (shc *SplitHTTPConn) SetReadDeadline(t time.Time) error  { return nil }
func (shc *SplitHTTPConn) SetWriteDeadline(t time.Time) error { return nil }

// SplitHTTPClient handles SplitHTTP client connections
type SplitHTTPClient struct {
	config     *SplitHTTPConfig
	tlsConfig  *tls.Config
	httpClient *http.Client
}

// NewSplitHTTPClient creates new SplitHTTP client
func NewSplitHTTPClient(config *SplitHTTPConfig, tlsConfig *tls.Config) *SplitHTTPClient {
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	}

	return &SplitHTTPClient{
		config:    config,
		tlsConfig: tlsConfig,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   0,
		},
	}
}

// Connect establishes SplitHTTP connection
func (shc *SplitHTTPClient) Connect(ctx context.Context, address string) (net.Conn, error) {
	// Generate session ID
	sessionID := generateSessionID()

	// Build base URL
	scheme := "https"
	if shc.tlsConfig == nil {
		scheme = "http"
	}

	host := shc.config.Host
	if host == "" {
		host = address
	}

	path := shc.config.Path
	if path == "" {
		path = "/"
	}

	baseURL := fmt.Sprintf("%s://%s%s%s", scheme, host, path, sessionID)

	conn := &SplitHTTPClientConn{
		client:      shc,
		sessionID:   sessionID,
		baseURL:     baseURL,
		uploadQueue: make(chan []byte, 100),
		downloadBuf: bytes.NewBuffer(nil),
		ctx:         ctx,
	}

	// Start download goroutine
	go conn.downloadLoop()

	// Start upload goroutine
	go conn.uploadLoop()

	return conn, nil
}

// generateSessionID generates random session ID
func generateSessionID() string {
	id := make([]byte, 16)
	rand.Read(id)
	return hex.EncodeToString(id)
}

// SplitHTTPClientConn wraps SplitHTTP client connection
type SplitHTTPClientConn struct {
	client      *SplitHTTPClient
	sessionID   string
	baseURL     string
	uploadQueue chan []byte
	downloadBuf *bytes.Buffer
	ctx         context.Context
	mu          sync.Mutex
	closed      bool
}

// downloadLoop handles download streaming
func (shcc *SplitHTTPClientConn) downloadLoop() {
	req, err := http.NewRequestWithContext(shcc.ctx, "GET", shcc.baseURL, nil)
	if err != nil {
		return
	}

	// Add headers
	for k, v := range shcc.client.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := shcc.client.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			shcc.mu.Lock()
			shcc.downloadBuf.Write(buf[:n])
			shcc.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

// uploadLoop handles upload requests
func (shcc *SplitHTTPClientConn) uploadLoop() {
	for data := range shcc.uploadQueue {
		req, err := http.NewRequestWithContext(shcc.ctx, "POST", shcc.baseURL, bytes.NewReader(data))
		if err != nil {
			continue
		}

		// Add headers
		for k, v := range shcc.client.config.Headers {
			req.Header.Set(k, v)
		}
		req.Header.Set("Content-Type", "application/octet-stream")

		resp, err := shcc.client.httpClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
	}
}

// Read reads from connection
func (shcc *SplitHTTPClientConn) Read(b []byte) (int, error) {
	for {
		shcc.mu.Lock()
		if shcc.closed {
			shcc.mu.Unlock()
			return 0, io.EOF
		}

		if shcc.downloadBuf.Len() > 0 {
			n, _ := shcc.downloadBuf.Read(b)
			shcc.mu.Unlock()
			return n, nil
		}
		shcc.mu.Unlock()

		time.Sleep(10 * time.Millisecond)
	}
}

// Write writes to connection
func (shcc *SplitHTTPClientConn) Write(b []byte) (int, error) {
	if shcc.closed {
		return 0, errors.New("connection closed")
	}

	data := make([]byte, len(b))
	copy(data, b)

	select {
	case shcc.uploadQueue <- data:
		return len(b), nil
	case <-shcc.ctx.Done():
		return 0, shcc.ctx.Err()
	}
}

// Close closes the connection
func (shcc *SplitHTTPClientConn) Close() error {
	shcc.mu.Lock()
	defer shcc.mu.Unlock()
	shcc.closed = true
	close(shcc.uploadQueue)
	return nil
}

// LocalAddr returns local address
func (shcc *SplitHTTPClientConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// RemoteAddr returns remote address
func (shcc *SplitHTTPClientConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// SetDeadline sets deadlines
func (shcc *SplitHTTPClientConn) SetDeadline(t time.Time) error      { return nil }
func (shcc *SplitHTTPClientConn) SetReadDeadline(t time.Time) error  { return nil }
func (shcc *SplitHTTPClientConn) SetWriteDeadline(t time.Time) error { return nil }

// Core/transport.go
// MXUI VPN Panel - Transport Layer
// Part 3: TCP, Fragment, Mux, Obfuscation, Transport Factory & Manager

// ==================== TCP Configuration ====================

// TCPConfig holds TCP configuration
type TCPConfig struct {
	AcceptProxyProtocol bool             `json:"accept_proxy_protocol,omitempty"`
	Header              *TCPHeaderConfig `json:"header,omitempty"`
	KeepAlive           int              `json:"keep_alive,omitempty"`
	NoDelay             bool             `json:"no_delay"`
	SendBuffer          int              `json:"send_buffer,omitempty"`
	ReceiveBuffer       int              `json:"receive_buffer,omitempty"`
	FastOpen            bool             `json:"fast_open,omitempty"`
	FastOpenQueueLength int              `json:"fast_open_queue_length,omitempty"`
	Congestion          string           `json:"congestion,omitempty"`
	Interface           string           `json:"interface,omitempty"`
	Mark                int              `json:"mark,omitempty"`
}

// TCPHeaderConfig holds TCP header obfuscation config
type TCPHeaderConfig struct {
	Type     string              `json:"type"`
	Request  *HTTPRequestConfig  `json:"request,omitempty"`
	Response *HTTPResponseConfig `json:"response,omitempty"`
}

// HTTPRequestConfig holds HTTP request configuration
type HTTPRequestConfig struct {
	Version string              `json:"version,omitempty"`
	Method  string              `json:"method,omitempty"`
	Path    []string            `json:"path,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
}

// HTTPResponseConfig holds HTTP response configuration
type HTTPResponseConfig struct {
	Version string              `json:"version,omitempty"`
	Status  string              `json:"status,omitempty"`
	Reason  string              `json:"reason,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
}

// TCPServer handles raw TCP connections
type TCPServer struct {
	config   *TCPConfig
	listener net.Listener
	handler  func(net.Conn)
	mu       sync.RWMutex
	stats    TCPStats
	stopChan chan struct{}
}

// TCPStats holds TCP server statistics
type TCPStats struct {
	TotalConnections  int64
	ActiveConnections int64
	BytesSent         int64
	BytesReceived     int64
	AcceptErrors      int64
}

// NewTCPServer creates new TCP server
func NewTCPServer(config *TCPConfig, handler func(net.Conn)) *TCPServer {
	return &TCPServer{
		config:   config,
		handler:  handler,
		stopChan: make(chan struct{}),
	}
}

// Listen starts TCP server
func (ts *TCPServer) Listen(address string) error {
	var err error

	// Configure listener
	lc := net.ListenConfig{
		KeepAlive: time.Duration(ts.config.KeepAlive) * time.Second,
	}

	// Enable TCP Fast Open if supported
	if ts.config.FastOpen {
		lc.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Set TCP_FASTOPEN socket option
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, 23, ts.config.FastOpenQueueLength)
			})
		}
	}

	ts.listener, err = lc.Listen(context.Background(), "tcp", address)
	if err != nil {
		return err
	}

	// Accept connections
	for {
		select {
		case <-ts.stopChan:
			return nil
		default:
			conn, err := ts.listener.Accept()
			if err != nil {
				atomic.AddInt64(&ts.stats.AcceptErrors, 1)
				continue
			}

			atomic.AddInt64(&ts.stats.TotalConnections, 1)
			atomic.AddInt64(&ts.stats.ActiveConnections, 1)

			go ts.handleConnection(conn)
		}
	}
}

// handleConnection handles a single TCP connection
func (ts *TCPServer) handleConnection(conn net.Conn) {
	defer atomic.AddInt64(&ts.stats.ActiveConnections, -1)
	defer conn.Close()

	// Configure TCP options
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if ts.config.NoDelay {
			tcpConn.SetNoDelay(true)
		}
		if ts.config.KeepAlive > 0 {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(time.Duration(ts.config.KeepAlive) * time.Second)
		}
		if ts.config.SendBuffer > 0 {
			tcpConn.SetWriteBuffer(ts.config.SendBuffer)
		}
		if ts.config.ReceiveBuffer > 0 {
			tcpConn.SetReadBuffer(ts.config.ReceiveBuffer)
		}
	}

	// Handle proxy protocol if enabled
	if ts.config.AcceptProxyProtocol {
		conn = ts.handleProxyProtocol(conn)
		if conn == nil {
			return
		}
	}

	// Wrap with header obfuscation if configured
	if ts.config.Header != nil && ts.config.Header.Type == "http" {
		conn = ts.wrapWithHTTPHeader(conn)
	}

	// Wrap with stats tracking
	wrappedConn := &TCPStatsConn{
		Conn:   conn,
		server: ts,
	}

	if ts.handler != nil {
		ts.handler(wrappedConn)
	}
}

// handleProxyProtocol handles PROXY protocol header
func (ts *TCPServer) handleProxyProtocol(conn net.Conn) net.Conn {
	// Read PROXY protocol header
	reader := bufio.NewReader(conn)

	// Read first line
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}

	// Check for PROXY protocol v1
	if strings.HasPrefix(line, "PROXY ") {
		parts := strings.Fields(strings.TrimSpace(line))
		if len(parts) >= 5 {
			// Parse source address
			srcIP := net.ParseIP(parts[2])
			srcPort, _ := strconv.Atoi(parts[4])

			return &ProxyProtocolConn{
				Conn:       conn,
				reader:     reader,
				remoteAddr: &net.TCPAddr{IP: srcIP, Port: srcPort},
			}
		}
	}

	// Check for PROXY protocol v2
	if len(line) >= 12 && line[0] == '\r' {
		// Handle binary format
		// This is simplified - full implementation needs binary parsing
	}

	// Not PROXY protocol, create buffered conn with read data
	return &BufferedConn{
		Conn:   conn,
		reader: reader,
	}
}

// wrapWithHTTPHeader wraps connection with HTTP header obfuscation
func (ts *TCPServer) wrapWithHTTPHeader(conn net.Conn) net.Conn {
	return &HTTPObfsConn{
		Conn:     conn,
		config:   ts.config.Header,
		isServer: true,
	}
}

// Close closes the server
func (ts *TCPServer) Close() error {
	close(ts.stopChan)
	if ts.listener != nil {
		return ts.listener.Close()
	}
	return nil
}

// GetStats returns TCP server statistics
func (ts *TCPServer) GetStats() TCPStats {
	return TCPStats{
		TotalConnections:  atomic.LoadInt64(&ts.stats.TotalConnections),
		ActiveConnections: atomic.LoadInt64(&ts.stats.ActiveConnections),
		BytesSent:         atomic.LoadInt64(&ts.stats.BytesSent),
		BytesReceived:     atomic.LoadInt64(&ts.stats.BytesReceived),
		AcceptErrors:      atomic.LoadInt64(&ts.stats.AcceptErrors),
	}
}

// TCPStatsConn wraps connection with stats tracking
type TCPStatsConn struct {
	net.Conn
	server *TCPServer
}

// Read reads with stats tracking
func (tsc *TCPStatsConn) Read(b []byte) (int, error) {
	n, err := tsc.Conn.Read(b)
	if n > 0 && tsc.server != nil {
		atomic.AddInt64(&tsc.server.stats.BytesReceived, int64(n))
	}
	return n, err
}

// Write writes with stats tracking
func (tsc *TCPStatsConn) Write(b []byte) (int, error) {
	n, err := tsc.Conn.Write(b)
	if n > 0 && tsc.server != nil {
		atomic.AddInt64(&tsc.server.stats.BytesSent, int64(n))
	}
	return n, err
}

// ProxyProtocolConn wraps connection with PROXY protocol info
type ProxyProtocolConn struct {
	net.Conn
	reader     *bufio.Reader
	remoteAddr net.Addr
}

// Read reads from buffered reader
func (ppc *ProxyProtocolConn) Read(b []byte) (int, error) {
	return ppc.reader.Read(b)
}

// RemoteAddr returns the proxied remote address
func (ppc *ProxyProtocolConn) RemoteAddr() net.Addr {
	return ppc.remoteAddr
}

// BufferedConn wraps connection with buffered reader
type BufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

// Read reads from buffered reader
func (bc *BufferedConn) Read(b []byte) (int, error) {
	return bc.reader.Read(b)
}

// TCPClient handles TCP client connections
type TCPClient struct {
	config *TCPConfig
	dialer *net.Dialer
}

// NewTCPClient creates new TCP client
func NewTCPClient(config *TCPConfig) *TCPClient {
	return &TCPClient{
		config: config,
		dialer: &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: time.Duration(config.KeepAlive) * time.Second,
		},
	}
}

// Connect establishes TCP connection
func (tc *TCPClient) Connect(ctx context.Context, address string) (net.Conn, error) {
	conn, err := tc.dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}

	// Configure TCP options
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if tc.config.NoDelay {
			tcpConn.SetNoDelay(true)
		}
		if tc.config.SendBuffer > 0 {
			tcpConn.SetWriteBuffer(tc.config.SendBuffer)
		}
		if tc.config.ReceiveBuffer > 0 {
			tcpConn.SetReadBuffer(tc.config.ReceiveBuffer)
		}
	}

	// Wrap with HTTP header if configured
	if tc.config.Header != nil && tc.config.Header.Type == "http" {
		return &HTTPObfsConn{
			Conn:     conn,
			config:   tc.config.Header,
			isServer: false,
		}, nil
	}

	return conn, nil
}

// HTTPObfsConn wraps connection with HTTP obfuscation
type HTTPObfsConn struct {
	net.Conn
	config       *TCPHeaderConfig
	isServer     bool
	headerSent   bool
	headerRecved bool
	readBuffer   bytes.Buffer
	mu           sync.Mutex
}

// Read reads with HTTP header parsing
func (hoc *HTTPObfsConn) Read(b []byte) (int, error) {
	hoc.mu.Lock()
	defer hoc.mu.Unlock()

	// Return buffered data first
	if hoc.readBuffer.Len() > 0 {
		return hoc.readBuffer.Read(b)
	}

	// Read from connection
	data := make([]byte, len(b)+1024) // Extra space for header
	n, err := hoc.Conn.Read(data)
	if err != nil {
		return 0, err
	}

	// Parse and strip header if not yet received
	if !hoc.headerRecved {
		payload := hoc.stripHTTPHeader(data[:n])
		hoc.headerRecved = true

		if len(payload) > len(b) {
			copy(b, payload[:len(b)])
			hoc.readBuffer.Write(payload[len(b):])
			return len(b), nil
		}

		return copy(b, payload), nil
	}

	return copy(b, data[:n]), nil
}

// Write writes with HTTP header prepending
func (hoc *HTTPObfsConn) Write(b []byte) (int, error) {
	hoc.mu.Lock()
	defer hoc.mu.Unlock()

	// Prepend header if not yet sent
	if !hoc.headerSent {
		header := hoc.buildHTTPHeader(len(b))
		hoc.headerSent = true

		data := append(header, b...)
		_, err := hoc.Conn.Write(data)
		if err != nil {
			return 0, err
		}
		return len(b), nil
	}

	return hoc.Conn.Write(b)
}

// buildHTTPHeader builds HTTP request/response header
func (hoc *HTTPObfsConn) buildHTTPHeader(contentLength int) []byte {
	var header bytes.Buffer

	if hoc.isServer {
		// Build response
		resp := hoc.config.Response
		if resp == nil {
			resp = &HTTPResponseConfig{
				Version: "1.1",
				Status:  "200",
				Reason:  "OK",
			}
		}

		header.WriteString(fmt.Sprintf("HTTP/%s %s %s\r\n", resp.Version, resp.Status, resp.Reason))
		header.WriteString(fmt.Sprintf("Content-Length: %d\r\n", contentLength))
		header.WriteString("Connection: keep-alive\r\n")

		for k, values := range resp.Headers {
			for _, v := range values {
				header.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
			}
		}
	} else {
		// Build request
		req := hoc.config.Request
		if req == nil {
			req = &HTTPRequestConfig{
				Version: "1.1",
				Method:  "GET",
				Path:    []string{"/"},
			}
		}

		path := "/"
		if len(req.Path) > 0 {
			path = req.Path[mrand.Intn(len(req.Path))]
		}

		header.WriteString(fmt.Sprintf("%s %s HTTP/%s\r\n", req.Method, path, req.Version))
		header.WriteString(fmt.Sprintf("Content-Length: %d\r\n", contentLength))
		header.WriteString("Connection: keep-alive\r\n")

		for k, values := range req.Headers {
			for _, v := range values {
				header.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
			}
		}
	}

	header.WriteString("\r\n")
	return header.Bytes()
}

// stripHTTPHeader strips HTTP header from data
func (hoc *HTTPObfsConn) stripHTTPHeader(data []byte) []byte {
	// Find end of header
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return data
	}

	return data[headerEnd+4:]
}

// ==================== Fragment Configuration ====================

// FragmentConfig holds fragment configuration
type FragmentConfig struct {
	Enabled   bool   `json:"enabled"`
	Packets   string `json:"packets,omitempty"`
	Length    string `json:"length,omitempty"`
	Interval  string `json:"interval,omitempty"`
	MinLength int    `json:"min_length,omitempty"`
	MaxLength int    `json:"max_length,omitempty"`
	MinDelay  int    `json:"min_delay,omitempty"`
	MaxDelay  int    `json:"max_delay,omitempty"`
}

// FragmentConn wraps connection with packet fragmentation
type FragmentConn struct {
	net.Conn
	config     *FragmentConfig
	minLength  int
	maxLength  int
	minDelay   time.Duration
	maxDelay   time.Duration
	packets    string
	writeCount int64
	mu         sync.Mutex
}

// NewFragmentConn creates new fragment connection wrapper
func NewFragmentConn(conn net.Conn, config *FragmentConfig) *FragmentConn {
	fc := &FragmentConn{
		Conn:      conn,
		config:    config,
		minLength: config.MinLength,
		maxLength: config.MaxLength,
		minDelay:  time.Duration(config.MinDelay) * time.Millisecond,
		maxDelay:  time.Duration(config.MaxDelay) * time.Millisecond,
		packets:   config.Packets,
	}

	// Parse length range
	if config.Length != "" {
		fc.parseRange(config.Length, &fc.minLength, &fc.maxLength)
	}

	// Parse interval range
	if config.Interval != "" {
		var minMs, maxMs int
		fc.parseRange(config.Interval, &minMs, &maxMs)
		fc.minDelay = time.Duration(minMs) * time.Millisecond
		fc.maxDelay = time.Duration(maxMs) * time.Millisecond
	}

	// Set defaults
	if fc.minLength == 0 {
		fc.minLength = 1
	}
	if fc.maxLength == 0 {
		fc.maxLength = 20
	}
	if fc.maxDelay == 0 {
		fc.maxDelay = 10 * time.Millisecond
	}

	return fc
}

// parseRange parses "min-max" format
func (fc *FragmentConn) parseRange(s string, minVal, maxVal *int) {
	parts := strings.Split(s, "-")
	if len(parts) == 2 {
		*minVal, _ = strconv.Atoi(strings.TrimSpace(parts[0]))
		*maxVal, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
	} else if len(parts) == 1 {
		val, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
		*minVal = val
		*maxVal = val
	}
}

// Write writes with fragmentation
func (fc *FragmentConn) Write(b []byte) (int, error) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	// Check if fragmentation should be applied
	if !fc.shouldFragment() {
		return fc.Conn.Write(b)
	}

	written := 0
	remaining := b

	for len(remaining) > 0 {
		// Calculate fragment size
		fragSize := fc.randomInt(fc.minLength, fc.maxLength)
		if fragSize > len(remaining) {
			fragSize = len(remaining)
		}

		// Write fragment
		n, err := fc.Conn.Write(remaining[:fragSize])
		if err != nil {
			return written + n, err
		}
		written += n
		remaining = remaining[fragSize:]

		// Delay between fragments
		if len(remaining) > 0 {
			delay := fc.randomDuration(fc.minDelay, fc.maxDelay)
			time.Sleep(delay)
		}
	}

	atomic.AddInt64(&fc.writeCount, 1)
	return written, nil
}

// shouldFragment determines if current write should be fragmented
func (fc *FragmentConn) shouldFragment() bool {
	if !fc.config.Enabled {
		return false
	}

	switch fc.packets {
	case "tlshello":
		// Only fragment first packet (TLS ClientHello)
		return atomic.LoadInt64(&fc.writeCount) == 0
	case "1-3":
		// Fragment first 3 packets
		return atomic.LoadInt64(&fc.writeCount) < 3
	case "all":
		return true
	default:
		// Parse packet range
		if strings.Contains(fc.packets, "-") {
			parts := strings.Split(fc.packets, "-")
			if len(parts) == 2 {
				min, _ := strconv.ParseInt(parts[0], 10, 64)
				max, _ := strconv.ParseInt(parts[1], 10, 64)
				count := atomic.LoadInt64(&fc.writeCount)
				return count >= min && count <= max
			}
		}
		return true
	}
}

// randomInt returns random int in range [min, max]
func (fc *FragmentConn) randomInt(min, max int) int {
	if min >= max {
		return min
	}
	return min + mrand.Intn(max-min+1)
}

// randomDuration returns random duration in range [min, max]
func (fc *FragmentConn) randomDuration(min, max time.Duration) time.Duration {
	if min >= max {
		return min
	}
	return min + time.Duration(mrand.Int63n(int64(max-min)))
}

// ==================== Mux Configuration ====================

// MuxConfig holds multiplexing configuration
type MuxConfig struct {
	Enabled         bool   `json:"enabled"`
	Protocol        string `json:"protocol,omitempty"`
	MaxConnections  int    `json:"max_connections,omitempty"`
	MinStreams      int    `json:"min_streams,omitempty"`
	MaxStreams      int    `json:"max_streams,omitempty"`
	Padding         bool   `json:"padding,omitempty"`
	MaxPaddingBytes int    `json:"max_padding_bytes,omitempty"`
	Concurrency     int    `json:"concurrency,omitempty"`
	XudpConcurrency int    `json:"xudp_concurrency,omitempty"`
	XudpProxyUDP443 string `json:"xudp_proxy_udp443,omitempty"`
}

// MuxSession represents a multiplexing session
type MuxSession struct {
	config    *MuxConfig
	conn      net.Conn
	streams   map[uint32]*MuxStream
	nextID    uint32
	mu        sync.RWMutex
	closeChan chan struct{}
	closed    bool
	stats     MuxStats
}

// MuxStats holds mux session statistics
type MuxStats struct {
	TotalStreams  int64
	ActiveStreams int64
	BytesSent     int64
	BytesReceived int64
}

// MuxStream represents a single stream in mux session
type MuxStream struct {
	id         uint32
	session    *MuxSession
	readBuffer bytes.Buffer
	readChan   chan []byte
	mu         sync.Mutex
	closed     bool
}

// MuxFrameType represents mux frame types
type MuxFrameType byte

const (
	MuxFrameNew   MuxFrameType = 0x01
	MuxFrameData  MuxFrameType = 0x02
	MuxFrameClose MuxFrameType = 0x03
	MuxFrameKeep  MuxFrameType = 0x04
	MuxFrameEnd   MuxFrameType = 0x05
)

// MuxFrame represents a mux frame
type MuxFrame struct {
	Type     MuxFrameType
	StreamID uint32
	Length   uint16
	Data     []byte
	Padding  []byte
}

// NewMuxSession creates new mux session
func NewMuxSession(conn net.Conn, config *MuxConfig) *MuxSession {
	session := &MuxSession{
		config:    config,
		conn:      conn,
		streams:   make(map[uint32]*MuxStream),
		nextID:    1,
		closeChan: make(chan struct{}),
	}

	// Start read loop
	go session.readLoop()

	return session
}

// OpenStream opens a new stream
func (ms *MuxSession) OpenStream() (*MuxStream, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if ms.closed {
		return nil, errors.New("session closed")
	}

	// Check max streams
	if ms.config.MaxStreams > 0 && len(ms.streams) >= ms.config.MaxStreams {
		return nil, errors.New("max streams reached")
	}

	// Create stream
	stream := &MuxStream{
		id:       ms.nextID,
		session:  ms,
		readChan: make(chan []byte, 64),
	}

	ms.nextID += 2 // Odd IDs for client, even for server
	ms.streams[stream.id] = stream

	atomic.AddInt64(&ms.stats.TotalStreams, 1)
	atomic.AddInt64(&ms.stats.ActiveStreams, 1)

	// Send new stream frame
	frame := &MuxFrame{
		Type:     MuxFrameNew,
		StreamID: stream.id,
	}
	ms.writeFrame(frame)

	return stream, nil
}

// AcceptStream accepts an incoming stream
func (ms *MuxSession) AcceptStream() (*MuxStream, error) {
	// This is handled in readLoop
	// Wait for new stream notification
	ms.mu.RLock()
	if ms.closed {
		ms.mu.RUnlock()
		return nil, errors.New("session closed")
	}
	ms.mu.RUnlock()

	// In a real implementation, this would wait on a channel
	return nil, errors.New("accept not implemented")
}

// readLoop reads frames from connection
func (ms *MuxSession) readLoop() {
	defer ms.Close()

	for {
		select {
		case <-ms.closeChan:
			return
		default:
			frame, err := ms.readFrame()
			if err != nil {
				return
			}

			ms.handleFrame(frame)
		}
	}
}

// readFrame reads a single frame from connection
func (ms *MuxSession) readFrame() (*MuxFrame, error) {
	// Read header (1 byte type + 4 bytes stream ID + 2 bytes length)
	header := make([]byte, 7)
	if _, err := io.ReadFull(ms.conn, header); err != nil {
		return nil, err
	}

	frame := &MuxFrame{
		Type:     MuxFrameType(header[0]),
		StreamID: binary.BigEndian.Uint32(header[1:5]),
		Length:   binary.BigEndian.Uint16(header[5:7]),
	}

	// Read data
	if frame.Length > 0 {
		frame.Data = make([]byte, frame.Length)
		if _, err := io.ReadFull(ms.conn, frame.Data); err != nil {
			return nil, err
		}
	}

	atomic.AddInt64(&ms.stats.BytesReceived, int64(7+int(frame.Length)))

	return frame, nil
}

// writeFrame writes a frame to connection
func (ms *MuxSession) writeFrame(frame *MuxFrame) error {
	// Build frame
	data := make([]byte, 7+len(frame.Data)+len(frame.Padding))
	data[0] = byte(frame.Type)
	binary.BigEndian.PutUint32(data[1:5], frame.StreamID)
	binary.BigEndian.PutUint16(data[5:7], uint16(len(frame.Data)+len(frame.Padding)))
	copy(data[7:], frame.Data)
	if len(frame.Padding) > 0 {
		copy(data[7+len(frame.Data):], frame.Padding)
	}

	// Add padding if enabled
	if ms.config.Padding && ms.config.MaxPaddingBytes > 0 {
		paddingLen := mrand.Intn(ms.config.MaxPaddingBytes)
		if paddingLen > 0 {
			padding := make([]byte, paddingLen)
			rand.Read(padding)
			data = append(data, padding...)
		}
	}

	_, err := ms.conn.Write(data)
	if err == nil {
		atomic.AddInt64(&ms.stats.BytesSent, int64(len(data)))
	}
	return err
}

// handleFrame handles incoming frame
func (ms *MuxSession) handleFrame(frame *MuxFrame) {
	ms.mu.RLock()
	stream, exists := ms.streams[frame.StreamID]
	ms.mu.RUnlock()

	switch frame.Type {
	case MuxFrameNew:
		if !exists {
			// Create new stream
			stream = &MuxStream{
				id:       frame.StreamID,
				session:  ms,
				readChan: make(chan []byte, 64),
			}
			ms.mu.Lock()
			ms.streams[frame.StreamID] = stream
			ms.mu.Unlock()
			atomic.AddInt64(&ms.stats.TotalStreams, 1)
			atomic.AddInt64(&ms.stats.ActiveStreams, 1)
		}

	case MuxFrameData:
		if exists && !stream.closed {
			select {
			case stream.readChan <- frame.Data:
			default:
				// Buffer full, write to buffer
				stream.mu.Lock()
				stream.readBuffer.Write(frame.Data)
				stream.mu.Unlock()
			}
		}

	case MuxFrameClose, MuxFrameEnd:
		if exists {
			stream.close()
		}

	case MuxFrameKeep:
		// Keepalive, do nothing
	}
}

// Close closes the session
func (ms *MuxSession) Close() error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if ms.closed {
		return nil
	}
	ms.closed = true
	close(ms.closeChan)

	// Close all streams
	for _, stream := range ms.streams {
		stream.close()
	}

	return ms.conn.Close()
}

// GetStats returns mux session statistics
func (ms *MuxSession) GetStats() MuxStats {
	return MuxStats{
		TotalStreams:  atomic.LoadInt64(&ms.stats.TotalStreams),
		ActiveStreams: atomic.LoadInt64(&ms.stats.ActiveStreams),
		BytesSent:     atomic.LoadInt64(&ms.stats.BytesSent),
		BytesReceived: atomic.LoadInt64(&ms.stats.BytesReceived),
	}
}

// MuxStream methods

// Read reads from stream
func (mst *MuxStream) Read(b []byte) (int, error) {
	mst.mu.Lock()
	// Read from buffer first
	if mst.readBuffer.Len() > 0 {
		n, _ := mst.readBuffer.Read(b)
		mst.mu.Unlock()
		return n, nil
	}
	mst.mu.Unlock()

	if mst.closed {
		return 0, io.EOF
	}

	// Wait for data
	select {
	case data, ok := <-mst.readChan:
		if !ok {
			return 0, io.EOF
		}
		n := copy(b, data)
		if n < len(data) {
			mst.mu.Lock()
			mst.readBuffer.Write(data[n:])
			mst.mu.Unlock()
		}
		return n, nil
	}
}

// Write writes to stream
func (mst *MuxStream) Write(b []byte) (int, error) {
	if mst.closed {
		return 0, errors.New("stream closed")
	}

	frame := &MuxFrame{
		Type:     MuxFrameData,
		StreamID: mst.id,
		Data:     b,
	}

	if err := mst.session.writeFrame(frame); err != nil {
		return 0, err
	}

	return len(b), nil
}

// Close closes the stream
func (mst *MuxStream) Close() error {
	return mst.close()
}

func (mst *MuxStream) close() error {
	mst.mu.Lock()
	defer mst.mu.Unlock()

	if mst.closed {
		return nil
	}
	mst.closed = true

	close(mst.readChan)
	atomic.AddInt64(&mst.session.stats.ActiveStreams, -1)

	// Send close frame
	frame := &MuxFrame{
		Type:     MuxFrameClose,
		StreamID: mst.id,
	}
	return mst.session.writeFrame(frame)
}

// LocalAddr returns local address
func (mst *MuxStream) LocalAddr() net.Addr {
	return mst.session.conn.LocalAddr()
}

// RemoteAddr returns remote address
func (mst *MuxStream) RemoteAddr() net.Addr {
	return mst.session.conn.RemoteAddr()
}

// SetDeadline sets deadlines
func (mst *MuxStream) SetDeadline(t time.Time) error      { return nil }
func (mst *MuxStream) SetReadDeadline(t time.Time) error  { return nil }
func (mst *MuxStream) SetWriteDeadline(t time.Time) error { return nil }

// ==================== Obfuscation ====================

// ObfuscationConfig holds obfuscation configuration
type ObfuscationConfig struct {
	Type     string `json:"type"`
	Password string `json:"password,omitempty"`
	Method   string `json:"method,omitempty"`
	Seed     string `json:"seed,omitempty"`
}

// Obfuscator interface for obfuscation methods
type Obfuscator interface {
	Obfuscate(data []byte) []byte
	Deobfuscate(data []byte) []byte
}

// NewObfuscator creates obfuscator based on config
func NewObfuscator(config *ObfuscationConfig) (Obfuscator, error) {
	switch config.Type {
	case "xor":
		return NewXORObfuscator(config.Password), nil
	case "rc4":
		return NewRC4Obfuscator(config.Password)
	case "chacha":
		return NewChaChaObfuscator(config.Password)
	case "aes":
		return NewAESObfuscator(config.Password)
	case "random":
		return NewRandomObfuscator(config.Seed), nil
	default:
		return nil, fmt.Errorf("unknown obfuscation type: %s", config.Type)
	}
}

// XORObfuscator implements XOR obfuscation
type XORObfuscator struct {
	key []byte
}

// NewXORObfuscator creates XOR obfuscator
func NewXORObfuscator(password string) *XORObfuscator {
	key := sha256.Sum256([]byte(password))
	return &XORObfuscator{key: key[:]}
}

// Obfuscate XORs data with key
func (xo *XORObfuscator) Obfuscate(data []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ xo.key[i%len(xo.key)]
	}
	return result
}

// Deobfuscate XORs data with key (same as obfuscate)
func (xo *XORObfuscator) Deobfuscate(data []byte) []byte {
	return xo.Obfuscate(data)
}

// RC4Obfuscator implements RC4 obfuscation
type RC4Obfuscator struct {
	key []byte
}

// NewRC4Obfuscator creates RC4 obfuscator
func NewRC4Obfuscator(password string) (*RC4Obfuscator, error) {
	key := sha256.Sum256([]byte(password))
	return &RC4Obfuscator{key: key[:]}, nil
}

// Obfuscate applies RC4
func (ro *RC4Obfuscator) Obfuscate(data []byte) []byte {
	// RC4 implementation
	s := make([]byte, 256)
	for i := range s {
		s[i] = byte(i)
	}

	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(ro.key[i%len(ro.key)])) % 256
		s[i], s[j] = s[j], s[i]
	}

	result := make([]byte, len(data))
	i, j := 0, 0
	for k := range data {
		i = (i + 1) % 256
		j = (j + int(s[i])) % 256
		s[i], s[j] = s[j], s[i]
		result[k] = data[k] ^ s[(int(s[i])+int(s[j]))%256]
	}

	return result
}

// Deobfuscate applies RC4 (symmetric)
func (ro *RC4Obfuscator) Deobfuscate(data []byte) []byte {
	return ro.Obfuscate(data)
}

// ChaChaObfuscator implements ChaCha20 obfuscation
type ChaChaObfuscator struct {
	key   []byte
	nonce []byte
}

// NewChaChaObfuscator creates ChaCha20 obfuscator
func NewChaChaObfuscator(password string) (*ChaChaObfuscator, error) {
	key := sha256.Sum256([]byte(password))
	nonce := make([]byte, 12)
	copy(nonce, key[:12])

	return &ChaChaObfuscator{
		key:   key[:],
		nonce: nonce,
	}, nil
}

// Obfuscate applies ChaCha20
func (co *ChaChaObfuscator) Obfuscate(data []byte) []byte {
	aead, err := chacha20poly1305.New(co.key)
	if err != nil {
		return data
	}

	return aead.Seal(nil, co.nonce, data, nil)
}

// Deobfuscate reverses ChaCha20
func (co *ChaChaObfuscator) Deobfuscate(data []byte) []byte {
	aead, err := chacha20poly1305.New(co.key)
	if err != nil {
		return data
	}

	plaintext, err := aead.Open(nil, co.nonce, data, nil)
	if err != nil {
		return data
	}

	return plaintext
}

// AESObfuscator implements AES obfuscation
type AESObfuscator struct {
	block cipher.Block
	iv    []byte
}

// NewAESObfuscator creates AES obfuscator
func NewAESObfuscator(password string) (*AESObfuscator, error) {
	key := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	copy(iv, key[:aes.BlockSize])

	return &AESObfuscator{
		block: block,
		iv:    iv,
	}, nil
}

// Obfuscate applies AES-CFB
func (ao *AESObfuscator) Obfuscate(data []byte) []byte {
	result := make([]byte, len(data))
	stream := cipher.NewCFBEncrypter(ao.block, ao.iv)
	stream.XORKeyStream(result, data)
	return result
}

// Deobfuscate reverses AES-CFB
func (ao *AESObfuscator) Deobfuscate(data []byte) []byte {
	result := make([]byte, len(data))
	stream := cipher.NewCFBDecrypter(ao.block, ao.iv)
	stream.XORKeyStream(result, data)
	return result
}

// RandomObfuscator adds random padding
type RandomObfuscator struct {
	rng *mrand.Rand
}

// NewRandomObfuscator creates random obfuscator
func NewRandomObfuscator(seed string) *RandomObfuscator {
	hash := sha256.Sum256([]byte(seed))
	seedInt := int64(binary.BigEndian.Uint64(hash[:8]))
	return &RandomObfuscator{
		rng: mrand.New(mrand.NewSource(seedInt)),
	}
}

// Obfuscate adds random padding
func (ro *RandomObfuscator) Obfuscate(data []byte) []byte {
	paddingLen := ro.rng.Intn(64)
	padding := make([]byte, paddingLen)
	ro.rng.Read(padding)

	result := make([]byte, 2+len(data)+paddingLen)
	binary.BigEndian.PutUint16(result[:2], uint16(len(data)))
	copy(result[2:], data)
	copy(result[2+len(data):], padding)

	return result
}

// Deobfuscate removes random padding
func (ro *RandomObfuscator) Deobfuscate(data []byte) []byte {
	if len(data) < 2 {
		return data
	}

	dataLen := binary.BigEndian.Uint16(data[:2])
	if int(dataLen)+2 > len(data) {
		return data
	}

	return data[2 : 2+dataLen]
}

// ObfuscatedConn wraps connection with obfuscation
type ObfuscatedConn struct {
	net.Conn
	obfuscator Obfuscator
}

// NewObfuscatedConn creates obfuscated connection wrapper
func NewObfuscatedConn(conn net.Conn, obfuscator Obfuscator) *ObfuscatedConn {
	return &ObfuscatedConn{
		Conn:       conn,
		obfuscator: obfuscator,
	}
}

// Read reads and deobfuscates
func (oc *ObfuscatedConn) Read(b []byte) (int, error) {
	// Read length header
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(oc.Conn, lenBuf); err != nil {
		return 0, err
	}

	length := binary.BigEndian.Uint16(lenBuf)
	if length > uint16(len(b)) {
		length = uint16(len(b))
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(oc.Conn, data); err != nil {
		return 0, err
	}

	deobfuscated := oc.obfuscator.Deobfuscate(data)
	n := copy(b, deobfuscated)
	return n, nil
}

// Write obfuscates and writes
func (oc *ObfuscatedConn) Write(b []byte) (int, error) {
	obfuscated := oc.obfuscator.Obfuscate(b)

	// Write length header
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(obfuscated)))

	if _, err := oc.Conn.Write(lenBuf); err != nil {
		return 0, err
	}

	if _, err := oc.Conn.Write(obfuscated); err != nil {
		return 0, err
	}

	return len(b), nil
}

// ==================== Transport Factory ====================

// TransportFactory creates transport instances
type TransportFactory struct {
	tlsManager *TLSManager
	mu         sync.RWMutex
}

// NewTransportFactory creates new transport factory
func NewTransportFactory() *TransportFactory {
	return &TransportFactory{
		tlsManager: NewTLSManager(),
	}
}

// CreateServerTransport creates server transport based on config
func (tf *TransportFactory) CreateServerTransport(config *TransportConfig, handler func(net.Conn)) (interface{}, error) {
	tf.mu.Lock()
	defer tf.mu.Unlock()

	// Build TLS config if needed
	var tlsConfig *tls.Config
	var err error

	if config.Security == SecurityTLS && config.TLS != nil {
		tlsConfig, err = tf.tlsManager.BuildServerConfig(config.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
	}

	// Create transport based on type
	switch config.Type {
	case TransportTypeTCP:
		return NewTCPServer(config.TCP, handler), nil

	case TransportTypeWS, TransportTypeWSS:
		wsConfig := config.WebSocket
		if wsConfig == nil {
			wsConfig = &WebSocketConfig{Path: config.Path}
		}
		return NewWebSocketServer(wsConfig, tlsConfig, handler), nil

	case TransportTypeGRPC:
		grpcConfig := config.GRPC
		if grpcConfig == nil {
			grpcConfig = &GRPCConfig{ServiceName: "GunService"}
		}
		return NewGRPCServer(grpcConfig, tlsConfig, handler), nil

	case TransportTypeHTTP2:
		h2Config := config.HTTP2
		if h2Config == nil {
			h2Config = &HTTP2Config{Path: config.Path}
		}
		return NewHTTP2Server(h2Config, tlsConfig, handler), nil

	case TransportTypeQUIC:
		quicConfig := config.QUIC
		if quicConfig == nil {
			quicConfig = &QUICConfig{}
		}
		return NewQUICServer(quicConfig, tlsConfig, handler), nil

	case TransportTypeHTTPU:
		httpuConfig := config.HTTPUpgrade
		if httpuConfig == nil {
			httpuConfig = &HTTPUpgradeConfig{Path: config.Path}
		}
		return NewHTTPUpgradeServer(httpuConfig, tlsConfig, handler), nil

	case TransportTypeSplitHTTP:
		splitConfig := config.SplitHTTP
		if splitConfig == nil {
			splitConfig = &SplitHTTPConfig{Path: config.Path}
		}
		return NewSplitHTTPServer(splitConfig, tlsConfig, handler), nil

	default:
		return nil, fmt.Errorf("unknown transport type: %s", config.Type)
	}
}

// CreateClientTransport creates client transport based on config
func (tf *TransportFactory) CreateClientTransport(config *TransportConfig) (ClientTransport, error) {
	tf.mu.Lock()
	defer tf.mu.Unlock()

	// Build TLS config if needed
	var tlsConfig *tls.Config
	var err error

	if config.Security == SecurityTLS && config.TLS != nil {
		tlsConfig, err = tf.tlsManager.BuildClientConfig(config.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
	}

	// Create transport based on type
	switch config.Type {
	case TransportTypeTCP:
		tcpConfig := config.TCP
		if tcpConfig == nil {
			tcpConfig = &TCPConfig{}
		}
		return &TCPClientTransport{
			client:    NewTCPClient(tcpConfig),
			tlsConfig: tlsConfig,
			fragment:  config.Fragment,
			mux:       config.Mux,
		}, nil

	case TransportTypeWS, TransportTypeWSS:
		wsConfig := config.WebSocket
		if wsConfig == nil {
			wsConfig = &WebSocketConfig{Path: config.Path}
		}
		return &WSClientTransport{
			client: NewWebSocketClient(wsConfig, tlsConfig),
		}, nil

	case TransportTypeGRPC:
		grpcConfig := config.GRPC
		if grpcConfig == nil {
			grpcConfig = &GRPCConfig{ServiceName: "GunService"}
		}
		return &GRPCClientTransport{
			client: NewGRPCClient(grpcConfig, tlsConfig),
		}, nil

	case TransportTypeHTTP2:
		h2Config := config.HTTP2
		if h2Config == nil {
			h2Config = &HTTP2Config{Path: config.Path}
		}
		return &HTTP2ClientTransport{
			client: NewHTTP2Client(h2Config, tlsConfig),
		}, nil

	case TransportTypeHTTPU:
		httpuConfig := config.HTTPUpgrade
		if httpuConfig == nil {
			httpuConfig = &HTTPUpgradeConfig{Path: config.Path}
		}
		return &HTTPUpgradeClientTransport{
			client: NewHTTPUpgradeClient(httpuConfig, tlsConfig),
		}, nil

	case TransportTypeSplitHTTP:
		splitConfig := config.SplitHTTP
		if splitConfig == nil {
			splitConfig = &SplitHTTPConfig{Path: config.Path}
		}
		return &SplitHTTPClientTransport{
			client: NewSplitHTTPClient(splitConfig, tlsConfig),
		}, nil

	default:
		return nil, fmt.Errorf("unknown transport type: %s", config.Type)
	}
}

// ClientTransport interface for client transports
type ClientTransport interface {
	Connect(ctx context.Context, address string) (net.Conn, error)
	Close() error
}

// TCPClientTransport wraps TCP client
type TCPClientTransport struct {
	client    *TCPClient
	tlsConfig *tls.Config
	fragment  *FragmentConfig
	mux       *MuxConfig
}

// Connect establishes connection
func (tct *TCPClientTransport) Connect(ctx context.Context, address string) (net.Conn, error) {
	conn, err := tct.client.Connect(ctx, address)
	if err != nil {
		return nil, err
	}

	// Wrap with TLS if configured
	if tct.tlsConfig != nil {
		tlsConn := tls.Client(conn, tct.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tlsConn
	}

	// Wrap with fragment if configured
	if tct.fragment != nil && tct.fragment.Enabled {
		conn = NewFragmentConn(conn, tct.fragment)
	}

	return conn, nil
}

// Close closes client
func (tct *TCPClientTransport) Close() error { return nil }

// WSClientTransport wraps WebSocket client
type WSClientTransport struct {
	client *WebSocketClient
}

// Connect establishes connection
func (wct *WSClientTransport) Connect(ctx context.Context, address string) (net.Conn, error) {
	return wct.client.Connect(ctx, address)
}

// Close closes client
func (wct *WSClientTransport) Close() error { return nil }

// GRPCClientTransport wraps gRPC client
type GRPCClientTransport struct {
	client *GRPCClient
}

// Connect establishes connection
func (gct *GRPCClientTransport) Connect(ctx context.Context, address string) (net.Conn, error) {
	return gct.client.Connect(ctx, address)
}

// Close closes client
func (gct *GRPCClientTransport) Close() error { return gct.client.Close() }

// HTTP2ClientTransport wraps HTTP/2 client
type HTTP2ClientTransport struct {
	client *HTTP2Client
}

// Connect establishes connection
func (hct *HTTP2ClientTransport) Connect(ctx context.Context, address string) (net.Conn, error) {
	return hct.client.Connect(ctx, address)
}

// Close closes client
func (hct *HTTP2ClientTransport) Close() error { return hct.client.Close() }

// HTTPUpgradeClientTransport wraps HTTPUpgrade client
type HTTPUpgradeClientTransport struct {
	client *HTTPUpgradeClient
}

// Connect establishes connection
func (huct *HTTPUpgradeClientTransport) Connect(ctx context.Context, address string) (net.Conn, error) {
	return huct.client.Connect(ctx, address)
}

// Close closes client
func (huct *HTTPUpgradeClientTransport) Close() error { return nil }

// SplitHTTPClientTransport wraps SplitHTTP client
type SplitHTTPClientTransport struct {
	client *SplitHTTPClient
}

// Connect establishes connection
func (shct *SplitHTTPClientTransport) Connect(ctx context.Context, address string) (net.Conn, error) {
	return shct.client.Connect(ctx, address)
}

// Close closes client
func (shct *SplitHTTPClientTransport) Close() error { return nil }

// ==================== Transport Manager ====================

// TransportManager manages all transports
type TransportManager struct {
	factory *TransportFactory
	servers map[string]interface{}
	clients map[string]ClientTransport
	mu      sync.RWMutex
	stats   TransportManagerStats
}

// TransportManagerStats holds manager statistics
type TransportManagerStats struct {
	ActiveServers    int64
	ActiveClients    int64
	TotalConnections int64
}

// NewTransportManager creates new transport manager
func NewTransportManager() *TransportManager {
	return &TransportManager{
		factory: NewTransportFactory(),
		servers: make(map[string]interface{}),
		clients: make(map[string]ClientTransport),
	}
}

// AddServer adds and starts a server transport
func (tm *TransportManager) AddServer(id string, config *TransportConfig, handler func(net.Conn)) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if _, exists := tm.servers[id]; exists {
		return fmt.Errorf("server %s already exists", id)
	}

	server, err := tm.factory.CreateServerTransport(config, handler)
	if err != nil {
		return err
	}

	tm.servers[id] = server
	atomic.AddInt64(&tm.stats.ActiveServers, 1)

	// Start server in background
	go tm.startServer(id, server, config)

	return nil
}

// startServer starts server based on type
func (tm *TransportManager) startServer(id string, server interface{}, config *TransportConfig) {
	address := fmt.Sprintf("%s:%d", config.Host, config.Port)

	switch s := server.(type) {
	case *TCPServer:
		if err := s.Listen(address); err != nil {
			tm.removeServer(id)
		}
	case *WebSocketServer:
		if err := s.Listen(address); err != nil {
			tm.removeServer(id)
		}
	case *GRPCServer:
		if err := s.Listen(address); err != nil {
			tm.removeServer(id)
		}
	case *HTTP2Server:
		if err := s.Listen(address); err != nil {
			tm.removeServer(id)
		}
	case *HTTPUpgradeServer:
		if err := s.Listen(address); err != nil {
			tm.removeServer(id)
		}
	case *SplitHTTPServer:
		if err := s.Listen(address); err != nil {
			tm.removeServer(id)
		}
	}
}

// removeServer removes server from manager
func (tm *TransportManager) removeServer(id string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if _, exists := tm.servers[id]; exists {
		delete(tm.servers, id)
		atomic.AddInt64(&tm.stats.ActiveServers, -1)
	}
}

// RemoveServer stops and removes a server transport
func (tm *TransportManager) RemoveServer(id string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	server, exists := tm.servers[id]
	if !exists {
		return fmt.Errorf("server %s not found", id)
	}

	// Close server based on type
	switch s := server.(type) {
	case *TCPServer:
		s.Close()
	case *WebSocketServer:
		s.Close()
	case *GRPCServer:
		s.Close()
	case *HTTP2Server:
		s.Close()
	case *HTTPUpgradeServer:
		s.Close()
	case *SplitHTTPServer:
		s.Close()
	case io.Closer:
		s.Close()
	}

	delete(tm.servers, id)
	atomic.AddInt64(&tm.stats.ActiveServers, -1)

	return nil
}

// AddClient adds a client transport
func (tm *TransportManager) AddClient(id string, config *TransportConfig) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if _, exists := tm.clients[id]; exists {
		return fmt.Errorf("client %s already exists", id)
	}

	client, err := tm.factory.CreateClientTransport(config)
	if err != nil {
		return err
	}

	tm.clients[id] = client
	atomic.AddInt64(&tm.stats.ActiveClients, 1)

	return nil
}

// RemoveClient removes a client transport
func (tm *TransportManager) RemoveClient(id string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	client, exists := tm.clients[id]
	if !exists {
		return fmt.Errorf("client %s not found", id)
	}

	client.Close()
	delete(tm.clients, id)
	atomic.AddInt64(&tm.stats.ActiveClients, -1)

	return nil
}

// GetClient gets a client transport by ID
func (tm *TransportManager) GetClient(id string) (ClientTransport, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	client, exists := tm.clients[id]
	if !exists {
		return nil, fmt.Errorf("client %s not found", id)
	}

	return client, nil
}

// Connect establishes connection using specified client
func (tm *TransportManager) Connect(clientID string, ctx context.Context, address string) (net.Conn, error) {
	client, err := tm.GetClient(clientID)
	if err != nil {
		return nil, err
	}

	conn, err := client.Connect(ctx, address)
	if err != nil {
		return nil, err
	}

	atomic.AddInt64(&tm.stats.TotalConnections, 1)
	return conn, nil
}

// GetStats returns manager statistics
func (tm *TransportManager) GetStats() TransportManagerStats {
	return TransportManagerStats{
		ActiveServers:    atomic.LoadInt64(&tm.stats.ActiveServers),
		ActiveClients:    atomic.LoadInt64(&tm.stats.ActiveClients),
		TotalConnections: atomic.LoadInt64(&tm.stats.TotalConnections),
	}
}

// GetServerStats returns statistics for a specific server
func (tm *TransportManager) GetServerStats(id string) (interface{}, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	server, exists := tm.servers[id]
	if !exists {
		return nil, fmt.Errorf("server %s not found", id)
	}

	switch s := server.(type) {
	case *TCPServer:
		return s.GetStats(), nil
	case *WebSocketServer:
		return s.GetStats(), nil
	case *GRPCServer:
		return s.GetStats(), nil
	case *HTTP2Server:
		return s.GetStats(), nil
	case *HTTPUpgradeServer:
		return s.GetStats(), nil
	case *SplitHTTPServer:
		return s.GetStats(), nil
	default:
		return nil, errors.New("server type does not support stats")
	}
}

// ListServers returns list of server IDs
func (tm *TransportManager) ListServers() []string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	ids := make([]string, 0, len(tm.servers))
	for id := range tm.servers {
		ids = append(ids, id)
	}
	return ids
}

// ListClients returns list of client IDs
func (tm *TransportManager) ListClients() []string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	ids := make([]string, 0, len(tm.clients))
	for id := range tm.clients {
		ids = append(ids, id)
	}
	return ids
}

// Close closes all transports
func (tm *TransportManager) Close() error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Close all servers
	for _, server := range tm.servers {
		if closer, ok := server.(io.Closer); ok {
			closer.Close()
		}
	}

	// Close all clients
	for _, client := range tm.clients {
		client.Close()
	}

	tm.servers = make(map[string]interface{})
	tm.clients = make(map[string]ClientTransport)

	return nil
}
