// MXUI VPN Panel
// Core/single_port.go
// Single Port Mode - All Protocols on Port 443

package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// ============================================================================
// SINGLE PORT CONSTANTS
// ============================================================================

const (
	// SinglePortNumber defined in protocols.go
	SinglePortFallback   = "127.0.0.1:8080"
	SinglePortBufferSize = 32 * 1024
	SinglePortTimeout    = 30 * time.Second
)

// ============================================================================
// SINGLE PORT MANAGER
// ============================================================================

// SinglePortManager manages all protocols on a single port
type SinglePortManager struct {
	enabled      bool
	port         int
	fallbackAddr string
	listener     net.Listener
	tlsConfig    *tls.Config
	protocols    map[string]*ProtocolHandler
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
	stats        *PortStats
}

// ProtocolHandler handles specific protocol traffic
type ProtocolHandler struct {
	Name     string
	Detector ProtocolDetector
	Handler  ConnectionHandler
	Priority int
	Enabled  bool
}

// ProtocolDetector detects protocol from initial bytes
type ProtocolDetector func([]byte) bool

// ConnectionHandler handles the connection
type ConnectionHandler func(net.Conn, []byte) error

// PortStats tracks single port statistics
type PortStats struct {
	TotalConnections  int64
	ActiveConnections int64
	ProtocolCounts    map[string]int64
	BytesReceived     int64
	BytesSent         int64
	mu                sync.RWMutex
}

// Global single port manager
var SinglePort *SinglePortManager

// ============================================================================
// INITIALIZATION
// ============================================================================

// InitSinglePortManager initializes single port mode
func InitSinglePortManager(enabled bool, port int, fallback string) error {
	ctx, cancel := context.WithCancel(context.Background())

	SinglePort = &SinglePortManager{
		enabled:      enabled,
		port:         port,
		fallbackAddr: fallback,
		protocols:    make(map[string]*ProtocolHandler),
		ctx:          ctx,
		cancel:       cancel,
		stats: &PortStats{
			ProtocolCounts: make(map[string]int64),
		},
	}

	if !enabled {
		LogInfo("SINGLE-PORT", "Single port mode disabled")
		return nil
	}

	// Setup TLS config
	if err := SinglePort.setupTLS(); err != nil {
		return fmt.Errorf("failed to setup TLS: %w", err)
	}

	// Register protocol detectors
	SinglePort.registerProtocols()

	LogInfo("SINGLE-PORT", "Single port mode initialized on port %d", port)
	return nil
}

// Start starts the single port listener
func (spm *SinglePortManager) Start() error {
	if !spm.enabled {
		return nil
	}

	// Create listener
	addr := fmt.Sprintf("0.0.0.0:%d", spm.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	spm.listener = listener

	LogSuccess("SINGLE-PORT", "Listening on port %d", spm.port)

	// Start accepting connections
	go spm.acceptConnections()

	return nil
}

// Stop stops the single port listener
func (spm *SinglePortManager) Stop() error {
	if spm.listener != nil {
		spm.cancel()
		return spm.listener.Close()
	}
	return nil
}

// ============================================================================
// PROTOCOL REGISTRATION
// ============================================================================

// registerProtocols registers all protocol detectors
func (spm *SinglePortManager) registerProtocols() {
	// VLESS with REALITY/TLS
	spm.RegisterProtocol(&ProtocolHandler{
		Name:     "VLESS-TLS",
		Detector: detectVLESSTLS,
		Handler:  handleVLESS,
		Priority: 10,
		Enabled:  true,
	})

	// VMess
	spm.RegisterProtocol(&ProtocolHandler{
		Name:     "VMess",
		Detector: detectVMess,
		Handler:  handleVMess,
		Priority: 9,
		Enabled:  true,
	})

	// Trojan
	spm.RegisterProtocol(&ProtocolHandler{
		Name:     "Trojan",
		Detector: detectTrojan,
		Handler:  handleTrojan,
		Priority: 8,
		Enabled:  true,
	})

	// Shadowsocks
	spm.RegisterProtocol(&ProtocolHandler{
		Name:     "Shadowsocks",
		Detector: detectShadowsocks,
		Handler:  handleShadowsocks,
		Priority: 7,
		Enabled:  true,
	})

	// HTTP/HTTPS (Fallback to web panel)
	spm.RegisterProtocol(&ProtocolHandler{
		Name:     "HTTP",
		Detector: detectHTTP,
		Handler:  handleHTTPFallback,
		Priority: 1,
		Enabled:  true,
	})
}

// RegisterProtocol registers a protocol handler
func (spm *SinglePortManager) RegisterProtocol(handler *ProtocolHandler) {
	spm.mu.Lock()
	defer spm.mu.Unlock()

	spm.protocols[handler.Name] = handler
	LogInfo("SINGLE-PORT", "Registered protocol: %s (priority: %d)", handler.Name, handler.Priority)
}

// ============================================================================
// CONNECTION HANDLING
// ============================================================================

// acceptConnections accepts and routes incoming connections
func (spm *SinglePortManager) acceptConnections() {
	for {
		select {
		case <-spm.ctx.Done():
			return
		default:
		}

		conn, err := spm.listener.Accept()
		if err != nil {
			if spm.ctx.Err() != nil {
				return
			}
			LogError("SINGLE-PORT", "Accept error: %v", err)
			continue
		}

		// Update stats
		spm.stats.mu.Lock()
		spm.stats.TotalConnections++
		spm.stats.ActiveConnections++
		spm.stats.mu.Unlock()

		// Handle connection
		go spm.handleConnection(conn)
	}
}

// handleConnection routes a connection to appropriate handler
func (spm *SinglePortManager) handleConnection(conn net.Conn) {
	defer func() {
		conn.Close()
		spm.stats.mu.Lock()
		spm.stats.ActiveConnections--
		spm.stats.mu.Unlock()
	}()

	// Set deadline for protocol detection
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read initial bytes for protocol detection
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		LogDebug("SINGLE-PORT", "Failed to read initial bytes: %v", err)
		return
	}

	// Reset deadline
	conn.SetReadDeadline(time.Time{})

	initialBytes := buf[:n]

	// Detect and route to protocol handler
	handler := spm.detectProtocol(initialBytes)

	if handler == nil {
		LogWarn("SINGLE-PORT", "Unknown protocol, using fallback")
		spm.handleFallback(conn, initialBytes)
		return
	}

	// Update protocol stats
	spm.stats.mu.Lock()
	spm.stats.ProtocolCounts[handler.Name]++
	spm.stats.mu.Unlock()

	LogDebug("SINGLE-PORT", "Detected protocol: %s", handler.Name)

	// Handle with appropriate handler
	if err := handler.Handler(conn, initialBytes); err != nil {
		LogError("SINGLE-PORT", "Handler error for %s: %v", handler.Name, err)
	}
}

// detectProtocol detects protocol from initial bytes
func (spm *SinglePortManager) detectProtocol(data []byte) *ProtocolHandler {
	spm.mu.RLock()
	defer spm.mu.RUnlock()

	var matched []*ProtocolHandler

	// Test all protocol detectors
	for _, handler := range spm.protocols {
		if !handler.Enabled {
			continue
		}

		if handler.Detector(data) {
			matched = append(matched, handler)
		}
	}

	// Return highest priority match
	if len(matched) == 0 {
		return nil
	}

	best := matched[0]
	for _, h := range matched {
		if h.Priority > best.Priority {
			best = h
		}
	}

	return best
}

// handleFallback handles unknown protocols (redirect to web panel)
func (spm *SinglePortManager) handleFallback(conn net.Conn, initialBytes []byte) {
	// Connect to fallback address (web panel)
	backend, err := net.Dial("tcp", spm.fallbackAddr)
	if err != nil {
		LogError("SINGLE-PORT", "Fallback connection failed: %v", err)
		return
	}
	defer backend.Close()

	// Send initial bytes
	if _, err := backend.Write(initialBytes); err != nil {
		LogError("SINGLE-PORT", "Failed to write to fallback: %v", err)
		return
	}

	// Bidirectional copy
	go io.Copy(backend, conn)
	io.Copy(conn, backend)
}

// ============================================================================
// PROTOCOL DETECTORS
// ============================================================================

// detectTLS detects TLS protocol
func detectTLS(data []byte) bool {
	if len(data) < 3 {
		return false
	}

	// Check for TLS handshake (0x16 = handshake, 0x03 = SSL 3.0/TLS 1.x)
	if data[0] == 0x16 && data[1] == 0x03 {
		return true
	}

	return false
}

// detectVLESSTLS detects VLESS with TLS
func detectVLESSTLS(data []byte) bool {
	return detectTLS(data)
}

// detectVMess detects VMess protocol
func detectVMess(data []byte) bool {
	if len(data) < 16 {
		return false
	}

	// VMess v1: auth + cmd + ...
	// First byte should be auth version (usually 1)
	// VMess uses AEAD or legacy format

	// Check if it looks like encrypted data (high entropy)
	// For simplicity, check if first 16 bytes don't match other protocols
	if !detectTLS(data) && !detectHTTP(data) && !detectTrojan(data) {
		// Likely VMess or encrypted protocol
		return true
	}

	return false
}

// detectTrojan detects Trojan protocol
func detectTrojan(data []byte) bool {
	if len(data) < 56 {
		return false
	}

	// Trojan starts with 56 byte hex password hash
	for i := 0; i < 56; i++ {
		c := data[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}

	return true
}

// detectShadowsocks detects Shadowsocks
func detectShadowsocks(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Shadowsocks 2022 and AEAD formats
	// Check for salt (first 32 bytes for AEAD)
	// For simplicity, if it's encrypted and not other protocols, might be SS

	// Basic heuristic: if it's not TLS, HTTP, Trojan, or VMess
	// and appears to be encrypted, could be Shadowsocks
	if len(data) >= 32 {
		// Could be Shadowsocks AEAD with salt
		return !detectTLS(data) && !detectHTTP(data) && !detectTrojan(data)
	}

	return false
}

// detectHTTP detects HTTP/HTTPS traffic
func detectHTTP(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Check for HTTP methods
	methods := []string{"GET ", "POST", "PUT ", "HEAD", "DELE", "OPTI", "PATC", "CONN"}

	for _, method := range methods {
		if len(data) >= len(method) {
			if string(data[:len(method)]) == method {
				return true
			}
		}
	}

	return false
}

// ============================================================================
// PROTOCOL HANDLERS (Stub implementations)
// ============================================================================

func handleVLESS(conn net.Conn, initialBytes []byte) error {
	// Forward to Xray VLESS handler
	return forwardToXray(conn, initialBytes, "vless")
}

func handleVMess(conn net.Conn, initialBytes []byte) error {
	// Forward to Xray VMess handler
	return forwardToXray(conn, initialBytes, "vmess")
}

func handleTrojan(conn net.Conn, initialBytes []byte) error {
	// Forward to Xray Trojan handler
	return forwardToXray(conn, initialBytes, "trojan")
}

func handleShadowsocks(conn net.Conn, initialBytes []byte) error {
	// Forward to Shadowsocks handler
	return forwardToXray(conn, initialBytes, "shadowsocks")
}

func handleHTTPFallback(conn net.Conn, initialBytes []byte) error {
	// Forward to web panel
	backend, err := net.Dial("tcp", SinglePort.fallbackAddr)
	if err != nil {
		return err
	}
	defer backend.Close()

	backend.Write(initialBytes)

	go io.Copy(backend, conn)
	io.Copy(conn, backend)

	return nil
}

// forwardToXray forwards connection to Xray core
func forwardToXray(conn net.Conn, initialBytes []byte, protocol string) error {
	// Get appropriate inbound port based on protocol
	var xrayPort int

	switch protocol {
	case "vless":
		xrayPort = 62789 // VLESS inbound port
	case "vmess":
		xrayPort = 62788 // VMess inbound port
	case "trojan":
		xrayPort = 62787 // Trojan inbound port
	case "shadowsocks":
		xrayPort = 62786 // Shadowsocks inbound port
	default:
		xrayPort = 62789
	}

	backend, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", xrayPort))
	if err != nil {
		return fmt.Errorf("failed to connect to xray %s port: %w", protocol, err)
	}
	defer backend.Close()

	// Send initial bytes
	if _, err := backend.Write(initialBytes); err != nil {
		return err
	}

	// Bidirectional copy
	go io.Copy(backend, conn)
	io.Copy(conn, backend)

	return nil
}

// ============================================================================
// TLS SETUP
// ============================================================================

// setupTLS sets up TLS configuration
func (spm *SinglePortManager) setupTLS() error {
	// Load certificates
	cert, err := loadOrGenerateCertificate()
	if err != nil {
		return err
	}

	spm.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}

	return nil
}

// loadOrGenerateCertificate loads or generates SSL certificate
func loadOrGenerateCertificate() (tls.Certificate, error) {
	// Try to load existing certificate
	certFile := "./Data/certs/cert.pem"
	keyFile := "./Data/certs/key.pem"

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err == nil {
		return cert, nil
	}

	// Generate self-signed certificate
	LogWarn("SINGLE-PORT", "Generating self-signed certificate")
	return generateSelfSignedCert()
}

// generateSelfSignedCert generates a self-signed certificate
func generateSelfSignedCert() (tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"MXUI"},
			CommonName:   "mxui.local",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Save to files
	os.MkdirAll("./Data/certs", 0755)

	certOut, err := os.Create("./Data/certs/cert.pem")
	if err != nil {
		return tls.Certificate{}, err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.Create("./Data/certs/key.pem")
	if err != nil {
		return tls.Certificate{}, err
	}
	privBytes, _ := x509.MarshalECPrivateKey(privateKey)
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	keyOut.Close()

	return tls.LoadX509KeyPair("./Data/certs/cert.pem", "./Data/certs/key.pem")
}

// ============================================================================
// STATISTICS
// ============================================================================

// GetStats returns single port statistics
func (spm *SinglePortManager) GetStats() map[string]interface{} {
	spm.stats.mu.RLock()
	defer spm.stats.mu.RUnlock()

	protocolCounts := make(map[string]int64)
	for k, v := range spm.stats.ProtocolCounts {
		protocolCounts[k] = v
	}

	return map[string]interface{}{
		"enabled":            spm.enabled,
		"port":               spm.port,
		"total_connections":  spm.stats.TotalConnections,
		"active_connections": spm.stats.ActiveConnections,
		"protocol_counts":    protocolCounts,
		"bytes_received":     spm.stats.BytesReceived,
		"bytes_sent":         spm.stats.BytesSent,
	}
}

// ResetStats resets statistics
func (spm *SinglePortManager) ResetStats() {
	spm.stats.mu.Lock()
	defer spm.stats.mu.Unlock()

	spm.stats.TotalConnections = 0
	spm.stats.ProtocolCounts = make(map[string]int64)
	spm.stats.BytesReceived = 0
	spm.stats.BytesSent = 0
}
