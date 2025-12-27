// Core/tools.go
// MXUI VPN Panel - Tools & Utilities
// Part 1: Network Utils, Crypto, Validators, Helpers

package core

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/scrypt"
)

// ==================== Constants ====================

const (
	// Crypto constants
	AESKeySize   = 32 // AES-256
	NonceSize    = 12 // GCM nonce
	SaltSize     = 32
	ScryptN      = 32768
	ScryptR      = 8
	ScryptP      = 1
	ScryptKeyLen = 32

	// Network constants
	DefaultTimeout     = 10 * time.Second
	DefaultPingCount   = 4
	MaxConcurrentPings = 100

	// Validation patterns
	EmailPattern    = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	UsernamePattern = `^[a-zA-Z0-9_-]{3,32}$`
	DomainPattern   = `^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	UUIDPattern     = `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
)

// ==================== Network Utilities ====================

// NetworkTools provides network utility functions
type NetworkTools struct {
	httpClient *http.Client
	dnsServers []string
}

// NewNetworkTools creates new network tools instance
func NewNetworkTools() *NetworkTools {
	return &NetworkTools{
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
				MaxIdleConns:    100,
				IdleConnTimeout: 90 * time.Second,
			},
		},
		dnsServers: []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"},
	}
}

// PingResult represents ping test result
type PingResult struct {
	Host      string        `json:"host"`
	IP        string        `json:"ip"`
	Sent      int           `json:"sent"`
	Received  int           `json:"received"`
	Loss      float64       `json:"loss"`
	MinRTT    time.Duration `json:"min_rtt"`
	MaxRTT    time.Duration `json:"max_rtt"`
	AvgRTT    time.Duration `json:"avg_rtt"`
	Error     string        `json:"error,omitempty"`
	Reachable bool          `json:"reachable"`
}

// Ping performs ICMP ping to host
func (nt *NetworkTools) Ping(host string, count int) *PingResult {
	result := &PingResult{
		Host: host,
		Sent: count,
	}

	if count <= 0 {
		count = DefaultPingCount
	}

	// Resolve hostname
	ips, err := net.LookupIP(host)
	if err != nil {
		result.Error = fmt.Sprintf("DNS lookup failed: %v", err)
		return result
	}

	if len(ips) > 0 {
		result.IP = ips[0].String()
	}

	// Use system ping command
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", strconv.Itoa(count), host)
	} else {
		cmd = exec.Command("ping", "-c", strconv.Itoa(count), "-W", "2", host)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		result.Error = fmt.Sprintf("ping failed: %v", err)
		return result
	}

	// Parse ping output
	nt.parsePingOutput(string(output), result)

	return result
}

// parsePingOutput parses ping command output
func (nt *NetworkTools) parsePingOutput(output string, result *PingResult) {
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse packet statistics
		if strings.Contains(line, "packets transmitted") || strings.Contains(line, "Packets: Sent") {
			// Linux: 4 packets transmitted, 4 received, 0% packet loss
			// Windows: Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)
			re := regexp.MustCompile(`(\d+).*(?:transmitted|Sent).*?(\d+).*(?:received|Received)`)
			matches := re.FindStringSubmatch(line)
			if len(matches) >= 3 {
				result.Sent, _ = strconv.Atoi(matches[1])
				result.Received, _ = strconv.Atoi(matches[2])
				if result.Sent > 0 {
					result.Loss = float64(result.Sent-result.Received) / float64(result.Sent) * 100
				}
			}
		}

		// Parse RTT statistics
		if strings.Contains(line, "min/avg/max") || strings.Contains(line, "Minimum") {
			// Linux: rtt min/avg/max/mdev = 0.123/0.456/0.789/0.111 ms
			// Windows: Minimum = 1ms, Maximum = 5ms, Average = 2ms
			if runtime.GOOS == "windows" {
				re := regexp.MustCompile(`Minimum = (\d+)ms.*Maximum = (\d+)ms.*Average = (\d+)ms`)
				matches := re.FindStringSubmatch(line)
				if len(matches) >= 4 {
					min, _ := strconv.Atoi(matches[1])
					max, _ := strconv.Atoi(matches[2])
					avg, _ := strconv.Atoi(matches[3])
					result.MinRTT = time.Duration(min) * time.Millisecond
					result.MaxRTT = time.Duration(max) * time.Millisecond
					result.AvgRTT = time.Duration(avg) * time.Millisecond
				}
			} else {
				re := regexp.MustCompile(`([\d.]+)/([\d.]+)/([\d.]+)`)
				matches := re.FindStringSubmatch(line)
				if len(matches) >= 4 {
					min, _ := strconv.ParseFloat(matches[1], 64)
					avg, _ := strconv.ParseFloat(matches[2], 64)
					max, _ := strconv.ParseFloat(matches[3], 64)
					result.MinRTT = time.Duration(min * float64(time.Millisecond))
					result.AvgRTT = time.Duration(avg * float64(time.Millisecond))
					result.MaxRTT = time.Duration(max * float64(time.Millisecond))
				}
			}
		}
	}

	result.Reachable = result.Received > 0
}

// TCPPing performs TCP ping to host:port
func (nt *NetworkTools) TCPPing(host string, port int, timeout time.Duration) (time.Duration, error) {
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	address := fmt.Sprintf("%s:%d", host, port)
	start := time.Now()

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	return time.Since(start), nil
}

// PortCheck checks if a port is open
func (nt *NetworkTools) PortCheck(host string, port int, timeout time.Duration) bool {
	_, err := nt.TCPPing(host, port, timeout)
	return err == nil
}

// PortScan scans multiple ports on a host
func (nt *NetworkTools) PortScan(host string, ports []int, timeout time.Duration) map[int]bool {
	results := make(map[int]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, 50) // Limit concurrent scans

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			open := nt.PortCheck(host, p, timeout)
			mu.Lock()
			results[p] = open
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	return results
}

// GetOpenPorts returns list of open ports
func (nt *NetworkTools) GetOpenPorts(host string, startPort, endPort int) []int {
	var ports []int
	for i := startPort; i <= endPort; i++ {
		ports = append(ports, i)
	}

	results := nt.PortScan(host, ports, 2*time.Second)

	var openPorts []int
	for port, open := range results {
		if open {
			openPorts = append(openPorts, port)
		}
	}

	return openPorts
}

// DNSLookup performs DNS lookup
func (nt *NetworkTools) DNSLookup(host string) (*DNSResult, error) {
	result := &DNSResult{
		Host: host,
	}

	// A records
	ips, err := net.LookupIP(host)
	if err == nil {
		for _, ip := range ips {
			if ip.To4() != nil {
				result.IPv4 = append(result.IPv4, ip.String())
			} else {
				result.IPv6 = append(result.IPv6, ip.String())
			}
		}
	}

	// CNAME
	cname, err := net.LookupCNAME(host)
	if err == nil {
		result.CNAME = cname
	}

	// MX records
	mxRecords, err := net.LookupMX(host)
	if err == nil {
		for _, mx := range mxRecords {
			result.MX = append(result.MX, fmt.Sprintf("%s (priority: %d)", mx.Host, mx.Pref))
		}
	}

	// TXT records
	txtRecords, err := net.LookupTXT(host)
	if err == nil {
		result.TXT = txtRecords
	}

	// NS records
	nsRecords, err := net.LookupNS(host)
	if err == nil {
		for _, ns := range nsRecords {
			result.NS = append(result.NS, ns.Host)
		}
	}

	return result, nil
}

// DNSResult represents DNS lookup result
type DNSResult struct {
	Host  string   `json:"host"`
	IPv4  []string `json:"ipv4,omitempty"`
	IPv6  []string `json:"ipv6,omitempty"`
	CNAME string   `json:"cname,omitempty"`
	MX    []string `json:"mx,omitempty"`
	TXT   []string `json:"txt,omitempty"`
	NS    []string `json:"ns,omitempty"`
}

// ReverseDNS performs reverse DNS lookup
func (nt *NetworkTools) ReverseDNS(ip string) ([]string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return nil, err
	}
	return names, nil
}

// GetPublicIP returns public IP address
func (nt *NetworkTools) GetPublicIP() (string, error) {
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
		"https://ipinfo.io/ip",
	}

	for _, service := range services {
		resp, err := nt.httpClient.Get(service)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) != nil {
			return ip, nil
		}
	}

	return "", errors.New("failed to get public IP")
}

// GetIPInfo returns information about an IP address
func (nt *NetworkTools) GetIPInfo(ip string) (*IPInfo, error) {
	if ip == "" {
		var err error
		ip, err = nt.GetPublicIP()
		if err != nil {
			return nil, err
		}
	}

	url := fmt.Sprintf("http://ip-api.com/json/%s", ip)
	resp, err := nt.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var info IPInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}

	return &info, nil
}

// IPInfo represents IP geolocation info
type IPInfo struct {
	IP          string  `json:"query"`
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
}

// CheckHTTP checks HTTP(S) endpoint
func (nt *NetworkTools) CheckHTTP(urlStr string, timeout time.Duration) (*HTTPCheckResult, error) {
	result := &HTTPCheckResult{
		URL: urlStr,
	}

	if timeout == 0 {
		timeout = DefaultTimeout
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			result.Redirects = len(via)
			return nil
		},
	}

	start := time.Now()
	resp, err := client.Get(urlStr)
	result.ResponseTime = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		result.Available = false
		return result, nil
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Status = resp.Status
	result.Available = resp.StatusCode >= 200 && resp.StatusCode < 400

	// Get headers
	result.Headers = make(map[string]string)
	for key, values := range resp.Header {
		result.Headers[key] = strings.Join(values, ", ")
	}

	// Check SSL
	if resp.TLS != nil {
		result.SSLValid = true
		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			result.SSLExpiry = cert.NotAfter
			result.SSLIssuer = cert.Issuer.CommonName
		}
	}

	return result, nil
}

// HTTPCheckResult represents HTTP check result
type HTTPCheckResult struct {
	URL          string            `json:"url"`
	Available    bool              `json:"available"`
	StatusCode   int               `json:"status_code"`
	Status       string            `json:"status"`
	ResponseTime time.Duration     `json:"response_time"`
	Redirects    int               `json:"redirects"`
	Headers      map[string]string `json:"headers,omitempty"`
	SSLValid     bool              `json:"ssl_valid"`
	SSLExpiry    time.Time         `json:"ssl_expiry,omitempty"`
	SSLIssuer    string            `json:"ssl_issuer,omitempty"`
	Error        string            `json:"error,omitempty"`
}

// SpeedTest performs a simple speed test
func (nt *NetworkTools) SpeedTest(downloadURL, uploadURL string) (*SpeedTestResult, error) {
	result := &SpeedTestResult{}

	// Download test
	if downloadURL != "" {
		start := time.Now()
		resp, err := nt.httpClient.Get(downloadURL)
		if err != nil {
			result.DownloadError = err.Error()
		} else {
			defer resp.Body.Close()
			written, _ := io.Copy(io.Discard, resp.Body)
			duration := time.Since(start).Seconds()
			if duration > 0 {
				result.DownloadSpeed = float64(written) / duration / 1024 / 1024 // MB/s
				result.DownloadBytes = written
			}
		}
	}

	// Upload test (simplified - sends random data)
	if uploadURL != "" {
		data := make([]byte, 1024*1024) // 1MB
		rand.Read(data)

		start := time.Now()
		resp, err := nt.httpClient.Post(uploadURL, "application/octet-stream", bytes.NewReader(data))
		if err != nil {
			result.UploadError = err.Error()
		} else {
			defer resp.Body.Close()
			duration := time.Since(start).Seconds()
			if duration > 0 {
				result.UploadSpeed = float64(len(data)) / duration / 1024 / 1024 // MB/s
				result.UploadBytes = int64(len(data))
			}
		}
	}

	return result, nil
}

// SpeedTestResult represents speed test result
type SpeedTestResult struct {
	DownloadSpeed float64 `json:"download_speed_mbps"`
	UploadSpeed   float64 `json:"upload_speed_mbps"`
	DownloadBytes int64   `json:"download_bytes"`
	UploadBytes   int64   `json:"upload_bytes"`
	DownloadError string  `json:"download_error,omitempty"`
	UploadError   string  `json:"upload_error,omitempty"`
}

// GetLocalIPs returns local IP addresses
func GetLocalIPs() ([]string, error) {
	var ips []string

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}

	return ips, nil
}

// GetLocalIPv6s returns local IPv6 addresses
func GetLocalIPv6s() ([]string, error) {
	var ips []string

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() == nil && ipnet.IP.To16() != nil {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}

	return ips, nil
}

// IsPrivateIP checks if IP is private
func IsPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
		"127.0.0.0/8",
		"::1/128",
	}

	for _, block := range privateBlocks {
		_, cidr, _ := net.ParseCIDR(block)
		if cidr.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// ==================== Crypto Utilities ====================

// CryptoTools provides cryptographic utility functions
type CryptoTools struct{}

// NewCryptoTools creates new crypto tools instance
func NewCryptoTools() *CryptoTools {
	return &CryptoTools{}
}

// GenerateRandomBytes generates cryptographically secure random bytes
func (ct *CryptoTools) GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateRandomString generates random string of specified length
func (ct *CryptoTools) GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	rand.Read(b)
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

// GenerateSecureToken generates a secure token
func (ct *CryptoTools) GenerateSecureToken(length int) string {
	bytes, _ := ct.GenerateRandomBytes(length)
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}

// GenerateUUID generates a new UUID
func (ct *CryptoTools) GenerateUUID() string {
	return uuid.New().String()
}

// GenerateShortID generates a short unique ID
func (ct *CryptoTools) GenerateShortID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)[:13]
}

// HashPassword hashes password using bcrypt
func (ct *CryptoTools) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// VerifyPassword verifies password against hash
func (ct *CryptoTools) VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// HashSHA256 returns SHA256 hash of data
func (ct *CryptoTools) HashSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// HashSHA512 returns SHA512 hash of data
func (ct *CryptoTools) HashSHA512(data []byte) string {
	hash := sha512.Sum512(data)
	return hex.EncodeToString(hash[:])
}

// HashMD5 returns MD5 hash of data
func (ct *CryptoTools) HashMD5(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

// HMACSHA256 generates HMAC-SHA256
func (ct *CryptoTools) HMACSHA256(data, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// HMACSHA512 generates HMAC-SHA512
func (ct *CryptoTools) HMACSHA512(data, key []byte) string {
	h := hmac.New(sha512.New, key)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// DeriveKey derives a key from password using scrypt
func (ct *CryptoTools) DeriveKey(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, ScryptN, ScryptR, ScryptP, ScryptKeyLen)
}

// EncryptAES encrypts data using AES-GCM
func (ct *CryptoTools) EncryptAES(plaintext, key []byte) ([]byte, error) {
	if len(key) != AESKeySize {
		return nil, errors.New("invalid key size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptAES decrypts data using AES-GCM
func (ct *CryptoTools) DecryptAES(ciphertext, key []byte) ([]byte, error) {
	if len(key) != AESKeySize {
		return nil, errors.New("invalid key size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// EncryptString encrypts string and returns base64
func (ct *CryptoTools) EncryptString(plaintext string, key []byte) (string, error) {
	encrypted, err := ct.EncryptAES([]byte(plaintext), key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptString decrypts base64 encoded string
func (ct *CryptoTools) DecryptString(ciphertext string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	decrypted, err := ct.DecryptAES(data, key)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

// GenerateAESKey generates a random AES key
func (ct *CryptoTools) GenerateAESKey() ([]byte, error) {
	return ct.GenerateRandomBytes(AESKeySize)
}

// GenerateRSAKeyPair generates RSA key pair
func (ct *CryptoTools) GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if bits < 2048 {
		bits = 2048
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// RSAKeyToPEM converts RSA private key to PEM
func (ct *CryptoTools) RSAKeyToPEM(privateKey *rsa.PrivateKey) string {
	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}
	return string(pem.EncodeToMemory(block))
}

// RSAPublicKeyToPEM converts RSA public key to PEM
func (ct *CryptoTools) RSAPublicKeyToPEM(publicKey *rsa.PublicKey) string {
	keyBytes := x509.MarshalPKCS1PublicKey(publicKey)
	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: keyBytes,
	}
	return string(pem.EncodeToMemory(block))
}

// GenerateECDSAKeyPair generates ECDSA key pair
func (ct *CryptoTools) GenerateECDSAKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// GenerateEd25519KeyPair generates Ed25519 key pair
func (ct *CryptoTools) GenerateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// GenerateX25519KeyPair generates X25519 key pair for key exchange
func (ct *CryptoTools) GenerateX25519KeyPair() (publicKey, privateKey []byte, err error) {
	privateKey = make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, nil, err
	}

	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, nil
}

// X25519SharedSecret computes shared secret from X25519 keys
func (ct *CryptoTools) X25519SharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	return curve25519.X25519(privateKey, publicKey)
}

// GenerateSelfSignedCert generates self-signed TLS certificate
func (ct *CryptoTools) GenerateSelfSignedCert(hosts []string, validDays int) (certPEM, keyPEM []byte, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"MXUI VPN"},
			CommonName:   hosts[0],
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validDays),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return certPEM, keyPEM, nil
}

// Base64Encode encodes to base64
func (ct *CryptoTools) Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Base64Decode decodes from base64
func (ct *CryptoTools) Base64Decode(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

// Base64URLEncode encodes to URL-safe base64
func (ct *CryptoTools) Base64URLEncode(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

// Base64URLDecode decodes from URL-safe base64
func (ct *CryptoTools) Base64URLDecode(encoded string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(encoded)
}

// HexEncode encodes to hex
func (ct *CryptoTools) HexEncode(data []byte) string {
	return hex.EncodeToString(data)
}

// HexDecode decodes from hex
func (ct *CryptoTools) HexDecode(encoded string) ([]byte, error) {
	return hex.DecodeString(encoded)
}

// ==================== Validators ====================

// Validator provides validation functions
type Validator struct {
	emailRegex    *regexp.Regexp
	usernameRegex *regexp.Regexp
	domainRegex   *regexp.Regexp
	uuidRegex     *regexp.Regexp
}

// NewValidator creates new validator instance
func NewValidator() *Validator {
	return &Validator{
		emailRegex:    regexp.MustCompile(EmailPattern),
		usernameRegex: regexp.MustCompile(UsernamePattern),
		domainRegex:   regexp.MustCompile(DomainPattern),
		uuidRegex:     regexp.MustCompile(UUIDPattern),
	}
}

// IsValidEmail validates email address
func (v *Validator) IsValidEmail(email string) bool {
	return v.emailRegex.MatchString(email)
}

// IsValidUsername validates username
func (v *Validator) IsValidUsername(username string) bool {
	return v.usernameRegex.MatchString(username)
}

// IsValidDomain validates domain name
func (v *Validator) IsValidDomain(domain string) bool {
	return v.domainRegex.MatchString(domain)
}

// IsValidUUID validates UUID
func (v *Validator) IsValidUUID(id string) bool {
	return v.uuidRegex.MatchString(id)
}

// IsValidIP validates IP address (v4 or v6)
func (v *Validator) IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// IsValidIPv4 validates IPv4 address
func (v *Validator) IsValidIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil
}

// IsValidIPv6 validates IPv6 address
func (v *Validator) IsValidIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}

// IsValidCIDR validates CIDR notation
func (v *Validator) IsValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// IsValidPort validates port number
func (v *Validator) IsValidPort(port int) bool {
	return port > 0 && port <= 65535
}

// IsValidURL validates URL
func (v *Validator) IsValidURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return u.Scheme != "" && u.Host != ""
}

// IsValidHTTPURL validates HTTP/HTTPS URL
func (v *Validator) IsValidHTTPURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// IsValidMAC validates MAC address
func (v *Validator) IsValidMAC(mac string) bool {
	_, err := net.ParseMAC(mac)
	return err == nil
}

// IsValidJSON validates JSON string
func (v *Validator) IsValidJSON(jsonStr string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(jsonStr), &js) == nil
}

// IsValidBase64 validates base64 string
func (v *Validator) IsValidBase64(str string) bool {
	_, err := base64.StdEncoding.DecodeString(str)
	return err == nil
}

// IsValidHex validates hex string
func (v *Validator) IsValidHex(str string) bool {
	_, err := hex.DecodeString(str)
	return err == nil
}

// IsStrongPassword checks if password is strong
func (v *Validator) IsStrongPassword(password string) (bool, []string) {
	var issues []string

	if len(password) < 8 {
		issues = append(issues, "at least 8 characters required")
	}
	if len(password) > 128 {
		issues = append(issues, "maximum 128 characters allowed")
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		issues = append(issues, "at least one uppercase letter required")
	}
	if !hasLower {
		issues = append(issues, "at least one lowercase letter required")
	}
	if !hasDigit {
		issues = append(issues, "at least one digit required")
	}
	if !hasSpecial {
		issues = append(issues, "at least one special character required")
	}

	return len(issues) == 0, issues
}

// IsValidPhoneNumber validates phone number (basic)
func (v *Validator) IsValidPhoneNumber(phone string) bool {
	// Remove common formatting characters
	cleaned := strings.Map(func(r rune) rune {
		if r == '+' || r == '-' || r == ' ' || r == '(' || r == ')' {
			return -1
		}
		return r
	}, phone)

	// Check if all remaining are digits
	for _, r := range cleaned {
		if !unicode.IsDigit(r) {
			return false
		}
	}

	// Check length
	return len(cleaned) >= 7 && len(cleaned) <= 15
}

// ValidateStruct validates struct fields (basic implementation)
func (v *Validator) ValidateStruct(s interface{}) []string {
	// This is a simplified implementation
	// In production, use a library like validator
	return nil
}

// SanitizeString removes potentially dangerous characters
func (v *Validator) SanitizeString(input string) string {
	// Remove null bytes and control characters
	var result strings.Builder
	for _, r := range input {
		if r >= 32 && r != 127 {
			result.WriteRune(r)
		}
	}
	return strings.TrimSpace(result.String())
}

// SanitizeHTML removes HTML tags
func (v *Validator) SanitizeHTML(input string) string {
	re := regexp.MustCompile(`<[^>]*>`)
	return re.ReplaceAllString(input, "")
}

// SanitizeSQL escapes SQL special characters
func (v *Validator) SanitizeSQL(input string) string {
	replacer := strings.NewReplacer(
		"'", "''",
		"\\", "\\\\",
		"\x00", "",
		"\n", "\\n",
		"\r", "\\r",
		"\x1a", "\\Z",
	)
	return replacer.Replace(input)
}

// ==================== File Utilities ====================

// FileTools provides file utility functions
type FileTools struct{}

// NewFileTools creates new file tools instance
func NewFileTools() *FileTools {
	return &FileTools{}
}

// FileExists checks if file exists
func (ft *FileTools) FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// DirExists checks if directory exists
func (ft *FileTools) DirExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

// CreateDir creates directory with parents
func (ft *FileTools) CreateDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// ReadFile reads entire file
func (ft *FileTools) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// WriteFile writes data to file
func (ft *FileTools) WriteFile(path string, data []byte, perm os.FileMode) error {
	if perm == 0 {
		perm = 0644
	}
	return os.WriteFile(path, data, perm)
}

// AppendFile appends data to file
func (ft *FileTools) AppendFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

// CopyFile copies file from src to dst
func (ft *FileTools) CopyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}

// MoveFile moves file from src to dst
func (ft *FileTools) MoveFile(src, dst string) error {
	return os.Rename(src, dst)
}

// DeleteFile deletes file
func (ft *FileTools) DeleteFile(path string) error {
	return os.Remove(path)
}

// DeleteDir deletes directory and contents
func (ft *FileTools) DeleteDir(path string) error {
	return os.RemoveAll(path)
}

// GetFileSize returns file size in bytes
func (ft *FileTools) GetFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// GetFileInfo returns file information
func (ft *FileTools) GetFileInfo(path string) (*FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	return &FileInfo{
		Name:    info.Name(),
		Size:    info.Size(),
		Mode:    info.Mode().String(),
		ModTime: info.ModTime(),
		IsDir:   info.IsDir(),
	}, nil
}

// FileInfo represents file information
type FileInfo struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"mod_time"`
	IsDir   bool      `json:"is_dir"`
}

// ListDir lists directory contents
func (ft *FileTools) ListDir(path string) ([]FileInfo, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	var files []FileInfo
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, FileInfo{
			Name:    info.Name(),
			Size:    info.Size(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime(),
			IsDir:   info.IsDir(),
		})
	}
	return files, nil
}

// GetFileHash returns hash of file
func (ft *FileTools) GetFileHash(path string, hashType string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var h hash.Hash
	switch strings.ToLower(hashType) {
	case "md5":
		h = md5.New()
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	default:
		h = sha256.New()
	}

	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// CompressGzip compresses data using gzip
func (ft *FileTools) CompressGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecompressGzip decompresses gzip data
func (ft *FileTools) DecompressGzip(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// CompressFile compresses file to .gz
func (ft *FileTools) CompressFile(src, dst string) error {
	input, err := os.Open(src)
	if err != nil {
		return err
	}
	defer input.Close()

	output, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer output.Close()

	writer := gzip.NewWriter(output)
	defer writer.Close()

	_, err = io.Copy(writer, input)
	return err
}

// DecompressFile decompresses .gz file
func (ft *FileTools) DecompressFile(src, dst string) error {
	input, err := os.Open(src)
	if err != nil {
		return err
	}
	defer input.Close()

	reader, err := gzip.NewReader(input)
	if err != nil {
		return err
	}
	defer reader.Close()

	output, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer output.Close()

	_, err = io.Copy(output, reader)
	return err
}

// ReadLines reads file lines
func (ft *FileTools) ReadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// WriteLines writes lines to file
func (ft *FileTools) WriteLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	for _, line := range lines {
		fmt.Fprintln(writer, line)
	}
	return writer.Flush()
}

// WalkDir walks directory recursively
func (ft *FileTools) WalkDir(root string, fn func(path string, info os.FileInfo) error) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return fn(path, info)
	})
}

// GetDirSize returns total size of directory
func (ft *FileTools) GetDirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

// TempFile creates temporary file
func (ft *FileTools) TempFile(dir, pattern string) (*os.File, error) {
	return os.CreateTemp(dir, pattern)
}

// TempDir creates temporary directory
func (ft *FileTools) TempDir(dir, pattern string) (string, error) {
	return os.MkdirTemp(dir, pattern)
}

// Core/tools.go
// MXUI VPN Panel - Tools & Utilities
// Part 2: String Utils, Time Utils, System Utils, Updater, QR Code

// ==================== String Utilities ====================

// StringTools provides string utility functions
type StringTools struct{}

// NewStringTools creates new string tools instance
func NewStringTools() *StringTools {
	return &StringTools{}
}

// Truncate truncates string to max length
func (st *StringTools) Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// PadLeft pads string on left to specified length
func (st *StringTools) PadLeft(s string, length int, pad string) string {
	if len(s) >= length {
		return s
	}
	if pad == "" {
		pad = " "
	}
	for len(s) < length {
		s = pad + s
	}
	return s[:length]
}

// PadRight pads string on right to specified length
func (st *StringTools) PadRight(s string, length int, pad string) string {
	if len(s) >= length {
		return s
	}
	if pad == "" {
		pad = " "
	}
	for len(s) < length {
		s = s + pad
	}
	return s[:length]
}

// Center centers string in specified width
func (st *StringTools) Center(s string, width int, pad string) string {
	if len(s) >= width {
		return s
	}
	if pad == "" {
		pad = " "
	}
	leftPad := (width - len(s)) / 2
	rightPad := width - len(s) - leftPad
	return strings.Repeat(pad, leftPad) + s + strings.Repeat(pad, rightPad)
}

// Reverse reverses string
func (st *StringTools) Reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// CountWords counts words in string
func (st *StringTools) CountWords(s string) int {
	return len(strings.Fields(s))
}

// CountLines counts lines in string
func (st *StringTools) CountLines(s string) int {
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}

// RemoveWhitespace removes all whitespace
func (st *StringTools) RemoveWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// CollapseWhitespace collapses multiple whitespaces to single space
func (st *StringTools) CollapseWhitespace(s string) string {
	re := regexp.MustCompile(`\s+`)
	return strings.TrimSpace(re.ReplaceAllString(s, " "))
}

// ToSnakeCase converts to snake_case
func (st *StringTools) ToSnakeCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) {
			if i > 0 {
				result.WriteRune('_')
			}
			result.WriteRune(unicode.ToLower(r))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// ToCamelCase converts to camelCase
func (st *StringTools) ToCamelCase(s string) string {
	words := strings.FieldsFunc(s, func(r rune) bool {
		return r == '_' || r == '-' || r == ' '
	})

	for i := range words {
		if i == 0 {
			words[i] = strings.ToLower(words[i])
		} else {
			words[i] = strings.Title(strings.ToLower(words[i]))
		}
	}
	return strings.Join(words, "")
}

// ToPascalCase converts to PascalCase
func (st *StringTools) ToPascalCase(s string) string {
	words := strings.FieldsFunc(s, func(r rune) bool {
		return r == '_' || r == '-' || r == ' '
	})

	for i := range words {
		words[i] = strings.Title(strings.ToLower(words[i]))
	}
	return strings.Join(words, "")
}

// ToKebabCase converts to kebab-case
func (st *StringTools) ToKebabCase(s string) string {
	return strings.ReplaceAll(st.ToSnakeCase(s), "_", "-")
}

// Slugify creates URL-friendly slug
func (st *StringTools) Slugify(s string) string {
	s = strings.ToLower(s)
	s = regexp.MustCompile(`[^a-z0-9\s-]`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`[\s_]+`).ReplaceAllString(s, "-")
	s = regexp.MustCompile(`-+`).ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

// ExtractEmails extracts email addresses from text
func (st *StringTools) ExtractEmails(s string) []string {
	re := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	return re.FindAllString(s, -1)
}

// ExtractURLs extracts URLs from text
func (st *StringTools) ExtractURLs(s string) []string {
	re := regexp.MustCompile(`https?://[^\s<>"{}|\\^` + "`" + `\[\]]+`)
	return re.FindAllString(s, -1)
}

// ExtractIPs extracts IP addresses from text
func (st *StringTools) ExtractIPs(s string) []string {
	re := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	return re.FindAllString(s, -1)
}

// ExtractNumbers extracts numbers from text
func (st *StringTools) ExtractNumbers(s string) []string {
	re := regexp.MustCompile(`-?\d+\.?\d*`)
	return re.FindAllString(s, -1)
}

// MaskString masks part of string (for sensitive data)
func (st *StringTools) MaskString(s string, showFirst, showLast int, maskChar string) string {
	if maskChar == "" {
		maskChar = "*"
	}

	runes := []rune(s)
	length := len(runes)

	if length <= showFirst+showLast {
		return s
	}

	masked := string(runes[:showFirst])
	masked += strings.Repeat(maskChar, length-showFirst-showLast)
	masked += string(runes[length-showLast:])

	return masked
}

// MaskEmail masks email address
func (st *StringTools) MaskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}

	name := parts[0]
	domain := parts[1]

	if len(name) <= 2 {
		return name + "@" + domain
	}

	return string(name[0]) + strings.Repeat("*", len(name)-2) + string(name[len(name)-1]) + "@" + domain
}

// MaskPhone masks phone number
func (st *StringTools) MaskPhone(phone string) string {
	digits := regexp.MustCompile(`\d`).FindAllString(phone, -1)
	if len(digits) < 4 {
		return phone
	}

	// Show first 3 and last 2 digits
	masked := strings.Join(digits[:3], "") + strings.Repeat("*", len(digits)-5) + strings.Join(digits[len(digits)-2:], "")
	return masked
}

// WrapText wraps text at specified width
func (st *StringTools) WrapText(s string, width int) string {
	if width <= 0 {
		return s
	}

	words := strings.Fields(s)
	if len(words) == 0 {
		return s
	}

	var lines []string
	var currentLine strings.Builder

	for _, word := range words {
		if currentLine.Len() == 0 {
			currentLine.WriteString(word)
		} else if currentLine.Len()+1+len(word) <= width {
			currentLine.WriteString(" ")
			currentLine.WriteString(word)
		} else {
			lines = append(lines, currentLine.String())
			currentLine.Reset()
			currentLine.WriteString(word)
		}
	}

	if currentLine.Len() > 0 {
		lines = append(lines, currentLine.String())
	}

	return strings.Join(lines, "\n")
}

// LevenshteinDistance calculates edit distance between two strings
func (st *StringTools) LevenshteinDistance(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	matrix := make([][]int, len(a)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(b)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}

	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,
				min(matrix[i][j-1]+1, matrix[i-1][j-1]+cost),
			)
		}
	}

	return matrix[len(a)][len(b)]
}

// SimilarityPercent returns similarity percentage between two strings
func (st *StringTools) SimilarityPercent(a, b string) float64 {
	if a == b {
		return 100.0
	}

	distance := st.LevenshteinDistance(a, b)
	maxLen := max(len(a), len(b))

	if maxLen == 0 {
		return 100.0
	}

	return (1.0 - float64(distance)/float64(maxLen)) * 100.0
}

// RandomString generates random string from charset
func (st *StringTools) RandomString(length int, charset string) string {
	if charset == "" {
		charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	}

	b := make([]byte, length)
	rand.Read(b)

	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}

	return string(b)
}

// ParseKeyValue parses key=value string
func (st *StringTools) ParseKeyValue(s, sep string) map[string]string {
	result := make(map[string]string)
	if sep == "" {
		sep = "="
	}

	for _, part := range strings.Split(s, "\n") {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, "#") {
			continue
		}

		idx := strings.Index(part, sep)
		if idx > 0 {
			key := strings.TrimSpace(part[:idx])
			value := strings.TrimSpace(part[idx+len(sep):])
			result[key] = value
		}
	}

	return result
}

// FormatBytes formats bytes to human readable
func (st *StringTools) FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// ParseBytes parses human readable bytes string
func (st *StringTools) ParseBytes(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))

	units := map[string]int64{
		"B":  1,
		"K":  1024,
		"KB": 1024,
		"M":  1024 * 1024,
		"MB": 1024 * 1024,
		"G":  1024 * 1024 * 1024,
		"GB": 1024 * 1024 * 1024,
		"T":  1024 * 1024 * 1024 * 1024,
		"TB": 1024 * 1024 * 1024 * 1024,
	}

	for suffix, multiplier := range units {
		if strings.HasSuffix(s, suffix) {
			numStr := strings.TrimSuffix(s, suffix)
			numStr = strings.TrimSpace(numStr)
			num, err := strconv.ParseFloat(numStr, 64)
			if err != nil {
				return 0, err
			}
			return int64(num * float64(multiplier)), nil
		}
	}

	return strconv.ParseInt(s, 10, 64)
}

// FormatDuration formats duration to human readable
func (st *StringTools) FormatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}

	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	if seconds > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%ds", seconds))
	}

	return strings.Join(parts, " ")
}

// ==================== Time Utilities ====================

// TimeTools provides time utility functions
type TimeTools struct {
	location *time.Location
}

// NewTimeTools creates new time tools instance
func NewTimeTools() *TimeTools {
	return &TimeTools{
		location: time.Local,
	}
}

// SetTimezone sets timezone
func (tt *TimeTools) SetTimezone(tz string) error {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return err
	}
	tt.location = loc
	return nil
}

// Now returns current time in set timezone
func (tt *TimeTools) Now() time.Time {
	return time.Now().In(tt.location)
}

// NowUTC returns current UTC time
func (tt *TimeTools) NowUTC() time.Time {
	return time.Now().UTC()
}

// NowUnix returns current Unix timestamp
func (tt *TimeTools) NowUnix() int64 {
	return time.Now().Unix()
}

// NowUnixMilli returns current Unix timestamp in milliseconds
func (tt *TimeTools) NowUnixMilli() int64 {
	return time.Now().UnixMilli()
}

// FromUnix creates time from Unix timestamp
func (tt *TimeTools) FromUnix(timestamp int64) time.Time {
	return time.Unix(timestamp, 0).In(tt.location)
}

// FromUnixMilli creates time from Unix milliseconds timestamp
func (tt *TimeTools) FromUnixMilli(timestamp int64) time.Time {
	return time.UnixMilli(timestamp).In(tt.location)
}

// Parse parses time string
func (tt *TimeTools) Parse(layout, value string) (time.Time, error) {
	return time.ParseInLocation(layout, value, tt.location)
}

// ParseAny tries to parse time with common formats
func (tt *TimeTools) ParseAny(value string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"02/01/2006",
		"01/02/2006",
		"2006/01/02",
		"02-01-2006",
		"Jan 2, 2006",
		"January 2, 2006",
		"02 Jan 2006",
		"2006-01-02T15:04:05Z07:00",
		"Mon Jan 2 15:04:05 2006",
		"15:04:05",
		"15:04",
	}

	for _, format := range formats {
		if t, err := time.ParseInLocation(format, value, tt.location); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse time: %s", value)
}

// Format formats time
func (tt *TimeTools) Format(t time.Time, layout string) string {
	return t.In(tt.location).Format(layout)
}

// FormatISO formats time to ISO 8601
func (tt *TimeTools) FormatISO(t time.Time) string {
	return t.In(tt.location).Format(time.RFC3339)
}

// FormatDate formats time to date only
func (tt *TimeTools) FormatDate(t time.Time) string {
	return t.In(tt.location).Format("2006-01-02")
}

// FormatTime formats time to time only
func (tt *TimeTools) FormatTime(t time.Time) string {
	return t.In(tt.location).Format("15:04:05")
}

// FormatDateTime formats time to date and time
func (tt *TimeTools) FormatDateTime(t time.Time) string {
	return t.In(tt.location).Format("2006-01-02 15:04:05")
}

// FormatRelative formats time relative to now
func (tt *TimeTools) FormatRelative(t time.Time) string {
	now := tt.Now()
	diff := now.Sub(t)

	if diff < 0 {
		diff = -diff
		return tt.formatFuture(diff)
	}

	return tt.formatPast(diff)
}

func (tt *TimeTools) formatPast(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		mins := int(d.Minutes())
		if mins == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", mins)
	case d < 24*time.Hour:
		hours := int(d.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	case d < 7*24*time.Hour:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "yesterday"
		}
		return fmt.Sprintf("%d days ago", days)
	case d < 30*24*time.Hour:
		weeks := int(d.Hours() / 24 / 7)
		if weeks == 1 {
			return "1 week ago"
		}
		return fmt.Sprintf("%d weeks ago", weeks)
	case d < 365*24*time.Hour:
		months := int(d.Hours() / 24 / 30)
		if months == 1 {
			return "1 month ago"
		}
		return fmt.Sprintf("%d months ago", months)
	default:
		years := int(d.Hours() / 24 / 365)
		if years == 1 {
			return "1 year ago"
		}
		return fmt.Sprintf("%d years ago", years)
	}
}

func (tt *TimeTools) formatFuture(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "in a moment"
	case d < time.Hour:
		mins := int(d.Minutes())
		if mins == 1 {
			return "in 1 minute"
		}
		return fmt.Sprintf("in %d minutes", mins)
	case d < 24*time.Hour:
		hours := int(d.Hours())
		if hours == 1 {
			return "in 1 hour"
		}
		return fmt.Sprintf("in %d hours", hours)
	case d < 7*24*time.Hour:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "tomorrow"
		}
		return fmt.Sprintf("in %d days", days)
	case d < 30*24*time.Hour:
		weeks := int(d.Hours() / 24 / 7)
		if weeks == 1 {
			return "in 1 week"
		}
		return fmt.Sprintf("in %d weeks", weeks)
	case d < 365*24*time.Hour:
		months := int(d.Hours() / 24 / 30)
		if months == 1 {
			return "in 1 month"
		}
		return fmt.Sprintf("in %d months", months)
	default:
		years := int(d.Hours() / 24 / 365)
		if years == 1 {
			return "in 1 year"
		}
		return fmt.Sprintf("in %d years", years)
	}
}

// StartOfDay returns start of day
func (tt *TimeTools) StartOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, tt.location)
}

// EndOfDay returns end of day
func (tt *TimeTools) EndOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 999999999, tt.location)
}

// StartOfWeek returns start of week (Monday)
func (tt *TimeTools) StartOfWeek(t time.Time) time.Time {
	weekday := int(t.Weekday())
	if weekday == 0 {
		weekday = 7
	}
	return tt.StartOfDay(t.AddDate(0, 0, -weekday+1))
}

// EndOfWeek returns end of week (Sunday)
func (tt *TimeTools) EndOfWeek(t time.Time) time.Time {
	return tt.EndOfDay(tt.StartOfWeek(t).AddDate(0, 0, 6))
}

// StartOfMonth returns start of month
func (tt *TimeTools) StartOfMonth(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, tt.location)
}

// EndOfMonth returns end of month
func (tt *TimeTools) EndOfMonth(t time.Time) time.Time {
	return tt.StartOfMonth(t).AddDate(0, 1, 0).Add(-time.Nanosecond)
}

// StartOfYear returns start of year
func (tt *TimeTools) StartOfYear(t time.Time) time.Time {
	return time.Date(t.Year(), 1, 1, 0, 0, 0, 0, tt.location)
}

// EndOfYear returns end of year
func (tt *TimeTools) EndOfYear(t time.Time) time.Time {
	return time.Date(t.Year(), 12, 31, 23, 59, 59, 999999999, tt.location)
}

// AddBusinessDays adds business days (excluding weekends)
func (tt *TimeTools) AddBusinessDays(t time.Time, days int) time.Time {
	for days > 0 {
		t = t.AddDate(0, 0, 1)
		if t.Weekday() != time.Saturday && t.Weekday() != time.Sunday {
			days--
		}
	}
	return t
}

// IsWeekend checks if time is weekend
func (tt *TimeTools) IsWeekend(t time.Time) bool {
	return t.Weekday() == time.Saturday || t.Weekday() == time.Sunday
}

// IsSameDay checks if two times are on same day
func (tt *TimeTools) IsSameDay(a, b time.Time) bool {
	return a.Year() == b.Year() && a.YearDay() == b.YearDay()
}

// DaysBetween returns days between two times
func (tt *TimeTools) DaysBetween(a, b time.Time) int {
	a = tt.StartOfDay(a)
	b = tt.StartOfDay(b)
	return int(b.Sub(a).Hours() / 24)
}

// Age calculates age from birth date
func (tt *TimeTools) Age(birthDate time.Time) int {
	now := tt.Now()
	years := now.Year() - birthDate.Year()

	if now.Month() < birthDate.Month() ||
		(now.Month() == birthDate.Month() && now.Day() < birthDate.Day()) {
		years--
	}

	return years
}

// ParseDuration parses duration string with extended support
func (tt *TimeTools) ParseDuration(s string) (time.Duration, error) {
	// Try standard parsing first
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}

	// Extended format: 1d, 1w, 1M, 1y
	s = strings.TrimSpace(s)
	re := regexp.MustCompile(`^(\d+)\s*([a-zA-Z]+)$`)
	matches := re.FindStringSubmatch(s)

	if len(matches) != 3 {
		return 0, fmt.Errorf("invalid duration: %s", s)
	}

	value, _ := strconv.Atoi(matches[1])
	unit := strings.ToLower(matches[2])

	switch unit {
	case "d", "day", "days":
		return time.Duration(value) * 24 * time.Hour, nil
	case "w", "week", "weeks":
		return time.Duration(value) * 7 * 24 * time.Hour, nil
	case "m", "month", "months":
		return time.Duration(value) * 30 * 24 * time.Hour, nil
	case "y", "year", "years":
		return time.Duration(value) * 365 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("unknown unit: %s", unit)
	}
}

// ==================== System Utilities ====================

// SystemTools provides system utility functions
type SystemTools struct {
	startTime time.Time
}

// MemoryInfo represents memory information
type MemoryInfo struct {
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"used_percent"`
}

// DiskInfo is defined in monitor.go

// NewSystemTools creates new system tools instance
func NewSystemTools() *SystemTools {
	return &SystemTools{
		startTime: time.Now(),
	}
}

// SystemInfo represents system information
type SystemInfo struct {
	OS          string     `json:"os"`
	Arch        string     `json:"arch"`
	CPUs        int        `json:"cpus"`
	Hostname    string     `json:"hostname"`
	GoVersion   string     `json:"go_version"`
	Uptime      string     `json:"uptime"`
	StartTime   time.Time  `json:"start_time"`
	MemoryUsage MemoryInfo `json:"memory_usage"`
	DiskUsage   DiskInfo   `json:"disk_usage"`
	LoadAvg     []float64  `json:"load_avg,omitempty"`
}

// GetSystemInfo returns system information
func (st *SystemTools) GetSystemInfo() (*SystemInfo, error) {
	hostname, _ := os.Hostname()

	info := &SystemInfo{
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		CPUs:      runtime.NumCPU(),
		Hostname:  hostname,
		GoVersion: runtime.Version(),
		StartTime: st.startTime,
		Uptime:    time.Since(st.startTime).String(),
	}

	// Memory info
	info.MemoryUsage = st.GetMemoryInfo()

	// Disk info
	info.DiskUsage, _ = st.GetDiskInfo("/")

	// Load average (Linux only)
	if runtime.GOOS == "linux" {
		info.LoadAvg = st.GetLoadAverage()
	}

	return info, nil
}

// GetMemoryInfo returns memory information
func (st *SystemTools) GetMemoryInfo() MemoryInfo {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	_ = NewStringTools() // Available for future use

	// Get system memory (Linux)
	var total, free uint64
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/meminfo")
		if err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				fields := strings.Fields(line)
				if len(fields) < 2 {
					continue
				}
				value, _ := strconv.ParseUint(fields[1], 10, 64)
				value *= 1024 // Convert from KB to bytes

				switch fields[0] {
				case "MemTotal:":
					total = value
				case "MemFree:":
					free = value
				}
			}
		}
	}

	if total == 0 {
		total = m.Sys
		free = m.Sys - m.Alloc
	}

	used := total - free
	usedPercent := float64(used) / float64(total) * 100

	return MemoryInfo{
		Total:       total,
		Used:        used,
		Free:        free,
		UsedPercent: usedPercent,
	}
}

// GetDiskInfo returns disk information for path
func (st *SystemTools) GetDiskInfo(path string) (DiskInfo, error) {

	if runtime.GOOS == "windows" {
		// Windows implementation would need syscall
		return DiskInfo{}, nil
	}

	// Unix implementation using df command
	cmd := exec.Command("df", "-B1", path)
	output, err := cmd.Output()
	if err != nil {
		return DiskInfo{}, err
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		return DiskInfo{}, errors.New("failed to parse df output")
	}

	fields := strings.Fields(lines[1])
	if len(fields) < 4 {
		return DiskInfo{}, errors.New("failed to parse df output")
	}

	total, _ := strconv.ParseUint(fields[1], 10, 64)
	used, _ := strconv.ParseUint(fields[2], 10, 64)
	free, _ := strconv.ParseUint(fields[3], 10, 64)

	usedPercent := float64(used) / float64(total) * 100

	return DiskInfo{
		MountPoint: path,
		Total:      total,
		Used:       used,
		Free:       free,
		Usage:      usedPercent,
	}, nil
}

// GetLoadAverage returns load average (Linux only)
func (st *SystemTools) GetLoadAverage() []float64 {
	if runtime.GOOS != "linux" {
		return nil
	}

	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return nil
	}

	load := make([]float64, 3)
	for i := 0; i < 3; i++ {
		load[i], _ = strconv.ParseFloat(fields[i], 64)
	}

	return load
}

// GetCPUUsage returns CPU usage percentage
func (st *SystemTools) GetCPUUsage() (float64, error) {
	if runtime.GOOS != "linux" {
		return 0, errors.New("only supported on Linux")
	}

	// Read first time
	idle1, total1 := st.readCPUStats()

	time.Sleep(100 * time.Millisecond)

	// Read second time
	idle2, total2 := st.readCPUStats()

	idleDelta := idle2 - idle1
	totalDelta := total2 - total1

	if totalDelta == 0 {
		return 0, nil
	}

	return (1.0 - float64(idleDelta)/float64(totalDelta)) * 100, nil
}

func (st *SystemTools) readCPUStats() (idle, total uint64) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}

			for i := 1; i < len(fields); i++ {
				val, _ := strconv.ParseUint(fields[i], 10, 64)
				total += val
				if i == 4 {
					idle = val
				}
			}
			break
		}
	}

	return idle, total
}

// GetNetworkStats returns network statistics
func (st *SystemTools) GetNetworkStats() (map[string]NetworkStats, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("only supported on Linux")
	}

	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil, err
	}

	stats := make(map[string]NetworkStats)
	lines := strings.Split(string(data), "\n")

	for _, line := range lines[2:] { // Skip headers
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		iface := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}

		rxBytes, _ := strconv.ParseUint(fields[0], 10, 64)
		rxPackets, _ := strconv.ParseUint(fields[1], 10, 64)
		rxErrors, _ := strconv.ParseUint(fields[2], 10, 64)
		txBytes, _ := strconv.ParseUint(fields[8], 10, 64)
		txPackets, _ := strconv.ParseUint(fields[9], 10, 64)
		txErrors, _ := strconv.ParseUint(fields[10], 10, 64)

		stats[iface] = NetworkStats{
			RxBytes:   rxBytes,
			RxPackets: rxPackets,
			RxErrors:  rxErrors,
			TxBytes:   txBytes,
			TxPackets: txPackets,
			TxErrors:  txErrors,
		}
	}

	return stats, nil
}

// NetworkStats represents network interface statistics
type NetworkStats struct {
	RxBytes   uint64 `json:"rx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	TxBytes   uint64 `json:"tx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
	TxErrors  uint64 `json:"tx_errors"`
}

// GetProcessInfo returns current process information
func (st *SystemTools) GetProcessInfo() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return map[string]interface{}{
		"pid":         os.Getpid(),
		"ppid":        os.Getppid(),
		"uid":         os.Getuid(),
		"gid":         os.Getgid(),
		"goroutines":  runtime.NumGoroutine(),
		"alloc":       m.Alloc,
		"total_alloc": m.TotalAlloc,
		"sys":         m.Sys,
		"num_gc":      m.NumGC,
		"cgo_calls":   runtime.NumCgoCall(),
	}
}

// ExecuteCommand executes shell command
func (st *SystemTools) ExecuteCommand(command string, timeout time.Duration) (string, string, error) {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", command)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	return stdout.String(), stderr.String(), err
}

// ExecuteCommandAsync executes command asynchronously
func (st *SystemTools) ExecuteCommandAsync(command string) (<-chan string, <-chan error) {
	outputChan := make(chan string, 100)
	errorChan := make(chan error, 1)

	go func() {
		defer close(outputChan)
		defer close(errorChan)

		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("cmd", "/C", command)
		} else {
			cmd = exec.Command("sh", "-c", command)
		}

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			errorChan <- err
			return
		}

		if err := cmd.Start(); err != nil {
			errorChan <- err
			return
		}

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			outputChan <- scanner.Text()
		}

		if err := cmd.Wait(); err != nil {
			errorChan <- err
		}
	}()

	return outputChan, errorChan
}

// IsRoot checks if running as root
func (st *SystemTools) IsRoot() bool {
	return os.Getuid() == 0
}

// GetEnv gets environment variable with default
func (st *SystemTools) GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// SetEnv sets environment variable
func (st *SystemTools) SetEnv(key, value string) error {
	return os.Setenv(key, value)
}

// GetAllEnv returns all environment variables
func (st *SystemTools) GetAllEnv() map[string]string {
	env := make(map[string]string)
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		if len(pair) == 2 {
			env[pair[0]] = pair[1]
		}
	}
	return env
}

// ServiceControl controls systemd services
func (st *SystemTools) ServiceControl(service, action string) error {
	if runtime.GOOS != "linux" {
		return errors.New("only supported on Linux")
	}

	validActions := map[string]bool{
		"start":   true,
		"stop":    true,
		"restart": true,
		"status":  true,
		"enable":  true,
		"disable": true,
	}

	if !validActions[action] {
		return fmt.Errorf("invalid action: %s", action)
	}

	cmd := exec.Command("systemctl", action, service)
	return cmd.Run()
}

// GetServiceStatus returns service status
func (st *SystemTools) GetServiceStatus(service string) (string, error) {
	if runtime.GOOS != "linux" {
		return "", errors.New("only supported on Linux")
	}

	cmd := exec.Command("systemctl", "is-active", service)
	output, _ := cmd.Output()

	return strings.TrimSpace(string(output)), nil
}

// ==================== Updater System ====================

// Updater handles updates for core and panel
type Updater struct {
	currentVersion string
	repoOwner      string
	repoName       string
	httpClient     *http.Client
	downloadDir    string
	backupDir      string
}

// UpdateInfo represents update information
type UpdateInfo struct {
	Available      bool      `json:"available"`
	CurrentVersion string    `json:"current_version"`
	LatestVersion  string    `json:"latest_version"`
	ReleaseDate    time.Time `json:"release_date"`
	ReleaseNotes   string    `json:"release_notes"`
	DownloadURL    string    `json:"download_url"`
	Size           int64     `json:"size"`
	Checksum       string    `json:"checksum"`
	Breaking       bool      `json:"breaking"`
	MinGoVersion   string    `json:"min_go_version,omitempty"`
}

// GithubRelease represents GitHub release API response
type GithubRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	CreatedAt   time.Time `json:"created_at"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name               string `json:"name"`
		Size               int64  `json:"size"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// NewUpdater creates new updater instance
func NewUpdater(currentVersion, repoOwner, repoName string) *Updater {
	return &Updater{
		currentVersion: currentVersion,
		repoOwner:      repoOwner,
		repoName:       repoName,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		downloadDir: "/tmp/mxui-update",
		backupDir:   "/var/backup/mxui",
	}
}

// CheckForUpdates checks for available updates
func (u *Updater) CheckForUpdates() (*UpdateInfo, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", u.repoOwner, u.repoName)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to check for updates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release GithubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to parse release info: %w", err)
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")

	info := &UpdateInfo{
		Available:      u.isNewerVersion(latestVersion, u.currentVersion),
		CurrentVersion: u.currentVersion,
		LatestVersion:  latestVersion,
		ReleaseDate:    release.PublishedAt,
		ReleaseNotes:   release.Body,
		Breaking:       strings.Contains(strings.ToLower(release.Body), "breaking"),
	}

	// Find appropriate asset
	osArch := fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH)
	for _, asset := range release.Assets {
		if strings.Contains(asset.Name, osArch) {
			info.DownloadURL = asset.BrowserDownloadURL
			info.Size = asset.Size
			break
		}
	}

	return info, nil
}

// isNewerVersion compares semantic versions
func (u *Updater) isNewerVersion(latest, current string) bool {
	latestParts := strings.Split(latest, ".")
	currentParts := strings.Split(current, ".")

	for i := 0; i < len(latestParts) && i < len(currentParts); i++ {
		l, _ := strconv.Atoi(latestParts[i])
		c, _ := strconv.Atoi(currentParts[i])

		if l > c {
			return true
		} else if l < c {
			return false
		}
	}

	return len(latestParts) > len(currentParts)
}

// DownloadUpdate downloads the update
func (u *Updater) DownloadUpdate(info *UpdateInfo, progressFn func(downloaded, total int64)) (string, error) {
	if info.DownloadURL == "" {
		return "", errors.New("no download URL available")
	}

	// Create download directory
	if err := os.MkdirAll(u.downloadDir, 0755); err != nil {
		return "", err
	}

	// Start download
	resp, err := u.httpClient.Get(info.DownloadURL)
	if err != nil {
		return "", fmt.Errorf("failed to download update: %w", err)
	}
	defer resp.Body.Close()

	// Create output file
	filename := filepath.Base(info.DownloadURL)
	outputPath := filepath.Join(u.downloadDir, filename)

	out, err := os.Create(outputPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	// Download with progress
	var downloaded int64
	buf := make([]byte, 32*1024)

	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			out.Write(buf[:n])
			downloaded += int64(n)
			if progressFn != nil {
				progressFn(downloaded, info.Size)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}

	return outputPath, nil
}

// BackupCurrent creates backup of current installation
func (u *Updater) BackupCurrent(paths []string) (string, error) {
	if err := os.MkdirAll(u.backupDir, 0755); err != nil {
		return "", err
	}

	backupName := fmt.Sprintf("backup_%s_%s", u.currentVersion, time.Now().Format("20060102_150405"))
	backupPath := filepath.Join(u.backupDir, backupName)

	if err := os.MkdirAll(backupPath, 0755); err != nil {
		return "", err
	}

	ft := NewFileTools()
	for _, path := range paths {
		if ft.FileExists(path) {
			dest := filepath.Join(backupPath, filepath.Base(path))
			if err := ft.CopyFile(path, dest); err != nil {
				return "", fmt.Errorf("failed to backup %s: %w", path, err)
			}
		}
	}

	return backupPath, nil
}

// InstallUpdate installs the downloaded update
func (u *Updater) InstallUpdate(downloadPath string, targetPaths map[string]string) error {
	ft := NewFileTools()

	// Check if it's an archive
	if strings.HasSuffix(downloadPath, ".tar.gz") || strings.HasSuffix(downloadPath, ".tgz") {
		extractDir := filepath.Join(u.downloadDir, "extracted")
		if err := u.extractTarGz(downloadPath, extractDir); err != nil {
			return fmt.Errorf("failed to extract update: %w", err)
		}

		// Copy files to targets
		for src, dest := range targetPaths {
			srcPath := filepath.Join(extractDir, src)
			if ft.FileExists(srcPath) {
				if err := ft.CopyFile(srcPath, dest); err != nil {
					return fmt.Errorf("failed to install %s: %w", src, err)
				}
				os.Chmod(dest, 0755)
			}
		}
	} else {
		// Single binary
		for _, dest := range targetPaths {
			if err := ft.CopyFile(downloadPath, dest); err != nil {
				return err
			}
			os.Chmod(dest, 0755)
		}
	}

	return nil
}

// extractTarGz extracts tar.gz archive
func (u *Updater) extractTarGz(src, dest string) error {
	cmd := exec.Command("tar", "-xzf", src, "-C", dest)
	if err := os.MkdirAll(dest, 0755); err != nil {
		return err
	}
	return cmd.Run()
}

// Rollback restores from backup
func (u *Updater) Rollback(backupPath string, targetPaths []string) error {
	ft := NewFileTools()

	for _, target := range targetPaths {
		backupFile := filepath.Join(backupPath, filepath.Base(target))
		if ft.FileExists(backupFile) {
			if err := ft.CopyFile(backupFile, target); err != nil {
				return fmt.Errorf("failed to restore %s: %w", target, err)
			}
		}
	}

	return nil
}

// CleanupDownloads removes downloaded files
func (u *Updater) CleanupDownloads() error {
	return os.RemoveAll(u.downloadDir)
}

// GetBackupList returns list of backups
func (u *Updater) GetBackupList() ([]BackupInfo, error) {
	ft := NewFileTools()

	if !ft.DirExists(u.backupDir) {
		return nil, nil
	}

	entries, err := os.ReadDir(u.backupDir)
	if err != nil {
		return nil, err
	}

	var backups []BackupInfo
	for _, entry := range entries {
		if entry.IsDir() {
			info, _ := entry.Info()
			backups = append(backups, BackupInfo{
				ID:           entry.Name(),
				Filename:     entry.Name(),
				OriginalSize: getDirectorySize(filepath.Join(u.backupDir, entry.Name())),
				CreatedAt:    info.ModTime().Unix(),
			})
		}
	}

	return backups, nil
}

func getDirectorySize(path string) int64 {
	var size int64
	filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size
}

// AutoUpdate performs automatic update
func (u *Updater) AutoUpdate(targetPaths map[string]string, restartCmd string) error {
	// Check for updates
	info, err := u.CheckForUpdates()
	if err != nil {
		return err
	}

	if !info.Available {
		return nil // No update available
	}

	// Don't auto-update breaking changes
	if info.Breaking {
		return errors.New("breaking changes detected, manual update required")
	}

	// Create backup
	var pathsToBackup []string
	for _, p := range targetPaths {
		pathsToBackup = append(pathsToBackup, p)
	}

	backupPath, err := u.BackupCurrent(pathsToBackup)
	if err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}

	// Download update
	downloadPath, err := u.DownloadUpdate(info, nil)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	// Install update
	if err := u.InstallUpdate(downloadPath, targetPaths); err != nil {
		// Rollback on failure
		u.Rollback(backupPath, pathsToBackup)
		return fmt.Errorf("installation failed, rolled back: %w", err)
	}

	// Cleanup
	u.CleanupDownloads()

	// Restart service if command provided
	if restartCmd != "" {
		st := NewSystemTools()
		st.ExecuteCommand(restartCmd, 30*time.Second)
	}

	return nil
}

// ==================== QR Code Generator ====================

// QRCodeGenerator generates QR codes
type QRCodeGenerator struct {
	size       int
	margin     int
	darkColor  string
	lightColor string
}

// NewQRCodeGenerator creates new QR code generator
func NewQRCodeGenerator() *QRCodeGenerator {
	return &QRCodeGenerator{
		size:       256,
		margin:     4,
		darkColor:  "#000000",
		lightColor: "#FFFFFF",
	}
}

// SetSize sets QR code size
func (qr *QRCodeGenerator) SetSize(size int) *QRCodeGenerator {
	qr.size = size
	return qr
}

// SetMargin sets QR code margin
func (qr *QRCodeGenerator) SetMargin(margin int) *QRCodeGenerator {
	qr.margin = margin
	return qr
}

// SetColors sets QR code colors
func (qr *QRCodeGenerator) SetColors(dark, light string) *QRCodeGenerator {
	qr.darkColor = dark
	qr.lightColor = light
	return qr
}

// GenerateSVG generates QR code as SVG
func (qr *QRCodeGenerator) GenerateSVG(content string) (string, error) {
	// Generate QR code matrix
	matrix, err := qr.encode(content)
	if err != nil {
		return "", err
	}

	moduleSize := qr.size / (len(matrix) + qr.margin*2)
	totalSize := moduleSize * (len(matrix) + qr.margin*2)

	var svg strings.Builder
	svg.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d">`,
		totalSize, totalSize, qr.size, qr.size))
	svg.WriteString(fmt.Sprintf(`<rect width="100%%" height="100%%" fill="%s"/>`, qr.lightColor))

	for y, row := range matrix {
		for x, cell := range row {
			if cell {
				px := (x + qr.margin) * moduleSize
				py := (y + qr.margin) * moduleSize
				svg.WriteString(fmt.Sprintf(`<rect x="%d" y="%d" width="%d" height="%d" fill="%s"/>`,
					px, py, moduleSize, moduleSize, qr.darkColor))
			}
		}
	}

	svg.WriteString("</svg>")
	return svg.String(), nil
}

// GeneratePNG generates QR code as PNG bytes
func (qr *QRCodeGenerator) GeneratePNG(content string) ([]byte, error) {
	// Use external library or command for PNG generation
	// This is a simplified implementation using SVG conversion

	svg, err := qr.GenerateSVG(content)
	if err != nil {
		return nil, err
	}

	// In production, use proper image library
	// For now, return SVG as base64 encoded
	return []byte(base64.StdEncoding.EncodeToString([]byte(svg))), nil
}

// GenerateBase64 generates QR code as base64 data URL
func (qr *QRCodeGenerator) GenerateBase64(content string) (string, error) {
	svg, err := qr.GenerateSVG(content)
	if err != nil {
		return "", err
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(svg))
	return "data:image/svg+xml;base64," + encoded, nil
}

// GenerateToFile saves QR code to file
func (qr *QRCodeGenerator) GenerateToFile(content, filename string) error {
	svg, err := qr.GenerateSVG(content)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, []byte(svg), 0644)
}

// encode creates QR code matrix (simplified implementation)
func (qr *QRCodeGenerator) encode(content string) ([][]bool, error) {
	// This is a simplified QR code generation
	// In production, use a proper QR code library like "github.com/skip2/go-qrcode"

	size := 21 + (len(content) / 10 * 4) // Approximate size based on content
	if size > 177 {
		size = 177
	}

	matrix := make([][]bool, size)
	for i := range matrix {
		matrix[i] = make([]bool, size)
	}

	// Add finder patterns (corners)
	qr.addFinderPattern(matrix, 0, 0)
	qr.addFinderPattern(matrix, size-7, 0)
	qr.addFinderPattern(matrix, 0, size-7)

	// Add timing patterns
	for i := 8; i < size-8; i++ {
		matrix[6][i] = i%2 == 0
		matrix[i][6] = i%2 == 0
	}

	// Add data (simplified - just fills remaining space based on content hash)
	hash := sha256.Sum256([]byte(content))
	hashIdx := 0

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			// Skip finder patterns and timing
			if qr.isReserved(x, y, size) {
				continue
			}

			bit := hashIdx % 8
			byteIdx := hashIdx / 8 % 32
			matrix[y][x] = (hash[byteIdx] & (1 << bit)) != 0
			hashIdx++
		}
	}

	return matrix, nil
}

func (qr *QRCodeGenerator) addFinderPattern(matrix [][]bool, startX, startY int) {
	for y := 0; y < 7; y++ {
		for x := 0; x < 7; x++ {
			if (y == 0 || y == 6 || x == 0 || x == 6) ||
				(y >= 2 && y <= 4 && x >= 2 && x <= 4) {
				matrix[startY+y][startX+x] = true
			}
		}
	}
}

func (qr *QRCodeGenerator) isReserved(x, y, size int) bool {
	// Finder patterns
	if (x < 9 && y < 9) || (x >= size-8 && y < 9) || (x < 9 && y >= size-8) {
		return true
	}
	// Timing patterns
	if x == 6 || y == 6 {
		return true
	}
	return false
}

// ==================== Misc Helpers ====================

// min returns minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Contains checks if slice contains element
func Contains[T comparable](slice []T, element T) bool {
	for _, e := range slice {
		if e == element {
			return true
		}
	}
	return false
}

// Unique returns unique elements from slice
func Unique[T comparable](slice []T) []T {
	seen := make(map[T]bool)
	result := make([]T, 0)

	for _, e := range slice {
		if !seen[e] {
			seen[e] = true
			result = append(result, e)
		}
	}

	return result
}

// FilterSlice filters slice based on predicate
func FilterSlice[T any](slice []T, predicate func(T) bool) []T {
	result := make([]T, 0)
	for _, e := range slice {
		if predicate(e) {
			result = append(result, e)
		}
	}
	return result
}

// Map transforms slice elements
func Map[T, U any](slice []T, transform func(T) U) []U {
	result := make([]U, len(slice))
	for i, e := range slice {
		result[i] = transform(e)
	}
	return result
}

// Reduce reduces slice to single value
func Reduce[T, U any](slice []T, initial U, reducer func(U, T) U) U {
	result := initial
	for _, e := range slice {
		result = reducer(result, e)
	}
	return result
}

// Chunk splits slice into chunks
func Chunk[T any](slice []T, size int) [][]T {
	if size <= 0 {
		return nil
	}

	var result [][]T
	for i := 0; i < len(slice); i += size {
		end := i + size
		if end > len(slice) {
			end = len(slice)
		}
		result = append(result, slice[i:end])
	}

	return result
}

// Retry retries function with exponential backoff
func Retry(attempts int, delay time.Duration, fn func() error) error {
	var lastErr error

	for i := 0; i < attempts; i++ {
		if err := fn(); err != nil {
			lastErr = err
			time.Sleep(delay)
			delay *= 2 // Exponential backoff
			continue
		}
		return nil
	}

	return fmt.Errorf("failed after %d attempts: %w", attempts, lastErr)
}

// Debounce creates debounced function
func Debounce(fn func(), delay time.Duration) func() {
	var timer *time.Timer
	var mu sync.Mutex

	return func() {
		mu.Lock()
		defer mu.Unlock()

		if timer != nil {
			timer.Stop()
		}

		timer = time.AfterFunc(delay, fn)
	}
}

// Throttle creates throttled function
func Throttle(fn func(), interval time.Duration) func() {
	var lastCall time.Time
	var mu sync.Mutex

	return func() {
		mu.Lock()
		defer mu.Unlock()

		if time.Since(lastCall) >= interval {
			fn()
			lastCall = time.Now()
		}
	}
}

// SafeGo runs goroutine with panic recovery
func SafeGo(fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Log panic
				fmt.Printf("Recovered from panic: %v\n", r)
			}
		}()
		fn()
	}()
}

// WaitGroup with error collection
type ErrorGroup struct {
	wg     sync.WaitGroup
	errors []error
	mu     sync.Mutex
}

func NewErrorGroup() *ErrorGroup {
	return &ErrorGroup{}
}

func (eg *ErrorGroup) Go(fn func() error) {
	eg.wg.Add(1)
	go func() {
		defer eg.wg.Done()
		if err := fn(); err != nil {
			eg.mu.Lock()
			eg.errors = append(eg.errors, err)
			eg.mu.Unlock()
		}
	}()
}

func (eg *ErrorGroup) Wait() []error {
	eg.wg.Wait()
	return eg.errors
}

// TokenBucketLimiter - simple rate limiter using token bucket
type TokenBucketLimiter struct {
	rate      float64
	capacity  float64
	tokens    float64
	lastCheck time.Time
	mu        sync.Mutex
}

func NewTokenBucketLimiter(rate, capacity float64) *TokenBucketLimiter {
	return &TokenBucketLimiter{
		rate:      rate,
		capacity:  capacity,
		tokens:    capacity,
		lastCheck: time.Now(),
	}
}

func (rl *TokenBucketLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastCheck).Seconds()
	rl.lastCheck = now

	rl.tokens += elapsed * rl.rate
	if rl.tokens > rl.capacity {
		rl.tokens = rl.capacity
	}

	if rl.tokens >= 1 {
		rl.tokens--
		return true
	}

	return false
}

func (rl *TokenBucketLimiter) Wait() {
	for !rl.Allow() {
		time.Sleep(time.Millisecond * 100)
	}
}
