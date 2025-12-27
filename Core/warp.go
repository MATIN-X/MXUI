// MXUI VPN Panel
// Core/warp.go
// Cloudflare WARP Integration: Configuration, Management, Routing

package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// WARP CONSTANTS
// ============================================================================

const (
	WarpConfigDir  = "./Data/warp"
	WarpConfigFile = "warp.conf"
	WarpBinaryPath = "/usr/local/bin/warp-cli"
	WarpSocketPath = "/var/run/warp-svc.sock"

	WarpModeWarp     = "warp"
	WarpModeWarpPlus = "warp+"
	WarpModeDOH      = "doh"
	WarpModeProxy    = "proxy"

	WarpStatusConnected    = "connected"
	WarpStatusDisconnected = "disconnected"
	WarpStatusConnecting   = "connecting"

	WarpEndpoint = "engage.cloudflareclient.com:2408"
	WarpIPv4     = "162.159.192.1"
	WarpIPv6     = "2606:4700:d0::a29f:c001"

	// WireGuard for WARP
	WarpInterfaceName = "warp0"
	WarpListenPort    = 51820
)

// ============================================================================
// WARP STRUCTURES
// ============================================================================

// WarpManager manages WARP integration
type WarpManager struct {
	config      *WarpConfig
	isEnabled   bool
	isConnected bool
	accountID   string
	deviceID    string
	privateKey  string
	publicKey   string
	addresses   []string
	endpoint    string
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// WarpConfig represents WARP configuration
type WarpConfig struct {
	Enabled        bool     `json:"enabled" yaml:"enabled"`
	Mode           string   `json:"mode" yaml:"mode"` // warp, warp+, doh, proxy
	LicenseKey     string   `json:"license_key,omitempty" yaml:"license_key,omitempty"`
	InterfaceName  string   `json:"interface_name" yaml:"interface_name"`
	ListenPort     int      `json:"listen_port" yaml:"listen_port"`
	MTU            int      `json:"mtu" yaml:"mtu"`
	AllowedIPs     []string `json:"allowed_ips" yaml:"allowed_ips"`
	ExcludedRoutes []string `json:"excluded_routes,omitempty" yaml:"excluded_routes,omitempty"`
	UseForIranian  bool     `json:"use_for_iranian" yaml:"use_for_iranian"`
	UseAsOutbound  bool     `json:"use_as_outbound" yaml:"use_as_outbound"`
	ProxyPort      int      `json:"proxy_port,omitempty" yaml:"proxy_port,omitempty"`
}

// WarpAccount represents WARP account information
type WarpAccount struct {
	AccountID   string    `json:"account_id"`
	LicenseKey  string    `json:"license_key,omitempty"`
	AccountType string    `json:"account_type"` // free, plus
	Quota       int64     `json:"quota"`
	CreatedAt   time.Time `json:"created_at"`
}

// WarpDevice represents a WARP device
type WarpDevice struct {
	DeviceID  string    `json:"device_id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	PublicKey string    `json:"public_key"`
	CreatedAt time.Time `json:"created_at"`
	Active    bool      `json:"active"`
}

// WarpStatus represents WARP connection status
type WarpStatus struct {
	Connected bool      `json:"connected"`
	Mode      string    `json:"mode"`
	AccountID string    `json:"account_id"`
	DeviceID  string    `json:"device_id"`
	Endpoint  string    `json:"endpoint"`
	Latency   int64     `json:"latency"` // milliseconds
	Upload    int64     `json:"upload"`
	Download  int64     `json:"download"`
	LastCheck time.Time `json:"last_check"`
}

// Global WARP manager
var Warp *WarpManager

// ============================================================================
// WARP INITIALIZATION
// ============================================================================

// InitWarpManager initializes the WARP manager
func InitWarpManager(config *WarpConfig) error {
	ctx, cancel := context.WithCancel(context.Background())

	Warp = &WarpManager{
		config:    config,
		isEnabled: config.Enabled,
		ctx:       ctx,
		cancel:    cancel,
		endpoint:  WarpEndpoint,
	}

	// Create config directory
	if err := os.MkdirAll(WarpConfigDir, 0755); err != nil {
		return fmt.Errorf("failed to create WARP config directory: %w", err)
	}

	// Load existing configuration
	if err := Warp.loadConfig(); err != nil {
		LogWarn("WARP", "Failed to load config: %v", err)
	}

	return nil
}

// ============================================================================
// WARP ACCOUNT MANAGEMENT
// ============================================================================

// RegisterDevice registers a new WARP device
func (wm *WarpManager) RegisterDevice() (*WarpDevice, error) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	// Generate WireGuard keys
	privateKey, publicKey, err := GenerateWireGuardKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate keys: %w", err)
	}

	// Prepare registration request
	reqBody := map[string]interface{}{
		"install_id": "",
		"tos":        time.Now().Format(time.RFC3339),
		"key":        publicKey,
		"fcm_token":  "",
		"type":       "Linux",
		"model":      runtime.GOARCH,
		"locale":     "en_US",
	}

	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send registration request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(
		"https://api.cloudflareclient.com/v0a884/reg",
		"application/json",
		strings.NewReader(string(bodyJSON)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register device: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("registration failed: %s", string(body))
	}

	// Parse response
	var result struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Account struct {
			ID          string `json:"id"`
			AccountType string `json:"account_type"`
			License     string `json:"license,omitempty"`
		} `json:"account"`
		Config struct {
			Peers []struct {
				PublicKey string `json:"public_key"`
				Endpoint  struct {
					V4   string `json:"v4"`
					V6   string `json:"v6"`
					Host string `json:"host"`
				} `json:"endpoint"`
			} `json:"peers"`
			Interface struct {
				Addresses struct {
					V4 string `json:"v4"`
					V6 string `json:"v6"`
				} `json:"addresses"`
			} `json:"interface"`
		} `json:"config"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Store configuration
	wm.deviceID = result.ID
	wm.accountID = result.Account.ID
	wm.privateKey = privateKey
	wm.publicKey = publicKey

	if len(result.Config.Interface.Addresses.V4) > 0 {
		wm.addresses = append(wm.addresses, result.Config.Interface.Addresses.V4)
	}
	if len(result.Config.Interface.Addresses.V6) > 0 {
		wm.addresses = append(wm.addresses, result.Config.Interface.Addresses.V6)
	}

	// Save configuration
	if err := wm.saveConfig(); err != nil {
		LogWarn("WARP", "Failed to save config: %v", err)
	}

	device := &WarpDevice{
		DeviceID:  result.ID,
		Name:      "MXUI Panel",
		Type:      result.Type,
		PublicKey: publicKey,
		CreatedAt: time.Now(),
		Active:    true,
	}

	LogInfo("WARP", "Device registered successfully: %s", device.DeviceID)
	return device, nil
}

// ApplyLicenseKey applies a WARP+ license key
func (wm *WarpManager) ApplyLicenseKey(licenseKey string) error {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	if wm.deviceID == "" {
		return errors.New("device not registered")
	}

	reqBody := map[string]interface{}{
		"license": licenseKey,
	}

	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(
		"PUT",
		fmt.Sprintf("https://api.cloudflareclient.com/v0a884/reg/%s/account", wm.deviceID),
		strings.NewReader(string(bodyJSON)),
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to apply license: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("license application failed: %s", string(body))
	}

	wm.config.LicenseKey = licenseKey
	wm.saveConfig()

	LogInfo("WARP", "License key applied successfully")
	return nil
}

// ============================================================================
// WARP CONNECTION
// ============================================================================

// Connect establishes WARP connection
func (wm *WarpManager) Connect() error {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	if wm.isConnected {
		return nil
	}

	if wm.deviceID == "" {
		// Register device if not registered
		if _, err := wm.RegisterDevice(); err != nil {
			return fmt.Errorf("failed to register device: %w", err)
		}
	}

	// Generate WireGuard configuration
	if err := wm.generateWireGuardConfig(); err != nil {
		return fmt.Errorf("failed to generate config: %w", err)
	}

	// Bring up WireGuard interface
	if err := wm.bringUpInterface(); err != nil {
		return fmt.Errorf("failed to bring up interface: %w", err)
	}

	wm.isConnected = true
	LogInfo("WARP", "Connected successfully")
	return nil
}

// Disconnect disconnects WARP
func (wm *WarpManager) Disconnect() error {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	if !wm.isConnected {
		return nil
	}

	// Bring down interface
	if err := wm.bringDownInterface(); err != nil {
		return fmt.Errorf("failed to bring down interface: %w", err)
	}

	wm.isConnected = false
	LogInfo("WARP", "Disconnected successfully")
	return nil
}

// ============================================================================
// WIREGUARD CONFIGURATION
// ============================================================================

// generateWireGuardConfig generates WireGuard configuration for WARP
func (wm *WarpManager) generateWireGuardConfig() error {
	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
MTU = %d

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = %s
Endpoint = %s
PersistentKeepalive = 25
`,
		wm.privateKey,
		strings.Join(wm.addresses, ","),
		wm.config.MTU,
		strings.Join(wm.config.AllowedIPs, ","),
		wm.endpoint,
	)

	configPath := filepath.Join(WarpConfigDir, "warp.conf")
	if err := ioutil.WriteFile(configPath, []byte(config), 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// bringUpInterface brings up the WARP WireGuard interface
func (wm *WarpManager) bringUpInterface() error {
	configPath := filepath.Join(WarpConfigDir, "warp.conf")

	// wg-quick up
	cmd := exec.Command("wg-quick", "up", configPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to bring up interface: %s", string(output))
	}

	return nil
}

// bringDownInterface brings down the WARP WireGuard interface
func (wm *WarpManager) bringDownInterface() error {
	configPath := filepath.Join(WarpConfigDir, "warp.conf")

	cmd := exec.Command("wg-quick", "down", configPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to bring down interface: %s", string(output))
	}

	return nil
}

// ============================================================================
// WARP AS OUTBOUND
// ============================================================================

// GenerateWarpOutbound generates WARP outbound configuration for Xray
func (wm *WarpManager) GenerateWarpOutbound() (map[string]interface{}, error) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	if !wm.isEnabled || wm.deviceID == "" {
		return nil, errors.New("WARP not configured")
	}

	// Xray wireguard outbound
	outbound := map[string]interface{}{
		"protocol": "wireguard",
		"settings": map[string]interface{}{
			"secretKey": wm.privateKey,
			"address":   wm.addresses,
			"peers": []map[string]interface{}{
				{
					"publicKey":  "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
					"endpoint":   wm.endpoint,
					"keepAlive":  25,
					"allowedIPs": wm.config.AllowedIPs,
				},
			},
			"mtu": wm.config.MTU,
		},
		"tag": "warp-out",
	}

	return outbound, nil
}

// ============================================================================
// CONFIG PERSISTENCE
// ============================================================================

// loadConfig loads WARP configuration from file
func (wm *WarpManager) loadConfig() error {
	configPath := filepath.Join(WarpConfigDir, "config.json")

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var config struct {
		DeviceID   string   `json:"device_id"`
		AccountID  string   `json:"account_id"`
		PrivateKey string   `json:"private_key"`
		PublicKey  string   `json:"public_key"`
		Addresses  []string `json:"addresses"`
		Endpoint   string   `json:"endpoint"`
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	wm.deviceID = config.DeviceID
	wm.accountID = config.AccountID
	wm.privateKey = config.PrivateKey
	wm.publicKey = config.PublicKey
	wm.addresses = config.Addresses
	if config.Endpoint != "" {
		wm.endpoint = config.Endpoint
	}

	return nil
}

// saveConfig saves WARP configuration to file
func (wm *WarpManager) saveConfig() error {
	config := map[string]interface{}{
		"device_id":   wm.deviceID,
		"account_id":  wm.accountID,
		"private_key": wm.privateKey,
		"public_key":  wm.publicKey,
		"addresses":   wm.addresses,
		"endpoint":    wm.endpoint,
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	configPath := filepath.Join(WarpConfigDir, "config.json")
	return ioutil.WriteFile(configPath, data, 0600)
}

// ============================================================================
// STATUS CHECK
// ============================================================================

// GetStatus returns WARP connection status
func (wm *WarpManager) GetStatus() *WarpStatus {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	status := &WarpStatus{
		Connected: wm.isConnected,
		Mode:      wm.config.Mode,
		AccountID: wm.accountID,
		DeviceID:  wm.deviceID,
		Endpoint:  wm.endpoint,
		LastCheck: time.Now(),
	}

	// Check latency if connected
	if wm.isConnected {
		if latency, err := wm.checkLatency(); err == nil {
			status.Latency = latency
		}
	}

	return status
}

// checkLatency checks WARP connection latency
func (wm *WarpManager) checkLatency() (int64, error) {
	start := time.Now()

	conn, err := net.DialTimeout("tcp", "1.1.1.1:80", 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	latency := time.Since(start).Milliseconds()
	return latency, nil
}
