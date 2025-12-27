// MX-UI VPN Panel
// Core/subscription.go
// Advanced Subscription Management: URL Generation, Multi-client Support, Auto-update

package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"
)

// ============================================================================
// SUBSCRIPTION CONSTANTS
// ============================================================================

const (
	// Subscription types
	SubTypeBase64       = "base64"
	SubTypeJSON         = "json"
	SubTypeClash        = "clash"
	SubTypeClashMeta    = "clash_meta"
	SubTypeSingbox      = "singbox"
	SubTypeSFA          = "sfa" // Shadowrocket/SFI format
	SubTypeSurge        = "surge"
	SubTypeQuantumult   = "quantumult"
	SubTypeQuantumultX  = "quantumult_x"
	SubTypeStash        = "stash"
	SubTypeLoon         = "loon"
	SubTypeShadowrocket = "shadowrocket"
	SubTypeV2rayN       = "v2rayn"

	// Update intervals
	SubUpdateDaily   = "daily"
	SubUpdateWeekly  = "weekly"
	SubUpdateMonthly = "monthly"

	// Client types
	ClientClash        = "clash"
	ClientV2Ray        = "v2ray"
	ClientSingbox      = "sing-box"
	ClientShadowrocket = "shadowrocket"
	ClientQuantumultX  = "quantumult-x"
	ClientSurge        = "surge"
	ClientStash        = "stash"
)

// ============================================================================
// SUBSCRIPTION STRUCTURES
// ============================================================================

// SubscriptionManager manages user subscriptions
type SubscriptionManager struct {
	config    *SubscriptionConfig
	templates map[string]*template.Template
	cache     map[string]*CachedSubscription
	mu        sync.RWMutex
	cacheMu   sync.RWMutex
}

// SubscriptionConfig represents subscription configuration
type SubscriptionConfig struct {
	Enabled           bool     `json:"enabled" yaml:"enabled"`
	BaseURL           string   `json:"base_url" yaml:"base_url"`
	PathPrefix        string   `json:"path_prefix" yaml:"path_prefix"`
	PathLength        int      `json:"path_length" yaml:"path_length"`
	CacheEnabled      bool     `json:"cache_enabled" yaml:"cache_enabled"`
	CacheTTL          int      `json:"cache_ttl" yaml:"cache_ttl"` // seconds
	DefaultClientName string   `json:"default_client_name" yaml:"default_client_name"`
	ShowInfo          bool     `json:"show_info" yaml:"show_info"`
	ShowExpiry        bool     `json:"show_expiry" yaml:"show_expiry"`
	ShowTraffic       bool     `json:"show_traffic" yaml:"show_traffic"`
	CustomRules       []string `json:"custom_rules,omitempty" yaml:"custom_rules,omitempty"`
	ExcludedProtocols []string `json:"excluded_protocols,omitempty" yaml:"excluded_protocols,omitempty"`
	FragmentEnabled   bool     `json:"fragment_enabled" yaml:"fragment_enabled"`
	MuxEnabled        bool     `json:"mux_enabled" yaml:"mux_enabled"`
}

// CachedSubscription represents a cached subscription
type CachedSubscription struct {
	Content     string
	Format      string
	GeneratedAt time.Time
	ExpiresAt   time.Time
}

// SubscriptionInfo represents subscription metadata
type SubscriptionInfo struct {
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
	Total    int64  `json:"total"`
	Expire   int64  `json:"expire,omitempty"`
	Title    string `json:"title,omitempty"`
	URL      string `json:"url,omitempty"`
	UserInfo string `json:"user_info,omitempty"`
}

// ProxyConfig represents a proxy configuration
type ProxyConfig struct {
	Name     string                 `json:"name"`
	Type     string                 `json:"type"`
	Server   string                 `json:"server"`
	Port     int                    `json:"port"`
	UUID     string                 `json:"uuid,omitempty"`
	Password string                 `json:"password,omitempty"`
	Method   string                 `json:"method,omitempty"`
	Network  string                 `json:"network,omitempty"`
	TLS      bool                   `json:"tls,omitempty"`
	SNI      string                 `json:"sni,omitempty"`
	ALPN     []string               `json:"alpn,omitempty"`
	Path     string                 `json:"path,omitempty"`
	Host     string                 `json:"host,omitempty"`
	Headers  map[string]string      `json:"headers,omitempty"`

	// Protocol-specific fields
	AlterID     int    `json:"alter_id,omitempty"`     // VMess
	Security    string `json:"security,omitempty"`     // VMess
	Flow        string `json:"flow,omitempty"`         // VLESS
	ServiceName string `json:"service_name,omitempty"` // gRPC

	Extra    map[string]interface{} `json:"extra,omitempty"`
}

// Global subscription manager
var Subscription *SubscriptionManager

// ============================================================================
// INITIALIZATION
// ============================================================================

// InitSubscriptionManager initializes the subscription manager
func InitSubscriptionManager(config *SubscriptionConfig) error {
	Subscription = &SubscriptionManager{
		config:    config,
		templates: make(map[string]*template.Template),
		cache:     make(map[string]*CachedSubscription),
	}

	// Load templates
	if err := Subscription.loadTemplates(); err != nil {
		return fmt.Errorf("failed to load templates: %w", err)
	}

	// Start cache cleanup routine
	if config.CacheEnabled {
		go Subscription.cacheCleanupRoutine()
	}

	return nil
}

// ============================================================================
// SUBSCRIPTION GENERATION
// ============================================================================

// GenerateSubscription generates a subscription for a user
func (sm *SubscriptionManager) GenerateSubscription(user *User, format string, clientType string) (string, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Check cache
	if sm.config.CacheEnabled {
		cacheKey := fmt.Sprintf("%d:%s:%s", user.ID, format, clientType)
		if cached := sm.getCache(cacheKey); cached != nil {
			return cached.Content, nil
		}
	}

	// Get user configs
	configs, err := sm.getUserConfigs(user)
	if err != nil {
		return "", fmt.Errorf("failed to get user configs: %w", err)
	}

	// Get subscription info
	info := sm.getSubscriptionInfo(user)

	// Generate based on format
	var content string
	switch format {
	case SubTypeBase64:
		content, err = sm.generateBase64Sub(configs, info)
	case SubTypeJSON:
		content, err = sm.generateJSONSub(configs, info)
	case SubTypeClash:
		content, err = sm.generateClashSub(configs, info, false)
	case SubTypeClashMeta:
		content, err = sm.generateClashSub(configs, info, true)
	case SubTypeSingbox:
		content, err = sm.generateSingboxSub(configs, info)
	case SubTypeSurge:
		content, err = sm.generateSurgeSub(configs, info)
	case SubTypeQuantumultX:
		content, err = sm.generateQuantumultXSub(configs, info)
	case SubTypeShadowrocket:
		content, err = sm.generateShadowrocketSub(configs, info)
	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}

	if err != nil {
		return "", err
	}

	// Cache result
	if sm.config.CacheEnabled {
		cacheKey := fmt.Sprintf("%d:%s:%s", user.ID, format, clientType)
		sm.setCache(cacheKey, content, format)
	}

	return content, nil
}

// ============================================================================
// FORMAT GENERATORS
// ============================================================================

// generateBase64Sub generates base64 encoded subscription
func (sm *SubscriptionManager) generateBase64Sub(configs []*ProxyConfig, info *SubscriptionInfo) (string, error) {
	var links []string

	for _, config := range configs {
		link, err := sm.configToShareLink(config)
		if err != nil {
			LogWarn("SUB", "Failed to generate link for %s: %v", config.Name, err)
			continue
		}
		links = append(links, link)
	}

	content := strings.Join(links, "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(content))

	return encoded, nil
}

// generateJSONSub generates JSON subscription
func (sm *SubscriptionManager) generateJSONSub(configs []*ProxyConfig, info *SubscriptionInfo) (string, error) {
	data := map[string]interface{}{
		"version": "1.0",
		"info":    info,
		"proxies": configs,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return string(jsonData), nil
}

// generateClashSub generates Clash/ClashMeta subscription
func (sm *SubscriptionManager) generateClashSub(configs []*ProxyConfig, info *SubscriptionInfo, isMeta bool) (string, error) {
	// Convert configs to Clash format
	proxies := make([]map[string]interface{}, 0, len(configs))
	proxyNames := make([]string, 0, len(configs))

	for _, config := range configs {
		clashProxy := sm.configToClashProxy(config, isMeta)
		if clashProxy != nil {
			proxies = append(proxies, clashProxy)
			proxyNames = append(proxyNames, config.Name)
		}
	}

	// Build Clash config
	clashConfig := map[string]interface{}{
		"port":                7890,
		"socks-port":          7891,
		"allow-lan":           false,
		"mode":                "rule",
		"log-level":           "info",
		"external-controller": "127.0.0.1:9090",
		"dns": map[string]interface{}{
			"enable":        true,
			"listen":        "0.0.0.0:53",
			"enhanced-mode": "fake-ip",
			"nameserver":    []string{"1.1.1.1", "8.8.8.8"},
			"fallback":      []string{"1.0.0.1", "8.8.4.4"},
		},
		"proxies": proxies,
		"proxy-groups": []map[string]interface{}{
			{
				"name":    "PROXY",
				"type":    "select",
				"proxies": proxyNames,
			},
			{
				"name":     "AUTO",
				"type":     "url-test",
				"proxies":  proxyNames,
				"url":      "http://www.gstatic.com/generate_204",
				"interval": 300,
			},
		},
		"rules": sm.getClashRules(),
	}

	// Add meta-specific features
	if isMeta {
		clashConfig["tun"] = map[string]interface{}{
			"enable":     false,
			"stack":      "system",
			"dns-hijack": []string{"any:53"},
		}
	}

	// Convert to YAML
	yamlData, err := yaml.Marshal(clashConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal YAML: %w", err)
	}

	return string(yamlData), nil
}

// generateSingboxSub generates sing-box subscription
func (sm *SubscriptionManager) generateSingboxSub(configs []*ProxyConfig, info *SubscriptionInfo) (string, error) {
	outbounds := make([]map[string]interface{}, 0)

	// Convert configs to sing-box outbounds
	for _, config := range configs {
		outbound := sm.configToSingboxOutbound(config)
		if outbound != nil {
			outbounds = append(outbounds, outbound)
		}
	}

	// Build sing-box config
	singboxConfig := map[string]interface{}{
		"log": map[string]interface{}{
			"level": "info",
		},
		"dns": map[string]interface{}{
			"servers": []map[string]interface{}{
				{"tag": "google", "address": "8.8.8.8"},
				{"tag": "cloudflare", "address": "1.1.1.1"},
			},
		},
		"inbounds": []map[string]interface{}{
			{
				"type":        "mixed",
				"tag":         "mixed-in",
				"listen":      "127.0.0.1",
				"listen_port": 2080,
			},
		},
		"outbounds": outbounds,
		"route": map[string]interface{}{
			"rules": sm.getSingboxRules(),
		},
	}

	jsonData, err := json.MarshalIndent(singboxConfig, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return string(jsonData), nil
}

// generateSurgeSub generates Surge subscription
func (sm *SubscriptionManager) generateSurgeSub(configs []*ProxyConfig, info *SubscriptionInfo) (string, error) {
	var lines []string

	// Header
	lines = append(lines, "[General]")
	lines = append(lines, "loglevel = notify")
	lines = append(lines, "skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local")
	lines = append(lines, "dns-server = 8.8.8.8, 1.1.1.1")
	lines = append(lines, "")

	// Proxies
	lines = append(lines, "[Proxy]")
	for _, config := range configs {
		surgeProxy := sm.configToSurgeProxy(config)
		if surgeProxy != "" {
			lines = append(lines, surgeProxy)
		}
	}
	lines = append(lines, "")

	// Proxy groups
	lines = append(lines, "[Proxy Group]")
	var proxyNames []string
	for _, config := range configs {
		proxyNames = append(proxyNames, config.Name)
	}
	lines = append(lines, fmt.Sprintf("Proxy = select, %s", strings.Join(proxyNames, ", ")))
	lines = append(lines, "")

	// Rules
	lines = append(lines, "[Rule]")
	lines = append(lines, "DOMAIN-SUFFIX,google.com,Proxy")
	lines = append(lines, "GEOIP,CN,DIRECT")
	lines = append(lines, "FINAL,Proxy")

	return strings.Join(lines, "\n"), nil
}

// generateQuantumultXSub generates Quantumult X subscription
func (sm *SubscriptionManager) generateQuantumultXSub(configs []*ProxyConfig, info *SubscriptionInfo) (string, error) {
	var lines []string

	for _, config := range configs {
		qxProxy := sm.configToQuantumultXProxy(config)
		if qxProxy != "" {
			lines = append(lines, qxProxy)
		}
	}

	content := strings.Join(lines, "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(content))

	return encoded, nil
}

// generateShadowrocketSub generates Shadowrocket subscription
func (sm *SubscriptionManager) generateShadowrocketSub(configs []*ProxyConfig, info *SubscriptionInfo) (string, error) {
	// Shadowrocket uses base64 encoded share links
	return sm.generateBase64Sub(configs, info)
}

// ============================================================================
// CONFIG CONVERTERS
// ============================================================================

// configToShareLink converts ProxyConfig to share link
func (sm *SubscriptionManager) configToShareLink(config *ProxyConfig) (string, error) {
	switch config.Type {
	case ProtocolVMess:
		return sm.vmessToShareLink(config)
	case ProtocolVLESS:
		return sm.vlessToShareLink(config)
	case ProtocolTrojan:
		return sm.trojanToShareLink(config)
	case ProtocolShadowsocks:
		return sm.shadowsocksToShareLink(config)
	default:
		return "", fmt.Errorf("unsupported protocol: %s", config.Type)
	}
}

// vmessToShareLink generates VMess share link
func (sm *SubscriptionManager) vmessToShareLink(config *ProxyConfig) (string, error) {
	vmessData := map[string]interface{}{
		"v":    "2",
		"ps":   config.Name,
		"add":  config.Server,
		"port": config.Port,
		"id":   config.UUID,
		"aid":  "0",
		"net":  config.Network,
		"type": "none",
		"host": config.Host,
		"path": config.Path,
		"tls":  "",
	}

	if config.TLS {
		vmessData["tls"] = "tls"
		if config.SNI != "" {
			vmessData["sni"] = config.SNI
		}
	}

	jsonData, err := json.Marshal(vmessData)
	if err != nil {
		return "", err
	}

	encoded := base64.StdEncoding.EncodeToString(jsonData)
	return "vmess://" + encoded, nil
}

// vlessToShareLink generates VLESS share link
func (sm *SubscriptionManager) vlessToShareLink(config *ProxyConfig) (string, error) {
	u := &url.URL{
		Scheme: "vless",
		User:   url.User(config.UUID),
		Host:   fmt.Sprintf("%s:%d", config.Server, config.Port),
	}

	query := url.Values{}
	query.Set("type", config.Network)
	query.Set("security", "none")

	if config.TLS {
		query.Set("security", "tls")
		if config.SNI != "" {
			query.Set("sni", config.SNI)
		}
	}

	if config.Path != "" {
		query.Set("path", config.Path)
	}
	if config.Host != "" {
		query.Set("host", config.Host)
	}

	u.RawQuery = query.Encode()
	u.Fragment = config.Name

	return u.String(), nil
}

// trojanToShareLink generates Trojan share link
func (sm *SubscriptionManager) trojanToShareLink(config *ProxyConfig) (string, error) {
	u := &url.URL{
		Scheme: "trojan",
		User:   url.User(config.Password),
		Host:   fmt.Sprintf("%s:%d", config.Server, config.Port),
	}

	query := url.Values{}
	if config.SNI != "" {
		query.Set("sni", config.SNI)
	}
	if config.Network != "" && config.Network != "tcp" {
		query.Set("type", config.Network)
	}

	u.RawQuery = query.Encode()
	u.Fragment = config.Name

	return u.String(), nil
}

// shadowsocksToShareLink generates Shadowsocks share link
func (sm *SubscriptionManager) shadowsocksToShareLink(config *ProxyConfig) (string, error) {
	userInfo := fmt.Sprintf("%s:%s", config.Method, config.Password)
	encoded := base64.StdEncoding.EncodeToString([]byte(userInfo))

	link := fmt.Sprintf("ss://%s@%s:%d", encoded, config.Server, config.Port)
	if config.Name != "" {
		link += "#" + url.QueryEscape(config.Name)
	}

	return link, nil
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// getUserConfigs retrieves all proxy configurations for a user
func (sm *SubscriptionManager) getUserConfigs(user *User) ([]*ProxyConfig, error) {
	// TODO: Implement based on user's enabled protocols and inbounds
	return nil, nil
}

// getSubscriptionInfo retrieves subscription info for a user
func (sm *SubscriptionManager) getSubscriptionInfo(user *User) *SubscriptionInfo {
	info := &SubscriptionInfo{
		Upload:   user.UploadUsed,
		Download: user.DownloadUsed,
		Total:    user.DataLimit,
		Title:    user.Username,
	}

	if user.ExpiryTime != nil {
		info.Expire = user.ExpiryTime.Unix()
	}

	return info
}

// getClashRules returns Clash routing rules
func (sm *SubscriptionManager) getClashRules() []string {
	return []string{
		"DOMAIN-SUFFIX,google.com,PROXY",
		"GEOIP,CN,DIRECT",
		"MATCH,PROXY",
	}
}

// getSingboxRules returns sing-box routing rules
func (sm *SubscriptionManager) getSingboxRules() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"geoip":    "cn",
			"outbound": "direct",
		},
	}
}

// ============================================================================
// CACHE MANAGEMENT
// ============================================================================

// getCache retrieves cached subscription
func (sm *SubscriptionManager) getCache(key string) *CachedSubscription {
	sm.cacheMu.RLock()
	defer sm.cacheMu.RUnlock()

	cached, exists := sm.cache[key]
	if !exists {
		return nil
	}

	if time.Now().After(cached.ExpiresAt) {
		return nil
	}

	return cached
}

// setCache stores subscription in cache
func (sm *SubscriptionManager) setCache(key, content, format string) {
	sm.cacheMu.Lock()
	defer sm.cacheMu.Unlock()

	sm.cache[key] = &CachedSubscription{
		Content:     content,
		Format:      format,
		GeneratedAt: time.Now(),
		ExpiresAt:   time.Now().Add(time.Duration(sm.config.CacheTTL) * time.Second),
	}
}

// cacheCleanupRoutine periodically cleans expired cache entries
func (sm *SubscriptionManager) cacheCleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sm.cacheMu.Lock()
		now := time.Now()
		for key, cached := range sm.cache {
			if now.After(cached.ExpiresAt) {
				delete(sm.cache, key)
			}
		}
		sm.cacheMu.Unlock()
	}
}

// loadTemplates loads subscription templates
func (sm *SubscriptionManager) loadTemplates() error {
	// TODO: Load custom templates if needed
	return nil
}

// ====================================================================================
// SUBSCRIPTION FORMAT CONVERTERS
// ====================================================================================

// configToClashProxy converts config to Clash/ClashMeta format
func (sm *SubscriptionManager) configToClashProxy(config *ProxyConfig, isMeta bool) map[string]interface{} {
	proxy := map[string]interface{}{
		"name":   config.Name,
		"server": config.Server,
		"port":   config.Port,
	}

	switch config.Type {
	case "vmess":
		proxy["type"] = "vmess"
		proxy["uuid"] = config.UUID
		proxy["alterId"] = config.AlterID
		proxy["cipher"] = config.Security
		proxy["tls"] = config.TLS
		if config.Network != "" {
			proxy["network"] = config.Network
		}
		if config.Host != "" {
			proxy["ws-opts"] = map[string]interface{}{
				"path": config.Path,
				"headers": map[string]string{
					"Host": config.Host,
				},
			}
		}

	case "vless":
		proxy["type"] = "vless"
		proxy["uuid"] = config.UUID
		proxy["flow"] = config.Flow
		proxy["tls"] = config.TLS
		if config.Network != "" {
			proxy["network"] = config.Network
		}
		if config.Network == "grpc" {
			proxy["grpc-opts"] = map[string]interface{}{
				"grpc-service-name": config.ServiceName,
			}
		}

	case "trojan":
		proxy["type"] = "trojan"
		proxy["password"] = config.Password
		proxy["sni"] = config.SNI
		proxy["skip-cert-verify"] = false
		if config.Network != "" {
			proxy["network"] = config.Network
		}

	case "shadowsocks":
		proxy["type"] = "ss"
		proxy["cipher"] = config.Method
		proxy["password"] = config.Password
	}

	if config.TLS {
		proxy["skip-cert-verify"] = false
		if config.SNI != "" {
			proxy["servername"] = config.SNI
		}
	}

	return proxy
}

// configToSingboxOutbound converts config to Sing-box outbound format
func (sm *SubscriptionManager) configToSingboxOutbound(config *ProxyConfig) map[string]interface{} {
	outbound := map[string]interface{}{
		"tag":    config.Name,
		"server": config.Server,
		"server_port": config.Port,
	}

	switch config.Type {
	case "vmess":
		outbound["type"] = "vmess"
		outbound["uuid"] = config.UUID
		outbound["alter_id"] = config.AlterID
		outbound["security"] = config.Security

		if config.Network != "" {
			transport := map[string]interface{}{
				"type": config.Network,
			}
			if config.Network == "ws" {
				transport["path"] = config.Path
				transport["headers"] = map[string]string{
					"Host": config.Host,
				}
			}
			outbound["transport"] = transport
		}

		if config.TLS {
			outbound["tls"] = map[string]interface{}{
				"enabled": true,
				"server_name": config.SNI,
				"insecure": false,
			}
		}

	case "vless":
		outbound["type"] = "vless"
		outbound["uuid"] = config.UUID
		outbound["flow"] = config.Flow

		if config.Network != "" {
			transport := map[string]interface{}{
				"type": config.Network,
			}
			if config.Network == "grpc" {
				transport["service_name"] = config.ServiceName
			}
			outbound["transport"] = transport
		}

		if config.TLS {
			outbound["tls"] = map[string]interface{}{
				"enabled": true,
				"server_name": config.SNI,
			}
		}

	case "trojan":
		outbound["type"] = "trojan"
		outbound["password"] = config.Password

		if config.TLS {
			outbound["tls"] = map[string]interface{}{
				"enabled": true,
				"server_name": config.SNI,
			}
		}

	case "shadowsocks":
		outbound["type"] = "shadowsocks"
		outbound["method"] = config.Method
		outbound["password"] = config.Password
	}

	return outbound
}

// configToSurgeProxy converts config to Surge format
func (sm *SubscriptionManager) configToSurgeProxy(config *ProxyConfig) string {
	var parts []string
	parts = append(parts, config.Name)
	parts = append(parts, fmt.Sprintf("%s", config.Type))
	parts = append(parts, config.Server)
	parts = append(parts, fmt.Sprintf("%d", config.Port))

	switch config.Type {
	case "vmess":
		parts = append(parts, fmt.Sprintf("username=%s", config.UUID))
		if config.TLS {
			parts = append(parts, "tls=true")
			if config.SNI != "" {
				parts = append(parts, fmt.Sprintf("sni=%s", config.SNI))
			}
		}
		if config.Network == "ws" {
			parts = append(parts, fmt.Sprintf("ws=true"))
			parts = append(parts, fmt.Sprintf("ws-path=%s", config.Path))
			if config.Host != "" {
				parts = append(parts, fmt.Sprintf("ws-headers=Host:%s", config.Host))
			}
		}

	case "trojan":
		parts = append(parts, fmt.Sprintf("password=%s", config.Password))
		if config.SNI != "" {
			parts = append(parts, fmt.Sprintf("sni=%s", config.SNI))
		}
		parts = append(parts, "skip-cert-verify=false")

	case "shadowsocks":
		parts = append(parts, fmt.Sprintf("encrypt-method=%s", config.Method))
		parts = append(parts, fmt.Sprintf("password=%s", config.Password))
	}

	return strings.Join(parts, ", ")
}

// configToQuantumultXProxy converts config to QuantumultX format
func (sm *SubscriptionManager) configToQuantumultXProxy(config *ProxyConfig) string {
	var parts []string

	switch config.Type {
	case "vmess":
		// vmess = server:port, method=aes-128-gcm, password=uuid, obfs=ws, obfs-host=example.com
		parts = append(parts, "vmess")
		parts = append(parts, fmt.Sprintf("%s:%d", config.Server, config.Port))
		parts = append(parts, fmt.Sprintf("method=%s", config.Security))
		parts = append(parts, fmt.Sprintf("password=%s", config.UUID))

		if config.Network == "ws" {
			parts = append(parts, "obfs=ws")
			if config.Host != "" {
				parts = append(parts, fmt.Sprintf("obfs-host=%s", config.Host))
			}
			if config.Path != "" {
				parts = append(parts, fmt.Sprintf("obfs-uri=%s", config.Path))
			}
		}

		if config.TLS {
			parts = append(parts, "tls=true")
		}

		parts = append(parts, fmt.Sprintf("tag=%s", config.Name))

	case "trojan":
		// trojan = server:port, password=pwd, over-tls=true, tls-host=example.com
		parts = append(parts, "trojan")
		parts = append(parts, fmt.Sprintf("%s:%d", config.Server, config.Port))
		parts = append(parts, fmt.Sprintf("password=%s", config.Password))
		parts = append(parts, "over-tls=true")

		if config.SNI != "" {
			parts = append(parts, fmt.Sprintf("tls-host=%s", config.SNI))
		}

		parts = append(parts, fmt.Sprintf("tag=%s", config.Name))

	case "shadowsocks":
		// shadowsocks = server:port, method=aes-256-gcm, password=pwd
		parts = append(parts, "shadowsocks")
		parts = append(parts, fmt.Sprintf("%s:%d", config.Server, config.Port))
		parts = append(parts, fmt.Sprintf("method=%s", config.Method))
		parts = append(parts, fmt.Sprintf("password=%s", config.Password))
		parts = append(parts, fmt.Sprintf("tag=%s", config.Name))
	}

	return strings.Join(parts, ", ")
}
