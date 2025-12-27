// MX-UI VPN Panel
// Core/advanced_routing.go
// Advanced Routing Features: DNS over HTTPS, MUX, Fragment, Routing Rules Management

package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// DNS OVER HTTPS (DoH) CONFIGURATION
// ============================================================================

// DoHConfig represents DNS over HTTPS configuration
type DoHConfig struct {
	Enabled       bool              `json:"enabled" yaml:"enabled"`
	Servers       []DoHServer       `json:"servers" yaml:"servers"`
	QueryStrategy string            `json:"query_strategy" yaml:"query_strategy"` // UseIP, UseIPv4, UseIPv6
	DisableCache  bool              `json:"disable_cache" yaml:"disable_cache"`
	CacheTTL      int               `json:"cache_ttl" yaml:"cache_ttl"` // seconds
	Hosts         map[string]string `json:"hosts,omitempty" yaml:"hosts,omitempty"`
	FakeDNS       *FakeDNSConfig    `json:"fake_dns,omitempty" yaml:"fake_dns,omitempty"`
}

// DoHServer represents a DoH server configuration
type DoHServer struct {
	Address       string   `json:"address" yaml:"address"` // URL or IP
	Port          int      `json:"port,omitempty" yaml:"port,omitempty"`
	Domains       []string `json:"domains,omitempty" yaml:"domains,omitempty"`
	ExpectIPs     []string `json:"expect_ips,omitempty" yaml:"expect_ips,omitempty"`
	SkipFallback  bool     `json:"skip_fallback,omitempty" yaml:"skip_fallback,omitempty"`
	QueryStrategy string   `json:"query_strategy,omitempty" yaml:"query_strategy,omitempty"`
	Tag           string   `json:"tag,omitempty" yaml:"tag,omitempty"`
}

// FakeDNSConfig represents Fake DNS configuration
type FakeDNSConfig struct {
	Enabled  bool   `json:"enabled" yaml:"enabled"`
	IPPool   string `json:"ip_pool" yaml:"ip_pool"`                           // e.g., "198.18.0.0/15"
	IPPoolV6 string `json:"ip_pool_v6,omitempty" yaml:"ip_pool_v6,omitempty"` // e.g., "fc00::/18"
	PoolSize int    `json:"pool_size,omitempty" yaml:"pool_size,omitempty"`
}

// DoHPresets contains common DoH server presets
var DoHPresets = map[string]*DoHServer{
	"google": {
		Address: "https://dns.google/dns-query",
		Tag:     "google-doh",
	},
	"cloudflare": {
		Address: "https://cloudflare-dns.com/dns-query",
		Tag:     "cloudflare-doh",
	},
	"cloudflare-security": {
		Address: "https://security.cloudflare-dns.com/dns-query",
		Tag:     "cloudflare-security-doh",
	},
	"cloudflare-family": {
		Address: "https://family.cloudflare-dns.com/dns-query",
		Tag:     "cloudflare-family-doh",
	},
	"adguard": {
		Address: "https://dns.adguard.com/dns-query",
		Tag:     "adguard-doh",
	},
	"quad9": {
		Address: "https://dns.quad9.net/dns-query",
		Tag:     "quad9-doh",
	},
	"403": {
		Address: "https://dns.403.online/dns-query",
		Tag:     "403-doh",
	},
}

// DefaultDoHConfig returns default DoH configuration
func DefaultDoHConfig() *DoHConfig {
	return &DoHConfig{
		Enabled:       false,
		QueryStrategy: "UseIP",
		CacheTTL:      600,
		Servers: []DoHServer{
			*DoHPresets["cloudflare"],
			*DoHPresets["google"],
		},
	}
}

// GenerateXrayDNSConfig generates Xray DNS configuration from DoH config
func (cfg *DoHConfig) GenerateXrayDNSConfig() map[string]interface{} {
	if !cfg.Enabled {
		return nil
	}

	servers := make([]interface{}, 0)

	for _, server := range cfg.Servers {
		if len(server.Domains) > 0 || len(server.ExpectIPs) > 0 {
			serverObj := map[string]interface{}{
				"address": server.Address,
			}
			if len(server.Domains) > 0 {
				serverObj["domains"] = server.Domains
			}
			if len(server.ExpectIPs) > 0 {
				serverObj["expectIPs"] = server.ExpectIPs
			}
			if server.SkipFallback {
				serverObj["skipFallback"] = true
			}
			if server.QueryStrategy != "" {
				serverObj["queryStrategy"] = server.QueryStrategy
			}
			servers = append(servers, serverObj)
		} else {
			servers = append(servers, server.Address)
		}
	}

	dnsConfig := map[string]interface{}{
		"servers":       servers,
		"queryStrategy": cfg.QueryStrategy,
		"disableCache":  cfg.DisableCache,
		"cacheStrategy": "enable",
	}

	if len(cfg.Hosts) > 0 {
		dnsConfig["hosts"] = cfg.Hosts
	}

	if cfg.FakeDNS != nil && cfg.FakeDNS.Enabled {
		fakedns := []map[string]interface{}{
			{"ipPool": cfg.FakeDNS.IPPool, "poolSize": cfg.FakeDNS.PoolSize},
		}
		if cfg.FakeDNS.IPPoolV6 != "" {
			fakedns = append(fakedns, map[string]interface{}{
				"ipPool":   cfg.FakeDNS.IPPoolV6,
				"poolSize": cfg.FakeDNS.PoolSize,
			})
		}
		dnsConfig["fakedns"] = fakedns
	}

	return dnsConfig
}

// ============================================================================
// MUX CONFIGURATION
// ============================================================================

// RoutingMuxConfig represents MUX multiplexing configuration for routing
type RoutingMuxConfig struct {
	Enabled         bool   `json:"enabled" yaml:"enabled"`
	Concurrency     int    `json:"concurrency" yaml:"concurrency"`             // 1-1024
	XudpConcurrency int    `json:"xudp_concurrency" yaml:"xudp_concurrency"`   // sing-box
	XudpProxyUDP443 string `json:"xudp_proxy_udp443" yaml:"xudp_proxy_udp443"` // reject, allow, skip
}

// DefaultRoutingMuxConfig returns default MUX configuration
func DefaultRoutingMuxConfig() *RoutingMuxConfig {
	return &RoutingMuxConfig{
		Enabled:         false,
		Concurrency:     8,
		XudpConcurrency: 16,
		XudpProxyUDP443: "reject",
	}
}

// GenerateXrayMuxConfig generates Xray MUX configuration
func (cfg *RoutingMuxConfig) GenerateXrayMuxConfig() map[string]interface{} {
	if !cfg.Enabled {
		return nil
	}

	return map[string]interface{}{
		"enabled":         true,
		"concurrency":     cfg.Concurrency,
		"xudpConcurrency": cfg.XudpConcurrency,
		"xudpProxyUDP443": cfg.XudpProxyUDP443,
	}
}

// GenerateSingboxMuxConfig generates sing-box MUX configuration
func (cfg *RoutingMuxConfig) GenerateSingboxMuxConfig() map[string]interface{} {
	if !cfg.Enabled {
		return nil
	}

	return map[string]interface{}{
		"enabled":         true,
		"protocol":        "smux",
		"max_connections": cfg.Concurrency,
		"min_streams":     4,
		"max_streams":     0,
	}
}

// ============================================================================
// FRAGMENT CONFIGURATION
// ============================================================================

// RoutingFragmentConfig represents TCP fragment configuration for routing
type RoutingFragmentConfig struct {
	Enabled  bool   `json:"enabled" yaml:"enabled"`
	Packets  string `json:"packets" yaml:"packets"`   // tlshello, 1-3
	Length   string `json:"length" yaml:"length"`     // 100-200
	Interval string `json:"interval" yaml:"interval"` // 10-20 ms
}

// DefaultRoutingFragmentConfig returns default fragment configuration
func DefaultRoutingFragmentConfig() *RoutingFragmentConfig {
	return &RoutingFragmentConfig{
		Enabled:  false,
		Packets:  "tlshello",
		Length:   "100-200",
		Interval: "10-20",
	}
}

// GenerateXrayFragmentOutbound generates Xray fragment outbound
func (cfg *RoutingFragmentConfig) GenerateXrayFragmentOutbound() map[string]interface{} {
	if !cfg.Enabled {
		return nil
	}

	return map[string]interface{}{
		"tag":      "fragment",
		"protocol": "freedom",
		"settings": map[string]interface{}{
			"fragment": map[string]interface{}{
				"packets":  cfg.Packets,
				"length":   cfg.Length,
				"interval": cfg.Interval,
			},
		},
	}
}

// ============================================================================
// ROUTING RULES MANAGER
// ============================================================================

// RoutingRulesManager manages routing rules
type RoutingRulesManager struct {
	rules   []*ExtendedRoutingRule
	presets map[string]*RoutingPreset
	mu      sync.RWMutex
}

// ExtendedRoutingRule represents an extended routing rule
type ExtendedRoutingRule struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	Priority    int    `json:"priority"`

	// Conditions
	Domains    []string `json:"domains,omitempty"`
	IPs        []string `json:"ips,omitempty"`
	GeoIP      []string `json:"geoip,omitempty"`
	GeoSite    []string `json:"geosite,omitempty"`
	Port       string   `json:"port,omitempty"`
	Protocol   []string `json:"protocol,omitempty"`
	Network    string   `json:"network,omitempty"`
	Source     []string `json:"source,omitempty"`
	User       []string `json:"user,omitempty"`
	InboundTag []string `json:"inbound_tag,omitempty"`

	// Action
	OutboundTag string `json:"outbound_tag"`

	// Metadata
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RoutingPreset represents a preset routing configuration
type RoutingPreset struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Rules       []*ExtendedRoutingRule `json:"rules"`
}

// Global routing rules manager
var RoutingRules *RoutingRulesManager

// InitRoutingRulesManager initializes the routing rules manager
func InitRoutingRulesManager() error {
	RoutingRules = &RoutingRulesManager{
		rules:   []*ExtendedRoutingRule{},
		presets: make(map[string]*RoutingPreset),
	}

	// Load preset routing rules
	RoutingRules.loadPresets()

	return nil
}

// loadPresets loads preset routing configurations
func (rm *RoutingRulesManager) loadPresets() {
	// China direct preset
	rm.presets["china-direct"] = &RoutingPreset{
		Name:        "China Direct",
		Description: "Route China traffic directly, others through proxy",
		Rules: []*ExtendedRoutingRule{
			{
				Name:        "China Sites Direct",
				Description: "Chinese websites go direct",
				Enabled:     true,
				Priority:    100,
				GeoSite:     []string{"geosite:cn"},
				OutboundTag: "direct",
			},
			{
				Name:        "China IPs Direct",
				Description: "Chinese IPs go direct",
				Enabled:     true,
				Priority:    101,
				GeoIP:       []string{"geoip:cn", "geoip:private"},
				OutboundTag: "direct",
			},
		},
	}

	// Iran bypass preset
	rm.presets["iran-bypass"] = &RoutingPreset{
		Name:        "Iran Bypass",
		Description: "Route Iran traffic directly",
		Rules: []*ExtendedRoutingRule{
			{
				Name:        "Iran Sites Direct",
				Description: "Iranian websites go direct",
				Enabled:     true,
				Priority:    100,
				GeoSite:     []string{"geosite:category-ir"},
				OutboundTag: "direct",
			},
			{
				Name:        "Iran IPs Direct",
				Description: "Iranian IPs go direct",
				Enabled:     true,
				Priority:    101,
				GeoIP:       []string{"geoip:ir", "geoip:private"},
				OutboundTag: "direct",
			},
		},
	}

	// Block ads preset
	rm.presets["block-ads"] = &RoutingPreset{
		Name:        "Block Ads",
		Description: "Block advertisement domains",
		Rules: []*ExtendedRoutingRule{
			{
				Name:        "Block Ad Domains",
				Description: "Block advertisement and tracking domains",
				Enabled:     true,
				Priority:    1,
				GeoSite:     []string{"geosite:category-ads", "geosite:category-ads-all"},
				OutboundTag: "blocked",
			},
		},
	}

	// Gaming optimization preset
	rm.presets["gaming"] = &RoutingPreset{
		Name:        "Gaming Optimization",
		Description: "Optimize routing for gaming",
		Rules: []*ExtendedRoutingRule{
			{
				Name:        "Gaming Platforms Direct",
				Description: "Direct connection for gaming platforms",
				Enabled:     true,
				Priority:    50,
				Domains:     []string{"domain:steam.com", "domain:epicgames.com", "domain:playstation.net"},
				OutboundTag: "direct",
			},
		},
	}

	// Security preset
	rm.presets["security"] = &RoutingPreset{
		Name:        "Security",
		Description: "Block malware and phishing domains",
		Rules: []*ExtendedRoutingRule{
			{
				Name:        "Block Malware",
				Description: "Block known malware domains",
				Enabled:     true,
				Priority:    1,
				GeoSite:     []string{"geosite:category-malware"},
				OutboundTag: "blocked",
			},
			{
				Name:        "Block Phishing",
				Description: "Block known phishing domains",
				Enabled:     true,
				Priority:    2,
				GeoSite:     []string{"geosite:category-phishing"},
				OutboundTag: "blocked",
			},
		},
	}
}

// GetPresets returns available presets
func (rm *RoutingRulesManager) GetPresets() map[string]*RoutingPreset {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.presets
}

// ApplyPreset applies a routing preset
func (rm *RoutingRulesManager) ApplyPreset(nodeID int64, presetName string) error {
	rm.mu.RLock()
	preset, exists := rm.presets[presetName]
	rm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("preset not found: %s", presetName)
	}

	for _, rule := range preset.Rules {
		if err := rm.AddRule(nodeID, rule); err != nil {
			return err
		}
	}

	return nil
}

// AddRule adds a routing rule
func (rm *RoutingRulesManager) AddRule(nodeID int64, rule *ExtendedRoutingRule) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	now := time.Now()
	rule.CreatedAt = now
	rule.UpdatedAt = now

	// Convert to database format and save
	domains, _ := json.Marshal(rule.Domains)
	ips, _ := json.Marshal(rule.IPs)
	geoip, _ := json.Marshal(rule.GeoIP)
	geosite, _ := json.Marshal(rule.GeoSite)
	protocols, _ := json.Marshal(rule.Protocol)
	sources, _ := json.Marshal(rule.Source)
	users, _ := json.Marshal(rule.User)
	inboundTags, _ := json.Marshal(rule.InboundTag)

	result, err := DB.db.Exec(`
		INSERT INTO routing_rules 
		(node_id, priority, type, domain, ip, port, network, source, user, 
		 inbound_tag, protocol, outbound_tag, is_active, remark, created_at, updated_at)
		VALUES (?, ?, 'field', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, nodeID, rule.Priority, string(domains), string(ips), rule.Port, rule.Network,
		string(sources), string(users), string(inboundTags), string(protocols),
		rule.OutboundTag, rule.Enabled, rule.Description, now, now)

	if err != nil {
		return err
	}

	rule.ID, _ = result.LastInsertId()
	rm.rules = append(rm.rules, rule)

	// Also save GeoIP and GeoSite as separate fields or combined
	if len(rule.GeoIP) > 0 || len(rule.GeoSite) > 0 {
		// Store in extended routing rules table
		DB.db.Exec(`
			INSERT INTO extended_routing_rules 
			(routing_rule_id, geoip, geosite) VALUES (?, ?, ?)
		`, rule.ID, string(geoip), string(geosite))
	}

	return nil
}

// UpdateRule updates a routing rule
func (rm *RoutingRulesManager) UpdateRule(ruleID int64, rule *ExtendedRoutingRule) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rule.UpdatedAt = time.Now()

	domains, _ := json.Marshal(rule.Domains)
	ips, _ := json.Marshal(rule.IPs)
	protocols, _ := json.Marshal(rule.Protocol)

	_, err := DB.db.Exec(`
		UPDATE routing_rules SET
			priority = ?, domain = ?, ip = ?, port = ?, network = ?,
			protocol = ?, outbound_tag = ?, is_active = ?, remark = ?, updated_at = ?
		WHERE id = ?
	`, rule.Priority, string(domains), string(ips), rule.Port, rule.Network,
		string(protocols), rule.OutboundTag, rule.Enabled, rule.Description,
		rule.UpdatedAt, ruleID)

	return err
}

// DeleteRule deletes a routing rule
func (rm *RoutingRulesManager) DeleteRule(ruleID int64) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	_, err := DB.db.Exec("DELETE FROM routing_rules WHERE id = ?", ruleID)
	if err != nil {
		return err
	}

	// Remove from cache
	for i, r := range rm.rules {
		if r.ID == ruleID {
			rm.rules = append(rm.rules[:i], rm.rules[i+1:]...)
			break
		}
	}

	return nil
}

// GetRulesByNode retrieves all rules for a node
func (rm *RoutingRulesManager) GetRulesByNode(nodeID int64) ([]*ExtendedRoutingRule, error) {
	rows, err := DB.db.Query(`
		SELECT id, priority, domain, ip, port, network, protocol, 
		       outbound_tag, is_active, remark, created_at, updated_at
		FROM routing_rules
		WHERE node_id = ?
		ORDER BY priority ASC
	`, nodeID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*ExtendedRoutingRule
	for rows.Next() {
		rule := &ExtendedRoutingRule{}
		var domains, ips, protocols string

		err := rows.Scan(&rule.ID, &rule.Priority, &domains, &ips, &rule.Port,
			&rule.Network, &protocols, &rule.OutboundTag, &rule.Enabled,
			&rule.Description, &rule.CreatedAt, &rule.UpdatedAt)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(domains), &rule.Domains)
		json.Unmarshal([]byte(ips), &rule.IPs)
		json.Unmarshal([]byte(protocols), &rule.Protocol)

		rules = append(rules, rule)
	}

	return rules, nil
}

// GenerateXrayRoutingConfig generates Xray routing configuration
func (rm *RoutingRulesManager) GenerateXrayRoutingConfig(nodeID int64) (map[string]interface{}, error) {
	rules, err := rm.GetRulesByNode(nodeID)
	if err != nil {
		return nil, err
	}

	xrayRules := make([]map[string]interface{}, 0)

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		xrayRule := map[string]interface{}{
			"type":        "field",
			"outboundTag": rule.OutboundTag,
		}

		if len(rule.Domains) > 0 {
			xrayRule["domain"] = rule.Domains
		}
		if len(rule.IPs) > 0 {
			xrayRule["ip"] = rule.IPs
		}
		if len(rule.GeoIP) > 0 {
			if ips, ok := xrayRule["ip"].([]string); ok {
				xrayRule["ip"] = append(ips, rule.GeoIP...)
			} else {
				xrayRule["ip"] = rule.GeoIP
			}
		}
		if len(rule.GeoSite) > 0 {
			if domains, ok := xrayRule["domain"].([]string); ok {
				xrayRule["domain"] = append(domains, rule.GeoSite...)
			} else {
				xrayRule["domain"] = rule.GeoSite
			}
		}
		if rule.Port != "" {
			xrayRule["port"] = rule.Port
		}
		if rule.Network != "" {
			xrayRule["network"] = rule.Network
		}
		if len(rule.Protocol) > 0 {
			xrayRule["protocol"] = rule.Protocol
		}
		if len(rule.InboundTag) > 0 {
			xrayRule["inboundTag"] = rule.InboundTag
		}

		xrayRules = append(xrayRules, xrayRule)
	}

	// Add final catch-all rule
	xrayRules = append(xrayRules, map[string]interface{}{
		"type":        "field",
		"port":        "0-65535",
		"outboundTag": "proxy",
	})

	return map[string]interface{}{
		"domainStrategy": "IPIfNonMatch",
		"domainMatcher":  "hybrid",
		"rules":          xrayRules,
	}, nil
}

// ============================================================================
// DATABASE TABLES
// ============================================================================

// CreateAdvancedRoutingTables creates tables for advanced routing features
func CreateAdvancedRoutingTables() error {
	// Extended routing rules table for GeoIP/GeoSite
	_, err := DB.db.Exec(`
		CREATE TABLE IF NOT EXISTS extended_routing_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			routing_rule_id INTEGER NOT NULL,
			geoip TEXT,
			geosite TEXT,
			FOREIGN KEY (routing_rule_id) REFERENCES routing_rules(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return err
	}

	// DNS configuration table
	_, err = DB.db.Exec(`
		CREATE TABLE IF NOT EXISTS dns_configs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			node_id INTEGER NOT NULL,
			config TEXT NOT NULL,
			enabled INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return err
	}

	return nil
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// ParseRuleFromString parses a routing rule from a domain:value format
func ParseRuleFromString(input string) (*ExtendedRoutingRule, error) {
	parts := strings.SplitN(input, ":", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid rule format")
	}

	rule := &ExtendedRoutingRule{
		Enabled: true,
	}

	ruleType := strings.ToLower(parts[0])
	value := parts[1]

	switch ruleType {
	case "domain":
		rule.Domains = []string{"domain:" + value}
	case "full":
		rule.Domains = []string{"full:" + value}
	case "regexp":
		rule.Domains = []string{"regexp:" + value}
	case "geosite":
		rule.GeoSite = []string{"geosite:" + value}
	case "geoip":
		rule.GeoIP = []string{"geoip:" + value}
	case "ip":
		rule.IPs = []string{value}
	default:
		return nil, fmt.Errorf("unknown rule type: %s", ruleType)
	}

	return rule, nil
}
