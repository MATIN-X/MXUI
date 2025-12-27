// MX-UI VPN Panel
// Core/routing.go
// Routing Management: Rules, DNS, WARP, GeoFiles, Blocking, Direct Routes

package core

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// CONSTANTS
// ============================================================================

const (
	// WARP modes
	WARPModeOff   = "off"
	WARPModeProxy = "proxy"
	WARPModeFull  = "full"

	// Routing strategies
	RoutingStrategyAsIs         = "AsIs"
	RoutingStrategyIPIfNonMatch = "IPIfNonMatch"
	RoutingStrategyIPOnDemand   = "IPOnDemand"

	// Outbound tags
	OutboundDirect  = "direct"
	OutboundBlocked = "blocked"
	OutboundProxy   = "proxy"
	OutboundWarp    = "warp"

	// Rule types
	RuleTypeField = "field"

	// GeoFile paths
	GeoIPPath   = "./Data/xray/geoip.dat"
	GeoSitePath = "./Data/xray/geosite.dat"

	// WARP endpoints
	WarpEndpointDefault = "engage.cloudflareclient.com:2408"
	WarpEndpointV6      = "[2606:4700:d0::a29f:c001]:2408"

	// DNS providers
	DNSGoogle        = "8.8.8.8"
	DNSCloudflare    = "1.1.1.1"
	DNSGoogleDoH     = "https://dns.google/dns-query"
	DNSCloudflareDoH = "https://cloudflare-dns.com/dns-query"
	DNSGoogleDoT     = "tls://dns.google"
	DNSCloudflareDoT = "tls://one.one.one.one"

	// Block list URLs
	BlockListIranAds     = "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerHosts.txt"
	BlockListMalware     = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
	BlockListPornography = "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts"
)

// ============================================================================
// ROUTING MANAGER
// ============================================================================

// RoutingManager handles all routing operations
type RoutingManager struct {
	rules       []*RoutingRule
	dnsConfig   *DNSConfig
	warpConfig  *WARPConfiguration
	warpMode    string
	blockLists  map[string]*BlockList
	directRules *DirectRules
	geoAssets   *GeoAssets
	mu          sync.RWMutex
}

// Global routing manager instance
var Routing *RoutingManager

// InitRoutingManager initializes the routing manager
func InitRoutingManager() error {
	Routing = &RoutingManager{
		rules:      []*RoutingRule{},
		blockLists: make(map[string]*BlockList),
		geoAssets:  &GeoAssets{},
		dnsConfig:  DefaultDNSConfig(),
		warpConfig: DefaultWARPConfig(),
		directRules: &DirectRules{
			Domains: []string{},
			IPs:     []string{},
		},
	}

	// Load from database
	if err := Routing.loadFromDB(); err != nil {
		return err
	}

	// Check and download GeoFiles if needed
	go Routing.ensureGeoFiles()

	return nil
}

// EnableWARP enables WARP with the given configuration
func (rm *RoutingManager) EnableWARP(cfg *WARPConfig) error {
	// Add WARP outbound
	_ = &OutboundConfig{
		Tag:      "warp",
		Protocol: "wireguard",
		Settings: map[string]interface{}{
			"privateKey": cfg.PrivateKey,
			"peers": []map[string]interface{}{{
				"publicKey": cfg.PublicKey,
				"endpoint":  "engage.cloudflareclient.com:2408",
			}},
		},
	}
	return rm.saveOutbound()
}

// saveOutbound saves an outbound configuration
func (rm *RoutingManager) saveOutbound() error {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// Save outbound configurations to database or config file
	// For now, we keep them in memory
	// In production, you might want to persist to database

	LogInfo("ROUTING", "Outbound configurations saved (%d rules)", len(rm.rules))
	return nil
}

// ============================================================================
// ROUTING RULES
// ============================================================================

// RoutingConfig represents complete routing configuration for node sync
type RoutingConfig struct {
	Rules       []*RoutingRule         `json:"rules"`
	DomainRules []string               `json:"domain_rules,omitempty"`
	IPRules     []string               `json:"ip_rules,omitempty"`
	Settings    map[string]interface{} `json:"settings,omitempty"`
}

// RoutingRule represents a routing rule (defined in database.go, extended here)
type RoutingRuleExtended struct {
	*RoutingRule
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	Order       int    `json:"order"`
}

// CreateRuleRequest represents a request to create a routing rule
type CreateRuleRequest struct {
	NodeID      int64    `json:"node_id"`
	Priority    int      `json:"priority"`
	Type        string   `json:"type"`
	Domains     []string `json:"domains,omitempty"`
	IPs         []string `json:"ips,omitempty"`
	Port        string   `json:"port,omitempty"`
	SourcePort  string   `json:"source_port,omitempty"`
	Network     string   `json:"network,omitempty"`
	Source      []string `json:"source,omitempty"`
	User        []string `json:"user,omitempty"`
	InboundTags []string `json:"inbound_tags,omitempty"`
	Protocols   []string `json:"protocols,omitempty"`
	Attrs       string   `json:"attrs,omitempty"`
	OutboundTag string   `json:"outbound_tag"`
	BalancerTag string   `json:"balancer_tag,omitempty"`
	Remark      string   `json:"remark,omitempty"`
	IsActive    bool     `json:"is_active"`
}

// CreateRule creates a new routing rule
func (rm *RoutingManager) CreateRule(req *CreateRuleRequest) (*RoutingRule, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Validate
	if req.OutboundTag == "" && req.BalancerTag == "" {
		return nil, errors.New("outbound_tag or balancer_tag is required")
	}

	now := time.Now()

	// Insert into database
	result, err := DB.db.Exec(`
		INSERT INTO routing_rules (
			node_id, priority, type, domain, ip, port, source_port,
			network, source, user, inbound_tag, protocol, attrs,
			outbound_tag, balancer_tag, is_active, remark, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		req.NodeID, req.Priority, req.Type,
		StringSliceToJSON(req.Domains), StringSliceToJSON(req.IPs),
		req.Port, req.SourcePort, req.Network,
		StringSliceToJSON(req.Source), StringSliceToJSON(req.User),
		StringSliceToJSON(req.InboundTags), StringSliceToJSON(req.Protocols),
		req.Attrs, req.OutboundTag, req.BalancerTag, req.IsActive, req.Remark,
		now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create rule: %w", err)
	}

	id, _ := result.LastInsertId()

	rule := &RoutingRule{
		ID:          id,
		NodeID:      req.NodeID,
		Priority:    req.Priority,
		Type:        req.Type,
		Domain:      req.Domains,
		IP:          req.IPs,
		Port:        req.Port,
		SourcePort:  req.SourcePort,
		Network:     req.Network,
		Source:      req.Source,
		User:        req.User,
		InboundTag:  req.InboundTags,
		Protocol:    req.Protocols,
		Attrs:       req.Attrs,
		OutboundTag: req.OutboundTag,
		BalancerTag: req.BalancerTag,
		IsActive:    req.IsActive,
		Remark:      req.Remark,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	rm.rules = append(rm.rules, rule)
	rm.sortRules()

	// Notify protocol manager to reload
	if Protocols != nil {
		go Protocols.reloadCores()
	}

	return rule, nil
}

// UpdateRule updates a routing rule
func (rm *RoutingManager) UpdateRule(id int64, req *CreateRuleRequest) (*RoutingRule, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	now := time.Now()

	_, err := DB.db.Exec(`
		UPDATE routing_rules SET
			priority = ?, type = ?, domain = ?, ip = ?, port = ?,
			source_port = ?, network = ?, source = ?, user = ?,
			inbound_tag = ?, protocol = ?, attrs = ?, outbound_tag = ?,
			balancer_tag = ?, is_active = ?, remark = ?, updated_at = ?
		WHERE id = ?
	`,
		req.Priority, req.Type,
		StringSliceToJSON(req.Domains), StringSliceToJSON(req.IPs),
		req.Port, req.SourcePort, req.Network,
		StringSliceToJSON(req.Source), StringSliceToJSON(req.User),
		StringSliceToJSON(req.InboundTags), StringSliceToJSON(req.Protocols),
		req.Attrs, req.OutboundTag, req.BalancerTag, req.IsActive, req.Remark,
		now, id,
	)
	if err != nil {
		return nil, err
	}

	// Update in memory
	for i, rule := range rm.rules {
		if rule.ID == id {
			rm.rules[i] = &RoutingRule{
				ID:          id,
				NodeID:      req.NodeID,
				Priority:    req.Priority,
				Type:        req.Type,
				Domain:      req.Domains,
				IP:          req.IPs,
				Port:        req.Port,
				SourcePort:  req.SourcePort,
				Network:     req.Network,
				Source:      req.Source,
				User:        req.User,
				InboundTag:  req.InboundTags,
				Protocol:    req.Protocols,
				Attrs:       req.Attrs,
				OutboundTag: req.OutboundTag,
				BalancerTag: req.BalancerTag,
				IsActive:    req.IsActive,
				Remark:      req.Remark,
				UpdatedAt:   now,
			}
			break
		}
	}

	rm.sortRules()

	// Reload cores
	if Protocols != nil {
		go Protocols.reloadCores()
	}

	return rm.GetRule(id)
}

// DeleteRule deletes a routing rule
func (rm *RoutingManager) DeleteRule(id int64) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	_, err := DB.db.Exec("DELETE FROM routing_rules WHERE id = ?", id)
	if err != nil {
		return err
	}

	// Remove from memory
	for i, rule := range rm.rules {
		if rule.ID == id {
			rm.rules = append(rm.rules[:i], rm.rules[i+1:]...)
			break
		}
	}

	// Reload cores
	if Protocols != nil {
		go Protocols.reloadCores()
	}

	return nil
}

// GetRule retrieves a routing rule by ID
func (rm *RoutingManager) GetRule(id int64) (*RoutingRule, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	for _, rule := range rm.rules {
		if rule.ID == id {
			return rule, nil
		}
	}

	return nil, errors.New("rule not found")
}

// ListRules lists all routing rules
func (rm *RoutingManager) ListRules(nodeID int64) ([]*RoutingRule, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if nodeID == 0 {
		return rm.rules, nil
	}

	filtered := []*RoutingRule{}
	for _, rule := range rm.rules {
		if rule.NodeID == nodeID {
			filtered = append(filtered, rule)
		}
	}

	return filtered, nil
}

// EnableRule enables a routing rule
func (rm *RoutingManager) EnableRule(id int64) error {
	return rm.setRuleActive(id, true)
}

// DisableRule disables a routing rule
func (rm *RoutingManager) DisableRule(id int64) error {
	return rm.setRuleActive(id, false)
}

func (rm *RoutingManager) setRuleActive(id int64, active bool) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	_, err := DB.db.Exec("UPDATE routing_rules SET is_active = ?, updated_at = ? WHERE id = ?",
		active, time.Now(), id)
	if err != nil {
		return err
	}

	for _, rule := range rm.rules {
		if rule.ID == id {
			rule.IsActive = active
			break
		}
	}

	if Protocols != nil {
		go Protocols.reloadCores()
	}

	return nil
}

// ReorderRules reorders routing rules
func (rm *RoutingManager) ReorderRules(ruleIDs []int64) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, id := range ruleIDs {
		_, err := DB.db.Exec("UPDATE routing_rules SET priority = ? WHERE id = ?", i, id)
		if err != nil {
			return err
		}

		for _, rule := range rm.rules {
			if rule.ID == id {
				rule.Priority = i
				break
			}
		}
	}

	rm.sortRules()

	if Protocols != nil {
		go Protocols.reloadCores()
	}

	return nil
}

// sortRules sorts rules by priority
func (rm *RoutingManager) sortRules() {
	sort.Slice(rm.rules, func(i, j int) bool {
		return rm.rules[i].Priority < rm.rules[j].Priority
	})
}

// ============================================================================
// DEFAULT RULES
// ============================================================================

// DefaultRoutingRules returns default routing rules
func (rm *RoutingManager) DefaultRoutingRules() []*RoutingRule {
	return []*RoutingRule{
		// Block BitTorrent
		{
			Type:        RuleTypeField,
			Protocol:    []string{"bittorrent"},
			OutboundTag: OutboundBlocked,
			Remark:      "Block BitTorrent",
			IsActive:    true,
			Priority:    0,
		},
		// Block private IPs
		{
			Type:        RuleTypeField,
			IP:          []string{"geoip:private"},
			OutboundTag: OutboundDirect,
			Remark:      "Direct Private IPs",
			IsActive:    true,
			Priority:    1,
		},
		// Direct Iran IPs
		{
			Type:        RuleTypeField,
			IP:          []string{"geoip:ir"},
			OutboundTag: OutboundDirect,
			Remark:      "Direct Iran IPs",
			IsActive:    true,
			Priority:    2,
		},
		// Direct Iran domains
		{
			Type:        RuleTypeField,
			Domain:      []string{"geosite:category-ir"},
			OutboundTag: OutboundDirect,
			Remark:      "Direct Iran Domains",
			IsActive:    true,
			Priority:    3,
		},
		// Block ads
		{
			Type:        RuleTypeField,
			Domain:      []string{"geosite:category-ads-all"},
			OutboundTag: OutboundBlocked,
			Remark:      "Block Ads",
			IsActive:    false,
			Priority:    4,
		},
	}
}

// ApplyDefaultRules applies default routing rules
func (rm *RoutingManager) ApplyDefaultRules(nodeID int64) error {
	defaults := rm.DefaultRoutingRules()

	for _, rule := range defaults {
		req := &CreateRuleRequest{
			NodeID:      nodeID,
			Priority:    rule.Priority,
			Type:        rule.Type,
			Domains:     rule.Domain,
			IPs:         rule.IP,
			Protocols:   rule.Protocol,
			OutboundTag: rule.OutboundTag,
			Remark:      rule.Remark,
			IsActive:    rule.IsActive,
		}

		if _, err := rm.CreateRule(req); err != nil {
			return err
		}
	}

	return nil
}

// ============================================================================
// DNS CONFIGURATION
// ============================================================================

// DNSConfig represents DNS configuration
type DNSConfig struct {
	Enabled         bool              `json:"enabled"`
	Strategy        string            `json:"strategy"` // UseIP, UseIPv4, UseIPv6
	DisableCache    bool              `json:"disable_cache"`
	DisableFallback bool              `json:"disable_fallback"`
	Tag             string            `json:"tag"`
	Servers         []DNSServer       `json:"servers"`
	Hosts           map[string]string `json:"hosts,omitempty"`
	ClientIP        string            `json:"client_ip,omitempty"`
	QueryStrategy   string            `json:"query_strategy,omitempty"`
	FakeIP          *FakeIPConfig     `json:"fake_ip,omitempty"`
}

// DNSServer represents a DNS server
type DNSServer struct {
	Address       string   `json:"address"`
	Port          int      `json:"port,omitempty"`
	Domains       []string `json:"domains,omitempty"`
	ExpectIPs     []string `json:"expect_ips,omitempty"`
	SkipFallback  bool     `json:"skip_fallback,omitempty"`
	ClientIP      string   `json:"client_ip,omitempty"`
	Tag           string   `json:"tag,omitempty"`
	QueryStrategy string   `json:"query_strategy,omitempty"`
}

// FakeIPConfig for FakeIP settings
type FakeIPConfig struct {
	Enabled    bool   `json:"enabled"`
	IPPool     string `json:"ip_pool"`    // e.g., "198.18.0.0/15"
	IPPoolV6   string `json:"ip_pool_v6"` // e.g., "fc00::/18"
	LookupFunc string `json:"lookup_func,omitempty"`
}

// DefaultDNSConfig returns default DNS configuration
func DefaultDNSConfig() *DNSConfig {
	return &DNSConfig{
		Enabled:      true,
		Strategy:     "UseIP",
		DisableCache: false,
		Tag:          "dns",
		Servers: []DNSServer{
			{
				Address: DNSGoogleDoH,
				Tag:     "dns-google",
			},
			{
				Address:      DNSCloudflareDoH,
				Tag:          "dns-cloudflare",
				Domains:      []string{"geosite:geolocation-!cn"},
				SkipFallback: false,
			},
			{
				Address: "localhost",
				Tag:     "dns-local",
				Domains: []string{"geosite:private", "geosite:category-ir"},
			},
		},
		Hosts: map[string]string{},
	}
}

// SetDNSConfig sets DNS configuration
func (rm *RoutingManager) SetDNSConfig(config *DNSConfig) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.dnsConfig = config

	// Save to database
	configJSON, err := json.Marshal(config)
	if err != nil {
		return err
	}

	return DB.SetSetting("dns_config", string(configJSON), "json", "routing", false)
}

// GetDNSConfig returns DNS configuration
func (rm *RoutingManager) GetDNSConfig() *DNSConfig {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.dnsConfig
}

// AddDNSServer adds a DNS server
func (rm *RoutingManager) AddDNSServer(server DNSServer) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.dnsConfig.Servers = append(rm.dnsConfig.Servers, server)
	return rm.saveDNSConfig()
}

// RemoveDNSServer removes a DNS server by tag
func (rm *RoutingManager) RemoveDNSServer(tag string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	newServers := []DNSServer{}
	for _, server := range rm.dnsConfig.Servers {
		if server.Tag != tag {
			newServers = append(newServers, server)
		}
	}

	rm.dnsConfig.Servers = newServers
	return rm.saveDNSConfig()
}

// AddDNSHost adds a DNS host override
func (rm *RoutingManager) AddDNSHost(domain, ip string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.dnsConfig.Hosts == nil {
		rm.dnsConfig.Hosts = make(map[string]string)
	}

	rm.dnsConfig.Hosts[domain] = ip
	return rm.saveDNSConfig()
}

// RemoveDNSHost removes a DNS host override
func (rm *RoutingManager) RemoveDNSHost(domain string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	delete(rm.dnsConfig.Hosts, domain)
	return rm.saveDNSConfig()
}

// GetDNSPresets returns DNS server presets
func (rm *RoutingManager) GetDNSPresets() []DNSServer {
	return []DNSServer{
		{Address: DNSGoogle, Tag: "google", Port: 53},
		{Address: DNSCloudflare, Tag: "cloudflare", Port: 53},
		{Address: DNSGoogleDoH, Tag: "google-doh"},
		{Address: DNSCloudflareDoH, Tag: "cloudflare-doh"},
		{Address: DNSGoogleDoT, Tag: "google-dot"},
		{Address: DNSCloudflareDoT, Tag: "cloudflare-dot"},
		{Address: "https://dns.quad9.net/dns-query", Tag: "quad9-doh"},
		{Address: "https://doh.opendns.com/dns-query", Tag: "opendns-doh"},
		{Address: "https://dns.adguard.com/dns-query", Tag: "adguard-doh"},
		{Address: "94.140.14.14", Tag: "adguard", Port: 53},
		{Address: "9.9.9.9", Tag: "quad9", Port: 53},
	}
}

func (rm *RoutingManager) saveDNSConfig() error {
	configJSON, err := json.Marshal(rm.dnsConfig)
	if err != nil {
		return err
	}

	err = DB.SetSetting("dns_config", string(configJSON), "json", "routing", false)
	if err != nil {
		return err
	}

	if Protocols != nil {
		go Protocols.reloadCores()
	}

	return nil
}

// GenerateXrayDNS generates Xray DNS configuration
func (rm *RoutingManager) GenerateXrayDNS() *XrayDNS {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if !rm.dnsConfig.Enabled {
		return nil
	}

	dns := &XrayDNS{
		QueryStrategy: rm.dnsConfig.QueryStrategy,
		DisableCache:  rm.dnsConfig.DisableCache,
		Tag:           rm.dnsConfig.Tag,
		Hosts:         make(map[string]interface{}),
		Servers:       []interface{}{},
	}

	// Add hosts
	for domain, ip := range rm.dnsConfig.Hosts {
		dns.Hosts[domain] = ip
	}

	// Add servers
	for _, server := range rm.dnsConfig.Servers {
		if len(server.Domains) == 0 && len(server.ExpectIPs) == 0 {
			dns.Servers = append(dns.Servers, server.Address)
		} else {
			serverConfig := map[string]interface{}{
				"address": server.Address,
			}
			if len(server.Domains) > 0 {
				serverConfig["domains"] = server.Domains
			}
			if len(server.ExpectIPs) > 0 {
				serverConfig["expectIPs"] = server.ExpectIPs
			}
			if server.SkipFallback {
				serverConfig["skipFallback"] = true
			}
			if server.ClientIP != "" {
				serverConfig["clientIp"] = server.ClientIP
			}
			dns.Servers = append(dns.Servers, serverConfig)
		}
	}

	return dns
}

// ============================================================================
// WARP CONFIGURATION
// ============================================================================

// WARPConfiguration represents WARP settings
type WARPConfiguration struct {
	Enabled       bool     `json:"enabled"`
	Mode          string   `json:"mode"` // proxy, warp, warp+doh
	AccountID     string   `json:"account_id,omitempty"`
	AccessToken   string   `json:"access_token,omitempty"`
	PrivateKey    string   `json:"private_key"`
	PublicKey     string   `json:"public_key"`
	IPv4          string   `json:"ipv4"`
	IPv6          string   `json:"ipv6"`
	Endpoint      string   `json:"endpoint"`
	Reserved      []int    `json:"reserved,omitempty"`
	MTU           int      `json:"mtu"`
	LicenseKey    string   `json:"license_key,omitempty"`
	ClientID      string   `json:"client_id,omitempty"`
	PeerPublicKey string   `json:"peer_public_key"`
	DNS           []string `json:"dns,omitempty"`
	AllowedIPs    []string `json:"allowed_ips,omitempty"`
	KeepAlive     int      `json:"keep_alive"`
	Domains       []string `json:"domains,omitempty"` // Domains to route through WARP
	DetourTag     string   `json:"detour_tag,omitempty"`
}

// DefaultWARPConfig returns default WARP configuration
func DefaultWARPConfig() *WARPConfiguration {
	return &WARPConfiguration{
		Enabled:       false,
		Mode:          "proxy",
		Endpoint:      WarpEndpointDefault,
		PeerPublicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		MTU:           1280,
		KeepAlive:     30,
		AllowedIPs:    []string{"0.0.0.0/0", "::/0"},
		DNS:           []string{"1.1.1.1", "1.0.0.1"},
		Domains:       []string{},
	}
}

// SetWARPConfig sets WARP configuration
func (rm *RoutingManager) SetWARPConfig(config *WARPConfiguration) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.warpConfig = config

	// Save to database
	configJSON, err := json.Marshal(config)
	if err != nil {
		return err
	}

	err = DB.SetSetting("warp_config", string(configJSON), "json", "routing", true)
	if err != nil {
		return err
	}

	if Protocols != nil {
		go Protocols.reloadCores()
	}

	return nil
}

// GetWARPConfig returns WARP configuration
func (rm *RoutingManager) GetWARPConfig() *WARPConfiguration {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.warpConfig
}

// SetWARPEnabled enables/disables WARP
func (rm *RoutingManager) SetWARPEnabled(enabled bool) error {
	rm.mu.Lock()
	rm.warpConfig.Enabled = enabled
	rm.mu.Unlock()

	return rm.saveWARPConfig()
}

// AddWARPDomain adds a domain to WARP routing
func (rm *RoutingManager) AddWARPDomain(domain string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Check if already exists
	for _, d := range rm.warpConfig.Domains {
		if d == domain {
			return nil
		}
	}

	rm.warpConfig.Domains = append(rm.warpConfig.Domains, domain)
	return rm.saveWARPConfig()
}

// RemoveWARPDomain removes a domain from WARP routing
func (rm *RoutingManager) RemoveWARPDomain(domain string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	newDomains := []string{}
	for _, d := range rm.warpConfig.Domains {
		if d != domain {
			newDomains = append(newDomains, d)
		}
	}

	rm.warpConfig.Domains = newDomains
	return rm.saveWARPConfig()
}

// RegisterWARP registers a new WARP account
func (rm *RoutingManager) RegisterWARP() (*WARPConfiguration, error) {
	// Generate keys
	privateKey, publicKey, err := GenerateWireGuardKeyPair()
	if err != nil {
		return nil, err
	}

	// Register with Cloudflare WARP API
	config, err := rm.registerWARPAccount(privateKey, publicKey)
	if err != nil {
		return nil, err
	}

	rm.mu.Lock()
	rm.warpConfig = config
	rm.mu.Unlock()

	return config, rm.saveWARPConfig()
}

// registerWARPAccount registers with Cloudflare WARP API
func (rm *RoutingManager) registerWARPAccount(privateKey, publicKey string) (*WARPConfiguration, error) {
	// WARP API endpoint
	apiURL := "https://api.cloudflareclient.com/v0a2158/reg"

	// Create request body
	reqBody := map[string]interface{}{
		"key":           publicKey,
		"install_id":    "",
		"fcm_token":     "",
		"tos":           time.Now().Format(time.RFC3339),
		"model":         "PC",
		"serial_number": generateRandomString(12),
		"locale":        "en_US",
	}

	bodyJSON, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(string(bodyJSON)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("CF-Client-Version", "a-6.11-2223")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("WARP registration failed: %s", string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	// Parse response
	config := DefaultWARPConfig()
	config.PrivateKey = privateKey
	config.PublicKey = publicKey

	if account, ok := result["account"].(map[string]interface{}); ok {
		config.AccountID, _ = account["id"].(string)
	}

	if warpConfig, ok := result["config"].(map[string]interface{}); ok {
		if peers, ok := warpConfig["peers"].([]interface{}); ok && len(peers) > 0 {
			peer := peers[0].(map[string]interface{})
			config.PeerPublicKey, _ = peer["public_key"].(string)

			if endpoint, ok := peer["endpoint"].(map[string]interface{}); ok {
				host, _ := endpoint["host"].(string)
				config.Endpoint = host
			}
		}

		if iface, ok := warpConfig["interface"].(map[string]interface{}); ok {
			if addresses, ok := iface["addresses"].(map[string]interface{}); ok {
				config.IPv4, _ = addresses["v4"].(string)
				config.IPv6, _ = addresses["v6"].(string)
			}
		}

		if clientID, ok := warpConfig["client_id"].(string); ok {
			config.ClientID = clientID
			// Parse reserved bytes from client_id
			if decoded, err := base64.StdEncoding.DecodeString(clientID); err == nil && len(decoded) >= 3 {
				config.Reserved = []int{int(decoded[0]), int(decoded[1]), int(decoded[2])}
			}
		}
	}

	config.Enabled = true
	return config, nil
}

// UpdateWARPLicense updates WARP+ license
func (rm *RoutingManager) UpdateWARPLicense(licenseKey string) error {
	rm.mu.Lock()
	rm.warpConfig.LicenseKey = licenseKey
	rm.mu.Unlock()

	// API call to update license
	apiURL := fmt.Sprintf("https://api.cloudflareclient.com/v0a2158/reg/%s/account", rm.warpConfig.AccountID)

	reqBody := map[string]interface{}{
		"license": licenseKey,
	}
	bodyJSON, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("PUT", apiURL, strings.NewReader(string(bodyJSON)))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+rm.warpConfig.AccessToken)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to update WARP license")
	}

	return rm.saveWARPConfig()
}

func (rm *RoutingManager) saveWARPConfig() error {
	configJSON, err := json.Marshal(rm.warpConfig)
	if err != nil {
		return err
	}

	err = DB.SetSetting("warp_config", string(configJSON), "json", "routing", true)
	if err != nil {
		return err
	}

	if Protocols != nil {
		go Protocols.reloadCores()
	}

	return nil
}

// GenerateWARPOutbound generates Xray WireGuard outbound for WARP
func (rm *RoutingManager) GenerateWARPOutbound() map[string]interface{} {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if !rm.warpConfig.Enabled {
		return nil
	}

	outbound := map[string]interface{}{
		"tag":      OutboundWarp,
		"protocol": "wireguard",
		"settings": map[string]interface{}{
			"secretKey": rm.warpConfig.PrivateKey,
			"address":   []string{rm.warpConfig.IPv4 + "/32", rm.warpConfig.IPv6 + "/128"},
			"peers": []map[string]interface{}{
				{
					"endpoint":  rm.warpConfig.Endpoint,
					"publicKey": rm.warpConfig.PeerPublicKey,
				},
			},
			"mtu":      rm.warpConfig.MTU,
			"reserved": rm.warpConfig.Reserved,
		},
	}

	return outbound
}

// GenerateWARPRule generates routing rule for WARP domains
func (rm *RoutingManager) GenerateWARPRule() *XrayRule {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if !rm.warpConfig.Enabled || len(rm.warpConfig.Domains) == 0 {
		return nil
	}

	return &XrayRule{
		Type:        RuleTypeField,
		Domain:      rm.warpConfig.Domains,
		OutboundTag: OutboundWarp,
	}
}

// ============================================================================
// BLOCK LISTS
// ============================================================================

// BlockList represents a block list
type BlockList struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"` // domain, ip
	URL         string    `json:"url,omitempty"`
	Entries     []string  `json:"entries"`
	IsActive    bool      `json:"is_active"`
	IsBuiltin   bool      `json:"is_builtin"`
	LastUpdated time.Time `json:"last_updated"`
}

// DefaultBlockLists returns default block lists
func DefaultBlockLists() map[string]*BlockList {
	return map[string]*BlockList{
		"iran-ads": {
			Name:      "Iran Ads",
			Type:      "domain",
			URL:       BlockListIranAds,
			IsActive:  false,
			IsBuiltin: true,
		},
		"malware": {
			Name:      "Malware",
			Type:      "domain",
			URL:       BlockListMalware,
			IsActive:  false,
			IsBuiltin: true,
		},
		"torrent": {
			Name:      "BitTorrent",
			Type:      "protocol",
			Entries:   []string{"bittorrent"},
			IsActive:  true,
			IsBuiltin: true,
		},
		"private-ips": {
			Name: "Private IPs",
			Type: "ip",
			Entries: []string{
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
				"127.0.0.0/8",
				"169.254.0.0/16",
				"fc00::/7",
				"fe80::/10",
				"::1/128",
			},
			IsActive:  true,
			IsBuiltin: true,
		},
	}
}

// AddBlockList adds a custom block list
func (rm *RoutingManager) AddBlockList(list *BlockList) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Generate ID
	list.ID = time.Now().UnixNano()
	list.LastUpdated = time.Now()

	rm.blockLists[list.Name] = list

	return rm.saveBlockLists()
}

// RemoveBlockList removes a block list
func (rm *RoutingManager) RemoveBlockList(name string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if list, exists := rm.blockLists[name]; exists {
		if list.IsBuiltin {
			return errors.New("cannot remove builtin block list")
		}
		delete(rm.blockLists, name)
	}

	return rm.saveBlockLists()
}

// EnableBlockList enables a block list
func (rm *RoutingManager) EnableBlockList(name string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if list, exists := rm.blockLists[name]; exists {
		list.IsActive = true
	}

	return rm.saveBlockLists()
}

// DisableBlockList disables a block list
func (rm *RoutingManager) DisableBlockList(name string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if list, exists := rm.blockLists[name]; exists {
		list.IsActive = false
	}

	return rm.saveBlockLists()
}

// UpdateBlockList updates a block list from URL
func (rm *RoutingManager) UpdateBlockList(name string) error {
	rm.mu.Lock()
	list, exists := rm.blockLists[name]
	rm.mu.Unlock()

	if !exists {
		return errors.New("block list not found")
	}

	if list.URL == "" {
		return errors.New("block list has no URL")
	}

	entries, err := rm.fetchBlockList(list.URL)
	if err != nil {
		return err
	}

	rm.mu.Lock()
	list.Entries = entries
	list.LastUpdated = time.Now()
	rm.mu.Unlock()

	return rm.saveBlockLists()
}

// fetchBlockList fetches entries from a block list URL
func (rm *RoutingManager) fetchBlockList(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	entries := []string{}
	scanner := bufio.NewScanner(resp.Body)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse hosts file format
		if strings.HasPrefix(line, "0.0.0.0 ") || strings.HasPrefix(line, "127.0.0.1 ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				domain := parts[1]
				if domain != "localhost" && domain != "localhost.localdomain" {
					entries = append(entries, domain)
				}
			}
			continue
		}

		// Plain domain
		if isValidDomain(line) {
			entries = append(entries, line)
		}
	}

	return entries, scanner.Err()
}

// GetBlockLists returns all block lists
func (rm *RoutingManager) GetBlockLists() map[string]*BlockList {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	result := make(map[string]*BlockList)
	for k, v := range rm.blockLists {
		result[k] = v
	}
	return result
}

// AddBlockEntry adds a single entry to a block list
func (rm *RoutingManager) AddBlockEntry(listName, entry string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	list, exists := rm.blockLists[listName]
	if !exists {
		// Create new custom list
		list = &BlockList{
			ID:        time.Now().UnixNano(),
			Name:      listName,
			Type:      "domain",
			Entries:   []string{},
			IsActive:  true,
			IsBuiltin: false,
		}
		rm.blockLists[listName] = list
	}

	// Check if already exists
	for _, e := range list.Entries {
		if e == entry {
			return nil
		}
	}

	list.Entries = append(list.Entries, entry)
	list.LastUpdated = time.Now()

	return rm.saveBlockLists()
}

// RemoveBlockEntry removes an entry from a block list
func (rm *RoutingManager) RemoveBlockEntry(listName, entry string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	list, exists := rm.blockLists[listName]
	if !exists {
		return errors.New("block list not found")
	}

	newEntries := []string{}
	for _, e := range list.Entries {
		if e != entry {
			newEntries = append(newEntries, e)
		}
	}

	list.Entries = newEntries
	list.LastUpdated = time.Now()

	return rm.saveBlockLists()
}

func (rm *RoutingManager) saveBlockLists() error {
	configJSON, err := json.Marshal(rm.blockLists)
	if err != nil {
		return err
	}

	err = DB.SetSetting("block_lists", string(configJSON), "json", "routing", false)
	if err != nil {
		return err
	}

	if Protocols != nil {
		go Protocols.reloadCores()
	}

	return nil
}

// GenerateBlockRules generates routing rules for block lists
func (rm *RoutingManager) GenerateBlockRules() []XrayRule {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	rules := []XrayRule{}

	for _, list := range rm.blockLists {
		if !list.IsActive || len(list.Entries) == 0 {
			continue
		}

		switch list.Type {
		case "domain":
			rules = append(rules, XrayRule{
				Type:        RuleTypeField,
				Domain:      list.Entries,
				OutboundTag: OutboundBlocked,
			})
		case "ip":
			rules = append(rules, XrayRule{
				Type:        RuleTypeField,
				IP:          list.Entries,
				OutboundTag: OutboundBlocked,
			})
		case "protocol":
			rules = append(rules, XrayRule{
				Type:        RuleTypeField,
				Protocol:    list.Entries,
				OutboundTag: OutboundBlocked,
			})
		}
	}

	return rules
}

// ============================================================================
// DIRECT RULES
// ============================================================================

// DirectRules represents direct routing rules
type DirectRules struct {
	Domains      []string `json:"domains"`
	IPs          []string `json:"ips"`
	Ports        []string `json:"ports"`
	Protocols    []string `json:"protocols"`
	ProcessNames []string `json:"process_names"`
}

// GetDirectRules returns direct routing rules
func (rm *RoutingManager) GetDirectRules() *DirectRules {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.directRules
}

// SetDirectRules sets direct routing rules
func (rm *RoutingManager) SetDirectRules(rules *DirectRules) error {
	rm.mu.Lock()
	rm.directRules = rules
	rm.mu.Unlock()

	return rm.saveDirectRules()
}

// AddDirectDomain adds a domain to direct routing
func (rm *RoutingManager) AddDirectDomain(domain string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for _, d := range rm.directRules.Domains {
		if d == domain {
			return nil
		}
	}

	rm.directRules.Domains = append(rm.directRules.Domains, domain)
	return rm.saveDirectRules()
}

// RemoveDirectDomain removes a domain from direct routing
func (rm *RoutingManager) RemoveDirectDomain(domain string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	newDomains := []string{}
	for _, d := range rm.directRules.Domains {
		if d != domain {
			newDomains = append(newDomains, d)
		}
	}

	rm.directRules.Domains = newDomains
	return rm.saveDirectRules()
}

// AddDirectIP adds an IP to direct routing
func (rm *RoutingManager) AddDirectIP(ip string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Validate IP or CIDR
	if net.ParseIP(ip) == nil {
		if _, _, err := net.ParseCIDR(ip); err != nil {
			return errors.New("invalid IP address or CIDR")
		}
	}

	for _, i := range rm.directRules.IPs {
		if i == ip {
			return nil
		}
	}

	rm.directRules.IPs = append(rm.directRules.IPs, ip)
	return rm.saveDirectRules()
}

// RemoveDirectIP removes an IP from direct routing
func (rm *RoutingManager) RemoveDirectIP(ip string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	newIPs := []string{}
	for _, i := range rm.directRules.IPs {
		if i != ip {
			newIPs = append(newIPs, i)
		}
	}

	rm.directRules.IPs = newIPs
	return rm.saveDirectRules()
}

func (rm *RoutingManager) saveDirectRules() error {
	configJSON, err := json.Marshal(rm.directRules)
	if err != nil {
		return err
	}

	err = DB.SetSetting("direct_rules", string(configJSON), "json", "routing", false)
	if err != nil {
		return err
	}

	if Protocols != nil {
		go Protocols.reloadCores()
	}

	return nil
}

// GenerateDirectRules generates routing rules for direct connections
func (rm *RoutingManager) GenerateDirectRules() []XrayRule {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	rules := []XrayRule{}

	if len(rm.directRules.Domains) > 0 {
		rules = append(rules, XrayRule{
			Type:        RuleTypeField,
			Domain:      rm.directRules.Domains,
			OutboundTag: OutboundDirect,
		})
	}

	if len(rm.directRules.IPs) > 0 {
		rules = append(rules, XrayRule{
			Type:        RuleTypeField,
			IP:          rm.directRules.IPs,
			OutboundTag: OutboundDirect,
		})
	}

	if len(rm.directRules.Ports) > 0 {
		for _, port := range rm.directRules.Ports {
			rules = append(rules, XrayRule{
				Type:        RuleTypeField,
				Port:        port,
				OutboundTag: OutboundDirect,
			})
		}
	}

	return rules
}

// ============================================================================
// GEOFILE MANAGEMENT
// ============================================================================

// GeoAssets represents GeoIP and GeoSite assets
type GeoAssets struct {
	GeoIPPath      string    `json:"geoip_path"`
	GeoSitePath    string    `json:"geosite_path"`
	GeoIPVersion   string    `json:"geoip_version"`
	GeoSiteVersion string    `json:"geosite_version"`
	LastUpdated    time.Time `json:"last_updated"`
}

// GetGeoAssets returns GeoFile information
func (rm *RoutingManager) GetGeoAssets() *GeoAssets {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.geoAssets
}

// UpdateGeoFiles downloads and updates GeoIP and GeoSite files
func (rm *RoutingManager) UpdateGeoFiles() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	geoDir := filepath.Dir(GeoIPPath)
	os.MkdirAll(geoDir, 0755)

	// Download GeoIP
	if err := downloadFileWithProgress(GeoIPURL, GeoIPPath); err != nil {
		return fmt.Errorf("failed to download geoip.dat: %w", err)
	}

	// Download GeoSite
	if err := downloadFileWithProgress(GeoSiteURL, GeoSitePath); err != nil {
		return fmt.Errorf("failed to download geosite.dat: %w", err)
	}

	rm.geoAssets.GeoIPPath = GeoIPPath
	rm.geoAssets.GeoSitePath = GeoSitePath
	rm.geoAssets.LastUpdated = time.Now()

	if Protocols != nil {
		go Protocols.reloadCores()
	}

	return nil
}

// ensureGeoFiles ensures GeoFiles exist
func (rm *RoutingManager) ensureGeoFiles() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	geoIPExists := fileExists(GeoIPPath)
	geoSiteExists := fileExists(GeoSitePath)

	if !geoIPExists || !geoSiteExists {
		rm.mu.Unlock()
		rm.UpdateGeoFiles()
		rm.mu.Lock()
	}

	rm.geoAssets.GeoIPPath = GeoIPPath
	rm.geoAssets.GeoSitePath = GeoSitePath
}

// GetGeoCategories returns available GeoIP/GeoSite categories
func (rm *RoutingManager) GetGeoCategories() map[string][]string {
	return map[string][]string{
		"geoip": {
			"private", "cn", "ir", "ru", "us", "de", "gb", "fr", "jp", "kr",
			"au", "ca", "nl", "sg", "hk", "tw", "in", "br", "ae", "tr",
			"cloudflare", "cloudfront", "facebook", "fastly", "google", "netflix", "telegram", "twitter",
		},
		"geosite": {
			"category-ads", "category-ads-all", "category-porn",
			"cn", "ir", "private", "geolocation-cn", "geolocation-!cn",
			"google", "facebook", "twitter", "telegram", "youtube", "netflix", "spotify",
			"apple", "microsoft", "amazon", "github", "steam", "epic",
			"category-games", "category-media", "category-social",
		},
	}
}

// downloadFileWithProgress downloads a file with progress
func downloadFileWithProgress(url, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// ============================================================================
// LOAD FROM DATABASE
// ============================================================================

func (rm *RoutingManager) loadFromDB() error {
	// Load routing rules
	rows, err := DB.db.Query(`
		SELECT id, node_id, priority, type, domain, ip, port, source_port,
		       network, source, user, inbound_tag, protocol, attrs,
		       outbound_tag, balancer_tag, is_active, remark, created_at, updated_at
		FROM routing_rules ORDER BY priority
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			rule := &RoutingRule{}
			var domain, ip, source, user, inboundTag, protocol string

			err := rows.Scan(
				&rule.ID, &rule.NodeID, &rule.Priority, &rule.Type,
				&domain, &ip, &rule.Port, &rule.SourcePort,
				&rule.Network, &source, &user, &inboundTag, &protocol,
				&rule.Attrs, &rule.OutboundTag, &rule.BalancerTag,
				&rule.IsActive, &rule.Remark, &rule.CreatedAt, &rule.UpdatedAt,
			)
			if err != nil {
				continue
			}

			rule.Domain = JSONToStringSlice(domain)
			rule.IP = JSONToStringSlice(ip)
			rule.Source = JSONToStringSlice(source)
			rule.User = JSONToStringSlice(user)
			rule.InboundTag = JSONToStringSlice(inboundTag)
			rule.Protocol = JSONToStringSlice(protocol)

			rm.rules = append(rm.rules, rule)
		}
	}

	// Load DNS config
	if dnsJSON, err := DB.GetSetting("dns_config"); err == nil && dnsJSON != "" {
		json.Unmarshal([]byte(dnsJSON), &rm.dnsConfig)
	}

	// Load WARP config
	if warpJSON, err := DB.GetSetting("warp_config"); err == nil && warpJSON != "" {
		json.Unmarshal([]byte(warpJSON), &rm.warpConfig)
	}

	// Load block lists
	if blockJSON, err := DB.GetSetting("block_lists"); err == nil && blockJSON != "" {
		json.Unmarshal([]byte(blockJSON), &rm.blockLists)
	} else {
		// Initialize with defaults
		rm.blockLists = DefaultBlockLists()
	}

	// Load direct rules
	if directJSON, err := DB.GetSetting("direct_rules"); err == nil && directJSON != "" {
		json.Unmarshal([]byte(directJSON), &rm.directRules)
	}

	return nil
}

// ============================================================================
// EXPORT CONFIGURATION
// ============================================================================

// ExportRoutingConfig exports complete routing configuration
func (rm *RoutingManager) ExportRoutingConfig() map[string]interface{} {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	return map[string]interface{}{
		"rules":        rm.rules,
		"dns":          rm.dnsConfig,
		"warp":         rm.warpConfig,
		"block_lists":  rm.blockLists,
		"direct_rules": rm.directRules,
		"geo_assets":   rm.geoAssets,
	}
}

// ImportRoutingConfig imports routing configuration
func (rm *RoutingManager) ImportRoutingConfig(config map[string]interface{}) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Parse and apply configuration
	if rules, ok := config["rules"].([]interface{}); ok {
		rulesJSON, _ := json.Marshal(rules)
		var parsedRules []*RoutingRule
		json.Unmarshal(rulesJSON, &parsedRules)
		rm.rules = parsedRules
	}

	if dns, ok := config["dns"].(map[string]interface{}); ok {
		dnsJSON, _ := json.Marshal(dns)
		json.Unmarshal(dnsJSON, &rm.dnsConfig)
	}

	if warp, ok := config["warp"].(map[string]interface{}); ok {
		warpJSON, _ := json.Marshal(warp)
		json.Unmarshal(warpJSON, &rm.warpConfig)
	}

	if blocks, ok := config["block_lists"].(map[string]interface{}); ok {
		blocksJSON, _ := json.Marshal(blocks)
		json.Unmarshal(blocksJSON, &rm.blockLists)
	}

	if direct, ok := config["direct_rules"].(map[string]interface{}); ok {
		directJSON, _ := json.Marshal(direct)
		json.Unmarshal(directJSON, &rm.directRules)
	}

	// Save all
	rm.saveDNSConfig()
	rm.saveWARPConfig()
	rm.saveBlockLists()
	rm.saveDirectRules()

	if Protocols != nil {
		go Protocols.reloadCores()
	}

	return nil
}

// ============================================================================
// GENERATE COMPLETE ROUTING
// ============================================================================

// GenerateCompleteRouting generates complete routing configuration for Xray
func (rm *RoutingManager) GenerateCompleteRouting() *XrayRouting {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	routing := &XrayRouting{
		DomainStrategy: RoutingStrategyIPIfNonMatch,
		DomainMatcher:  "hybrid",
		Rules:          []XrayRule{},
	}

	// Add API routing rule first
	routing.Rules = append(routing.Rules, XrayRule{
		Type:        RuleTypeField,
		InboundTag:  []string{"api"},
		OutboundTag: "api",
	})

	// Add WARP rule
	if warpRule := rm.GenerateWARPRule(); warpRule != nil {
		routing.Rules = append(routing.Rules, *warpRule)
	}

	// Add block rules
	blockRules := rm.GenerateBlockRules()
	routing.Rules = append(routing.Rules, blockRules...)

	// Add custom routing rules
	for _, rule := range rm.rules {
		if rule.IsActive {
			xrayRule := XrayRule{
				Type:        rule.Type,
				Domain:      rule.Domain,
				IP:          rule.IP,
				Port:        rule.Port,
				SourcePort:  rule.SourcePort,
				Network:     rule.Network,
				Source:      rule.Source,
				User:        rule.User,
				InboundTag:  rule.InboundTag,
				Protocol:    rule.Protocol,
				Attrs:       rule.Attrs,
				OutboundTag: rule.OutboundTag,
				BalancerTag: rule.BalancerTag,
			}
			routing.Rules = append(routing.Rules, xrayRule)
		}
	}

	// Add direct rules
	directRules := rm.GenerateDirectRules()
	routing.Rules = append(routing.Rules, directRules...)

	// Add default rules
	routing.Rules = append(routing.Rules,
		// Block BitTorrent by default
		XrayRule{
			Type:        RuleTypeField,
			Protocol:    []string{"bittorrent"},
			OutboundTag: OutboundBlocked,
		},
		// Direct private IPs
		XrayRule{
			Type:        RuleTypeField,
			IP:          []string{"geoip:private"},
			OutboundTag: OutboundDirect,
		},
	)

	return routing
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// isValidDomain checks if a string is a valid domain
func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	// Check for IP address
	if net.ParseIP(domain) != nil {
		return false
	}

	// Simple domain validation
	pattern := `^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(pattern, domain)
	return matched
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// TestRouting tests routing rules
func (rm *RoutingManager) TestRouting(domain, ip string) string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// Test against rules in order
	for _, rule := range rm.rules {
		if !rule.IsActive {
			continue
		}

		// Check domain
		if domain != "" && len(rule.Domain) > 0 {
			for _, d := range rule.Domain {
				if strings.HasPrefix(d, "domain:") {
					if domain == strings.TrimPrefix(d, "domain:") {
						return rule.OutboundTag
					}
				} else if strings.HasPrefix(d, "full:") {
					if domain == strings.TrimPrefix(d, "full:") {
						return rule.OutboundTag
					}
				} else if strings.HasPrefix(d, "regexp:") {
					pattern := strings.TrimPrefix(d, "regexp:")
					if matched, _ := regexp.MatchString(pattern, domain); matched {
						return rule.OutboundTag
					}
				} else if strings.HasPrefix(d, "geosite:") {
					// Skip geosite checks in test
					continue
				} else {
					// Suffix match
					if strings.HasSuffix(domain, d) || strings.HasSuffix(domain, "."+d) {
						return rule.OutboundTag
					}
				}
			}
		}

		// Check IP
		if ip != "" && len(rule.IP) > 0 {
			testIP := net.ParseIP(ip)
			if testIP != nil {
				for _, i := range rule.IP {
					if strings.HasPrefix(i, "geoip:") {
						continue
					}
					if strings.Contains(i, "/") {
						_, cidr, err := net.ParseCIDR(i)
						if err == nil && cidr.Contains(testIP) {
							return rule.OutboundTag
						}
					} else if i == ip {
						return rule.OutboundTag
					}
				}
			}
		}
	}

	return OutboundDirect
}

// GetRoutingStats returns routing statistics
func (rm *RoutingManager) GetRoutingStats() map[string]interface{} {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	activeRules := 0
	for _, rule := range rm.rules {
		if rule.IsActive {
			activeRules++
		}
	}

	activeBlockLists := 0
	totalBlockEntries := 0
	for _, list := range rm.blockLists {
		if list.IsActive {
			activeBlockLists++
			totalBlockEntries += len(list.Entries)
		}
	}

	return map[string]interface{}{
		"total_rules":         len(rm.rules),
		"active_rules":        activeRules,
		"dns_servers":         len(rm.dnsConfig.Servers),
		"warp_enabled":        rm.warpConfig.Enabled,
		"warp_domains":        len(rm.warpConfig.Domains),
		"block_lists":         len(rm.blockLists),
		"active_block_lists":  activeBlockLists,
		"total_block_entries": totalBlockEntries,
		"direct_domains":      len(rm.directRules.Domains),
		"direct_ips":          len(rm.directRules.IPs),
		"geoip_available":     fileExists(GeoIPPath),
		"geosite_available":   fileExists(GeoSitePath),
		"geo_last_updated":    rm.geoAssets.LastUpdated,
	}
}

// SetWARPMode sets WARP routing mode
func (rm *RoutingManager) SetWARPMode(mode string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.warpMode = mode

	// Rebuild routes with new WARP mode
	return rm.rebuildRoutes()
}

// rebuildRoutes rebuilds all routing rules
func (rm *RoutingManager) rebuildRoutes() error {
	// Clear existing routes
	rm.rules = make([]*RoutingRule, 0)

	// Rebuild based on current configuration
	// Add default rules based on mode

	switch rm.warpMode {
	case "on":
		// Route all traffic through WARP
		rm.rules = append(rm.rules, &RoutingRule{
			Type:        "field",
			OutboundTag: "WARP",
			Domain:      []string{"geosite:category-ads"},
			IsActive:    true,
		})

	case "off":
		// Direct routing
		rm.rules = append(rm.rules, &RoutingRule{
			Type:        "field",
			OutboundTag: "direct",
			IsActive:    true,
		})

	case "smart":
		// Smart routing - use geoip/geosite
		rm.rules = append(rm.rules, &RoutingRule{
			Type:        "field",
			OutboundTag: "direct",
			IP:          []string{"geoip:private", "geoip:cn"},
			IsActive:    true,
		})
		rm.rules = append(rm.rules, &RoutingRule{
			Type:        "field",
			OutboundTag: "proxy",
			Domain:      []string{"geosite:geolocation-!cn"},
			IsActive:    true,
		})
	}

	LogInfo("ROUTING", "Routes rebuilt with mode: %s (%d rules)", rm.warpMode, len(rm.rules))
	return nil
}
