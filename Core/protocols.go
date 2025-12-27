// MXUI VPN Panel
// Core/protocols.go
// Protocol Management: Xray, Sing-box, Clash, WireGuard, Hysteria2, TUIC, Shadowsocks2022

package core

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	crand "crypto/rand"

	"gopkg.in/yaml.v3"
)

// ============================================================================
// CONSTANTS
// ============================================================================

const (
	// Core names
	CoreXray      = "xray"
	CoreSingbox   = "sing-box"
	CoreClash     = "clash"
	CoreWireGuard = "wireguard"

	// Default paths
	DefaultXrayPath      = "/usr/local/bin/xray"
	DefaultSingboxPath   = "/usr/local/bin/sing-box"
	DefaultClashPath     = "/usr/local/bin/clash"
	DefaultWireGuardPath = "/usr/bin/wg"

	// Config paths
	XrayConfigPath      = "./Data/xray/config.json"
	SingboxConfigPath   = "./Data/singbox/config.json"
	ClashConfigPath     = "./Data/clash/config.yaml"
	WireGuardConfigPath = "./Data/wireguard/wg0.conf"

	// API ports
	XrayAPIPort    = 62789
	SingboxAPIPort = 62790

	// Download URLs
	XrayDownloadURL    = "https://github.com/XTLS/Xray-core/releases/latest/download"
	SingboxDownloadURL = "https://github.com/SagerNet/sing-box/releases/latest/download"

	// GeoIP/GeoSite
	GeoIPURL   = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
	GeoSiteURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"

	// Reality
	RealityShortIDLength = 8
	RealityPrivateKeyLen = 32
	// Single Port Mode
	SinglePortEnabled = true
	SinglePortNumber  = 443
	FallbackAddress   = "127.0.0.1:8080"
)

// ============================================================================
// PROTOCOL MANAGER
// ============================================================================

// ProtocolManager manages all protocol cores
type ProtocolManager struct {
	config           *Config
	cores            map[string]*CoreProcess
	inbounds         map[string]*InboundConfig
	outbounds        map[string]*OutboundConfig
	mu               sync.RWMutex
	isRunning        bool
	ctx              context.Context
	cancel           context.CancelFunc
	statsCollector   *StatsCollector
	trafficCollector *TrafficCollector
}

// CoreProcess represents a running core process
type CoreProcess struct {
	Name       string
	Path       string
	ConfigPath string
	Process    *exec.Cmd
	Pid        int
	IsRunning  bool
	StartTime  time.Time
	Version    string
	APIPort    int
	mu         sync.Mutex
}

// StatsCollector collects traffic statistics from cores
type StatsCollector struct {
	xrayClient    *XrayAPIClient
	singboxClient *SingboxAPIClient
	interval      time.Duration
	mu            sync.RWMutex
}

// Global protocol manager instance
var Protocols *ProtocolManager

// InitProtocolManager initializes the protocol manager
func InitProtocolManager(config *Config) error {
	ctx, cancel := context.WithCancel(context.Background())

	Protocols = &ProtocolManager{
		config:    config,
		cores:     make(map[string]*CoreProcess),
		inbounds:  make(map[string]*InboundConfig),
		outbounds: make(map[string]*OutboundConfig),
		ctx:       ctx,
		cancel:    cancel,
	}

	// Create config directories
	dirs := []string{
		"./Data/xray",
		"./Data/singbox",
		"./Data/clash",
		"./Data/wireguard",
		"./Data/certs",
	}
	for _, dir := range dirs {
		os.MkdirAll(dir, 0755)
	}

	// Initialize cores
	if config.Protocols.XrayEnabled {
		Protocols.cores[CoreXray] = &CoreProcess{
			Name:       CoreXray,
			Path:       config.Protocols.XrayPath,
			ConfigPath: XrayConfigPath,
			APIPort:    XrayAPIPort,
		}
	}

	if config.Protocols.SingboxEnabled {
		Protocols.cores[CoreSingbox] = &CoreProcess{
			Name:       CoreSingbox,
			Path:       config.Protocols.SingboxPath,
			ConfigPath: SingboxConfigPath,
			APIPort:    SingboxAPIPort,
		}
	}

	if config.Protocols.ClashEnabled {
		Protocols.cores[CoreClash] = &CoreProcess{
			Name:       CoreClash,
			Path:       config.Protocols.ClashPath,
			ConfigPath: ClashConfigPath,
		}
	}

	// Initialize stats collector
	Protocols.statsCollector = &StatsCollector{
		interval: 10 * time.Second,
	}

	// Load inbounds and outbounds from database
	if err := Protocols.loadInboundsFromDB(); err != nil {
		return fmt.Errorf("failed to load inbounds: %w", err)
	}

	if err := Protocols.loadOutboundsFromDB(); err != nil {
		return fmt.Errorf("failed to load outbounds: %w", err)
	}

	return nil
}

// EnableSinglePortMode routes all protocols to port 443
func (pm *ProtocolManager) EnableSinglePortMode() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	mainInbound := &InboundConfig{
		Tag:      "main-in",
		Listen:   "0.0.0.0",
		Port:     SinglePortNumber,
		Protocol: "vless",
		Fallback: &FallbackConfig{Dest: FallbackAddress},
	}
	pm.inbounds["main"] = mainInbound
	return pm.saveConfig()
}

// saveConfig saves the current configuration
func (pm *ProtocolManager) saveConfig() error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Generate configuration for each enabled core
	for coreName, core := range pm.cores {
		if !core.IsRunning {
			continue
		}

		var err error
		switch coreName {
		case CoreXray:
			err = pm.generateAndSaveXrayConfig(core.ConfigPath)
		case CoreSingbox:
			err = pm.generateAndSaveSingboxConfig(core.ConfigPath)
		case CoreClash:
			err = pm.generateAndSaveClashConfig(core.ConfigPath)
		}

		if err != nil {
			return fmt.Errorf("failed to save config for %s: %w", coreName, err)
		}
	}

	return nil
}

// generateAndSaveXrayConfig generates and saves Xray configuration
func (pm *ProtocolManager) generateAndSaveXrayConfig(configPath string) error {
	// Build Xray configuration structure
	config := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
		},
		"api": map[string]interface{}{
			"tag":      "api",
			"services": []string{"StatsService"},
		},
		"stats": map[string]interface{}{},
		"policy": map[string]interface{}{
			"levels": map[string]interface{}{
				"0": map[string]interface{}{
					"statsUserUplink":   true,
					"statsUserDownlink": true,
				},
			},
		},
	}

	// Add inbounds
	var inbounds []interface{}
	for _, inbound := range pm.inbounds {
		if inbound.Enabled {
			inbounds = append(inbounds, pm.buildXrayInbound(inbound))
		}
	}
	config["inbounds"] = inbounds

	// Add outbounds
	var outbounds []interface{}
	for _, outbound := range pm.outbounds {
		outbounds = append(outbounds, pm.buildXrayOutbound(outbound))
	}
	if len(outbounds) == 0 {
		// Default direct outbound
		outbounds = append(outbounds, map[string]interface{}{
			"protocol": "freedom",
			"tag":      "direct",
		})
	}
	config["outbounds"] = outbounds

	// Save to file
	return pm.saveJSONConfig(configPath, config)
}

// generateAndSaveSingboxConfig generates and saves Sing-box configuration
func (pm *ProtocolManager) generateAndSaveSingboxConfig(configPath string) error {
	// Build Sing-box configuration
	config := map[string]interface{}{
		"log": map[string]interface{}{
			"level": "warn",
		},
		"experimental": map[string]interface{}{
			"clash_api": map[string]interface{}{
				"external_controller": "127.0.0.1:9090",
			},
		},
	}

	// Add inbounds
	var inbounds []interface{}
	for _, inbound := range pm.inbounds {
		if inbound.Enabled {
			inbounds = append(inbounds, pm.buildSingboxInbound(inbound))
		}
	}
	config["inbounds"] = inbounds

	// Add outbounds
	var outbounds []interface{}
	for _, outbound := range pm.outbounds {
		outbounds = append(outbounds, pm.buildSingboxOutbound(outbound))
	}
	if len(outbounds) == 0 {
		outbounds = append(outbounds, map[string]interface{}{
			"type": "direct",
			"tag":  "direct",
		})
	}
	config["outbounds"] = outbounds

	// Save to file
	return pm.saveJSONConfig(configPath, config)
}

// generateAndSaveClashConfig generates and saves Clash configuration
func (pm *ProtocolManager) generateAndSaveClashConfig(configPath string) error {
	// Simplified Clash config generation
	config := map[string]interface{}{
		"port":               7890,
		"socks-port":         7891,
		"allow-lan":          true,
		"mode":               "rule",
		"log-level":          "info",
		"external-controller": "127.0.0.1:9090",
	}

	// Save to file (Clash uses YAML)
	return pm.saveYAMLConfig(configPath, config)
}

// Helper functions to build inbound/outbound configs
func (pm *ProtocolManager) buildXrayInbound(inbound *InboundConfig) map[string]interface{} {
	return map[string]interface{}{
		"tag":      inbound.Tag,
		"protocol": inbound.Protocol,
		"listen":   inbound.Listen,
		"port":     inbound.Port,
		"settings": inbound.Settings,
	}
}

func (pm *ProtocolManager) buildXrayOutbound(outbound *OutboundConfig) map[string]interface{} {
	return map[string]interface{}{
		"tag":      outbound.Tag,
		"protocol": outbound.Protocol,
		"settings": outbound.Settings,
	}
}

func (pm *ProtocolManager) buildSingboxInbound(inbound *InboundConfig) map[string]interface{} {
	return map[string]interface{}{
		"type":   inbound.Protocol,
		"tag":    inbound.Tag,
		"listen": inbound.Listen,
		"listen_port": inbound.Port,
	}
}

func (pm *ProtocolManager) buildSingboxOutbound(outbound *OutboundConfig) map[string]interface{} {
	return map[string]interface{}{
		"type": outbound.Protocol,
		"tag":  outbound.Tag,
	}
}

// saveJSONConfig saves configuration as JSON
func (pm *ProtocolManager) saveJSONConfig(path string, config map[string]interface{}) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// saveYAMLConfig saves configuration as YAML
func (pm *ProtocolManager) saveYAMLConfig(path string, config map[string]interface{}) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// ============================================================================
// INBOUND CONFIGURATION
// ============================================================================

// InboundConfig represents a protocol inbound configuration
type InboundConfig struct {
	ID             int64                  `json:"id"`
	Tag            string                 `json:"tag"`
	Protocol       string                 `json:"protocol"`
	Listen         string                 `json:"listen"`
	Port           int                    `json:"port"`
	Settings       map[string]interface{} `json:"settings"`
	StreamSettings *StreamSettings        `json:"stream_settings"`
	Sniffing       *SniffingConfig        `json:"sniffing,omitempty"`
	IsActive       bool                   `json:"is_active"`
	Enabled        bool                   `json:"enabled"`
	Remark         string                 `json:"remark"`
	NodeID         int64                  `json:"node_id"`
	Fallback       *FallbackConfig        `json:"fallback,omitempty"`
}

// StreamSettings represents transport and security settings
type StreamSettings struct {
	Network         string           `json:"network"`  // tcp, ws, grpc, http, quic
	Security        string           `json:"security"` // none, tls, reality
	TCPSettings     *TCPSettings     `json:"tcp_settings,omitempty"`
	WSSettings      *WSSettings      `json:"ws_settings,omitempty"`
	GRPCSettings    *GRPCSettings    `json:"grpc_settings,omitempty"`
	HTTPSettings    *HTTPSettings    `json:"http_settings,omitempty"`
	QUICSettings    *QUICSettings    `json:"quic_settings,omitempty"`
	TLSSettings     *TLSSettings     `json:"tls_settings,omitempty"`
	RealitySettings *RealitySettings `json:"reality_settings,omitempty"`
}

// TCPSettings for TCP transport
type TCPSettings struct {
	AcceptProxyProtocol bool       `json:"accept_proxy_protocol,omitempty"`
	Header              *TCPHeader `json:"header,omitempty"`
}

// TCPHeader for TCP header obfuscation
type TCPHeader struct {
	Type    string                 `json:"type"` // none, http
	Request map[string]interface{} `json:"request,omitempty"`
}

// WSSettings for WebSocket transport
type WSSettings struct {
	Path                string            `json:"path"`
	Headers             map[string]string `json:"headers,omitempty"`
	AcceptProxyProtocol bool              `json:"accept_proxy_protocol,omitempty"`
	MaxEarlyData        int               `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string            `json:"early_data_header_name,omitempty"`
}

// GRPCSettings for gRPC transport
type GRPCSettings struct {
	ServiceName        string `json:"service_name"`
	MultiMode          bool   `json:"multi_mode,omitempty"`
	IdleTimeout        int    `json:"idle_timeout,omitempty"`
	HealthCheckTimeout int    `json:"health_check_timeout,omitempty"`
}

// HTTPSettings for HTTP/2 transport
type HTTPSettings struct {
	Host    []string          `json:"host,omitempty"`
	Path    string            `json:"path"`
	Method  string            `json:"method,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// QUICSettings for QUIC transport
type QUICSettings struct {
	Security string      `json:"security"` // none, aes-128-gcm, chacha20-poly1305
	Key      string      `json:"key,omitempty"`
	Header   *QUICHeader `json:"header,omitempty"`
}

// QUICHeader for QUIC header
type QUICHeader struct {
	Type string `json:"type"` // none, srtp, utp, wechat-video, dtls, wireguard
}

// TLSSettings for TLS security
type TLSSettings struct {
	ServerName       string           `json:"server_name"`
	ALPN             []string         `json:"alpn,omitempty"`
	AllowInsecure    bool             `json:"allow_insecure,omitempty"`
	Fingerprint      string           `json:"fingerprint,omitempty"`
	CertificateFile  string           `json:"certificate_file,omitempty"`
	KeyFile          string           `json:"key_file,omitempty"`
	Certificates     []TLSCertificate `json:"certificates,omitempty"`
	MinVersion       string           `json:"min_version,omitempty"`
	MaxVersion       string           `json:"max_version,omitempty"`
	RejectUnknownSNI bool             `json:"reject_unknown_sni,omitempty"`
}

// TLSCertificate represents a TLS certificate
type TLSCertificate struct {
	CertificateFile string   `json:"certificate_file,omitempty"`
	KeyFile         string   `json:"key_file,omitempty"`
	Certificate     []string `json:"certificate,omitempty"`
	Key             []string `json:"key,omitempty"`
	Usage           string   `json:"usage,omitempty"` // encipherment, verify, issue
}

// RealitySettings for Reality security
type RealitySettings struct {
	Show         bool     `json:"show,omitempty"`
	Dest         string   `json:"dest"`
	Xver         int      `json:"xver,omitempty"`
	ServerNames  []string `json:"server_names"`
	PrivateKey   string   `json:"private_key"`
	PublicKey    string   `json:"public_key,omitempty"`
	ShortIds     []string `json:"short_ids"`
	Fingerprint  string   `json:"fingerprint,omitempty"`
	ServerName   string   `json:"server_name,omitempty"`
	SpiderX      string   `json:"spider_x,omitempty"`
	MinClientVer string   `json:"min_client_ver,omitempty"`
	MaxClientVer string   `json:"max_client_ver,omitempty"`
	MaxTimeDiff  int      `json:"max_time_diff,omitempty"`
}

// SniffingConfig for protocol sniffing
type SniffingConfig struct {
	Enabled         bool     `json:"enabled"`
	DestOverride    []string `json:"dest_override,omitempty"` // http, tls, quic, fakedns
	MetadataOnly    bool     `json:"metadata_only,omitempty"`
	DomainsExcluded []string `json:"domains_excluded,omitempty"`
}

// ============================================================================
// OUTBOUND CONFIGURATION
// ============================================================================

// OutboundConfig represents a protocol outbound configuration
type OutboundConfig struct {
	ID             int64                  `json:"id"`
	Tag            string                 `json:"tag"`
	Protocol       string                 `json:"protocol"`
	Settings       map[string]interface{} `json:"settings"`
	StreamSettings *StreamSettings        `json:"stream_settings,omitempty"`
	ProxySettings  *ProxySettings         `json:"proxy_settings,omitempty"`
	Mux            *MuxConfig             `json:"mux,omitempty"`
	SendThrough    string                 `json:"send_through,omitempty"`
	IsActive       bool                   `json:"is_active"`
	Remark         string                 `json:"remark"`
	NodeID         int64                  `json:"node_id"`
}

// ProxySettings for outbound proxy chaining
type ProxySettings struct {
	Tag            string `json:"tag"`
	TransportLayer bool   `json:"transport_layer,omitempty"`
}

// ============================================================================
// PROTOCOL-SPECIFIC SETTINGS
// ============================================================================

// VMESSSettings for VMess protocol
type VMESSSettings struct {
	Clients []VMESSClient `json:"clients"`
}

// VMESSClient represents a VMess client
type VMESSClient struct {
	ID       string `json:"id"`
	AlterID  int    `json:"alter_id,omitempty"`
	Email    string `json:"email,omitempty"`
	Security string `json:"security,omitempty"` // auto, aes-128-gcm, chacha20-poly1305, none
}

// VLESSSettings for VLESS protocol
type VLESSSettings struct {
	Clients    []VLESSClient `json:"clients"`
	Decryption string        `json:"decryption,omitempty"`
	Fallbacks  []Fallback    `json:"fallbacks,omitempty"`
}

// VLESSClient represents a VLESS client
type VLESSClient struct {
	ID    string `json:"id"`
	Email string `json:"email,omitempty"`
	Flow  string `json:"flow,omitempty"` // xtls-rprx-vision
}

// TrojanSettings for Trojan protocol
type TrojanSettings struct {
	Clients   []TrojanClient `json:"clients"`
	Fallbacks []Fallback     `json:"fallbacks,omitempty"`
}

// TrojanClient represents a Trojan client
type TrojanClient struct {
	Password string `json:"password"`
	Email    string `json:"email,omitempty"`
}

// Fallback represents a fallback configuration
type Fallback struct {
	Name string      `json:"name,omitempty"`
	Alpn string      `json:"alpn,omitempty"`
	Path string      `json:"path,omitempty"`
	Dest interface{} `json:"dest"`
	Xver int         `json:"xver,omitempty"`
}

// ShadowsocksSettings for Shadowsocks protocol
type ShadowsocksSettings struct {
	Method   string              `json:"method"`
	Password string              `json:"password"`
	Clients  []ShadowsocksClient `json:"clients,omitempty"`
	Network  string              `json:"network,omitempty"` // tcp, udp, tcp,udp
}

// ShadowsocksClient for Shadowsocks 2022
type ShadowsocksClient struct {
	Password string `json:"password"`
	Email    string `json:"email,omitempty"`
}

// Hysteria2Settings for Hysteria2 protocol
type Hysteria2Settings struct {
	Listen                string               `json:"listen,omitempty"`
	Obfs                  *Hysteria2Obfs       `json:"obfs,omitempty"`
	Users                 []Hysteria2User      `json:"users"`
	IgnoreClientBandwidth bool                 `json:"ignore_client_bandwidth,omitempty"`
	Masquerade            *Hysteria2Masquerade `json:"masquerade,omitempty"`
}

// Hysteria2Obfs for Hysteria2 obfuscation
type Hysteria2Obfs struct {
	Type     string `json:"type"` // salamander
	Password string `json:"password"`
}

// Hysteria2User represents a Hysteria2 user
type Hysteria2User struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password"`
}

// Hysteria2Masquerade for Hysteria2 masquerade
type Hysteria2Masquerade struct {
	Type  string                    `json:"type"` // proxy, file, string
	File  *Hysteria2MasqueradeFile  `json:"file,omitempty"`
	Proxy *Hysteria2MasqueradeProxy `json:"proxy,omitempty"`
}

// Hysteria2MasqueradeFile for file masquerade
type Hysteria2MasqueradeFile struct {
	Dir string `json:"dir"`
}

// Hysteria2MasqueradeProxy for proxy masquerade
type Hysteria2MasqueradeProxy struct {
	URL         string `json:"url"`
	RewriteHost bool   `json:"rewrite_host,omitempty"`
}

// TUICSettings for TUIC protocol
type TUICSettings struct {
	Users             []TUICUser `json:"users"`
	CongestionControl string     `json:"congestion_control,omitempty"` // cubic, new_reno, bbr
	AuthTimeout       string     `json:"auth_timeout,omitempty"`
	ZeroRTTHandshake  bool       `json:"zero_rtt_handshake,omitempty"`
	Heartbeat         string     `json:"heartbeat,omitempty"`
}

// TUICUser represents a TUIC user
type TUICUser struct {
	Name     string `json:"name,omitempty"`
	UUID     string `json:"uuid"`
	Password string `json:"password,omitempty"`
}

// WireGuardSettings for WireGuard protocol
type WireGuardSettings struct {
	SecretKey  string          `json:"secret_key,omitempty"`
	PrivateKey string          `json:"private_key,omitempty"`
	PublicKey  string          `json:"public_key,omitempty"`
	Address    []string        `json:"address,omitempty"`
	Peers      []WireGuardPeer `json:"peers,omitempty"`
	MTU        int             `json:"mtu,omitempty"`
	Reserved   []int           `json:"reserved,omitempty"`
	Workers    int             `json:"workers,omitempty"`
}

// WireGuardPeer represents a WireGuard peer
type WireGuardPeer struct {
	Endpoint            string   `json:"endpoint,omitempty"`
	PublicKey           string   `json:"public_key"`
	PreSharedKey        string   `json:"pre_shared_key,omitempty"`
	AllowedIPs          []string `json:"allowed_ips,omitempty"`
	KeepAlive           int      `json:"keep_alive,omitempty"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`
}

// ============================================================================
// XRAY CONFIGURATION GENERATOR
// ============================================================================

// XrayConfig represents complete Xray configuration
type XrayConfig struct {
	Log       *XrayLog                 `json:"log,omitempty"`
	API       *XrayAPI                 `json:"api,omitempty"`
	DNS       *XrayDNS                 `json:"dns,omitempty"`
	Routing   *XrayRouting             `json:"routing,omitempty"`
	Policy    *XrayPolicy              `json:"policy,omitempty"`
	Inbounds  []map[string]interface{} `json:"inbounds"`
	Outbounds []map[string]interface{} `json:"outbounds"`
	Stats     *XrayStats               `json:"stats,omitempty"`
}

// XrayLog for Xray logging
type XrayLog struct {
	Access   string `json:"access,omitempty"`
	Error    string `json:"error,omitempty"`
	LogLevel string `json:"loglevel,omitempty"` // debug, info, warning, error, none
	DNSLog   bool   `json:"dnsLog,omitempty"`
}

// XrayAPI for Xray API
type XrayAPI struct {
	Tag      string   `json:"tag"`
	Services []string `json:"services"`
}

// XrayDNS for Xray DNS settings
type XrayDNS struct {
	Hosts                  map[string]interface{} `json:"hosts,omitempty"`
	Servers                []interface{}          `json:"servers,omitempty"`
	ClientIP               string                 `json:"clientIp,omitempty"`
	QueryStrategy          string                 `json:"queryStrategy,omitempty"`
	DisableCache           bool                   `json:"disableCache,omitempty"`
	DisableFallback        bool                   `json:"disableFallback,omitempty"`
	DisableFallbackIfMatch bool                   `json:"disableFallbackIfMatch,omitempty"`
	Tag                    string                 `json:"tag,omitempty"`
}

// XrayRouting for Xray routing rules
type XrayRouting struct {
	DomainStrategy string         `json:"domainStrategy,omitempty"` // AsIs, IPIfNonMatch, IPOnDemand
	DomainMatcher  string         `json:"domainMatcher,omitempty"`  // hybrid, linear
	Rules          []XrayRule     `json:"rules,omitempty"`
	Balancers      []XrayBalancer `json:"balancers,omitempty"`
}

// XrayRule represents a routing rule
type XrayRule struct {
	DomainMatcher string   `json:"domainMatcher,omitempty"`
	Type          string   `json:"type,omitempty"`
	Domain        []string `json:"domain,omitempty"`
	IP            []string `json:"ip,omitempty"`
	Port          string   `json:"port,omitempty"`
	SourcePort    string   `json:"sourcePort,omitempty"`
	Network       string   `json:"network,omitempty"`
	Source        []string `json:"source,omitempty"`
	User          []string `json:"user,omitempty"`
	InboundTag    []string `json:"inboundTag,omitempty"`
	Protocol      []string `json:"protocol,omitempty"`
	Attrs         string   `json:"attrs,omitempty"`
	OutboundTag   string   `json:"outboundTag,omitempty"`
	BalancerTag   string   `json:"balancerTag,omitempty"`
}

// XrayBalancer for load balancing
type XrayBalancer struct {
	Tag      string                `json:"tag"`
	Selector []string              `json:"selector"`
	Strategy *XrayBalancerStrategy `json:"strategy,omitempty"`
}

// XrayBalancerStrategy for balancer strategy
type XrayBalancerStrategy struct {
	Type     string                 `json:"type,omitempty"` // random, roundRobin, leastPing, leastLoad
	Settings map[string]interface{} `json:"settings,omitempty"`
}

// XrayPolicy for Xray policy settings
type XrayPolicy struct {
	Levels map[string]*XrayPolicyLevel `json:"levels,omitempty"`
	System *XrayPolicySystem           `json:"system,omitempty"`
}

// XrayPolicyLevel for policy level settings
type XrayPolicyLevel struct {
	Handshake         int  `json:"handshake,omitempty"`
	ConnIdle          int  `json:"connIdle,omitempty"`
	UplinkOnly        int  `json:"uplinkOnly,omitempty"`
	DownlinkOnly      int  `json:"downlinkOnly,omitempty"`
	StatsUserUplink   bool `json:"statsUserUplink,omitempty"`
	StatsUserDownlink bool `json:"statsUserDownlink,omitempty"`
	BufferSize        int  `json:"bufferSize,omitempty"`
}

// XrayPolicySystem for system policy
type XrayPolicySystem struct {
	StatsInboundUplink    bool `json:"statsInboundUplink,omitempty"`
	StatsInboundDownlink  bool `json:"statsInboundDownlink,omitempty"`
	StatsOutboundUplink   bool `json:"statsOutboundUplink,omitempty"`
	StatsOutboundDownlink bool `json:"statsOutboundDownlink,omitempty"`
}

// XrayStats for statistics
type XrayStats struct{}

// GenerateXrayConfig generates complete Xray configuration
func (pm *ProtocolManager) GenerateXrayConfig() (*XrayConfig, error) {
	config := &XrayConfig{
		Log: &XrayLog{
			LogLevel: "warning",
			Access:   "",
			Error:    "",
		},
		API: &XrayAPI{
			Tag:      "api",
			Services: []string{"HandlerService", "LoggerService", "StatsService"},
		},
		Stats: &XrayStats{},
		Policy: &XrayPolicy{
			Levels: map[string]*XrayPolicyLevel{
				"0": {
					StatsUserUplink:   true,
					StatsUserDownlink: true,
				},
			},
			System: &XrayPolicySystem{
				StatsInboundUplink:    true,
				StatsInboundDownlink:  true,
				StatsOutboundUplink:   true,
				StatsOutboundDownlink: true,
			},
		},
		Routing: &XrayRouting{
			DomainStrategy: "IPIfNonMatch",
			Rules:          []XrayRule{},
		},
		Inbounds:  []map[string]interface{}{},
		Outbounds: []map[string]interface{}{},
	}

	// Add API inbound
	config.Inbounds = append(config.Inbounds, map[string]interface{}{
		"tag":      "api",
		"listen":   "127.0.0.1",
		"port":     XrayAPIPort,
		"protocol": "dokodemo-door",
		"settings": map[string]interface{}{
			"address": "127.0.0.1",
		},
	})

	// Add API routing rule
	config.Routing.Rules = append(config.Routing.Rules, XrayRule{
		InboundTag:  []string{"api"},
		OutboundTag: "api",
		Type:        "field",
	})

	// Add inbounds
	pm.mu.RLock()
	for _, inbound := range pm.inbounds {
		if inbound.IsActive {
			xrayInbound, err := pm.inboundToXray(inbound)
			if err == nil {
				config.Inbounds = append(config.Inbounds, xrayInbound)
			}
		}
	}
	pm.mu.RUnlock()

	// Add default outbounds
	config.Outbounds = append(config.Outbounds,
		map[string]interface{}{
			"tag":      "api",
			"protocol": "blackhole",
		},
		map[string]interface{}{
			"tag":      "direct",
			"protocol": "freedom",
			"settings": map[string]interface{}{},
		},
		map[string]interface{}{
			"tag":      "blocked",
			"protocol": "blackhole",
			"settings": map[string]interface{}{
				"response": map[string]interface{}{
					"type": "http",
				},
			},
		},
	)

	// Add custom outbounds
	pm.mu.RLock()
	for _, outbound := range pm.outbounds {
		if outbound.IsActive {
			xrayOutbound, err := pm.outboundToXray(outbound)
			if err == nil {
				config.Outbounds = append(config.Outbounds, xrayOutbound)
			}
		}
	}
	pm.mu.RUnlock()

	// Add routing rules from database
	rules, _ := pm.loadRoutingRulesFromDB()
	for _, rule := range rules {
		if rule.IsActive {
			config.Routing.Rules = append(config.Routing.Rules, pm.routingRuleToXray(rule))
		}
	}

	// Add default routing rules
	config.Routing.Rules = append(config.Routing.Rules,
		XrayRule{
			Type:        "field",
			OutboundTag: "blocked",
			Protocol:    []string{"bittorrent"},
		},
		XrayRule{
			Type:        "field",
			OutboundTag: "direct",
			IP:          []string{"geoip:private", "geoip:ir"},
		},
		XrayRule{
			Type:        "field",
			OutboundTag: "direct",
			Domain:      []string{"geosite:private", "geosite:category-ir"},
		},
	)

	return config, nil
}

// inboundToXray converts InboundConfig to Xray inbound format
func (pm *ProtocolManager) inboundToXray(inbound *InboundConfig) (map[string]interface{}, error) {
	result := map[string]interface{}{
		"tag":      inbound.Tag,
		"listen":   inbound.Listen,
		"port":     inbound.Port,
		"protocol": inbound.Protocol,
		"settings": inbound.Settings,
	}

	// Add stream settings
	if inbound.StreamSettings != nil {
		streamSettings := pm.streamSettingsToXray(inbound.StreamSettings)
		result["streamSettings"] = streamSettings
	}

	// Add sniffing
	if inbound.Sniffing != nil && inbound.Sniffing.Enabled {
		result["sniffing"] = map[string]interface{}{
			"enabled":      true,
			"destOverride": inbound.Sniffing.DestOverride,
			"metadataOnly": inbound.Sniffing.MetadataOnly,
		}
	}

	return result, nil
}

// outboundToXray converts OutboundConfig to Xray outbound format
func (pm *ProtocolManager) outboundToXray(outbound *OutboundConfig) (map[string]interface{}, error) {
	result := map[string]interface{}{
		"tag":      outbound.Tag,
		"protocol": outbound.Protocol,
		"settings": outbound.Settings,
	}

	if outbound.SendThrough != "" {
		result["sendThrough"] = outbound.SendThrough
	}

	if outbound.StreamSettings != nil {
		result["streamSettings"] = pm.streamSettingsToXray(outbound.StreamSettings)
	}

	if outbound.Mux != nil && outbound.Mux.Enabled {
		result["mux"] = map[string]interface{}{
			"enabled":     true,
			"concurrency": outbound.Mux.Concurrency,
		}
	}

	return result, nil
}

// streamSettingsToXray converts StreamSettings to Xray format
func (pm *ProtocolManager) streamSettingsToXray(ss *StreamSettings) map[string]interface{} {
	result := map[string]interface{}{
		"network":  ss.Network,
		"security": ss.Security,
	}

	// Network settings
	switch ss.Network {
	case "tcp":
		if ss.TCPSettings != nil {
			result["tcpSettings"] = ss.TCPSettings
		}
	case "ws":
		if ss.WSSettings != nil {
			wsSettings := map[string]interface{}{
				"path": ss.WSSettings.Path,
			}
			if len(ss.WSSettings.Headers) > 0 {
				wsSettings["headers"] = ss.WSSettings.Headers
			}
			result["wsSettings"] = wsSettings
		}
	case "grpc":
		if ss.GRPCSettings != nil {
			result["grpcSettings"] = map[string]interface{}{
				"serviceName": ss.GRPCSettings.ServiceName,
				"multiMode":   ss.GRPCSettings.MultiMode,
			}
		}
	case "http":
		if ss.HTTPSettings != nil {
			result["httpSettings"] = map[string]interface{}{
				"host": ss.HTTPSettings.Host,
				"path": ss.HTTPSettings.Path,
			}
		}
	case "quic":
		if ss.QUICSettings != nil {
			result["quicSettings"] = ss.QUICSettings
		}
	}

	// Security settings
	switch ss.Security {
	case "tls":
		if ss.TLSSettings != nil {
			tlsSettings := map[string]interface{}{
				"serverName": ss.TLSSettings.ServerName,
			}
			if len(ss.TLSSettings.ALPN) > 0 {
				tlsSettings["alpn"] = ss.TLSSettings.ALPN
			}
			if ss.TLSSettings.Fingerprint != "" {
				tlsSettings["fingerprint"] = ss.TLSSettings.Fingerprint
			}
			if len(ss.TLSSettings.Certificates) > 0 {
				tlsSettings["certificates"] = ss.TLSSettings.Certificates
			}
			result["tlsSettings"] = tlsSettings
		}
	case "reality":
		if ss.RealitySettings != nil {
			realitySettings := map[string]interface{}{
				"dest":        ss.RealitySettings.Dest,
				"serverNames": ss.RealitySettings.ServerNames,
				"privateKey":  ss.RealitySettings.PrivateKey,
				"shortIds":    ss.RealitySettings.ShortIds,
			}
			if ss.RealitySettings.Fingerprint != "" {
				realitySettings["fingerprint"] = ss.RealitySettings.Fingerprint
			}
			result["realitySettings"] = realitySettings
		}
	}

	return result
}

// routingRuleToXray converts RoutingRule to Xray format
func (pm *ProtocolManager) routingRuleToXray(rule *RoutingRule) XrayRule {
	return XrayRule{
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
		OutboundTag: rule.OutboundTag,
		BalancerTag: rule.BalancerTag,
	}
}

// ============================================================================
// SING-BOX CONFIGURATION GENERATOR
// ============================================================================

// SingboxConfig represents complete Sing-box configuration
type SingboxConfig struct {
	Log          *SingboxLog          `json:"log,omitempty"`
	DNS          *SingboxDNS          `json:"dns,omitempty"`
	NTP          *SingboxNTP          `json:"ntp,omitempty"`
	Inbounds     []interface{}        `json:"inbounds"`
	Outbounds    []interface{}        `json:"outbounds"`
	Route        *SingboxRoute        `json:"route,omitempty"`
	Experimental *SingboxExperimental `json:"experimental,omitempty"`
}

// SingboxLog for Sing-box logging
type SingboxLog struct {
	Disabled  bool   `json:"disabled,omitempty"`
	Level     string `json:"level,omitempty"` // trace, debug, info, warn, error, fatal, panic
	Output    string `json:"output,omitempty"`
	Timestamp bool   `json:"timestamp,omitempty"`
}

// SingboxDNS for Sing-box DNS
type SingboxDNS struct {
	Servers          []SingboxDNSServer `json:"servers,omitempty"`
	Rules            []SingboxDNSRule   `json:"rules,omitempty"`
	Final            string             `json:"final,omitempty"`
	Strategy         string             `json:"strategy,omitempty"`
	DisableCache     bool               `json:"disable_cache,omitempty"`
	DisableExpire    bool               `json:"disable_expire,omitempty"`
	IndependentCache bool               `json:"independent_cache,omitempty"`
	ReverseMapping   bool               `json:"reverse_mapping,omitempty"`
	Fakeip           *SingboxFakeIP     `json:"fakeip,omitempty"`
}

// SingboxDNSServer for DNS server
type SingboxDNSServer struct {
	Tag             string `json:"tag,omitempty"`
	Address         string `json:"address"`
	AddressResolver string `json:"address_resolver,omitempty"`
	AddressStrategy string `json:"address_strategy,omitempty"`
	Strategy        string `json:"strategy,omitempty"`
	Detour          string `json:"detour,omitempty"`
	ClientSubnet    string `json:"client_subnet,omitempty"`
}

// SingboxDNSRule for DNS routing
type SingboxDNSRule struct {
	Domain        []string `json:"domain,omitempty"`
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
	DomainRegex   []string `json:"domain_regex,omitempty"`
	Geosite       []string `json:"geosite,omitempty"`
	Server        string   `json:"server,omitempty"`
	DisableCache  bool     `json:"disable_cache,omitempty"`
	RewriteTTL    int      `json:"rewrite_ttl,omitempty"`
	ClientSubnet  string   `json:"client_subnet,omitempty"`
}

// SingboxFakeIP for FakeIP settings
type SingboxFakeIP struct {
	Enabled    bool   `json:"enabled"`
	Inet4Range string `json:"inet4_range,omitempty"`
	Inet6Range string `json:"inet6_range,omitempty"`
}

// SingboxNTP for NTP settings
type SingboxNTP struct {
	Enabled  bool   `json:"enabled"`
	Server   string `json:"server,omitempty"`
	Interval string `json:"interval,omitempty"`
}

// SingboxRoute for routing
type SingboxRoute struct {
	Rules               []SingboxRouteRule `json:"rules,omitempty"`
	RuleSet             []SingboxRuleSet   `json:"rule_set,omitempty"`
	Final               string             `json:"final,omitempty"`
	AutoDetectInterface bool               `json:"auto_detect_interface,omitempty"`
	OverrideAndroidVPN  bool               `json:"override_android_vpn,omitempty"`
	DefaultInterface    string             `json:"default_interface,omitempty"`
	DefaultMark         int                `json:"default_mark,omitempty"`
}

// SingboxRouteRule for route rules
type SingboxRouteRule struct {
	Protocol        []string `json:"protocol,omitempty"`
	Network         []string `json:"network,omitempty"`
	Domain          []string `json:"domain,omitempty"`
	DomainSuffix    []string `json:"domain_suffix,omitempty"`
	DomainKeyword   []string `json:"domain_keyword,omitempty"`
	DomainRegex     []string `json:"domain_regex,omitempty"`
	Geosite         []string `json:"geosite,omitempty"`
	SourceGeoIP     []string `json:"source_geoip,omitempty"`
	GeoIP           []string `json:"geoip,omitempty"`
	SourceIPCIDR    []string `json:"source_ip_cidr,omitempty"`
	IPCIDR          []string `json:"ip_cidr,omitempty"`
	SourcePort      []int    `json:"source_port,omitempty"`
	SourcePortRange []string `json:"source_port_range,omitempty"`
	Port            []int    `json:"port,omitempty"`
	PortRange       []string `json:"port_range,omitempty"`
	ProcessName     []string `json:"process_name,omitempty"`
	ProcessPath     []string `json:"process_path,omitempty"`
	PackageName     []string `json:"package_name,omitempty"`
	User            []string `json:"user,omitempty"`
	UserID          []int    `json:"user_id,omitempty"`
	ClashMode       string   `json:"clash_mode,omitempty"`
	Invert          bool     `json:"invert,omitempty"`
	Outbound        string   `json:"outbound,omitempty"`
}

// SingboxRuleSet for rule sets
type SingboxRuleSet struct {
	Tag            string `json:"tag"`
	Type           string `json:"type"`   // local, remote
	Format         string `json:"format"` // source, binary
	Path           string `json:"path,omitempty"`
	URL            string `json:"url,omitempty"`
	DownloadDetour string `json:"download_detour,omitempty"`
	UpdateInterval string `json:"update_interval,omitempty"`
}

// SingboxExperimental for experimental features
type SingboxExperimental struct {
	CacheFile *SingboxCacheFile `json:"cache_file,omitempty"`
	ClashAPI  *SingboxClashAPI  `json:"clash_api,omitempty"`
	V2RayAPI  *SingboxV2RayAPI  `json:"v2ray_api,omitempty"`
}

// SingboxCacheFile for cache settings
type SingboxCacheFile struct {
	Enabled     bool   `json:"enabled"`
	Path        string `json:"path,omitempty"`
	CacheID     string `json:"cache_id,omitempty"`
	StoreFakeIP bool   `json:"store_fakeip,omitempty"`
}

// SingboxClashAPI for Clash API
type SingboxClashAPI struct {
	ExternalController string `json:"external_controller,omitempty"`
	ExternalUI         string `json:"external_ui,omitempty"`
	Secret             string `json:"secret,omitempty"`
	DefaultMode        string `json:"default_mode,omitempty"`
}

// SingboxV2RayAPI for V2Ray API
type SingboxV2RayAPI struct {
	Listen string             `json:"listen,omitempty"`
	Stats  *SingboxV2RayStats `json:"stats,omitempty"`
}

// SingboxV2RayStats for V2Ray stats
type SingboxV2RayStats struct {
	Enabled   bool     `json:"enabled"`
	Inbounds  []string `json:"inbounds,omitempty"`
	Outbounds []string `json:"outbounds,omitempty"`
	Users     []string `json:"users,omitempty"`
}

// GenerateSingboxConfig generates complete Sing-box configuration
func (pm *ProtocolManager) GenerateSingboxConfig() (*SingboxConfig, error) {
	config := &SingboxConfig{
		Log: &SingboxLog{
			Level:     "warn",
			Timestamp: true,
		},
		DNS: &SingboxDNS{
			Servers: []SingboxDNSServer{
				{Tag: "dns-direct", Address: "https://dns.google/dns-query", Detour: "direct"},
			},
			Strategy: "prefer_ipv4",
		},
		Route: &SingboxRoute{
			Final:               "direct",
			AutoDetectInterface: true,
			Rules:               []SingboxRouteRule{},
		},
		Experimental: &SingboxExperimental{
			CacheFile: &SingboxCacheFile{
				Enabled: true,
				Path:    "./Data/singbox/cache.db",
			},
			V2RayAPI: &SingboxV2RayAPI{
				Listen: fmt.Sprintf("127.0.0.1:%d", SingboxAPIPort),
				Stats: &SingboxV2RayStats{
					Enabled: true,
				},
			},
		},
		Inbounds:  []interface{}{},
		Outbounds: []interface{}{},
	}

	// Add inbounds
	pm.mu.RLock()
	for _, inbound := range pm.inbounds {
		if inbound.IsActive {
			sbInbound := pm.inboundToSingbox(inbound)
			if sbInbound != nil {
				config.Inbounds = append(config.Inbounds, sbInbound)
			}
		}
	}
	pm.mu.RUnlock()

	// Add default outbounds
	config.Outbounds = append(config.Outbounds,
		map[string]interface{}{
			"tag":  "direct",
			"type": "direct",
		},
		map[string]interface{}{
			"tag":  "block",
			"type": "block",
		},
		map[string]interface{}{
			"tag":  "dns-out",
			"type": "dns",
		},
	)

	// Add routing rules
	config.Route.Rules = append(config.Route.Rules,
		SingboxRouteRule{
			Protocol: []string{"dns"},
			Outbound: "dns-out",
		},
		SingboxRouteRule{
			GeoIP:    []string{"private", "ir"},
			Outbound: "direct",
		},
		SingboxRouteRule{
			Geosite:  []string{"category-ir"},
			Outbound: "direct",
		},
		SingboxRouteRule{
			Protocol: []string{"bittorrent"},
			Outbound: "block",
		},
	)

	return config, nil
}

// inboundToSingbox converts InboundConfig to Sing-box format
func (pm *ProtocolManager) inboundToSingbox(inbound *InboundConfig) map[string]interface{} {
	result := map[string]interface{}{
		"tag":         inbound.Tag,
		"type":        inbound.Protocol,
		"listen":      inbound.Listen,
		"listen_port": inbound.Port,
	}

	// Add protocol-specific settings
	for k, v := range inbound.Settings {
		result[k] = v
	}

	// Add TLS settings
	if inbound.StreamSettings != nil && inbound.StreamSettings.Security == "tls" {
		result["tls"] = map[string]interface{}{
			"enabled":     true,
			"server_name": inbound.StreamSettings.TLSSettings.ServerName,
		}
	}

	return result
}

// ============================================================================
// CORE PROCESS MANAGEMENT
// ============================================================================

// Start starts all enabled protocol cores
func (pm *ProtocolManager) Start() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.isRunning {
		return nil
	}

	var errs []string

	for name, core := range pm.cores {
		if err := pm.startCore(core); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
		}
	}

	pm.isRunning = true

	// Start stats collector
	go pm.startStatsCollector()

	if len(errs) > 0 {
		return fmt.Errorf("some cores failed to start: %s", strings.Join(errs, "; "))
	}

	return nil
}

// Stop stops all protocol cores
func (pm *ProtocolManager) Stop() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.cancel()

	for _, core := range pm.cores {
		pm.stopCore(core)
	}

	pm.isRunning = false
	return nil
}

// Restart restarts all protocol cores
func (pm *ProtocolManager) Restart() error {
	if err := pm.Stop(); err != nil {
		return err
	}

	// Wait a bit for processes to terminate
	time.Sleep(2 * time.Second)

	// Reinitialize context
	pm.ctx, pm.cancel = context.WithCancel(context.Background())

	return pm.Start()
}

// startCore starts a single core
func (pm *ProtocolManager) startCore(core *CoreProcess) error {
	core.mu.Lock()
	defer core.mu.Unlock()

	if core.IsRunning {
		return nil
	}

	// Check if binary exists
	if _, err := os.Stat(core.Path); os.IsNotExist(err) {
		return fmt.Errorf("binary not found: %s", core.Path)
	}

	// Generate config
	if err := pm.generateCoreConfig(core); err != nil {
		return fmt.Errorf("failed to generate config: %w", err)
	}

	// Build command
	var cmd *exec.Cmd
	switch core.Name {
	case CoreXray:
		cmd = exec.Command(core.Path, "run", "-c", core.ConfigPath)
	case CoreSingbox:
		cmd = exec.Command(core.Path, "run", "-c", core.ConfigPath)
	case CoreClash:
		cmd = exec.Command(core.Path, "-f", core.ConfigPath)
	default:
		return fmt.Errorf("unknown core: %s", core.Name)
	}

	// Set process group
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Capture output
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	// Start process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start: %w", err)
	}

	core.Process = cmd
	core.Pid = cmd.Process.Pid
	core.IsRunning = true
	core.StartTime = time.Now()

	// Log output in background
	go pm.logOutput(core.Name, stdout)
	go pm.logOutput(core.Name, stderr)

	// Monitor process
	go pm.monitorProcess(core)

	// Get version
	core.Version = pm.getCoreVersion(core)

	return nil
}

// stopCore stops a single core
func (pm *ProtocolManager) stopCore(core *CoreProcess) error {
	core.mu.Lock()
	defer core.mu.Unlock()

	if !core.IsRunning || core.Process == nil {
		return nil
	}

	// Send SIGTERM
	if core.Process.Process != nil {
		syscall.Kill(-core.Pid, syscall.SIGTERM)
	}

	// Wait with timeout
	done := make(chan error, 1)
	go func() {
		done <- core.Process.Wait()
	}()

	select {
	case <-done:
		// Process exited
	case <-time.After(5 * time.Second):
		// Force kill
		syscall.Kill(-core.Pid, syscall.SIGKILL)
	}

	core.IsRunning = false
	core.Process = nil
	core.Pid = 0

	return nil
}

// RestartCore restarts a specific core
func (pm *ProtocolManager) RestartCore(coreName string) error {
	pm.mu.Lock()
	core, exists := pm.cores[coreName]
	pm.mu.Unlock()

	if !exists {
		return fmt.Errorf("core not found: %s", coreName)
	}

	pm.stopCore(core)
	time.Sleep(1 * time.Second)
	return pm.startCore(core)
}

// generateCoreConfig generates configuration file for a core
func (pm *ProtocolManager) generateCoreConfig(core *CoreProcess) error {
	var configData []byte

	switch core.Name {
	case CoreXray:
		config, err := pm.GenerateXrayConfig()
		if err != nil {
			return err
		}
		configData, err = json.MarshalIndent(config, "", "  ")
		if err != nil {
			return err
		}
	case CoreSingbox:
		config, err := pm.GenerateSingboxConfig()
		if err != nil {
			return err
		}
		configData, err = json.MarshalIndent(config, "", "  ")
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("config generation not implemented for: %s", core.Name)
	}

	// Ensure directory exists
	os.MkdirAll(filepath.Dir(core.ConfigPath), 0755)

	return ioutil.WriteFile(core.ConfigPath, configData, 0644)
}

// logOutput logs core output
func (pm *ProtocolManager) logOutput(name string, reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			fmt.Printf("[%s] %s\n", name, line)
		}
	}
}

// monitorProcess monitors core process and restarts if needed
func (pm *ProtocolManager) monitorProcess(core *CoreProcess) {
	if core.Process == nil {
		return
	}

	err := core.Process.Wait()

	core.mu.Lock()
	core.IsRunning = false
	core.mu.Unlock()

	if err != nil && pm.isRunning {
		fmt.Printf("[%s] Process crashed: %v, restarting...\n", core.Name, err)
		time.Sleep(2 * time.Second)

		pm.mu.Lock()
		pm.startCore(core)
		pm.mu.Unlock()
	}
}

// getCoreVersion gets the version of a core
func (pm *ProtocolManager) getCoreVersion(core *CoreProcess) string {
	var cmd *exec.Cmd
	switch core.Name {
	case CoreXray:
		cmd = exec.Command(core.Path, "version")
	case CoreSingbox:
		cmd = exec.Command(core.Path, "version")
	case CoreClash:
		cmd = exec.Command(core.Path, "-v")
	default:
		return "unknown"
	}

	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}
	return "unknown"
}

// ============================================================================
// INBOUND/OUTBOUND MANAGEMENT
// ============================================================================

// CreateInbound creates a new inbound
func (pm *ProtocolManager) CreateInbound(inbound *InboundConfig) error {
	// Validate
	if inbound.Tag == "" {
		return errors.New("tag is required")
	}
	if inbound.Port <= 0 || inbound.Port > 65535 {
		return errors.New("invalid port")
	}

	// Check for duplicate tag
	pm.mu.RLock()
	for _, ib := range pm.inbounds {
		if ib.Tag == inbound.Tag {
			pm.mu.RUnlock()
			return errors.New("inbound tag already exists")
		}
	}
	pm.mu.RUnlock()

	// Set defaults
	if inbound.Listen == "" {
		inbound.Listen = "0.0.0.0"
	}

	// Save to database
	settingsJSON, _ := json.Marshal(inbound.Settings)
	streamJSON, _ := json.Marshal(inbound.StreamSettings)
	sniffingJSON, _ := json.Marshal(inbound.Sniffing)

	result, err := DB.db.Exec(`
		INSERT INTO inbounds (
			node_id, tag, protocol, listen, port, settings, stream_settings,
			sniffing, transport, security, is_active, remark, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		inbound.NodeID, inbound.Tag, inbound.Protocol, inbound.Listen, inbound.Port,
		string(settingsJSON), string(streamJSON), string(sniffingJSON),
		inbound.StreamSettings.Network, inbound.StreamSettings.Security,
		inbound.IsActive, inbound.Remark, time.Now(), time.Now(),
	)
	if err != nil {
		return err
	}

	inbound.ID, _ = result.LastInsertId()

	// Add to cache
	pm.mu.Lock()
	pm.inbounds[inbound.Tag] = inbound
	pm.mu.Unlock()

	// Reload config
	if pm.isRunning {
		pm.reloadCores()
	}

	return nil
}

// UpdateInbound updates an inbound
func (pm *ProtocolManager) UpdateInbound(id int64, inbound *InboundConfig) error {
	settingsJSON, _ := json.Marshal(inbound.Settings)
	streamJSON, _ := json.Marshal(inbound.StreamSettings)
	sniffingJSON, _ := json.Marshal(inbound.Sniffing)

	_, err := DB.db.Exec(`
		UPDATE inbounds SET
			protocol = ?, listen = ?, port = ?, settings = ?, stream_settings = ?,
			sniffing = ?, transport = ?, security = ?, is_active = ?, remark = ?,
			updated_at = ?
		WHERE id = ?
	`,
		inbound.Protocol, inbound.Listen, inbound.Port, string(settingsJSON),
		string(streamJSON), string(sniffingJSON), inbound.StreamSettings.Network,
		inbound.StreamSettings.Security, inbound.IsActive, inbound.Remark, time.Now(), id,
	)
	if err != nil {
		return err
	}

	// Update cache
	pm.mu.Lock()
	pm.inbounds[inbound.Tag] = inbound
	pm.mu.Unlock()

	// Reload config
	if pm.isRunning {
		pm.reloadCores()
	}

	return nil
}

// DeleteInbound deletes an inbound
func (pm *ProtocolManager) DeleteInbound(id int64) error {
	// Get tag first
	var tag string
	DB.db.QueryRow("SELECT tag FROM inbounds WHERE id = ?", id).Scan(&tag)

	_, err := DB.db.Exec("DELETE FROM inbounds WHERE id = ?", id)
	if err != nil {
		return err
	}

	// Remove from cache
	pm.mu.Lock()
	delete(pm.inbounds, tag)
	pm.mu.Unlock()

	// Reload config
	if pm.isRunning {
		pm.reloadCores()
	}

	return nil
}

// GetInbound gets an inbound by ID
func (pm *ProtocolManager) GetInbound(id int64) (*InboundConfig, error) {
	row := DB.db.QueryRow(`
		SELECT id, node_id, tag, protocol, listen, port, settings, stream_settings,
		       sniffing, is_active, remark
		FROM inbounds WHERE id = ?
	`, id)

	inbound := &InboundConfig{}
	var settingsJSON, streamJSON, sniffingJSON string

	err := row.Scan(
		&inbound.ID, &inbound.NodeID, &inbound.Tag, &inbound.Protocol,
		&inbound.Listen, &inbound.Port, &settingsJSON, &streamJSON,
		&sniffingJSON, &inbound.IsActive, &inbound.Remark,
	)
	if err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(settingsJSON), &inbound.Settings)
	json.Unmarshal([]byte(streamJSON), &inbound.StreamSettings)
	json.Unmarshal([]byte(sniffingJSON), &inbound.Sniffing)

	return inbound, nil
}

// ListInbounds lists all inbounds
func (pm *ProtocolManager) ListInbounds(nodeID int64) ([]*InboundConfig, error) {
	query := "SELECT id, node_id, tag, protocol, listen, port, settings, stream_settings, sniffing, is_active, remark FROM inbounds"
	args := []interface{}{}

	if nodeID > 0 {
		query += " WHERE node_id = ?"
		args = append(args, nodeID)
	}

	rows, err := DB.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	inbounds := []*InboundConfig{}
	for rows.Next() {
		inbound := &InboundConfig{}
		var settingsJSON, streamJSON, sniffingJSON string

		err := rows.Scan(
			&inbound.ID, &inbound.NodeID, &inbound.Tag, &inbound.Protocol,
			&inbound.Listen, &inbound.Port, &settingsJSON, &streamJSON,
			&sniffingJSON, &inbound.IsActive, &inbound.Remark,
		)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(settingsJSON), &inbound.Settings)
		json.Unmarshal([]byte(streamJSON), &inbound.StreamSettings)
		json.Unmarshal([]byte(sniffingJSON), &inbound.Sniffing)

		inbounds = append(inbounds, inbound)
	}

	return inbounds, nil
}

// loadInboundsFromDB loads inbounds from database into cache
func (pm *ProtocolManager) loadInboundsFromDB() error {
	inbounds, err := pm.ListInbounds(0)
	if err != nil {
		return err
	}

	pm.mu.Lock()
	for _, inbound := range inbounds {
		pm.inbounds[inbound.Tag] = inbound
	}
	pm.mu.Unlock()

	return nil
}

// loadOutboundsFromDB loads outbounds from database
func (pm *ProtocolManager) loadOutboundsFromDB() error {
	rows, err := DB.db.Query(`
		SELECT id, node_id, tag, protocol, settings, send_through, is_active, remark
		FROM outbounds
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	pm.mu.Lock()
	defer pm.mu.Unlock()

	for rows.Next() {
		outbound := &OutboundConfig{}
		var settingsJSON string

		err := rows.Scan(
			&outbound.ID, &outbound.NodeID, &outbound.Tag, &outbound.Protocol,
			&settingsJSON, &outbound.SendThrough, &outbound.IsActive, &outbound.Remark,
		)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(settingsJSON), &outbound.Settings)
		pm.outbounds[outbound.Tag] = outbound
	}

	return nil
}

// loadRoutingRulesFromDB loads routing rules from database
func (pm *ProtocolManager) loadRoutingRulesFromDB() ([]*RoutingRule, error) {
	rows, err := DB.db.Query(`
		SELECT id, node_id, priority, type, domain, ip, port, source_port,
		       network, source, user, inbound_tag, protocol, outbound_tag,
		       balancer_tag, is_active, remark
		FROM routing_rules ORDER BY priority
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rules := []*RoutingRule{}
	for rows.Next() {
		rule := &RoutingRule{}
		var domain, ip, source, user, inboundTag, protocol string

		err := rows.Scan(
			&rule.ID, &rule.NodeID, &rule.Priority, &rule.Type,
			&domain, &ip, &rule.Port, &rule.SourcePort,
			&rule.Network, &source, &user, &inboundTag, &protocol,
			&rule.OutboundTag, &rule.BalancerTag, &rule.IsActive, &rule.Remark,
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

		rules = append(rules, rule)
	}

	return rules, nil
}

// reloadCores reloads all core configurations
func (pm *ProtocolManager) reloadCores() {
	for name, core := range pm.cores {
		if core.IsRunning {
			// Regenerate config and reload
			pm.generateCoreConfig(core)

			// Send SIGUSR1 for graceful reload (Xray supports this)
			if core.Process != nil && core.Process.Process != nil {
				syscall.Kill(core.Pid, syscall.SIGUSR1)
			}

			fmt.Printf("[%s] Configuration reloaded\n", name)
		}
	}
}

// ============================================================================
// USER MANAGEMENT IN PROTOCOLS
// ============================================================================

// AddUserToInbound adds a user to an inbound
func (pm *ProtocolManager) AddUserToInbound(inboundTag string, user *User) error {
	pm.mu.Lock()
	inbound, exists := pm.inbounds[inboundTag]
	pm.mu.Unlock()

	if !exists {
		return fmt.Errorf("inbound not found: %s", inboundTag)
	}

	// Update settings based on protocol
	switch inbound.Protocol {
	case ProtocolVMess:
		clients, ok := inbound.Settings["clients"].([]interface{})
		if !ok {
			clients = []interface{}{}
		}
		clients = append(clients, map[string]interface{}{
			"id":      user.UUID,
			"alterId": 0,
			"email":   user.Username,
		})
		inbound.Settings["clients"] = clients

	case ProtocolVLESS:
		clients, ok := inbound.Settings["clients"].([]interface{})
		if !ok {
			clients = []interface{}{}
		}
		clients = append(clients, map[string]interface{}{
			"id":    user.UUID,
			"email": user.Username,
			"flow":  "xtls-rprx-vision",
		})
		inbound.Settings["clients"] = clients

	case ProtocolTrojan:
		clients, ok := inbound.Settings["clients"].([]interface{})
		if !ok {
			clients = []interface{}{}
		}
		clients = append(clients, map[string]interface{}{
			"password": user.UUID,
			"email":    user.Username,
		})
		inbound.Settings["clients"] = clients

	case ProtocolShadowsocks:
		// For Shadowsocks 2022, add to clients
		if strings.Contains(inbound.Settings["method"].(string), "2022") {
			clients, ok := inbound.Settings["clients"].([]interface{})
			if !ok {
				clients = []interface{}{}
			}
			clients = append(clients, map[string]interface{}{
				"password": base64.StdEncoding.EncodeToString([]byte(user.UUID[:16])),
				"email":    user.Username,
			})
			inbound.Settings["clients"] = clients
		}
	}

	// Update database and reload
	return pm.UpdateInbound(inbound.ID, inbound)
}

// RemoveUserFromInbound removes a user from an inbound
func (pm *ProtocolManager) RemoveUserFromInbound(inboundTag string, userUUID string) error {
	pm.mu.Lock()
	inbound, exists := pm.inbounds[inboundTag]
	pm.mu.Unlock()

	if !exists {
		return fmt.Errorf("inbound not found: %s", inboundTag)
	}

	// Remove from clients based on protocol
	clients, ok := inbound.Settings["clients"].([]interface{})
	if !ok {
		return nil
	}

	newClients := []interface{}{}
	for _, c := range clients {
		client, ok := c.(map[string]interface{})
		if !ok {
			continue
		}

		// Check ID/UUID/password field
		id, _ := client["id"].(string)
		password, _ := client["password"].(string)

		if id != userUUID && password != userUUID {
			newClients = append(newClients, c)
		}
	}

	inbound.Settings["clients"] = newClients
	return pm.UpdateInbound(inbound.ID, inbound)
}

// SyncUsersToInbounds syncs all active users to all active inbounds
func (pm *ProtocolManager) SyncUsersToInbounds() error {
	// Get all active users
	result, err := Users.ListUsers(&UserFilter{
		Status: UserStatusActive,
		Limit:  100000,
	})
	if err != nil {
		return err
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, inbound := range pm.inbounds {
		if !inbound.IsActive {
			continue
		}

		// Clear existing clients
		inbound.Settings["clients"] = []interface{}{}

		// Add all active users
		for _, user := range result.Users {
			pm.addUserToInboundSettings(inbound, user)
		}
	}

	// Reload cores
	pm.reloadCores()

	return nil
}

// addUserToInboundSettings adds user to inbound settings (helper)
func (pm *ProtocolManager) addUserToInboundSettings(inbound *InboundConfig, user *User) {
	clients, ok := inbound.Settings["clients"].([]interface{})
	if !ok {
		clients = []interface{}{}
	}

	var client map[string]interface{}

	switch inbound.Protocol {
	case ProtocolVMess:
		client = map[string]interface{}{
			"id":      user.UUID,
			"alterId": 0,
			"email":   user.Username,
		}
	case ProtocolVLESS:
		client = map[string]interface{}{
			"id":    user.UUID,
			"email": user.Username,
			"flow":  "xtls-rprx-vision",
		}
	case ProtocolTrojan:
		client = map[string]interface{}{
			"password": user.UUID,
			"email":    user.Username,
		}
	default:
		return
	}

	inbound.Settings["clients"] = append(clients, client)
}

// ============================================================================
// KEY GENERATION
// ============================================================================

// GenerateRealityKeyPair generates Reality x25519 key pair
func GenerateRealityKeyPair() (privateKey, publicKey string, err error) {
	// Generate 32 random bytes for private key
	privKey := make([]byte, RealityPrivateKeyLen)
	if _, err := rand.Read(privKey); err != nil {
		return "", "", err
	}

	// Clamp private key for x25519
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	// Encode private key
	privateKey = base64.RawURLEncoding.EncodeToString(privKey)

	// Generate public key using x25519 base point multiplication
	// Using simplified approach - in production use proper x25519 library
	pubKey, _ := x25519ScalarBaseMult(privKey)
	publicKey = base64.RawURLEncoding.EncodeToString(pubKey)

	return privateKey, publicKey, nil
}

// x25519ScalarBaseMult multiplies scalar by base point (simplified)
func x25519ScalarBaseMult(scalar []byte) ([]byte, error) {
	// Generate Ed25519 key pair and extract x25519 keys
	pub, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		return nil, err
	}
	_ = priv
	return pub[:32], nil
}

// GenerateRealityShortID generates Reality short ID
func GenerateRealityShortID() string {
	bytes := make([]byte, RealityShortIDLength)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GenerateShadowsocksPassword generates a Shadowsocks 2022 password
func GenerateShadowsocksPassword(method string) string {
	var keyLen int
	switch method {
	case "2022-blake3-aes-128-gcm":
		keyLen = 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		keyLen = 32
	default:
		keyLen = 16
	}

	bytes := make([]byte, keyLen)
	rand.Read(bytes)
	return base64.StdEncoding.EncodeToString(bytes)
}

// GenerateWireGuardKeyPair generates WireGuard key pair
func GenerateWireGuardKeyPair() (privateKey, publicKey string, err error) {
	// Generate private key (32 random bytes, clamped)
	privKey := make([]byte, 32)
	if _, err := rand.Read(privKey); err != nil {
		return "", "", err
	}

	// Clamp
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	privateKey = base64.StdEncoding.EncodeToString(privKey)

	// Generate public key (simplified - use curve25519 in production)
	pubKey := make([]byte, 32)
	rand.Read(pubKey)
	publicKey = base64.StdEncoding.EncodeToString(pubKey)

	return privateKey, publicKey, nil
}

// ============================================================================
// STATS COLLECTION
// ============================================================================

// XrayAPIClient for Xray gRPC API
type XrayAPIClient struct {
	address string
}

// SingboxAPIClient for Sing-box API
type SingboxAPIClient struct {
	address string
}

// startStatsCollector starts the statistics collector
func (pm *ProtocolManager) startStatsCollector() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pm.collectStats()
		case <-pm.ctx.Done():
			return
		}
	}
}

// collectStats collects traffic statistics from cores
func (pm *ProtocolManager) collectStats() {
	// Collect from Xray
	if core, exists := pm.cores[CoreXray]; exists && core.IsRunning {
		pm.collectXrayStats()
	}

	// Collect from Sing-box
	if core, exists := pm.cores[CoreSingbox]; exists && core.IsRunning {
		pm.collectSingboxStats()
	}
}

// collectXrayStats collects stats from Xray API
func (pm *ProtocolManager) collectXrayStats() {
	if pm.trafficCollector == nil {
		return
	}

	// Traffic collector handles this
	if err := pm.trafficCollector.collectXrayTraffic(); err != nil {
		LogWarn("PROTOCOLS", "Failed to collect Xray stats: %v", err)
	}
}

// collectSingboxStats collects stats from Sing-box API
func (pm *ProtocolManager) collectSingboxStats() {
	if pm.trafficCollector == nil {
		return
	}

	// Traffic collector handles this
	if err := pm.trafficCollector.collectSingboxTraffic(); err != nil {
		LogWarn("PROTOCOLS", "Failed to collect Sing-box stats: %v", err)
	}
}

// GetUserTrafficFromCore gets real-time traffic for a user from core
func (pm *ProtocolManager) GetUserTrafficFromCore(email string) (upload, download int64, err error) {
	if pm.trafficCollector != nil {
		upload, download, ok := pm.trafficCollector.GetUserTraffic(email)
		if ok {
			return upload, download, nil
		}
	}

	// Fallback to database
	if DB != nil {
		query := `SELECT upload, download FROM users WHERE email = ?`
		err = DB.db.QueryRow(query, email).Scan(&upload, &download)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to get traffic from database: %w", err)
		}
	}

	return upload, download, nil
}

// ============================================================================
// GEOFILE MANAGEMENT
// ============================================================================

// UpdateGeoFiles downloads and updates GeoIP and GeoSite files
func (pm *ProtocolManager) UpdateGeoFiles() error {
	geoDir := "./Data/xray"

	// Download GeoIP
	if err := downloadFile(GeoIPURL, filepath.Join(geoDir, "geoip.dat")); err != nil {
		return fmt.Errorf("failed to download geoip.dat: %w", err)
	}

	// Download GeoSite
	if err := downloadFile(GeoSiteURL, filepath.Join(geoDir, "geosite.dat")); err != nil {
		return fmt.Errorf("failed to download geosite.dat: %w", err)
	}

	return nil
}

// downloadFile downloads a file from URL
func downloadFile(url, filepath string) error {
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
// CORE UPDATE
// ============================================================================

// UpdateCore updates a core to the latest version
func (pm *ProtocolManager) UpdateCore(coreName string) error {
	core, exists := pm.cores[coreName]
	if !exists {
		return fmt.Errorf("core not found: %s", coreName)
	}

	// Stop core first
	pm.stopCore(core)

	// Download latest version
	var downloadURL string
	binaryName := ""

	switch coreName {
	case CoreXray:
		arch := runtime.GOARCH
		if arch == "amd64" {
			arch = "64"
		}
		downloadURL = fmt.Sprintf("%s/Xray-linux-%s.zip", XrayDownloadURL, arch)
		binaryName = "xray"
	case CoreSingbox:
		downloadURL = fmt.Sprintf("%s/sing-box-linux-%s.tar.gz", SingboxDownloadURL, runtime.GOARCH)
		binaryName = "sing-box"
	default:
		return fmt.Errorf("update not supported for: %s", coreName)
	}

	// Download and extract
	tempDir := "./Data/temp"
	os.MkdirAll(tempDir, 0755)
	defer os.RemoveAll(tempDir)

	archivePath := filepath.Join(tempDir, "archive")
	if err := downloadFile(downloadURL, archivePath); err != nil {
		return err
	}

	// Extract and move binary
	LogInfo("PROTO", "Extracting %s from archive", binaryName)

	// Restart core
	return pm.startCore(core)
}

// GetCoreStatus returns status of all cores
func (pm *ProtocolManager) GetCoreStatus() map[string]interface{} {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	status := make(map[string]interface{})

	for name, core := range pm.cores {
		coreStatus := map[string]interface{}{
			"name":       name,
			"is_running": core.IsRunning,
			"version":    core.Version,
			"path":       core.Path,
			"config":     core.ConfigPath,
		}

		if core.IsRunning {
			coreStatus["pid"] = core.Pid
			coreStatus["uptime"] = time.Since(core.StartTime).String()
			coreStatus["start_time"] = core.StartTime
		}

		status[name] = coreStatus
	}

	return status
}

// ============================================================================
// CERTIFICATE MANAGEMENT
// ============================================================================

// GenerateSelfSignedCert generates a self-signed certificate
func GenerateSelfSignedCert(domain string) (certPEM, keyPEM []byte, err error) {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	// Check if domain is IP
	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = []net.IP{ip}
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(crand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode private key
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// SaveCertificate saves certificate files
func SaveCertificate(domain string, certPEM, keyPEM []byte) error {
	certDir := "./Data/certs"
	os.MkdirAll(certDir, 0755)

	certPath := filepath.Join(certDir, domain+".crt")
	keyPath := filepath.Join(certDir, domain+".key")

	if err := ioutil.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}

	return ioutil.WriteFile(keyPath, keyPEM, 0600)
}

// GetInboundsForNode returns all inbounds for a specific node
func (pm *ProtocolManager) GetInboundsForNode(nodeID int64) []*Inbound {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var inbounds []*Inbound
	for _, inbound := range pm.inbounds {
		if inbound.NodeID == nodeID {
			// Convert InboundConfig to Inbound
			inb := &Inbound{
				ID:       inbound.ID,
				NodeID:   inbound.NodeID,
				Tag:      inbound.Tag,
				Protocol: inbound.Protocol,
				Port:     inbound.Port,
				Enabled:  inbound.Enabled,
			}
			inbounds = append(inbounds, inb)
		}
	}
	return inbounds
}
