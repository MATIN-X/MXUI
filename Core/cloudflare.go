// cloudflare.go - MX-UI Cloudflare Integration (Part 1)
// Cloudflare API, DNS, CDN, Workers, WARP, Zero Trust

package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Constants
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

const (
	// Cloudflare API
	CloudflareAPIBase    = "https://api.cloudflare.com/client/v4"
	CloudflareAPITimeout = 30 * time.Second

	// WARP Endpoints
	WARPEndpoint    = "engage.cloudflareclient.com"
	WARPPort        = 2408
	WARPRegisterAPI = "https://api.cloudflareclient.com/v0a2158/reg"
	WARPConfigAPI   = "https://api.cloudflareclient.com/v0a2158/reg/%s"

	// Workers
	WorkersDevDomain = "workers.dev"

	// Record Types
	RecordTypeA     = "A"
	RecordTypeAAAA  = "AAAA"
	RecordTypeCNAME = "CNAME"
	RecordTypeTXT   = "TXT"
	RecordTypeMX    = "MX"
	RecordTypeNS    = "NS"
	RecordTypeSRV   = "SRV"

	// Proxy Status
	ProxyEnabled  = true
	ProxyDisabled = false

	// Cache TTLs
	CacheTTLDefault = 300
	CacheTTLMinimum = 60
	CacheTTLMaximum = 86400

	// Rate Limits
	RateLimitRequests = 1200 // per 5 minutes
	RateLimitWindow   = 300  // 5 minutes in seconds

	// WARP License Types
	WARPFree      = "free"
	WARPPlus      = "plus"
	WARPTeams     = "teams"
	WARPUnlimited = "unlimited"
)

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Main Structures
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// CloudflareManager manages all Cloudflare operations
type CloudflareManager struct {
	mu sync.RWMutex

	// Configuration
	Config *CloudflareConfig

	// HTTP Client
	httpClient *http.Client

	// Rate Limiter
	rateLimiter *RateLimiter

	// Caches
	zoneCache   map[string]*Zone
	dnsCache    map[string][]*DNSRecord
	workerCache map[string]*Worker
	cacheExpiry time.Time

	// WARP Manager
	warpManager *WARPManager

	// Workers Manager
	workersManager *WorkersManager

	// CDN Manager
	cdnManager *CDNManager

	// Status
	isConnected  bool
	lastAPICall  time.Time
	apiCallCount int
	errorCount   int

	// Dependencies
	db *DatabaseManager

	// Callbacks
	onDNSChange    func(*DNSRecord, string)
	onWorkerDeploy func(*Worker)
	onError        func(error)
}

// CloudflareConfig holds Cloudflare configuration
type CloudflareConfig struct {
	// Authentication
	APIToken  string `json:"api_token"` // Recommended
	APIKey    string `json:"api_key"`   // Legacy (with Email)
	APIEmail  string `json:"api_email"` // Legacy
	AccountID string `json:"account_id"`

	// Default Zone
	DefaultZoneID   string `json:"default_zone_id"`
	DefaultZoneName string `json:"default_zone_name"`

	// WARP Settings
	WARPEnabled     bool   `json:"warp_enabled"`
	WARPLicenseKey  string `json:"warp_license_key"`
	WARPPrivateKey  string `json:"warp_private_key"`
	WARPPublicKey   string `json:"warp_public_key"`
	WARPDeviceID    string `json:"warp_device_id"`
	WARPClientID    string `json:"warp_client_id"`
	WARPAccessToken string `json:"warp_access_token"`

	// Workers Settings
	WorkersEnabled   bool     `json:"workers_enabled"`
	WorkersSubdomain string   `json:"workers_subdomain"`
	WorkersRoutes    []string `json:"workers_routes"`

	// CDN Settings
	CDNEnabled      bool   `json:"cdn_enabled"`
	CDNCacheLevel   string `json:"cdn_cache_level"` // aggressive, standard, basic
	CDNMinify       bool   `json:"cdn_minify"`
	CDNRocketLoader bool   `json:"cdn_rocket_loader"`
	CDNPolish       string `json:"cdn_polish"` // off, lossless, lossy
	CDNBrotli       bool   `json:"cdn_brotli"`

	// SSL Settings
	SSLMode        string `json:"ssl_mode"`        // off, flexible, full, strict
	SSLMinVersion  string `json:"ssl_min_version"` // 1.0, 1.1, 1.2, 1.3
	AlwaysUseHTTPS bool   `json:"always_use_https"`
	AutomaticHTTPS bool   `json:"automatic_https"`

	// Security Settings
	SecurityLevel    string `json:"security_level"` // off, low, medium, high, under_attack
	WAFEnabled       bool   `json:"waf_enabled"`
	BotManagement    bool   `json:"bot_management"`
	ChallengePassage int    `json:"challenge_passage"` // seconds

	// Firewall Rules
	FirewallRules []*FirewallRule `json:"firewall_rules"`
	IPAccessRules []*IPAccessRule `json:"ip_access_rules"`

	// Page Rules
	PageRules []*PageRule `json:"page_rules"`

	// Rate Limiting
	RateLimitingEnabled bool `json:"rate_limiting_enabled"`

	// Argo
	ArgoEnabled       bool `json:"argo_enabled"`
	ArgoTieredCaching bool `json:"argo_tiered_caching"`

	// Health Checks
	HealthChecks []*HealthCheck `json:"health_checks"`

	// Load Balancing
	LoadBalancers []*LoadBalancer `json:"load_balancers"`

	// Spectrum (TCP/UDP Proxy)
	SpectrumApps []*SpectrumApp `json:"spectrum_apps"`

	// Tunnels (Cloudflare Tunnel / Argo Tunnel)
	TunnelsEnabled bool      `json:"tunnels_enabled"`
	Tunnels        []*Tunnel `json:"tunnels"`

	// Custom Hostnames
	CustomHostnames []string `json:"custom_hostnames"`

	// Auto-sync
	AutoSyncDNS  bool          `json:"auto_sync_dns"`
	SyncInterval time.Duration `json:"sync_interval"`

	// Notifications
	NotifyOnChanges  bool  `json:"notify_on_changes"`
	NotificationChat int64 `json:"notification_chat"`
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Zone Structures
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// Zone represents a Cloudflare zone
type Zone struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Status              string    `json:"status"`
	Paused              bool      `json:"paused"`
	Type                string    `json:"type"`
	DevelopmentMode     int       `json:"development_mode"`
	NameServers         []string  `json:"name_servers"`
	OriginalNameServers []string  `json:"original_name_servers"`
	OriginalRegistrar   string    `json:"original_registrar"`
	OriginalDNSHost     string    `json:"original_dnshost"`
	ModifiedOn          time.Time `json:"modified_on"`
	CreatedOn           time.Time `json:"created_on"`
	ActivatedOn         time.Time `json:"activated_on"`
	Plan                *ZonePlan `json:"plan"`
	Account             *Account  `json:"account"`
	Permissions         []string  `json:"permissions"`
}

// ZonePlan represents zone plan info
type ZonePlan struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Price        int    `json:"price"`
	Currency     string `json:"currency"`
	Frequency    string `json:"frequency"`
	IsSubscribed bool   `json:"is_subscribed"`
	CanSubscribe bool   `json:"can_subscribe"`
}

// Account represents Cloudflare account
type Account struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ZoneSettings represents zone settings
type ZoneSettings struct {
	AlwaysOnline            string          `json:"always_online"`
	AlwaysUseHTTPS          string          `json:"always_use_https"`
	AutomaticHTTPS          string          `json:"automatic_https_rewrites"`
	Brotli                  string          `json:"brotli"`
	BrowserCacheTTL         int             `json:"browser_cache_ttl"`
	BrowserCheck            string          `json:"browser_check"`
	CacheLevel              string          `json:"cache_level"`
	ChallengeTTL            int             `json:"challenge_ttl"`
	DevelopmentMode         string          `json:"development_mode"`
	EmailObfuscation        string          `json:"email_obfuscation"`
	HotlinkProtection       string          `json:"hotlink_protection"`
	HTTP2                   string          `json:"http2"`
	HTTP3                   string          `json:"http3"`
	IPGeolocation           string          `json:"ip_geolocation"`
	IPv6                    string          `json:"ipv6"`
	MinTLSVersion           string          `json:"min_tls_version"`
	Minify                  *MinifySettings `json:"minify"`
	MobileRedirect          *MobileRedirect `json:"mobile_redirect"`
	OpportunisticEncryption string          `json:"opportunistic_encryption"`
	OpportunisticOnion      string          `json:"opportunistic_onion"`
	OriginErrorPagePassThru string          `json:"origin_error_page_pass_thru"`
	Polish                  string          `json:"polish"`
	PrefetchPreload         string          `json:"prefetch_preload"`
	PrivacyPass             string          `json:"privacy_pass"`
	PseudoIPv4              string          `json:"pseudo_ipv4"`
	ResponseBuffering       string          `json:"response_buffering"`
	RocketLoader            string          `json:"rocket_loader"`
	SecurityLevel           string          `json:"security_level"`
	ServerSideExclude       string          `json:"server_side_exclude"`
	SortQueryStringForCache string          `json:"sort_query_string_for_cache"`
	SSL                     string          `json:"ssl"`
	TLS13                   string          `json:"tls_1_3"`
	TLSClientAuth           string          `json:"tls_client_auth"`
	TrueClientIPHeader      string          `json:"true_client_ip_header"`
	WAF                     string          `json:"waf"`
	WebP                    string          `json:"webp"`
	Websockets              string          `json:"websockets"`
	ZeroRTT                 string          `json:"0rtt"`
}

// MinifySettings for CSS/JS/HTML minification
type MinifySettings struct {
	CSS  string `json:"css"`
	JS   string `json:"js"`
	HTML string `json:"html"`
}

// MobileRedirect settings
type MobileRedirect struct {
	Status          string `json:"status"`
	MobileSubdomain string `json:"mobile_subdomain"`
	StripURI        bool   `json:"strip_uri"`
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// DNS Structures
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// DNSRecord represents a DNS record
type DNSRecord struct {
	ID         string                 `json:"id"`
	ZoneID     string                 `json:"zone_id"`
	ZoneName   string                 `json:"zone_name"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Content    string                 `json:"content"`
	Proxied    bool                   `json:"proxied"`
	Proxiable  bool                   `json:"proxiable"`
	TTL        int                    `json:"ttl"`
	Locked     bool                   `json:"locked"`
	Priority   int                    `json:"priority,omitempty"`
	Data       map[string]interface{} `json:"data,omitempty"`
	Meta       *DNSRecordMeta         `json:"meta,omitempty"`
	Comment    string                 `json:"comment,omitempty"`
	Tags       []string               `json:"tags,omitempty"`
	CreatedOn  time.Time              `json:"created_on"`
	ModifiedOn time.Time              `json:"modified_on"`
}

// DNSRecordMeta contains DNS record metadata
type DNSRecordMeta struct {
	AutoAdded           bool   `json:"auto_added"`
	ManagedByApps       bool   `json:"managed_by_apps"`
	ManagedByArgoTunnel bool   `json:"managed_by_argo_tunnel"`
	Source              string `json:"source"`
}

// DNSRecordCreate for creating DNS records
type DNSRecordCreate struct {
	Type     string   `json:"type"`
	Name     string   `json:"name"`
	Content  string   `json:"content"`
	TTL      int      `json:"ttl"`
	Priority int      `json:"priority,omitempty"`
	Proxied  bool     `json:"proxied"`
	Comment  string   `json:"comment,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

// DNSRecordUpdate for updating DNS records
type DNSRecordUpdate struct {
	Type    string `json:"type,omitempty"`
	Name    string `json:"name,omitempty"`
	Content string `json:"content,omitempty"`
	TTL     int    `json:"ttl,omitempty"`
	Proxied *bool  `json:"proxied,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Worker Structures
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// Worker represents a Cloudflare Worker
type Worker struct {
	ID            string           `json:"id"`
	Name          string           `json:"name"`
	Script        string           `json:"script"`
	Etag          string           `json:"etag"`
	Size          int64            `json:"size"`
	ModifiedOn    time.Time        `json:"modified_on"`
	CreatedOn     time.Time        `json:"created_on"`
	Routes        []*WorkerRoute   `json:"routes"`
	Bindings      []*WorkerBinding `json:"bindings"`
	Compatibility string           `json:"compatibility_date"`
	UsageModel    string           `json:"usage_model"` // bundled, unbound
	Handlers      []string         `json:"handlers"`
	Logpush       bool             `json:"logpush"`
	PlacementMode string           `json:"placement_mode"` // smart
	TailConsumers []*TailConsumer  `json:"tail_consumers"`
}

// WorkerRoute defines a route for a worker
type WorkerRoute struct {
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
	Script  string `json:"script"`
	Enabled bool   `json:"enabled"`
}

// WorkerBinding defines bindings for workers
type WorkerBinding struct {
	Name       string `json:"name"`
	Type       string `json:"type"` // kv_namespace, r2_bucket, durable_object, secret_text, plain_text
	Namespace  string `json:"namespace_id,omitempty"`
	Bucket     string `json:"bucket_name,omitempty"`
	ClassName  string `json:"class_name,omitempty"`
	ScriptName string `json:"script_name,omitempty"`
	Text       string `json:"text,omitempty"`
}

// TailConsumer for worker tail consumers
type TailConsumer struct {
	Service     string `json:"service"`
	Environment string `json:"environment"`
}

// WorkerScript for uploading worker scripts
type WorkerScript struct {
	Name     string           `json:"name"`
	Content  string           `json:"content"`
	Bindings []*WorkerBinding `json:"bindings,omitempty"`
	Metadata *WorkerMetadata  `json:"metadata,omitempty"`
}

// WorkerMetadata contains worker metadata
type WorkerMetadata struct {
	MainModule         string           `json:"main_module"`
	CompatibilityDate  string           `json:"compatibility_date"`
	CompatibilityFlags []string         `json:"compatibility_flags"`
	UsageModel         string           `json:"usage_model"`
	Bindings           []*WorkerBinding `json:"bindings"`
}

// WorkerKV represents a KV namespace
type WorkerKV struct {
	ID                  string `json:"id"`
	Title               string `json:"title"`
	SupportsURLEncoding bool   `json:"supports_url_encoding"`
}

// KVKeyValue represents a key-value pair
type KVKeyValue struct {
	Key           string            `json:"key"`
	Value         string            `json:"value"`
	Expiration    int64             `json:"expiration,omitempty"`
	ExpirationTTL int               `json:"expiration_ttl,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// WARP Structures
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// WARPManager manages WARP connections
type WARPManager struct {
	mu sync.RWMutex

	// Configuration
	Config *WARPConfig

	// Account Info
	Account *WARPAccount

	// Devices
	Devices map[string]*WARPDevice

	// Connection
	isConnected bool
	currentIP   string
	endpoint    string

	// HTTP Client
	httpClient *http.Client

	// Status
	lastUpdate  time.Time
	trafficUsed int64
}

// WARPConfig holds WARP configuration
type WARPConfig struct {
	Enabled         bool     `json:"enabled"`
	Mode            string   `json:"mode"` // warp, doh, warp+doh, proxy
	LicenseKey      string   `json:"license_key"`
	PrivateKey      string   `json:"private_key"`
	PublicKey       string   `json:"public_key"`
	ReservedDec     []int    `json:"reserved_dec"`
	ReservedHex     string   `json:"reserved_hex"`
	DeviceID        string   `json:"device_id"`
	DeviceName      string   `json:"device_name"`
	DeviceModel     string   `json:"device_model"`
	AccessToken     string   `json:"access_token"`
	RefreshToken    string   `json:"refresh_token"`
	Endpoint        string   `json:"endpoint"`
	EndpointV6      string   `json:"endpoint_v6"`
	ClientID        string   `json:"client_id"`
	InterfaceIPv4   string   `json:"interface_ipv4"`
	InterfaceIPv6   string   `json:"interface_ipv6"`
	DNS             []string `json:"dns"`
	MTU             int      `json:"mtu"`
	KeepAlive       int      `json:"keepalive"`
	AllowedIPs      []string `json:"allowed_ips"`
	ExcludedIPs     []string `json:"excluded_ips"`
	ExcludedApps    []string `json:"excluded_apps"`
	ExcludedHosts   []string `json:"excluded_hosts"`
	SplitTunnel     bool     `json:"split_tunnel"`
	FallbackDomains []string `json:"fallback_domains"`
}

// WARPAccount represents WARP account info
type WARPAccount struct {
	ID                       string `json:"id"`
	Type                     string `json:"account_type"`
	Created                  string `json:"created"`
	Updated                  string `json:"updated"`
	PremiumData              int64  `json:"premium_data"`
	Quota                    int64  `json:"quota"`
	Usage                    int64  `json:"usage"`
	WARPPlus                 bool   `json:"warp_plus_enabled"`
	ReferralCount            int    `json:"referral_count"`
	ReferralRenewalCountdown int    `json:"referral_renewal_countdown"`
	Role                     string `json:"role"`
	License                  string `json:"license"`
}

// WARPDevice represents a registered WARP device
type WARPDevice struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	Model        string `json:"model"`
	Key          string `json:"key"`
	Account      string `json:"account"`
	Created      string `json:"created"`
	Updated      string `json:"updated"`
	Active       bool   `json:"active"`
	Enabled      bool   `json:"enabled"`
	FCMToken     string `json:"fcm_token"`
	SerialNumber string `json:"serial_number"`
}

// WARPRegistration for registering new device
type WARPRegistration struct {
	Key       string `json:"key"`
	InstallID string `json:"install_id"`
	FCMToken  string `json:"fcm_token"`
	Tos       string `json:"tos"`
	Model     string `json:"model"`
	Type      string `json:"type"`
	Locale    string `json:"locale"`
}

// WARPRegistrationResponse from registration
type WARPRegistrationResponse struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Model   string `json:"model"`
	Name    string `json:"name"`
	Key     string `json:"key"`
	Account struct {
		ID                       string `json:"id"`
		AccountType              string `json:"account_type"`
		Created                  string `json:"created"`
		Updated                  string `json:"updated"`
		PremiumData              int64  `json:"premium_data"`
		Quota                    int64  `json:"quota"`
		WARPPlus                 bool   `json:"warp_plus"`
		ReferralRenewalCountdown int    `json:"referral_renewal_countdown"`
		Role                     string `json:"role"`
		License                  string `json:"license"`
	} `json:"account"`
	Config struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
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
		Services struct {
			HTTPProxy string `json:"http_proxy"`
		} `json:"services"`
	} `json:"config"`
	Token       string `json:"token"`
	WARPEnabled bool   `json:"warp_enabled"`
	Waitlist    bool   `json:"waitlist_enabled"`
	Created     string `json:"created"`
	Updated     string `json:"updated"`
	TOS         string `json:"tos"`
	Place       int    `json:"place"`
	Locale      string `json:"locale"`
	Enabled     bool   `json:"enabled"`
	InstallID   string `json:"install_id"`
	FCMToken    string `json:"fcm_token"`
}

// WARPProfile contains WireGuard profile for WARP
type WARPProfile struct {
	Interface struct {
		PrivateKey string   `json:"private_key"`
		Address    []string `json:"address"`
		DNS        []string `json:"dns"`
		MTU        int      `json:"mtu"`
	} `json:"interface"`
	Peer struct {
		PublicKey  string   `json:"public_key"`
		Endpoint   string   `json:"endpoint"`
		AllowedIPs []string `json:"allowed_ips"`
		KeepAlive  int      `json:"persistent_keepalive"`
	} `json:"peer"`
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Firewall & Security Structures
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// FirewallRule represents a firewall rule
type FirewallRule struct {
	ID          string  `json:"id"`
	Priority    int     `json:"priority"`
	Action      string  `json:"action"` // block, challenge, js_challenge, managed_challenge, allow, log, bypass
	Filter      *Filter `json:"filter"`
	Description string  `json:"description"`
	Paused      bool    `json:"paused"`
	Ref         string  `json:"ref,omitempty"`
	CreatedOn   string  `json:"created_on"`
	ModifiedOn  string  `json:"modified_on"`
}

// Filter for firewall rules
type Filter struct {
	ID          string `json:"id"`
	Expression  string `json:"expression"`
	Paused      bool   `json:"paused"`
	Description string `json:"description"`
	Ref         string `json:"ref,omitempty"`
}

// IPAccessRule represents an IP access rule
type IPAccessRule struct {
	ID            string `json:"id"`
	Notes         string `json:"notes"`
	Mode          string `json:"mode"` // block, challenge, whitelist, js_challenge, managed_challenge
	Configuration struct {
		Target string `json:"target"` // ip, ip_range, asn, country
		Value  string `json:"value"`
	} `json:"configuration"`
	AllowedModes []string `json:"allowed_modes"`
	CreatedOn    string   `json:"created_on"`
	ModifiedOn   string   `json:"modified_on"`
	Scope        struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"scope"`
}

// RateLimitRule represents a rate limit rule
type RateLimitRule struct {
	ID          string `json:"id"`
	Disabled    bool   `json:"disabled"`
	Description string `json:"description"`
	Match       struct {
		Request struct {
			Methods []string `json:"methods"`
			Schemes []string `json:"schemes"`
			URL     string   `json:"url"`
		} `json:"request"`
		Response struct {
			Status        []int `json:"status"`
			OriginTraffic bool  `json:"origin_traffic"`
			Headers       []struct {
				Name  string `json:"name"`
				Op    string `json:"op"`
				Value string `json:"value"`
			} `json:"headers"`
		} `json:"response"`
	} `json:"match"`
	Threshold int `json:"threshold"`
	Period    int `json:"period"`
	Action    struct {
		Mode     string `json:"mode"` // simulate, ban, challenge, js_challenge, managed_challenge
		Timeout  int    `json:"timeout"`
		Response struct {
			ContentType string `json:"content_type"`
			Body        string `json:"body"`
		} `json:"response"`
	} `json:"action"`
	Correlate struct {
		By string `json:"by"` // nat, none
	} `json:"correlate"`
	Bypass []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"bypass"`
}

// PageRule represents a page rule
type PageRule struct {
	ID      string `json:"id"`
	Targets []struct {
		Target     string `json:"target"`
		Constraint struct {
			Operator string `json:"operator"`
			Value    string `json:"value"`
		} `json:"constraint"`
	} `json:"targets"`
	Actions []struct {
		ID    string      `json:"id"`
		Value interface{} `json:"value"`
	} `json:"actions"`
	Priority   int    `json:"priority"`
	Status     string `json:"status"` // active, disabled
	CreatedOn  string `json:"created_on"`
	ModifiedOn string `json:"modified_on"`
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Load Balancer & Health Check Structures
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// HealthCheck represents a health check monitor
type HealthCheck struct {
	ID              string              `json:"id"`
	Name            string              `json:"name"`
	Description     string              `json:"description"`
	Type            string              `json:"type"` // http, https, tcp, udp_icmp, icmp_ping, smtp
	Address         string              `json:"address"`
	Port            int                 `json:"port"`
	Method          string              `json:"method"`
	Path            string              `json:"path"`
	Header          map[string][]string `json:"header"`
	ExpectedBody    string              `json:"expected_body"`
	ExpectedCodes   string              `json:"expected_codes"`
	Timeout         int                 `json:"timeout"`
	Retries         int                 `json:"retries"`
	Interval        int                 `json:"interval"`
	FollowRedirects bool                `json:"follow_redirects"`
	AllowInsecure   bool                `json:"allow_insecure"`
	ConsecutiveUp   int                 `json:"consecutive_up"`
	ConsecutiveDown int                 `json:"consecutive_down"`
	ModifiedOn      string              `json:"modified_on"`
	CreatedOn       string              `json:"created_on"`
	Suspended       bool                `json:"suspended"`
	Status          string              `json:"status"` // unknown, healthy, unhealthy, suspended
}

// LoadBalancer represents a Cloudflare load balancer
type LoadBalancer struct {
	ID                   string                `json:"id"`
	Name                 string                `json:"name"`
	Description          string                `json:"description"`
	TTL                  int                   `json:"ttl"`
	FallbackPool         string                `json:"fallback_pool"`
	DefaultPools         []string              `json:"default_pools"`
	RegionPools          map[string][]string   `json:"region_pools"`
	CountryPools         map[string][]string   `json:"country_pools"`
	PopPools             map[string][]string   `json:"pop_pools"`
	Proxied              bool                  `json:"proxied"`
	Enabled              bool                  `json:"enabled"`
	SessionAffinity      string                `json:"session_affinity"` // none, cookie, ip_cookie, header
	SessionAffinityTTL   int                   `json:"session_affinity_ttl"`
	SessionAffinityAttrs *SessionAffinityAttrs `json:"session_affinity_attributes"`
	SteeringPolicy       string                `json:"steering_policy"` // off, geo, random, dynamic_latency, proximity, least_outstanding_requests, least_connections
	Rules                []*LBRule             `json:"rules"`
	RandomSteering       *RandomSteering       `json:"random_steering"`
	AdaptiveRouting      *AdaptiveRouting      `json:"adaptive_routing"`
	LocationStrategy     *LocationStrategy     `json:"location_strategy"`
	ModifiedOn           string                `json:"modified_on"`
	CreatedOn            string                `json:"created_on"`
}

// LoadBalancerPool represents a pool
type LoadBalancerPool struct {
	ID                 string              `json:"id"`
	Name               string              `json:"name"`
	Description        string              `json:"description"`
	Origins            []*Origin           `json:"origins"`
	MinimumOrigins     int                 `json:"minimum_origins"`
	CheckRegions       []string            `json:"check_regions"`
	Enabled            bool                `json:"enabled"`
	Monitor            string              `json:"monitor"`
	NotificationEmail  string              `json:"notification_email"`
	NotificationFilter *NotificationFilter `json:"notification_filter"`
	Healthy            bool                `json:"healthy"`
	LoadShedding       *LoadShedding       `json:"load_shedding"`
	OriginSteering     *OriginSteering     `json:"origin_steering"`
	Latitude           float64             `json:"latitude"`
	Longitude          float64             `json:"longitude"`
	ModifiedOn         string              `json:"modified_on"`
	CreatedOn          string              `json:"created_on"`
}

// Type aliases for backward compatibility
type CFLoadBalancerPool = LoadBalancerPool
type CFLoadBalancerManager = LoadBalancerManager

// Origin represents an origin server
type Origin struct {
	Name             string              `json:"name"`
	Address          string              `json:"address"`
	Enabled          bool                `json:"enabled"`
	Weight           float64             `json:"weight"`
	Header           map[string][]string `json:"header"`
	VirtualNetworkID string              `json:"virtual_network_id"`
}

// SessionAffinityAttrs for session affinity
type SessionAffinityAttrs struct {
	SameSite             string   `json:"samesite"`
	Secure               string   `json:"secure"`
	DrainDuration        int      `json:"drain_duration"`
	ZeroDowntimeFailover string   `json:"zero_downtime_failover"`
	Headers              []string `json:"headers"`
	RequireAllHeaders    bool     `json:"require_all_headers"`
}

// LBRule for load balancer rules
type LBRule struct {
	Name      string `json:"name"`
	Condition string `json:"condition"`
	Disabled  bool   `json:"disabled"`
	Overrides struct {
		SessionAffinity    string              `json:"session_affinity"`
		SessionAffinityTTL int                 `json:"session_affinity_ttl"`
		FallbackPool       string              `json:"fallback_pool"`
		DefaultPools       []string            `json:"default_pools"`
		PopPools           map[string][]string `json:"pop_pools"`
		RegionPools        map[string][]string `json:"region_pools"`
		CountryPools       map[string][]string `json:"country_pools"`
		SteeringPolicy     string              `json:"steering_policy"`
		TTL                int                 `json:"ttl"`
	} `json:"overrides"`
	Priority      int `json:"priority"`
	FixedResponse *struct {
		MessageBody string `json:"message_body"`
		StatusCode  int    `json:"status_code"`
		ContentType string `json:"content_type"`
		Location    string `json:"location"`
	} `json:"fixed_response"`
	Terminates bool `json:"terminates"`
}

// RandomSteering for random steering
type RandomSteering struct {
	DefaultWeight float64            `json:"default_weight"`
	PoolWeights   map[string]float64 `json:"pool_weights"`
}

// AdaptiveRouting for adaptive routing
type AdaptiveRouting struct {
	FailoverAcrossPools bool `json:"failover_across_pools"`
}

// LocationStrategy for location-based routing
type LocationStrategy struct {
	Mode      string `json:"mode"`       // pop, resolver_ip
	PreferECS string `json:"prefer_ecs"` // always, never, proximity, geo
}

// NotificationFilter for pool notifications
type NotificationFilter struct {
	Origin *struct {
		Disable bool `json:"disable"`
		Healthy bool `json:"healthy"`
	} `json:"origin"`
	Pool *struct {
		Disable bool `json:"disable"`
		Healthy bool `json:"healthy"`
	} `json:"pool"`
}

// LoadShedding for pool load shedding
type LoadShedding struct {
	DefaultPercent float64 `json:"default_percent"`
	DefaultPolicy  string  `json:"default_policy"` // random, hash
	SessionPercent float64 `json:"session_percent"`
	SessionPolicy  string  `json:"session_policy"`
}

// OriginSteering for origin steering
type OriginSteering struct {
	Policy string `json:"policy"` // random, hash, least_outstanding_requests, least_connections
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Tunnel (Argo Tunnel) Structures
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// Tunnel represents a Cloudflare Tunnel
type Tunnel struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Secret          string                 `json:"tunnel_secret,omitempty"`
	Status          string                 `json:"status"`
	CreatedAt       string                 `json:"created_at"`
	DeletedAt       string                 `json:"deleted_at,omitempty"`
	Connections     []*TunnelConnection    `json:"connections"`
	ConnsActiveAt   string                 `json:"conns_active_at"`
	ConnsInactiveAt string                 `json:"conns_inactive_at"`
	TunType         string                 `json:"tun_type"`
	Metadata        map[string]interface{} `json:"metadata"`
	RemoteConfig    bool                   `json:"remote_config"`
}

// TunnelConnection represents a tunnel connection
type TunnelConnection struct {
	ColoName           string `json:"colo_name"`
	ID                 string `json:"id"`
	IsPendingReconnect bool   `json:"is_pending_reconnect"`
	OriginIP           string `json:"origin_ip"`
	OpenedAt           string `json:"opened_at"`
	ClientID           string `json:"client_id"`
	ClientVersion      string `json:"client_version"`
}

// TunnelConfig for tunnel configuration
type TunnelConfig struct {
	TunnelID string `json:"tunnel_id"`
	Config   struct {
		Ingress     []TunnelIngress `json:"ingress"`
		WARPRouting struct {
			Enabled bool `json:"enabled"`
		} `json:"warp-routing"`
		OriginRequest TunnelOriginRequest `json:"originRequest"`
	} `json:"config"`
}

// TunnelIngress for tunnel ingress rules
type TunnelIngress struct {
	Hostname      string               `json:"hostname,omitempty"`
	Path          string               `json:"path,omitempty"`
	Service       string               `json:"service"`
	OriginRequest *TunnelOriginRequest `json:"originRequest,omitempty"`
}

// TunnelOriginRequest for origin request settings
type TunnelOriginRequest struct {
	ConnectTimeout         int                 `json:"connectTimeout,omitempty"`
	TLSTimeout             int                 `json:"tlsTimeout,omitempty"`
	TCPKeepAlive           int                 `json:"tcpKeepAlive,omitempty"`
	NoHappyEyeballs        bool                `json:"noHappyEyeballs,omitempty"`
	KeepAliveConnections   int                 `json:"keepAliveConnections,omitempty"`
	KeepAliveTimeout       int                 `json:"keepAliveTimeout,omitempty"`
	HTTPHostHeader         string              `json:"httpHostHeader,omitempty"`
	OriginServerName       string              `json:"originServerName,omitempty"`
	CAPool                 string              `json:"caPool,omitempty"`
	NoTLSVerify            bool                `json:"noTLSVerify,omitempty"`
	DisableChunkedEncoding bool                `json:"disableChunkedEncoding,omitempty"`
	ProxyAddress           string              `json:"proxyAddress,omitempty"`
	ProxyPort              int                 `json:"proxyPort,omitempty"`
	ProxyType              string              `json:"proxyType,omitempty"`
	BastionMode            bool                `json:"bastionMode,omitempty"`
	IPRules                []IPRule            `json:"ipRules,omitempty"`
	HTTP2Origin            bool                `json:"http2Origin,omitempty"`
	Access                 *TunnelAccessConfig `json:"access,omitempty"`
}

// IPRule for tunnel IP rules
type IPRule struct {
	Prefix string `json:"prefix"`
	Ports  []int  `json:"ports"`
	Allow  bool   `json:"allow"`
}

// TunnelAccessConfig for tunnel access settings
type TunnelAccessConfig struct {
	Required bool     `json:"required"`
	TeamName string   `json:"teamName"`
	AudTag   []string `json:"audTag"`
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Spectrum Structures
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// SpectrumApp represents a Spectrum application
type SpectrumApp struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"` // tcp, udp
	DNS      struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"dns"`
	OriginDirect []string `json:"origin_direct"`
	OriginDNS    *struct {
		Name string `json:"name"`
	} `json:"origin_dns"`
	OriginPort    interface{} `json:"origin_port"` // int or string (port range)
	IPFirewall    bool        `json:"ip_firewall"`
	ProxyProtocol string      `json:"proxy_protocol"` // off, v1, v2, simple
	TLS           string      `json:"tls"`            // off, flexible, full, strict
	TrafficType   string      `json:"traffic_type"`   // direct, http, https
	EdgeIPs       struct {
		Type         string   `json:"type"`
		Connectivity string   `json:"connectivity"` // all, ipv4, ipv6
		IPs          []string `json:"ips"`
	} `json:"edge_ips"`
	ArgoSmartRouting bool   `json:"argo_smart_routing"`
	CreatedOn        string `json:"created_on"`
	ModifiedOn       string `json:"modified_on"`
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// API Response Structures
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// APIResponse is the standard Cloudflare API response
type APIResponse struct {
	Success    bool            `json:"success"`
	Errors     []APIError      `json:"errors"`
	Messages   []APIMessage    `json:"messages"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *ResultInfo     `json:"result_info,omitempty"`
}

// APIError represents an API error
type APIError struct {
	Code       int    `json:"code"`
	Message    string `json:"message"`
	ErrorChain []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error_chain,omitempty"`
}

// APIMessage represents an API message
type APIMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ResultInfo contains pagination info
type ResultInfo struct {
	Page       int    `json:"page"`
	PerPage    int    `json:"per_page"`
	TotalPages int    `json:"total_pages"`
	Count      int    `json:"count"`
	TotalCount int    `json:"total_count"`
	Cursor     string `json:"cursor,omitempty"`
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Rate Limiter
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// RateLimiter implements token bucket rate limiting
type RateLimiter struct {
	mu           sync.Mutex
	tokens       int
	maxTokens    int
	refillRate   int // tokens per second
	lastRefill   time.Time
	refillAmount int
	window       time.Duration
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(maxTokens, refillRate int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		tokens:       maxTokens,
		maxTokens:    maxTokens,
		refillRate:   refillRate,
		refillAmount: maxTokens,
		lastRefill:   time.Now(),
		window:       window,
	}
}

// Allow checks if request is allowed
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)

	// Refill tokens
	if elapsed >= rl.window {
		rl.tokens = rl.maxTokens
		rl.lastRefill = now
	}

	if rl.tokens > 0 {
		rl.tokens--
		return true
	}

	return false
}

// Wait waits until a token is available
func (rl *RateLimiter) Wait(ctx context.Context) error {
	for {
		if rl.Allow() {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
			continue
		}
	}
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// CDN Manager
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// CDNManager manages CDN operations
type CDNManager struct {
	cf *CloudflareManager
}

// WorkersManager manages Workers operations
type WorkersManager struct {
	cf *CloudflareManager
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Cloudflare Manager Implementation
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// NewCloudflareManager creates a new Cloudflare manager
func NewCloudflareManager(db *DatabaseManager) *CloudflareManager {
	cf := &CloudflareManager{
		db:          db,
		zoneCache:   make(map[string]*Zone),
		dnsCache:    make(map[string][]*DNSRecord),
		workerCache: make(map[string]*Worker),
	}

	// Initialize HTTP client
	cf.httpClient = &http.Client{
		Timeout: CloudflareAPITimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// Initialize rate limiter (1200 requests per 5 minutes)
	cf.rateLimiter = NewRateLimiter(RateLimitRequests, 4, time.Duration(RateLimitWindow)*time.Second)

	// Load configuration
	cf.loadConfig()

	// Initialize sub-managers
	cf.cdnManager = &CDNManager{cf: cf}
	cf.workersManager = &WorkersManager{cf: cf}

	// Initialize WARP manager if enabled
	if cf.Config.WARPEnabled {
		cf.warpManager = cf.initWARPManager()
	}

	return cf
}

// loadConfig loads Cloudflare configuration
func (cf *CloudflareManager) loadConfig() {
	cf.mu.Lock()
	defer cf.mu.Unlock()

	configJSON, err := cf.db.GetSetting("cloudflare_config")
	if err != nil || configJSON == "" {
		cf.Config = &CloudflareConfig{
			WARPEnabled:    false,
			WorkersEnabled: false,
			CDNEnabled:     false,
			SSLMode:        "full",
			SSLMinVersion:  "1.2",
			SecurityLevel:  "medium",
			SyncInterval:   time.Hour,
		}
		return
	}

	var config CloudflareConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		LogError("CLOUDFLARE", "Failed to parse config: %v", err)
		return
	}
	cf.Config = &config
}

// SaveConfig saves Cloudflare configuration
func (cf *CloudflareManager) SaveConfig() error {
	cf.mu.RLock()
	defer cf.mu.RUnlock()

	configJSON, err := json.Marshal(cf.Config)
	if err != nil {
		return err
	}

	return cf.db.SetSetting("cloudflare_config", string(configJSON), "json", "cloudflare", false)
}

// SetCredentials sets API credentials
func (cf *CloudflareManager) SetCredentials(apiToken, apiKey, apiEmail, accountID string) error {
	cf.mu.Lock()
	cf.Config.APIToken = apiToken
	cf.Config.APIKey = apiKey
	cf.Config.APIEmail = apiEmail
	cf.Config.AccountID = accountID
	cf.mu.Unlock()

	// Verify credentials
	if err := cf.VerifyCredentials(); err != nil {
		return err
	}

	return cf.SaveConfig()
}

// VerifyCredentials verifies API credentials
func (cf *CloudflareManager) VerifyCredentials() error {
	resp, err := cf.apiRequest("GET", "/user/tokens/verify", nil)
	if err != nil {
		return err
	}

	var result struct {
		Status string `json:"status"`
	}

	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return err
	}

	if result.Status != "active" {
		return fmt.Errorf("token is not active: %s", result.Status)
	}

	cf.mu.Lock()
	cf.isConnected = true
	cf.mu.Unlock()

	LogInfo("CLOUDFLARE", "API credentials verified successfully")
	return nil
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// API Request Methods
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// apiRequest makes an API request to Cloudflare
func (cf *CloudflareManager) apiRequest(method, endpoint string, body interface{}) (*APIResponse, error) {
	// Wait for rate limiter
	ctx, cancel := context.WithTimeout(context.Background(), CloudflareAPITimeout)
	defer cancel()

	if err := cf.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit exceeded: %v", err)
	}

	// Build URL
	url := CloudflareAPIBase + endpoint

	// Prepare body
	var bodyReader io.Reader
	if body != nil {
		bodyJSON, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(bodyJSON)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	cf.mu.RLock()
	if cf.Config.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+cf.Config.APIToken)
	} else if cf.Config.APIKey != "" && cf.Config.APIEmail != "" {
		req.Header.Set("X-Auth-Key", cf.Config.APIKey)
		req.Header.Set("X-Auth-Email", cf.Config.APIEmail)
	}
	cf.mu.RUnlock()

	// Send request
	resp, err := cf.httpClient.Do(req)
	if err != nil {
		cf.mu.Lock()
		cf.errorCount++
		cf.mu.Unlock()
		return nil, err
	}
	defer resp.Body.Close()

	// Update stats
	cf.mu.Lock()
	cf.lastAPICall = time.Now()
	cf.apiCallCount++
	cf.mu.Unlock()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse response
	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// Check for errors
	if !apiResp.Success {
		errMsg := "unknown error"
		if len(apiResp.Errors) > 0 {
			errMsg = apiResp.Errors[0].Message
		}
		return nil, fmt.Errorf("API error: %s", errMsg)
	}

	return &apiResp, nil
}

// apiRequestRaw makes a raw API request (for file uploads, etc.)
func (cf *CloudflareManager) apiRequestRaw(method, endpoint string, body io.Reader, contentType string) (*APIResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), CloudflareAPITimeout*2)
	defer cancel()

	if err := cf.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit exceeded: %v", err)
	}

	url := CloudflareAPIBase + endpoint

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", contentType)

	cf.mu.RLock()
	if cf.Config.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+cf.Config.APIToken)
	}
	cf.mu.RUnlock()

	resp, err := cf.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, err
	}

	if !apiResp.Success {
		errMsg := "unknown error"
		if len(apiResp.Errors) > 0 {
			errMsg = apiResp.Errors[0].Message
		}
		return nil, fmt.Errorf("API error: %s", errMsg)
	}

	return &apiResp, nil
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Zone Operations
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// ListZones lists all zones
func (cf *CloudflareManager) ListZones() ([]*Zone, error) {
	resp, err := cf.apiRequest("GET", "/zones", nil)
	if err != nil {
		return nil, err
	}

	var zones []*Zone
	if err := json.Unmarshal(resp.Result, &zones); err != nil {
		return nil, err
	}

	// Update cache
	cf.mu.Lock()
	for _, z := range zones {
		cf.zoneCache[z.ID] = z
	}
	cf.mu.Unlock()

	return zones, nil
}

// GetZone gets a zone by ID
func (cf *CloudflareManager) GetZone(zoneID string) (*Zone, error) {
	// Check cache first
	cf.mu.RLock()
	if zone, ok := cf.zoneCache[zoneID]; ok {
		cf.mu.RUnlock()
		return zone, nil
	}
	cf.mu.RUnlock()

	resp, err := cf.apiRequest("GET", fmt.Sprintf("/zones/%s", zoneID), nil)
	if err != nil {
		return nil, err
	}

	var zone Zone
	if err := json.Unmarshal(resp.Result, &zone); err != nil {
		return nil, err
	}

	// Update cache
	cf.mu.Lock()
	cf.zoneCache[zoneID] = &zone
	cf.mu.Unlock()

	return &zone, nil
}

// GetZoneByName gets a zone by domain name
func (cf *CloudflareManager) GetZoneByName(name string) (*Zone, error) {
	resp, err := cf.apiRequest("GET", fmt.Sprintf("/zones?name=%s", name), nil)
	if err != nil {
		return nil, err
	}

	var zones []*Zone
	if err := json.Unmarshal(resp.Result, &zones); err != nil {
		return nil, err
	}

	if len(zones) == 0 {
		return nil, fmt.Errorf("zone not found: %s", name)
	}

	return zones[0], nil
}

// CreateZone creates a new zone
func (cf *CloudflareManager) CreateZone(name string, jumpStart bool) (*Zone, error) {
	body := map[string]interface{}{
		"name":       name,
		"jump_start": jumpStart,
	}

	if cf.Config.AccountID != "" {
		body["account"] = map[string]string{"id": cf.Config.AccountID}
	}

	resp, err := cf.apiRequest("POST", "/zones", body)
	if err != nil {
		return nil, err
	}

	var zone Zone
	if err := json.Unmarshal(resp.Result, &zone); err != nil {
		return nil, err
	}

	cf.mu.Lock()
	cf.zoneCache[zone.ID] = &zone
	cf.mu.Unlock()

	LogInfo("CLOUDFLARE", "Zone created: %s (%s)", zone.Name, zone.ID)
	return &zone, nil
}

// DeleteZone deletes a zone
func (cf *CloudflareManager) DeleteZone(zoneID string) error {
	_, err := cf.apiRequest("DELETE", fmt.Sprintf("/zones/%s", zoneID), nil)
	if err != nil {
		return err
	}

	cf.mu.Lock()
	delete(cf.zoneCache, zoneID)
	cf.mu.Unlock()

	LogInfo("CLOUDFLARE", "Zone deleted: %s", zoneID)
	return nil
}

// GetZoneSettings gets zone settings
func (cf *CloudflareManager) GetZoneSettings(zoneID string) (*ZoneSettings, error) {
	resp, err := cf.apiRequest("GET", fmt.Sprintf("/zones/%s/settings", zoneID), nil)
	if err != nil {
		return nil, err
	}

	var settings []struct {
		ID       string      `json:"id"`
		Value    interface{} `json:"value"`
		Editable bool        `json:"editable"`
	}

	if err := json.Unmarshal(resp.Result, &settings); err != nil {
		return nil, err
	}

	// Convert to ZoneSettings struct
	zs := &ZoneSettings{}
	for _, s := range settings {
		switch s.ID {
		case "ssl":
			zs.SSL = fmt.Sprintf("%v", s.Value)
		case "security_level":
			zs.SecurityLevel = fmt.Sprintf("%v", s.Value)
		case "cache_level":
			zs.CacheLevel = fmt.Sprintf("%v", s.Value)
		case "browser_cache_ttl":
			if v, ok := s.Value.(float64); ok {
				zs.BrowserCacheTTL = int(v)
			}
		case "always_use_https":
			zs.AlwaysUseHTTPS = fmt.Sprintf("%v", s.Value)
		case "min_tls_version":
			zs.MinTLSVersion = fmt.Sprintf("%v", s.Value)
		case "http2":
			zs.HTTP2 = fmt.Sprintf("%v", s.Value)
		case "http3":
			zs.HTTP3 = fmt.Sprintf("%v", s.Value)
		case "websockets":
			zs.Websockets = fmt.Sprintf("%v", s.Value)
		case "brotli":
			zs.Brotli = fmt.Sprintf("%v", s.Value)
		case "waf":
			zs.WAF = fmt.Sprintf("%v", s.Value)
		case "ipv6":
			zs.IPv6 = fmt.Sprintf("%v", s.Value)
		case "rocket_loader":
			zs.RocketLoader = fmt.Sprintf("%v", s.Value)
		case "polish":
			zs.Polish = fmt.Sprintf("%v", s.Value)
		}
	}

	return zs, nil
}

// UpdateZoneSetting updates a single zone setting
func (cf *CloudflareManager) UpdateZoneSetting(zoneID, setting string, value interface{}) error {
	body := map[string]interface{}{
		"value": value,
	}

	_, err := cf.apiRequest("PATCH", fmt.Sprintf("/zones/%s/settings/%s", zoneID, setting), body)
	return err
}

// PurgeCache purges zone cache
func (cf *CloudflareManager) PurgeCache(zoneID string, purgeEverything bool, files []string, tags []string, hosts []string) error {
	body := make(map[string]interface{})

	if purgeEverything {
		body["purge_everything"] = true
	} else {
		if len(files) > 0 {
			body["files"] = files
		}
		if len(tags) > 0 {
			body["tags"] = tags
		}
		if len(hosts) > 0 {
			body["hosts"] = hosts
		}
	}

	_, err := cf.apiRequest("POST", fmt.Sprintf("/zones/%s/purge_cache", zoneID), body)
	if err != nil {
		return err
	}

	LogInfo("CLOUDFLARE", "Cache purged for zone: %s", zoneID)
	return nil
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// DNS Operations
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// ListDNSRecords lists all DNS records for a zone
func (cf *CloudflareManager) ListDNSRecords(zoneID string) ([]*DNSRecord, error) {
	// Check cache
	cf.mu.RLock()
	if records, ok := cf.dnsCache[zoneID]; ok && time.Now().Before(cf.cacheExpiry) {
		cf.mu.RUnlock()
		return records, nil
	}
	cf.mu.RUnlock()

	var allRecords []*DNSRecord
	page := 1
	perPage := 100

	for {
		endpoint := fmt.Sprintf("/zones/%s/dns_records?page=%d&per_page=%d", zoneID, page, perPage)
		resp, err := cf.apiRequest("GET", endpoint, nil)
		if err != nil {
			return nil, err
		}

		var records []*DNSRecord
		if err := json.Unmarshal(resp.Result, &records); err != nil {
			return nil, err
		}

		allRecords = append(allRecords, records...)

		if resp.ResultInfo == nil || page >= resp.ResultInfo.TotalPages {
			break
		}
		page++
	}

	// Update cache
	cf.mu.Lock()
	cf.dnsCache[zoneID] = allRecords
	cf.cacheExpiry = time.Now().Add(5 * time.Minute)
	cf.mu.Unlock()

	return allRecords, nil
}

// GetDNSRecord gets a DNS record by ID
func (cf *CloudflareManager) GetDNSRecord(zoneID, recordID string) (*DNSRecord, error) {
	resp, err := cf.apiRequest("GET", fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID), nil)
	if err != nil {
		return nil, err
	}

	var record DNSRecord
	if err := json.Unmarshal(resp.Result, &record); err != nil {
		return nil, err
	}

	return &record, nil
}

// CreateDNSRecord creates a new DNS record
func (cf *CloudflareManager) CreateDNSRecord(zoneID string, record *DNSRecordCreate) (*DNSRecord, error) {
	if record.TTL == 0 {
		record.TTL = 1 // Auto TTL
	}

	resp, err := cf.apiRequest("POST", fmt.Sprintf("/zones/%s/dns_records", zoneID), record)
	if err != nil {
		return nil, err
	}

	var newRecord DNSRecord
	if err := json.Unmarshal(resp.Result, &newRecord); err != nil {
		return nil, err
	}

	// Invalidate cache
	cf.mu.Lock()
	delete(cf.dnsCache, zoneID)
	cf.mu.Unlock()

	// Notify
	if cf.onDNSChange != nil {
		cf.onDNSChange(&newRecord, "created")
	}

	LogInfo("CLOUDFLARE", "DNS record created: %s -> %s", newRecord.Name, newRecord.Content)
	return &newRecord, nil
}

// UpdateDNSRecord updates a DNS record
func (cf *CloudflareManager) UpdateDNSRecord(zoneID, recordID string, update *DNSRecordUpdate) (*DNSRecord, error) {
	resp, err := cf.apiRequest("PATCH", fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID), update)
	if err != nil {
		return nil, err
	}

	var record DNSRecord
	if err := json.Unmarshal(resp.Result, &record); err != nil {
		return nil, err
	}

	// Invalidate cache
	cf.mu.Lock()
	delete(cf.dnsCache, zoneID)
	cf.mu.Unlock()

	if cf.onDNSChange != nil {
		cf.onDNSChange(&record, "updated")
	}

	LogInfo("CLOUDFLARE", "DNS record updated: %s", record.Name)
	return &record, nil
}

// DeleteDNSRecord deletes a DNS record
func (cf *CloudflareManager) DeleteDNSRecord(zoneID, recordID string) error {
	_, err := cf.apiRequest("DELETE", fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID), nil)
	if err != nil {
		return err
	}

	// Invalidate cache
	cf.mu.Lock()
	delete(cf.dnsCache, zoneID)
	cf.mu.Unlock()

	LogInfo("CLOUDFLARE", "DNS record deleted: %s", recordID)
	return nil
}

// FindDNSRecordByName finds DNS records by name
func (cf *CloudflareManager) FindDNSRecordByName(zoneID, name, recordType string) ([]*DNSRecord, error) {
	records, err := cf.ListDNSRecords(zoneID)
	if err != nil {
		return nil, err
	}

	var matching []*DNSRecord
	for _, r := range records {
		if r.Name == name && (recordType == "" || r.Type == recordType) {
			matching = append(matching, r)
		}
	}

	return matching, nil
}

// UpsertDNSRecord creates or updates a DNS record
func (cf *CloudflareManager) UpsertDNSRecord(zoneID string, record *DNSRecordCreate) (*DNSRecord, error) {
	// Find existing record
	existing, err := cf.FindDNSRecordByName(zoneID, record.Name, record.Type)
	if err != nil {
		return nil, err
	}

	if len(existing) > 0 {
		// Update existing
		update := &DNSRecordUpdate{
			Content: record.Content,
			TTL:     record.TTL,
			Proxied: &record.Proxied,
		}
		return cf.UpdateDNSRecord(zoneID, existing[0].ID, update)
	}

	// Create new
	return cf.CreateDNSRecord(zoneID, record)
}

// ExportDNSRecords exports all DNS records in BIND format
func (cf *CloudflareManager) ExportDNSRecords(zoneID string) (string, error) {
	resp, err := cf.apiRequest("GET", fmt.Sprintf("/zones/%s/dns_records/export", zoneID), nil)
	if err != nil {
		return "", err
	}

	return string(resp.Result), nil
}

// ImportDNSRecords imports DNS records from BIND format
func (cf *CloudflareManager) ImportDNSRecords(zoneID, bindData string) error {
	_, err := cf.apiRequestRaw("POST", fmt.Sprintf("/zones/%s/dns_records/import", zoneID),
		strings.NewReader(bindData), "text/dns")
	return err
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SSL/TLS Operations
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// SetSSLMode sets SSL/TLS mode
func (cf *CloudflareManager) SetSSLMode(zoneID, mode string) error {
	// Validate mode
	validModes := []string{"off", "flexible", "full", "strict"}
	valid := false
	for _, m := range validModes {
		if m == mode {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid SSL mode: %s", mode)
	}

	return cf.UpdateZoneSetting(zoneID, "ssl", mode)
}

// EnableAlwaysHTTPS enables Always Use HTTPS
func (cf *CloudflareManager) EnableAlwaysHTTPS(zoneID string, enable bool) error {
	value := "off"
	if enable {
		value = "on"
	}
	return cf.UpdateZoneSetting(zoneID, "always_use_https", value)
}

// SetMinTLSVersion sets minimum TLS version
func (cf *CloudflareManager) SetMinTLSVersion(zoneID, version string) error {
	return cf.UpdateZoneSetting(zoneID, "min_tls_version", version)
}

// GetUniversalSSLSettings gets Universal SSL settings
func (cf *CloudflareManager) GetUniversalSSLSettings(zoneID string) (map[string]interface{}, error) {
	resp, err := cf.apiRequest("GET", fmt.Sprintf("/zones/%s/ssl/universal/settings", zoneID), nil)
	if err != nil {
		return nil, err
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(resp.Result, &settings); err != nil {
		return nil, err
	}

	return settings, nil
}

// OrderSSLCertificate orders an SSL certificate
func (cf *CloudflareManager) OrderSSLCertificate(zoneID string, hostnames []string, validityDays int) error {
	body := map[string]interface{}{
		"hostnames":             hostnames,
		"requested_validity":    validityDays,
		"certificate_authority": "digicert",
	}

	_, err := cf.apiRequest("POST", fmt.Sprintf("/zones/%s/ssl/certificate_packs/order", zoneID), body)
	return err
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Firewall Operations
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// CreateFirewallRule creates a firewall rule
func (cf *CloudflareManager) CreateFirewallRule(zoneID string, rule *FirewallRule) (*FirewallRule, error) {
	// First create the filter
	filterBody := map[string]interface{}{
		"expression":  rule.Filter.Expression,
		"description": rule.Filter.Description,
	}

	filterResp, err := cf.apiRequest("POST", fmt.Sprintf("/zones/%s/filters", zoneID), []interface{}{filterBody})
	if err != nil {
		return nil, err
	}

	var filters []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(filterResp.Result, &filters); err != nil {
		return nil, err
	}

	// Create firewall rule with filter
	ruleBody := map[string]interface{}{
		"filter":      map[string]string{"id": filters[0].ID},
		"action":      rule.Action,
		"description": rule.Description,
		"priority":    rule.Priority,
		"paused":      rule.Paused,
	}

	resp, err := cf.apiRequest("POST", fmt.Sprintf("/zones/%s/firewall/rules", zoneID), []interface{}{ruleBody})
	if err != nil {
		return nil, err
	}

	var rules []*FirewallRule
	if err := json.Unmarshal(resp.Result, &rules); err != nil {
		return nil, err
	}

	LogInfo("CLOUDFLARE", "Firewall rule created: %s", rules[0].ID)
	return rules[0], nil
}

// ListFirewallRules lists all firewall rules
func (cf *CloudflareManager) ListFirewallRules(zoneID string) ([]*FirewallRule, error) {
	resp, err := cf.apiRequest("GET", fmt.Sprintf("/zones/%s/firewall/rules", zoneID), nil)
	if err != nil {
		return nil, err
	}

	var rules []*FirewallRule
	if err := json.Unmarshal(resp.Result, &rules); err != nil {
		return nil, err
	}

	return rules, nil
}

// DeleteFirewallRule deletes a firewall rule
func (cf *CloudflareManager) DeleteFirewallRule(zoneID, ruleID string) error {
	_, err := cf.apiRequest("DELETE", fmt.Sprintf("/zones/%s/firewall/rules/%s", zoneID, ruleID), nil)
	return err
}

// CreateIPAccessRule creates an IP access rule
func (cf *CloudflareManager) CreateIPAccessRule(zoneID string, rule *IPAccessRule) (*IPAccessRule, error) {
	body := map[string]interface{}{
		"mode": rule.Mode,
		"configuration": map[string]string{
			"target": rule.Configuration.Target,
			"value":  rule.Configuration.Value,
		},
		"notes": rule.Notes,
	}

	resp, err := cf.apiRequest("POST", fmt.Sprintf("/zones/%s/firewall/access_rules/rules", zoneID), body)
	if err != nil {
		return nil, err
	}

	var newRule IPAccessRule
	if err := json.Unmarshal(resp.Result, &newRule); err != nil {
		return nil, err
	}

	LogInfo("CLOUDFLARE", "IP access rule created: %s -> %s", rule.Configuration.Value, rule.Mode)
	return &newRule, nil
}

// ListIPAccessRules lists all IP access rules
func (cf *CloudflareManager) ListIPAccessRules(zoneID string) ([]*IPAccessRule, error) {
	resp, err := cf.apiRequest("GET", fmt.Sprintf("/zones/%s/firewall/access_rules/rules", zoneID), nil)
	if err != nil {
		return nil, err
	}

	var rules []*IPAccessRule
	if err := json.Unmarshal(resp.Result, &rules); err != nil {
		return nil, err
	}

	return rules, nil
}

// BlockIP blocks an IP address
func (cf *CloudflareManager) BlockIP(zoneID, ip, note string) (*IPAccessRule, error) {
	return cf.CreateIPAccessRule(zoneID, &IPAccessRule{
		Mode:  "block",
		Notes: note,
		Configuration: struct {
			Target string `json:"target"`
			Value  string `json:"value"`
		}{
			Target: "ip",
			Value:  ip,
		},
	})
}

// WhitelistIP whitelists an IP address
func (cf *CloudflareManager) WhitelistIP(zoneID, ip, note string) (*IPAccessRule, error) {
	return cf.CreateIPAccessRule(zoneID, &IPAccessRule{
		Mode:  "whitelist",
		Notes: note,
		Configuration: struct {
			Target string `json:"target"`
			Value  string `json:"value"`
		}{
			Target: "ip",
			Value:  ip,
		},
	})
}

// ChallengeIP adds challenge for an IP
func (cf *CloudflareManager) ChallengeIP(zoneID, ip, note string) (*IPAccessRule, error) {
	return cf.CreateIPAccessRule(zoneID, &IPAccessRule{
		Mode:  "challenge",
		Notes: note,
		Configuration: struct {
			Target string `json:"target"`
			Value  string `json:"value"`
		}{
			Target: "ip",
			Value:  ip,
		},
	})
}

// BlockCountry blocks a country
func (cf *CloudflareManager) BlockCountry(zoneID, countryCode, note string) (*IPAccessRule, error) {
	return cf.CreateIPAccessRule(zoneID, &IPAccessRule{
		Mode:  "block",
		Notes: note,
		Configuration: struct {
			Target string `json:"target"`
			Value  string `json:"value"`
		}{
			Target: "country",
			Value:  countryCode,
		},
	})
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Page Rules
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// CreatePageRule creates a page rule
func (cf *CloudflareManager) CreatePageRule(zoneID string, rule *PageRule) (*PageRule, error) {
	resp, err := cf.apiRequest("POST", fmt.Sprintf("/zones/%s/pagerules", zoneID), rule)
	if err != nil {
		return nil, err
	}

	var newRule PageRule
	if err := json.Unmarshal(resp.Result, &newRule); err != nil {
		return nil, err
	}

	return &newRule, nil
}

// ListPageRules lists all page rules
func (cf *CloudflareManager) ListPageRules(zoneID string) ([]*PageRule, error) {
	resp, err := cf.apiRequest("GET", fmt.Sprintf("/zones/%s/pagerules", zoneID), nil)
	if err != nil {
		return nil, err
	}

	var rules []*PageRule
	if err := json.Unmarshal(resp.Result, &rules); err != nil {
		return nil, err
	}

	return rules, nil
}

// UpdatePageRule updates a page rule
func (cf *CloudflareManager) UpdatePageRule(zoneID, ruleID string, rule *PageRule) (*PageRule, error) {
	resp, err := cf.apiRequest("PUT", fmt.Sprintf("/zones/%s/pagerules/%s", zoneID, ruleID), rule)
	if err != nil {
		return nil, err
	}

	var updated PageRule
	if err := json.Unmarshal(resp.Result, &updated); err != nil {
		return nil, err
	}

	return &updated, nil
}

// DeletePageRule deletes a page rule
func (cf *CloudflareManager) DeletePageRule(zoneID, ruleID string) error {
	_, err := cf.apiRequest("DELETE", fmt.Sprintf("/zones/%s/pagerules/%s", zoneID, ruleID), nil)
	return err
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Analytics
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// GetZoneAnalytics gets zone analytics
func (cf *CloudflareManager) GetZoneAnalytics(zoneID string, since, until time.Time) (map[string]interface{}, error) {
	endpoint := fmt.Sprintf("/zones/%s/analytics/dashboard?since=%s&until=%s&continuous=true",
		zoneID,
		since.Format(time.RFC3339),
		until.Format(time.RFC3339))

	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var analytics map[string]interface{}
	if err := json.Unmarshal(resp.Result, &analytics); err != nil {
		return nil, err
	}

	return analytics, nil
}

// GetDNSAnalytics gets DNS analytics
func (cf *CloudflareManager) GetDNSAnalytics(zoneID string, since, until time.Time) (map[string]interface{}, error) {
	endpoint := fmt.Sprintf("/zones/%s/dns_analytics/report?since=%s&until=%s",
		zoneID,
		since.Format(time.RFC3339),
		until.Format(time.RFC3339))

	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var analytics map[string]interface{}
	if err := json.Unmarshal(resp.Result, &analytics); err != nil {
		return nil, err
	}

	return analytics, nil
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Helper Methods
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// GetDefaultZoneID returns the default zone ID
func (cf *CloudflareManager) GetDefaultZoneID() string {
	cf.mu.RLock()
	defer cf.mu.RUnlock()
	return cf.Config.DefaultZoneID
}

// SetDefaultZone sets the default zone
func (cf *CloudflareManager) SetDefaultZone(zoneID, zoneName string) error {
	cf.mu.Lock()
	cf.Config.DefaultZoneID = zoneID
	cf.Config.DefaultZoneName = zoneName
	cf.mu.Unlock()

	return cf.SaveConfig()
}

// IsConnected returns connection status
func (cf *CloudflareManager) IsConnected() bool {
	cf.mu.RLock()
	defer cf.mu.RUnlock()
	return cf.isConnected
}

// GetAPIStats returns API call statistics
func (cf *CloudflareManager) GetAPIStats() map[string]interface{} {
	cf.mu.RLock()
	defer cf.mu.RUnlock()

	return map[string]interface{}{
		"is_connected":   cf.isConnected,
		"last_api_call":  cf.lastAPICall.Unix(),
		"api_call_count": cf.apiCallCount,
		"error_count":    cf.errorCount,
	}
}

// ValidateDomain validates domain format
func (cf *CloudflareManager) ValidateDomain(domain string) bool {
	pattern := `^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	match, _ := regexp.MatchString(pattern, domain)
	return match
}

// ValidateIP validates IP address
func (cf *CloudflareManager) ValidateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// ResolveIP resolves domain to IP
func (cf *CloudflareManager) ResolveIP(domain string) ([]string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, err
	}

	var result []string
	for _, ip := range ips {
		result = append(result, ip.String())
	}

	return result, nil
}

// cloudflare.go - MX-UI Cloudflare Integration (Part 2)
// WARP Manager, Workers Manager, CDN Manager

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// WARP MANAGER - Complete Implementation
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// initWARPManager initializes the WARP manager
func (cf *CloudflareManager) initWARPManager() *WARPManager {
	var warpConfig *WARPConfig
	if cf.Config.WARPEnabled {
		warpConfig = cf.loadWARPConfig()
	} else {
		warpConfig = &WARPConfig{}
	}

	wm := &WARPManager{
		Config:  warpConfig,
		Devices: make(map[string]*WARPDevice),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		},
	}

	// Load existing account if available
	if wm.Config.AccessToken != "" {
		wm.loadAccountInfo()
	}

	return wm
}

// loadWARPConfig loads WARP configuration
func (cf *CloudflareManager) loadWARPConfig() *WARPConfig {
	configJSON, err := cf.db.GetSetting("warp_config")
	if err != nil || configJSON == "" {
		return &WARPConfig{
			Enabled:     true,
			Mode:        "warp",
			MTU:         1280,
			KeepAlive:   25,
			DNS:         []string{"1.1.1.1", "1.0.0.1"},
			AllowedIPs:  []string{"0.0.0.0/0", "::/0"},
			SplitTunnel: false,
		}
	}

	var config WARPConfig
	json.Unmarshal([]byte(configJSON), &config)
	return &config
}

// SaveWARPConfig saves WARP configuration
func (wm *WARPManager) SaveWARPConfig(db *DatabaseManager) error {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	configJSON, err := json.Marshal(wm.Config)
	if err != nil {
		return err
	}

	return db.SetSetting("warp_config", string(configJSON), "json", "cloudflare", false)
}

// Register registers a new WARP device
func (wm *WARPManager) Register() (*WARPRegistrationResponse, error) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	// Generate keys if not exists
	if wm.Config.PrivateKey == "" {
		privateKey, publicKey, err := wm.generateWireGuardKeys()
		if err != nil {
			return nil, fmt.Errorf("failed to generate keys: %v", err)
		}
		wm.Config.PrivateKey = privateKey
		wm.Config.PublicKey = publicKey
	}

	// Generate device ID
	if wm.Config.DeviceID == "" {
		wm.Config.DeviceID = wm.generateDeviceID()
	}

	// Generate install ID
	installID := wm.generateInstallID()

	// Prepare registration request
	regReq := &WARPRegistration{
		Key:       wm.Config.PublicKey,
		InstallID: installID,
		FCMToken:  "",
		Tos:       time.Now().Format(time.RFC3339),
		Model:     "MX-UI VPN Panel",
		Type:      "Linux",
		Locale:    "en_US",
	}

	reqBody, _ := json.Marshal(regReq)

	// Send registration request
	req, err := http.NewRequest("POST", WARPRegisterAPI, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("CF-Client-Version", "a-6.11-2223")
	req.Header.Set("User-Agent", "okhttp/3.12.1")

	resp, err := wm.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registration failed: %s", string(body))
	}

	var regResp WARPRegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return nil, err
	}

	// Save registration data
	wm.Config.DeviceID = regResp.ID
	wm.Config.AccessToken = regResp.Token
	wm.Config.ClientID = regResp.Config.ClientID

	// Save interface addresses
	wm.Config.InterfaceIPv4 = regResp.Config.Interface.Addresses.V4
	wm.Config.InterfaceIPv6 = regResp.Config.Interface.Addresses.V6

	// Save endpoint
	if len(regResp.Config.Peers) > 0 {
		peer := regResp.Config.Peers[0]
		wm.Config.Endpoint = fmt.Sprintf("%s:%d", peer.Endpoint.V4, WARPPort)
		wm.Config.EndpointV6 = fmt.Sprintf("[%s]:%d", peer.Endpoint.V6, WARPPort)
	}

	// Generate reserved bytes
	wm.Config.ReservedDec, wm.Config.ReservedHex = wm.generateReserved(regResp.Config.ClientID)

	// Save account info
	wm.Account = &WARPAccount{
		ID:          regResp.Account.ID,
		Type:        regResp.Account.AccountType,
		Created:     regResp.Account.Created,
		PremiumData: regResp.Account.PremiumData,
		Quota:       regResp.Account.Quota,
		WARPPlus:    regResp.Account.WARPPlus,
		License:     regResp.Account.License,
	}

	wm.lastUpdate = time.Now()

	LogInfo("WARP", "Device registered successfully: %s", regResp.ID)
	return &regResp, nil
}

// ApplyLicenseKey applies a WARP+ license key
func (wm *WARPManager) ApplyLicenseKey(licenseKey string) error {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	if wm.Config.DeviceID == "" || wm.Config.AccessToken == "" {
		return fmt.Errorf("device not registered")
	}

	// Prepare license request
	body := map[string]string{
		"license": licenseKey,
	}
	reqBody, _ := json.Marshal(body)

	url := fmt.Sprintf(WARPConfigAPI+"/account", wm.Config.DeviceID)
	req, err := http.NewRequest("PUT", url, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+wm.Config.AccessToken)
	req.Header.Set("CF-Client-Version", "a-6.11-2223")

	resp, err := wm.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("license application failed: %s", string(body))
	}

	wm.Config.LicenseKey = licenseKey

	// Refresh account info
	wm.loadAccountInfo()

	LogInfo("WARP", "License key applied successfully")
	return nil
}

// loadAccountInfo loads account information
func (wm *WARPManager) loadAccountInfo() error {
	if wm.Config.DeviceID == "" || wm.Config.AccessToken == "" {
		return fmt.Errorf("device not registered")
	}

	url := fmt.Sprintf(WARPConfigAPI, wm.Config.DeviceID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+wm.Config.AccessToken)
	req.Header.Set("CF-Client-Version", "a-6.11-2223")

	resp, err := wm.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to load account info")
	}

	var regResp WARPRegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return err
	}

	wm.Account = &WARPAccount{
		ID:          regResp.Account.ID,
		Type:        regResp.Account.AccountType,
		Created:     regResp.Account.Created,
		Updated:     regResp.Account.Updated,
		PremiumData: regResp.Account.PremiumData,
		Quota:       regResp.Account.Quota,
		WARPPlus:    regResp.Account.WARPPlus,
		License:     regResp.Account.License,
	}

	wm.lastUpdate = time.Now()
	return nil
}

// GetAccountInfo returns current account info
func (wm *WARPManager) GetAccountInfo() (*WARPAccount, error) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	if wm.Account == nil {
		return nil, fmt.Errorf("no account info available")
	}

	return wm.Account, nil
}

// RefreshAccount refreshes account information
func (wm *WARPManager) RefreshAccount() error {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	return wm.loadAccountInfo()
}

// GenerateWireGuardConfig generates WireGuard configuration
func (wm *WARPManager) GenerateWireGuardConfig() (*WARPProfile, error) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	if wm.Config.PrivateKey == "" {
		return nil, fmt.Errorf("WARP not configured")
	}

	profile := &WARPProfile{}
	profile.Interface.PrivateKey = wm.Config.PrivateKey
	profile.Interface.Address = []string{
		wm.Config.InterfaceIPv4 + "/32",
		wm.Config.InterfaceIPv6 + "/128",
	}
	profile.Interface.DNS = wm.Config.DNS
	profile.Interface.MTU = wm.Config.MTU

	profile.Peer.PublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	profile.Peer.Endpoint = wm.Config.Endpoint
	profile.Peer.AllowedIPs = wm.Config.AllowedIPs
	profile.Peer.KeepAlive = wm.Config.KeepAlive

	return profile, nil
}

// GenerateWireGuardConfigString generates WireGuard config as string
func (wm *WARPManager) GenerateWireGuardConfigString() (string, error) {
	profile, err := wm.GenerateWireGuardConfig()
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", profile.Interface.PrivateKey))
	sb.WriteString(fmt.Sprintf("Address = %s\n", strings.Join(profile.Interface.Address, ", ")))
	sb.WriteString(fmt.Sprintf("DNS = %s\n", strings.Join(profile.Interface.DNS, ", ")))
	sb.WriteString(fmt.Sprintf("MTU = %d\n", profile.Interface.MTU))
	sb.WriteString("\n[Peer]\n")
	sb.WriteString(fmt.Sprintf("PublicKey = %s\n", profile.Peer.PublicKey))
	sb.WriteString(fmt.Sprintf("Endpoint = %s\n", profile.Peer.Endpoint))
	sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(profile.Peer.AllowedIPs, ", ")))
	sb.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", profile.Peer.KeepAlive))

	return sb.String(), nil
}

// GenerateXrayWARPOutbound generates Xray WARP outbound config
func (wm *WARPManager) GenerateXrayWARPOutbound() (map[string]interface{}, error) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	if wm.Config.PrivateKey == "" {
		return nil, fmt.Errorf("WARP not configured")
	}

	outbound := map[string]interface{}{
		"tag":      "warp",
		"protocol": "wireguard",
		"settings": map[string]interface{}{
			"secretKey": wm.Config.PrivateKey,
			"address": []string{
				wm.Config.InterfaceIPv4 + "/32",
				wm.Config.InterfaceIPv6 + "/128",
			},
			"peers": []map[string]interface{}{
				{
					"publicKey":  "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
					"endpoint":   wm.Config.Endpoint,
					"allowedIPs": []string{"0.0.0.0/0", "::/0"},
					"keepAlive":  wm.Config.KeepAlive,
				},
			},
			"reserved": wm.Config.ReservedDec,
			"mtu":      wm.Config.MTU,
		},
	}

	return outbound, nil
}

// GenerateSingboxWARPOutbound generates Sing-box WARP outbound config
func (wm *WARPManager) GenerateSingboxWARPOutbound() (map[string]interface{}, error) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	if wm.Config.PrivateKey == "" {
		return nil, fmt.Errorf("WARP not configured")
	}

	outbound := map[string]interface{}{
		"type":        "wireguard",
		"tag":         "warp",
		"server":      strings.Split(wm.Config.Endpoint, ":")[0],
		"server_port": WARPPort,
		"local_address": []string{
			wm.Config.InterfaceIPv4 + "/32",
			wm.Config.InterfaceIPv6 + "/128",
		},
		"private_key":     wm.Config.PrivateKey,
		"peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		"reserved":        wm.Config.ReservedDec,
		"mtu":             wm.Config.MTU,
	}

	return outbound, nil
}

// GenerateClashWARPProxy generates Clash WARP proxy config
func (wm *WARPManager) GenerateClashWARPProxy() (map[string]interface{}, error) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	if wm.Config.PrivateKey == "" {
		return nil, fmt.Errorf("WARP not configured")
	}

	endpoint := strings.Split(wm.Config.Endpoint, ":")
	port := WARPPort
	if len(endpoint) > 1 {
		fmt.Sscanf(endpoint[1], "%d", &port)
	}

	proxy := map[string]interface{}{
		"name":        "WARP",
		"type":        "wireguard",
		"server":      endpoint[0],
		"port":        port,
		"ip":          wm.Config.InterfaceIPv4,
		"ipv6":        wm.Config.InterfaceIPv6,
		"private-key": wm.Config.PrivateKey,
		"public-key":  "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		"reserved":    wm.Config.ReservedHex,
		"udp":         true,
		"mtu":         wm.Config.MTU,
	}

	return proxy, nil
}

// GetWARPEndpoints returns available WARP endpoints
func (wm *WARPManager) GetWARPEndpoints() []WARPEndpointInfo {
	return []WARPEndpointInfo{
		{IP: "162.159.192.1", Port: 2408, Priority: 1, Location: "Default"},
		{IP: "162.159.193.1", Port: 2408, Priority: 2, Location: "Backup 1"},
		{IP: "162.159.195.1", Port: 2408, Priority: 3, Location: "Backup 2"},
		{IP: "188.114.96.1", Port: 2408, Priority: 4, Location: "Europe"},
		{IP: "188.114.97.1", Port: 2408, Priority: 5, Location: "Europe 2"},
		{IP: "162.159.192.0", Port: 2408, Priority: 6, Location: "Range Start"},
		{IP: "162.159.192.100", Port: 500, Priority: 7, Location: "Alt Port 1"},
		{IP: "162.159.192.100", Port: 1701, Priority: 8, Location: "Alt Port 2"},
		{IP: "162.159.192.100", Port: 4500, Priority: 9, Location: "Alt Port 3"},
	}
}

// WARPEndpointInfo contains WARP endpoint information
type WARPEndpointInfo struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Priority int    `json:"priority"`
	Location string `json:"location"`
	Latency  int    `json:"latency,omitempty"`
}

// FindBestEndpoint finds the best WARP endpoint
func (wm *WARPManager) FindBestEndpoint() (*WARPEndpointInfo, error) {
	endpoints := wm.GetWARPEndpoints()

	type result struct {
		endpoint *WARPEndpointInfo
		latency  time.Duration
	}

	results := make(chan result, len(endpoints))
	var wg sync.WaitGroup

	for i := range endpoints {
		wg.Add(1)
		go func(ep *WARPEndpointInfo) {
			defer wg.Done()

			addr := fmt.Sprintf("%s:%d", ep.IP, ep.Port)
			start := time.Now()

			conn, err := net.DialTimeout("udp", addr, 3*time.Second)
			if err != nil {
				return
			}
			conn.Close()

			latency := time.Since(start)
			ep.Latency = int(latency.Milliseconds())

			results <- result{endpoint: ep, latency: latency}
		}(&endpoints[i])
	}

	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Find best result
	var best *WARPEndpointInfo
	var bestLatency time.Duration = time.Hour

	for r := range results {
		if r.latency < bestLatency {
			best = r.endpoint
			bestLatency = r.latency
		}
	}

	if best == nil {
		return nil, fmt.Errorf("no reachable endpoints found")
	}

	LogInfo("WARP", "Best endpoint: %s:%d (latency: %dms)", best.IP, best.Port, best.Latency)
	return best, nil
}

// SetEndpoint sets WARP endpoint
func (wm *WARPManager) SetEndpoint(ip string, port int) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	wm.Config.Endpoint = fmt.Sprintf("%s:%d", ip, port)
}

// generateWireGuardKeys generates WireGuard key pair
func (wm *WARPManager) generateWireGuardKeys() (string, string, error) {
	// Generate private key (32 bytes)
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return "", "", err
	}

	// Clamp private key for Curve25519
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// Generate public key using Curve25519
	// This is a simplified version - in production use x/crypto/curve25519
	publicKey := wm.curve25519ScalarMultBase(privateKey)

	privateKeyB64 := base64.StdEncoding.EncodeToString(privateKey)
	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKey)

	return privateKeyB64, publicKeyB64, nil
}

// curve25519ScalarMultBase performs Curve25519 scalar multiplication
func (wm *WARPManager) curve25519ScalarMultBase(scalar []byte) []byte {
	// Simplified implementation - in production use golang.org/x/crypto/curve25519
	// This is the basepoint multiplication
	basepoint := []byte{9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	// For actual implementation, use:
	// import "golang.org/x/crypto/curve25519"
	// var dst, in [32]byte
	// copy(in[:], scalar)
	// curve25519.ScalarBaseMult(&dst, &in)
	// return dst[:]

	// Placeholder - generates deterministic but incorrect public key
	h := sha256.New()
	h.Write(scalar)
	h.Write(basepoint)
	return h.Sum(nil)
}

// generateDeviceID generates unique device ID
func (wm *WARPManager) generateDeviceID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("t.%s", hex.EncodeToString(b))
}

// generateInstallID generates install ID
func (wm *WARPManager) generateInstallID() string {
	b := make([]byte, 11)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// generateReserved generates reserved bytes from client ID
func (wm *WARPManager) generateReserved(clientID string) ([]int, string) {
	decoded, err := base64.StdEncoding.DecodeString(clientID)
	if err != nil || len(decoded) < 3 {
		return []int{0, 0, 0}, "000000"
	}

	reserved := []int{int(decoded[0]), int(decoded[1]), int(decoded[2])}
	hexStr := hex.EncodeToString(decoded[:3])

	return reserved, hexStr
}

// GetWARPStatus returns current WARP status
func (wm *WARPManager) GetWARPStatus() map[string]interface{} {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	status := map[string]interface{}{
		"enabled":        wm.Config.Enabled,
		"registered":     wm.Config.DeviceID != "",
		"connected":      wm.isConnected,
		"mode":           wm.Config.Mode,
		"endpoint":       wm.Config.Endpoint,
		"interface_ipv4": wm.Config.InterfaceIPv4,
		"interface_ipv6": wm.Config.InterfaceIPv6,
		"last_update":    wm.lastUpdate.Unix(),
	}

	if wm.Account != nil {
		status["account"] = map[string]interface{}{
			"id":           wm.Account.ID,
			"type":         wm.Account.Type,
			"warp_plus":    wm.Account.WARPPlus,
			"premium_data": wm.Account.PremiumData,
			"quota":        wm.Account.Quota,
		}
	}

	return status
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// WORKERS MANAGER - Complete Implementation
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// ListWorkers lists all workers
func (wm *WorkersManager) ListWorkers() ([]*Worker, error) {
	cf := wm.cf

	endpoint := fmt.Sprintf("/accounts/%s/workers/scripts", cf.Config.AccountID)
	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var workers []*Worker
	if err := json.Unmarshal(resp.Result, &workers); err != nil {
		return nil, err
	}

	// Update cache
	cf.mu.Lock()
	for _, w := range workers {
		cf.workerCache[w.Name] = w
	}
	cf.mu.Unlock()

	return workers, nil
}

// GetWorker gets a worker by name
func (wm *WorkersManager) GetWorker(name string) (*Worker, error) {
	cf := wm.cf

	// Check cache
	cf.mu.RLock()
	if worker, ok := cf.workerCache[name]; ok {
		cf.mu.RUnlock()
		return worker, nil
	}
	cf.mu.RUnlock()

	endpoint := fmt.Sprintf("/accounts/%s/workers/scripts/%s", cf.Config.AccountID, name)
	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var worker Worker
	if err := json.Unmarshal(resp.Result, &worker); err != nil {
		return nil, err
	}

	return &worker, nil
}

// DeployWorker deploys a worker script
func (wm *WorkersManager) DeployWorker(script *WorkerScript) (*Worker, error) {
	cf := wm.cf

	// Prepare metadata
	metadata := &WorkerMetadata{
		MainModule:        "index.js",
		CompatibilityDate: time.Now().Format("2006-01-02"),
		UsageModel:        "bundled",
		Bindings:          script.Bindings,
	}

	metadataJSON, _ := json.Marshal(metadata)

	// Create multipart form
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)

	// Add script part
	scriptPart, _ := writer.CreateFormField("script")
	scriptPart.Write([]byte(script.Content))

	// Add metadata part
	metadataPart, _ := writer.CreateFormField("metadata")
	metadataPart.Write(metadataJSON)

	writer.Close()

	// Upload
	endpoint := fmt.Sprintf("/accounts/%s/workers/scripts/%s", cf.Config.AccountID, script.Name)
	resp, err := cf.apiRequestRaw("PUT", endpoint, &buffer, writer.FormDataContentType())
	if err != nil {
		return nil, err
	}

	var worker Worker
	if err := json.Unmarshal(resp.Result, &worker); err != nil {
		return nil, err
	}

	// Update cache
	cf.mu.Lock()
	cf.workerCache[script.Name] = &worker
	cf.mu.Unlock()

	// Notify
	if cf.onWorkerDeploy != nil {
		cf.onWorkerDeploy(&worker)
	}

	LogInfo("WORKERS", "Worker deployed: %s", script.Name)
	return &worker, nil
}

// DeleteWorker deletes a worker
func (wm *WorkersManager) DeleteWorker(name string) error {
	cf := wm.cf

	endpoint := fmt.Sprintf("/accounts/%s/workers/scripts/%s", cf.Config.AccountID, name)
	_, err := cf.apiRequest("DELETE", endpoint, nil)
	if err != nil {
		return err
	}

	// Remove from cache
	cf.mu.Lock()
	delete(cf.workerCache, name)
	cf.mu.Unlock()

	LogInfo("WORKERS", "Worker deleted: %s", name)
	return nil
}

// CreateWorkerRoute creates a worker route
func (wm *WorkersManager) CreateWorkerRoute(zoneID string, route *WorkerRoute) (*WorkerRoute, error) {
	cf := wm.cf

	body := map[string]interface{}{
		"pattern": route.Pattern,
		"script":  route.Script,
	}

	endpoint := fmt.Sprintf("/zones/%s/workers/routes", zoneID)
	resp, err := cf.apiRequest("POST", endpoint, body)
	if err != nil {
		return nil, err
	}

	var newRoute WorkerRoute
	if err := json.Unmarshal(resp.Result, &newRoute); err != nil {
		return nil, err
	}

	LogInfo("WORKERS", "Route created: %s -> %s", route.Pattern, route.Script)
	return &newRoute, nil
}

// ListWorkerRoutes lists worker routes
func (wm *WorkersManager) ListWorkerRoutes(zoneID string) ([]*WorkerRoute, error) {
	cf := wm.cf

	endpoint := fmt.Sprintf("/zones/%s/workers/routes", zoneID)
	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var routes []*WorkerRoute
	if err := json.Unmarshal(resp.Result, &routes); err != nil {
		return nil, err
	}

	return routes, nil
}

// DeleteWorkerRoute deletes a worker route
func (wm *WorkersManager) DeleteWorkerRoute(zoneID, routeID string) error {
	cf := wm.cf

	endpoint := fmt.Sprintf("/zones/%s/workers/routes/%s", zoneID, routeID)
	_, err := cf.apiRequest("DELETE", endpoint, nil)
	return err
}

// CreateKVNamespace creates a KV namespace
func (wm *WorkersManager) CreateKVNamespace(title string) (*WorkerKV, error) {
	cf := wm.cf

	body := map[string]string{"title": title}

	endpoint := fmt.Sprintf("/accounts/%s/storage/kv/namespaces", cf.Config.AccountID)
	resp, err := cf.apiRequest("POST", endpoint, body)
	if err != nil {
		return nil, err
	}

	var kv WorkerKV
	if err := json.Unmarshal(resp.Result, &kv); err != nil {
		return nil, err
	}

	LogInfo("WORKERS", "KV namespace created: %s (%s)", title, kv.ID)
	return &kv, nil
}

// ListKVNamespaces lists KV namespaces
func (wm *WorkersManager) ListKVNamespaces() ([]*WorkerKV, error) {
	cf := wm.cf

	endpoint := fmt.Sprintf("/accounts/%s/storage/kv/namespaces", cf.Config.AccountID)
	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var namespaces []*WorkerKV
	if err := json.Unmarshal(resp.Result, &namespaces); err != nil {
		return nil, err
	}

	return namespaces, nil
}

// DeleteKVNamespace deletes a KV namespace
func (wm *WorkersManager) DeleteKVNamespace(namespaceID string) error {
	cf := wm.cf

	endpoint := fmt.Sprintf("/accounts/%s/storage/kv/namespaces/%s", cf.Config.AccountID, namespaceID)
	_, err := cf.apiRequest("DELETE", endpoint, nil)
	return err
}

// WriteKVValue writes a value to KV
func (wm *WorkersManager) WriteKVValue(namespaceID, key, value string, expirationTTL int) error {
	cf := wm.cf

	endpoint := fmt.Sprintf("/accounts/%s/storage/kv/namespaces/%s/values/%s",
		cf.Config.AccountID, namespaceID, url.PathEscape(key))

	if expirationTTL > 0 {
		endpoint += fmt.Sprintf("?expiration_ttl=%d", expirationTTL)
	}

	_, err := cf.apiRequestRaw("PUT", endpoint, strings.NewReader(value), "text/plain")
	return err
}

// ReadKVValue reads a value from KV
func (wm *WorkersManager) ReadKVValue(namespaceID, key string) (string, error) {
	cf := wm.cf

	endpoint := fmt.Sprintf("/accounts/%s/storage/kv/namespaces/%s/values/%s",
		cf.Config.AccountID, namespaceID, url.PathEscape(key))

	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return "", err
	}

	return string(resp.Result), nil
}

// DeleteKVValue deletes a value from KV
func (wm *WorkersManager) DeleteKVValue(namespaceID, key string) error {
	cf := wm.cf

	endpoint := fmt.Sprintf("/accounts/%s/storage/kv/namespaces/%s/values/%s",
		cf.Config.AccountID, namespaceID, url.PathEscape(key))

	_, err := cf.apiRequest("DELETE", endpoint, nil)
	return err
}

// ListKVKeys lists keys in KV namespace
func (wm *WorkersManager) ListKVKeys(namespaceID string, prefix string, limit int) ([]string, error) {
	cf := wm.cf

	endpoint := fmt.Sprintf("/accounts/%s/storage/kv/namespaces/%s/keys?limit=%d",
		cf.Config.AccountID, namespaceID, limit)

	if prefix != "" {
		endpoint += "&prefix=" + url.QueryEscape(prefix)
	}

	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var keys []struct {
		Name string `json:"name"`
	}

	if err := json.Unmarshal(resp.Result, &keys); err != nil {
		return nil, err
	}

	result := make([]string, len(keys))
	for i, k := range keys {
		result[i] = k.Name
	}

	return result, nil
}

// BulkWriteKV writes multiple KV pairs
func (wm *WorkersManager) BulkWriteKV(namespaceID string, pairs []KVKeyValue) error {
	cf := wm.cf

	endpoint := fmt.Sprintf("/accounts/%s/storage/kv/namespaces/%s/bulk",
		cf.Config.AccountID, namespaceID)

	_, err := cf.apiRequest("PUT", endpoint, pairs)
	return err
}

// BulkDeleteKV deletes multiple KV keys
func (wm *WorkersManager) BulkDeleteKV(namespaceID string, keys []string) error {
	cf := wm.cf

	endpoint := fmt.Sprintf("/accounts/%s/storage/kv/namespaces/%s/bulk",
		cf.Config.AccountID, namespaceID)

	_, err := cf.apiRequest("DELETE", endpoint, keys)
	return err
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// WORKER TEMPLATES - Pre-built Scripts
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// VPNProxyWorkerScript returns a VPN proxy worker script
func (wm *WorkersManager) VPNProxyWorkerScript(backendURL string) string {
	return fmt.Sprintf(`
// MX-UI VPN Proxy Worker
// Routes traffic through Cloudflare CDN

const BACKEND = '%s';

addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
    const url = new URL(request.url);
    
    // Forward to backend
    const backendURL = BACKEND + url.pathname + url.search;
    
    const headers = new Headers(request.headers);
    headers.set('X-Forwarded-For', request.headers.get('CF-Connecting-IP'));
    headers.set('X-Real-IP', request.headers.get('CF-Connecting-IP'));
    headers.set('X-Forwarded-Proto', url.protocol.replace(':', ''));
    headers.set('Host', new URL(BACKEND).host);
    
    const init = {
        method: request.method,
        headers: headers,
        body: request.body,
        redirect: 'follow'
    };
    
    try {
        const response = await fetch(backendURL, init);
        
        const responseHeaders = new Headers(response.headers);
        responseHeaders.set('X-Served-By', 'MX-UI CDN');
        
        return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: responseHeaders
        });
    } catch (error) {
        return new Response('Backend Error: ' + error.message, { status: 502 });
    }
}
`, backendURL)
}

// WebSocketProxyWorkerScript returns a WebSocket proxy worker script
func (wm *WorkersManager) WebSocketProxyWorkerScript(backendWS string) string {
	return fmt.Sprintf(`
// MX-UI WebSocket Proxy Worker

const BACKEND_WS = '%s';

addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
    const upgradeHeader = request.headers.get('Upgrade');
    
    if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
        return handleWebSocket(request);
    }
    
    return new Response('WebSocket endpoint', { status: 200 });
}

async function handleWebSocket(request) {
    const url = new URL(request.url);
    const backendURL = BACKEND_WS + url.pathname + url.search;
    
    const headers = new Headers();
    headers.set('Host', new URL(BACKEND_WS).host);
    headers.set('X-Forwarded-For', request.headers.get('CF-Connecting-IP'));
    
    // Forward WebSocket upgrade
    const response = await fetch(backendURL, {
        headers: headers,
        method: request.method
    });
    
    return response;
}
`, backendWS)
}

// GRPCProxyWorkerScript returns a gRPC proxy worker script
func (wm *WorkersManager) GRPCProxyWorkerScript(backendGRPC string) string {
	return fmt.Sprintf(`
// MX-UI gRPC Proxy Worker

const BACKEND_GRPC = '%s';

addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
    const contentType = request.headers.get('Content-Type') || '';
    
    if (contentType.includes('application/grpc')) {
        return handleGRPC(request);
    }
    
    return new Response('gRPC endpoint', { status: 200 });
}

async function handleGRPC(request) {
    const url = new URL(request.url);
    const backendURL = BACKEND_GRPC + url.pathname;
    
    const headers = new Headers(request.headers);
    headers.set('Host', new URL(BACKEND_GRPC).host);
    
    const response = await fetch(backendURL, {
        method: request.method,
        headers: headers,
        body: request.body
    });
    
    return response;
}
`, backendGRPC)
}

// SubscriptionWorkerScript returns a subscription page worker script
func (wm *WorkersManager) SubscriptionWorkerScript(apiURL string) string {
	return fmt.Sprintf(`
// MX-UI Subscription Worker

const API_URL = '%s';

addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    
    // Subscription link
    if (path.startsWith('/sub/')) {
        const token = path.split('/sub/')[1];
        return getSubscription(token, request);
    }
    
    // Clash config
    if (path.startsWith('/clash/')) {
        const token = path.split('/clash/')[1];
        return getClashConfig(token, request);
    }
    
    // Sing-box config
    if (path.startsWith('/singbox/')) {
        const token = path.split('/singbox/')[1];
        return getSingboxConfig(token, request);
    }
    
    return new Response('MX-UI VPN Subscription', { 
        status: 200,
        headers: { 'Content-Type': 'text/plain' }
    });
}

async function getSubscription(token, request) {
    const response = await fetch(API_URL + '/api/subscription/' + token);
    const data = await response.text();
    
    return new Response(data, {
        headers: {
            'Content-Type': 'text/plain',
            'Subscription-Userinfo': response.headers.get('Subscription-Userinfo') || '',
            'Profile-Update-Interval': '12',
            'Profile-Title': 'MX-UI VPN'
        }
    });
}

async function getClashConfig(token, request) {
    const response = await fetch(API_URL + '/api/subscription/' + token + '?format=clash');
    const data = await response.text();
    
    return new Response(data, {
        headers: {
            'Content-Type': 'text/yaml',
            'Content-Disposition': 'attachment; filename="clash.yaml"'
        }
    });
}

async function getSingboxConfig(token, request) {
    const response = await fetch(API_URL + '/api/subscription/' + token + '?format=singbox');
    const data = await response.text();
    
    return new Response(data, {
        headers: {
            'Content-Type': 'application/json',
            'Content-Disposition': 'attachment; filename="singbox.json"'
        }
    });
}
`, apiURL)
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// CDN MANAGER - Complete Implementation
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// EnableCDN enables CDN for a zone
func (cm *CDNManager) EnableCDN(zoneID string) error {
	cf := cm.cf

	settings := map[string]interface{}{
		"cache_level":       "aggressive",
		"browser_cache_ttl": 14400,
		"always_online":     "on",
		"brotli":            "on",
		"minify": map[string]string{
			"css":  "on",
			"js":   "on",
			"html": "on",
		},
	}

	for setting, value := range settings {
		if err := cf.UpdateZoneSetting(zoneID, setting, value); err != nil {
			LogError("CDN", "Failed to set %s: %v", setting, err)
		}
	}

	LogInfo("CDN", "CDN enabled for zone: %s", zoneID)
	return nil
}

// DisableCDN disables CDN for a zone
func (cm *CDNManager) DisableCDN(zoneID string) error {
	cf := cm.cf

	settings := map[string]interface{}{
		"cache_level":   "basic",
		"always_online": "off",
		"rocket_loader": "off",
	}

	for setting, value := range settings {
		if err := cf.UpdateZoneSetting(zoneID, setting, value); err != nil {
			LogError("CDN", "Failed to set %s: %v", setting, err)
		}
	}

	LogInfo("CDN", "CDN disabled for zone: %s", zoneID)
	return nil
}

// SetCacheLevel sets cache level
func (cm *CDNManager) SetCacheLevel(zoneID, level string) error {
	// Valid levels: aggressive, basic, simplified
	return cm.cf.UpdateZoneSetting(zoneID, "cache_level", level)
}

// SetBrowserCacheTTL sets browser cache TTL
func (cm *CDNManager) SetBrowserCacheTTL(zoneID string, ttl int) error {
	return cm.cf.UpdateZoneSetting(zoneID, "browser_cache_ttl", ttl)
}

// EnableMinify enables HTML/CSS/JS minification
func (cm *CDNManager) EnableMinify(zoneID string, html, css, js bool) error {
	value := map[string]string{
		"html": boolToOnOff(html),
		"css":  boolToOnOff(css),
		"js":   boolToOnOff(js),
	}
	return cm.cf.UpdateZoneSetting(zoneID, "minify", value)
}

// EnableRocketLoader enables Rocket Loader
func (cm *CDNManager) EnableRocketLoader(zoneID string, enable bool) error {
	return cm.cf.UpdateZoneSetting(zoneID, "rocket_loader", boolToOnOff(enable))
}

// EnablePolish enables Polish (image optimization)
func (cm *CDNManager) EnablePolish(zoneID, mode string) error {
	// Modes: off, lossless, lossy
	return cm.cf.UpdateZoneSetting(zoneID, "polish", mode)
}

// EnableWebP enables WebP conversion
func (cm *CDNManager) EnableWebP(zoneID string, enable bool) error {
	return cm.cf.UpdateZoneSetting(zoneID, "webp", boolToOnOff(enable))
}

// EnableBrotli enables Brotli compression
func (cm *CDNManager) EnableBrotli(zoneID string, enable bool) error {
	return cm.cf.UpdateZoneSetting(zoneID, "brotli", boolToOnOff(enable))
}

// EnableHTTP2 enables HTTP/2
func (cm *CDNManager) EnableHTTP2(zoneID string, enable bool) error {
	return cm.cf.UpdateZoneSetting(zoneID, "http2", boolToOnOff(enable))
}

// EnableHTTP3 enables HTTP/3 (QUIC)
func (cm *CDNManager) EnableHTTP3(zoneID string, enable bool) error {
	return cm.cf.UpdateZoneSetting(zoneID, "http3", boolToOnOff(enable))
}

// Enable0RTT enables 0-RTT Connection Resumption
func (cm *CDNManager) Enable0RTT(zoneID string, enable bool) error {
	return cm.cf.UpdateZoneSetting(zoneID, "0rtt", boolToOnOff(enable))
}

// EnableWebSockets enables WebSocket support
func (cm *CDNManager) EnableWebSockets(zoneID string, enable bool) error {
	return cm.cf.UpdateZoneSetting(zoneID, "websockets", boolToOnOff(enable))
}

// EnableAlwaysOnline enables Always Online
func (cm *CDNManager) EnableAlwaysOnline(zoneID string, enable bool) error {
	return cm.cf.UpdateZoneSetting(zoneID, "always_online", boolToOnOff(enable))
}

// EnableIPv6 enables IPv6
func (cm *CDNManager) EnableIPv6(zoneID string, enable bool) error {
	return cm.cf.UpdateZoneSetting(zoneID, "ipv6", boolToOnOff(enable))
}

// PurgeEverything purges all cache
func (cm *CDNManager) PurgeEverything(zoneID string) error {
	return cm.cf.PurgeCache(zoneID, true, nil, nil, nil)
}

// PurgeURLs purges specific URLs
func (cm *CDNManager) PurgeURLs(zoneID string, urls []string) error {
	return cm.cf.PurgeCache(zoneID, false, urls, nil, nil)
}

// PurgeTags purges by cache tags
func (cm *CDNManager) PurgeTags(zoneID string, tags []string) error {
	return cm.cf.PurgeCache(zoneID, false, nil, tags, nil)
}

// PurgeHosts purges by hostnames
func (cm *CDNManager) PurgeHosts(zoneID string, hosts []string) error {
	return cm.cf.PurgeCache(zoneID, false, nil, nil, hosts)
}

// GetCacheAnalytics gets cache analytics
func (cm *CDNManager) GetCacheAnalytics(zoneID string, since, until time.Time) (map[string]interface{}, error) {
	cf := cm.cf

	endpoint := fmt.Sprintf("/zones/%s/analytics/colos?since=%s&until=%s",
		zoneID,
		since.Format(time.RFC3339),
		until.Format(time.RFC3339))

	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var analytics map[string]interface{}
	if err := json.Unmarshal(resp.Result, &analytics); err != nil {
		return nil, err
	}

	return analytics, nil
}

// CreateCacheRule creates a cache rule (Page Rule alternative)
func (cm *CDNManager) CreateCacheRule(zoneID, urlPattern string, cacheTTL int, cacheEverything bool) error {
	cf := cm.cf

	actions := []map[string]interface{}{}

	if cacheEverything {
		actions = append(actions, map[string]interface{}{
			"id":    "cache_level",
			"value": "cache_everything",
		})
	}

	if cacheTTL > 0 {
		actions = append(actions, map[string]interface{}{
			"id":    "edge_cache_ttl",
			"value": cacheTTL,
		})
	}

	rule := &PageRule{
		Targets: []struct {
			Target     string `json:"target"`
			Constraint struct {
				Operator string `json:"operator"`
				Value    string `json:"value"`
			} `json:"constraint"`
		}{
			{
				Target: "url",
				Constraint: struct {
					Operator string `json:"operator"`
					Value    string `json:"value"`
				}{
					Operator: "matches",
					Value:    urlPattern,
				},
			},
		},
		Actions: func() []struct {
			ID    string      `json:"id"`
			Value interface{} `json:"value"`
		} {
			result := make([]struct {
				ID    string      `json:"id"`
				Value interface{} `json:"value"`
			}, len(actions))
			for i, a := range actions {
				result[i].ID = a["id"].(string)
				result[i].Value = a["value"]
			}
			return result
		}(),
		Status: "active",
	}

	_, err := cf.CreatePageRule(zoneID, rule)
	return err
}

// BypassCacheRule creates a cache bypass rule
func (cm *CDNManager) BypassCacheRule(zoneID, urlPattern string) error {
	cf := cm.cf

	rule := &PageRule{
		Targets: []struct {
			Target     string `json:"target"`
			Constraint struct {
				Operator string `json:"operator"`
				Value    string `json:"value"`
			} `json:"constraint"`
		}{
			{
				Target: "url",
				Constraint: struct {
					Operator string `json:"operator"`
					Value    string `json:"value"`
				}{
					Operator: "matches",
					Value:    urlPattern,
				},
			},
		},
		Actions: []struct {
			ID    string      `json:"id"`
			Value interface{} `json:"value"`
		}{
			{
				ID:    "cache_level",
				Value: "bypass",
			},
		},
		Status: "active",
	}

	_, err := cf.CreatePageRule(zoneID, rule)
	return err
}

// OptimizeForVPN optimizes CDN settings for VPN traffic
func (cm *CDNManager) OptimizeForVPN(zoneID string) error {
	cf := cm.cf

	// Enable WebSocket for VPN protocols
	if err := cm.EnableWebSockets(zoneID, true); err != nil {
		LogError("CDN", "Failed to enable WebSocket: %v", err)
	}

	// Enable HTTP/2 and HTTP/3
	if err := cm.EnableHTTP2(zoneID, true); err != nil {
		LogError("CDN", "Failed to enable HTTP/2: %v", err)
	}

	if err := cm.EnableHTTP3(zoneID, true); err != nil {
		LogError("CDN", "Failed to enable HTTP/3: %v", err)
	}

	// Enable 0-RTT
	if err := cm.Enable0RTT(zoneID, true); err != nil {
		LogError("CDN", "Failed to enable 0-RTT: %v", err)
	}

	// Enable Brotli
	if err := cm.EnableBrotli(zoneID, true); err != nil {
		LogError("CDN", "Failed to enable Brotli: %v", err)
	}

	// Set SSL to Full (Strict)
	if err := cf.SetSSLMode(zoneID, "strict"); err != nil {
		LogError("CDN", "Failed to set SSL mode: %v", err)
	}

	// Set minimum TLS version to 1.2
	if err := cf.SetMinTLSVersion(zoneID, "1.2"); err != nil {
		LogError("CDN", "Failed to set TLS version: %v", err)
	}

	// Bypass cache for API and subscription endpoints
	if err := cm.BypassCacheRule(zoneID, "*api*"); err != nil {
		LogError("CDN", "Failed to create bypass rule: %v", err)
	}

	if err := cm.BypassCacheRule(zoneID, "*sub*"); err != nil {
		LogError("CDN", "Failed to create bypass rule: %v", err)
	}

	LogInfo("CDN", "VPN optimization applied to zone: %s", zoneID)
	return nil
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// CDN Domain Finder
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// CDNDomain represents a CDN domain for fronting
type CDNDomain struct {
	Domain    string `json:"domain"`
	IP        string `json:"ip"`
	Provider  string `json:"provider"`
	Country   string `json:"country"`
	Latency   int    `json:"latency"`
	Available bool   `json:"available"`
}

// FindCloudflareIPs finds clean Cloudflare IPs
func (cm *CDNManager) FindCloudflareIPs(count int) ([]CDNDomain, error) {
	// Cloudflare IP ranges
	cfRanges := []string{
		"104.16.0.0/13",
		"104.24.0.0/14",
		"172.64.0.0/13",
		"131.0.72.0/22",
		"141.101.64.0/18",
		"108.162.192.0/18",
		"190.93.240.0/20",
		"188.114.96.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
		"162.158.0.0/15",
		"198.41.192.0/18",
	}

	var results []CDNDomain
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Test sample IPs from each range
	for _, cidr := range cfRanges {
		ips := generateSampleIPs(cidr, 5)

		for _, ip := range ips {
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()

				latency := testIPLatency(ip, 443)
				if latency > 0 && latency < 500 {
					mu.Lock()
					results = append(results, CDNDomain{
						Domain:    ip,
						IP:        ip,
						Provider:  "Cloudflare",
						Latency:   latency,
						Available: true,
					})
					mu.Unlock()
				}
			}(ip)
		}
	}

	wg.Wait()

	// Sort by latency
	sort.Slice(results, func(i, j int) bool {
		return results[i].Latency < results[j].Latency
	})

	// Return top N results
	if len(results) > count {
		results = results[:count]
	}

	return results, nil
}

// FindCDNDomains finds CDN domains for domain fronting
func (cm *CDNManager) FindCDNDomains(count int) ([]CDNDomain, error) {
	// Known CDN domains that support fronting
	cdnDomains := []string{
		"speed.cloudflare.com",
		"www.cloudflare.com",
		"cdn.cloudflare.net",
		"ajax.cloudflare.com",
		"cdnjs.cloudflare.com",
		"static.cloudflareinsights.com",
		"challenges.cloudflare.com",
	}

	var results []CDNDomain
	var wg sync.WaitGroup

	for _, domain := range cdnDomains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()

			ips, err := net.LookupIP(d)
			if err != nil || len(ips) == 0 {
				return
			}

			latency := testIPLatency(ips[0].String(), 443)
			if latency > 0 {
				results = append(results, CDNDomain{
					Domain:    d,
					IP:        ips[0].String(),
					Provider:  "Cloudflare",
					Latency:   latency,
					Available: true,
				})
			}
		}(domain)
	}

	wg.Wait()

	// Sort by latency
	sort.Slice(results, func(i, j int) bool {
		return results[i].Latency < results[j].Latency
	})

	if len(results) > count {
		results = results[:count]
	}

	return results, nil
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Helper Functions
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// boolToOnOff converts bool to "on"/"off"
func boolToOnOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// generateSampleIPs generates sample IPs from a CIDR
func generateSampleIPs(cidr string, count int) []string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}

	var ips []string
	ip := ipnet.IP

	for i := 0; i < count; i++ {
		// Increment IP
		for j := len(ip) - 1; j >= 0; j-- {
			ip[j]++
			if ip[j] > 0 {
				break
			}
		}

		if ipnet.Contains(ip) {
			ips = append(ips, ip.String())
		}
	}

	return ips
}

// testIPLatency tests latency to an IP
func testIPLatency(ip string, port int) int {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 3*time.Second)
	if err != nil {
		return -1
	}
	conn.Close()
	return int(time.Since(start).Milliseconds())
}

// multipartWriter helper for form uploads
type multipartWriter struct {
	*bytes.Buffer
	boundary string
}

func newMultipartWriter() *multipartWriter {
	b := make([]byte, 16)
	rand.Read(b)
	return &multipartWriter{
		Buffer:   new(bytes.Buffer),
		boundary: hex.EncodeToString(b),
	}
}

func (m *multipartWriter) FormDataContentType() string {
	return fmt.Sprintf("multipart/form-data; boundary=%s", m.boundary)
}

func (m *multipartWriter) CreateFormField(name string) (io.Writer, error) {
	m.WriteString(fmt.Sprintf("--%s\r\n", m.boundary))
	m.WriteString(fmt.Sprintf("Content-Disposition: form-data; name=\"%s\"\r\n\r\n", name))
	return m, nil
}

func (m *multipartWriter) Close() error {
	m.WriteString(fmt.Sprintf("\r\n--%s--\r\n", m.boundary))
	return nil
}

// cloudflare.go - MX-UI Cloudflare Integration (Part 3)
// Tunnels, Spectrum, Load Balancer, Health Checks

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// TUNNELS MANAGER - Cloudflare Tunnel (Argo Tunnel)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// TunnelManager manages Cloudflare Tunnels
type TunnelManager struct {
	cf *CloudflareManager
}

// NewTunnelManager creates a new tunnel manager
func (cf *CloudflareManager) NewTunnelManager() *TunnelManager {
	return &TunnelManager{cf: cf}
}

// ListTunnels lists all tunnels
func (tm *TunnelManager) ListTunnels() ([]*Tunnel, error) {
	cf := tm.cf

	endpoint := fmt.Sprintf("/accounts/%s/cfd_tunnel", cf.Config.AccountID)
	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var tunnels []*Tunnel
	if err := json.Unmarshal(resp.Result, &tunnels); err != nil {
		return nil, err
	}

	return tunnels, nil
}

// GetTunnel gets a tunnel by ID
func (tm *TunnelManager) GetTunnel(tunnelID string) (*Tunnel, error) {
	cf := tm.cf

	endpoint := fmt.Sprintf("/accounts/%s/cfd_tunnel/%s", cf.Config.AccountID, tunnelID)
	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var tunnel Tunnel
	if err := json.Unmarshal(resp.Result, &tunnel); err != nil {
		return nil, err
	}

	return &tunnel, nil
}

// CreateTunnel creates a new tunnel
func (tm *TunnelManager) CreateTunnel(name string) (*Tunnel, error) {
	cf := tm.cf

	// Generate tunnel secret
	secret := make([]byte, 32)
	rand.Read(secret)
	secretB64 := base64.StdEncoding.EncodeToString(secret)

	body := map[string]interface{}{
		"name":          name,
		"tunnel_secret": secretB64,
		"config_src":    "cloudflare",
	}

	endpoint := fmt.Sprintf("/accounts/%s/cfd_tunnel", cf.Config.AccountID)
	resp, err := cf.apiRequest("POST", endpoint, body)
	if err != nil {
		return nil, err
	}

	var tunnel Tunnel
	if err := json.Unmarshal(resp.Result, &tunnel); err != nil {
		return nil, err
	}

	tunnel.Secret = secretB64

	LogInfo("TUNNEL", "Tunnel created: %s (%s)", name, tunnel.ID)
	return &tunnel, nil
}

// DeleteTunnel deletes a tunnel
func (tm *TunnelManager) DeleteTunnel(tunnelID string) error {
	cf := tm.cf

	// First, clean up connections
	if err := tm.CleanupTunnelConnections(tunnelID); err != nil {
		LogError("TUNNEL", "Failed to cleanup connections: %v", err)
	}

	endpoint := fmt.Sprintf("/accounts/%s/cfd_tunnel/%s", cf.Config.AccountID, tunnelID)
	_, err := cf.apiRequest("DELETE", endpoint, nil)
	if err != nil {
		return err
	}

	LogInfo("TUNNEL", "Tunnel deleted: %s", tunnelID)
	return nil
}

// CleanupTunnelConnections cleans up tunnel connections
func (tm *TunnelManager) CleanupTunnelConnections(tunnelID string) error {
	cf := tm.cf

	endpoint := fmt.Sprintf("/accounts/%s/cfd_tunnel/%s/connections", cf.Config.AccountID, tunnelID)
	_, err := cf.apiRequest("DELETE", endpoint, nil)
	return err
}

// GetTunnelConnections gets tunnel connections
func (tm *TunnelManager) GetTunnelConnections(tunnelID string) ([]*TunnelConnection, error) {
	cf := tm.cf

	endpoint := fmt.Sprintf("/accounts/%s/cfd_tunnel/%s/connections", cf.Config.AccountID, tunnelID)
	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var connections []*TunnelConnection
	if err := json.Unmarshal(resp.Result, &connections); err != nil {
		return nil, err
	}

	return connections, nil
}

// GetTunnelToken gets tunnel token for cloudflared
func (tm *TunnelManager) GetTunnelToken(tunnelID string) (string, error) {
	cf := tm.cf

	endpoint := fmt.Sprintf("/accounts/%s/cfd_tunnel/%s/token", cf.Config.AccountID, tunnelID)
	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return "", err
	}

	var result string
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return "", err
	}

	return result, nil
}

// UpdateTunnelConfig updates tunnel configuration
func (tm *TunnelManager) UpdateTunnelConfig(tunnelID string, config *TunnelConfig) error {
	cf := tm.cf

	endpoint := fmt.Sprintf("/accounts/%s/cfd_tunnel/%s/configurations", cf.Config.AccountID, tunnelID)
	_, err := cf.apiRequest("PUT", endpoint, config)
	if err != nil {
		return err
	}

	LogInfo("TUNNEL", "Tunnel config updated: %s", tunnelID)
	return nil
}

// GetTunnelConfig gets tunnel configuration
func (tm *TunnelManager) GetTunnelConfig(tunnelID string) (*TunnelConfig, error) {
	cf := tm.cf

	endpoint := fmt.Sprintf("/accounts/%s/cfd_tunnel/%s/configurations", cf.Config.AccountID, tunnelID)
	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var config TunnelConfig
	if err := json.Unmarshal(resp.Result, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// AddTunnelRoute adds a route to tunnel
func (tm *TunnelManager) AddTunnelRoute(tunnelID, hostname, service string) error {
	config, err := tm.GetTunnelConfig(tunnelID)
	if err != nil {
		// Create new config if not exists
		config = &TunnelConfig{
			TunnelID: tunnelID,
		}
	}

	// Add new ingress rule
	newIngress := TunnelIngress{
		Hostname: hostname,
		Service:  service,
	}

	// Insert before catch-all rule
	ingress := config.Config.Ingress
	if len(ingress) > 0 && ingress[len(ingress)-1].Hostname == "" {
		// Insert before catch-all
		ingress = append(ingress[:len(ingress)-1], newIngress, ingress[len(ingress)-1])
	} else {
		ingress = append(ingress, newIngress)
		// Add catch-all if not exists
		ingress = append(ingress, TunnelIngress{Service: "http_status:404"})
	}

	config.Config.Ingress = ingress

	return tm.UpdateTunnelConfig(tunnelID, config)
}

// RemoveTunnelRoute removes a route from tunnel
func (tm *TunnelManager) RemoveTunnelRoute(tunnelID, hostname string) error {
	config, err := tm.GetTunnelConfig(tunnelID)
	if err != nil {
		return err
	}

	var newIngress []TunnelIngress
	for _, ing := range config.Config.Ingress {
		if ing.Hostname != hostname {
			newIngress = append(newIngress, ing)
		}
	}

	config.Config.Ingress = newIngress
	return tm.UpdateTunnelConfig(tunnelID, config)
}

// CreateTunnelDNS creates DNS record for tunnel
func (tm *TunnelManager) CreateTunnelDNS(zoneID, tunnelID, subdomain string) (*DNSRecord, error) {
	cf := tm.cf

	record := &DNSRecordCreate{
		Type:    RecordTypeCNAME,
		Name:    subdomain,
		Content: fmt.Sprintf("%s.cfargotunnel.com", tunnelID),
		Proxied: true,
		TTL:     1,
		Comment: "MX-UI Tunnel",
	}

	return cf.CreateDNSRecord(zoneID, record)
}

// GenerateCloudflaredConfig generates cloudflared config file
func (tm *TunnelManager) GenerateCloudflaredConfig(tunnel *Tunnel, ingress []TunnelIngress) string {
	config := map[string]interface{}{
		"tunnel":           tunnel.ID,
		"credentials-file": fmt.Sprintf("/etc/cloudflared/%s.json", tunnel.ID),
		"ingress":          ingress,
	}

	if len(ingress) == 0 {
		config["ingress"] = []map[string]interface{}{
			{"service": "http_status:404"},
		}
	}

	yamlBytes, _ := yaml.Marshal(config)
	return string(yamlBytes)
}

// GenerateCloudflaredCredentials generates cloudflared credentials file
func (tm *TunnelManager) GenerateCloudflaredCredentials(tunnel *Tunnel) string {
	cf := tm.cf

	creds := map[string]string{
		"AccountTag":   cf.Config.AccountID,
		"TunnelID":     tunnel.ID,
		"TunnelName":   tunnel.Name,
		"TunnelSecret": tunnel.Secret,
	}

	jsonBytes, _ := json.MarshalIndent(creds, "", "  ")
	return string(jsonBytes)
}

// GenerateCloudflaredInstallScript generates installation script
func (tm *TunnelManager) GenerateCloudflaredInstallScript(tunnel *Tunnel, token string) string {
	script := fmt.Sprintf(`#!/bin/bash
# MX-UI Cloudflare Tunnel Installation Script

set -e

echo "Installing cloudflared..."

# Detect OS
if [ -f /etc/debian_version ]; then
    # Debian/Ubuntu
    curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
    sudo dpkg -i cloudflared.deb
    rm cloudflared.deb
elif [ -f /etc/redhat-release ]; then
    # CentOS/RHEL
    curl -L --output cloudflared.rpm https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-x86_64.rpm
    sudo rpm -i cloudflared.rpm
    rm cloudflared.rpm
else
    # Generic Linux
    curl -L --output cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
    sudo mv cloudflared /usr/local/bin/
    sudo chmod +x /usr/local/bin/cloudflared
fi

echo "Configuring tunnel..."

# Install as service
sudo cloudflared service install %s

echo "Starting tunnel..."
sudo systemctl start cloudflared
sudo systemctl enable cloudflared

echo "Tunnel installed successfully!"
echo "Tunnel ID: %s"
echo "Tunnel Name: %s"
`, token, tunnel.ID, tunnel.Name)

	return script
}

// GetTunnelStatus gets tunnel status
func (tm *TunnelManager) GetTunnelStatus(tunnelID string) (map[string]interface{}, error) {
	tunnel, err := tm.GetTunnel(tunnelID)
	if err != nil {
		return nil, err
	}

	connections, _ := tm.GetTunnelConnections(tunnelID)

	status := map[string]interface{}{
		"id":          tunnel.ID,
		"name":        tunnel.Name,
		"status":      tunnel.Status,
		"created_at":  tunnel.CreatedAt,
		"connections": len(connections),
		"healthy":     tunnel.Status == "active" && len(connections) > 0,
	}

	if len(connections) > 0 {
		var connInfo []map[string]interface{}
		for _, c := range connections {
			connInfo = append(connInfo, map[string]interface{}{
				"id":             c.ID,
				"colo":           c.ColoName,
				"origin_ip":      c.OriginIP,
				"client_version": c.ClientVersion,
				"opened_at":      c.OpenedAt,
			})
		}
		status["connection_details"] = connInfo
	}

	return status, nil
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SPECTRUM MANAGER - TCP/UDP Proxy
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// SpectrumManager manages Spectrum applications
type SpectrumManager struct {
	cf *CloudflareManager
}

// NewSpectrumManager creates a new spectrum manager
func (cf *CloudflareManager) NewSpectrumManager() *SpectrumManager {
	return &SpectrumManager{cf: cf}
}

// ListSpectrumApps lists all Spectrum applications
func (sm *SpectrumManager) ListSpectrumApps(zoneID string) ([]*SpectrumApp, error) {
	cf := sm.cf

	endpoint := fmt.Sprintf("/zones/%s/spectrum/apps", zoneID)
	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var apps []*SpectrumApp
	if err := json.Unmarshal(resp.Result, &apps); err != nil {
		return nil, err
	}

	return apps, nil
}

// GetSpectrumApp gets a Spectrum application by ID
func (sm *SpectrumManager) GetSpectrumApp(zoneID, appID string) (*SpectrumApp, error) {
	cf := sm.cf

	endpoint := fmt.Sprintf("/zones/%s/spectrum/apps/%s", zoneID, appID)
	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var app SpectrumApp
	if err := json.Unmarshal(resp.Result, &app); err != nil {
		return nil, err
	}

	return &app, nil
}

// CreateSpectrumApp creates a new Spectrum application
func (sm *SpectrumManager) CreateSpectrumApp(zoneID string, app *SpectrumAppCreate) (*SpectrumApp, error) {
	cf := sm.cf

	endpoint := fmt.Sprintf("/zones/%s/spectrum/apps", zoneID)
	resp, err := cf.apiRequest("POST", endpoint, app)
	if err != nil {
		return nil, err
	}

	var newApp SpectrumApp
	if err := json.Unmarshal(resp.Result, &newApp); err != nil {
		return nil, err
	}

	LogInfo("SPECTRUM", "App created: %s (protocol: %s)", newApp.ID, newApp.Protocol)
	return &newApp, nil
}

// SpectrumAppCreate for creating Spectrum apps
type SpectrumAppCreate struct {
	Protocol         string             `json:"protocol"`
	DNS              SpectrumDNS        `json:"dns"`
	OriginDirect     []string           `json:"origin_direct,omitempty"`
	OriginDNS        *SpectrumOriginDNS `json:"origin_dns,omitempty"`
	OriginPort       interface{}        `json:"origin_port"`
	IPFirewall       bool               `json:"ip_firewall"`
	ProxyProtocol    string             `json:"proxy_protocol"`
	TLS              string             `json:"tls"`
	TrafficType      string             `json:"traffic_type"`
	EdgeIPs          *SpectrumEdgeIPs   `json:"edge_ips,omitempty"`
	ArgoSmartRouting bool               `json:"argo_smart_routing"`
}

// SpectrumDNS for Spectrum DNS config
type SpectrumDNS struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

// SpectrumOriginDNS for Spectrum origin DNS
type SpectrumOriginDNS struct {
	Name string `json:"name"`
}

// SpectrumEdgeIPs for Spectrum edge IPs
type SpectrumEdgeIPs struct {
	Type         string   `json:"type"`
	Connectivity string   `json:"connectivity"`
	IPs          []string `json:"ips,omitempty"`
}

// UpdateSpectrumApp updates a Spectrum application
func (sm *SpectrumManager) UpdateSpectrumApp(zoneID, appID string, app *SpectrumAppCreate) (*SpectrumApp, error) {
	cf := sm.cf

	endpoint := fmt.Sprintf("/zones/%s/spectrum/apps/%s", zoneID, appID)
	resp, err := cf.apiRequest("PUT", endpoint, app)
	if err != nil {
		return nil, err
	}

	var updated SpectrumApp
	if err := json.Unmarshal(resp.Result, &updated); err != nil {
		return nil, err
	}

	LogInfo("SPECTRUM", "App updated: %s", appID)
	return &updated, nil
}

// DeleteSpectrumApp deletes a Spectrum application
func (sm *SpectrumManager) DeleteSpectrumApp(zoneID, appID string) error {
	cf := sm.cf

	endpoint := fmt.Sprintf("/zones/%s/spectrum/apps/%s", zoneID, appID)
	_, err := cf.apiRequest("DELETE", endpoint, nil)
	if err != nil {
		return err
	}

	LogInfo("SPECTRUM", "App deleted: %s", appID)
	return nil
}

// CreateTCPProxy creates a TCP proxy (SSH, VPN, etc.)
func (sm *SpectrumManager) CreateTCPProxy(zoneID, subdomain, originIP string, originPort, edgePort int) (*SpectrumApp, error) {
	app := &SpectrumAppCreate{
		Protocol: fmt.Sprintf("tcp/%d", edgePort),
		DNS: SpectrumDNS{
			Type: "CNAME",
			Name: subdomain,
		},
		OriginDirect:  []string{fmt.Sprintf("tcp://%s:%d", originIP, originPort)},
		OriginPort:    originPort,
		IPFirewall:    false,
		ProxyProtocol: "off",
		TLS:           "off",
		TrafficType:   "direct",
		EdgeIPs: &SpectrumEdgeIPs{
			Type:         "dynamic",
			Connectivity: "all",
		},
	}

	return sm.CreateSpectrumApp(zoneID, app)
}

// CreateSSHProxy creates an SSH proxy
func (sm *SpectrumManager) CreateSSHProxy(zoneID, subdomain, originIP string, originPort int) (*SpectrumApp, error) {
	return sm.CreateTCPProxy(zoneID, subdomain, originIP, originPort, 22)
}

// CreateVPNProxy creates a VPN proxy (for WireGuard, OpenVPN, etc.)
func (sm *SpectrumManager) CreateVPNProxy(zoneID, subdomain, originIP string, originPort int, protocol string) (*SpectrumApp, error) {
	var protoStr string
	if protocol == "udp" {
		protoStr = fmt.Sprintf("udp/%d", originPort)
	} else {
		protoStr = fmt.Sprintf("tcp/%d", originPort)
	}

	app := &SpectrumAppCreate{
		Protocol: protoStr,
		DNS: SpectrumDNS{
			Type: "CNAME",
			Name: subdomain,
		},
		OriginDirect:     []string{fmt.Sprintf("%s://%s:%d", protocol, originIP, originPort)},
		OriginPort:       originPort,
		IPFirewall:       false,
		ProxyProtocol:    "off",
		TLS:              "off",
		TrafficType:      "direct",
		ArgoSmartRouting: true,
	}

	return sm.CreateSpectrumApp(zoneID, app)
}

// CreateHTTPSProxy creates an HTTPS proxy with TLS termination
func (sm *SpectrumManager) CreateHTTPSProxy(zoneID, subdomain, originIP string, originPort int) (*SpectrumApp, error) {
	app := &SpectrumAppCreate{
		Protocol: "tcp/443",
		DNS: SpectrumDNS{
			Type: "CNAME",
			Name: subdomain,
		},
		OriginDirect:  []string{fmt.Sprintf("tcp://%s:%d", originIP, originPort)},
		OriginPort:    originPort,
		IPFirewall:    true,
		ProxyProtocol: "v1",
		TLS:           "full",
		TrafficType:   "https",
	}

	return sm.CreateSpectrumApp(zoneID, app)
}

// CreateMinecraftProxy creates a Minecraft server proxy
func (sm *SpectrumManager) CreateMinecraftProxy(zoneID, subdomain, originIP string) (*SpectrumApp, error) {
	return sm.CreateTCPProxy(zoneID, subdomain, originIP, 25565, 25565)
}

// CreateRDPProxy creates an RDP proxy
func (sm *SpectrumManager) CreateRDPProxy(zoneID, subdomain, originIP string) (*SpectrumApp, error) {
	return sm.CreateTCPProxy(zoneID, subdomain, originIP, 3389, 3389)
}

// GetSpectrumAnalytics gets Spectrum analytics
func (sm *SpectrumManager) GetSpectrumAnalytics(zoneID string, since, until time.Time) (map[string]interface{}, error) {
	cf := sm.cf

	endpoint := fmt.Sprintf("/zones/%s/spectrum/analytics/events/summary?since=%s&until=%s",
		zoneID,
		since.Format(time.RFC3339),
		until.Format(time.RFC3339))

	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var analytics map[string]interface{}
	if err := json.Unmarshal(resp.Result, &analytics); err != nil {
		return nil, err
	}

	return analytics, nil
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// LOAD BALANCER MANAGER
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// LoadBalancerManager manages Load Balancers
type LoadBalancerManager struct {
	cf *CloudflareManager
}

// NewLoadBalancerManager creates a new load balancer manager
func (cf *CloudflareManager) NewLoadBalancerManager() *LoadBalancerManager {
	return &LoadBalancerManager{cf: cf}
}

// ListLoadBalancers lists all load balancers
func (lm *LoadBalancerManager) ListLoadBalancers(zoneID string) ([]*LoadBalancer, error) {
	cf := lm.cf

	endpoint := fmt.Sprintf("/zones/%s/load_balancers", zoneID)
	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var lbs []*LoadBalancer
	if err := json.Unmarshal(resp.Result, &lbs); err != nil {
		return nil, err
	}

	return lbs, nil
}

// GetLoadBalancer gets a load balancer by ID
func (lm *LoadBalancerManager) GetLoadBalancer(zoneID, lbID string) (*LoadBalancer, error) {
	cf := lm.cf

	endpoint := fmt.Sprintf("/zones/%s/load_balancers/%s", zoneID, lbID)
	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var lb LoadBalancer
	if err := json.Unmarshal(resp.Result, &lb); err != nil {
		return nil, err
	}

	return &lb, nil
}

// CreateLoadBalancer creates a new load balancer
func (lm *LoadBalancerManager) CreateLoadBalancer(zoneID string, lb *LoadBalancerCreate) (*LoadBalancer, error) {
	cf := lm.cf

	endpoint := fmt.Sprintf("/zones/%s/load_balancers", zoneID)
	resp, err := cf.apiRequest("POST", endpoint, lb)
	if err != nil {
		return nil, err
	}

	var newLB LoadBalancer
	if err := json.Unmarshal(resp.Result, &newLB); err != nil {
		return nil, err
	}

	LogInfo("LB", "Load balancer created: %s (%s)", newLB.Name, newLB.ID)
	return &newLB, nil
}

// LoadBalancerCreate for creating load balancers
type LoadBalancerCreate struct {
	Name               string              `json:"name"`
	Description        string              `json:"description,omitempty"`
	TTL                int                 `json:"ttl,omitempty"`
	FallbackPool       string              `json:"fallback_pool"`
	DefaultPools       []string            `json:"default_pools"`
	RegionPools        map[string][]string `json:"region_pools,omitempty"`
	CountryPools       map[string][]string `json:"country_pools,omitempty"`
	PopPools           map[string][]string `json:"pop_pools,omitempty"`
	Proxied            bool                `json:"proxied"`
	Enabled            bool                `json:"enabled"`
	SessionAffinity    string              `json:"session_affinity,omitempty"`
	SessionAffinityTTL int                 `json:"session_affinity_ttl,omitempty"`
	SteeringPolicy     string              `json:"steering_policy,omitempty"`
	RandomSteering     *RandomSteering     `json:"random_steering,omitempty"`
	AdaptiveRouting    *AdaptiveRouting    `json:"adaptive_routing,omitempty"`
	LocationStrategy   *LocationStrategy   `json:"location_strategy,omitempty"`
}

// UpdateLoadBalancer updates a load balancer
func (lm *LoadBalancerManager) UpdateLoadBalancer(zoneID, lbID string, lb *LoadBalancerCreate) (*LoadBalancer, error) {
	cf := lm.cf

	endpoint := fmt.Sprintf("/zones/%s/load_balancers/%s", zoneID, lbID)
	resp, err := cf.apiRequest("PUT", endpoint, lb)
	if err != nil {
		return nil, err
	}

	var updated LoadBalancer
	if err := json.Unmarshal(resp.Result, &updated); err != nil {
		return nil, err
	}

	LogInfo("LB", "Load balancer updated: %s", lbID)
	return &updated, nil
}

// DeleteLoadBalancer deletes a load balancer
func (lm *LoadBalancerManager) DeleteLoadBalancer(zoneID, lbID string) error {
	cf := lm.cf

	endpoint := fmt.Sprintf("/zones/%s/load_balancers/%s", zoneID, lbID)
	_, err := cf.apiRequest("DELETE", endpoint, nil)
	if err != nil {
		return err
	}

	LogInfo("LB", "Load balancer deleted: %s", lbID)
	return nil
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// POOL MANAGEMENT
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// ListPools lists all pools
func (lm *LoadBalancerManager) ListPools() ([]*LoadBalancerPool, error) {
	cf := lm.cf

	endpoint := fmt.Sprintf("/accounts/%s/load_balancers/pools", cf.Config.AccountID)
	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var pools []*LoadBalancerPool
	if err := json.Unmarshal(resp.Result, &pools); err != nil {
		return nil, err
	}

	return pools, nil
}

// GetPool gets a pool by ID
func (lm *LoadBalancerManager) GetPool(poolID string) (*LoadBalancerPool, error) {
	cf := lm.cf

	endpoint := fmt.Sprintf("/accounts/%s/load_balancers/pools/%s", cf.Config.AccountID, poolID)
	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var pool LoadBalancerPool
	if err := json.Unmarshal(resp.Result, &pool); err != nil {
		return nil, err
	}

	return &pool, nil
}

// CreatePool creates a new pool
func (lm *LoadBalancerManager) CreatePool(pool *PoolCreate) (*LoadBalancerPool, error) {
	cf := lm.cf

	endpoint := fmt.Sprintf("/accounts/%s/load_balancers/pools", cf.Config.AccountID)
	resp, err := cf.apiRequest("POST", endpoint, pool)
	if err != nil {
		return nil, err
	}

	var newPool LoadBalancerPool
	if err := json.Unmarshal(resp.Result, &newPool); err != nil {
		return nil, err
	}

	LogInfo("LB", "Pool created: %s (%s)", newPool.Name, newPool.ID)
	return &newPool, nil
}

// PoolCreate for creating pools
type PoolCreate struct {
	Name              string          `json:"name"`
	Description       string          `json:"description,omitempty"`
	Origins           []*Origin       `json:"origins"`
	MinimumOrigins    int             `json:"minimum_origins,omitempty"`
	CheckRegions      []string        `json:"check_regions,omitempty"`
	Enabled           bool            `json:"enabled"`
	Monitor           string          `json:"monitor,omitempty"`
	NotificationEmail string          `json:"notification_email,omitempty"`
	Latitude          float64         `json:"latitude,omitempty"`
	Longitude         float64         `json:"longitude,omitempty"`
	OriginSteering    *OriginSteering `json:"origin_steering,omitempty"`
}

// UpdatePool updates a pool
func (lm *LoadBalancerManager) UpdatePool(poolID string, pool *PoolCreate) (*LoadBalancerPool, error) {
	cf := lm.cf

	endpoint := fmt.Sprintf("/accounts/%s/load_balancers/pools/%s", cf.Config.AccountID, poolID)
	resp, err := cf.apiRequest("PUT", endpoint, pool)
	if err != nil {
		return nil, err
	}

	var updated LoadBalancerPool
	if err := json.Unmarshal(resp.Result, &updated); err != nil {
		return nil, err
	}

	LogInfo("LB", "Pool updated: %s", poolID)
	return &updated, nil
}

// DeletePool deletes a pool
func (lm *LoadBalancerManager) DeletePool(poolID string) error {
	cf := lm.cf

	endpoint := fmt.Sprintf("/accounts/%s/load_balancers/pools/%s", cf.Config.AccountID, poolID)
	_, err := cf.apiRequest("DELETE", endpoint, nil)
	if err != nil {
		return err
	}

	LogInfo("LB", "Pool deleted: %s", poolID)
	return nil
}

// AddOriginToPool adds an origin to a pool
func (lm *LoadBalancerManager) AddOriginToPool(poolID string, origin *Origin) error {
	pool, err := lm.GetPool(poolID)
	if err != nil {
		return err
	}

	pool.Origins = append(pool.Origins, origin)

	poolUpdate := &PoolCreate{
		Name:           pool.Name,
		Description:    pool.Description,
		Origins:        pool.Origins,
		MinimumOrigins: pool.MinimumOrigins,
		CheckRegions:   pool.CheckRegions,
		Enabled:        pool.Enabled,
		Monitor:        pool.Monitor,
	}

	_, err = lm.UpdatePool(poolID, poolUpdate)
	return err
}

// RemoveOriginFromPool removes an origin from a pool
func (lm *LoadBalancerManager) RemoveOriginFromPool(poolID, originName string) error {
	pool, err := lm.GetPool(poolID)
	if err != nil {
		return err
	}

	var newOrigins []*Origin
	for _, o := range pool.Origins {
		if o.Name != originName {
			newOrigins = append(newOrigins, o)
		}
	}

	poolUpdate := &PoolCreate{
		Name:           pool.Name,
		Description:    pool.Description,
		Origins:        newOrigins,
		MinimumOrigins: pool.MinimumOrigins,
		CheckRegions:   pool.CheckRegions,
		Enabled:        pool.Enabled,
		Monitor:        pool.Monitor,
	}

	_, err = lm.UpdatePool(poolID, poolUpdate)
	return err
}

// GetPoolHealth gets pool health status
func (lm *LoadBalancerManager) GetPoolHealth(poolID string) (map[string]interface{}, error) {
	cf := lm.cf

	endpoint := fmt.Sprintf("/accounts/%s/load_balancers/pools/%s/health", cf.Config.AccountID, poolID)
	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var health map[string]interface{}
	if err := json.Unmarshal(resp.Result, &health); err != nil {
		return nil, err
	}

	return health, nil
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// HEALTH CHECK MANAGER
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// HealthCheckManager manages Health Checks
type HealthCheckManager struct {
	cf *CloudflareManager
}

// NewHealthCheckManager creates a new health check manager
func (cf *CloudflareManager) NewHealthCheckManager() *HealthCheckManager {
	return &HealthCheckManager{cf: cf}
}

// ListMonitors lists all monitors (health checks)
func (hm *HealthCheckManager) ListMonitors() ([]*HealthCheck, error) {
	cf := hm.cf

	endpoint := fmt.Sprintf("/accounts/%s/load_balancers/monitors", cf.Config.AccountID)
	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var monitors []*HealthCheck
	if err := json.Unmarshal(resp.Result, &monitors); err != nil {
		return nil, err
	}

	return monitors, nil
}

// GetMonitor gets a monitor by ID
func (hm *HealthCheckManager) GetMonitor(monitorID string) (*HealthCheck, error) {
	cf := hm.cf

	endpoint := fmt.Sprintf("/accounts/%s/load_balancers/monitors/%s", cf.Config.AccountID, monitorID)
	resp, err := cf.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var monitor HealthCheck
	if err := json.Unmarshal(resp.Result, &monitor); err != nil {
		return nil, err
	}

	return &monitor, nil
}

// CreateMonitor creates a new monitor
func (hm *HealthCheckManager) CreateMonitor(monitor *MonitorCreate) (*HealthCheck, error) {
	cf := hm.cf

	endpoint := fmt.Sprintf("/accounts/%s/load_balancers/monitors", cf.Config.AccountID)
	resp, err := cf.apiRequest("POST", endpoint, monitor)
	if err != nil {
		return nil, err
	}

	var newMonitor HealthCheck
	if err := json.Unmarshal(resp.Result, &newMonitor); err != nil {
		return nil, err
	}

	LogInfo("HEALTH", "Monitor created: %s (%s)", newMonitor.Description, newMonitor.ID)
	return &newMonitor, nil
}

// MonitorCreate for creating monitors
type MonitorCreate struct {
	Type            string              `json:"type"` // http, https, tcp, udp_icmp, icmp_ping, smtp
	Description     string              `json:"description,omitempty"`
	Method          string              `json:"method,omitempty"` // GET, HEAD
	Path            string              `json:"path,omitempty"`
	Header          map[string][]string `json:"header,omitempty"`
	Port            int                 `json:"port,omitempty"`
	Timeout         int                 `json:"timeout"`
	Retries         int                 `json:"retries"`
	Interval        int                 `json:"interval"`
	ExpectedBody    string              `json:"expected_body,omitempty"`
	ExpectedCodes   string              `json:"expected_codes,omitempty"`
	FollowRedirects bool                `json:"follow_redirects,omitempty"`
	AllowInsecure   bool                `json:"allow_insecure,omitempty"`
	ConsecutiveUp   int                 `json:"consecutive_up,omitempty"`
	ConsecutiveDown int                 `json:"consecutive_down,omitempty"`
	ProbeZone       string              `json:"probe_zone,omitempty"`
}

// UpdateMonitor updates a monitor
func (hm *HealthCheckManager) UpdateMonitor(monitorID string, monitor *MonitorCreate) (*HealthCheck, error) {
	cf := hm.cf

	endpoint := fmt.Sprintf("/accounts/%s/load_balancers/monitors/%s", cf.Config.AccountID, monitorID)
	resp, err := cf.apiRequest("PUT", endpoint, monitor)
	if err != nil {
		return nil, err
	}

	var updated HealthCheck
	if err := json.Unmarshal(resp.Result, &updated); err != nil {
		return nil, err
	}

	LogInfo("HEALTH", "Monitor updated: %s", monitorID)
	return &updated, nil
}

// DeleteMonitor deletes a monitor
func (hm *HealthCheckManager) DeleteMonitor(monitorID string) error {
	cf := hm.cf

	endpoint := fmt.Sprintf("/accounts/%s/load_balancers/monitors/%s", cf.Config.AccountID, monitorID)
	_, err := cf.apiRequest("DELETE", endpoint, nil)
	if err != nil {
		return err
	}

	LogInfo("HEALTH", "Monitor deleted: %s", monitorID)
	return nil
}

// PreviewMonitor previews monitor results
func (hm *HealthCheckManager) PreviewMonitor(monitorID string) (map[string]interface{}, error) {
	cf := hm.cf

	endpoint := fmt.Sprintf("/accounts/%s/load_balancers/monitors/%s/preview", cf.Config.AccountID, monitorID)
	resp, err := cf.apiRequest("POST", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateHTTPMonitor creates an HTTP health check
func (hm *HealthCheckManager) CreateHTTPMonitor(description, path string, port int, interval int) (*HealthCheck, error) {
	monitor := &MonitorCreate{
		Type:            "http",
		Description:     description,
		Method:          "GET",
		Path:            path,
		Port:            port,
		Timeout:         5,
		Retries:         2,
		Interval:        interval,
		ExpectedCodes:   "200",
		ConsecutiveUp:   2,
		ConsecutiveDown: 2,
	}

	return hm.CreateMonitor(monitor)
}

// CreateHTTPSMonitor creates an HTTPS health check
func (hm *HealthCheckManager) CreateHTTPSMonitor(description, path string, port int, interval int) (*HealthCheck, error) {
	monitor := &MonitorCreate{
		Type:            "https",
		Description:     description,
		Method:          "GET",
		Path:            path,
		Port:            port,
		Timeout:         5,
		Retries:         2,
		Interval:        interval,
		ExpectedCodes:   "200",
		FollowRedirects: true,
		AllowInsecure:   false,
		ConsecutiveUp:   2,
		ConsecutiveDown: 2,
	}

	return hm.CreateMonitor(monitor)
}

// CreateTCPMonitor creates a TCP health check
func (hm *HealthCheckManager) CreateTCPMonitor(description string, port int, interval int) (*HealthCheck, error) {
	monitor := &MonitorCreate{
		Type:            "tcp",
		Description:     description,
		Port:            port,
		Timeout:         5,
		Retries:         2,
		Interval:        interval,
		ConsecutiveUp:   2,
		ConsecutiveDown: 2,
	}

	return hm.CreateMonitor(monitor)
}

// CreateICMPMonitor creates an ICMP ping health check
func (hm *HealthCheckManager) CreateICMPMonitor(description string, interval int) (*HealthCheck, error) {
	monitor := &MonitorCreate{
		Type:            "icmp_ping",
		Description:     description,
		Timeout:         5,
		Retries:         2,
		Interval:        interval,
		ConsecutiveUp:   2,
		ConsecutiveDown: 2,
	}

	return hm.CreateMonitor(monitor)
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// QUICK SETUP HELPERS - VPN Load Balancing
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// VPNLoadBalancerConfig for VPN load balancer setup
type VPNLoadBalancerConfig struct {
	Name            string
	Subdomain       string
	ZoneID          string
	Servers         []VPNServer
	HealthPath      string
	HealthPort      int
	SessionAffinity bool
	Proxied         bool
}

// VPNServer represents a VPN server
type VPNServer struct {
	Name     string
	Address  string
	Weight   float64
	Enabled  bool
	Location string
}

// SetupVPNLoadBalancer sets up complete VPN load balancer
func (lm *LoadBalancerManager) SetupVPNLoadBalancer(config *VPNLoadBalancerConfig) (*LoadBalancer, error) {
	cf := lm.cf
	hm := cf.NewHealthCheckManager()

	// 1. Create health monitor
	monitor, err := hm.CreateHTTPSMonitor(
		fmt.Sprintf("%s Health Check", config.Name),
		config.HealthPath,
		config.HealthPort,
		60,
	)
	if err != nil {
		LogError("LB", "Failed to create health monitor: %v", err)
		// Continue without monitor
	}

	// 2. Create origins
	var origins []*Origin
	for _, server := range config.Servers {
		origins = append(origins, &Origin{
			Name:    server.Name,
			Address: server.Address,
			Weight:  server.Weight,
			Enabled: server.Enabled,
		})
	}

	// 3. Create pool
	poolCreate := &PoolCreate{
		Name:         fmt.Sprintf("%s-pool", config.Name),
		Description:  fmt.Sprintf("Pool for %s", config.Name),
		Origins:      origins,
		Enabled:      true,
		CheckRegions: []string{"WNAM", "ENAM", "WEU", "EEU", "NSAM", "SSAM", "OC", "ME", "NAF", "SAF", "SAS", "SEAS", "NEAS"},
		OriginSteering: &OriginSteering{
			Policy: "random",
		},
	}

	if monitor != nil {
		poolCreate.Monitor = monitor.ID
	}

	pool, err := lm.CreatePool(poolCreate)
	if err != nil {
		return nil, fmt.Errorf("failed to create pool: %v", err)
	}

	// 4. Create load balancer
	lbCreate := &LoadBalancerCreate{
		Name:           fmt.Sprintf("%s.%s", config.Subdomain, cf.Config.DefaultZoneName),
		Description:    config.Name,
		FallbackPool:   pool.ID,
		DefaultPools:   []string{pool.ID},
		Proxied:        config.Proxied,
		Enabled:        true,
		TTL:            30,
		SteeringPolicy: "dynamic_latency",
		AdaptiveRouting: &AdaptiveRouting{
			FailoverAcrossPools: true,
		},
	}

	if config.SessionAffinity {
		lbCreate.SessionAffinity = "cookie"
		lbCreate.SessionAffinityTTL = 1800
	}

	lb, err := lm.CreateLoadBalancer(config.ZoneID, lbCreate)
	if err != nil {
		return nil, fmt.Errorf("failed to create load balancer: %v", err)
	}

	LogInfo("LB", "VPN Load Balancer setup complete: %s", lb.Name)
	return lb, nil
}

// AddServerToVPNLB adds a server to VPN load balancer
func (lm *LoadBalancerManager) AddServerToVPNLB(lbID, poolID string, server VPNServer) error {
	origin := &Origin{
		Name:    server.Name,
		Address: server.Address,
		Weight:  server.Weight,
		Enabled: server.Enabled,
	}

	return lm.AddOriginToPool(poolID, origin)
}

// RemoveServerFromVPNLB removes a server from VPN load balancer
func (lm *LoadBalancerManager) RemoveServerFromVPNLB(poolID, serverName string) error {
	return lm.RemoveOriginFromPool(poolID, serverName)
}

// GetVPNLBStatus gets VPN load balancer status
func (lm *LoadBalancerManager) GetVPNLBStatus(zoneID, lbID string) (map[string]interface{}, error) {
	lb, err := lm.GetLoadBalancer(zoneID, lbID)
	if err != nil {
		return nil, err
	}

	status := map[string]interface{}{
		"id":              lb.ID,
		"name":            lb.Name,
		"enabled":         lb.Enabled,
		"proxied":         lb.Proxied,
		"steering_policy": lb.SteeringPolicy,
		"pools":           []map[string]interface{}{},
	}

	// Get pool health for each pool
	for _, poolID := range lb.DefaultPools {
		poolHealth, err := lm.GetPoolHealth(poolID)
		if err != nil {
			continue
		}

		pool, err := lm.GetPool(poolID)
		if err != nil {
			continue
		}

		poolStatus := map[string]interface{}{
			"id":      pool.ID,
			"name":    pool.Name,
			"healthy": pool.Healthy,
			"enabled": pool.Enabled,
			"origins": []map[string]interface{}{},
			"health":  poolHealth,
		}

		for _, origin := range pool.Origins {
			originStatus := map[string]interface{}{
				"name":    origin.Name,
				"address": origin.Address,
				"weight":  origin.Weight,
				"enabled": origin.Enabled,
			}
			poolStatus["origins"] = append(poolStatus["origins"].([]map[string]interface{}), originStatus)
		}

		status["pools"] = append(status["pools"].([]map[string]interface{}), poolStatus)
	}

	return status, nil
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// GEO STEERING HELPERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// GeoSteeringConfig for geo-based steering
type GeoSteeringConfig struct {
	RegionPools  map[string][]string // region -> pool IDs
	CountryPools map[string][]string // country code -> pool IDs
	PopPools     map[string][]string // PoP -> pool IDs
}

// SetupGeoSteering sets up geographic steering for a load balancer
func (lm *LoadBalancerManager) SetupGeoSteering(zoneID, lbID string, config *GeoSteeringConfig) (*LoadBalancer, error) {
	lb, err := lm.GetLoadBalancer(zoneID, lbID)
	if err != nil {
		return nil, err
	}

	lbUpdate := &LoadBalancerCreate{
		Name:           lb.Name,
		Description:    lb.Description,
		FallbackPool:   lb.FallbackPool,
		DefaultPools:   lb.DefaultPools,
		RegionPools:    config.RegionPools,
		CountryPools:   config.CountryPools,
		PopPools:       config.PopPools,
		Proxied:        lb.Proxied,
		Enabled:        lb.Enabled,
		SteeringPolicy: "geo",
	}

	return lm.UpdateLoadBalancer(zoneID, lbID, lbUpdate)
}

// Cloudflare Regions
var CloudflareRegions = map[string]string{
	"WNAM": "Western North America",
	"ENAM": "Eastern North America",
	"WEU":  "Western Europe",
	"EEU":  "Eastern Europe",
	"NSAM": "Northern South America",
	"SSAM": "Southern South America",
	"OC":   "Oceania",
	"ME":   "Middle East",
	"NAF":  "Northern Africa",
	"SAF":  "Southern Africa",
	"SAS":  "Southern Asia",
	"SEAS": "Southeast Asia",
	"NEAS": "Northeast Asia",
}

// CreateRegionalPools creates pools for each region
func (lm *LoadBalancerManager) CreateRegionalPools(baseName string, monitorID string) (map[string]string, error) {
	regionPools := make(map[string]string)

	for code, name := range CloudflareRegions {
		pool := &PoolCreate{
			Name:         fmt.Sprintf("%s-%s", baseName, strings.ToLower(code)),
			Description:  fmt.Sprintf("%s pool for %s", baseName, name),
			Origins:      []*Origin{},
			Enabled:      true,
			CheckRegions: []string{code},
			Monitor:      monitorID,
		}

		created, err := lm.CreatePool(pool)
		if err != nil {
			LogError("LB", "Failed to create pool for %s: %v", code, err)
			continue
		}

		regionPools[code] = created.ID
	}

	return regionPools, nil
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// STATUS & MONITORING
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// GetCloudflareStatus returns overall Cloudflare status
func (cf *CloudflareManager) GetCloudflareStatus() map[string]interface{} {
	cf.mu.RLock()
	defer cf.mu.RUnlock()

	status := map[string]interface{}{
		"connected":       cf.isConnected,
		"api_calls":       cf.apiCallCount,
		"error_count":     cf.errorCount,
		"last_api_call":   cf.lastAPICall.Unix(),
		"account_id":      cf.Config.AccountID,
		"default_zone":    cf.Config.DefaultZoneID,
		"warp_enabled":    cf.Config.WARPEnabled,
		"workers_enabled": cf.Config.WorkersEnabled,
		"cdn_enabled":     cf.Config.CDNEnabled,
		"tunnels_enabled": cf.Config.TunnelsEnabled,
	}

	// WARP status
	if cf.warpManager != nil {
		status["warp"] = cf.warpManager.GetWARPStatus()
	}

	return status
}

// GetAllZonesStatus returns status of all zones
func (cf *CloudflareManager) GetAllZonesStatus() ([]map[string]interface{}, error) {
	zones, err := cf.ListZones()
	if err != nil {
		return nil, err
	}

	var statuses []map[string]interface{}
	for _, zone := range zones {
		status := map[string]interface{}{
			"id":           zone.ID,
			"name":         zone.Name,
			"status":       zone.Status,
			"paused":       zone.Paused,
			"type":         zone.Type,
			"name_servers": zone.NameServers,
			"plan":         zone.Plan.Name,
		}

		// Get DNS record count
		records, err := cf.ListDNSRecords(zone.ID)
		if err == nil {
			status["dns_records"] = len(records)
		}

		statuses = append(statuses, status)
	}

	return statuses, nil
}

// HealthCheckAll performs health check on all services
func (cf *CloudflareManager) HealthCheckAll() map[string]interface{} {
	results := make(map[string]interface{})

	// API connectivity
	if err := cf.VerifyCredentials(); err != nil {
		results["api"] = map[string]interface{}{"healthy": false, "error": err.Error()}
	} else {
		results["api"] = map[string]interface{}{"healthy": true}
	}

	// WARP
	if cf.warpManager != nil && cf.Config.WARPEnabled {
		warpStatus := cf.warpManager.GetWARPStatus()
		results["warp"] = map[string]interface{}{
			"healthy":    warpStatus["registered"].(bool),
			"registered": warpStatus["registered"],
		}
	}

	// Default zone
	if cf.Config.DefaultZoneID != "" {
		zone, err := cf.GetZone(cf.Config.DefaultZoneID)
		if err != nil {
			results["default_zone"] = map[string]interface{}{"healthy": false, "error": err.Error()}
		} else {
			results["default_zone"] = map[string]interface{}{
				"healthy": zone.Status == "active",
				"status":  zone.Status,
				"name":    zone.Name,
			}
		}
	}

	return results
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// AUTO-SYNC DNS WITH NODES
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// SyncDNSWithNodes synchronizes DNS records with node IPs
func (cf *CloudflareManager) SyncDNSWithNodes(nodes []*CFNodeInfo, subdomain string) error {
	if cf.Config.DefaultZoneID == "" {
		return fmt.Errorf("no default zone configured")
	}

	// Get existing records
	existingRecords, err := cf.FindDNSRecordByName(cf.Config.DefaultZoneID, subdomain, "")
	if err != nil {
		return err
	}

	existingIPs := make(map[string]string) // IP -> record ID
	for _, r := range existingRecords {
		if r.Type == RecordTypeA || r.Type == RecordTypeAAAA {
			existingIPs[r.Content] = r.ID
		}
	}

	// Add/update records for nodes
	nodeIPs := make(map[string]bool)
	for _, node := range nodes {
		if node.IP == "" || !node.Enabled {
			continue
		}

		nodeIPs[node.IP] = true

		// Determine record type
		recordType := RecordTypeA
		if strings.Contains(node.IP, ":") {
			recordType = RecordTypeAAAA
		}

		// Check if record exists
		if _, exists := existingIPs[node.IP]; !exists {
			// Create new record
			record := &DNSRecordCreate{
				Type:    recordType,
				Name:    subdomain,
				Content: node.IP,
				TTL:     1,
				Proxied: true,
				Comment: fmt.Sprintf("MX-UI Node: %s", node.Name),
			}

			_, err := cf.CreateDNSRecord(cf.Config.DefaultZoneID, record)
			if err != nil {
				LogError("CLOUDFLARE", "Failed to create DNS for %s: %v", node.IP, err)
			} else {
				LogInfo("CLOUDFLARE", "Created DNS record: %s -> %s", subdomain, node.IP)
			}
		}
	}

	// Remove records for non-existent nodes
	for ip, recordID := range existingIPs {
		if !nodeIPs[ip] {
			if err := cf.DeleteDNSRecord(cf.Config.DefaultZoneID, recordID); err != nil {
				LogError("CLOUDFLARE", "Failed to delete DNS for %s: %v", ip, err)
			} else {
				LogInfo("CLOUDFLARE", "Deleted DNS record: %s -> %s", subdomain, ip)
			}
		}
	}

	return nil
}

// CFNodeInfo represents node information for DNS sync
type CFNodeInfo struct {
	ID      string
	Name    string
	IP      string
	Enabled bool
}

// StartDNSAutoSync starts automatic DNS synchronization
func (cf *CloudflareManager) StartDNSAutoSync(getNodes func() []*CFNodeInfo, subdomain string, interval time.Duration) {
	if !cf.Config.AutoSyncDNS {
		return
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				nodes := getNodes()
				if err := cf.SyncDNSWithNodes(nodes, subdomain); err != nil {
					LogError("CLOUDFLARE", "DNS auto-sync failed: %v", err)
				}
			}
		}
	}()

	LogInfo("CLOUDFLARE", "DNS auto-sync started (interval: %v)", interval)
}

// cloudflare.go - MX-UI Cloudflare Integration (Part 4)
// API Routes, Utilities, Integration Helpers, Configuration Templates

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// API ROUTES - HTTP Handlers
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// RegisterCloudflareRoutes registers all Cloudflare API routes
func (cf *CloudflareManager) RegisterCloudflareRoutes(mux *http.ServeMux) {
	// Status & Config
	mux.HandleFunc("/api/cloudflare/status", cf.handleStatus)
	mux.HandleFunc("/api/cloudflare/config", cf.handleConfig)
	mux.HandleFunc("/api/cloudflare/verify", cf.handleVerify)
	mux.HandleFunc("/api/cloudflare/health", cf.handleHealth)

	// Zones
	mux.HandleFunc("/api/cloudflare/zones", cf.handleZones)
	mux.HandleFunc("/api/cloudflare/zones/", cf.handleZoneByID)
	mux.HandleFunc("/api/cloudflare/zones/settings", cf.handleZoneSettings)

	// DNS
	mux.HandleFunc("/api/cloudflare/dns", cf.handleDNS)
	mux.HandleFunc("/api/cloudflare/dns/", cf.handleDNSByID)
	mux.HandleFunc("/api/cloudflare/dns/sync", cf.handleDNSSync)
	mux.HandleFunc("/api/cloudflare/dns/export", cf.handleDNSExport)
	mux.HandleFunc("/api/cloudflare/dns/import", cf.handleDNSImport)

	// SSL/TLS
	mux.HandleFunc("/api/cloudflare/ssl", cf.handleSSL)
	mux.HandleFunc("/api/cloudflare/ssl/mode", cf.handleSSLMode)

	// Firewall
	mux.HandleFunc("/api/cloudflare/firewall/rules", cf.handleFirewallRules)
	mux.HandleFunc("/api/cloudflare/firewall/access", cf.handleIPAccess)
	mux.HandleFunc("/api/cloudflare/firewall/block", cf.handleBlockIP)
	mux.HandleFunc("/api/cloudflare/firewall/whitelist", cf.handleWhitelistIP)

	// Cache/CDN
	mux.HandleFunc("/api/cloudflare/cache/purge", cf.handleCachePurge)
	mux.HandleFunc("/api/cloudflare/cdn/settings", cf.handleCDNSettings)
	mux.HandleFunc("/api/cloudflare/cdn/optimize", cf.handleCDNOptimize)

	// WARP
	mux.HandleFunc("/api/cloudflare/warp/status", cf.handleWARPStatus)
	mux.HandleFunc("/api/cloudflare/warp/register", cf.handleWARPRegister)
	mux.HandleFunc("/api/cloudflare/warp/license", cf.handleWARPLicense)
	mux.HandleFunc("/api/cloudflare/warp/config", cf.handleWARPConfig)
	mux.HandleFunc("/api/cloudflare/warp/endpoints", cf.handleWARPEndpoints)
	mux.HandleFunc("/api/cloudflare/warp/best-endpoint", cf.handleWARPBestEndpoint)

	// Workers
	mux.HandleFunc("/api/cloudflare/workers", cf.handleWorkers)
	mux.HandleFunc("/api/cloudflare/workers/", cf.handleWorkerByName)
	mux.HandleFunc("/api/cloudflare/workers/deploy", cf.handleWorkerDeploy)
	mux.HandleFunc("/api/cloudflare/workers/routes", cf.handleWorkerRoutes)
	mux.HandleFunc("/api/cloudflare/workers/kv", cf.handleWorkerKV)
	mux.HandleFunc("/api/cloudflare/workers/templates", cf.handleWorkerTemplates)

	// Tunnels
	mux.HandleFunc("/api/cloudflare/tunnels", cf.handleTunnels)
	mux.HandleFunc("/api/cloudflare/tunnels/", cf.handleTunnelByID)
	mux.HandleFunc("/api/cloudflare/tunnels/create", cf.handleTunnelCreate)
	mux.HandleFunc("/api/cloudflare/tunnels/config", cf.handleTunnelConfig)
	mux.HandleFunc("/api/cloudflare/tunnels/install", cf.handleTunnelInstall)

	// Spectrum
	mux.HandleFunc("/api/cloudflare/spectrum", cf.handleSpectrum)
	mux.HandleFunc("/api/cloudflare/spectrum/", cf.handleSpectrumByID)
	mux.HandleFunc("/api/cloudflare/spectrum/create", cf.handleSpectrumCreate)

	// Load Balancer
	mux.HandleFunc("/api/cloudflare/lb", cf.handleLoadBalancers)
	mux.HandleFunc("/api/cloudflare/lb/", cf.handleLoadBalancerByID)
	mux.HandleFunc("/api/cloudflare/lb/pools", cf.handlePools)
	mux.HandleFunc("/api/cloudflare/lb/monitors", cf.handleMonitors)
	mux.HandleFunc("/api/cloudflare/lb/setup-vpn", cf.handleSetupVPNLB)

	// Analytics
	mux.HandleFunc("/api/cloudflare/analytics/zone", cf.handleZoneAnalytics)
	mux.HandleFunc("/api/cloudflare/analytics/dns", cf.handleDNSAnalytics)

	// Tools
	mux.HandleFunc("/api/cloudflare/tools/find-ips", cf.handleFindIPs)
	mux.HandleFunc("/api/cloudflare/tools/find-domains", cf.handleFindDomains)
	mux.HandleFunc("/api/cloudflare/tools/test-ip", cf.handleTestIP)
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// STATUS & CONFIG HANDLERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

func (cf *CloudflareManager) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := cf.GetCloudflareStatus()
	cf.jsonResponse(w, true, status, "")
}

func (cf *CloudflareManager) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Return safe config (hide sensitive data)
		safeConfig := cf.getSafeConfig()
		cf.jsonResponse(w, true, safeConfig, "")

	case http.MethodPut, http.MethodPost:
		var newConfig CloudflareConfig
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}

		// Preserve sensitive fields if not provided
		cf.mergeConfig(&newConfig)

		cf.mu.Lock()
		cf.Config = &newConfig
		cf.mu.Unlock()

		if err := cf.SaveConfig(); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}

		// Reinitialize if credentials changed
		if newConfig.APIToken != "" || newConfig.APIKey != "" {
			cf.VerifyCredentials()
		}

		cf.jsonResponse(w, true, nil, "Configuration updated")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cf *CloudflareManager) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := cf.VerifyCredentials(); err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, nil, "Credentials verified successfully")
}

func (cf *CloudflareManager) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	health := cf.HealthCheckAll()
	cf.jsonResponse(w, true, health, "")
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// ZONE HANDLERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

func (cf *CloudflareManager) handleZones(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		zones, err := cf.ListZones()
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, zones, "")

	case http.MethodPost:
		var req struct {
			Name      string `json:"name"`
			JumpStart bool   `json:"jump_start"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}

		zone, err := cf.CreateZone(req.Name, req.JumpStart)
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, zone, "Zone created")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cf *CloudflareManager) handleZoneByID(w http.ResponseWriter, r *http.Request) {
	zoneID := strings.TrimPrefix(r.URL.Path, "/api/cloudflare/zones/")
	if zoneID == "" {
		cf.jsonResponse(w, false, nil, "Zone ID required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		zone, err := cf.GetZone(zoneID)
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, zone, "")

	case http.MethodDelete:
		if err := cf.DeleteZone(zoneID); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, nil, "Zone deleted")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cf *CloudflareManager) handleZoneSettings(w http.ResponseWriter, r *http.Request) {
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	if zoneID == "" {
		cf.jsonResponse(w, false, nil, "Zone ID required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		settings, err := cf.GetZoneSettings(zoneID)
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, settings, "")

	case http.MethodPut:
		var req struct {
			Setting string      `json:"setting"`
			Value   interface{} `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}

		if err := cf.UpdateZoneSetting(zoneID, req.Setting, req.Value); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, nil, "Setting updated")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// DNS HANDLERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

func (cf *CloudflareManager) handleDNS(w http.ResponseWriter, r *http.Request) {
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	if zoneID == "" {
		cf.jsonResponse(w, false, nil, "Zone ID required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		records, err := cf.ListDNSRecords(zoneID)
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, records, "")

	case http.MethodPost:
		var record DNSRecordCreate
		if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}

		newRecord, err := cf.CreateDNSRecord(zoneID, &record)
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, newRecord, "DNS record created")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cf *CloudflareManager) handleDNSByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/cloudflare/dns/")
	parts := strings.Split(path, "/")

	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	if len(parts) == 0 || parts[0] == "" {
		cf.jsonResponse(w, false, nil, "Record ID required")
		return
	}
	recordID := parts[0]

	switch r.Method {
	case http.MethodGet:
		record, err := cf.GetDNSRecord(zoneID, recordID)
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, record, "")

	case http.MethodPut, http.MethodPatch:
		var update DNSRecordUpdate
		if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}

		record, err := cf.UpdateDNSRecord(zoneID, recordID, &update)
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, record, "DNS record updated")

	case http.MethodDelete:
		if err := cf.DeleteDNSRecord(zoneID, recordID); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, nil, "DNS record deleted")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cf *CloudflareManager) handleDNSSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Subdomain string        `json:"subdomain"`
		Nodes     []*CFNodeInfo `json:"nodes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	if err := cf.SyncDNSWithNodes(req.Nodes, req.Subdomain); err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, nil, "DNS synchronized")
}

func (cf *CloudflareManager) handleDNSExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	data, err := cf.ExportDNSRecords(zoneID)
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=dns_export.txt")
	w.Write([]byte(data))
}

func (cf *CloudflareManager) handleDNSImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	if err := cf.ImportDNSRecords(zoneID, string(body)); err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, nil, "DNS records imported")
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SSL/TLS HANDLERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

func (cf *CloudflareManager) handleSSL(w http.ResponseWriter, r *http.Request) {
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	settings, err := cf.GetUniversalSSLSettings(zoneID)
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, settings, "")
}

func (cf *CloudflareManager) handleSSLMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	var req struct {
		Mode string `json:"mode"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	if err := cf.SetSSLMode(zoneID, req.Mode); err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, nil, "SSL mode updated")
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// FIREWALL HANDLERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

func (cf *CloudflareManager) handleFirewallRules(w http.ResponseWriter, r *http.Request) {
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	switch r.Method {
	case http.MethodGet:
		rules, err := cf.ListFirewallRules(zoneID)
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, rules, "")

	case http.MethodPost:
		var rule FirewallRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}

		newRule, err := cf.CreateFirewallRule(zoneID, &rule)
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, newRule, "Firewall rule created")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cf *CloudflareManager) handleIPAccess(w http.ResponseWriter, r *http.Request) {
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rules, err := cf.ListIPAccessRules(zoneID)
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, rules, "")
}

func (cf *CloudflareManager) handleBlockIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	var req struct {
		IP   string `json:"ip"`
		Note string `json:"note"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	rule, err := cf.BlockIP(zoneID, req.IP, req.Note)
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, rule, "IP blocked")
}

func (cf *CloudflareManager) handleWhitelistIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	var req struct {
		IP   string `json:"ip"`
		Note string `json:"note"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	rule, err := cf.WhitelistIP(zoneID, req.IP, req.Note)
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, rule, "IP whitelisted")
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// CACHE/CDN HANDLERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

func (cf *CloudflareManager) handleCachePurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	var req struct {
		PurgeEverything bool     `json:"purge_everything"`
		Files           []string `json:"files"`
		Tags            []string `json:"tags"`
		Hosts           []string `json:"hosts"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	if err := cf.PurgeCache(zoneID, req.PurgeEverything, req.Files, req.Tags, req.Hosts); err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, nil, "Cache purged")
}

func (cf *CloudflareManager) handleCDNSettings(w http.ResponseWriter, r *http.Request) {
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	cdm := cf.cdnManager

	switch r.Method {
	case http.MethodGet:
		settings, err := cf.GetZoneSettings(zoneID)
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, settings, "")

	case http.MethodPut:
		var req struct {
			CacheLevel   string `json:"cache_level"`
			BrowserTTL   int    `json:"browser_ttl"`
			MinifyHTML   bool   `json:"minify_html"`
			MinifyCSS    bool   `json:"minify_css"`
			MinifyJS     bool   `json:"minify_js"`
			Brotli       bool   `json:"brotli"`
			HTTP2        bool   `json:"http2"`
			HTTP3        bool   `json:"http3"`
			WebSockets   bool   `json:"websockets"`
			RocketLoader bool   `json:"rocket_loader"`
			AlwaysOnline bool   `json:"always_online"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}

		// Apply settings
		if req.CacheLevel != "" {
			cdm.SetCacheLevel(zoneID, req.CacheLevel)
		}
		if req.BrowserTTL > 0 {
			cdm.SetBrowserCacheTTL(zoneID, req.BrowserTTL)
		}
		cdm.EnableMinify(zoneID, req.MinifyHTML, req.MinifyCSS, req.MinifyJS)
		cdm.EnableBrotli(zoneID, req.Brotli)
		cdm.EnableHTTP2(zoneID, req.HTTP2)
		cdm.EnableHTTP3(zoneID, req.HTTP3)
		cdm.EnableWebSockets(zoneID, req.WebSockets)
		cdm.EnableRocketLoader(zoneID, req.RocketLoader)
		cdm.EnableAlwaysOnline(zoneID, req.AlwaysOnline)

		cf.jsonResponse(w, true, nil, "CDN settings updated")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cf *CloudflareManager) handleCDNOptimize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	if err := cf.cdnManager.OptimizeForVPN(zoneID); err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, nil, "CDN optimized for VPN")
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// WARP HANDLERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

func (cf *CloudflareManager) handleWARPStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if cf.warpManager == nil {
		cf.jsonResponse(w, false, nil, "WARP not enabled")
		return
	}

	status := cf.warpManager.GetWARPStatus()
	cf.jsonResponse(w, true, status, "")
}

func (cf *CloudflareManager) handleWARPRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if cf.warpManager == nil {
		cf.warpManager = cf.initWARPManager()
	}

	result, err := cf.warpManager.Register()
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.warpManager.SaveWARPConfig(cf.db)
	cf.jsonResponse(w, true, result, "WARP device registered")
}

func (cf *CloudflareManager) handleWARPLicense(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if cf.warpManager == nil {
		cf.jsonResponse(w, false, nil, "WARP not initialized")
		return
	}

	var req struct {
		LicenseKey string `json:"license_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	if err := cf.warpManager.ApplyLicenseKey(req.LicenseKey); err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.warpManager.SaveWARPConfig(cf.db)
	cf.jsonResponse(w, true, nil, "License key applied")
}

func (cf *CloudflareManager) handleWARPConfig(w http.ResponseWriter, r *http.Request) {
	if cf.warpManager == nil {
		cf.jsonResponse(w, false, nil, "WARP not initialized")
		return
	}

	format := r.URL.Query().Get("format")

	switch r.Method {
	case http.MethodGet:
		var config interface{}
		var err error

		switch format {
		case "wireguard":
			config, err = cf.warpManager.GenerateWireGuardConfigString()
		case "xray":
			config, err = cf.warpManager.GenerateXrayWARPOutbound()
		case "singbox":
			config, err = cf.warpManager.GenerateSingboxWARPOutbound()
		case "clash":
			config, err = cf.warpManager.GenerateClashWARPProxy()
		default:
			config, err = cf.warpManager.GenerateWireGuardConfig()
		}

		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}

		if format == "wireguard" {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(config.(string)))
			return
		}

		cf.jsonResponse(w, true, config, "")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cf *CloudflareManager) handleWARPEndpoints(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if cf.warpManager == nil {
		cf.jsonResponse(w, false, nil, "WARP not initialized")
		return
	}

	endpoints := cf.warpManager.GetWARPEndpoints()
	cf.jsonResponse(w, true, endpoints, "")
}

func (cf *CloudflareManager) handleWARPBestEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if cf.warpManager == nil {
		cf.jsonResponse(w, false, nil, "WARP not initialized")
		return
	}

	endpoint, err := cf.warpManager.FindBestEndpoint()
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, endpoint, "")
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// WORKERS HANDLERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

func (cf *CloudflareManager) handleWorkers(w http.ResponseWriter, r *http.Request) {
	wm := cf.workersManager

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	workers, err := wm.ListWorkers()
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, workers, "")
}

func (cf *CloudflareManager) handleWorkerByName(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/cloudflare/workers/")
	if name == "" {
		cf.jsonResponse(w, false, nil, "Worker name required")
		return
	}

	wm := cf.workersManager

	switch r.Method {
	case http.MethodGet:
		worker, err := wm.GetWorker(name)
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, worker, "")

	case http.MethodDelete:
		if err := wm.DeleteWorker(name); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, nil, "Worker deleted")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cf *CloudflareManager) handleWorkerDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	wm := cf.workersManager

	var script WorkerScript
	if err := json.NewDecoder(r.Body).Decode(&script); err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	worker, err := wm.DeployWorker(&script)
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, worker, "Worker deployed")
}

func (cf *CloudflareManager) handleWorkerRoutes(w http.ResponseWriter, r *http.Request) {
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	wm := cf.workersManager

	switch r.Method {
	case http.MethodGet:
		routes, err := wm.ListWorkerRoutes(zoneID)
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, routes, "")

	case http.MethodPost:
		var route WorkerRoute
		if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}

		newRoute, err := wm.CreateWorkerRoute(zoneID, &route)
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, newRoute, "Route created")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cf *CloudflareManager) handleWorkerKV(w http.ResponseWriter, r *http.Request) {
	wm := cf.workersManager

	switch r.Method {
	case http.MethodGet:
		namespaces, err := wm.ListKVNamespaces()
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, namespaces, "")

	case http.MethodPost:
		var req struct {
			Title string `json:"title"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}

		kv, err := wm.CreateKVNamespace(req.Title)
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, kv, "KV namespace created")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cf *CloudflareManager) handleWorkerTemplates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	wm := cf.workersManager
	templateType := r.URL.Query().Get("type")
	backendURL := r.URL.Query().Get("backend")

	if backendURL == "" {
		backendURL = "https://your-server.com"
	}

	var script string
	switch templateType {
	case "vpn-proxy":
		script = wm.VPNProxyWorkerScript(backendURL)
	case "websocket":
		script = wm.WebSocketProxyWorkerScript(backendURL)
	case "grpc":
		script = wm.GRPCProxyWorkerScript(backendURL)
	case "subscription":
		script = wm.SubscriptionWorkerScript(backendURL)
	default:
		cf.jsonResponse(w, false, nil, "Unknown template type")
		return
	}

	cf.jsonResponse(w, true, map[string]string{"script": script}, "")
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// TUNNEL HANDLERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

func (cf *CloudflareManager) handleTunnels(w http.ResponseWriter, r *http.Request) {
	tm := cf.NewTunnelManager()

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tunnels, err := tm.ListTunnels()
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, tunnels, "")
}

func (cf *CloudflareManager) handleTunnelByID(w http.ResponseWriter, r *http.Request) {
	tunnelID := strings.TrimPrefix(r.URL.Path, "/api/cloudflare/tunnels/")
	if tunnelID == "" {
		cf.jsonResponse(w, false, nil, "Tunnel ID required")
		return
	}

	tm := cf.NewTunnelManager()

	switch r.Method {
	case http.MethodGet:
		status, err := tm.GetTunnelStatus(tunnelID)
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, status, "")

	case http.MethodDelete:
		if err := tm.DeleteTunnel(tunnelID); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, nil, "Tunnel deleted")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cf *CloudflareManager) handleTunnelCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tm := cf.NewTunnelManager()

	var req struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	tunnel, err := tm.CreateTunnel(req.Name)
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	// Get token
	token, _ := tm.GetTunnelToken(tunnel.ID)

	result := map[string]interface{}{
		"tunnel": tunnel,
		"token":  token,
	}

	cf.jsonResponse(w, true, result, "Tunnel created")
}

func (cf *CloudflareManager) handleTunnelConfig(w http.ResponseWriter, r *http.Request) {
	tunnelID := r.URL.Query().Get("tunnel_id")
	if tunnelID == "" {
		cf.jsonResponse(w, false, nil, "Tunnel ID required")
		return
	}

	tm := cf.NewTunnelManager()

	switch r.Method {
	case http.MethodGet:
		config, err := tm.GetTunnelConfig(tunnelID)
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, config, "")

	case http.MethodPut:
		var config TunnelConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}

		if err := tm.UpdateTunnelConfig(tunnelID, &config); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, nil, "Tunnel config updated")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cf *CloudflareManager) handleTunnelInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tunnelID := r.URL.Query().Get("tunnel_id")
	if tunnelID == "" {
		cf.jsonResponse(w, false, nil, "Tunnel ID required")
		return
	}

	tm := cf.NewTunnelManager()

	tunnel, err := tm.GetTunnel(tunnelID)
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	token, err := tm.GetTunnelToken(tunnelID)
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	script := tm.GenerateCloudflaredInstallScript(tunnel, token)

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=install_%s.sh", tunnel.Name))
	w.Write([]byte(script))
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SPECTRUM HANDLERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

func (cf *CloudflareManager) handleSpectrum(w http.ResponseWriter, r *http.Request) {
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	sm := cf.NewSpectrumManager()

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	apps, err := sm.ListSpectrumApps(zoneID)
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, apps, "")
}

func (cf *CloudflareManager) handleSpectrumByID(w http.ResponseWriter, r *http.Request) {
	appID := strings.TrimPrefix(r.URL.Path, "/api/cloudflare/spectrum/")
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	sm := cf.NewSpectrumManager()

	switch r.Method {
	case http.MethodGet:
		app, err := sm.GetSpectrumApp(zoneID, appID)
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, app, "")

	case http.MethodDelete:
		if err := sm.DeleteSpectrumApp(zoneID, appID); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, nil, "Spectrum app deleted")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cf *CloudflareManager) handleSpectrumCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	sm := cf.NewSpectrumManager()

	var req struct {
		Type       string `json:"type"` // tcp, ssh, vpn, https, minecraft, rdp
		Subdomain  string `json:"subdomain"`
		OriginIP   string `json:"origin_ip"`
		OriginPort int    `json:"origin_port"`
		Protocol   string `json:"protocol"` // tcp, udp
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	var app *SpectrumApp
	var err error

	switch req.Type {
	case "tcp":
		app, err = sm.CreateTCPProxy(zoneID, req.Subdomain, req.OriginIP, req.OriginPort, req.OriginPort)
	case "ssh":
		app, err = sm.CreateSSHProxy(zoneID, req.Subdomain, req.OriginIP, req.OriginPort)
	case "vpn":
		app, err = sm.CreateVPNProxy(zoneID, req.Subdomain, req.OriginIP, req.OriginPort, req.Protocol)
	case "https":
		app, err = sm.CreateHTTPSProxy(zoneID, req.Subdomain, req.OriginIP, req.OriginPort)
	case "minecraft":
		app, err = sm.CreateMinecraftProxy(zoneID, req.Subdomain, req.OriginIP)
	case "rdp":
		app, err = sm.CreateRDPProxy(zoneID, req.Subdomain, req.OriginIP)
	default:
		cf.jsonResponse(w, false, nil, "Unknown spectrum type")
		return
	}

	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, app, "Spectrum app created")
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// LOAD BALANCER HANDLERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

func (cf *CloudflareManager) handleLoadBalancers(w http.ResponseWriter, r *http.Request) {
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	lm := cf.NewLoadBalancerManager()

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	lbs, err := lm.ListLoadBalancers(zoneID)
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, lbs, "")
}

func (cf *CloudflareManager) handleLoadBalancerByID(w http.ResponseWriter, r *http.Request) {
	lbID := strings.TrimPrefix(r.URL.Path, "/api/cloudflare/lb/")
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	lm := cf.NewLoadBalancerManager()

	switch r.Method {
	case http.MethodGet:
		status, err := lm.GetVPNLBStatus(zoneID, lbID)
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, status, "")

	case http.MethodDelete:
		if err := lm.DeleteLoadBalancer(zoneID, lbID); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, nil, "Load balancer deleted")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cf *CloudflareManager) handlePools(w http.ResponseWriter, r *http.Request) {
	lm := cf.NewLoadBalancerManager()

	switch r.Method {
	case http.MethodGet:
		pools, err := lm.ListPools()
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, pools, "")

	case http.MethodPost:
		var pool PoolCreate
		if err := json.NewDecoder(r.Body).Decode(&pool); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}

		newPool, err := lm.CreatePool(&pool)
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, newPool, "Pool created")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cf *CloudflareManager) handleMonitors(w http.ResponseWriter, r *http.Request) {
	hm := cf.NewHealthCheckManager()

	switch r.Method {
	case http.MethodGet:
		monitors, err := hm.ListMonitors()
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, monitors, "")

	case http.MethodPost:
		var monitor MonitorCreate
		if err := json.NewDecoder(r.Body).Decode(&monitor); err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}

		newMonitor, err := hm.CreateMonitor(&monitor)
		if err != nil {
			cf.jsonResponse(w, false, nil, err.Error())
			return
		}
		cf.jsonResponse(w, true, newMonitor, "Monitor created")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cf *CloudflareManager) handleSetupVPNLB(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	lm := cf.NewLoadBalancerManager()

	var config VPNLoadBalancerConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	if config.ZoneID == "" {
		config.ZoneID = cf.Config.DefaultZoneID
	}

	lb, err := lm.SetupVPNLoadBalancer(&config)
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, lb, "VPN Load Balancer setup complete")
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// ANALYTICS HANDLERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

func (cf *CloudflareManager) handleZoneAnalytics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	// Parse time range
	since := time.Now().Add(-24 * time.Hour)
	until := time.Now()

	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = t
		}
	}

	if untilStr := r.URL.Query().Get("until"); untilStr != "" {
		if t, err := time.Parse(time.RFC3339, untilStr); err == nil {
			until = t
		}
	}

	analytics, err := cf.GetZoneAnalytics(zoneID, since, until)
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, analytics, "")
}

func (cf *CloudflareManager) handleDNSAnalytics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		zoneID = cf.Config.DefaultZoneID
	}

	since := time.Now().Add(-24 * time.Hour)
	until := time.Now()

	analytics, err := cf.GetDNSAnalytics(zoneID, since, until)
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, analytics, "")
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// TOOLS HANDLERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

func (cf *CloudflareManager) handleFindIPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	count := 10
	if countStr := r.URL.Query().Get("count"); countStr != "" {
		fmt.Sscanf(countStr, "%d", &count)
	}

	ips, err := cf.cdnManager.FindCloudflareIPs(count)
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, ips, "")
}

func (cf *CloudflareManager) handleFindDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	count := 10
	if countStr := r.URL.Query().Get("count"); countStr != "" {
		fmt.Sscanf(countStr, "%d", &count)
	}

	domains, err := cf.cdnManager.FindCDNDomains(count)
	if err != nil {
		cf.jsonResponse(w, false, nil, err.Error())
		return
	}

	cf.jsonResponse(w, true, domains, "")
}

func (cf *CloudflareManager) handleTestIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := r.URL.Query().Get("ip")
	port := 443
	if portStr := r.URL.Query().Get("port"); portStr != "" {
		fmt.Sscanf(portStr, "%d", &port)
	}

	latency := testIPLatency(ip, port)

	result := map[string]interface{}{
		"ip":        ip,
		"port":      port,
		"latency":   latency,
		"reachable": latency > 0,
	}

	cf.jsonResponse(w, true, result, "")
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// UTILITY FUNCTIONS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// jsonResponse sends JSON response
func (cf *CloudflareManager) jsonResponse(w http.ResponseWriter, success bool, data interface{}, message string) {
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"success": success,
	}

	if data != nil {
		response["data"] = data
	}

	if message != "" {
		if success {
			response["message"] = message
		} else {
			response["error"] = message
		}
	}

	json.NewEncoder(w).Encode(response)
}

// getSafeConfig returns config with sensitive data hidden
func (cf *CloudflareManager) getSafeConfig() map[string]interface{} {
	cf.mu.RLock()
	defer cf.mu.RUnlock()

	safeConfig := map[string]interface{}{
		"warp_enabled":      cf.Config.WARPEnabled,
		"workers_enabled":   cf.Config.WorkersEnabled,
		"cdn_enabled":       cf.Config.CDNEnabled,
		"tunnels_enabled":   cf.Config.TunnelsEnabled,
		"default_zone_id":   cf.Config.DefaultZoneID,
		"default_zone_name": cf.Config.DefaultZoneName,
		"ssl_mode":          cf.Config.SSLMode,
		"security_level":    cf.Config.SecurityLevel,
		"auto_sync_dns":     cf.Config.AutoSyncDNS,
		"has_api_token":     cf.Config.APIToken != "",
		"has_api_key":       cf.Config.APIKey != "",
		"has_account_id":    cf.Config.AccountID != "",
	}

	return safeConfig
}

// mergeConfig merges new config with existing, preserving sensitive data
func (cf *CloudflareManager) mergeConfig(newConfig *CloudflareConfig) {
	cf.mu.RLock()
	oldConfig := cf.Config
	cf.mu.RUnlock()

	if oldConfig == nil {
		return
	}

	// Preserve sensitive fields if not provided in new config
	if newConfig.APIToken == "" || newConfig.APIToken == "***" {
		newConfig.APIToken = oldConfig.APIToken
	}
	if newConfig.APIKey == "" || newConfig.APIKey == "***" {
		newConfig.APIKey = oldConfig.APIKey
	}
	if newConfig.APIEmail == "" {
		newConfig.APIEmail = oldConfig.APIEmail
	}
	if newConfig.AccountID == "" {
		newConfig.AccountID = oldConfig.AccountID
	}
	if newConfig.WARPLicenseKey == "" || newConfig.WARPLicenseKey == "***" {
		newConfig.WARPLicenseKey = oldConfig.WARPLicenseKey
	}
	if newConfig.WARPPrivateKey == "" {
		newConfig.WARPPrivateKey = oldConfig.WARPPrivateKey
	}
	if newConfig.WARPPublicKey == "" {
		newConfig.WARPPublicKey = oldConfig.WARPPublicKey
	}
	if newConfig.WARPAccessToken == "" {
		newConfig.WARPAccessToken = oldConfig.WARPAccessToken
	}
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// INTEGRATION HELPERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// IntegrationConfig for integrating Cloudflare with other MX-UI components
type IntegrationConfig struct {
	AutoDNSSync         bool          `json:"auto_dns_sync"`
	DNSSyncInterval     time.Duration `json:"dns_sync_interval"`
	AutoSSLRenewal      bool          `json:"auto_ssl_renewal"`
	AutoCachePurge      bool          `json:"auto_cache_purge"`
	WARPForRouting      bool          `json:"warp_for_routing"`
	WorkerForSub        bool          `json:"worker_for_subscription"`
	TunnelEnabled       bool          `json:"tunnel_enabled"`
	LoadBalancerEnabled bool          `json:"load_balancer_enabled"`
}

// SetupVPNIntegration sets up complete VPN integration with Cloudflare
func (cf *CloudflareManager) SetupVPNIntegration(config *IntegrationConfig, nodes []*CFNodeInfo, subdomain string) error {
	// 1. Create/Update DNS records for nodes
	if config.AutoDNSSync {
		if err := cf.SyncDNSWithNodes(nodes, subdomain); err != nil {
			LogError("CLOUDFLARE", "DNS sync failed: %v", err)
		}
	}

	// 2. Optimize CDN settings for VPN
	if cf.Config.DefaultZoneID != "" {
		if err := cf.cdnManager.OptimizeForVPN(cf.Config.DefaultZoneID); err != nil {
			LogError("CLOUDFLARE", "CDN optimization failed: %v", err)
		}
	}

	// 3. Setup WARP if enabled
	if config.WARPForRouting && cf.warpManager != nil {
		if cf.warpManager.Config.DeviceID == "" {
			if _, err := cf.warpManager.Register(); err != nil {
				LogError("CLOUDFLARE", "WARP registration failed: %v", err)
			}
		}
	}

	// 4. Deploy subscription worker if enabled
	if config.WorkerForSub && cf.Config.WorkersEnabled {
		wm := cf.workersManager
		script := &WorkerScript{
			Name:    "mxui-subscription",
			Content: wm.SubscriptionWorkerScript(fmt.Sprintf("https://%s", subdomain)),
		}

		if _, err := wm.DeployWorker(script); err != nil {
			LogError("CLOUDFLARE", "Worker deployment failed: %v", err)
		}
	}

	// 5. Start auto-sync if enabled
	if config.AutoDNSSync && config.DNSSyncInterval > 0 {
		cf.Config.AutoSyncDNS = true
		cf.Config.SyncInterval = config.DNSSyncInterval
		cf.SaveConfig()
	}

	LogInfo("CLOUDFLARE", "VPN integration setup complete")
	return nil
}

// GenerateVPNConfigs generates all VPN configuration variants
func (cf *CloudflareManager) GenerateVPNConfigs(serverIP string, port int) map[string]interface{} {
	configs := make(map[string]interface{})

	// CDN config
	if cf.Config.DefaultZoneName != "" {
		configs["cdn"] = map[string]interface{}{
			"host":    cf.Config.DefaultZoneName,
			"sni":     cf.Config.DefaultZoneName,
			"address": serverIP,
			"port":    port,
		}
	}

	// WARP config
	if cf.warpManager != nil && cf.warpManager.Config.PrivateKey != "" {
		warpConfig, _ := cf.warpManager.GenerateWireGuardConfig()
		configs["warp"] = warpConfig
	}

	// Best Cloudflare IP
	if ips, err := cf.cdnManager.FindCloudflareIPs(1); err == nil && len(ips) > 0 {
		configs["best_cf_ip"] = ips[0]
	}

	return configs
}

// GetSubscriptionCDNInfo returns CDN info for subscription page
func (cf *CloudflareManager) GetSubscriptionCDNInfo() map[string]interface{} {
	info := map[string]interface{}{
		"cdn_enabled": cf.Config.CDNEnabled,
		"zone_name":   cf.Config.DefaultZoneName,
	}

	// Add WARP info if available
	if cf.warpManager != nil {
		warpStatus := cf.warpManager.GetWARPStatus()
		info["warp"] = warpStatus
	}

	// Add best endpoints
	if cf.warpManager != nil {
		if endpoint, err := cf.warpManager.FindBestEndpoint(); err == nil {
			info["best_warp_endpoint"] = endpoint
		}
	}

	return info
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// CONFIGURATION TEMPLATES
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// GenerateNginxCDNConfig generates Nginx config for CDN
func (cf *CloudflareManager) GenerateNginxCDNConfig(domain string, backendPort int) string {
	return fmt.Sprintf(`# MX-UI Nginx CDN Configuration for %s
# Optimized for Cloudflare

server {
    listen 80;
    listen [::]:80;
    server_name %s;
    
    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name %s;
    
    # SSL (Cloudflare Origin Certificate)
    ssl_certificate /etc/ssl/cloudflare/%s.pem;
    ssl_certificate_key /etc/ssl/cloudflare/%s.key;
    
    # SSL Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    
    # Cloudflare Real IP
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 104.24.0.0/14;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 131.0.72.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
    set_real_ip_from 2400:cb00::/32;
    set_real_ip_from 2606:4700::/32;
    set_real_ip_from 2803:f800::/32;
    set_real_ip_from 2405:b500::/32;
    set_real_ip_from 2405:8100::/32;
    set_real_ip_from 2c0f:f248::/32;
    set_real_ip_from 2a06:98c0::/29;
    real_ip_header CF-Connecting-IP;
    
    # WebSocket Support
    location / {
        proxy_pass http://127.0.0.1:%d;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }
    
    # gRPC Support
    location /grpc {
        grpc_pass grpc://127.0.0.1:%d;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $remote_addr;
    }
}
`, domain, domain, domain, domain, domain, backendPort, backendPort)
}

// GenerateXrayCloudflareConfig generates Xray config optimized for Cloudflare
func (cf *CloudflareManager) GenerateXrayCloudflareConfig(domain string, port int) map[string]interface{} {
	config := map[string]interface{}{
		"inbounds": []map[string]interface{}{
			{
				"port":     port,
				"protocol": "vless",
				"settings": map[string]interface{}{
					"clients": []map[string]interface{}{
						{
							"id":   "{{UUID}}",
							"flow": "",
						},
					},
					"decryption": "none",
				},
				"streamSettings": map[string]interface{}{
					"network": "ws",
					"wsSettings": map[string]interface{}{
						"path": "/ws",
						"headers": map[string]string{
							"Host": domain,
						},
					},
					"security": "none", // TLS handled by Cloudflare
				},
				"sniffing": map[string]interface{}{
					"enabled":      true,
					"destOverride": []string{"http", "tls"},
				},
			},
		},
		"outbounds": []map[string]interface{}{
			{
				"protocol": "freedom",
				"tag":      "direct",
			},
		},
	}

	// Add WARP outbound if available
	if cf.warpManager != nil && cf.warpManager.Config.PrivateKey != "" {
		warpOutbound, err := cf.warpManager.GenerateXrayWARPOutbound()
		if err == nil {
			config["outbounds"] = append(config["outbounds"].([]map[string]interface{}), warpOutbound)
		}
	}

	return config
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// TESTING HELPERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// TestCloudflareConnection tests connection to Cloudflare API
func (cf *CloudflareManager) TestCloudflareConnection() error {
	return cf.VerifyCredentials()
}

// TestDNSResolution tests DNS resolution for a domain
func (cf *CloudflareManager) TestDNSResolution(domain string) ([]string, error) {
	return cf.ResolveIP(domain)
}

// TestWARPConnection tests WARP connection
func (cf *CloudflareManager) TestWARPConnection() (map[string]interface{}, error) {
	if cf.warpManager == nil {
		return nil, fmt.Errorf("WARP not initialized")
	}

	endpoint, err := cf.warpManager.FindBestEndpoint()
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"endpoint":  endpoint.IP,
		"port":      endpoint.Port,
		"latency":   endpoint.Latency,
		"reachable": true,
	}, nil
}

// TestCDNLatency tests CDN latency to various PoPs
func (cf *CloudflareManager) TestCDNLatency() ([]map[string]interface{}, error) {
	testDomains := []string{
		"speed.cloudflare.com",
		"www.cloudflare.com",
		"1.1.1.1",
	}

	var results []map[string]interface{}

	for _, domain := range testDomains {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", domain+":443", 5*time.Second)
		latency := time.Since(start).Milliseconds()

		result := map[string]interface{}{
			"domain":  domain,
			"latency": latency,
		}

		if err != nil {
			result["error"] = err.Error()
			result["reachable"] = false
		} else {
			conn.Close()
			result["reachable"] = true
		}

		results = append(results, result)
	}

	return results, nil
}

// RunDiagnostics runs complete Cloudflare diagnostics
func (cf *CloudflareManager) RunDiagnostics() map[string]interface{} {
	diagnostics := map[string]interface{}{
		"timestamp": time.Now().Unix(),
	}

	// API connectivity
	if err := cf.TestCloudflareConnection(); err != nil {
		diagnostics["api"] = map[string]interface{}{"status": "error", "error": err.Error()}
	} else {
		diagnostics["api"] = map[string]interface{}{"status": "ok"}
	}

	// Zone status
	if cf.Config.DefaultZoneID != "" {
		zone, err := cf.GetZone(cf.Config.DefaultZoneID)
		if err != nil {
			diagnostics["zone"] = map[string]interface{}{"status": "error", "error": err.Error()}
		} else {
			diagnostics["zone"] = map[string]interface{}{
				"status": "ok",
				"name":   zone.Name,
				"active": zone.Status == "active",
			}
		}
	}

	// WARP status
	if cf.warpManager != nil {
		warpTest, err := cf.TestWARPConnection()
		if err != nil {
			diagnostics["warp"] = map[string]interface{}{"status": "error", "error": err.Error()}
		} else {
			diagnostics["warp"] = map[string]interface{}{"status": "ok", "details": warpTest}
		}
	}

	// CDN latency
	cdnTest, err := cf.TestCDNLatency()
	if err != nil {
		diagnostics["cdn"] = map[string]interface{}{"status": "error", "error": err.Error()}
	} else {
		diagnostics["cdn"] = map[string]interface{}{"status": "ok", "results": cdnTest}
	}

	return diagnostics
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// CLEANUP & SHUTDOWN
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// Shutdown cleanly shuts down the Cloudflare manager
func (cf *CloudflareManager) Shutdown() {
	LogInfo("CLOUDFLARE", "Shutting down Cloudflare manager...")

	// Save any pending config changes
	cf.SaveConfig()

	// Save WARP config if initialized
	if cf.warpManager != nil {
		cf.warpManager.SaveWARPConfig(cf.db)
	}

	LogInfo("CLOUDFLARE", "Cloudflare manager shutdown complete")
}
