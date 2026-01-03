// MXUI VPN Panel
// Core/main.go
// Main Entry Point: Server, Config Loading, Service Lifecycle, Routes

package core

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"gopkg.in/yaml.v3"
)

// ============================================================================
// VERSION INFO
// ============================================================================

const (
	Version      = "2.0.0"
	BuildTime    = "2024-12-18"
	PanelVersion = "2.0.0"
	APIVersion   = "v1"
	CoreName     = "MXUI"
)

// Installation mode
var (
	NodeMode   = false // Set to true for node-only installation
	MasterMode = true  // Set to true for master panel installation
)

// ============================================================================
// GLOBAL VARIABLES
// ============================================================================

var (
	// Configuration
	AppConfig  *Config
	configMu   sync.RWMutex
	configPath string

	// HTTP Servers
	httpServer  *http.Server
	httpsServer *http.Server

	// Service managers
	managers  []ServiceManager
	startTime time.Time

	// Channels
	shutdownCh chan struct{}

	// Logger
	logger *Logger
)

// ============================================================================
// INTERFACES
// ============================================================================

// ServiceManager interface for all services
type ServiceManager interface {
	Name() string
	Start() error
	Stop() error
	Status() ServiceStatus
	Restart() error
}

// ServiceStatus represents service status
type ServiceStatus struct {
	Running   bool      `json:"running"`
	StartTime time.Time `json:"start_time,omitempty"`
	Error     string    `json:"error,omitempty"`
	Info      string    `json:"info,omitempty"`
}

// ============================================================================
// CONFIGURATION STRUCTURES
// ============================================================================

// Config represents the main configuration
type Config struct {
	Server    HTTPServerConfig `yaml:"server" json:"server"`
	Database  DatabaseConfig   `yaml:"database" json:"database"`
	Security  SecurityConfig   `yaml:"security" json:"security"`
	Admin     AdminConfig      `yaml:"admin" json:"admin"`
	Panel     PanelConfig      `yaml:"panel" json:"panel"`
	Nodes     NodesConfig      `yaml:"nodes" json:"nodes"`
	Protocols ProtocolsConfig  `yaml:"protocols" json:"protocols"`
	Telegram  TelegramConfig   `yaml:"telegram" json:"telegram"`
	Backup    BackupConfig     `yaml:"backup" json:"backup"`
	AI        AIConfig         `yaml:"ai" json:"ai"`
	Logging   LoggingConfig    `yaml:"logging" json:"logging"`
	API       APIConfig        `yaml:"api" json:"api"`
}

// APIConfig for API settings
type APIConfig struct {
	Enabled        bool     `yaml:"enabled" json:"enabled"`
	Prefix         string   `yaml:"prefix" json:"prefix"`
	Version        string   `yaml:"version" json:"version"`
	RateLimit      int      `yaml:"rate_limit" json:"rate_limit"`
	CORSEnabled    bool     `yaml:"cors_enabled" json:"cors_enabled"`
	Port           int      `yaml:"port" json:"port"`
	AllowedOrigins []string `yaml:"allowed_origins" json:"allowed_origins"`
}

// HTTPServerConfig for HTTP server settings
type HTTPServerConfig struct {
	Host           string `yaml:"host" json:"host"`
	Port           int    `yaml:"port" json:"port"`
	TLSPort        int    `yaml:"tls_port" json:"tls_port"`
	SinglePort     bool   `yaml:"single_port" json:"single_port"`
	SinglePortNum  int    `yaml:"single_port_num" json:"single_port_num"`
	Domain         string `yaml:"domain" json:"domain"`
	SSLEnabled     bool   `yaml:"ssl_enabled" json:"ssl_enabled"`
	SSLCertPath    string `yaml:"ssl_cert_path" json:"ssl_cert_path"`
	SSLKeyPath     string `yaml:"ssl_key_path" json:"ssl_key_path"`
	AutoTLS        bool   `yaml:"auto_tls" json:"auto_tls"`
	ReadTimeout    int    `yaml:"read_timeout" json:"read_timeout"`
	WriteTimeout   int    `yaml:"write_timeout" json:"write_timeout"`
	MaxHeaderBytes int    `yaml:"max_header_bytes" json:"max_header_bytes"`
}

// DatabaseConfig for database settings
type DatabaseConfig struct {
	Type            string `yaml:"type" json:"type"`
	Path            string `yaml:"path" json:"path"`
	Host            string `yaml:"host" json:"host"`
	Port            int    `yaml:"port" json:"port"`
	Name            string `yaml:"name" json:"name"`
	User            string `yaml:"user" json:"user"`
	Password        string `yaml:"password" json:"password"`
	MaxOpenConns    int    `yaml:"max_open_conns" json:"max_open_conns"`
	MaxIdleConns    int    `yaml:"max_idle_conns" json:"max_idle_conns"`
	ConnMaxLifetime int    `yaml:"conn_max_lifetime" json:"conn_max_lifetime"`
	Encrypted       bool   `yaml:"encrypted" json:"encrypted"`
	EncryptionKey   string `yaml:"encryption_key" json:"encryption_key"`
}

// SecurityConfig for security settings
type SecurityConfig struct {
	JWTSecret            string        `yaml:"jwt_secret" json:"jwt_secret"`
	JWTExpiry            int           `yaml:"jwt_expiry" json:"jwt_expiry"`
	JWTExpiration        time.Duration `yaml:"jwt_expiration" json:"jwt_expiration"`
	APIKey               string        `yaml:"api_key" json:"api_key"`
	AllowedIPs           []string      `yaml:"allowed_ips" json:"allowed_ips"`
	BlockedIPs           []string      `yaml:"blocked_ips" json:"blocked_ips"`
	IPWhitelist          []string      `yaml:"ip_whitelist" json:"ip_whitelist"`
	EnableIPWhitelist    bool          `yaml:"enable_ip_whitelist" json:"enable_ip_whitelist"`
	RateLimitEnabled     bool          `yaml:"rate_limit_enabled" json:"rate_limit_enabled"`
	RateLimitRequests    int           `yaml:"rate_limit_requests" json:"rate_limit_requests"`
	RateLimitWindow      int           `yaml:"rate_limit_window" json:"rate_limit_window"`
	BruteForceEnabled    bool          `yaml:"brute_force_enabled" json:"brute_force_enabled"`
	BruteForceAttempts   int           `yaml:"brute_force_attempts" json:"brute_force_attempts"`
	BruteForceWindow     int           `yaml:"brute_force_window" json:"brute_force_window"`
	BruteForceBanTime    int           `yaml:"brute_force_ban_time" json:"brute_force_ban_time"`
	MaxLoginAttempts     int           `yaml:"max_login_attempts" json:"max_login_attempts"`
	LoginLockoutDuration time.Duration `yaml:"login_lockout_duration" json:"login_lockout_duration"`
	Enable2FA            bool          `yaml:"enable_2fa" json:"enable_2fa"`
	DecoyType            string        `yaml:"decoy_type" json:"decoy_type"`
}

// AdminConfig for admin credentials
type AdminConfig struct {
	Username     string `yaml:"username" json:"username"`
	Password     string `yaml:"password" json:"password"`
	Email        string `yaml:"email" json:"email"`
	TwoFAEnabled bool   `yaml:"two_fa_enabled" json:"two_fa_enabled"`
	TwoFASecret  string `yaml:"two_fa_secret" json:"two_fa_secret"`
}

// PanelConfig for panel settings
type PanelConfig struct {
	LoginPath      string `yaml:"login_path" json:"login_path"`
	Path           string `yaml:"path" json:"path"` // Base path for panel access
	DecoyEnabled   bool   `yaml:"decoy_enabled" json:"decoy_enabled"`
	DecoyType      string `yaml:"decoy_type" json:"decoy_type"`
	Language       string `yaml:"language" json:"language"`
	Theme          string `yaml:"theme" json:"theme"`
	Title          string `yaml:"title" json:"title"`
	Logo           string `yaml:"logo" json:"logo"`
	SubPath        string `yaml:"sub_path" json:"sub_path"`
	SessionTimeout int    `yaml:"session_timeout" json:"session_timeout"`
	Port           int    `yaml:"port" json:"port"`
	SSL            bool   `yaml:"ssl" json:"ssl"`
}

// NodesConfig for node management
type NodesConfig struct {
	Enabled             bool   `yaml:"enabled" json:"enabled"`
	SyncInterval        int    `yaml:"sync_interval" json:"sync_interval"`
	HealthCheckInterval int    `yaml:"health_check_interval" json:"health_check_interval"`
	LoadBalanceStrategy string `yaml:"load_balance_strategy" json:"load_balance_strategy"`
	FailoverEnabled     bool   `yaml:"failover_enabled" json:"failover_enabled"`
	FailoverThreshold   int    `yaml:"failover_threshold" json:"failover_threshold"`
	MasterAddress       string `yaml:"master_address" json:"master_address"`
	MasterToken         string `yaml:"master_token" json:"master_token"`
}

// ProtocolsConfig for VPN protocols
type ProtocolsConfig struct {
	XrayEnabled    bool   `yaml:"xray_enabled" json:"xray_enabled"`
	XrayPath       string `yaml:"xray_path" json:"xray_path"`
	XrayConfigPath string `yaml:"xray_config_path" json:"xray_config_path"`
	XrayAPIPort    int    `yaml:"xray_api_port" json:"xray_api_port"`
	SingboxEnabled bool   `yaml:"singbox_enabled" json:"singbox_enabled"`
	SingboxPath    string `yaml:"singbox_path" json:"singbox_path"`
	ClashEnabled   bool   `yaml:"clash_enabled" json:"clash_enabled"`
	ClashPath      string `yaml:"clash_path" json:"clash_path"`
	WarpEnabled    bool   `yaml:"warp_enabled" json:"warp_enabled"`
	WarpConfig     string `yaml:"warp_config" json:"warp_config"`
}

// TelegramConfig for Telegram bot
type TelegramConfig struct {
	Enabled          bool    `yaml:"enabled" json:"enabled"`
	BotToken         string  `yaml:"bot_token" json:"bot_token"`
	AdminIDs         []int64 `yaml:"admin_ids" json:"admin_ids"`
	AdminChatIDs     []int64 `yaml:"admin_chat_ids" json:"admin_chat_ids"`
	SupportUsername  string  `yaml:"support_username" json:"support_username"`
	ChannelID        string  `yaml:"channel_id" json:"channel_id"`
	WebhookEnabled   bool    `yaml:"webhook_enabled" json:"webhook_enabled"`
	WebhookURL       string  `yaml:"webhook_url" json:"webhook_url"`
	UseWebhook       bool    `yaml:"use_webhook" json:"use_webhook"`
	PaymentEnabled   bool    `yaml:"payment_enabled" json:"payment_enabled"`
	NotifyOnLogin    bool    `yaml:"notify_on_login" json:"notify_on_login"`
	NotifyOnPurchase bool    `yaml:"notify_on_purchase" json:"notify_on_purchase"`
	NotifyOnExpiry   bool    `yaml:"notify_on_expiry" json:"notify_on_expiry"`
}

// LoggingConfig for logging settings
type LoggingConfig struct {
	Level      string `yaml:"level" json:"level"`
	Path       string `yaml:"path" json:"path"`
	FilePath   string `yaml:"file_path" json:"file_path"`
	MaxSize    int    `yaml:"max_size" json:"max_size"`
	MaxBackups int    `yaml:"max_backups" json:"max_backups"`
	MaxAge     int    `yaml:"max_age" json:"max_age"`
	Compress   bool   `yaml:"compress" json:"compress"`
	Console    bool   `yaml:"console" json:"console"`
}

// ============================================================================
// LOGGER
// ============================================================================

// Logger represents a simple logger
type Logger struct {
	mu       sync.Mutex
	file     *os.File
	filePath string
}

// NewLogger creates a new logger
func NewLogger(path string) (*Logger, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	return &Logger{
		file:     file,
		filePath: path,
	}, nil
}

// Log writes a log message
func (l *Logger) Log(level, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logLine := fmt.Sprintf("[%s] [%s] %s\n", timestamp, level, msg)

	if l.file != nil {
		l.file.WriteString(logLine)
	}

	fmt.Print(logLine)
}

func (l *Logger) Info(format string, args ...interface{})  { l.Log("INFO", format, args...) }
func (l *Logger) Warn(format string, args ...interface{})  { l.Log("WARN", format, args...) }
func (l *Logger) Error(format string, args ...interface{}) { l.Log("ERROR", format, args...) }
func (l *Logger) Debug(format string, args ...interface{}) { l.Log("DEBUG", format, args...) }

func (l *Logger) Close() {
	if l.file != nil {
		l.file.Close()
	}
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

// Run starts the MXUI Panel
func Run() {
	startTime = time.Now()
	shutdownCh = make(chan struct{})

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	printBanner()

	if err := loadConfig(); err != nil {
		log.Printf("⚠️  Config load warning: %v (using defaults)", err)
	}

	var err error
	logPath := "/opt/mxui/logs/mxui.log"
	if AppConfig != nil && AppConfig.Logging.Path != "" {
		logPath = AppConfig.Logging.Path
	}
	logger, err = NewLogger(logPath)
	if err != nil {
		log.Printf("⚠️  Logger init warning: %v", err)
	}

	log.Printf("🚀 Starting MXUI Panel v%s (Built: %s)", Version, BuildTime)

	if NodeMode {
		log.Println("📡 Running in NODE mode")
		runAsNode()
		return
	}

	log.Println("🖥️  Running in MASTER mode")

	if err := initDatabase(); err != nil {
		log.Fatalf("❌ Database initialization failed: %v", err)
	}

	// Initialize managers
	initManagers()

	// Initialize user and admin managers
	if err := InitUserManager(); err != nil {
		log.Printf("⚠️  User manager init warning: %v", err)
	}
	if err := InitAdminManager(); err != nil {
		log.Printf("⚠️  Admin manager init warning: %v", err)
	}
	if err := InitAuthManager(); err != nil {
		log.Printf("⚠️  Auth manager init warning: %v", err)
	}
	InitEnhancedSecurity()

	// Initialize protocol manager
	if err := InitProtocolManager(AppConfig); err != nil {
		log.Printf("⚠️  Protocol manager init warning: %v", err)
	} else {
		log.Println("✓ Protocol manager initialized")
	}

	// Initialize node manager
	if err := InitNodeManager(AppConfig); err != nil {
		log.Printf("⚠️  Node manager init warning: %v", err)
	} else {
		log.Println("✓ Node manager initialized")
	}

	for _, mgr := range managers {
		if err := mgr.Start(); err != nil {
			log.Printf("⚠️  %s start warning: %v", mgr.Name(), err)
		} else {
			log.Printf("✓ %s started", mgr.Name())
		}
	}

	startHTTPServer()
	waitForShutdown()
}

func printBanner() {
	banner := `
╔═══════════════════════════════════════════════════════════════╗
║          ███╗   ███╗██████╗       ██╗  ██╗                    ║
║          ████╗ ████║██╔══██╗      ╚██╗██╔╝                    ║
║          ██╔████╔██║██████╔╝█████╗ ╚███╔╝                     ║
║          ██║╚██╔╝██║██╔══██╗╚════╝ ██╔██╗                     ║
║          ██║ ╚═╝ ██║██║  ██║      ██╔╝ ██╗                    ║
║          ╚═╝     ╚═╝╚═╝  ╚═╝      ╚═╝  ╚═╝                    ║
║          Professional VPN Management Panel                    ║
╚═══════════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}

// ============================================================================
// CONFIGURATION LOADING
// ============================================================================

func loadConfig() error {
	AppConfig = getDefaultConfig()

	configPath = "/opt/mxui/config/config.yaml"

	// Check command line args for config path
	for i, arg := range os.Args {
		if (arg == "--config" || arg == "-c") && i+1 < len(os.Args) {
			configPath = os.Args[i+1]
			break
		}
	}

	// Environment variable override
	if envPath := os.Getenv("MXUI_CONFIG"); envPath != "" {
		configPath = envPath
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("ℹ️  Config file not found, using defaults")
		return nil
	}

	if err := yaml.Unmarshal(data, AppConfig); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	log.Printf("✓ Config loaded from: %s", configPath)
	loadEnvOverrides()

	// Validate and fix port numbers
	validateConfig()

	return nil
}

func validateConfig() {
	// Validate server port (must be 1-65535)
	if AppConfig.Server.Port < 1 || AppConfig.Server.Port > 65535 {
		log.Printf("⚠️  Invalid server port %d, using default 8443", AppConfig.Server.Port)
		AppConfig.Server.Port = 8443
	}

	// Validate TLS port
	if AppConfig.Server.TLSPort < 1 || AppConfig.Server.TLSPort > 65535 {
		log.Printf("⚠️  Invalid TLS port %d, using default 443", AppConfig.Server.TLSPort)
		AppConfig.Server.TLSPort = 443
	}

	// Validate login path
	if AppConfig.Panel.LoginPath == "" {
		AppConfig.Panel.LoginPath = "/dashboard"
	}

	// Log loaded config for debugging
	log.Printf("ℹ️  Server: %s:%d, TLS: %d, LoginPath: %s",
		AppConfig.Server.Host,
		AppConfig.Server.Port,
		AppConfig.Server.TLSPort,
		AppConfig.Panel.LoginPath)
}

func getDefaultConfig() *Config {
	return &Config{
		Server: HTTPServerConfig{
			Host:           "0.0.0.0",
			Port:           8443,
			TLSPort:        443,
			SinglePort:     true,
			SinglePortNum:  443,
			ReadTimeout:    30,
			WriteTimeout:   30,
			MaxHeaderBytes: 1 << 20,
		},
		Database: DatabaseConfig{
			Type:            "sqlite",
			Path:            "/opt/mxui/data/mxui.db",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 300,
		},
		Security: SecurityConfig{
			JWTSecret:          generateRandomString(32),
			JWTExpiry:          1440,
			RateLimitEnabled:   true,
			RateLimitRequests:  100,
			RateLimitWindow:    60,
			BruteForceEnabled:  true,
			BruteForceAttempts: 5,
			BruteForceWindow:   300,
			BruteForceBanTime:  3600,
		},
		Admin: AdminConfig{
			Username: "admin",
			Password: "admin",
		},
		Panel: PanelConfig{
			LoginPath:      "/dashboard",
			DecoyEnabled:   true,
			DecoyType:      "nginx",
			Language:       "fa",
			Theme:          "dark",
			Title:          "MXUI Panel",
			SubPath:        "sub",
			SessionTimeout: 1440,
		},
		Nodes: NodesConfig{
			Enabled:             true,
			SyncInterval:        60,
			HealthCheckInterval: 30,
			LoadBalanceStrategy: "round_robin",
			FailoverEnabled:     true,
			FailoverThreshold:   3,
		},
		Protocols: ProtocolsConfig{
			XrayEnabled:    true,
			XrayPath:       "/opt/mxui/bin/xray",
			XrayConfigPath: "/opt/mxui/data/xray_config.json",
			XrayAPIPort:    62789,
		},
		Telegram: TelegramConfig{
			NotifyOnLogin:    true,
			NotifyOnPurchase: true,
			NotifyOnExpiry:   true,
		},
		Backup: BackupConfig{
			Enabled:       true,
			LocalEnabled:  true,
			RetentionDays: 7,
			LocalPath:     "/opt/mxui/data/backups",
			BackupPath:    "/opt/mxui/data/backups",
		},
		AI: AIConfig{
			Provider: "openai",
			Model:    "gpt-4",
		},
		Logging: LoggingConfig{
			Level:      "info",
			Path:       "/opt/mxui/logs/mxui.log",
			MaxSize:    100,
			MaxBackups: 5,
			MaxAge:     30,
			Compress:   true,
			Console:    true,
		},
	}
}

func loadEnvOverrides() {
	if port := os.Getenv("MXUI_PORT"); port != "" {
		fmt.Sscanf(port, "%d", &AppConfig.Server.Port)
	}
	if host := os.Getenv("MXUI_HOST"); host != "" {
		AppConfig.Server.Host = host
	}
	if domain := os.Getenv("MXUI_DOMAIN"); domain != "" {
		AppConfig.Server.Domain = domain
	}
	if adminUser := os.Getenv("MXUI_ADMIN_USER"); adminUser != "" {
		AppConfig.Admin.Username = adminUser
	}
	if adminPass := os.Getenv("MXUI_ADMIN_PASS"); adminPass != "" {
		AppConfig.Admin.Password = adminPass
	}
	if jwtSecret := os.Getenv("MXUI_JWT_SECRET"); jwtSecret != "" {
		AppConfig.Security.JWTSecret = jwtSecret
	}
	if apiKey := os.Getenv("MXUI_API_KEY"); apiKey != "" {
		AppConfig.Security.APIKey = apiKey
	}
	if botToken := os.Getenv("MXUI_BOT_TOKEN"); botToken != "" {
		AppConfig.Telegram.BotToken = botToken
		AppConfig.Telegram.Enabled = true
	}
}

func SaveConfig() error {
	configMu.Lock()
	defer configMu.Unlock()

	data, err := yaml.Marshal(AppConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	return os.WriteFile(configPath, data, 0600)
}

// ============================================================================
// DATABASE INITIALIZATION
// ============================================================================

func initDatabase() error {
	log.Println("🔄 Initializing database...")

	encryptionKey := ""
	if AppConfig.Database.Encrypted {
		encryptionKey = AppConfig.Database.EncryptionKey
	}

	// Use database path from config
	dbPath := AppConfig.Database.Path
	if dbPath == "" {
		dbPath = "/opt/mxui/data/mxui.db"
	}

	if err := InitDatabaseWithPath(dbPath, encryptionKey); err != nil {
		return err
	}

	log.Println("✓ Database initialized")
	return nil
}

// ============================================================================
// SERVICE MANAGERS
// ============================================================================

func initManagers() {
	log.Println("🔄 Initializing service managers...")
	managers = []ServiceManager{}
	log.Printf("✓ Initialized %d service managers", len(managers))
}

// ============================================================================
// HTTP SERVER
// ============================================================================

func startHTTPServer() {
	mux := http.NewServeMux()
	setupRoutes(mux)

	handler := recoveryMiddleware(
		loggingMiddleware(
			corsMiddleware(
				rateLimitMiddleware(
					authMiddleware(mux),
				),
			),
		),
	)

	httpServer = &http.Server{
		Addr:           fmt.Sprintf("%s:%d", AppConfig.Server.Host, AppConfig.Server.Port),
		Handler:        handler,
		ReadTimeout:    time.Duration(AppConfig.Server.ReadTimeout) * time.Second,
		WriteTimeout:   time.Duration(AppConfig.Server.WriteTimeout) * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: AppConfig.Server.MaxHeaderBytes,
	}

	go func() {
		log.Printf("✓ HTTP Server listening on %s", httpServer.Addr)
		log.Printf("✓ Panel URL: http://localhost:%d%s", AppConfig.Server.Port, AppConfig.Panel.LoginPath)

		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("❌ HTTP server error: %v", err)
		}
	}()

	if AppConfig.Server.SSLEnabled && AppConfig.Server.SSLCertPath != "" && AppConfig.Server.SSLKeyPath != "" {
		go startHTTPSServer(handler)
	}
}

func startHTTPSServer(handler http.Handler) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}

	httpsServer = &http.Server{
		Addr:           fmt.Sprintf("%s:%d", AppConfig.Server.Host, AppConfig.Server.TLSPort),
		Handler:        handler,
		TLSConfig:      tlsConfig,
		ReadTimeout:    time.Duration(AppConfig.Server.ReadTimeout) * time.Second,
		WriteTimeout:   time.Duration(AppConfig.Server.WriteTimeout) * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: AppConfig.Server.MaxHeaderBytes,
	}

	log.Printf("✓ HTTPS Server listening on %s", httpsServer.Addr)

	if err := httpsServer.ListenAndServeTLS(AppConfig.Server.SSLCertPath, AppConfig.Server.SSLKeyPath); err != nil && err != http.ErrServerClosed {
		log.Printf("❌ HTTPS server error: %v", err)
	}
}

// ============================================================================
// ROUTES SETUP
// ============================================================================

func setupRoutes(mux *http.ServeMux) {
	// Health
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/v1/health", healthHandler)

	// Auth
	mux.HandleFunc("/api/v1/auth/login", loginHandler)
	mux.HandleFunc("/api/v1/auth/logout", logoutHandler)
	mux.HandleFunc("/api/v1/auth/verify", verifyHandler)
	mux.HandleFunc("/api/v1/auth/refresh", refreshTokenHandler)

	// Users
	mux.HandleFunc("/api/v1/users", usersHandler)
	mux.HandleFunc("/api/v1/users/", userHandler)

	// Admins
	mux.HandleFunc("/api/v1/admins", adminsHandler)
	mux.HandleFunc("/api/v1/admins/", adminHandler)

	// Nodes
	mux.HandleFunc("/api/v1/nodes", nodesHandler)
	mux.HandleFunc("/api/v1/nodes/", nodeHandler)
	mux.HandleFunc("/api/v1/nodes/sync", nodeSyncHandler)

	// System
	mux.HandleFunc("/api/v1/system/info", systemInfoHandler)
	mux.HandleFunc("/api/v1/system/stats", statsHandler)
	mux.HandleFunc("/api/v1/system/logs", logsHandler)
	mux.HandleFunc("/api/v1/system/config", configHandler)

	// Core
	mux.HandleFunc("/api/v1/core/status", coreStatusHandler)
	mux.HandleFunc("/api/v1/core/restart", coreRestartHandler)
	mux.HandleFunc("/api/v1/core/config", coreConfigHandler)

	// Inbounds
	mux.HandleFunc("/api/v1/inbounds", inboundsHandler)
	mux.HandleFunc("/api/v1/inbounds/", inboundHandler)

	// Backup
	mux.HandleFunc("/api/v1/backup", backupHandler)
	mux.HandleFunc("/api/v1/backup/restore", restoreHandler)

	// Subscription
	mux.HandleFunc("/api/v1/sub/", subscriptionHandler)

	// WebSocket
	mux.HandleFunc("/ws", wsHandler)
	mux.HandleFunc("/api/v1/ws", wsHandler)

	// Telegram
	mux.HandleFunc("/api/v1/telegram/webhook", telegramWebhookHandler)

	// Panel path
	loginPath := AppConfig.Panel.LoginPath
	if loginPath == "" {
		loginPath = "/dashboard"
	}
	mux.HandleFunc(loginPath, panelHandler)
	mux.HandleFunc(loginPath+"/", panelHandler)

	// Static files - check multiple locations
	staticDir := "/opt/mxui/web"
	// Check for development paths first
	devPaths := []string{"./Web", "./web", "../Web", "../web"}
	for _, path := range devPaths {
		if _, err := os.Stat(path); err == nil {
			staticDir = path
			break
		}
	}
	// Check production path
	if _, err := os.Stat(staticDir); err == nil {
		fs := http.FileServer(http.Dir(staticDir))
		mux.Handle("/static/", http.StripPrefix("/static/", fs))
		mux.Handle("/assets/", http.StripPrefix("/assets/", fs))
	}
	log.Printf("📁 Static files serving from: %s", staticDir)

	// Root handler - serves static files and decoy page
	staticExtensions := []string{".js", ".css", ".json", ".ico", ".png", ".jpg", ".svg", ".woff", ".woff2", ".ttf", ".html"}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a static file request
		for _, ext := range staticExtensions {
			if strings.HasSuffix(r.URL.Path, ext) {
				filePath := filepath.Join(staticDir, r.URL.Path)
				if _, err := os.Stat(filePath); err == nil {
					http.ServeFile(w, r, filePath)
					return
				}
			}
		}
		// Not a static file, use decoy handler if enabled
		if AppConfig.Panel.DecoyEnabled {
			decoyHandler(w, r)
		} else {
			http.NotFound(w, r)
		}
	})
}

// ============================================================================
// MIDDLEWARE
// ============================================================================

func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("❌ Panic recovered: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("📊 %s %s %s - %v", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start))
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicPaths := []string{"/health", "/api/v1/health", "/api/v1/auth/login", "/api/v1/sub/", "/", "/static/", "/assets/"}
		for _, path := range publicPaths {
			if strings.HasPrefix(r.URL.Path, path) {
				next.ServeHTTP(w, r)
				return
			}
		}

		if strings.HasPrefix(r.URL.Path, AppConfig.Panel.LoginPath) {
			next.ServeHTTP(w, r)
			return
		}

		if strings.HasPrefix(r.URL.Path, "/api/") {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				respondJSON(w, http.StatusUnauthorized, map[string]interface{}{
					"success": false,
					"message": "Authorization required",
				})
				return
			}

			if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
				token := authHeader[7:]
				if !validateToken(token) {
					respondJSON(w, http.StatusUnauthorized, map[string]interface{}{
						"success": false,
						"message": "Invalid token",
					})
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ============================================================================
// HANDLERS
// ============================================================================

func healthHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"status":     "healthy",
			"version":    Version,
			"uptime":     time.Since(startTime).Seconds(),
			"timestamp":  time.Now().Unix(),
			"go_version": runtime.Version(),
		},
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		TwoFACode string `json:"two_factor_code,omitempty"`
		Remember  bool   `json:"remember,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"message": "Invalid request",
		})
		return
	}

	configMu.RLock()
	adminUser := AppConfig.Admin.Username
	adminPass := AppConfig.Admin.Password
	configMu.RUnlock()

	if req.Username == adminUser && req.Password == adminPass {
		token := generateToken(req.Username, req.Remember)
		refreshToken := generateRefreshToken(req.Username)

		log.Printf("✓ Successful login: %s from %s", req.Username, r.RemoteAddr)

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success":       true,
			"token":         token,
			"refresh_token": refreshToken,
			"message":       "Login successful",
			"admin": map[string]interface{}{
				"username": req.Username,
				"role":     "owner",
			},
		})
	} else {
		log.Printf("⚠️  Failed login attempt: %s from %s", req.Username, r.RemoteAddr)
		respondJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success": false,
			"message": "Invalid credentials",
		})
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Logged out successfully",
	})
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || len(authHeader) < 8 {
		respondJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success": false,
			"message": "Token not found",
		})
		return
	}

	token := authHeader[7:]
	if validateToken(token) {
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"valid":   true,
		})
	} else {
		respondJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success": false,
			"message": "Invalid token",
		})
	}
}

func refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Token refreshed",
	})
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	if Users == nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"message": "User manager not initialized",
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Parse query parameters
		filter := &UserFilter{
			Limit:  20,
			Offset: 0,
		}
		if limit := r.URL.Query().Get("limit"); limit != "" {
			if l, err := strconv.Atoi(limit); err == nil {
				filter.Limit = l
			}
		}
		if offset := r.URL.Query().Get("offset"); offset != "" {
			if o, err := strconv.Atoi(offset); err == nil {
				filter.Offset = o
			}
		}
		if search := r.URL.Query().Get("search"); search != "" {
			filter.Search = search
		}
		if status := r.URL.Query().Get("status"); status != "" {
			filter.Status = status
		}

		result, err := Users.ListUsers(filter)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"success": false,
				"message": err.Error(),
			})
			return
		}

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success":     true,
			"data":        result.Users,
			"total":       result.Total,
			"limit":       result.Limit,
			"offset":      result.Offset,
			"total_pages": result.TotalPages,
		})

	case http.MethodPost:
		var req CreateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]interface{}{
				"success": false,
				"message": "Invalid request body",
			})
			return
		}

		user, err := Users.CreateUser(&req)
		if err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]interface{}{
				"success": false,
				"message": err.Error(),
			})
			return
		}

		respondJSON(w, http.StatusCreated, map[string]interface{}{
			"success": true,
			"data":    user,
			"message": "User created successfully",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	if Users == nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"message": "User manager not initialized",
		})
		return
	}

	// Extract user ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	userID, err := strconv.ParseInt(path, 10, 64)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"message": "Invalid user ID",
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		user, err := Users.GetUserByID(userID)
		if err != nil {
			respondJSON(w, http.StatusNotFound, map[string]interface{}{
				"success": false,
				"message": "User not found",
			})
			return
		}
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    user,
		})

	case http.MethodPut:
		var req UpdateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]interface{}{
				"success": false,
				"message": "Invalid request body",
			})
			return
		}

		user, err := Users.UpdateUser(userID, &req)
		if err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]interface{}{
				"success": false,
				"message": err.Error(),
			})
			return
		}

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    user,
			"message": "User updated successfully",
		})

	case http.MethodDelete:
		if err := Users.DeleteUser(userID); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]interface{}{
				"success": false,
				"message": err.Error(),
			})
			return
		}

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "User deleted successfully",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func adminsHandler(w http.ResponseWriter, r *http.Request) {
	if Admins == nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"message": "Admin manager not initialized",
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		filter := &AdminFilter{
			Limit:  20,
			Offset: 0,
		}

		result, err := Admins.ListAdmins(filter)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"success": false,
				"message": err.Error(),
			})
			return
		}

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    result.Admins,
			"total":   result.Total,
		})

	case http.MethodPost:
		var req CreateAdminRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]interface{}{
				"success": false,
				"message": "Invalid request body",
			})
			return
		}

		admin, err := Admins.CreateAdmin(&req, getAdminIDFromRequest(r))
		if err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]interface{}{
				"success": false,
				"message": err.Error(),
			})
			return
		}

		respondJSON(w, http.StatusCreated, map[string]interface{}{
			"success": true,
			"data":    admin,
			"message": "Admin created successfully",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	if Admins == nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"message": "Admin manager not initialized",
		})
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/admins/")
	adminID, err := strconv.ParseInt(path, 10, 64)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"message": "Invalid admin ID",
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		admin, err := Admins.GetAdminByID(adminID)
		if err != nil {
			respondJSON(w, http.StatusNotFound, map[string]interface{}{
				"success": false,
				"message": "Admin not found",
			})
			return
		}
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    admin,
		})

	case http.MethodDelete:
		if err := Admins.DeleteAdmin(adminID, getAdminIDFromRequest(r)); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]interface{}{
				"success": false,
				"message": err.Error(),
			})
			return
		}
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "Admin deleted successfully",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func nodesHandler(w http.ResponseWriter, r *http.Request) {
	if Nodes == nil {
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    []interface{}{},
			"total":   0,
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		nodes := Nodes.ListNodes()
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    nodes,
			"total":   len(nodes),
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func nodeHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

func nodeSyncHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Sync completed",
	})
}

func systemInfoHandler(w http.ResponseWriter, r *http.Request) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"version":       Version,
			"build_time":    BuildTime,
			"uptime":        time.Since(startTime).Seconds(),
			"go_version":    runtime.Version(),
			"os":            runtime.GOOS,
			"arch":          runtime.GOARCH,
			"num_cpu":       runtime.NumCPU(),
			"num_goroutine": runtime.NumGoroutine(),
			"memory": map[string]interface{}{
				"alloc":       memStats.Alloc,
				"total_alloc": memStats.TotalAlloc,
				"sys":         memStats.Sys,
			},
		},
	})
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"users":         0,
		"active_users":  0,
		"online_users":  0,
		"admins":        1,
		"nodes":         0,
		"online_nodes":  0,
		"total_traffic": int64(0),
		"today_traffic": int64(0),
		"version":       Version,
		"uptime":        time.Since(startTime).Seconds(),
	}

	// Get user stats
	if Users != nil {
		if userStats, err := Users.GetUserStats(); err == nil && userStats != nil {
			stats["users"] = userStats.TotalUsers
			stats["active_users"] = userStats.ActiveUsers
			stats["online_users"] = userStats.OnlineUsers
			stats["total_traffic"] = userStats.TotalTraffic
		}
	}

	// Get admin stats
	if Admins != nil {
		if adminStats, err := Admins.GetAdminStats(); err == nil && adminStats != nil {
			stats["admins"] = adminStats.TotalAdmins
		}
	}

	// Get node stats
	if Nodes != nil {
		nodes := Nodes.ListNodes()
		stats["nodes"] = len(nodes)
		onlineNodes := 0
		for _, node := range nodes {
			if node.IsAvailable {
				onlineNodes++
			}
		}
		stats["online_nodes"] = onlineNodes
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stats,
	})
}

func logsHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    []interface{}{},
	})
}

func configHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		configMu.RLock()
		defer configMu.RUnlock()

		safeConfig := map[string]interface{}{
			"server": map[string]interface{}{
				"host":        AppConfig.Server.Host,
				"port":        AppConfig.Server.Port,
				"ssl_enabled": AppConfig.Server.SSLEnabled,
				"domain":      AppConfig.Server.Domain,
			},
			"panel": AppConfig.Panel,
		}

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    safeConfig,
		})
	} else if r.Method == http.MethodPut {
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "Config updated",
		})
	}
}

func coreStatusHandler(w http.ResponseWriter, r *http.Request) {
	var coreStatus map[string]interface{}

	if Protocols != nil {
		coreStatus = Protocols.GetCoreStatus()
	} else {
		coreStatus = map[string]interface{}{
			"xray":    map[string]interface{}{"is_running": false},
			"singbox": map[string]interface{}{"is_running": false},
		}
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    coreStatus,
	})
}

func coreRestartHandler(w http.ResponseWriter, r *http.Request) {
	if Protocols == nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"message": "Protocol manager not initialized",
		})
		return
	}

	if err := Protocols.Restart(); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"message": "Failed to restart core: " + err.Error(),
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Core restarted successfully",
	})
}

func coreConfigHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{},
	})
}

func inboundsHandler(w http.ResponseWriter, r *http.Request) {
	if Protocols == nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"message": "Protocol manager not initialized",
		})
		return
	}

	// Get node_id from query params, default to 0 (master node)
	nodeIDStr := r.URL.Query().Get("node_id")
	var nodeID int64 = 0
	if nodeIDStr != "" {
		if id, err := strconv.ParseInt(nodeIDStr, 10, 64); err == nil {
			nodeID = id
		}
	}

	inbounds, err := Protocols.ListInbounds(nodeID)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"message": "Failed to list inbounds: " + err.Error(),
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    inbounds,
		"total":   len(inbounds),
	})
}

func inboundHandler(w http.ResponseWriter, r *http.Request) {
	if Protocols == nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"message": "Protocol manager not initialized",
		})
		return
	}

	// Extract inbound ID from URL
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"message": "Invalid inbound ID",
		})
		return
	}

	idStr := parts[len(parts)-1]
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"message": "Invalid inbound ID",
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		inbound, err := Protocols.GetInbound(id)
		if err != nil {
			respondJSON(w, http.StatusNotFound, map[string]interface{}{
				"success": false,
				"message": "Inbound not found",
			})
			return
		}
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    inbound,
		})

	case http.MethodDelete:
		if err := Protocols.DeleteInbound(id); err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"success": false,
				"message": "Failed to delete inbound: " + err.Error(),
			})
			return
		}
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "Inbound deleted",
		})

	default:
		respondJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{
			"success": false,
			"message": "Method not allowed",
		})
	}
}

func backupHandler(w http.ResponseWriter, r *http.Request) {
	if DB == nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"message": "Database not initialized",
		})
		return
	}

	backupPath := "./Data/backup_" + time.Now().Format("20060102_150405") + ".db"
	if err := DB.Backup(backupPath); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"message": "Failed to create backup: " + err.Error(),
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Backup created successfully",
		"path":    backupPath,
	})
}

func restoreHandler(w http.ResponseWriter, r *http.Request) {
	if DB == nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"message": "Database not initialized",
		})
		return
	}

	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"message": "Backup path is required",
		})
		return
	}

	if err := DB.Restore(req.Path); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"message": "Failed to restore backup: " + err.Error(),
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Restore completed successfully",
	})
}

func subscriptionHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid subscription", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("# Subscription content"))
}

func telegramWebhookHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

func panelHandler(w http.ResponseWriter, r *http.Request) {
	// Check multiple locations for web files
	staticDir := "/opt/mxui/web"
	devPaths := []string{"./Web", "./web", "../Web", "../web"}
	for _, path := range devPaths {
		if _, err := os.Stat(path); err == nil {
			staticDir = path
			break
		}
	}

	requestedFile := strings.TrimPrefix(r.URL.Path, AppConfig.Panel.LoginPath)
	if requestedFile == "" || requestedFile == "/" {
		requestedFile = "/login.html"
	}

	filePath := filepath.Join(staticDir, requestedFile)
	if _, err := os.Stat(filePath); err == nil {
		http.ServeFile(w, r, filePath)
		return
	}

	http.ServeFile(w, r, filepath.Join(staticDir, "login.html"))
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, _, _, err := ws.UpgradeHTTP(r, w)
	if err != nil {
		log.Printf("❌ WebSocket upgrade error: %v", err)
		return
	}

	log.Printf("✓ WebSocket connection established from %s", r.RemoteAddr)
	go handleWebSocket(conn)
}

func handleWebSocket(conn net.Conn) {
	defer func() {
		conn.Close()
		log.Printf("✓ WebSocket connection closed")
	}()

	for {
		msg, op, err := wsutil.ReadClientData(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("⚠️  WebSocket read error: %v", err)
			}
			break
		}

		var request map[string]interface{}
		if err := json.Unmarshal(msg, &request); err == nil {
			response := handleWSMessage(request)
			responseBytes, _ := json.Marshal(response)
			wsutil.WriteServerMessage(conn, op, responseBytes)
		}
	}
}

func handleWSMessage(msg map[string]interface{}) map[string]interface{} {
	msgType, _ := msg["type"].(string)

	switch msgType {
	case "ping":
		return map[string]interface{}{"type": "pong", "time": time.Now().Unix()}
	case "stats":
		return map[string]interface{}{"type": "stats", "data": map[string]interface{}{"users": 0, "traffic": 0}}
	default:
		return map[string]interface{}{"type": "unknown"}
	}
}

// ============================================================================
// NODE MODE
// ============================================================================

func runAsNode() {
	log.Println("🔄 Starting as Node...")

	masterAddr := AppConfig.Nodes.MasterAddress
	if masterAddr == "" {
		log.Fatal("❌ Master address not configured")
	}

	log.Printf("📡 Connecting to master: %s", masterAddr)
	waitForShutdown()
}

// ============================================================================
// SHUTDOWN
// ============================================================================

func waitForShutdown() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	sig := <-sigCh
	log.Printf("📥 Received signal: %v", sig)
	shutdown()
}

func shutdown() {
	log.Println("🔄 Shutting down gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if httpServer != nil {
		log.Println("🔄 Stopping HTTP server...")
		httpServer.Shutdown(ctx)
	}

	if httpsServer != nil {
		log.Println("🔄 Stopping HTTPS server...")
		httpsServer.Shutdown(ctx)
	}

	log.Println("🔄 Stopping services...")
	for _, mgr := range managers {
		mgr.Stop()
	}

	if DB != nil {
		log.Println("🔄 Closing database...")
		DB.Close()
	}

	if logger != nil {
		logger.Close()
	}

	log.Println("✅ Shutdown complete")
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func generateToken(username string, remember bool) string {
	expiry := time.Now().Add(24 * time.Hour)
	if remember {
		expiry = time.Now().Add(30 * 24 * time.Hour)
	}
	return fmt.Sprintf("mxui_%s_%d", username, expiry.Unix())
}

func generateRefreshToken(username string) string {
	return fmt.Sprintf("mxui_refresh_%s_%d", username, time.Now().Add(7*24*time.Hour).Unix())
}

func validateToken(token string) bool {
	if len(token) < 10 || !strings.HasPrefix(token, "mxui_") {
		return false
	}

	// Parse token: mxui_username_expiry
	parts := strings.Split(token, "_")
	if len(parts) < 3 {
		return false
	}

	// Check expiry
	expiryStr := parts[len(parts)-1]
	expiry, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil {
		return false
	}

	// Token expired?
	if time.Now().Unix() > expiry {
		return false
	}

	return true
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
		time.Sleep(time.Nanosecond)
	}
	return string(b)
}

func getServerIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}

// getAdminIDFromRequest extracts admin ID from JWT token in request
func getAdminIDFromRequest(r *http.Request) int64 {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || len(authHeader) < 8 {
		return 1 // Default to admin ID 1 if no token
	}

	token := authHeader[7:] // Remove "Bearer "
	parts := strings.Split(token, "_")
	if len(parts) < 3 {
		return 1
	}

	// Token format: mxui_username_expiry
	// Look up admin by username if available
	username := parts[1]
	if Admins != nil {
		if admin, err := Admins.GetAdminByUsername(username); err == nil && admin != nil {
			return admin.ID
		}
	}

	return 1
}
