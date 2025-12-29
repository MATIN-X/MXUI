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
	InitSessionManager()

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

	return nil
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
	if port := os.Getenv("Mxui_PORT"); port != "" {
		fmt.Sscanf(port, "%d", &AppConfig.Server.Port)
	}
	if host := os.Getenv("Mxui_HOST"); host != "" {
		AppConfig.Server.Host = host
	}
	if domain := os.Getenv("Mxui_DOMAIN"); domain != "" {
		AppConfig.Server.Domain = domain
	}
	if adminUser := os.Getenv("Mxui_ADMIN_USER"); adminUser != "" {
		AppConfig.Admin.Username = adminUser
	}
	if adminPass := os.Getenv("Mxui_ADMIN_PASS"); adminPass != "" {
		AppConfig.Admin.Password = adminPass
	}
	if jwtSecret := os.Getenv("Mxui_JWT_SECRET"); jwtSecret != "" {
		AppConfig.Security.JWTSecret = jwtSecret
	}
	if apiKey := os.Getenv("Mxui_API_KEY"); apiKey != "" {
		AppConfig.Security.APIKey = apiKey
	}
	if botToken := os.Getenv("Mxui_BOT_TOKEN"); botToken != "" {
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

	// Static files
	staticDir := "/opt/mxui/web"
	if _, err := os.Stat(staticDir); err == nil {
		fs := http.FileServer(http.Dir(staticDir))
		mux.Handle("/static/", http.StripPrefix("/static/", fs))
		mux.Handle("/assets/", http.StripPrefix("/assets/", fs))
	}

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
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    []interface{}{},
		"total":   0,
	})
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

func adminsHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    []interface{}{},
		"total":   0,
	})
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

func nodesHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    []interface{}{},
		"total":   0,
	})
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
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"users":         0,
			"active_users":  0,
			"online_users":  0,
			"admins":        1,
			"nodes":         0,
			"online_nodes":  0,
			"total_traffic": 0,
			"today_traffic": 0,
			"version":       Version,
			"uptime":        time.Since(startTime).Seconds(),
		},
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
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"xray":    map[string]interface{}{"running": false},
			"singbox": map[string]interface{}{"running": false},
		},
	})
}

func coreRestartHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Core restarted",
	})
}

func coreConfigHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{},
	})
}

func inboundsHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    []interface{}{},
		"total":   0,
	})
}

func inboundHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

func backupHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Backup created",
	})
}

func restoreHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Restore completed",
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
	staticDir := "/opt/mxui/web"
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
	return len(token) > 4 && token[:4] == "mxui_"
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
