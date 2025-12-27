// MXUI VPN Panel
// Core/database.go
// Database Layer: SQLite + Encryption + Models + Migrations

package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/pbkdf2"
)

// ============================================================================
// CONSTANTS
// ============================================================================

const (
	// Database
	DBFileName       = "mxui.db"
	DBBackupFileName = "mxui.db.backup"
	DBPath           = "./Data/"

	// Encryption
	EncryptionIterations = 100000
	EncryptionKeyLength  = 32
	EncryptionSaltLength = 16

	// User Status
	UserStatusActive   = "active"
	UserStatusExpired  = "expired"
	UserStatusDisabled = "disabled"
	UserStatusLimited  = "limited"
	UserStatusOnHold   = "on_hold"

	// Admin Roles
	AdminRoleOwner    = "owner"
	AdminRoleReseller = "reseller"

	// Traffic Reset Periods
	TrafficResetNone    = "none"
	TrafficResetDaily   = "daily"
	TrafficResetWeekly  = "weekly"
	TrafficResetMonthly = "monthly"
	TrafficResetYearly  = "yearly"

	// Data Reset Strategies
	ResetStrategyNoReset   = "no_reset"   // Never reset
	ResetStrategyOnRenewal = "on_renewal" // Reset when subscription renewed
	ResetStrategyPeriodic  = "periodic"   // Reset based on period

	// Node Status
	NodeStatusOnline  = "online"
	NodeStatusOffline = "offline"
	NodeStatusError   = "error"

	// Protocol Types
	ProtocolVMess       = "vmess"
	ProtocolVLESS       = "vless"
	ProtocolTrojan      = "trojan"
	ProtocolShadowsocks = "shadowsocks"
	ProtocolWireGuard   = "wireguard"
	ProtocolHysteria2   = "hysteria2"
	ProtocolTUIC        = "tuic"

	// Transport Types
	TransportTCP       = "tcp"
	TransportWebSocket = "ws"
	TransportGRPC      = "grpc"
	TransportHTTP2     = "http"
	TransportQUIC      = "quic"

	// Decoy Settings
	DecoyEnabled = "decoy_enabled"
	DecoyType    = "decoy_type" // nginx, apache, custom

	// Subscription
	SubPathPrefix = "sub"
	SubPathLength = 16
)

// ============================================================================
// DATABASE MANAGER
// ============================================================================

// DatabaseManager handles all database operations
type DatabaseManager struct {
	db            *sql.DB
	dbPath        string
	encryptionKey []byte
	mu            sync.RWMutex
	isEncrypted   bool
	dbType        DatabaseType  // Added for multi-DB support
	queryBuilder  *QueryBuilder // Added for multi-DB support
}

// Global database instance
var (
	DB       *DatabaseManager
	Database *DatabaseManager // Alias for DB
	once     sync.Once
)

// InitDatabase initializes the database connection
func InitDatabase(encryptionPassword string) error {
	return InitDatabaseWithPath("", encryptionPassword)
}

// InitDatabaseWithPath initializes the database connection with a specific path
func InitDatabaseWithPath(dbPath, encryptionPassword string) error {
	var initErr error

	once.Do(func() {
		// Use provided path or fall back to default
		if dbPath == "" {
			dbPath = filepath.Join(DBPath, DBFileName)
		}

		DB = &DatabaseManager{
			dbPath: dbPath,
		}
		Database = DB // Set alias

		// Create data directory if not exists
		dbDir := filepath.Dir(dbPath)
		if err := os.MkdirAll(dbDir, 0755); err != nil {
			initErr = fmt.Errorf("failed to create data directory: %w", err)
			return
		}

		// Generate encryption key if password provided
		if encryptionPassword != "" {
			DB.encryptionKey = DB.deriveKey(encryptionPassword)
			DB.isEncrypted = true
		}

		// Open database connection
		db, err := sql.Open("sqlite3", DB.dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
		if err != nil {
			initErr = fmt.Errorf("failed to open database: %w", err)
			return
		}

		// Configure connection pool
		db.SetMaxOpenConns(25)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(5 * time.Minute)

		DB.db = db

		// Run migrations
		if err := DB.migrate(); err != nil {
			initErr = fmt.Errorf("failed to run migrations: %w", err)
			return
		}

		// Create default owner admin if not exists
		if err := DB.createDefaultOwner(); err != nil {
			initErr = fmt.Errorf("failed to create default owner: %w", err)
			return
		}

		log.Println("✅ Database initialized successfully")
	})

	return initErr
}

// NewDatabaseManager creates a new database manager for testing
func NewDatabaseManager(dbPath, encryptionPassword string) (*DatabaseManager, error) {
	dm := &DatabaseManager{
		dbPath: dbPath,
	}

	// Generate encryption key if password provided
	if encryptionPassword != "" {
		dm.encryptionKey = dm.deriveKey(encryptionPassword)
		dm.isEncrypted = true
	}

	// Open database connection
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	dm.db = db

	// Run migrations
	if err := dm.migrate(); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return dm, nil
}

// Close closes the database connection
func (dm *DatabaseManager) Close() error {
	if dm.db != nil {
		return dm.db.Close()
	}
	return nil
}

// GetDB returns the database connection
func (dm *DatabaseManager) GetDB() *sql.DB {
	return dm.db
}

// ============================================================================
// MODELS
// ============================================================================

// Admin represents an admin user
type Admin struct {
	ID               int64  `json:"id"`
	Username         string `json:"username"`
	Password         string `json:"-"` // Never expose password
	Email            string `json:"email,omitempty"`
	Role             string `json:"role"` // owner, reseller
	IsActive         bool   `json:"is_active"`
	TelegramID       int64  `json:"telegram_id,omitempty"`
	TelegramUsername string `json:"telegram_username,omitempty"`

	// Reseller specific
	ParentAdminID *int64 `json:"parent_admin_id,omitempty"`
	TrafficLimit  int64  `json:"traffic_limit,omitempty"` // bytes, 0 = unlimited
	UserLimit     int    `json:"user_limit,omitempty"`    // 0 = unlimited
	TrafficUsed   int64  `json:"traffic_used"`
	UsersCreated  int    `json:"users_created"`

	// Metadata
	LastLogin    *time.Time `json:"last_login,omitempty"`
	LastIP       string     `json:"last_ip,omitempty"`
	IsFirstLogin bool       `json:"is_first_login"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// User represents a VPN user
type User struct {
	ID       int64    `json:"id"`
	UUID     string   `json:"uuid"`
	Username string   `json:"username"`
	Email    string   `json:"email,omitempty"`
	Note     string   `json:"note,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Token    string   `json:"token,omitempty"`

	// Status
	Status   string `json:"status"` // active, expired, disabled, limited, on_hold
	IsActive bool   `json:"is_active"`
	Enabled  bool   `json:"enabled"`

	// Subscription
	SubscriptionURL  string     `json:"subscription_url"`
	ExpiryTime       *time.Time `json:"expiry_time,omitempty"`
	OnHoldExpireDays int        `json:"on_hold_expire_days,omitempty"`
	OnHoldTimeout    *time.Time `json:"on_hold_timeout,omitempty"`

	// Traffic
	DataLimit          int64      `json:"data_limit"`           // bytes, 0 = unlimited
	DataUsed           int64      `json:"data_used"`            // bytes
	UploadUsed         int64      `json:"upload_used"`          // bytes
	DownloadUsed       int64      `json:"download_used"`        // bytes
	TrafficResetPeriod string     `json:"traffic_reset_period"` // none, daily, weekly, monthly
	LastTrafficReset   *time.Time `json:"last_traffic_reset,omitempty"`

	// Limits
	DeviceLimit   int `json:"device_limit"` // 0 = unlimited
	IPLimit       int `json:"ip_limit"`     // 0 = unlimited
	MaxDevices    int `json:"max_devices"`
	ActiveDevices int `json:"active_devices"`

	// Protocols & Inbounds
	EnabledProtocols []string `json:"enabled_protocols"`
	EnabledInbounds  []string `json:"enabled_inbounds"`

	// Admin
	CreatedByAdminID int64 `json:"created_by_admin_id"`

	// Metadata
	LastOnline       *time.Time `json:"last_online,omitempty"`
	LastIP           string     `json:"last_ip,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	TelegramID       int64      `json:"telegram_id,omitempty"`
	SubscriptionPath string     `json:"subscription_path"`
}

// UserDevice represents a logged-in device
type UserDevice struct {
	ID         int64     `json:"id"`
	UserID     int64     `json:"user_id"`
	DeviceID   string    `json:"device_id"`
	DeviceName string    `json:"device_name"`
	DeviceType string    `json:"device_type"` // android, ios, windows, macos, linux
	IP         string    `json:"ip"`
	Location   string    `json:"location,omitempty"`
	LastSeen   time.Time `json:"last_seen"`
	IsActive   bool      `json:"is_active"`
	CreatedAt  time.Time `json:"created_at"`
}

// OnlineUser represents a currently connected user
type OnlineUser struct {
	UserID      int64     `json:"user_id"`
	Username    string    `json:"username"`
	IP          string    `json:"ip"`
	Location    string    `json:"location,omitempty"`
	Protocol    string    `json:"protocol"`
	Inbound     string    `json:"inbound"`
	NodeID      int64     `json:"node_id,omitempty"`
	ConnectedAt time.Time `json:"connected_at"`
}

// Node represents a VPN server node
type Node struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Address   string `json:"address"` // IP or domain
	Port      int    `json:"port"`
	APIPort   int    `json:"api_port"`
	SecretKey string `json:"-"` // For node authentication

	// Status
	Status     string `json:"status"` // online, offline, error
	IsActive   bool   `json:"is_active"`
	IsMainNode bool   `json:"is_main_node"`

	// Metrics
	CPUUsage      float64 `json:"cpu_usage"`
	RAMUsage      float64 `json:"ram_usage"`
	DiskUsage     float64 `json:"disk_usage"`
	NetworkIn     int64   `json:"network_in"`     // bytes/s
	NetworkOut    int64   `json:"network_out"`    // bytes/s
	TotalUpload   int64   `json:"total_upload"`   // bytes
	TotalDownload int64   `json:"total_download"` // bytes
	ActiveUsers   int     `json:"active_users"`

	// Configuration
	Protocols    []string `json:"protocols"`
	TrafficRatio float64  `json:"traffic_ratio"` // Load balancing weight

	// Health
	LastCheck *time.Time `json:"last_check,omitempty"`
	LastError string     `json:"last_error,omitempty"`
	Uptime    int64      `json:"uptime"` // seconds

	// Metadata
	Location  string    `json:"location,omitempty"`
	Country   string    `json:"country,omitempty"`
	Flag      string    `json:"flag,omitempty"` // Country flag emoji
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Inbound represents a protocol inbound configuration
type Inbound struct {
	ID       int64  `json:"id"`
	NodeID   int64  `json:"node_id"`
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
	Listen   string `json:"listen"`
	Port     int    `json:"port"`
	Enabled  bool   `json:"enabled"`

	// Settings
	Settings       string `json:"settings"`           // JSON
	StreamSettings string `json:"stream_settings"`    // JSON
	Sniffing       string `json:"sniffing,omitempty"` // JSON

	// Protocol specific
	Method   string `json:"method,omitempty"`
	Password string `json:"password,omitempty"`

	// Transport
	Transport   string            `json:"transport"` // tcp, ws, grpc, http, quic
	Security    string            `json:"security"`  // none, tls, reality
	Path        string            `json:"path,omitempty"`
	Host        string            `json:"host,omitempty"`
	ServiceName string            `json:"service_name,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Flow        string            `json:"flow,omitempty"`

	// TLS/Reality
	TLSSettings     string `json:"tls_settings,omitempty"`     // JSON
	RealitySettings string `json:"reality_settings,omitempty"` // JSON
	SNI             string `json:"sni,omitempty"`
	ALPN            string `json:"alpn,omitempty"`
	Fingerprint     string `json:"fingerprint,omitempty"`
	AllowInsecure   bool   `json:"allow_insecure,omitempty"`

	// Reality specific
	RealityPublicKey string `json:"reality_public_key,omitempty"`
	RealityShortID   string `json:"reality_short_id,omitempty"`
	RealitySpiderX   string `json:"reality_spider_x,omitempty"`

	// Status
	IsActive bool `json:"is_active"`

	// Metadata
	Remark    string    `json:"remark,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Outbound represents a protocol outbound configuration
type Outbound struct {
	ID       int64  `json:"id"`
	NodeID   int64  `json:"node_id"`
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
	Settings string `json:"settings"` // JSON

	// Routing
	SendThrough string `json:"send_through,omitempty"`

	// Status
	IsActive bool `json:"is_active"`

	// Metadata
	Remark    string    `json:"remark,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RoutingRule represents a routing rule
type RoutingRule struct {
	ID       int64 `json:"id"`
	NodeID   int64 `json:"node_id"`
	Priority int   `json:"priority"`

	// Conditions
	Type       string   `json:"type"` // field, chinaip, chinasites, etc.
	Domain     []string `json:"domain,omitempty"`
	IP         []string `json:"ip,omitempty"`
	Port       string   `json:"port,omitempty"`
	SourcePort string   `json:"source_port,omitempty"`
	Network    string   `json:"network,omitempty"` // tcp, udp, tcp,udp
	Source     []string `json:"source,omitempty"`
	User       []string `json:"user,omitempty"`
	InboundTag []string `json:"inbound_tag,omitempty"`
	Protocol   []string `json:"protocol,omitempty"` // http, tls, bittorrent
	Attrs      string   `json:"attrs,omitempty"`

	// Action
	OutboundTag string `json:"outbound_tag"`
	BalancerTag string `json:"balancer_tag,omitempty"`

	// Status
	IsActive bool `json:"is_active"`

	// Metadata
	Remark    string    `json:"remark,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Settings represents panel settings
type Settings struct {
	ID          int64     `json:"id"`
	Key         string    `json:"key"`
	Value       string    `json:"value"`
	Type        string    `json:"type"` // string, int, bool, json
	Category    string    `json:"category"`
	IsEncrypted bool      `json:"is_encrypted"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ConnectionLog represents a user connection log
type ConnectionLog struct {
	ID             int64      `json:"id"`
	UserID         int64      `json:"user_id"`
	NodeID         int64      `json:"node_id"`
	IP             string     `json:"ip"`
	Location       string     `json:"location,omitempty"`
	Protocol       string     `json:"protocol"`
	Inbound        string     `json:"inbound"`
	Upload         int64      `json:"upload"`   // bytes
	Download       int64      `json:"download"` // bytes
	Duration       int64      `json:"duration"` // seconds
	ConnectedAt    time.Time  `json:"connected_at"`
	DisconnectedAt *time.Time `json:"disconnected_at,omitempty"`
}

// AuditLog represents an admin action log
type AuditLog struct {
	ID            int64     `json:"id"`
	AdminID       int64     `json:"admin_id"`
	AdminUsername string    `json:"admin_username"`
	Action        string    `json:"action"`
	Resource      string    `json:"resource"`
	ResourceID    int64     `json:"resource_id,omitempty"`
	OldValue      string    `json:"old_value,omitempty"` // JSON
	NewValue      string    `json:"new_value,omitempty"` // JSON
	IP            string    `json:"ip"`
	UserAgent     string    `json:"user_agent,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// Backup represents a backup record
type Backup struct {
	ID          int64     `json:"id"`
	FileName    string    `json:"file_name"`
	FilePath    string    `json:"file_path"`
	FileSize    int64     `json:"file_size"`
	Type        string    `json:"type"`        // auto, manual
	Destination string    `json:"destination"` // local, telegram, gdrive, s3
	Status      string    `json:"status"`      // pending, completed, failed
	Error       string    `json:"error,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Payment represents a payment/invoice
type Payment struct {
	ID            int64     `json:"id"`
	UserID        int64     `json:"user_id"`
	AdminID       int64     `json:"admin_id"`
	Amount        float64   `json:"amount"`
	Currency      string    `json:"currency"`
	Status        string    `json:"status"` // pending, completed, failed, refunded
	Method        string    `json:"method"` // wallet, card, crypto
	Description   string    `json:"description,omitempty"`
	InvoiceNumber string    `json:"invoice_number"`
	TransactionID string    `json:"transaction_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Template represents a page template
type Template struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`    // subscription, home, admin
	Content   string    `json:"content"` // HTML
	IsActive  bool      `json:"is_active"`
	IsDefault bool      `json:"is_default"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ============================================================================
// MIGRATIONS
// ============================================================================

func (dm *DatabaseManager) migrate() error {
	migrations := []string{
		// Admins table
		`CREATE TABLE IF NOT EXISTS admins (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			email TEXT,
			role TEXT NOT NULL DEFAULT 'reseller',
			is_active INTEGER DEFAULT 1,
			telegram_id INTEGER,
			telegram_username TEXT,
			parent_admin_id INTEGER,
			traffic_limit INTEGER DEFAULT 0,
			user_limit INTEGER DEFAULT 0,
			traffic_used INTEGER DEFAULT 0,
			users_created INTEGER DEFAULT 0,
			last_login DATETIME,
			last_ip TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (parent_admin_id) REFERENCES admins(id) ON DELETE SET NULL
		)`,

		// Users table
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			uuid TEXT UNIQUE NOT NULL,
			username TEXT UNIQUE NOT NULL,
			email TEXT,
			note TEXT,
			tags TEXT,
			status TEXT DEFAULT 'active',
			is_active INTEGER DEFAULT 1,
			subscription_url TEXT UNIQUE NOT NULL,
			expiry_time DATETIME,
			on_hold_expire_days INTEGER DEFAULT 0,
			on_hold_timeout DATETIME,
			data_limit INTEGER DEFAULT 0,
			data_used INTEGER DEFAULT 0,
			upload_used INTEGER DEFAULT 0,
			download_used INTEGER DEFAULT 0,
			traffic_reset_period TEXT DEFAULT 'none',
			last_traffic_reset DATETIME,
			device_limit INTEGER DEFAULT 0,
			ip_limit INTEGER DEFAULT 0,
			enabled_protocols TEXT,
			enabled_inbounds TEXT,
			created_by_admin_id INTEGER NOT NULL,
			last_online DATETIME,
			last_ip TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (created_by_admin_id) REFERENCES admins(id) ON DELETE CASCADE
		)`,

		// User devices table
		`CREATE TABLE IF NOT EXISTS user_devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			device_id TEXT NOT NULL,
			device_name TEXT,
			device_type TEXT,
			ip TEXT,
			location TEXT,
			last_seen DATETIME,
			is_active INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			UNIQUE(user_id, device_id)
		)`,

		// Online users table (temporary/session)
		`CREATE TABLE IF NOT EXISTS online_users (
			user_id INTEGER NOT NULL,
			ip TEXT NOT NULL,
			location TEXT,
			protocol TEXT,
			inbound TEXT,
			node_id INTEGER,
			connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, ip),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE SET NULL
		)`,

		// Nodes table
		`CREATE TABLE IF NOT EXISTS nodes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			address TEXT NOT NULL,
			port INTEGER DEFAULT 443,
			api_port INTEGER DEFAULT 62050,
			secret_key TEXT NOT NULL,
			status TEXT DEFAULT 'offline',
			is_active INTEGER DEFAULT 1,
			is_main_node INTEGER DEFAULT 0,
			cpu_usage REAL DEFAULT 0,
			ram_usage REAL DEFAULT 0,
			disk_usage REAL DEFAULT 0,
			network_in INTEGER DEFAULT 0,
			network_out INTEGER DEFAULT 0,
			total_upload INTEGER DEFAULT 0,
			total_download INTEGER DEFAULT 0,
			active_users INTEGER DEFAULT 0,
			protocols TEXT,
			traffic_ratio REAL DEFAULT 1.0,
			last_check DATETIME,
			last_error TEXT,
			uptime INTEGER DEFAULT 0,
			location TEXT,
			flag TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Inbounds table
		`CREATE TABLE IF NOT EXISTS inbounds (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			node_id INTEGER NOT NULL,
			tag TEXT NOT NULL,
			protocol TEXT NOT NULL,
			listen TEXT DEFAULT '0.0.0.0',
			port INTEGER NOT NULL,
			settings TEXT,
			stream_settings TEXT,
			sniffing TEXT,
			transport TEXT DEFAULT 'tcp',
			security TEXT DEFAULT 'none',
			tls_settings TEXT,
			reality_settings TEXT,
			is_active INTEGER DEFAULT 1,
			remark TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
			UNIQUE(node_id, tag)
		)`,

		// Outbounds table
		`CREATE TABLE IF NOT EXISTS outbounds (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			node_id INTEGER NOT NULL,
			tag TEXT NOT NULL,
			protocol TEXT NOT NULL,
			settings TEXT,
			send_through TEXT,
			is_active INTEGER DEFAULT 1,
			remark TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
			UNIQUE(node_id, tag)
		)`,

		// Routing rules table
		`CREATE TABLE IF NOT EXISTS routing_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			node_id INTEGER NOT NULL,
			priority INTEGER DEFAULT 0,
			type TEXT DEFAULT 'field',
			domain TEXT,
			ip TEXT,
			port TEXT,
			source_port TEXT,
			network TEXT,
			source TEXT,
			user TEXT,
			inbound_tag TEXT,
			protocol TEXT,
			attrs TEXT,
			outbound_tag TEXT NOT NULL,
			balancer_tag TEXT,
			is_active INTEGER DEFAULT 1,
			remark TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
		)`,

		// Settings table
		`CREATE TABLE IF NOT EXISTS settings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			key TEXT UNIQUE NOT NULL,
			value TEXT,
			type TEXT DEFAULT 'string',
			category TEXT DEFAULT 'general',
			is_encrypted INTEGER DEFAULT 0,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Connection logs table
		`CREATE TABLE IF NOT EXISTS connection_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			node_id INTEGER,
			ip TEXT,
			location TEXT,
			protocol TEXT,
			inbound TEXT,
			upload INTEGER DEFAULT 0,
			download INTEGER DEFAULT 0,
			duration INTEGER DEFAULT 0,
			connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			disconnected_at DATETIME,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE SET NULL
		)`,

		// Audit logs table
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			admin_id INTEGER NOT NULL,
			admin_username TEXT,
			action TEXT NOT NULL,
			resource TEXT,
			resource_id INTEGER,
			old_value TEXT,
			new_value TEXT,
			ip TEXT,
			user_agent TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
		)`,

		// Backups table
		`CREATE TABLE IF NOT EXISTS backups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			file_name TEXT NOT NULL,
			file_path TEXT,
			file_size INTEGER,
			type TEXT DEFAULT 'manual',
			destination TEXT DEFAULT 'local',
			status TEXT DEFAULT 'pending',
			error TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Payments table
		`CREATE TABLE IF NOT EXISTS payments (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			admin_id INTEGER,
			amount REAL NOT NULL,
			currency TEXT DEFAULT 'USD',
			status TEXT DEFAULT 'pending',
			method TEXT,
			description TEXT,
			invoice_number TEXT UNIQUE,
			transaction_id TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
			FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE SET NULL
		)`,

		// Wallets table
		`CREATE TABLE IF NOT EXISTS wallets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER UNIQUE NOT NULL,
			balance REAL DEFAULT 0,
			currency TEXT DEFAULT 'USD',
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,

		// Subscription plans table
		`CREATE TABLE IF NOT EXISTS subscription_plans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT,
			price REAL NOT NULL,
			currency TEXT DEFAULT 'USD',
			duration INTEGER NOT NULL,
			data_limit INTEGER DEFAULT 0,
			device_limit INTEGER DEFAULT 0,
			ip_limit INTEGER DEFAULT 0,
			protocols TEXT,
			is_active INTEGER DEFAULT 1,
			sort_order INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Templates table
		`CREATE TABLE IF NOT EXISTS templates (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			type TEXT NOT NULL,
			content TEXT,
			is_active INTEGER DEFAULT 1,
			is_default INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Create indexes
		`CREATE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid)`,
		`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`,
		`CREATE INDEX IF NOT EXISTS idx_users_subscription_url ON users(subscription_url)`,
		`CREATE INDEX IF NOT EXISTS idx_users_status ON users(status)`,
		`CREATE INDEX IF NOT EXISTS idx_users_admin ON users(created_by_admin_id)`,
		`CREATE INDEX IF NOT EXISTS idx_connection_logs_user ON connection_logs(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_connection_logs_date ON connection_logs(connected_at)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_admin ON audit_logs(admin_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_date ON audit_logs(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_inbounds_node ON inbounds(node_id)`,
		`CREATE INDEX IF NOT EXISTS idx_outbounds_node ON outbounds(node_id)`,
		`CREATE INDEX IF NOT EXISTS idx_routing_rules_node ON routing_rules(node_id)`,

		// Import logs table for database migration from other panels
		`CREATE TABLE IF NOT EXISTS import_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			source_panel TEXT NOT NULL,
			file_path TEXT,
			imported_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			users_count INTEGER DEFAULT 0,
			admins_count INTEGER DEFAULT 0,
			nodes_count INTEGER DEFAULT 0,
			status TEXT DEFAULT 'pending',
			error_message TEXT,
			details TEXT
		)`,

		// Enhanced traffic history table
		`CREATE TABLE IF NOT EXISTS traffic_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			upload INTEGER DEFAULT 0,
			download INTEGER DEFAULT 0,
			total INTEGER DEFAULT 0,
			recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			period_type TEXT DEFAULT 'hourly',
			node_id INTEGER,
			inbound_tag TEXT,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE SET NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_history_user ON traffic_history(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_history_date ON traffic_history(recorded_at)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_history_period ON traffic_history(period_type)`,

		// Traffic notifications table
		`CREATE TABLE IF NOT EXISTS traffic_notifications (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			threshold_percent INTEGER NOT NULL,
			notified_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			notification_type TEXT DEFAULT 'threshold',
			message TEXT,
			sent_via TEXT,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_notifications_user ON traffic_notifications(user_id)`,

		// User notes table
		`CREATE TABLE IF NOT EXISTS user_notes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			admin_id INTEGER,
			note TEXT NOT NULL,
			note_type TEXT DEFAULT 'general',
			is_pinned INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE SET NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_user_notes_user ON user_notes(user_id)`,

		// Next plans table (queue next subscription)
		`CREATE TABLE IF NOT EXISTS next_plans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL UNIQUE,
			template_id INTEGER,
			data_limit INTEGER DEFAULT 0,
			expire_duration INTEGER DEFAULT 0,
			expire_strategy TEXT DEFAULT 'fixed_date',
			ip_limit INTEGER DEFAULT 0,
			protocols TEXT,
			inbounds TEXT,
			notes TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (template_id) REFERENCES user_templates(id) ON DELETE SET NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_next_plans_user ON next_plans(user_id)`,

		// Extended routing rules table
		`CREATE TABLE IF NOT EXISTS extended_routing_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT,
			rule_type TEXT NOT NULL,
			domains TEXT,
			ips TEXT,
			ports TEXT,
			protocols TEXT,
			source_ips TEXT,
			source_ports TEXT,
			network TEXT,
			outbound_tag TEXT NOT NULL,
			balancer_tag TEXT,
			priority INTEGER DEFAULT 100,
			enabled INTEGER DEFAULT 1,
			node_id INTEGER,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_extended_routing_rules_node ON extended_routing_rules(node_id)`,
		`CREATE INDEX IF NOT EXISTS idx_extended_routing_rules_enabled ON extended_routing_rules(enabled)`,

		// DNS configurations table
		`CREATE TABLE IF NOT EXISTS dns_configs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			config_type TEXT NOT NULL DEFAULT 'doh',
			servers TEXT NOT NULL,
			hosts TEXT,
			client_ip TEXT,
			query_strategy TEXT DEFAULT 'UseIP',
			disable_cache INTEGER DEFAULT 0,
			disable_fallback INTEGER DEFAULT 0,
			disable_fallback_if_match INTEGER DEFAULT 0,
			tag TEXT,
			enabled INTEGER DEFAULT 1,
			node_id INTEGER,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_configs_node ON dns_configs(node_id)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_configs_enabled ON dns_configs(enabled)`,

		// Fragment settings table
		`CREATE TABLE IF NOT EXISTS fragment_settings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			packets TEXT DEFAULT 'tlshello',
			length TEXT DEFAULT '100-200',
			interval TEXT DEFAULT '10-20',
			enabled INTEGER DEFAULT 1,
			node_id INTEGER,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
		)`,

		// MUX settings table
		`CREATE TABLE IF NOT EXISTS mux_settings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			enabled INTEGER DEFAULT 0,
			protocol TEXT DEFAULT 'smux',
			max_connections INTEGER DEFAULT 4,
			min_streams INTEGER DEFAULT 4,
			max_streams INTEGER DEFAULT 0,
			padding INTEGER DEFAULT 1,
			brutal_enabled INTEGER DEFAULT 0,
			brutal_up_mbps INTEGER DEFAULT 10,
			brutal_down_mbps INTEGER DEFAULT 100,
			only_tcp INTEGER DEFAULT 0,
			node_id INTEGER,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
		)`,

		// WARP endpoints table
		`CREATE TABLE IF NOT EXISTS warp_endpoints (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			endpoint TEXT NOT NULL,
			latency_ms INTEGER DEFAULT 0,
			last_tested DATETIME,
			success_rate REAL DEFAULT 0,
			is_active INTEGER DEFAULT 1,
			region TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_warp_endpoints_latency ON warp_endpoints(latency_ms)`,

		// Subscription access logs table
		`CREATE TABLE IF NOT EXISTS subscription_access_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			access_token TEXT,
			user_agent TEXT,
			client_type TEXT,
			ip_address TEXT,
			format_requested TEXT,
			accessed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sub_access_logs_user ON subscription_access_logs(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sub_access_logs_date ON subscription_access_logs(accessed_at)`,

		// Add new columns to users table for enhanced features
		`ALTER TABLE users ADD COLUMN last_online_at DATETIME`,
		`ALTER TABLE users ADD COLUMN online_status TEXT DEFAULT 'offline'`,
		`ALTER TABLE users ADD COLUMN upload_traffic INTEGER DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN download_traffic INTEGER DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN last_traffic_reset DATETIME`,
		`ALTER TABLE users ADD COLUMN traffic_reset_strategy TEXT DEFAULT 'no_reset'`,
		`ALTER TABLE users ADD COLUMN next_plan_id INTEGER REFERENCES next_plans(id)`,

		// Add first login flag to admins
		`ALTER TABLE admins ADD COLUMN is_first_login INTEGER DEFAULT 1`,
	}

	for _, migration := range migrations {
		if _, err := dm.db.Exec(migration); err != nil {
			// Ignore "duplicate column" errors for ALTER TABLE statements
			// This allows migrations to be re-run safely
			errStr := err.Error()
			if strings.Contains(migration, "ALTER TABLE") &&
				(strings.Contains(errStr, "duplicate column") ||
					strings.Contains(errStr, "already exists")) {
				continue
			}
			return fmt.Errorf("migration failed: %w", err)
		}
	}

	return nil
}

// ============================================================================
// DEFAULT DATA
// ============================================================================

func (dm *DatabaseManager) createDefaultOwner() error {
	// Check if any admin exists
	var count int
	err := dm.db.QueryRow("SELECT COUNT(*) FROM admins").Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		return nil // Admin already exists
	}

	// Create default owner admin
	hashedPassword, err := HashPassword("admin")
	if err != nil {
		return err
	}

	_, err = dm.db.Exec(`
		INSERT INTO admins (username, password, role, is_active) 
		VALUES (?, ?, ?, ?)
	`, "admin", hashedPassword, AdminRoleOwner, true)

	if err != nil {
		return err
	}

	log.Println("âœ… Default owner admin created (username: admin, password: admin)")
	log.Println("âš ï¸  IMPORTANT: Change the default password immediately!")

	return nil
}

// ============================================================================
// ENCRYPTION HELPERS
// ============================================================================

func (dm *DatabaseManager) deriveKey(password string) []byte {
	salt := []byte("MRX-VPN-PANEL-SALT") // In production, use random salt stored separately
	return pbkdf2.Key([]byte(password), salt, EncryptionIterations, EncryptionKeyLength, sha256.New)
}

// Encrypt encrypts data using AES-GCM
func (dm *DatabaseManager) Encrypt(plaintext string) (string, error) {
	if !dm.isEncrypted || dm.encryptionKey == nil {
		return plaintext, nil
	}

	block, err := aes.NewCipher(dm.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data using AES-GCM
func (dm *DatabaseManager) Decrypt(ciphertext string) (string, error) {
	if !dm.isEncrypted || dm.encryptionKey == nil {
		return ciphertext, nil
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(dm.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(data) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// ============================================================================
// PASSWORD HELPERS
// ============================================================================

// HashPassword hashes password using SHA-256 with salt
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)

	// Combine salt and hash
	result := make([]byte, 16+32)
	copy(result[:16], salt)
	copy(result[16:], hash)

	return hex.EncodeToString(result), nil
}

// VerifyPassword verifies password against hash
func VerifyPassword(password, hashedPassword string) bool {
	data, err := hex.DecodeString(hashedPassword)
	if err != nil || len(data) != 48 {
		return false
	}

	salt := data[:16]
	expectedHash := data[16:]

	hash := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)

	// Constant time comparison
	if len(hash) != len(expectedHash) {
		return false
	}

	result := 0
	for i := 0; i < len(hash); i++ {
		result |= int(hash[i] ^ expectedHash[i])
	}

	return result == 0
}

// ============================================================================
// GENERIC CRUD HELPERS
// ============================================================================

// Transaction executes a function within a transaction
func (dm *DatabaseManager) Transaction(fn func(*sql.Tx) error) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	tx, err := dm.db.Begin()
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

// ============================================================================
// SETTINGS CRUD
// ============================================================================

// GetSetting retrieves a setting by key
func (dm *DatabaseManager) GetSetting(key string) (string, error) {
	var value string
	var isEncrypted bool

	err := dm.db.QueryRow(
		"SELECT value, is_encrypted FROM settings WHERE key = ?",
		key,
	).Scan(&value, &isEncrypted)

	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	if isEncrypted {
		return dm.Decrypt(value)
	}

	return value, nil
}

// SetSetting sets a setting value
func (dm *DatabaseManager) SetSetting(key, value, valueType, category string, encrypted bool) error {
	if encrypted {
		var err error
		value, err = dm.Encrypt(value)
		if err != nil {
			return err
		}
	}

	_, err := dm.db.Exec(`
		INSERT INTO settings (key, value, type, category, is_encrypted, updated_at)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET
			value = excluded.value,
			type = excluded.type,
			category = excluded.category,
			is_encrypted = excluded.is_encrypted,
			updated_at = CURRENT_TIMESTAMP
	`, key, value, valueType, category, encrypted)

	return err
}

// GetAllSettings retrieves all settings by category
func (dm *DatabaseManager) GetAllSettings(category string) (map[string]string, error) {
	query := "SELECT key, value, is_encrypted FROM settings"
	args := []interface{}{}

	if category != "" {
		query += " WHERE category = ?"
		args = append(args, category)
	}

	rows, err := dm.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	settings := make(map[string]string)
	for rows.Next() {
		var key, value string
		var isEncrypted bool

		if err := rows.Scan(&key, &value, &isEncrypted); err != nil {
			return nil, err
		}

		if isEncrypted {
			value, _ = dm.Decrypt(value)
		}

		settings[key] = value
	}

	return settings, rows.Err()
}

// ============================================================================
// JSON HELPERS
// ============================================================================

// StringSliceToJSON converts string slice to JSON string
func StringSliceToJSON(slice []string) string {
	if slice == nil {
		return "[]"
	}
	data, _ := json.Marshal(slice)
	return string(data)
}

// JSONToStringSlice converts JSON string to string slice
func JSONToStringSlice(jsonStr string) []string {
	if jsonStr == "" || jsonStr == "null" {
		return nil
	}
	var slice []string
	json.Unmarshal([]byte(jsonStr), &slice)
	return slice
}

// ============================================================================
// STATISTICS
// ============================================================================

// SystemStats represents system statistics
type SystemStats struct {
	TotalUsers    int   `json:"total_users"`
	ActiveUsers   int   `json:"active_users"`
	OnlineUsers   int   `json:"online_users"`
	ExpiredUsers  int   `json:"expired_users"`
	DisabledUsers int   `json:"disabled_users"`
	TotalAdmins   int   `json:"total_admins"`
	TotalNodes    int   `json:"total_nodes"`
	OnlineNodes   int   `json:"online_nodes"`
	TotalTraffic  int64 `json:"total_traffic"`
	TotalUpload   int64 `json:"total_upload"`
	TotalDownload int64 `json:"total_download"`

	// System resources
	CPUUsage    float64 `json:"cpu_usage"`
	RAMUsage    float64 `json:"ram_usage"`
	RAMTotal    uint64  `json:"ram_total"`
	RAMUsed     uint64  `json:"ram_used"`
	DiskUsage   float64 `json:"disk_usage"`
	DiskTotal   uint64  `json:"disk_total"`
	DiskUsed    uint64  `json:"disk_used"`
	Uptime      int64   `json:"uptime"`
	IPv4        string  `json:"ipv4"`
	IPv6        string  `json:"ipv6"`
	CoreStatus  string  `json:"core_status"`
	CoreVersion string  `json:"core_version"`
}

// GetSystemStats retrieves system statistics
func (dm *DatabaseManager) GetSystemStats() (*SystemStats, error) {
	stats := &SystemStats{}

	// Users stats
	dm.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&stats.TotalUsers)
	dm.db.QueryRow("SELECT COUNT(*) FROM users WHERE status = 'active' AND is_active = 1").Scan(&stats.ActiveUsers)
	dm.db.QueryRow("SELECT COUNT(*) FROM online_users").Scan(&stats.OnlineUsers)
	dm.db.QueryRow("SELECT COUNT(*) FROM users WHERE status = 'expired'").Scan(&stats.ExpiredUsers)
	dm.db.QueryRow("SELECT COUNT(*) FROM users WHERE is_active = 0").Scan(&stats.DisabledUsers)

	// Admins stats
	dm.db.QueryRow("SELECT COUNT(*) FROM admins").Scan(&stats.TotalAdmins)

	// Nodes stats
	dm.db.QueryRow("SELECT COUNT(*) FROM nodes").Scan(&stats.TotalNodes)
	dm.db.QueryRow("SELECT COUNT(*) FROM nodes WHERE status = 'online' AND is_active = 1").Scan(&stats.OnlineNodes)

	// Traffic stats
	dm.db.QueryRow("SELECT COALESCE(SUM(data_used), 0) FROM users").Scan(&stats.TotalTraffic)
	dm.db.QueryRow("SELECT COALESCE(SUM(upload_used), 0) FROM users").Scan(&stats.TotalUpload)
	dm.db.QueryRow("SELECT COALESCE(SUM(download_used), 0) FROM users").Scan(&stats.TotalDownload)

	// System resources
	stats.CPUUsage, stats.RAMUsage, stats.RAMTotal, stats.RAMUsed = getSystemResourceUsage()
	stats.DiskUsage, stats.DiskTotal, stats.DiskUsed = getDetailedDiskUsage("/")
	stats.Uptime = getDetailedSystemUptime()
	stats.IPv4, stats.IPv6 = getServerIPs()

	// Core status
	if Protocols != nil {
		coreStatus := Protocols.GetCoreStatus()
		if status, ok := coreStatus["xray"].(map[string]interface{}); ok {
			if running, ok := status["running"].(bool); ok && running {
				stats.CoreStatus = "running"
			} else {
				stats.CoreStatus = "stopped"
			}
			if version, ok := status["version"].(string); ok {
				stats.CoreVersion = version
			}
		}
	} else {
		stats.CoreStatus = "unknown"
	}

	return stats, nil
}

// getSystemResourceUsage returns CPU usage, RAM usage percentage, total RAM, and used RAM
func getSystemResourceUsage() (float64, float64, uint64, uint64) {
	// Read /proc/meminfo for RAM
	var ramTotal, ramAvailable uint64
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			value, _ := strconv.ParseUint(fields[1], 10, 64)
			value *= 1024 // Convert KB to bytes
			switch fields[0] {
			case "MemTotal:":
				ramTotal = value
			case "MemAvailable:":
				ramAvailable = value
			}
		}
	}
	ramUsed := ramTotal - ramAvailable
	ramUsage := float64(0)
	if ramTotal > 0 {
		ramUsage = float64(ramUsed) / float64(ramTotal) * 100
	}

	// Read /proc/stat for CPU (simplified - returns current load average instead)
	var cpuUsage float64
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			load, _ := strconv.ParseFloat(fields[0], 64)
			// Normalize by number of CPUs
			numCPU := float64(runtime.NumCPU())
			cpuUsage = (load / numCPU) * 100
			if cpuUsage > 100 {
				cpuUsage = 100
			}
		}
	}

	return cpuUsage, ramUsage, ramTotal, ramUsed
}

// getDetailedDiskUsage returns disk usage percentage, total, and used for a path
func getDetailedDiskUsage(path string) (float64, uint64, uint64) {
	// Use syscall to get disk stats
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, 0
	}

	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used := total - free
	usage := float64(0)
	if total > 0 {
		usage = float64(used) / float64(total) * 100
	}

	return usage, total, used
}

// getDetailedSystemUptime returns system uptime in seconds
func getDetailedSystemUptime() int64 {
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			uptime, _ := strconv.ParseFloat(fields[0], 64)
			return int64(uptime)
		}
	}
	return 0
}

// getServerIPs returns the server's IPv4 and IPv6 addresses
func getServerIPs() (string, string) {
	var ipv4, ipv6 string

	interfaces, err := net.Interfaces()
	if err != nil {
		return "", ""
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}

			if ip4 := ip.To4(); ip4 != nil {
				if ipv4 == "" {
					ipv4 = ip4.String()
				}
			} else if ipv6 == "" {
				ipv6 = ip.String()
			}
		}
	}

	return ipv4, ipv6
}

// ============================================================================
// CLEANUP & MAINTENANCE
// ============================================================================

// CleanupExpiredSessions removes expired online users
func (dm *DatabaseManager) CleanupExpiredSessions(timeout time.Duration) error {
	_, err := dm.db.Exec(`
		DELETE FROM online_users 
		WHERE connected_at < ?
	`, time.Now().Add(-timeout))
	return err
}

// CleanupOldLogs removes old connection logs
func (dm *DatabaseManager) CleanupOldLogs(olderThan time.Duration) error {
	_, err := dm.db.Exec(`
		DELETE FROM connection_logs 
		WHERE connected_at < ?
	`, time.Now().Add(-olderThan))
	return err
}

// CleanupOldAuditLogs removes old audit logs
func (dm *DatabaseManager) CleanupOldAuditLogs(olderThan time.Duration) error {
	_, err := dm.db.Exec(`
		DELETE FROM audit_logs 
		WHERE created_at < ?
	`, time.Now().Add(-olderThan))
	return err
}

// VacuumDatabase optimizes the database
func (dm *DatabaseManager) VacuumDatabase() error {
	_, err := dm.db.Exec("VACUUM")
	return err
}

// ============================================================================
// BACKUP & RESTORE
// ============================================================================

// BackupDatabase creates a database backup
func (dm *DatabaseManager) BackupDatabase(backupPath string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Execute checkpoint to ensure all WAL data is written
	if _, err := dm.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return err
	}

	// Copy database file
	srcFile, err := os.Open(dm.dbPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(backupPath)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// RestoreDatabase restores database from backup
func (dm *DatabaseManager) RestoreDatabase(backupPath string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Close current connection
	if err := dm.db.Close(); err != nil {
		return err
	}

	// Create backup of current database
	currentBackup := dm.dbPath + ".pre-restore"
	if err := os.Rename(dm.dbPath, currentBackup); err != nil {
		return err
	}

	// Copy backup file
	srcFile, err := os.Open(backupPath)
	if err != nil {
		// Restore original
		os.Rename(currentBackup, dm.dbPath)
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dm.dbPath)
	if err != nil {
		os.Rename(currentBackup, dm.dbPath)
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		os.Rename(currentBackup, dm.dbPath)
		return err
	}

	// Remove old backup
	os.Remove(currentBackup)

	// Reopen database
	db, err := sql.Open("sqlite3", dm.dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return err
	}
	dm.db = db

	return nil
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

// HealthCheck verifies database connectivity and integrity
func (dm *DatabaseManager) HealthCheck() error {
	// Ping database
	if err := dm.db.Ping(); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	// Check integrity
	var result string
	if err := dm.db.QueryRow("PRAGMA integrity_check").Scan(&result); err != nil {
		return fmt.Errorf("integrity check failed: %w", err)
	}

	if result != "ok" {
		return fmt.Errorf("database integrity check failed: %s", result)
	}

	return nil
}

// GetDatabaseSize returns the database file size in bytes
func (dm *DatabaseManager) GetDatabaseSize() (int64, error) {
	info, err := os.Stat(dm.dbPath)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func (dm *DatabaseManager) EncryptSensitive(data string) string {

	if !dm.isEncrypted || dm.encryptionKey == nil {
		return data
	}
	return data
}

func (dm *DatabaseManager) DecryptSensitive(data string) string {
	if !dm.isEncrypted || dm.encryptionKey == nil {
		return data
	}
	return data
}

func (dm *DatabaseManager) Backup(path string) error {
	return nil
}

func (dm *DatabaseManager) Restore(path string) error {
	return nil
}
