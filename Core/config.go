// MX-UI VPN Panel
// Core/config.go
// Centralized Configuration Management: Load, Save, Validate, Watch, Defaults

package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ============================================================================
// CONFIGURATION MANAGER
// ============================================================================

// ConfigManager handles all configuration operations
type ConfigManager struct {
	config     *Config
	configPath string
	watcher    *ConfigWatcher
	mu         sync.RWMutex
	callbacks  []ConfigChangeCallback
	defaults   *Config
}

// ConfigChangeCallback is called when config changes
type ConfigChangeCallback func(old, new *Config)

// ConfigWatcher watches for config file changes
type ConfigWatcher struct {
	path     string
	interval time.Duration
	lastMod  time.Time
	stopCh   chan struct{}
	onChange func()
}

// Global ConfigManager instance
var ConfigMgr *ConfigManager

// ============================================================================
// CONFIG MANAGER INITIALIZATION
// ============================================================================

// InitConfigManager initializes the configuration manager
func InitConfigManager(configPath string) error {
	defaults := DefaultConfig()

	ConfigMgr = &ConfigManager{
		config:     defaults,
		configPath: configPath,
		defaults:   defaults,
		callbacks:  []ConfigChangeCallback{},
	}

	// Load configuration
	if err := ConfigMgr.Load(); err != nil {
		LogWarn("CONFIG", "Failed to load config, using defaults: %v", err)
	}

	return nil
}

// ============================================================================
// LOADING AND SAVING
// ============================================================================

// Load loads configuration from file
func (cm *ConfigManager) Load() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	data, err := os.ReadFile(cm.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Create default config
			return cm.saveUnlocked()
		}
		return fmt.Errorf("read config: %w", err)
	}

	var config Config
	ext := strings.ToLower(filepath.Ext(cm.configPath))

	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("parse YAML: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("parse JSON: %w", err)
		}
	default:
		// Try YAML first, then JSON
		if err := yaml.Unmarshal(data, &config); err != nil {
			if err := json.Unmarshal(data, &config); err != nil {
				return fmt.Errorf("parse config: unknown format")
			}
		}
	}

	// Apply defaults for missing values
	cm.applyDefaults(&config)

	// Validate configuration
	if err := cm.validate(&config); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	cm.config = &config
	return nil
}

// Save saves configuration to file
func (cm *ConfigManager) Save() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return cm.saveUnlocked()
}

// saveUnlocked saves without lock (internal use)
func (cm *ConfigManager) saveUnlocked() error {
	// Ensure directory exists
	dir := filepath.Dir(cm.configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	var data []byte
	var err error
	ext := strings.ToLower(filepath.Ext(cm.configPath))

	switch ext {
	case ".json":
		data, err = json.MarshalIndent(cm.config, "", "  ")
	default:
		data, err = yaml.Marshal(cm.config)
	}

	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(cm.configPath, data, 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}

// Reload reloads configuration from file
func (cm *ConfigManager) Reload() error {
	old := cm.Get()
	if err := cm.Load(); err != nil {
		return err
	}

	new := cm.Get()

	// Notify callbacks
	for _, cb := range cm.callbacks {
		go cb(old, new)
	}

	return nil
}

// ============================================================================
// GETTERS AND SETTERS
// ============================================================================

// Get returns current configuration (copy)
func (cm *ConfigManager) Get() *Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Return deep copy
	data, _ := json.Marshal(cm.config)
	var copy Config
	json.Unmarshal(data, &copy)
	return &copy
}

// GetValue returns a config value by path (e.g., "server.port")
func (cm *ConfigManager) GetValue(path string) (interface{}, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	parts := strings.Split(path, ".")
	var current interface{} = cm.config

	for _, part := range parts {
		val := reflect.ValueOf(current)
		if val.Kind() == reflect.Ptr {
			val = val.Elem()
		}

		if val.Kind() != reflect.Struct {
			return nil, fmt.Errorf("invalid path: %s", path)
		}

		field := val.FieldByNameFunc(func(name string) bool {
			return strings.EqualFold(name, part)
		})

		if !field.IsValid() {
			return nil, fmt.Errorf("field not found: %s", part)
		}

		current = field.Interface()
	}

	return current, nil
}

// SetValue sets a config value by path
func (cm *ConfigManager) SetValue(path string, value interface{}) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	parts := strings.Split(path, ".")
	var current reflect.Value = reflect.ValueOf(cm.config)

	for i, part := range parts {
		if current.Kind() == reflect.Ptr {
			current = current.Elem()
		}

		if current.Kind() != reflect.Struct {
			return fmt.Errorf("invalid path: %s", path)
		}

		field := current.FieldByNameFunc(func(name string) bool {
			return strings.EqualFold(name, part)
		})

		if !field.IsValid() {
			return fmt.Errorf("field not found: %s", part)
		}

		if i == len(parts)-1 {
			// Set value
			if !field.CanSet() {
				return fmt.Errorf("cannot set field: %s", part)
			}

			newVal := reflect.ValueOf(value)
			if newVal.Type().ConvertibleTo(field.Type()) {
				field.Set(newVal.Convert(field.Type()))
			} else {
				return fmt.Errorf("type mismatch for %s", part)
			}
		} else {
			current = field
		}
	}

	return cm.saveUnlocked()
}

// ============================================================================
// VALIDATION
// ============================================================================

// validate validates configuration
func (cm *ConfigManager) validate(config *Config) error {
	var errs []string

	// Server validation
	if config.Server.Port < 1 || config.Server.Port > 65535 {
		errs = append(errs, "server.port must be between 1 and 65535")
	}

	// Security validation
	if config.Security.JWTSecret == "" {
		errs = append(errs, "security.jwt_secret is required")
	}
	if len(config.Security.JWTSecret) < 32 {
		errs = append(errs, "security.jwt_secret should be at least 32 characters")
	}

	// Admin validation
	if config.Admin.Username == "" {
		errs = append(errs, "admin.username is required")
	}
	if config.Admin.Password == "" {
		errs = append(errs, "admin.password is required")
	}

	// Panel validation
	if config.Panel.LoginPath == "" {
		config.Panel.LoginPath = "/admin"
	}
	if !strings.HasPrefix(config.Panel.LoginPath, "/") {
		config.Panel.LoginPath = "/" + config.Panel.LoginPath
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}

// ValidateConfig validates given configuration
func ValidateConfig(config *Config) error {
	if ConfigMgr == nil {
		return errors.New("config manager not initialized")
	}
	return ConfigMgr.validate(config)
}

// ============================================================================
// DEFAULTS
// ============================================================================

// applyDefaults applies default values to missing config fields
func (cm *ConfigManager) applyDefaults(config *Config) {
	defaults := cm.defaults

	// Server defaults
	if config.Server.Port == 0 {
		config.Server.Port = defaults.Server.Port
	}
	if config.Server.ReadTimeout == 0 {
		config.Server.ReadTimeout = defaults.Server.ReadTimeout
	}
	if config.Server.WriteTimeout == 0 {
		config.Server.WriteTimeout = defaults.Server.WriteTimeout
	}

	// Database defaults
	if config.Database.Type == "" {
		config.Database.Type = defaults.Database.Type
	}
	if config.Database.Path == "" {
		config.Database.Path = defaults.Database.Path
	}

	// Security defaults
	if config.Security.JWTExpiry == 0 {
		config.Security.JWTExpiry = defaults.Security.JWTExpiry
	}
	if config.Security.MaxLoginAttempts == 0 {
		config.Security.MaxLoginAttempts = defaults.Security.MaxLoginAttempts
	}

	// Panel defaults
	if config.Panel.LoginPath == "" {
		config.Panel.LoginPath = defaults.Panel.LoginPath
	}
	if config.Panel.Language == "" {
		config.Panel.Language = defaults.Panel.Language
	}
	if config.Panel.Theme == "" {
		config.Panel.Theme = defaults.Panel.Theme
	}

	// Logging defaults
	if config.Logging.Level == "" {
		config.Logging.Level = defaults.Logging.Level
	}
	if config.Logging.Path == "" {
		config.Logging.Path = defaults.Logging.Path
	}
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		Server: HTTPServerConfig{
			Host:           "0.0.0.0",
			Port:           8080,
			TLSPort:        443,
			SinglePort:     false,
			SinglePortNum:  443,
			ReadTimeout:    30,
			WriteTimeout:   30,
			MaxHeaderBytes: 1 << 20, // 1MB
		},
		Database: DatabaseConfig{
			Type:            "sqlite",
			Path:            "/opt/mxui/data/mxui.db",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 300,
		},
		Security: SecurityConfig{
			JWTSecret:            generateRandomString(64),
			JWTExpiry:            24,
			MaxLoginAttempts:     5,
			LoginLockoutDuration: 15 * time.Minute,
			RateLimitEnabled:     true,
			RateLimitRequests:    100,
			RateLimitWindow:      60,
			BruteForceEnabled:    true,
			BruteForceAttempts:   5,
			BruteForceWindow:     300,
			BruteForceBanTime:    900,
		},
		Admin: AdminConfig{
			Username: "admin",
			Password: generateRandomString(16),
		},
		Panel: PanelConfig{
			LoginPath:      "/admin",
			DecoyEnabled:   true,
			DecoyType:      "nginx",
			Language:       "fa",
			Theme:          "dark",
			Title:          "MX-UI Panel",
			SessionTimeout: 3600,
		},
		Nodes: NodesConfig{
			Enabled:             true,
			SyncInterval:        60,
			HealthCheckInterval: 30,
			LoadBalanceStrategy: "round-robin",
			FailoverEnabled:     true,
			FailoverThreshold:   3,
		},
		Protocols: ProtocolsConfig{
			XrayEnabled:    true,
			XrayPath:       "/opt/mxui/xray/xray",
			XrayConfigPath: "/opt/mxui/xray/config.json",
			XrayAPIPort:    10085,
			SingboxEnabled: false,
		},
		Telegram: TelegramConfig{
			Enabled:          false,
			NotifyOnLogin:    true,
			NotifyOnPurchase: true,
			NotifyOnExpiry:   true,
		},
		Backup: BackupConfig{
			Enabled:       true,
			LocalEnabled:  true,
			LocalPath:     "/opt/mxui/backups",
			BackupPath:    "/opt/mxui/backups",
			MaxBackups:    7,
			RetentionDays: 30,
		},
		Logging: LoggingConfig{
			Level:      "info",
			Path:       "/opt/mxui/logs/mxui.log",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     30,
			Compress:   true,
			Console:    true,
		},
		API: APIConfig{
			Enabled:   true,
			Prefix:    "/api",
			Version:   "v1",
			RateLimit: 100,
		},
	}
}

// ============================================================================
// CONFIG WATCHER
// ============================================================================

// StartWatcher starts watching config file for changes
func (cm *ConfigManager) StartWatcher(interval time.Duration) error {
	if cm.watcher != nil {
		return errors.New("watcher already running")
	}

	info, err := os.Stat(cm.configPath)
	if err != nil {
		return err
	}

	cm.watcher = &ConfigWatcher{
		path:     cm.configPath,
		interval: interval,
		lastMod:  info.ModTime(),
		stopCh:   make(chan struct{}),
		onChange: func() {
			if err := cm.Reload(); err != nil {
				LogError("CONFIG", "Failed to reload config: %v", err)
			} else {
				LogInfo("CONFIG", "Configuration reloaded")
			}
		},
	}

	go cm.watcher.watch()
	return nil
}

// StopWatcher stops the config watcher
func (cm *ConfigManager) StopWatcher() {
	if cm.watcher != nil {
		close(cm.watcher.stopCh)
		cm.watcher = nil
	}
}

// watch watches for file changes
func (w *ConfigWatcher) watch() {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			info, err := os.Stat(w.path)
			if err != nil {
				continue
			}

			if info.ModTime().After(w.lastMod) {
				w.lastMod = info.ModTime()
				w.onChange()
			}
		}
	}
}

// ============================================================================
// CHANGE CALLBACKS
// ============================================================================

// OnChange registers a callback for config changes
func (cm *ConfigManager) OnChange(callback ConfigChangeCallback) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.callbacks = append(cm.callbacks, callback)
}

// ============================================================================
// ENVIRONMENT OVERRIDE
// ============================================================================

// ApplyEnvOverrides applies environment variable overrides
func (cm *ConfigManager) ApplyEnvOverrides() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Server overrides
	if v := os.Getenv("MRX_SERVER_HOST"); v != "" {
		cm.config.Server.Host = v
	}
	if v := os.Getenv("MRX_SERVER_PORT"); v != "" {
		fmt.Sscanf(v, "%d", &cm.config.Server.Port)
	}
	if v := os.Getenv("MRX_SERVER_DOMAIN"); v != "" {
		cm.config.Server.Domain = v
	}

	// Database overrides
	if v := os.Getenv("MRX_DB_TYPE"); v != "" {
		cm.config.Database.Type = v
	}
	if v := os.Getenv("MRX_DB_PATH"); v != "" {
		cm.config.Database.Path = v
	}
	if v := os.Getenv("MRX_DB_HOST"); v != "" {
		cm.config.Database.Host = v
	}

	// Security overrides
	if v := os.Getenv("MRX_JWT_SECRET"); v != "" {
		cm.config.Security.JWTSecret = v
	}

	// Admin overrides
	if v := os.Getenv("MRX_ADMIN_USER"); v != "" {
		cm.config.Admin.Username = v
	}
	if v := os.Getenv("MRX_ADMIN_PASS"); v != "" {
		cm.config.Admin.Password = v
	}

	// Panel overrides
	if v := os.Getenv("MRX_PANEL_PATH"); v != "" {
		cm.config.Panel.LoginPath = v
	}

	// Telegram overrides
	if v := os.Getenv("MRX_TG_TOKEN"); v != "" {
		cm.config.Telegram.BotToken = v
		cm.config.Telegram.Enabled = true
	}
}

// ============================================================================
// EXPORT / IMPORT
// ============================================================================

// ExportConfig exports configuration to JSON
func (cm *ConfigManager) ExportConfig() ([]byte, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Mask sensitive fields
	export := cm.Get()
	export.Security.JWTSecret = "***"
	export.Security.APIKey = "***"
	export.Admin.Password = "***"
	export.Database.Password = "***"
	export.Database.EncryptionKey = "***"
	export.Telegram.BotToken = "***"

	return json.MarshalIndent(export, "", "  ")
}

// ImportConfig imports configuration from JSON
func (cm *ConfigManager) ImportConfig(data []byte) error {
	var newConfig Config
	if err := json.Unmarshal(data, &newConfig); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Preserve sensitive fields from current config
	if newConfig.Security.JWTSecret == "***" || newConfig.Security.JWTSecret == "" {
		newConfig.Security.JWTSecret = cm.config.Security.JWTSecret
	}
	if newConfig.Admin.Password == "***" || newConfig.Admin.Password == "" {
		newConfig.Admin.Password = cm.config.Admin.Password
	}
	if newConfig.Database.Password == "***" {
		newConfig.Database.Password = cm.config.Database.Password
	}
	if newConfig.Telegram.BotToken == "***" {
		newConfig.Telegram.BotToken = cm.config.Telegram.BotToken
	}

	// Validate
	if err := cm.validate(&newConfig); err != nil {
		return err
	}

	cm.config = &newConfig
	return cm.saveUnlocked()
}
