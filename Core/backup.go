// backup.go - MXUI Backup System
// Telegram, Google Drive, S3, Scheduler, Split Large Files

package core

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Constants & Configuration
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

const (
	// Backup Types
	BackupTypeFull        = "full"
	BackupTypeDatabase    = "database"
	BackupTypeConfig      = "config"
	BackupTypeLogs        = "logs"
	BackupTypeIncremental = "incremental"

	// Backup Destinations
	BackupDestLocal    = "local"
	BackupDestTelegram = "telegram"
	BackupDestGDrive   = "gdrive"
	BackupDestS3       = "s3"
	BackupDestWebDAV   = "webdav"

	// Schedule Types
	ScheduleHourly  = "hourly"
	ScheduleDaily   = "daily"
	ScheduleWeekly  = "weekly"
	ScheduleMonthly = "monthly"
	ScheduleCustom  = "custom"

	// Telegram file size limit (50MB for bots, we use 45MB for safety)
	TelegramMaxFileSize = 45 * 1024 * 1024
	// Split chunk size
	SplitChunkSize = 40 * 1024 * 1024

	// Backup retention defaults
	DefaultRetentionDays   = 30
	DefaultMaxBackups      = 50
	DefaultMaxBackupSizeMB = 5000

	// Backup directory
	BackupDirectory = "Data/backups"
	TempDirectory   = "Data/temp"

	// Single file backup
	BackupFileName = "mxui_backup_%s.zip"
	BackupVersion  = "1.0"
)

// ============================================================================
// Structures
// ============================================================================

// BackupManager manages all backup operations
type BackupManager struct {
	mu sync.RWMutex

	// Configuration
	Config *BackupConfig

	// Scheduler
	scheduler     *BackupScheduler
	schedulerStop chan struct{}

	// Status
	isRunning     bool
	lastBackup    *BackupInfo
	currentBackup *BackupProgress

	// Dependencies
	db       *DatabaseManager
	bot      *TelegramBot
	security *SecurityManager

	// Cloud clients
	gdriveClient *GDriveClient
	s3Client     *S3Client
	webdavClient *WebDAVClient

	// Hooks
	onBackupComplete  func(*BackupInfo)
	onBackupFailed    func(error)
	onRestoreComplete func(*RestoreInfo)
}

// BackupService is a simple backup service wrapper
type BackupService struct {
	manager *BackupManager
}

func (bs *BackupService) CreateSimpleBackup() (string, error) {
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("mxui_backup_%s.zip", timestamp)

	// Create zip with: database, config, certs
	files := []string{
		DB.dbPath,
		"/opt/mxui/config.yaml",
		"/opt/mxui/data/certs/",
	}
	return bs.createZipBackup(filename, files)
}

func (bs *BackupService) createZipBackup(filename string, files []string) (string, error) {
	// Ensure backup directory exists
	backupDir := filepath.Dir(filename)
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Create the tar.gz file
	outFile, err := os.Create(filename)
	if err != nil {
		return "", fmt.Errorf("failed to create backup file: %w", err)
	}
	defer outFile.Close()

	gzWriter := gzip.NewWriter(outFile)
	defer gzWriter.Close()

	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	// Add each file/directory to archive
	for _, sourcePath := range files {
		// Check if file exists
		info, err := os.Stat(sourcePath)
		if err != nil {
			if os.IsNotExist(err) {
				LogWarn("BACKUP", "Skipping non-existent file: %s", sourcePath)
				continue
			}
			return "", fmt.Errorf("failed to stat %s: %w", sourcePath, err)
		}

		// Calculate archive path (strip leading paths)
		archivePath := filepath.Base(sourcePath)

		// Add to archive
		if info.IsDir() {
			err = filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				// Calculate relative path within archive
				relPath, err := filepath.Rel(sourcePath, path)
				if err != nil {
					return err
				}
				arcPath := filepath.Join(archivePath, relPath)

				// Create header
				header, err := tar.FileInfoHeader(info, "")
				if err != nil {
					return err
				}
				header.Name = arcPath

				// Write header
				if err := tarWriter.WriteHeader(header); err != nil {
					return err
				}

				// If directory, we're done
				if info.IsDir() {
					return nil
				}

				// Copy file contents
				file, err := os.Open(path)
				if err != nil {
					return err
				}
				defer file.Close()

				_, err = io.Copy(tarWriter, file)
				return err
			})
		} else {
			// Single file
			header, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return "", err
			}
			header.Name = archivePath

			if err := tarWriter.WriteHeader(header); err != nil {
				return "", err
			}

			file, err := os.Open(sourcePath)
			if err != nil {
				return "", err
			}
			defer file.Close()

			if _, err := io.Copy(tarWriter, file); err != nil {
				return "", err
			}
		}

		if err != nil {
			return "", fmt.Errorf("failed to add %s to archive: %w", sourcePath, err)
		}
	}

	LogInfo("BACKUP", "Created backup: %s", filename)
	return filename, nil
}

func (bs *BackupService) RestoreSimpleBackup(zipPath string) error {
	return bs.extractAndRestore(zipPath)
}

func (bs *BackupService) extractAndRestore(zipPath string) error {
	// Verify backup file exists
	if _, err := os.Stat(zipPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file not found: %s", zipPath)
	}

	// Open backup file
	file, err := os.Open(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer file.Close()

	// Create gzip reader
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Create tar reader
	tarReader := tar.NewReader(gzReader)

	// Extract each file
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Determine target path based on file type
		var targetPath string
		if strings.HasPrefix(header.Name, "database.db") {
			targetPath = filepath.Join("/opt/mxui/data", header.Name)
		} else if strings.HasPrefix(header.Name, "config.yaml") {
			targetPath = "/opt/mxui/config.yaml"
		} else if strings.HasPrefix(header.Name, "certs") {
			targetPath = filepath.Join("/opt/mxui/data", header.Name)
		} else {
			// Unknown file, place in data directory
			targetPath = filepath.Join("/opt/mxui/data", header.Name)
		}

		// Sanitize path
		targetPath = filepath.Clean(targetPath)
		if !strings.HasPrefix(targetPath, "/opt/mxui") {
			return fmt.Errorf("invalid path in archive: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", targetPath, err)
			}

		case tar.TypeReg:
			// Create parent directories
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory: %w", err)
			}

			// Create file
			outFile, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", targetPath, err)
			}

			// Copy contents
			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("failed to write file %s: %w", targetPath, err)
			}
			outFile.Close()

			// Set permissions
			if err := os.Chmod(targetPath, os.FileMode(header.Mode)); err != nil {
				LogWarn("BACKUP", "Failed to set permissions for %s: %v", targetPath, err)
			}

			LogInfo("BACKUP", "Restored: %s", targetPath)
		}
	}

	LogInfo("BACKUP", "Successfully restored from: %s", zipPath)
	return nil
}

// BackupConfig holds backup configuration
type BackupConfig struct {
	// General
	Enabled           bool   `json:"enabled"`
	EncryptionEnabled bool   `json:"encryption_enabled"`
	EncryptionKey     string `json:"encryption_key"`
	CompressionLevel  int    `json:"compression_level"` // 1-9
	BackupPath        string `json:"backup_path"`

	// Local
	LocalEnabled   bool   `json:"local_enabled"`
	LocalPath      string `json:"local_path"`
	RetentionDays  int    `json:"retention_days"`
	MaxBackups     int    `json:"max_backups"`
	MaxTotalSizeMB int    `json:"max_total_size_mb"`

	// Telegram
	TelegramEnabled  bool   `json:"telegram_enabled"`
	TelegramChatID   int64  `json:"telegram_chat_id"`
	TelegramBotToken string `json:"telegram_bot_token"`
	SplitLargeFiles  bool   `json:"split_large_files"`

	// Google Drive
	GDriveEnabled      bool   `json:"gdrive_enabled"`
	GDriveCredentials  string `json:"gdrive_credentials"`
	GDriveFolderID     string `json:"gdrive_folder_id"`
	GDriveRefreshToken string `json:"gdrive_refresh_token"`

	// AWS S3
	S3Enabled    bool   `json:"s3_enabled"`
	S3Endpoint   string `json:"s3_endpoint"`
	S3Region     string `json:"s3_region"`
	S3Bucket     string `json:"s3_bucket"`
	S3AccessKey  string `json:"s3_access_key"`
	S3SecretKey  string `json:"s3_secret_key"`
	S3PathPrefix string `json:"s3_path_prefix"`

	// WebDAV
	WebDAVEnabled  bool   `json:"webdav_enabled"`
	WebDAVURL      string `json:"webdav_url"`
	WebDAVUsername string `json:"webdav_username"`
	WebDAVPassword string `json:"webdav_password"`
	WebDAVPath     string `json:"webdav_path"`

	// Schedule
	ScheduleEnabled bool              `json:"schedule_enabled"`
	Schedules       []*BackupSchedule `json:"schedules"`

	// What to backup
	IncludeDatabase bool     `json:"include_database"`
	IncludeConfigs  bool     `json:"include_configs"`
	IncludeLogs     bool     `json:"include_logs"`
	IncludeCerts    bool     `json:"include_certs"`
	ExcludePaths    []string `json:"exclude_paths"`
	IncludePaths    []string `json:"include_paths"`

	// Notifications
	NotifyOnSuccess  bool  `json:"notify_on_success"`
	NotifyOnFailure  bool  `json:"notify_on_failure"`
	NotificationChat int64 `json:"notification_chat"`

	// Auto-cleanup
	AutoCleanupEnabled bool `json:"auto_cleanup_enabled"`
	CleanupOnLowDisk   bool `json:"cleanup_on_low_disk"`
	MinFreeDiskGB      int  `json:"min_free_disk_gb"`
}

// BackupSchedule defines a backup schedule
type BackupSchedule struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Type         string   `json:"type"`         // hourly, daily, weekly, monthly, custom
	Hour         int      `json:"hour"`         // 0-23
	Minute       int      `json:"minute"`       // 0-59
	DayOfWeek    int      `json:"day_of_week"`  // 0-6 (Sunday = 0)
	DayOfMonth   int      `json:"day_of_month"` // 1-31
	CronExpr     string   `json:"cron_expr"`    // For custom
	BackupType   string   `json:"backup_type"`  // full, database, config
	Destinations []string `json:"destinations"`
	Enabled      bool     `json:"enabled"`
	LastRun      int64    `json:"last_run"`
	NextRun      int64    `json:"next_run"`
}

// BackupInfo contains information about a backup
type BackupInfo struct {
	ID             string            `json:"id"`
	Type           string            `json:"type"`
	Filename       string            `json:"filename"`
	OriginalSize   int64             `json:"original_size"`
	CompressedSize int64             `json:"compressed_size"`
	Encrypted      bool              `json:"encrypted"`
	Checksum       string            `json:"checksum"`
	CreatedAt      int64             `json:"created_at"`
	CreatedBy      string            `json:"created_by"`
	Destinations   []string          `json:"destinations"`
	UploadResults  map[string]string `json:"upload_results"`
	Metadata       *BackupMetadata   `json:"metadata"`
	Parts          []*BackupPart     `json:"parts,omitempty"`
	Status         string            `json:"status"`
	Error          string            `json:"error,omitempty"`
}

// BackupMetadata contains metadata about backup contents
type BackupMetadata struct {
	Version       string   `json:"version"`
	ServerID      string   `json:"server_id"`
	Hostname      string   `json:"hostname"`
	IPAddress     string   `json:"ip_address"`
	TotalUsers    int      `json:"total_users"`
	TotalAdmins   int      `json:"total_admins"`
	TotalNodes    int      `json:"total_nodes"`
	DatabaseSize  int64    `json:"database_size"`
	ConfigHash    string   `json:"config_hash"`
	IncludedFiles []string `json:"included_files"`
}

// BackupPart represents a split backup part
type BackupPart struct {
	Index      int    `json:"index"`
	Filename   string `json:"filename"`
	Size       int64  `json:"size"`
	Checksum   string `json:"checksum"`
	UploadedTo string `json:"uploaded_to"`
	MessageID  int    `json:"message_id,omitempty"` // Telegram message ID
}

// BackupProgress tracks current backup progress
type BackupProgress struct {
	ID             string  `json:"id"`
	Phase          string  `json:"phase"`
	Progress       float64 `json:"progress"`
	CurrentFile    string  `json:"current_file"`
	BytesWritten   int64   `json:"bytes_written"`
	TotalBytes     int64   `json:"total_bytes"`
	FilesProcessed int     `json:"files_processed"`
	TotalFiles     int     `json:"total_files"`
	StartedAt      int64   `json:"started_at"`
	EstimatedETA   int64   `json:"estimated_eta"`
}

// RestoreInfo contains information about a restore operation
type RestoreInfo struct {
	ID            string `json:"id"`
	BackupID      string `json:"backup_id"`
	Source        string `json:"source"`
	StartedAt     int64  `json:"started_at"`
	CompletedAt   int64  `json:"completed_at"`
	Status        string `json:"status"`
	RestoredFiles int    `json:"restored_files"`
	Error         string `json:"error,omitempty"`
}

// BackupScheduler handles scheduled backups
type BackupScheduler struct {
	mu        sync.Mutex
	manager   *BackupManager
	schedules map[string]*BackupSchedule
	timers    map[string]*time.Timer
	running   bool
	stopChan  chan struct{}
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Google Drive Client
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// GDriveClient handles Google Drive operations
type GDriveClient struct {
	config      *oauth2.Config
	token       *oauth2.Token
	httpClient  *http.Client
	folderID    string
	initialized bool
}

// GDriveFile represents a file in Google Drive
type GDriveFile struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Size     int64  `json:"size,string"`
	MimeType string `json:"mimeType"`
	Created  string `json:"createdTime"`
}

// GDriveFileList response from Google Drive API
type GDriveFileList struct {
	Files         []*GDriveFile `json:"files"`
	NextPageToken string        `json:"nextPageToken"`
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// AWS S3 Client
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// S3Client handles S3 operations
type S3Client struct {
	endpoint   string
	region     string
	bucket     string
	accessKey  string
	secretKey  string
	pathPrefix string
	httpClient *http.Client
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// WebDAV Client
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// WebDAVClient handles WebDAV operations
type WebDAVClient struct {
	baseURL    string
	username   string
	password   string
	path       string
	httpClient *http.Client
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Backup Manager Implementation
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// NewBackupManager creates a new backup manager
func NewBackupManager(db *DatabaseManager, bot *TelegramBot, security *SecurityManager) *BackupManager {
	bm := &BackupManager{
		db:            db,
		bot:           bot,
		security:      security,
		schedulerStop: make(chan struct{}),
	}

	// Load configuration
	bm.loadConfig()

	// Ensure directories exist
	bm.ensureDirectories()

	// Initialize cloud clients
	bm.initCloudClients()

	return bm
}

// loadConfig loads backup configuration from database
func (bm *BackupManager) loadConfig() {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	configJSON, err := bm.db.GetSetting("backup_config")
	if err != nil || configJSON == "" {
		// Default configuration
		bm.Config = &BackupConfig{
			Enabled:            true,
			EncryptionEnabled:  true,
			CompressionLevel:   6,
			LocalEnabled:       true,
			LocalPath:          BackupDirectory,
			RetentionDays:      DefaultRetentionDays,
			MaxBackups:         DefaultMaxBackups,
			MaxTotalSizeMB:     DefaultMaxBackupSizeMB,
			SplitLargeFiles:    true,
			IncludeDatabase:    true,
			IncludeConfigs:     true,
			IncludeLogs:        false,
			IncludeCerts:       true,
			AutoCleanupEnabled: true,
			CleanupOnLowDisk:   true,
			MinFreeDiskGB:      5,
			NotifyOnSuccess:    true,
			NotifyOnFailure:    true,
			Schedules:          make([]*BackupSchedule, 0),
		}

		// Generate encryption key if not exists
		if bm.Config.EncryptionKey == "" {
			key := make([]byte, 32)
			rand.Read(key)
			bm.Config.EncryptionKey = base64.StdEncoding.EncodeToString(key)
		}

		bm.SaveConfig()
		return
	}

	var config BackupConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		LogError("BACKUP", "Failed to parse config: %v", err)
		return
	}
	bm.Config = &config
}

// SaveConfig saves backup configuration
func (bm *BackupManager) SaveConfig() error {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	configJSON, err := json.Marshal(bm.Config)
	if err != nil {
		return err
	}

	return bm.db.SetSetting("backup_config", string(configJSON), "json", "backup", false)
}

// ensureDirectories creates necessary directories
func (bm *BackupManager) ensureDirectories() {
	dirs := []string{
		BackupDirectory,
		TempDirectory,
		filepath.Join(BackupDirectory, "local"),
		filepath.Join(BackupDirectory, "temp"),
	}

	for _, dir := range dirs {
		os.MkdirAll(dir, 0755)
	}
}

// initCloudClients initializes cloud storage clients
func (bm *BackupManager) initCloudClients() {
	// Google Drive
	if bm.Config.GDriveEnabled && bm.Config.GDriveCredentials != "" {
		bm.gdriveClient = bm.initGDriveClient()
	}

	// S3
	if bm.Config.S3Enabled && bm.Config.S3AccessKey != "" {
		bm.s3Client = bm.initS3Client()
	}

	// WebDAV
	if bm.Config.WebDAVEnabled && bm.Config.WebDAVURL != "" {
		bm.webdavClient = bm.initWebDAVClient()
	}
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Backup Creation
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// CreateBackup creates a new backup
func (bm *BackupManager) CreateBackup(backupType string, destinations []string, createdBy string) (*BackupInfo, error) {
	bm.mu.Lock()
	if bm.isRunning {
		bm.mu.Unlock()
		return nil, fmt.Errorf("backup already in progress")
	}
	bm.isRunning = true
	bm.mu.Unlock()

	defer func() {
		bm.mu.Lock()
		bm.isRunning = false
		bm.currentBackup = nil
		bm.mu.Unlock()
	}()

	// Initialize backup info
	backupID := GenerateID("BKP")
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("mxui_backup_%s_%s.tar.gz", backupType, timestamp)

	if bm.Config.EncryptionEnabled {
		filename += ".enc"
	}

	info := &BackupInfo{
		ID:            backupID,
		Type:          backupType,
		Filename:      filename,
		Encrypted:     bm.Config.EncryptionEnabled,
		CreatedAt:     time.Now().Unix(),
		CreatedBy:     createdBy,
		Destinations:  destinations,
		UploadResults: make(map[string]string),
		Status:        "creating",
	}

	// Initialize progress tracking
	bm.mu.Lock()
	bm.currentBackup = &BackupProgress{
		ID:        backupID,
		Phase:     "collecting",
		StartedAt: time.Now().Unix(),
	}
	bm.mu.Unlock()

	// Collect files to backup
	files, err := bm.collectBackupFiles(backupType)
	if err != nil {
		info.Status = "failed"
		info.Error = err.Error()
		bm.handleBackupFailed(info, err)
		return info, err
	}

	// Create archive
	bm.updateProgress("archiving", 0.1)
	archivePath, originalSize, err := bm.createArchive(backupID, files)
	if err != nil {
		info.Status = "failed"
		info.Error = err.Error()
		bm.handleBackupFailed(info, err)
		return info, err
	}
	info.OriginalSize = originalSize

	// Compress
	bm.updateProgress("compressing", 0.3)
	compressedPath, compressedSize, err := bm.compressArchive(archivePath)
	if err != nil {
		os.Remove(archivePath)
		info.Status = "failed"
		info.Error = err.Error()
		bm.handleBackupFailed(info, err)
		return info, err
	}
	os.Remove(archivePath)
	info.CompressedSize = compressedSize

	// Encrypt if enabled
	var finalPath string
	if bm.Config.EncryptionEnabled {
		bm.updateProgress("encrypting", 0.5)
		finalPath, err = bm.encryptFile(compressedPath)
		if err != nil {
			os.Remove(compressedPath)
			info.Status = "failed"
			info.Error = err.Error()
			bm.handleBackupFailed(info, err)
			return info, err
		}
		os.Remove(compressedPath)
	} else {
		finalPath = compressedPath
	}

	// Calculate checksum
	checksum, err := bm.calculateChecksum(finalPath)
	if err != nil {
		os.Remove(finalPath)
		info.Status = "failed"
		info.Error = err.Error()
		bm.handleBackupFailed(info, err)
		return info, err
	}
	info.Checksum = checksum

	// Collect metadata
	info.Metadata = bm.collectMetadata(files)

	// Get final file size
	fileInfo, _ := os.Stat(finalPath)
	info.CompressedSize = fileInfo.Size()

	// Upload to destinations
	bm.updateProgress("uploading", 0.6)
	for i, dest := range destinations {
		progress := 0.6 + (0.35 * float64(i) / float64(len(destinations)))
		bm.updateProgress(fmt.Sprintf("uploading_%s", dest), progress)

		switch dest {
		case BackupDestLocal:
			err = bm.saveLocal(finalPath, info)
		case BackupDestTelegram:
			err = bm.uploadToTelegram(finalPath, info)
		case BackupDestGDrive:
			err = bm.uploadToGDrive(finalPath, info)
		case BackupDestS3:
			err = bm.uploadToS3(finalPath, info)
		case BackupDestWebDAV:
			err = bm.uploadToWebDAV(finalPath, info)
		}

		if err != nil {
			info.UploadResults[dest] = fmt.Sprintf("error: %s", err.Error())
			LogError("BACKUP", "Upload to %s failed: %v", dest, err)
		} else {
			info.UploadResults[dest] = "success"
		}
	}

	// Cleanup temp file if not saving locally
	if !containsString(destinations, BackupDestLocal) {
		os.Remove(finalPath)
	}

	// Update status
	info.Status = "completed"
	bm.updateProgress("completed", 1.0)

	// Save backup info to database
	bm.saveBackupInfo(info)

	// Update last backup
	bm.mu.Lock()
	bm.lastBackup = info
	bm.mu.Unlock()

	// Notify
	bm.handleBackupComplete(info)

	// Cleanup old backups
	if bm.Config.AutoCleanupEnabled {
		go bm.CleanupOldBackups()
	}

	LogInfo("BACKUP", "Backup completed: %s (%s)", info.ID, FormatBytes(info.CompressedSize))
	return info, nil
}

// collectBackupFiles collects files to be backed up
func (bm *BackupManager) collectBackupFiles(backupType string) ([]string, error) {
	var files []string

	switch backupType {
	case BackupTypeFull:
		if bm.Config.IncludeDatabase {
			files = append(files, "Data/mxui.db")
		}
		if bm.Config.IncludeConfigs {
			files = append(files, "config.yaml", ".env")
		}
		if bm.Config.IncludeCerts {
			files = append(files, "Data/certs/")
		}
		if bm.Config.IncludeLogs {
			files = append(files, "Data/logs/")
		}
		// Add custom paths
		files = append(files, bm.Config.IncludePaths...)

	case BackupTypeDatabase:
		files = append(files, "Data/mxui.db")

	case BackupTypeConfig:
		files = append(files, "config.yaml", ".env")
		if bm.Config.IncludeCerts {
			files = append(files, "Data/certs/")
		}

	case BackupTypeLogs:
		files = append(files, "Data/logs/")
	}

	// Filter out excluded paths
	filteredFiles := make([]string, 0)
	for _, file := range files {
		excluded := false
		for _, excludePath := range bm.Config.ExcludePaths {
			if strings.HasPrefix(file, excludePath) {
				excluded = true
				break
			}
		}
		if !excluded {
			if _, err := os.Stat(file); err == nil {
				filteredFiles = append(filteredFiles, file)
			}
		}
	}

	if len(filteredFiles) == 0 {
		return nil, fmt.Errorf("no files to backup")
	}

	return filteredFiles, nil
}

// createArchive creates a tar archive
func (bm *BackupManager) createArchive(backupID string, files []string) (string, int64, error) {
	archivePath := filepath.Join(TempDirectory, backupID+".tar")

	file, err := os.Create(archivePath)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	tw := tar.NewWriter(file)
	defer tw.Close()

	var totalSize int64

	for _, filePath := range files {
		err := filepath.Walk(filePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Create header
			header, err := tar.FileInfoHeader(info, info.Name())
			if err != nil {
				return err
			}

			// Use relative path
			header.Name = path

			if err := tw.WriteHeader(header); err != nil {
				return err
			}

			// Write file content
			if !info.IsDir() {
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				defer f.Close()

				written, err := io.Copy(tw, f)
				if err != nil {
					return err
				}
				totalSize += written
			}

			return nil
		})

		if err != nil {
			return "", 0, err
		}
	}

	return archivePath, totalSize, nil
}

// compressArchive compresses archive with gzip
func (bm *BackupManager) compressArchive(archivePath string) (string, int64, error) {
	compressedPath := archivePath + ".gz"

	inputFile, err := os.Open(archivePath)
	if err != nil {
		return "", 0, err
	}
	defer inputFile.Close()

	outputFile, err := os.Create(compressedPath)
	if err != nil {
		return "", 0, err
	}
	defer outputFile.Close()

	gzipWriter, err := gzip.NewWriterLevel(outputFile, bm.Config.CompressionLevel)
	if err != nil {
		return "", 0, err
	}
	defer gzipWriter.Close()

	_, err = io.Copy(gzipWriter, inputFile)
	if err != nil {
		return "", 0, err
	}

	// Get compressed size
	gzipWriter.Close()
	outputFile.Close()

	fileInfo, err := os.Stat(compressedPath)
	if err != nil {
		return "", 0, err
	}

	return compressedPath, fileInfo.Size(), nil
}

// encryptFile encrypts a file using AES-GCM
func (bm *BackupManager) encryptFile(inputPath string) (string, error) {
	outputPath := inputPath + ".enc"

	// Decode encryption key
	key, err := base64.StdEncoding.DecodeString(bm.Config.EncryptionKey)
	if err != nil {
		return "", fmt.Errorf("invalid encryption key: %v", err)
	}

	// Read input file
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return "", err
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Write output
	err = os.WriteFile(outputPath, ciphertext, 0600)
	if err != nil {
		return "", err
	}

	return outputPath, nil
}

// decryptFile decrypts an encrypted file
func (bm *BackupManager) decryptFile(inputPath string) (string, error) {
	outputPath := strings.TrimSuffix(inputPath, ".enc")

	// Decode encryption key
	key, err := base64.StdEncoding.DecodeString(bm.Config.EncryptionKey)
	if err != nil {
		return "", fmt.Errorf("invalid encryption key: %v", err)
	}

	// Read encrypted file
	ciphertext, err := os.ReadFile(inputPath)
	if err != nil {
		return "", err
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	// Write output
	err = os.WriteFile(outputPath, plaintext, 0600)
	if err != nil {
		return "", err
	}

	return outputPath, nil
}

// calculateChecksum calculates SHA256 checksum
func (bm *BackupManager) calculateChecksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// collectMetadata collects backup metadata
func (bm *BackupManager) collectMetadata(files []string) *BackupMetadata {
	hostname, _ := os.Hostname()

	metadata := &BackupMetadata{
		Version:       VERSION,
		ServerID:      GetServerID(),
		Hostname:      hostname,
		IPAddress:     GetPublicIP(),
		IncludedFiles: files,
	}

	// Get counts from database
	if bm.db != nil {
		// TODO: implement proper count methods
		metadata.TotalUsers = 0
		metadata.TotalAdmins = 0
		metadata.TotalNodes = 0

		// Database size
		if dbInfo, err := os.Stat("Data/mxui.db"); err == nil {
			metadata.DatabaseSize = dbInfo.Size()
		}
	}

	// Config hash
	if configData, err := os.ReadFile("config.yaml"); err == nil {
		hash := sha256.Sum256(configData)
		metadata.ConfigHash = fmt.Sprintf("%x", hash[:8])
	}

	return metadata
}

// updateProgress updates backup progress
func (bm *BackupManager) updateProgress(phase string, progress float64) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if bm.currentBackup != nil {
		bm.currentBackup.Phase = phase
		bm.currentBackup.Progress = progress

		// Estimate ETA
		elapsed := time.Now().Unix() - bm.currentBackup.StartedAt
		if progress > 0 {
			totalEstimate := float64(elapsed) / progress
			bm.currentBackup.EstimatedETA = bm.currentBackup.StartedAt + int64(totalEstimate)
		}
	}
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Local Storage
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// saveLocal saves backup to local storage
func (bm *BackupManager) saveLocal(sourcePath string, info *BackupInfo) error {
	destPath := filepath.Join(bm.Config.LocalPath, "local", info.Filename)

	// Copy file
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()

	dest, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer dest.Close()

	_, err = io.Copy(dest, source)
	if err != nil {
		os.Remove(destPath)
		return err
	}

	LogInfo("BACKUP", "Saved to local: %s", destPath)
	return nil
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Telegram Upload
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// uploadToTelegram uploads backup to Telegram
func (bm *BackupManager) uploadToTelegram(filePath string, info *BackupInfo) error {
	if bm.Config.TelegramChatID == 0 || bm.Config.TelegramBotToken == "" {
		return fmt.Errorf("telegram not configured")
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return err
	}

	// Check if file needs to be split
	if fileInfo.Size() > TelegramMaxFileSize && bm.Config.SplitLargeFiles {
		return bm.uploadSplitToTelegram(filePath, info)
	}

	// Upload as single file
	return bm.uploadSingleToTelegram(filePath, info)
}

// uploadSingleToTelegram uploads a single file to Telegram
func (bm *BackupManager) uploadSingleToTelegram(filePath string, info *BackupInfo) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create caption
	caption := fmt.Sprintf(
		"ðŸ”„ MXUI Backup\n\n"+
			"ðŸ“¦ Type: %s\n"+
			"ðŸ“… Date: %s\n"+
			"ðŸ“Š Size: %s\n"+
			"ðŸ” Encrypted: %v\n"+
			"ðŸ”¢ Checksum: %s...\n"+
			"ðŸ‘¤ Created by: %s",
		info.Type,
		time.Unix(info.CreatedAt, 0).Format("2006-01-02 15:04:05"),
		FormatBytes(info.CompressedSize),
		info.Encrypted,
		info.Checksum[:16],
		info.CreatedBy,
	)

	// Create multipart form
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)

	// Add chat_id
	writer.WriteField("chat_id", fmt.Sprintf("%d", bm.Config.TelegramChatID))
	writer.WriteField("caption", caption)

	// Add file
	part, err := writer.CreateFormFile("document", info.Filename)
	if err != nil {
		return err
	}

	_, err = io.Copy(part, file)
	if err != nil {
		return err
	}

	writer.Close()

	// Send request
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", bm.Config.TelegramBotToken)
	req, err := http.NewRequest("POST", url, &buffer)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API error: %s", string(body))
	}

	LogInfo("BACKUP", "Uploaded to Telegram: %s", info.Filename)
	return nil
}

// uploadSplitToTelegram splits and uploads file to Telegram
func (bm *BackupManager) uploadSplitToTelegram(filePath string, info *BackupInfo) error {
	// Split file into chunks
	parts, err := bm.splitFile(filePath)
	if err != nil {
		return err
	}

	info.Parts = make([]*BackupPart, len(parts))

	// Send info message first
	infoMsg := fmt.Sprintf(
		"ðŸ“¦ MXUI Backup (Split)\n\n"+
			"ðŸ“‹ Type: %s\n"+
			"ðŸ“… Date: %s\n"+
			"ðŸ“Š Total Size: %s\n"+
			"ðŸ“ Parts: %d\n"+
			"ðŸ” Encrypted: %v\n"+
			"ðŸ”¢ Checksum: %s\n\n"+
			"â³ Uploading parts...",
		info.Type,
		time.Unix(info.CreatedAt, 0).Format("2006-01-02 15:04:05"),
		FormatBytes(info.CompressedSize),
		len(parts),
		info.Encrypted,
		info.Checksum,
	)

	bm.sendTelegramMessage(infoMsg)

	// Upload each part
	for i, partPath := range parts {
		partFile, err := os.Open(partPath)
		if err != nil {
			return err
		}

		partInfo, _ := os.Stat(partPath)
		partChecksum, _ := bm.calculateChecksum(partPath)

		part := &BackupPart{
			Index:      i + 1,
			Filename:   filepath.Base(partPath),
			Size:       partInfo.Size(),
			Checksum:   partChecksum,
			UploadedTo: BackupDestTelegram,
		}

		caption := fmt.Sprintf("ðŸ“¦ Part %d/%d - %s", i+1, len(parts), info.Filename)

		// Upload part
		err = bm.uploadFileToTelegram(partFile, part.Filename, caption)
		partFile.Close()

		if err != nil {
			return fmt.Errorf("failed to upload part %d: %v", i+1, err)
		}

		info.Parts[i] = part

		// Cleanup temp part file
		os.Remove(partPath)
	}

	// Send completion message
	completeMsg := fmt.Sprintf(
		"âœ… Backup uploaded successfully!\n\n"+
			"ðŸ“¦ %s\n"+
			"ðŸ“Š %d parts uploaded",
		info.Filename,
		len(parts),
	)
	bm.sendTelegramMessage(completeMsg)

	LogInfo("BACKUP", "Uploaded %d parts to Telegram", len(parts))
	return nil
}

// splitFile splits a file into chunks
func (bm *BackupManager) splitFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fileInfo, _ := file.Stat()
	numParts := int(fileInfo.Size()/SplitChunkSize) + 1

	var parts []string
	buffer := make([]byte, SplitChunkSize)

	for i := 0; i < numParts; i++ {
		partPath := fmt.Sprintf("%s.part%03d", filePath, i+1)

		partFile, err := os.Create(partPath)
		if err != nil {
			return nil, err
		}

		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			partFile.Close()
			return nil, err
		}

		if n > 0 {
			partFile.Write(buffer[:n])
			parts = append(parts, partPath)
		}

		partFile.Close()
	}

	return parts, nil
}

// uploadFileToTelegram uploads a file to Telegram
func (bm *BackupManager) uploadFileToTelegram(file io.Reader, filename, caption string) error {
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)

	writer.WriteField("chat_id", fmt.Sprintf("%d", bm.Config.TelegramChatID))
	writer.WriteField("caption", caption)

	part, err := writer.CreateFormFile("document", filename)
	if err != nil {
		return err
	}

	_, err = io.Copy(part, file)
	if err != nil {
		return err
	}

	writer.Close()

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", bm.Config.TelegramBotToken)
	req, err := http.NewRequest("POST", url, &buffer)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram error: %s", string(body))
	}

	return nil
}

// sendTelegramMessage sends a text message to Telegram
func (bm *BackupManager) sendTelegramMessage(text string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", bm.Config.TelegramBotToken)

	data := map[string]interface{}{
		"chat_id":    bm.Config.TelegramChatID,
		"text":       text,
		"parse_mode": "HTML",
	}

	jsonData, _ := json.Marshal(data)

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Google Drive Upload
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// initGDriveClient initializes Google Drive client
func (bm *BackupManager) initGDriveClient() *GDriveClient {
	client := &GDriveClient{
		folderID: bm.Config.GDriveFolderID,
	}

	// Parse credentials
	if bm.Config.GDriveCredentials == "" {
		return nil
	}

	var creds struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}

	if err := json.Unmarshal([]byte(bm.Config.GDriveCredentials), &creds); err != nil {
		LogError("BACKUP", "Invalid GDrive credentials: %v", err)
		return nil
	}

	client.config = &oauth2.Config{
		ClientID:     creds.ClientID,
		ClientSecret: creds.ClientSecret,
		Endpoint:     google.Endpoint,
		Scopes:       []string{"https://www.googleapis.com/auth/drive.file"},
		RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
	}

	// Set token if exists
	if bm.Config.GDriveRefreshToken != "" {
		client.token = &oauth2.Token{
			RefreshToken: bm.Config.GDriveRefreshToken,
		}
		client.httpClient = client.config.Client(context.Background(), client.token)
		client.initialized = true
	}

	return client
}

// uploadToGDrive uploads backup to Google Drive
func (bm *BackupManager) uploadToGDrive(filePath string, info *BackupInfo) error {
	if bm.gdriveClient == nil || !bm.gdriveClient.initialized {
		return fmt.Errorf("google drive not configured")
	}

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	fileInfo, _ := file.Stat()

	// Create metadata
	metadata := map[string]interface{}{
		"name":     info.Filename,
		"mimeType": "application/gzip",
	}

	if bm.gdriveClient.folderID != "" {
		metadata["parents"] = []string{bm.gdriveClient.folderID}
	}

	metadataJSON, _ := json.Marshal(metadata)

	// Create multipart request
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)

	// Metadata part
	metaPart, _ := writer.CreatePart(map[string][]string{
		"Content-Type": {"application/json; charset=UTF-8"},
	})
	metaPart.Write(metadataJSON)

	// File part
	filePart, _ := writer.CreatePart(map[string][]string{
		"Content-Type": {"application/gzip"},
	})
	io.Copy(filePart, file)

	writer.Close()

	// Upload
	url := "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart"
	req, err := http.NewRequest("POST", url, &buffer)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Content-Length", fmt.Sprintf("%d", buffer.Len()))

	resp, err := bm.gdriveClient.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gdrive error: %s", string(body))
	}

	LogInfo("BACKUP", "Uploaded to Google Drive: %s (%s)", info.Filename, FormatBytes(fileInfo.Size()))
	return nil
}

// GetGDriveAuthURL returns Google Drive authorization URL
func (bm *BackupManager) GetGDriveAuthURL() (string, error) {
	if bm.gdriveClient == nil || bm.gdriveClient.config == nil {
		return "", fmt.Errorf("google drive not configured")
	}

	return bm.gdriveClient.config.AuthCodeURL("state-token", oauth2.AccessTypeOffline), nil
}

// ExchangeGDriveCode exchanges authorization code for token
func (bm *BackupManager) ExchangeGDriveCode(code string) error {
	if bm.gdriveClient == nil || bm.gdriveClient.config == nil {
		return fmt.Errorf("google drive not configured")
	}

	token, err := bm.gdriveClient.config.Exchange(context.Background(), code)
	if err != nil {
		return err
	}

	bm.gdriveClient.token = token
	bm.gdriveClient.httpClient = bm.gdriveClient.config.Client(context.Background(), token)
	bm.gdriveClient.initialized = true

	// Save refresh token
	bm.Config.GDriveRefreshToken = token.RefreshToken
	bm.SaveConfig()

	return nil
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// AWS S3 Upload
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// initS3Client initializes S3 client
func (bm *BackupManager) initS3Client() *S3Client {
	return &S3Client{
		endpoint:   bm.Config.S3Endpoint,
		region:     bm.Config.S3Region,
		bucket:     bm.Config.S3Bucket,
		accessKey:  bm.Config.S3AccessKey,
		secretKey:  bm.Config.S3SecretKey,
		pathPrefix: bm.Config.S3PathPrefix,
		httpClient: &http.Client{Timeout: 10 * time.Minute},
	}
}

// uploadToS3 uploads backup to S3
func (bm *BackupManager) uploadToS3(filePath string, info *BackupInfo) error {
	if bm.s3Client == nil {
		return fmt.Errorf("s3 not configured")
	}

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	fileInfo, _ := file.Stat()
	fileContent, _ := io.ReadAll(file)

	// Build key
	key := info.Filename
	if bm.s3Client.pathPrefix != "" {
		key = bm.s3Client.pathPrefix + "/" + key
	}

	// Build URL
	url := fmt.Sprintf("%s/%s/%s", bm.s3Client.endpoint, bm.s3Client.bucket, key)

	// Create request
	req, err := http.NewRequest("PUT", url, bytes.NewReader(fileContent))
	if err != nil {
		return err
	}

	// Sign request (simplified AWS Signature V4)
	now := time.Now().UTC()
	dateStr := now.Format("20060102T150405Z")
	shortDate := now.Format("20060102")

	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("X-Amz-Date", dateStr)
	req.Header.Set("Content-Type", "application/gzip")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(fileContent)))

	// Simple auth header (in production, use proper AWS SDK)
	authHeader := bm.signS3Request(req, shortDate, dateStr, fileContent)
	req.Header.Set("Authorization", authHeader)

	// Send request
	resp, err := bm.s3Client.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("s3 error: %s", string(body))
	}

	LogInfo("BACKUP", "Uploaded to S3: %s (%s)", key, FormatBytes(fileInfo.Size()))
	return nil
}

// signS3Request creates AWS Signature V4 authorization header
func (bm *BackupManager) signS3Request(req *http.Request, shortDate, dateStr string, payload []byte) string {
	// AWS Signature Version 4 implementation
	// Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html

	// Step 1: Create canonical request
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	canonicalQueryString := req.URL.Query().Encode()

	// Canonical headers (must be lowercase and sorted)
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-date:%s\n",
		req.Host, req.Header.Get("x-amz-date"))

	signedHeaders := "host;x-amz-date"

	// Hash the payload
	payloadHash := sha256.Sum256(payload)
	payloadHashHex := hex.EncodeToString(payloadHash[:])

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		payloadHashHex,
	)

	// Step 2: Create string to sign
	canonicalRequestHash := sha256.Sum256([]byte(canonicalRequest))
	canonicalRequestHashHex := hex.EncodeToString(canonicalRequestHash[:])

	credentialScope := fmt.Sprintf("%s/%s/s3/aws4_request", shortDate, bm.s3Client.region)

	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		dateStr,
		credentialScope,
		canonicalRequestHashHex,
	)

	// Step 3: Calculate signing key
	kDate := hmacSHA256([]byte("AWS4"+bm.s3Client.secretKey), []byte(shortDate))
	kRegion := hmacSHA256(kDate, []byte(bm.s3Client.region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	signingKey := hmacSHA256(kService, []byte("aws4_request"))

	// Step 4: Calculate signature
	signature := hmacSHA256(signingKey, []byte(stringToSign))
	signatureHex := hex.EncodeToString(signature)

	// Step 5: Build authorization header
	return fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		bm.s3Client.accessKey,
		credentialScope,
		signedHeaders,
		signatureHex,
	)
}

// hmacSHA256 computes HMAC-SHA256
func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// WebDAV Upload
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// initWebDAVClient initializes WebDAV client
func (bm *BackupManager) initWebDAVClient() *WebDAVClient {
	return &WebDAVClient{
		baseURL:    bm.Config.WebDAVURL,
		username:   bm.Config.WebDAVUsername,
		password:   bm.Config.WebDAVPassword,
		path:       bm.Config.WebDAVPath,
		httpClient: &http.Client{Timeout: 10 * time.Minute},
	}
}

// uploadToWebDAV uploads backup to WebDAV server
func (bm *BackupManager) uploadToWebDAV(filePath string, info *BackupInfo) error {
	if bm.webdavClient == nil {
		return fmt.Errorf("webdav not configured")
	}

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	fileInfo, _ := file.Stat()

	// Build URL
	url := bm.webdavClient.baseURL
	if bm.webdavClient.path != "" {
		url = strings.TrimSuffix(url, "/") + "/" + bm.webdavClient.path
	}
	url = strings.TrimSuffix(url, "/") + "/" + info.Filename

	// Create request
	req, err := http.NewRequest("PUT", url, file)
	if err != nil {
		return err
	}

	req.SetBasicAuth(bm.webdavClient.username, bm.webdavClient.password)
	req.Header.Set("Content-Type", "application/gzip")
	req.ContentLength = fileInfo.Size()

	// Send request
	resp, err := bm.webdavClient.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webdav error: %s", string(body))
	}

	LogInfo("BACKUP", "Uploaded to WebDAV: %s (%s)", url, FormatBytes(fileInfo.Size()))
	return nil
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Restore Operations
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// RestoreBackup restores a backup
func (bm *BackupManager) RestoreBackup(backupID string, source string) (*RestoreInfo, error) {
	restoreInfo := &RestoreInfo{
		ID:        GenerateID("RST"),
		BackupID:  backupID,
		Source:    source,
		StartedAt: time.Now().Unix(),
		Status:    "in_progress",
	}

	// Get backup info
	info, err := bm.GetBackupInfo(backupID)
	if err != nil {
		restoreInfo.Status = "failed"
		restoreInfo.Error = err.Error()
		return restoreInfo, err
	}

	// Download backup if from cloud
	var filePath string
	switch source {
	case BackupDestLocal:
		filePath = filepath.Join(bm.Config.LocalPath, "local", info.Filename)
	case BackupDestTelegram:
		// Download from Telegram would require message IDs stored during backup
		return nil, fmt.Errorf("telegram restore not implemented - please download manually")
	case BackupDestGDrive:
		filePath, err = bm.downloadFromGDrive(info.Filename)
	case BackupDestS3:
		filePath, err = bm.downloadFromS3(info.Filename)
	case BackupDestWebDAV:
		filePath, err = bm.downloadFromWebDAV(info.Filename)
	}

	if err != nil {
		restoreInfo.Status = "failed"
		restoreInfo.Error = err.Error()
		return restoreInfo, err
	}

	// Verify checksum
	checksum, err := bm.calculateChecksum(filePath)
	if err != nil || checksum != info.Checksum {
		restoreInfo.Status = "failed"
		restoreInfo.Error = "checksum mismatch"
		return restoreInfo, fmt.Errorf("checksum verification failed")
	}

	// Decrypt if encrypted
	if info.Encrypted {
		decryptedPath, err := bm.decryptFile(filePath)
		if err != nil {
			restoreInfo.Status = "failed"
			restoreInfo.Error = err.Error()
			return restoreInfo, err
		}
		if source != BackupDestLocal {
			os.Remove(filePath)
		}
		filePath = decryptedPath
	}

	// Decompress
	decompressedPath, err := bm.decompressArchive(filePath)
	if err != nil {
		os.Remove(filePath)
		restoreInfo.Status = "failed"
		restoreInfo.Error = err.Error()
		return restoreInfo, err
	}
	os.Remove(filePath)

	// Extract archive
	restoredCount, err := bm.extractArchive(decompressedPath)
	if err != nil {
		os.Remove(decompressedPath)
		restoreInfo.Status = "failed"
		restoreInfo.Error = err.Error()
		return restoreInfo, err
	}
	os.Remove(decompressedPath)

	// Update restore info
	restoreInfo.CompletedAt = time.Now().Unix()
	restoreInfo.Status = "completed"
	restoreInfo.RestoredFiles = restoredCount

	// Notify
	if bm.onRestoreComplete != nil {
		bm.onRestoreComplete(restoreInfo)
	}

	LogInfo("BACKUP", "Restore completed: %d files restored", restoredCount)
	return restoreInfo, nil
}

// decompressArchive decompresses a gzip archive
func (bm *BackupManager) decompressArchive(filePath string) (string, error) {
	outputPath := strings.TrimSuffix(filePath, ".gz")

	inputFile, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer inputFile.Close()

	gzipReader, err := gzip.NewReader(inputFile)
	if err != nil {
		return "", err
	}
	defer gzipReader.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return "", err
	}
	defer outputFile.Close()

	_, err = io.Copy(outputFile, gzipReader)
	if err != nil {
		return "", err
	}

	return outputPath, nil
}

// extractArchive extracts a tar archive
func (bm *BackupManager) extractArchive(archivePath string) (int, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	tr := tar.NewReader(file)
	count := 0

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, err
		}

		targetPath := header.Name

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return count, err
			}

		case tar.TypeReg:
			// Ensure directory exists
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return count, err
			}

			// Create backup of existing file
			if _, err := os.Stat(targetPath); err == nil {
				backupPath := targetPath + ".bak"
				os.Rename(targetPath, backupPath)
			}

			// Create file
			outFile, err := os.Create(targetPath)
			if err != nil {
				return count, err
			}

			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return count, err
			}
			outFile.Close()

			// Set permissions
			os.Chmod(targetPath, os.FileMode(header.Mode))
			count++
		}
	}

	return count, nil
}

// downloadFromGDrive downloads file from Google Drive
func (bm *BackupManager) downloadFromGDrive(filename string) (string, error) {
	if bm.gdriveClient == nil || !bm.gdriveClient.initialized {
		return "", fmt.Errorf("google drive not configured")
	}

	// Search for file
	searchURL := fmt.Sprintf(
		"https://www.googleapis.com/drive/v3/files?q=name='%s'&fields=files(id,name)",
		filename,
	)

	resp, err := bm.gdriveClient.httpClient.Get(searchURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result GDriveFileList
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if len(result.Files) == 0 {
		return "", fmt.Errorf("file not found in Google Drive")
	}

	fileID := result.Files[0].ID

	// Download file
	downloadURL := fmt.Sprintf("https://www.googleapis.com/drive/v3/files/%s?alt=media", fileID)
	resp, err = bm.gdriveClient.httpClient.Get(downloadURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Save to temp
	localPath := filepath.Join(TempDirectory, filename)
	outFile, err := os.Create(localPath)
	if err != nil {
		return "", err
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, resp.Body)
	if err != nil {
		return "", err
	}

	return localPath, nil
}

// downloadFromS3 downloads file from S3
func (bm *BackupManager) downloadFromS3(filename string) (string, error) {
	if bm.s3Client == nil {
		return "", fmt.Errorf("s3 not configured")
	}

	key := filename
	if bm.s3Client.pathPrefix != "" {
		key = bm.s3Client.pathPrefix + "/" + key
	}

	url := fmt.Sprintf("%s/%s/%s", bm.s3Client.endpoint, bm.s3Client.bucket, key)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	// Add auth headers (simplified)
	now := time.Now().UTC()
	req.Header.Set("X-Amz-Date", now.Format("20060102T150405Z"))

	resp, err := bm.s3Client.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("s3 download failed: %d", resp.StatusCode)
	}

	localPath := filepath.Join(TempDirectory, filename)
	outFile, err := os.Create(localPath)
	if err != nil {
		return "", err
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, resp.Body)
	if err != nil {
		return "", err
	}

	return localPath, nil
}

// downloadFromWebDAV downloads file from WebDAV
func (bm *BackupManager) downloadFromWebDAV(filename string) (string, error) {
	if bm.webdavClient == nil {
		return "", fmt.Errorf("webdav not configured")
	}

	url := bm.webdavClient.baseURL
	if bm.webdavClient.path != "" {
		url = strings.TrimSuffix(url, "/") + "/" + bm.webdavClient.path
	}
	url = strings.TrimSuffix(url, "/") + "/" + filename

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.SetBasicAuth(bm.webdavClient.username, bm.webdavClient.password)

	resp, err := bm.webdavClient.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("webdav download failed: %d", resp.StatusCode)
	}

	localPath := filepath.Join(TempDirectory, filename)
	outFile, err := os.Create(localPath)
	if err != nil {
		return "", err
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, resp.Body)
	if err != nil {
		return "", err
	}

	return localPath, nil
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Backup Scheduler
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// StartScheduler starts the backup scheduler
func (bm *BackupManager) StartScheduler() {
	if !bm.Config.ScheduleEnabled || len(bm.Config.Schedules) == 0 {
		return
	}

	bm.scheduler = &BackupScheduler{
		manager:   bm,
		schedules: make(map[string]*BackupSchedule),
		timers:    make(map[string]*time.Timer),
		running:   true,
		stopChan:  make(chan struct{}),
	}

	for _, schedule := range bm.Config.Schedules {
		if schedule.Enabled {
			bm.scheduler.schedules[schedule.ID] = schedule
			bm.scheduler.scheduleNext(schedule)
		}
	}

	LogInfo("BACKUP", "Scheduler started with %d schedules", len(bm.Config.Schedules))
}

// StopScheduler stops the backup scheduler
func (bm *BackupManager) StopScheduler() {
	if bm.scheduler == nil {
		return
	}

	bm.scheduler.mu.Lock()
	defer bm.scheduler.mu.Unlock()

	bm.scheduler.running = false
	close(bm.scheduler.stopChan)

	for _, timer := range bm.scheduler.timers {
		timer.Stop()
	}

	LogInfo("BACKUP", "Scheduler stopped")
}

// scheduleNext schedules the next run for a schedule
func (bs *BackupScheduler) scheduleNext(schedule *BackupSchedule) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if !bs.running {
		return
	}

	// Calculate next run time
	nextRun := bs.calculateNextRun(schedule)
	schedule.NextRun = nextRun.Unix()

	// Set timer
	duration := time.Until(nextRun)
	if duration < 0 {
		duration = time.Minute // Fallback
	}

	if timer, exists := bs.timers[schedule.ID]; exists {
		timer.Stop()
	}

	bs.timers[schedule.ID] = time.AfterFunc(duration, func() {
		bs.executeSchedule(schedule)
	})

	LogInfo("BACKUP", "Scheduled '%s' for %s", schedule.Name, nextRun.Format("2006-01-02 15:04:05"))
}

// calculateNextRun calculates the next run time for a schedule
func (bs *BackupScheduler) calculateNextRun(schedule *BackupSchedule) time.Time {
	now := time.Now()

	switch schedule.Type {
	case ScheduleHourly:
		next := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), schedule.Minute, 0, 0, now.Location())
		if next.Before(now) {
			next = next.Add(time.Hour)
		}
		return next

	case ScheduleDaily:
		next := time.Date(now.Year(), now.Month(), now.Day(), schedule.Hour, schedule.Minute, 0, 0, now.Location())
		if next.Before(now) {
			next = next.AddDate(0, 0, 1)
		}
		return next

	case ScheduleWeekly:
		next := time.Date(now.Year(), now.Month(), now.Day(), schedule.Hour, schedule.Minute, 0, 0, now.Location())
		daysUntil := (schedule.DayOfWeek - int(now.Weekday()) + 7) % 7
		if daysUntil == 0 && next.Before(now) {
			daysUntil = 7
		}
		next = next.AddDate(0, 0, daysUntil)
		return next

	case ScheduleMonthly:
		next := time.Date(now.Year(), now.Month(), schedule.DayOfMonth, schedule.Hour, schedule.Minute, 0, 0, now.Location())
		if next.Before(now) {
			next = next.AddDate(0, 1, 0)
		}
		return next

	default:
		return now.Add(time.Hour * 24) // Default to daily
	}
}

// executeSchedule executes a scheduled backup
func (bs *BackupScheduler) executeSchedule(schedule *BackupSchedule) {
	LogInfo("BACKUP", "Executing scheduled backup: %s", schedule.Name)

	// Update last run
	schedule.LastRun = time.Now().Unix()

	// Create backup
	_, err := bs.manager.CreateBackup(
		schedule.BackupType,
		schedule.Destinations,
		"scheduler",
	)

	if err != nil {
		LogError("BACKUP", "Scheduled backup failed: %v", err)
	}

	// Schedule next run
	bs.scheduleNext(schedule)

	// Save updated schedule
	bs.manager.SaveConfig()
}

// AddSchedule adds a new backup schedule
func (bm *BackupManager) AddSchedule(schedule *BackupSchedule) error {
	if schedule.ID == "" {
		schedule.ID = GenerateID("SCH")
	}

	bm.mu.Lock()
	bm.Config.Schedules = append(bm.Config.Schedules, schedule)
	bm.mu.Unlock()

	if err := bm.SaveConfig(); err != nil {
		return err
	}

	// Add to scheduler if running
	if bm.scheduler != nil && schedule.Enabled {
		bm.scheduler.schedules[schedule.ID] = schedule
		bm.scheduler.scheduleNext(schedule)
	}

	return nil
}

// RemoveSchedule removes a backup schedule
func (bm *BackupManager) RemoveSchedule(scheduleID string) error {
	bm.mu.Lock()
	for i, s := range bm.Config.Schedules {
		if s.ID == scheduleID {
			bm.Config.Schedules = append(bm.Config.Schedules[:i], bm.Config.Schedules[i+1:]...)
			break
		}
	}
	bm.mu.Unlock()

	if err := bm.SaveConfig(); err != nil {
		return err
	}

	// Remove from scheduler
	if bm.scheduler != nil {
		bm.scheduler.mu.Lock()
		if timer, exists := bm.scheduler.timers[scheduleID]; exists {
			timer.Stop()
			delete(bm.scheduler.timers, scheduleID)
		}
		delete(bm.scheduler.schedules, scheduleID)
		bm.scheduler.mu.Unlock()
	}

	return nil
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Cleanup & Maintenance
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// CleanupOldBackups removes old backups based on retention policy
func (bm *BackupManager) CleanupOldBackups() error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	localPath := filepath.Join(bm.Config.LocalPath, "local")

	// Get all backup files
	files, err := os.ReadDir(localPath)
	if err != nil {
		return err
	}

	// Sort by modification time (oldest first)
	type fileWithTime struct {
		name    string
		modTime time.Time
		size    int64
	}

	var backupFiles []fileWithTime
	var totalSize int64

	for _, f := range files {
		if !f.IsDir() && strings.HasPrefix(f.Name(), "mxui_backup_") {
			info, err := f.Info()
			if err != nil {
				continue
			}
			backupFiles = append(backupFiles, fileWithTime{
				name:    f.Name(),
				modTime: info.ModTime(),
				size:    info.Size(),
			})
			totalSize += info.Size()
		}
	}

	sort.Slice(backupFiles, func(i, j int) bool {
		return backupFiles[i].modTime.Before(backupFiles[j].modTime)
	})

	// Remove old backups
	deletedCount := 0
	cutoffTime := time.Now().AddDate(0, 0, -bm.Config.RetentionDays)

	for len(backupFiles) > bm.Config.MaxBackups || totalSize > int64(bm.Config.MaxTotalSizeMB)*1024*1024 {
		if len(backupFiles) == 0 {
			break
		}

		oldest := backupFiles[0]

		// Always keep at least one backup, unless it's too old
		if len(backupFiles) == 1 && oldest.modTime.After(cutoffTime) {
			break
		}

		// Delete file
		filePath := filepath.Join(localPath, oldest.name)
		if err := os.Remove(filePath); err != nil {
			LogError("BACKUP", "Failed to delete old backup: %v", err)
		} else {
			totalSize -= oldest.size
			deletedCount++
			LogInfo("BACKUP", "Deleted old backup: %s", oldest.name)
		}

		backupFiles = backupFiles[1:]
	}

	// Delete by age
	for _, bf := range backupFiles {
		if bf.modTime.Before(cutoffTime) {
			filePath := filepath.Join(localPath, bf.name)
			if err := os.Remove(filePath); err == nil {
				deletedCount++
				LogInfo("BACKUP", "Deleted expired backup: %s", bf.name)
			}
		}
	}

	if deletedCount > 0 {
		LogInfo("BACKUP", "Cleanup completed: %d backups removed", deletedCount)
	}

	return nil
}

// CheckDiskSpace checks available disk space
func (bm *BackupManager) CheckDiskSpace() (bool, int64) {
	// Get disk usage for backup directory
	// This is a simplified version - in production use syscall for accurate info

	var totalUsed int64
	filepath.Walk(bm.Config.LocalPath, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			totalUsed += info.Size()
		}
		return nil
	})

	// Check if we have enough space
	_ = int64(bm.Config.MinFreeDiskGB) * 1024 * 1024 * 1024
	hasEnoughSpace := true // Would need syscall to properly check

	return hasEnoughSpace, totalUsed
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Backup Info Management
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// saveBackupInfo saves backup info to database
func (bm *BackupManager) saveBackupInfo(info *BackupInfo) error {
	infoJSON, err := json.Marshal(info)
	if err != nil {
		return err
	}

	return bm.db.SetSetting(fmt.Sprintf("backup_%s", info.ID), string(infoJSON), "json", "backup", false)
}

// GetBackupInfo retrieves backup info by ID
func (bm *BackupManager) GetBackupInfo(backupID string) (*BackupInfo, error) {
	infoJSON, err := bm.db.GetSetting(fmt.Sprintf("backup_%s", backupID))
	if err != nil || infoJSON == "" {
		return nil, fmt.Errorf("backup not found")
	}

	var info BackupInfo
	if err := json.Unmarshal([]byte(infoJSON), &info); err != nil {
		return nil, err
	}

	return &info, nil
}

// ListBackups lists all backups
func (bm *BackupManager) ListBackups() ([]*BackupInfo, error) {
	// Get from local storage
	localPath := filepath.Join(bm.Config.LocalPath, "local")

	files, err := os.ReadDir(localPath)
	if err != nil {
		return nil, err
	}

	var backups []*BackupInfo

	for _, f := range files {
		if !f.IsDir() && strings.HasPrefix(f.Name(), "mxui_backup_") {
			info, _ := f.Info()

			backup := &BackupInfo{
				Filename:       f.Name(),
				CompressedSize: info.Size(),
				CreatedAt:      info.ModTime().Unix(),
				Status:         "completed",
			}

			// Try to extract ID from filename
			parts := strings.Split(f.Name(), "_")
			if len(parts) >= 3 {
				backup.Type = parts[2]
			}

			// Check for checksum file
			checksumPath := filepath.Join(localPath, f.Name()+".sha256")
			if checksumData, err := os.ReadFile(checksumPath); err == nil {
				backup.Checksum = strings.TrimSpace(string(checksumData))
			}

			backups = append(backups, backup)
		}
	}

	// Sort by creation time (newest first)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].CreatedAt > backups[j].CreatedAt
	})

	return backups, nil
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Quick Backup Methods
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// QuickBackupLocal creates a quick local backup
func (bm *BackupManager) QuickBackupLocal() (*BackupInfo, error) {
	return bm.CreateBackup(BackupTypeFull, []string{BackupDestLocal}, "quick_backup")
}

// QuickBackupTelegram creates a quick Telegram backup
func (bm *BackupManager) QuickBackupTelegram() (*BackupInfo, error) {
	return bm.CreateBackup(BackupTypeFull, []string{BackupDestTelegram}, "quick_backup")
}

// QuickBackupDatabase creates a quick database-only backup
func (bm *BackupManager) QuickBackupDatabase() (*BackupInfo, error) {
	return bm.CreateBackup(BackupTypeDatabase, []string{BackupDestLocal}, "quick_backup")
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Notification Handlers
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// handleBackupComplete handles successful backup completion
func (bm *BackupManager) handleBackupComplete(info *BackupInfo) {
	if bm.onBackupComplete != nil {
		bm.onBackupComplete(info)
	}

	if bm.Config.NotifyOnSuccess && bm.Config.NotificationChat != 0 {
		msg := fmt.Sprintf(
			"âœ… <b>Backup Completed</b>\n\n"+
				"ðŸ“¦ Type: %s\n"+
				"ðŸ“Š Size: %s\n"+
				"ðŸ“… Time: %s\n"+
				"ðŸ“ Destinations: %s",
			info.Type,
			FormatBytes(info.CompressedSize),
			time.Unix(info.CreatedAt, 0).Format("2006-01-02 15:04:05"),
			strings.Join(info.Destinations, ", "),
		)

		if bm.bot != nil {
			bm.bot.SendNotification("Backup", msg)
		}
	}
}

// handleBackupFailed handles backup failure
func (bm *BackupManager) handleBackupFailed(info *BackupInfo, err error) {
	if bm.onBackupFailed != nil {
		bm.onBackupFailed(err)
	}

	if bm.Config.NotifyOnFailure && bm.Config.NotificationChat != 0 {
		msg := fmt.Sprintf(
			"âŒ <b>Backup Failed</b>\n\n"+
				"ðŸ“¦ Type: %s\n"+
				"âš ï¸ Error: %s\n"+
				"ðŸ“… Time: %s",
			info.Type,
			err.Error(),
			time.Now().Format("2006-01-02 15:04:05"),
		)

		if bm.bot != nil {
			bm.bot.SendNotification("Backup", msg)
		}
	}
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Status & Info Methods
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// GetStatus returns current backup manager status
func (bm *BackupManager) GetStatus() map[string]interface{} {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	status := map[string]interface{}{
		"enabled":            bm.Config.Enabled,
		"is_running":         bm.isRunning,
		"scheduler_active":   bm.scheduler != nil && bm.scheduler.running,
		"local_enabled":      bm.Config.LocalEnabled,
		"telegram_enabled":   bm.Config.TelegramEnabled,
		"gdrive_enabled":     bm.Config.GDriveEnabled && bm.gdriveClient != nil && bm.gdriveClient.initialized,
		"s3_enabled":         bm.Config.S3Enabled && bm.s3Client != nil,
		"webdav_enabled":     bm.Config.WebDAVEnabled && bm.webdavClient != nil,
		"encryption_enabled": bm.Config.EncryptionEnabled,
		"auto_cleanup":       bm.Config.AutoCleanupEnabled,
		"schedules_count":    len(bm.Config.Schedules),
	}

	if bm.lastBackup != nil {
		status["last_backup"] = map[string]interface{}{
			"id":         bm.lastBackup.ID,
			"type":       bm.lastBackup.Type,
			"created_at": bm.lastBackup.CreatedAt,
			"size":       bm.lastBackup.CompressedSize,
			"status":     bm.lastBackup.Status,
		}
	}

	if bm.currentBackup != nil {
		status["current_backup"] = map[string]interface{}{
			"id":       bm.currentBackup.ID,
			"phase":    bm.currentBackup.Phase,
			"progress": bm.currentBackup.Progress,
		}
	}

	return status
}

// GetProgress returns current backup progress
func (bm *BackupManager) GetProgress() *BackupProgress {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.currentBackup
}

// GetLastBackup returns last completed backup info
func (bm *BackupManager) GetLastBackup() *BackupInfo {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.lastBackup
}

// GetSchedules returns all schedules
func (bm *BackupManager) GetSchedules() []*BackupSchedule {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.Config.Schedules
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Helper Functions
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// containsString checks if slice contains string
func containsString(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// FormatBytes formats bytes to human readable format
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// GenerateID generates a unique ID with prefix
func GenerateID(prefix string) string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%s_%s_%d", prefix, fmt.Sprintf("%x", b)[:8], time.Now().Unix()%10000)
}

// GetServerID returns unique server identifier
func GetServerID() string {
	hostname, _ := os.Hostname()
	hash := sha256.Sum256([]byte(hostname + os.Getenv("USER")))
	return fmt.Sprintf("%x", hash[:8])
}

// GetPublicIP returns public IP address
func GetPublicIP() string {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

// LogInfo logs info message
func LogInfo(module, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("[%s] [%s] INFO: %s\n", time.Now().Format("2006-01-02 15:04:05"), module, msg)
}

// LogSuccess logs success message
func LogSuccess(module, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("[%s] [%s] SUCCESS: %s\n", time.Now().Format("2006-01-02 15:04:05"), module, msg)
}

// LogWarn logs warning message
func LogWarn(module, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("[%s] [%s] WARN: %s\n", time.Now().Format("2006-01-02 15:04:05"), module, msg)
}

// LogError logs error message
func LogError(module, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("[%s] [%s] ERROR: %s\n", time.Now().Format("2006-01-02 15:04:05"), module, msg)
}

// LogDebug logs debug message
func LogDebug(module, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("[%s] [%s] DEBUG: %s\n", time.Now().Format("2006-01-02 15:04:05"), module, msg)
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// API Handlers
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// RegisterBackupRoutes registers backup API routes
func (bm *BackupManager) RegisterBackupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/backup/status", bm.handleStatus)
	mux.HandleFunc("/api/backup/create", bm.handleCreate)
	mux.HandleFunc("/api/backup/list", bm.handleList)
	mux.HandleFunc("/api/backup/restore", bm.handleRestore)
	mux.HandleFunc("/api/backup/download", bm.handleDownload)
	mux.HandleFunc("/api/backup/delete", bm.handleDelete)
	mux.HandleFunc("/api/backup/config", bm.handleConfig)
	mux.HandleFunc("/api/backup/schedules", bm.handleSchedules)
	mux.HandleFunc("/api/backup/cleanup", bm.handleCleanup)
	mux.HandleFunc("/api/backup/progress", bm.handleProgress)
}

func (bm *BackupManager) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := bm.GetStatus()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    status,
	})
}

func (bm *BackupManager) handleCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Type         string   `json:"type"`
		Destinations []string `json:"destinations"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Type == "" {
		req.Type = BackupTypeFull
	}
	if len(req.Destinations) == 0 {
		req.Destinations = []string{BackupDestLocal}
	}

	// Run async
	go func() {
		bm.CreateBackup(req.Type, req.Destinations, "api")
	}()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Backup started",
	})
}

func (bm *BackupManager) handleList(w http.ResponseWriter, r *http.Request) {
	backups, err := bm.ListBackups()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    backups,
	})
}

func (bm *BackupManager) handleRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		BackupID string `json:"backup_id"`
		Source   string `json:"source"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	info, err := bm.RestoreBackup(req.BackupID, req.Source)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    info,
	})
}

func (bm *BackupManager) handleDownload(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		http.Error(w, "Filename required", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(bm.Config.LocalPath, "local", filename)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "Backup not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Type", "application/gzip")
	http.ServeFile(w, r, filePath)
}

func (bm *BackupManager) handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := r.URL.Query().Get("filename")
	if filename == "" {
		http.Error(w, "Filename required", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(bm.Config.LocalPath, "local", filename)
	if err := os.Remove(filePath); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Backup deleted",
	})
}

func (bm *BackupManager) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Return config (hide sensitive data)
		safeConfig := *bm.Config
		safeConfig.EncryptionKey = "***"
		safeConfig.TelegramBotToken = "***"
		safeConfig.S3SecretKey = "***"
		safeConfig.WebDAVPassword = "***"

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    safeConfig,
		})

	case http.MethodPut:
		var newConfig BackupConfig
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Preserve sensitive data if not provided
		if newConfig.EncryptionKey == "" || newConfig.EncryptionKey == "***" {
			newConfig.EncryptionKey = bm.Config.EncryptionKey
		}
		if newConfig.TelegramBotToken == "" || newConfig.TelegramBotToken == "***" {
			newConfig.TelegramBotToken = bm.Config.TelegramBotToken
		}

		bm.mu.Lock()
		bm.Config = &newConfig
		bm.mu.Unlock()

		if err := bm.SaveConfig(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Reinitialize cloud clients
		bm.initCloudClients()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Config updated",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (bm *BackupManager) handleSchedules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    bm.GetSchedules(),
		})

	case http.MethodPost:
		var schedule BackupSchedule
		if err := json.NewDecoder(r.Body).Decode(&schedule); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := bm.AddSchedule(&schedule); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    schedule,
		})

	case http.MethodDelete:
		scheduleID := r.URL.Query().Get("id")
		if scheduleID == "" {
			http.Error(w, "Schedule ID required", http.StatusBadRequest)
			return
		}

		if err := bm.RemoveSchedule(scheduleID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Schedule deleted",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (bm *BackupManager) handleCleanup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := bm.CleanupOldBackups(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Cleanup completed",
	})
}

func (bm *BackupManager) handleProgress(w http.ResponseWriter, r *http.Request) {
	progress := bm.GetProgress()
	if progress == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"is_running": false,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"is_running": true,
		"data":       progress,
	})
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Version
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

const VERSION = "1.0.0"

// createZipBackup creates a zip backup file
func (bm *BackupManager) createZipBackup(destPath string) error {
	// Ensure backup directory exists
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Create the zip file
	zipFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create zip file: %w", err)
	}
	defer zipFile.Close()

	// Create gzip writer
	gzWriter := gzip.NewWriter(zipFile)
	defer gzWriter.Close()

	// Create tar writer
	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	// Files to backup
	filesToBackup := []struct {
		path     string
		arcPath  string
		required bool
	}{
		{"Data/database.db", "database.db", true},
		{"Data/database.db-shm", "database.db-shm", false},
		{"Data/database.db-wal", "database.db-wal", false},
		{"config.yaml", "config.yaml", true},
		{"Data/certs", "certs", false},
		{"Data/geoip.dat", "geoip.dat", false},
		{"Data/geosite.dat", "geosite.dat", false},
	}

	// Add each file/directory to the archive
	for _, item := range filesToBackup {
		if err := bm.addToTarGz(tarWriter, item.path, item.arcPath); err != nil {
			if item.required {
				return fmt.Errorf("failed to add required file %s: %w", item.path, err)
			}
			// Optional files - just log warning
			LogWarn("BACKUP", "Skipping optional file %s: %v", item.path, err)
		}
	}

	LogInfo("BACKUP", "Created ZIP backup: %s", destPath)
	return nil
}

// extractZipBackup extracts a zip backup file
func (bm *BackupManager) extractZipBackup(zipPath string) error {
	// Verify file exists
	if _, err := os.Stat(zipPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file not found: %s", zipPath)
	}

	// Open the zip file
	zipFile, err := os.Open(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer zipFile.Close()

	// Create gzip reader
	gzReader, err := gzip.NewReader(zipFile)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Create tar reader
	tarReader := tar.NewReader(gzReader)

	// Extract each file
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Determine target path
		targetPath := filepath.Join("Data", header.Name)
		if header.Name == "config.yaml" {
			targetPath = "config.yaml"
		}

		// Sanitize path to prevent directory traversal
		targetPath = filepath.Clean(targetPath)
		if !strings.HasPrefix(targetPath, "Data") && targetPath != "config.yaml" {
			return fmt.Errorf("invalid file path in archive: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			// Create directory
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", targetPath, err)
			}

		case tar.TypeReg:
			// Create parent directory
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory for %s: %w", targetPath, err)
			}

			// Create the file
			outFile, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", targetPath, err)
			}

			// Copy file contents
			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("failed to write file %s: %w", targetPath, err)
			}
			outFile.Close()

			// Set file permissions
			if err := os.Chmod(targetPath, os.FileMode(header.Mode)); err != nil {
				LogWarn("BACKUP", "Failed to set permissions for %s: %v", targetPath, err)
			}

			LogInfo("BACKUP", "Extracted: %s", targetPath)
		}
	}

	LogInfo("BACKUP", "Successfully restored from backup: %s", zipPath)
	return nil
}

// addToTarGz adds a file or directory to tar archive
func (bm *BackupManager) addToTarGz(tarWriter *tar.Writer, sourcePath, archivePath string) error {
	// Get file info
	info, err := os.Stat(sourcePath)
	if err != nil {
		return err
	}

	// If it's a directory, recursively add all files
	if info.IsDir() {
		return filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Calculate relative path
			relPath, err := filepath.Rel(sourcePath, path)
			if err != nil {
				return err
			}
			arcPath := filepath.Join(archivePath, relPath)

			// Add file/dir to archive
			return bm.addFileToTar(tarWriter, path, arcPath, info)
		})
	}

	// Single file
	return bm.addFileToTar(tarWriter, sourcePath, archivePath, info)
}

// addFileToTar adds a single file to tar archive
func (bm *BackupManager) addFileToTar(tarWriter *tar.Writer, filePath, archivePath string, info os.FileInfo) error {
	// Create tar header
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return fmt.Errorf("failed to create tar header: %w", err)
	}
	header.Name = archivePath

	// Write header
	if err := tarWriter.WriteHeader(header); err != nil {
		return fmt.Errorf("failed to write tar header: %w", err)
	}

	// If it's a directory, we're done
	if info.IsDir() {
		return nil
	}

	// Open and copy file contents
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	if _, err := io.Copy(tarWriter, file); err != nil {
		return fmt.Errorf("failed to write file contents: %w", err)
	}

	return nil
}

// CreateSingleFileBackup creates a single ZIP backup
func (bm *BackupManager) CreateSingleFileBackup() (string, error) {
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf(BackupFileName, timestamp)
	backupPath := filepath.Join(BackupDirectory, filename)

	// Create ZIP with db + config + certs
	return backupPath, bm.createZipBackup(backupPath)
}

// RestoreSingleFileBackup restores from ZIP
func (bm *BackupManager) RestoreSingleFileBackup(zipPath string) error {
	return bm.extractZipBackup(zipPath)
}
