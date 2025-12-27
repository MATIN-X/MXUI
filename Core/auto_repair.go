// MXUI VPN Panel
// Core/auto_repair.go
// Auto-Repair & Self-Healing System

package core

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// ============================================================================
// AUTO REPAIR CONSTANTS
// ============================================================================

const (
	RepairCheckInterval = 5 * time.Minute
	RepairMaxRetries    = 3
	RepairLogFile       = "./Data/logs/auto-repair.log"
	RepairBackupDir     = "./Data/backups/auto-repair"
)

// ============================================================================
// AUTO REPAIR MANAGER
// ============================================================================

// AutoRepairManager manages automatic system repair
type AutoRepairManager struct {
	enabled bool
	checks  map[string]*SystemHealthCheck
	repairs map[string]*RepairAction
	history []*RepairEvent
	mu      sync.RWMutex
	ctx     context.Context
	cancel  context.CancelFunc
	logger  *RepairLogger
}

// SystemHealthCheck represents a system health check
type SystemHealthCheck struct {
	Name        string
	Description string
	Check       func() error
	Severity    string // critical, warning, info
	Interval    time.Duration
	Enabled     bool
}

// RepairAction represents an automated repair action
type RepairAction struct {
	Name        string
	Description string
	Action      func() error
	Backup      func() error
	Verify      func() error
	MaxRetries  int
	Enabled     bool
}

// RepairEvent represents a repair event
type RepairEvent struct {
	Timestamp time.Time
	CheckName string
	Issue     string
	Action    string
	Success   bool
	Error     string
	Duration  time.Duration
}

// RepairLogger logs repair operations
type RepairLogger struct {
	logFile string
	mu      sync.Mutex
}

// Global auto-repair manager
var AutoRepair *AutoRepairManager

// ============================================================================
// INITIALIZATION
// ============================================================================

// InitAutoRepairManager initializes auto-repair system
func InitAutoRepairManager(enabled bool) error {
	ctx, cancel := context.WithCancel(context.Background())

	AutoRepair = &AutoRepairManager{
		enabled: enabled,
		checks:  make(map[string]*SystemHealthCheck),
		repairs: make(map[string]*RepairAction),
		history: make([]*RepairEvent, 0),
		ctx:     ctx,
		cancel:  cancel,
		logger:  &RepairLogger{logFile: RepairLogFile},
	}

	if !enabled {
		LogInfo("AUTO-REPAIR", "Auto-repair disabled")
		return nil
	}

	// Create directories
	os.MkdirAll(filepath.Dir(RepairLogFile), 0755)
	os.MkdirAll(RepairBackupDir, 0755)

	// Register health checks
	AutoRepair.registerSystemHealthChecks()

	// Register repair actions
	AutoRepair.registerRepairActions()

	// Start monitoring
	go AutoRepair.startMonitoring()

	LogSuccess("AUTO-REPAIR", "Auto-repair system initialized")
	return nil
}

// ============================================================================
// HEALTH CHECKS REGISTRATION
// ============================================================================

// registerSystemHealthChecks registers all health checks
func (arm *AutoRepairManager) registerSystemHealthChecks() {
	// Database health
	arm.RegisterCheck(&SystemHealthCheck{
		Name:        "database",
		Description: "Check database integrity and connectivity",
		Check:       arm.checkDatabase,
		Severity:    "critical",
		Interval:    5 * time.Minute,
		Enabled:     true,
	})

	// Xray core health
	arm.RegisterCheck(&SystemHealthCheck{
		Name:        "xray-core",
		Description: "Check Xray core status",
		Check:       arm.checkXrayCore,
		Severity:    "critical",
		Interval:    2 * time.Minute,
		Enabled:     true,
	})

	// Configuration validity
	arm.RegisterCheck(&SystemHealthCheck{
		Name:        "config",
		Description: "Validate configuration files",
		Check:       arm.checkConfiguration,
		Severity:    "warning",
		Interval:    10 * time.Minute,
		Enabled:     true,
	})

	// Disk space
	arm.RegisterCheck(&SystemHealthCheck{
		Name:        "disk-space",
		Description: "Check available disk space",
		Check:       arm.checkDiskSpace,
		Severity:    "warning",
		Interval:    15 * time.Minute,
		Enabled:     true,
	})

	// Port availability
	arm.RegisterCheck(&SystemHealthCheck{
		Name:        "ports",
		Description: "Check if required ports are available",
		Check:       arm.checkPorts,
		Severity:    "critical",
		Interval:    5 * time.Minute,
		Enabled:     true,
	})

	// SSL certificates
	arm.RegisterCheck(&SystemHealthCheck{
		Name:        "ssl-certs",
		Description: "Check SSL certificate validity",
		Check:       arm.checkSSLCertificates,
		Severity:    "warning",
		Interval:    1 * time.Hour,
		Enabled:     true,
	})

	// Node connectivity (if master)
	if MasterNode != nil && MasterNode.isMaster {
		arm.RegisterCheck(&SystemHealthCheck{
			Name:        "nodes",
			Description: "Check node connectivity",
			Check:       arm.checkNodes,
			Severity:    "warning",
			Interval:    3 * time.Minute,
			Enabled:     true,
		})
	}
}

// ============================================================================
// REPAIR ACTIONS REGISTRATION
// ============================================================================

// registerRepairActions registers all repair actions
func (arm *AutoRepairManager) registerRepairActions() {
	// Repair database
	arm.RegisterRepair(&RepairAction{
		Name:        "database",
		Description: "Repair database corruption",
		Action:      arm.repairDatabase,
		Backup:      arm.backupDatabase,
		Verify:      arm.verifyDatabase,
		MaxRetries:  3,
		Enabled:     true,
	})

	// Restart Xray core
	arm.RegisterRepair(&RepairAction{
		Name:        "xray-core",
		Description: "Restart Xray core",
		Action:      arm.restartXrayCore,
		Verify:      arm.verifyXrayCore,
		MaxRetries:  3,
		Enabled:     true,
	})

	// Fix configuration
	arm.RegisterRepair(&RepairAction{
		Name:        "config",
		Description: "Restore valid configuration",
		Action:      arm.repairConfiguration,
		Backup:      arm.backupConfiguration,
		Verify:      arm.verifyConfiguration,
		MaxRetries:  2,
		Enabled:     true,
	})

	// Clean disk space
	arm.RegisterRepair(&RepairAction{
		Name:        "disk-space",
		Description: "Clean up disk space",
		Action:      arm.cleanDiskSpace,
		Verify:      arm.verifyDiskSpace,
		MaxRetries:  1,
		Enabled:     true,
	})

	// Reconnect nodes
	arm.RegisterRepair(&RepairAction{
		Name:        "nodes",
		Description: "Reconnect offline nodes",
		Action:      arm.reconnectNodes,
		Verify:      arm.verifyNodes,
		MaxRetries:  3,
		Enabled:     true,
	})
}

// RegisterCheck registers a health check
func (arm *AutoRepairManager) RegisterCheck(check *SystemHealthCheck) {
	arm.mu.Lock()
	defer arm.mu.Unlock()

	arm.checks[check.Name] = check
	LogInfo("AUTO-REPAIR", "Registered health check: %s", check.Name)
}

// RegisterRepair registers a repair action
func (arm *AutoRepairManager) RegisterRepair(repair *RepairAction) {
	arm.mu.Lock()
	defer arm.mu.Unlock()

	arm.repairs[repair.Name] = repair
	LogInfo("AUTO-REPAIR", "Registered repair action: %s", repair.Name)
}

// ============================================================================
// MONITORING
// ============================================================================

// startMonitoring starts continuous health monitoring
func (arm *AutoRepairManager) startMonitoring() {
	ticker := time.NewTicker(RepairCheckInterval)
	defer ticker.Stop()

	// Initial check
	arm.runAllChecks()

	for {
		select {
		case <-arm.ctx.Done():
			return
		case <-ticker.C:
			arm.runAllChecks()
		}
	}
}

// runAllChecks runs all health checks
func (arm *AutoRepairManager) runAllChecks() {
	arm.mu.RLock()
	checks := make([]*SystemHealthCheck, 0, len(arm.checks))
	for _, check := range arm.checks {
		if check.Enabled {
			checks = append(checks, check)
		}
	}
	arm.mu.RUnlock()

	for _, check := range checks {
		go arm.runCheck(check)
	}
}

// runCheck runs a single health check
func (arm *AutoRepairManager) runCheck(check *SystemHealthCheck) {
	startTime := time.Now()
	err := check.Check()
	duration := time.Since(startTime)

	if err != nil {
		LogWarn("AUTO-REPAIR", "Health check failed: %s - %v", check.Name, err)

		// Log event
		event := &RepairEvent{
			Timestamp: time.Now(),
			CheckName: check.Name,
			Issue:     err.Error(),
			Duration:  duration,
		}

		// Attempt repair
		if repair, exists := arm.repairs[check.Name]; exists && repair.Enabled {
			LogInfo("AUTO-REPAIR", "Attempting repair: %s", repair.Name)

			if err := arm.executeRepair(repair, event); err != nil {
				LogError("AUTO-REPAIR", "Repair failed: %s - %v", repair.Name, err)
			}
		}

		arm.addEvent(event)
	}
}

// executeRepair executes a repair action
func (arm *AutoRepairManager) executeRepair(repair *RepairAction, event *RepairEvent) error {
	event.Action = repair.Name
	startTime := time.Now()

	// Backup if available
	if repair.Backup != nil {
		LogInfo("AUTO-REPAIR", "Creating backup for: %s", repair.Name)
		if err := repair.Backup(); err != nil {
			LogWarn("AUTO-REPAIR", "Backup failed: %v", err)
		}
	}

	// Execute repair with retries
	var lastErr error
	for i := 0; i < repair.MaxRetries; i++ {
		if i > 0 {
			LogInfo("AUTO-REPAIR", "Retry %d/%d: %s", i+1, repair.MaxRetries, repair.Name)
			time.Sleep(time.Duration(i) * 5 * time.Second)
		}

		if err := repair.Action(); err != nil {
			lastErr = err
			continue
		}

		// Verify repair
		if repair.Verify != nil {
			if err := repair.Verify(); err != nil {
				lastErr = err
				continue
			}
		}

		// Success
		event.Success = true
		event.Duration = time.Since(startTime)
		LogSuccess("AUTO-REPAIR", "Repair successful: %s", repair.Name)
		arm.logger.Log("SUCCESS", repair.Name, "Repair completed successfully")
		return nil
	}

	// Failed after retries
	event.Success = false
	event.Error = lastErr.Error()
	event.Duration = time.Since(startTime)
	arm.logger.Log("FAILED", repair.Name, lastErr.Error())

	return lastErr
}

// ============================================================================
// HEALTH CHECK IMPLEMENTATIONS
// ============================================================================

func (arm *AutoRepairManager) checkDatabase() error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	// Test query
	var count int
	err := DB.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return fmt.Errorf("database query failed: %w", err)
	}

	// Check integrity
	var integrityCheck string
	err = DB.db.QueryRow("PRAGMA integrity_check").Scan(&integrityCheck)
	if err != nil || integrityCheck != "ok" {
		return fmt.Errorf("database integrity check failed: %s", integrityCheck)
	}

	return nil
}

func (arm *AutoRepairManager) checkXrayCore() error {
	if Protocols == nil {
		return fmt.Errorf("protocols not initialized")
	}

	// Check if Xray core is running
	core := Protocols.cores[CoreXray]
	if core == nil || !core.IsRunning {
		return fmt.Errorf("xray core not running")
	}

	return nil
}

func (arm *AutoRepairManager) checkConfiguration() error {
	if ConfigMgr == nil {
		return fmt.Errorf("config manager not initialized")
	}

	config := ConfigMgr.Get()
	if config == nil {
		return fmt.Errorf("config is nil")
	}

	return ValidateConfig(config)
}

func (arm *AutoRepairManager) checkDiskSpace() error {
	// Check available disk space
	var stat syscall.Statfs_t
	err := syscall.Statfs(".", &stat)
	if err != nil {
		return err
	}

	available := stat.Bavail * uint64(stat.Bsize)
	total := stat.Blocks * uint64(stat.Bsize)
	usedPercent := float64(total-available) / float64(total) * 100

	if usedPercent > 90 {
		return fmt.Errorf("disk usage too high: %.1f%%", usedPercent)
	}

	return nil
}

func (arm *AutoRepairManager) checkPorts() error {
	// Check if main port is available
	ports := []int{8080, 443}

	for _, port := range ports {
		addr := fmt.Sprintf(":%d", port)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("port %d not available: %w", port, err)
		}
		listener.Close()
	}

	return nil
}

func (arm *AutoRepairManager) checkSSLCertificates() error {
	// Check SSL certificate expiration
	certFile := "./Data/certs/cert.pem"

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		return nil // No certificate configured
	}

	// Load certificate
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	// Parse certificate
	block, _ := pem.Decode(certData)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check expiration (warn if expires within 30 days)
	daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)

	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("certificate expired on %s", cert.NotAfter.Format("2006-01-02"))
	}

	if daysUntilExpiry < 30 {
		LogWarn("AUTO-REPAIR", "Certificate expires in %d days (%s)", daysUntilExpiry, cert.NotAfter.Format("2006-01-02"))
		if daysUntilExpiry < 7 {
			return fmt.Errorf("certificate expires in %d days", daysUntilExpiry)
		}
	}

	return nil
}

func (arm *AutoRepairManager) checkNodes() error {
	if MasterNode == nil || !MasterNode.isMaster {
		return nil
	}

	// Check if any nodes are offline
	status := MasterNode.GetNodeStatus()
	offlineCount := 0

	for _, node := range status {
		if node.Status == NodeStatusOffline {
			offlineCount++
		}
	}

	if offlineCount > 0 {
		return fmt.Errorf("%d nodes offline", offlineCount)
	}

	return nil
}

// ============================================================================
// REPAIR IMPLEMENTATIONS
// ============================================================================

func (arm *AutoRepairManager) repairDatabase() error {
	LogInfo("AUTO-REPAIR", "Repairing database...")

	// Run SQLite repair commands
	_, err := DB.db.Exec("VACUUM")
	if err != nil {
		return fmt.Errorf("vacuum failed: %w", err)
	}

	_, err = DB.db.Exec("REINDEX")
	if err != nil {
		return fmt.Errorf("reindex failed: %w", err)
	}

	return nil
}

func (arm *AutoRepairManager) backupDatabase() error {
	return DB.Backup("auto-repair-" + time.Now().Format("20060102-150405"))
}

func (arm *AutoRepairManager) verifyDatabase() error {
	return arm.checkDatabase()
}

func (arm *AutoRepairManager) restartXrayCore() error {
	LogInfo("AUTO-REPAIR", "Restarting Xray core...")

	if Protocols == nil {
		return fmt.Errorf("protocols not initialized")
	}

	core := Protocols.cores[CoreXray]
	if core == nil {
		return fmt.Errorf("xray core not found")
	}

	// Stop and restart using internal methods
	LogInfo("AUTO-REPAIR", "Restarting Xray core...")

	time.Sleep(2 * time.Second)

	// Use RestartCore which is public
	return Protocols.RestartCore(CoreXray)
}

func (arm *AutoRepairManager) verifyXrayCore() error {
	return arm.checkXrayCore()
}

func (arm *AutoRepairManager) repairConfiguration() error {
	LogInfo("AUTO-REPAIR", "Repairing configuration...")

	// Reload from file
	return ConfigMgr.Reload()
}

func (arm *AutoRepairManager) backupConfiguration() error {
	// Backup current config
	src := ConfigMgr.configPath
	dst := filepath.Join(RepairBackupDir, "config-"+time.Now().Format("20060102-150405")+".yaml")

	return copyFile(src, dst)
}

func (arm *AutoRepairManager) verifyConfiguration() error {
	return arm.checkConfiguration()
}

func (arm *AutoRepairManager) cleanDiskSpace() error {
	LogInfo("AUTO-REPAIR", "Cleaning disk space...")

	// Clean old logs
	cleanOldFiles("./Data/logs", 7*24*time.Hour)

	// Clean old backups
	cleanOldFiles("./Data/backups", 30*24*time.Hour)

	// Clean temp files
	cleanOldFiles("/tmp", 24*time.Hour)

	return nil
}

func (arm *AutoRepairManager) verifyDiskSpace() error {
	return arm.checkDiskSpace()
}

func (arm *AutoRepairManager) reconnectNodes() error {
	if MasterNode == nil || !MasterNode.isMaster {
		return nil
	}

	LogInfo("AUTO-REPAIR", "Attempting to reconnect nodes...")

	// Get all node statuses
	status := MasterNode.GetNodeStatus()
	reconnectedCount := 0
	failedCount := 0

	for _, nodeStatus := range status {
		// Only try to reconnect offline nodes
		if nodeStatus.Status != NodeStatusOffline {
			continue
		}

		LogInfo("AUTO-REPAIR", "Attempting to reconnect node: %s", nodeStatus.Name)

		// Get full node info from database
		node, err := arm.getNodeFromDB(nodeStatus.ID)
		if err != nil {
			LogError("AUTO-REPAIR", "Failed to get node %d from database: %v", nodeStatus.ID, err)
			failedCount++
			continue
		}

		// Attempt to ping the node
		if err := arm.pingNode(node); err != nil {
			LogWarn("AUTO-REPAIR", "Node %s is unreachable: %v", node.Name, err)
			failedCount++
			continue
		}

		// Node is reachable, mark as online
		// Actual syncing will happen via the SyncManager in nodes.go
		LogInfo("AUTO-REPAIR", "Node %s is reachable, marking as online", node.Name)

		// Update node status to online
		if err := arm.updateNodeStatus(node.ID, NodeStatusOnline); err != nil {
			LogWarn("AUTO-REPAIR", "Failed to update node status: %v", err)
		}

		LogInfo("AUTO-REPAIR", "Successfully reconnected node: %s", node.Name)
		reconnectedCount++
	}

	if failedCount > 0 {
		return fmt.Errorf("reconnected %d nodes, failed %d", reconnectedCount, failedCount)
	}

	LogInfo("AUTO-REPAIR", "Node reconnection complete: %d nodes reconnected", reconnectedCount)
	return nil
}

// Helper function to get node from database
func (arm *AutoRepairManager) getNodeFromDB(nodeID int64) (*Node, error) {
	query := `
		SELECT id, name, address, port, api_port, secret_key, is_active, status
		FROM nodes
		WHERE id = ?
	`

	var node Node
	err := Database.db.QueryRow(query, nodeID).Scan(
		&node.ID,
		&node.Name,
		&node.Address,
		&node.Port,
		&node.APIPort,
		&node.SecretKey,
		&node.IsActive,
		&node.Status,
	)

	if err != nil {
		return nil, err
	}

	return &node, nil
}

// Helper function to ping a node
func (arm *AutoRepairManager) pingNode(node *Node) error {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Build health check URL
	url := fmt.Sprintf("http://%s:%d/api/health", node.Address, node.APIPort)

	// Send request
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to reach node: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("node returned status %d", resp.StatusCode)
	}

	return nil
}

// Helper function to update node status
func (arm *AutoRepairManager) updateNodeStatus(nodeID int64, status string) error {
	query := `UPDATE nodes SET status = ?, last_seen = ? WHERE id = ?`
	_, err := Database.db.Exec(query, status, time.Now(), nodeID)
	return err
}

func (arm *AutoRepairManager) verifyNodes() error {
	return arm.checkNodes()
}

// ============================================================================
// UTILITIES
// ============================================================================

func (arm *AutoRepairManager) addEvent(event *RepairEvent) {
	arm.mu.Lock()
	defer arm.mu.Unlock()

	arm.history = append(arm.history, event)

	// Keep last 1000 events
	if len(arm.history) > 1000 {
		arm.history = arm.history[len(arm.history)-1000:]
	}
}

// GetHistory returns repair history
func (arm *AutoRepairManager) GetHistory(limit int) []*RepairEvent {
	arm.mu.RLock()
	defer arm.mu.RUnlock()

	if limit <= 0 || limit > len(arm.history) {
		limit = len(arm.history)
	}

	result := make([]*RepairEvent, limit)
	copy(result, arm.history[len(arm.history)-limit:])

	return result
}

// RepairLogger methods
func (rl *RepairLogger) Log(level, action, message string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	f, err := os.OpenFile(rl.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("[%s] [%s] %s: %s\n", timestamp, level, action, message)
	f.WriteString(line)
}

// Helper functions
func cleanOldFiles(dir string, maxAge time.Duration) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if !info.IsDir() && time.Since(info.ModTime()) > maxAge {
			os.Remove(path)
		}

		return nil
	})
}

func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	return os.WriteFile(dst, input, 0644)
}
