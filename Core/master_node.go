// MXUI VPN Panel
// Core/master_node.go
// Master-Node Architecture: Distributed Panel System

package core

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ============================================================================
// NODE TYPES & CONSTANTS
// ============================================================================

const (
	// Node types
	NodeTypeMaster = "master"
	NodeTypeNode   = "node"

	// Sync intervals (using existing from nodes.go)
	// NodeSyncPeriod, NodeHealthCheckPeriod, etc. defined in nodes.go

	// Master-specific constants
	MasterSyncInterval        = 60 * time.Second
	MasterHealthCheckInterval = 30 * time.Second
	MasterMetricsInterval     = 15 * time.Second

	// Master-specific statuses
	NodeStatusSyncing  = "syncing"
	NodeStatusDegraded = "degraded"
)

// ============================================================================
// MASTER-NODE MANAGER
// ============================================================================

// MasterNodeManager manages Master-Node architecture
type MasterNodeManager struct {
	isMaster  bool
	masterURL string
	nodes     map[int64]*ManagedNode
	syncToken string
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc

	// Database
	db *DatabaseManager

	// Channels
	syncChan   chan *NodeSyncRequest
	healthChan chan *NodeHealthCheck

	// Services
	syncService   *NodeSyncService
	healthService *NodeHealthService
	configService *NodeConfigService
}

// ManagedNode represents a managed node in the cluster
type ManagedNode struct {
	ID            int64              `json:"id"`
	Name          string             `json:"name"`
	Type          string             `json:"type"`
	Address       string             `json:"address"`
	Port          int                `json:"port"`
	APIPort       int                `json:"api_port"`
	SecretKey     string             `json:"secret_key"`
	SyncToken     string             `json:"sync_token"`
	Status        string             `json:"status"`
	LastSync      time.Time          `json:"last_sync"`
	LastHeartbeat time.Time          `json:"last_heartbeat"`
	Version       string             `json:"version"`
	Metrics       *NodeMetricsData   `json:"metrics,omitempty"`
	Config        *NodeConfiguration `json:"config,omitempty"`
	Enabled       bool               `json:"enabled"`
	Priority      int                `json:"priority"`
	Weight        int                `json:"weight"`
	Tags          []string           `json:"tags,omitempty"`
	CreatedAt     time.Time          `json:"created_at"`
	UpdatedAt     time.Time          `json:"updated_at"`
	mu            sync.RWMutex
}

// NodeMetricsData contains node performance metrics
type NodeMetricsData struct {
	CPU         float64   `json:"cpu_usage"`
	RAM         float64   `json:"ram_usage"`
	Disk        float64   `json:"disk_usage"`
	NetworkIn   int64     `json:"network_in"`
	NetworkOut  int64     `json:"network_out"`
	ActiveUsers int       `json:"active_users"`
	ActiveConns int       `json:"active_connections"`
	Uptime      int64     `json:"uptime"`
	LoadAvg     float64   `json:"load_avg"`
	CollectedAt time.Time `json:"collected_at"`
}

// NodeConfiguration contains node-specific configuration
type NodeConfiguration struct {
	Protocols []string               `json:"protocols"`
	Inbounds  []InboundConfig        `json:"inbounds"`
	Outbounds []OutboundConfig       `json:"outbounds"`
	Routing   *RoutingConfig         `json:"routing,omitempty"`
	DNS       *DNSConfig             `json:"dns,omitempty"`
	Settings  map[string]interface{} `json:"settings,omitempty"`
}

// NodeSyncRequest represents a sync request
type NodeSyncRequest struct {
	NodeID    int64       `json:"node_id"`
	Type      string      `json:"type"` // full, incremental, config
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// NodeHealthCheck represents a health check
type NodeHealthCheck struct {
	NodeID    int64     `json:"node_id"`
	Status    string    `json:"status"`
	Latency   int64     `json:"latency"`
	Errors    []string  `json:"errors,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Global Master-Node manager
var MasterNode *MasterNodeManager

// ============================================================================
// INITIALIZATION
// ============================================================================

// InitMasterNodeManager initializes the Master-Node manager
func InitMasterNodeManager(isMaster bool, masterURL string) error {
	ctx, cancel := context.WithCancel(context.Background())

	MasterNode = &MasterNodeManager{
		isMaster:   isMaster,
		masterURL:  masterURL,
		nodes:      make(map[int64]*ManagedNode),
		db:         DB,
		ctx:        ctx,
		cancel:     cancel,
		syncChan:   make(chan *NodeSyncRequest, 100),
		healthChan: make(chan *NodeHealthCheck, 100),
	}

	// Initialize services
	MasterNode.syncService = NewNodeSyncService()
	MasterNode.healthService = NewNodeHealthService()
	MasterNode.configService = NewNodeConfigService()

	if isMaster {
		// Master mode: manage nodes
		LogInfo("MASTER-NODE", "Starting in MASTER mode")

		// Load nodes from database
		if err := MasterNode.loadNodesFromDB(); err != nil {
			return fmt.Errorf("failed to load nodes: %w", err)
		}

		// Start master services
		go MasterNode.startMasterServices()

	} else {
		// Node mode: connect to master
		LogInfo("MASTER-NODE", "Starting in NODE mode, master: %s", masterURL)

		// Register with master
		if err := MasterNode.registerWithMaster(); err != nil {
			return fmt.Errorf("failed to register with master: %w", err)
		}

		// Start node services
		go MasterNode.startNodeServices()
	}

	return nil
}

// ============================================================================
// MASTER MODE SERVICES
// ============================================================================

// startMasterServices starts all master services
func (mnm *MasterNodeManager) startMasterServices() {
	LogInfo("MASTER", "Starting master services...")

	// Start sync service
	go mnm.syncService.Start(mnm.ctx, mnm)

	// Start health monitoring
	go mnm.healthService.Start(mnm.ctx, mnm)

	// Start config distribution
	go mnm.configService.Start(mnm.ctx, mnm)

	// Start sync processor
	go mnm.processSyncRequests()

	// Start health processor
	go mnm.processHealthChecks()

	LogSuccess("MASTER", "All master services started")
}

// AddNode adds a new node to the cluster (Master only)
func (mnm *MasterNodeManager) AddNode(node *ManagedNode) error {
	if !mnm.isMaster {
		return errors.New("only master can add nodes")
	}

	mnm.mu.Lock()
	defer mnm.mu.Unlock()

	// Generate sync token
	node.SyncToken = generateSyncToken()
	node.Status = NodeStatusOffline
	node.CreatedAt = time.Now()
	node.UpdatedAt = time.Now()

	// Save to database
	if err := mnm.saveNodeToDB(node); err != nil {
		return fmt.Errorf("failed to save node: %w", err)
	}

	mnm.nodes[node.ID] = node

	LogInfo("MASTER", "Node added: %s (%s)", node.Name, node.Address)
	return nil
}

// RemoveNode removes a node from the cluster (Master only)
func (mnm *MasterNodeManager) RemoveNode(nodeID int64) error {
	if !mnm.isMaster {
		return errors.New("only master can remove nodes")
	}

	mnm.mu.Lock()
	defer mnm.mu.Unlock()

	node, exists := mnm.nodes[nodeID]
	if !exists {
		return errors.New("node not found")
	}

	// Remove from database
	if err := mnm.deleteNodeFromDB(nodeID); err != nil {
		return fmt.Errorf("failed to delete node: %w", err)
	}

	delete(mnm.nodes, nodeID)

	LogInfo("MASTER", "Node removed: %s", node.Name)
	return nil
}

// SyncUserToNodes syncs a user to all nodes (Master only)
func (mnm *MasterNodeManager) SyncUserToNodes(user *User) error {
	if !mnm.isMaster {
		return errors.New("only master can sync users")
	}

	mnm.mu.RLock()
	defer mnm.mu.RUnlock()

	var errors []error

	for _, node := range mnm.nodes {
		if !node.Enabled || node.Status != NodeStatusOnline {
			continue
		}

		if err := mnm.syncUserToNode(node, user); err != nil {
			LogError("MASTER", "Failed to sync user %s to node %s: %v",
				user.Username, node.Name, err)
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to sync to %d nodes", len(errors))
	}

	return nil
}

// SyncProtocolChangesToNodes syncs protocol changes to all nodes
func (mnm *MasterNodeManager) SyncProtocolChangesToNodes(config interface{}) error {
	if !mnm.isMaster {
		return errors.New("only master can sync protocol changes")
	}

	mnm.mu.RLock()
	defer mnm.mu.RUnlock()

	syncReq := &NodeSyncRequest{
		Type:      "protocol_update",
		Data:      config,
		Timestamp: time.Now(),
	}

	var syncErrors []error

	for _, node := range mnm.nodes {
		if !node.Enabled || node.Status != NodeStatusOnline {
			continue
		}

		syncReq.NodeID = node.ID

		if err := mnm.sendSyncRequest(node, syncReq); err != nil {
			LogError("MASTER", "Failed to sync protocol to node %s: %v", node.Name, err)
			syncErrors = append(syncErrors, err)
		} else {
			LogInfo("MASTER", "Protocol synced to node %s", node.Name)
		}
	}

	if len(syncErrors) > 0 {
		return fmt.Errorf("failed to sync to %d nodes", len(syncErrors))
	}

	return nil
}

// GetNodeStatus returns status of all nodes
func (mnm *MasterNodeManager) GetNodeStatus() map[int64]*NodeStatus {
	mnm.mu.RLock()
	defer mnm.mu.RUnlock()

	status := make(map[int64]*NodeStatus)

	for id, node := range mnm.nodes {
		node.mu.RLock()
		status[id] = &NodeStatus{
			ID:            node.ID,
			Name:          node.Name,
			Address:       node.Address,
			Status:        node.Status,
			LastSync:      node.LastSync,
			LastHeartbeat: node.LastHeartbeat,
			Metrics:       node.Metrics,
			Enabled:       node.Enabled,
		}
		node.mu.RUnlock()
	}

	return status
}

// ============================================================================
// NODE MODE SERVICES
// ============================================================================

// startNodeServices starts all node services
func (mnm *MasterNodeManager) startNodeServices() {
	LogInfo("NODE", "Starting node services...")

	// Start heartbeat sender
	go mnm.sendHeartbeats()

	// Start sync receiver
	go mnm.receiveSyncFromMaster()

	// Start metrics reporter
	go mnm.reportMetricsToMaster()

	LogSuccess("NODE", "All node services started")
}

// registerWithMaster registers this node with the master
func (mnm *MasterNodeManager) registerWithMaster() error {
	// Get system info
	info := &NodeRegistrationInfo{
		Hostname:  getHostname(),
		IPAddress: getPublicIP(),
		Version:   Version,
		OS:        getOSInfo(),
		Arch:      getArchInfo(),
	}

	data, err := json.Marshal(info)
	if err != nil {
		return err
	}

	// Send registration request
	url := fmt.Sprintf("%s/api/node/register", mnm.masterURL)
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration failed with status: %d", resp.StatusCode)
	}

	// Parse response
	var result struct {
		Token  string `json:"token"`
		NodeID int64  `json:"node_id"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	mnm.syncToken = result.Token

	LogSuccess("NODE", "Registered with master, NodeID: %d", result.NodeID)
	return nil
}

// sendHeartbeats sends periodic heartbeats to master
func (mnm *MasterNodeManager) sendHeartbeats() {
	ticker := time.NewTicker(NodeHealthCheckPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-mnm.ctx.Done():
			return
		case <-ticker.C:
			if err := mnm.sendHeartbeat(); err != nil {
				LogError("NODE", "Failed to send heartbeat: %v", err)
			}
		}
	}
}

// sendHeartbeat sends a single heartbeat to master
func (mnm *MasterNodeManager) sendHeartbeat() error {
	heartbeat := &NodeHeartbeat{
		Timestamp: time.Now(),
		Status:    NodeStatusOnline,
		Metrics:   collectLocalMetrics(),
	}

	data, err := json.Marshal(heartbeat)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/api/node/heartbeat", mnm.masterURL)
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Token", mnm.syncToken)

	client := &http.Client{Timeout: NodeAPITimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat failed with status: %d", resp.StatusCode)
	}

	return nil
}

// receiveSyncFromMaster receives and applies sync from master
func (mnm *MasterNodeManager) receiveSyncFromMaster() {
	ticker := time.NewTicker(NodeSyncPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-mnm.ctx.Done():
			return
		case <-ticker.C:
			if err := mnm.pullSyncFromMaster(); err != nil {
				LogError("NODE", "Failed to pull sync: %v", err)
			}
		}
	}
}

// pullSyncFromMaster pulls latest sync from master
func (mnm *MasterNodeManager) pullSyncFromMaster() error {
	url := fmt.Sprintf("%s/api/node/sync", mnm.masterURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("X-Node-Token", mnm.syncToken)

	client := &http.Client{Timeout: NodeAPITimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		// No updates
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sync failed with status: %d", resp.StatusCode)
	}

	var syncData NodeSyncData
	if err := json.NewDecoder(resp.Body).Decode(&syncData); err != nil {
		return err
	}

	// Apply sync
	return mnm.applySyncData(&syncData)
}

// applySyncData applies sync data received from master
func (mnm *MasterNodeManager) applySyncData(data *NodeSyncData) error {
	LogInfo("NODE", "Applying sync data: type=%s", data.Type)

	switch data.Type {
	case "users":
		return mnm.syncUsers(data.Users)
	case "protocols":
		return mnm.syncProtocols(data.ProtocolConfig)
	case "config":
		return mnm.syncConfig(data.Config)
	case "full":
		// Full sync
		if err := mnm.syncUsers(data.Users); err != nil {
			return err
		}
		if err := mnm.syncProtocols(data.ProtocolConfig); err != nil {
			return err
		}
		return mnm.syncConfig(data.Config)
	default:
		return fmt.Errorf("unknown sync type: %s", data.Type)
	}
}

// reportMetricsToMaster reports metrics to master
func (mnm *MasterNodeManager) reportMetricsToMaster() {
	ticker := time.NewTicker(NodeMetricsPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-mnm.ctx.Done():
			return
		case <-ticker.C:
			metrics := collectLocalMetrics()
			if err := mnm.sendMetrics(metrics); err != nil {
				LogError("NODE", "Failed to send metrics: %v", err)
			}
		}
	}
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// generateSyncToken generates a secure sync token
func generateSyncToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// validateSyncToken validates a sync token
func validateSyncToken(token, secret string) bool {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(token))
	return hmac.Equal(h.Sum(nil), []byte(token))
}

// collectLocalMetrics collects local system metrics
func collectLocalMetrics() *NodeMetricsData {
	return &NodeMetricsData{
		CPU:         getCPUUsage(),
		RAM:         getRAMUsage(),
		Disk:        getDiskUsage(),
		NetworkIn:   getNetworkIn(),
		NetworkOut:  getNetworkOut(),
		ActiveUsers: getActiveUsersCount(),
		ActiveConns: getActiveConnectionsCount(),
		Uptime:      getSystemUptime(),
		LoadAvg:     getLoadAverage(),
		CollectedAt: time.Now(),
	}
}

// ====================================================================================
// DATABASE OPERATIONS
// ====================================================================================

// loadNodesFromDB loads all nodes from database
func (mnm *MasterNodeManager) loadNodesFromDB() error {
	if mnm.db == nil {
		return fmt.Errorf("database not initialized")
	}

	query := `
		SELECT id, name, address, port, secret_key, status, enabled,
		       last_heartbeat, created_at, updated_at
		FROM nodes
		WHERE deleted_at IS NULL
	`

	rows, err := mnm.db.db.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query nodes: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var node ManagedNode
		var lastHeartbeat sql.NullTime

		err := rows.Scan(
			&node.ID, &node.Name, &node.Address, &node.Port,
			&node.SecretKey, &node.Status, &node.Enabled,
			&lastHeartbeat, &node.CreatedAt, &node.UpdatedAt,
		)
		if err != nil {
			LogWarn("NODE", "Failed to scan node: %v", err)
			continue
		}

		if lastHeartbeat.Valid {
			node.LastHeartbeat = lastHeartbeat.Time
		}

		mnm.nodes[node.ID] = &node
		LogInfo("NODE", "Loaded node: %s (ID: %d)", node.Name, node.ID)
	}

	return rows.Err()
}

// saveNodeToDB saves or updates a node in database
func (mnm *MasterNodeManager) saveNodeToDB(node *ManagedNode) error {
	if mnm.db == nil {
		return fmt.Errorf("database not initialized")
	}

	if node.ID == 0 {
		// Insert new node
		query := `
			INSERT INTO nodes (name, address, port, secret_key, status, enabled, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`
		result, err := mnm.db.db.Exec(query,
			node.Name, node.Address, node.Port, node.SecretKey,
			node.Status, node.Enabled, time.Now(), time.Now(),
		)
		if err != nil {
			return fmt.Errorf("failed to insert node: %w", err)
		}

		id, _ := result.LastInsertId()
		node.ID = id
		LogInfo("NODE", "Created new node: %s (ID: %d)", node.Name, node.ID)
	} else {
		// Update existing node
		query := `
			UPDATE nodes
			SET name = ?, address = ?, port = ?, secret_key = ?,
			    status = ?, enabled = ?, last_heartbeat = ?, updated_at = ?
			WHERE id = ?
		`
		_, err := mnm.db.db.Exec(query,
			node.Name, node.Address, node.Port, node.SecretKey,
			node.Status, node.Enabled, node.LastHeartbeat, time.Now(),
			node.ID,
		)
		if err != nil {
			return fmt.Errorf("failed to update node: %w", err)
		}

		LogInfo("NODE", "Updated node: %s (ID: %d)", node.Name, node.ID)
	}

	return nil
}

// deleteNodeFromDB deletes a node from database (soft delete)
func (mnm *MasterNodeManager) deleteNodeFromDB(nodeID int64) error {
	if mnm.db == nil {
		return fmt.Errorf("database not initialized")
	}

	query := `UPDATE nodes SET deleted_at = ?, updated_at = ? WHERE id = ?`
	_, err := mnm.db.db.Exec(query, time.Now(), time.Now(), nodeID)
	if err != nil {
		return fmt.Errorf("failed to delete node: %w", err)
	}

	LogInfo("NODE", "Deleted node ID: %d", nodeID)
	return nil
}

// ====================================================================================
// NODE SYNCHRONIZATION
// ====================================================================================

// syncUserToNode synchronizes a user to a specific node
func (mnm *MasterNodeManager) syncUserToNode(node *ManagedNode, user *User) error {
	req := &NodeSyncRequest{
		Type: "user_sync",
		Data: &NodeSyncData{
			Type:      "users",
			Users:     []*User{user},
			Timestamp: time.Now(),
		},
	}

	return mnm.sendSyncRequest(node, req)
}

// sendSyncRequest sends a sync request to a node
func (mnm *MasterNodeManager) sendSyncRequest(node *ManagedNode, req *NodeSyncRequest) error {
	url := fmt.Sprintf("http://%s:%d/api/v1/node/sync", node.Address, node.Port)

	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication header
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Node-Secret", node.SecretKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("node returned status %d: %s", resp.StatusCode, string(body))
	}

	LogInfo("NODE", "Synced to node %s: %s", node.Name, req.Type)
	return nil
}

// processSyncRequests processes pending sync requests
func (mnm *MasterNodeManager) processSyncRequests() {
	mnm.mu.RLock()
	nodes := make([]*ManagedNode, 0, len(mnm.nodes))
	for _, node := range mnm.nodes {
		if node.Enabled && node.Status == NodeStatusOnline {
			nodes = append(nodes, node)
		}
	}
	mnm.mu.RUnlock()

	// Get all active users
	users, err := mnm.getAllActiveUsers()
	if err != nil {
		LogError("NODE", "Failed to get users for sync: %v", err)
		return
	}

	// Sync users to all active nodes
	for _, node := range nodes {
		if err := mnm.syncUsers(users); err != nil {
			LogError("NODE", "Failed to sync users to node %s: %v", node.Name, err)
		}
	}
}

// processHealthChecks checks health of all nodes
func (mnm *MasterNodeManager) processHealthChecks() {
	mnm.mu.RLock()
	nodes := make([]*ManagedNode, 0, len(mnm.nodes))
	for _, node := range mnm.nodes {
		if node.Enabled {
			nodes = append(nodes, node)
		}
	}
	mnm.mu.RUnlock()

	for _, node := range nodes {
		// Check if heartbeat is recent (within last 60 seconds)
		if time.Since(node.LastHeartbeat) > 60*time.Second {
			// Mark as offline
			mnm.mu.Lock()
			node.Status = NodeStatusOffline
			mnm.mu.Unlock()

			mnm.saveNodeToDB(node)
			LogWarn("NODE", "Node %s marked offline (no heartbeat)", node.Name)
		}
	}
}

// syncUsers syncs all users to nodes
func (mnm *MasterNodeManager) syncUsers(users []*User) error {
	mnm.mu.RLock()
	defer mnm.mu.RUnlock()

	for _, node := range mnm.nodes {
		if !node.Enabled || node.Status != NodeStatusOnline {
			continue
		}

		req := &NodeSyncRequest{
			Type: "users",
			Data: &NodeSyncData{
				Type:      "users",
				Users:     users,
				Timestamp: time.Now(),
			},
		}

		if err := mnm.sendSyncRequest(node, req); err != nil {
			LogError("NODE", "Failed to sync users to %s: %v", node.Name, err)
		}
	}

	return nil
}

// syncProtocols syncs protocol configuration to all nodes
func (mnm *MasterNodeManager) syncProtocols(config interface{}) error {
	mnm.mu.RLock()
	defer mnm.mu.RUnlock()

	for _, node := range mnm.nodes {
		if !node.Enabled || node.Status != NodeStatusOnline {
			continue
		}

		req := &NodeSyncRequest{
			Type: "protocols",
			Data: &NodeSyncData{
				Type:           "protocols",
				ProtocolConfig: config,
				Timestamp:      time.Now(),
			},
		}

		if err := mnm.sendSyncRequest(node, req); err != nil {
			LogError("NODE", "Failed to sync protocols to %s: %v", node.Name, err)
		}
	}

	return nil
}

// syncConfig syncs general configuration to all nodes
func (mnm *MasterNodeManager) syncConfig(config interface{}) error {
	mnm.mu.RLock()
	defer mnm.mu.RUnlock()

	for _, node := range mnm.nodes {
		if !node.Enabled || node.Status != NodeStatusOnline {
			continue
		}

		req := &NodeSyncRequest{
			Type: "config",
			Data: &NodeSyncData{
				Type:      "config",
				Config:    config,
				Timestamp: time.Now(),
			},
		}

		if err := mnm.sendSyncRequest(node, req); err != nil {
			LogError("NODE", "Failed to sync config to %s: %v", node.Name, err)
		}
	}

	return nil
}

// sendMetrics sends node metrics (not used by master)
func (mnm *MasterNodeManager) sendMetrics(metrics *NodeMetricsData) error {
	// This is only used by agent nodes, not master
	return nil
}

// getAllActiveUsers gets all active users from database
func (mnm *MasterNodeManager) getAllActiveUsers() ([]*User, error) {
	if mnm.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	query := `
		SELECT id, username, email, is_active, expiry_time
		FROM users
		WHERE is_active = 1 AND (expiry_time IS NULL OR expiry_time > ?)
	`

	rows, err := mnm.db.db.Query(query, time.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var user User
		var expiryTime sql.NullTime

		err := rows.Scan(
			&user.ID, &user.Username, &user.Email,
			&user.IsActive, &expiryTime,
		)
		if err != nil {
			continue
		}

		if expiryTime.Valid {
			user.ExpiryTime = &expiryTime.Time
		}

		users = append(users, &user)
	}

	return users, rows.Err()
}

// ====================================================================================
// SYSTEM INFO FUNCTIONS
// ====================================================================================

// getHostname returns system hostname
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// getPublicIP returns public IP address
func getPublicIP() string {
	// Try to get from external service
	resp, err := http.Get("https://api.ipify.org?format=text")
	if err != nil {
		return "0.0.0.0"
	}
	defer resp.Body.Close()

	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return "0.0.0.0"
	}

	return string(ip)
}

// getOSInfo returns OS information
func getOSInfo() string {
	return runtime.GOOS
}

// getArchInfo returns architecture information
func getArchInfo() string {
	return runtime.GOARCH
}

// getCPUUsage returns CPU usage percentage
func getCPUUsage() float64 {
	// Read /proc/stat for CPU usage (Linux only)
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0.0
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 8 {
				return 0.0
			}

			user, _ := strconv.ParseFloat(fields[1], 64)
			nice, _ := strconv.ParseFloat(fields[2], 64)
			system, _ := strconv.ParseFloat(fields[3], 64)
			idle, _ := strconv.ParseFloat(fields[4], 64)

			total := user + nice + system + idle
			used := user + nice + system

			if total == 0 {
				return 0.0
			}

			return (used / total) * 100
		}
	}

	return 0.0
}

// getRAMUsage returns RAM usage percentage
func getRAMUsage() float64 {
	// Read /proc/meminfo (Linux only)
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0.0
	}

	var memTotal, memAvailable float64
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		if strings.HasPrefix(line, "MemTotal:") {
			memTotal, _ = strconv.ParseFloat(fields[1], 64)
		} else if strings.HasPrefix(line, "MemAvailable:") {
			memAvailable, _ = strconv.ParseFloat(fields[1], 64)
		}
	}

	if memTotal == 0 {
		return 0.0
	}

	memUsed := memTotal - memAvailable
	return (memUsed / memTotal) * 100
}

// getDiskUsage returns disk usage percentage
func getDiskUsage() float64 {
	// Check root filesystem
	var stat syscall.Statfs_t
	err := syscall.Statfs("/", &stat)
	if err != nil {
		return 0.0
	}

	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used := total - free

	if total == 0 {
		return 0.0
	}

	return (float64(used) / float64(total)) * 100
}

// getNetworkIn returns network bytes received
func getNetworkIn() int64 {
	// Read /proc/net/dev (Linux only)
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0
	}

	var totalBytes int64
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		if !strings.Contains(line, ":") {
			continue
		}

		// Skip loopback
		if strings.Contains(line, "lo:") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 2 {
			bytes, _ := strconv.ParseInt(fields[1], 10, 64)
			totalBytes += bytes
		}
	}

	return totalBytes
}

// getNetworkOut returns network bytes transmitted
func getNetworkOut() int64 {
	// Read /proc/net/dev (Linux only)
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0
	}

	var totalBytes int64
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		if !strings.Contains(line, ":") {
			continue
		}

		// Skip loopback
		if strings.Contains(line, "lo:") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 10 {
			bytes, _ := strconv.ParseInt(fields[9], 10, 64)
			totalBytes += bytes
		}
	}

	return totalBytes
}

// getActiveUsersCount returns number of active users (requires DB access)
func getActiveUsersCount() int {
	if DB == nil {
		return 0
	}

	var count int
	query := `SELECT COUNT(*) FROM users WHERE is_active = 1`
	DB.db.QueryRow(query).Scan(&count)

	return count
}

// getActiveConnectionsCount returns number of active connections
func getActiveConnectionsCount() int {
	// This would require integration with VPN core stats
	// For now, return 0
	return 0
}

// getSystemUptime returns system uptime in seconds
func getSystemUptime() int64 {
	// Read /proc/uptime (Linux only)
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}

	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0
	}

	uptime, _ := strconv.ParseFloat(fields[0], 64)
	return int64(uptime)
}

// getLoadAverage returns system load average (1 minute)
func getLoadAverage() float64 {
	// Read /proc/loadavg (Linux only)
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0.0
	}

	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0.0
	}

	load, _ := strconv.ParseFloat(fields[0], 64)
	return load
}

// Supporting types
type NodeStatus struct {
	ID            int64            `json:"id"`
	Name          string           `json:"name"`
	Address       string           `json:"address"`
	Status        string           `json:"status"`
	LastSync      time.Time        `json:"last_sync"`
	LastHeartbeat time.Time        `json:"last_heartbeat"`
	Metrics       *NodeMetricsData `json:"metrics,omitempty"`
	Enabled       bool             `json:"enabled"`
}

type NodeRegistrationInfo struct {
	Hostname  string `json:"hostname"`
	IPAddress string `json:"ip_address"`
	Version   string `json:"version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

type NodeHeartbeat struct {
	Timestamp time.Time        `json:"timestamp"`
	Status    string           `json:"status"`
	Metrics   *NodeMetricsData `json:"metrics"`
}

type NodeSyncData struct {
	Type           string      `json:"type"`
	Users          []*User     `json:"users,omitempty"`
	ProtocolConfig interface{} `json:"protocol_config,omitempty"`
	Config         interface{} `json:"config,omitempty"`
	Timestamp      time.Time   `json:"timestamp"`
}

// Service stubs
type NodeSyncService struct{}

func NewNodeSyncService() *NodeSyncService                                   { return &NodeSyncService{} }
func (s *NodeSyncService) Start(ctx context.Context, mnm *MasterNodeManager) {}

type NodeHealthService struct{}

func NewNodeHealthService() *NodeHealthService                                 { return &NodeHealthService{} }
func (s *NodeHealthService) Start(ctx context.Context, mnm *MasterNodeManager) {}

type NodeConfigService struct{}

func NewNodeConfigService() *NodeConfigService                                 { return &NodeConfigService{} }
func (s *NodeConfigService) Start(ctx context.Context, mnm *MasterNodeManager) {}
