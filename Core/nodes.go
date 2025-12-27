// MXUI VPN Panel
// Core/nodes.go
// Node Management: CRUD, Health Check, Sync, Load Balancer, Failover, Metrics

package core

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// CONSTANTS
// ============================================================================

const (
	// Node connection
	NodeAPITimeout        = 10 * time.Second
	NodeHealthCheckPeriod = 30 * time.Second
	NodeSyncPeriod        = 60 * time.Second
	NodeMetricsPeriod     = 15 * time.Second

	// Health check thresholds
	HealthCheckMaxRetries   = 3
	HealthCheckRetryDelay   = 5 * time.Second
	HealthCheckCriticalCPU  = 90.0
	HealthCheckCriticalRAM  = 90.0
	HealthCheckCriticalDisk = 95.0
	HealthCheckWarningCPU   = 70.0
	HealthCheckWarningRAM   = 70.0
	HealthCheckWarningDisk  = 80.0

	// Load balancer strategies
	LoadBalanceRoundRobin  = "round_robin"
	LoadBalanceLeastLoad   = "least_load"
	LoadBalanceLeastUsers  = "least_users"
	LoadBalanceRandom      = "random"
	LoadBalanceWeighted    = "weighted"
	LoadBalanceGeoLocation = "geo_location"

	// Failover settings
	FailoverMaxAttempts   = 3
	FailoverCooldown      = 5 * time.Minute
	FailoverCheckInterval = 10 * time.Second

	// API endpoints
	NodeAPIHealthPath  = "/api/health"
	NodeAPIMetricsPath = "/api/metrics"
	NodeAPISyncPath    = "/api/sync"
	NodeAPIUsersPath   = "/api/users"
	NodeAPIConfigPath  = "/api/config"
	NodeAPIRestartPath = "/api/restart"
	NodeAPITrafficPath = "/api/traffic"

	// Node types - defined in master_node.go
	// NodeTypeMaster, NodeTypeNode
	NodeSyncEndpoint = "/api/node/sync"
)

// ============================================================================
// NODE MANAGER
// ============================================================================

// NodeManager manages all node operations
type NodeManager struct {
	nodes            map[int64]*NodeInfo
	mainNode         *NodeInfo
	healthChecker    *HealthChecker
	loadBalancer     *NodeLoadBalancer
	syncManager      *SyncManager
	failoverManager  *FailoverManager
	metricsCollector *MetricsCollector
	config           NodesConfig
	mu               sync.RWMutex
	ctx              context.Context
	cancel           context.CancelFunc
	isRunning        bool
}

// NodeInfo extends Node with runtime information
type NodeInfo struct {
	*Node
	Client          *NodeAPIClient
	HealthStatus    *HealthStatus
	Metrics         *NodeMetrics
	LastSync        time.Time
	LastHealthCheck time.Time
	FailCount       int
	NodeType        string `json:"node_type"` // master, slave
	MasterAddress   string `json:"master_address,omitempty"`
	SyncInterval    int    `json:"sync_interval"` // seconds
	SyncToken       string `json:"sync_token"`
	IsAvailable     bool
	mu              sync.RWMutex
}

// HealthStatus represents node health status
type HealthStatus struct {
	Status      string    `json:"status"`  // healthy, degraded, unhealthy, unknown
	Latency     int64     `json:"latency"` // milliseconds
	CheckTime   time.Time `json:"check_time"`
	Message     string    `json:"message,omitempty"`
	Warnings    []string  `json:"warnings,omitempty"`
	Errors      []string  `json:"errors,omitempty"`
	CoreRunning bool      `json:"core_running"`
	APIRunning  bool      `json:"api_running"`
}

// NodeMetrics represents node performance metrics
type NodeMetrics struct {
	CPUUsage      float64   `json:"cpu_usage"`
	CPUCores      int       `json:"cpu_cores"`
	RAMUsage      float64   `json:"ram_usage"`
	RAMTotal      int64     `json:"ram_total"`
	RAMUsed       int64     `json:"ram_used"`
	DiskUsage     float64   `json:"disk_usage"`
	DiskTotal     int64     `json:"disk_total"`
	DiskUsed      int64     `json:"disk_used"`
	NetworkIn     int64     `json:"network_in"`     // bytes per second
	NetworkOut    int64     `json:"network_out"`    // bytes per second
	TotalUpload   int64     `json:"total_upload"`   // total bytes
	TotalDownload int64     `json:"total_download"` // total bytes
	ActiveUsers   int       `json:"active_users"`
	ActiveConns   int       `json:"active_connections"`
	Uptime        int64     `json:"uptime"` // seconds
	LoadAvg1      float64   `json:"load_avg_1"`
	LoadAvg5      float64   `json:"load_avg_5"`
	LoadAvg15     float64   `json:"load_avg_15"`
	TCPConns      int       `json:"tcp_connections"`
	UDPConns      int       `json:"udp_connections"`
	CollectedAt   time.Time `json:"collected_at"`
}

// Global node manager instance
var Nodes *NodeManager

// InitNodeManager initializes the node manager
func InitNodeManager(config *Config) error {
	ctx, cancel := context.WithCancel(context.Background())

	Nodes = &NodeManager{
		nodes:  make(map[int64]*NodeInfo),
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize components
	Nodes.healthChecker = NewHealthChecker(config.Nodes)
	Nodes.loadBalancer = NewNodeLoadBalancer(config.Nodes)
	Nodes.syncManager = NewSyncManager()
	Nodes.failoverManager = NewFailoverManager(config.Nodes)
	Nodes.metricsCollector = NewMetricsCollector()

	// Load nodes from database
	if err := Nodes.loadFromDB(); err != nil {
		return err
	}

	return nil
}

// Start starts the node manager
func (nm *NodeManager) Start() error {
	nm.mu.Lock()
	if nm.isRunning {
		nm.mu.Unlock()
		return nil
	}
	nm.isRunning = true
	nm.mu.Unlock()

	// Start health checker
	go nm.healthChecker.Start(nm.ctx, nm)

	// Start metrics collector
	go nm.metricsCollector.Start(nm.ctx, nm)

	// Start sync manager
	go nm.syncManager.Start(nm.ctx, nm)

	// Start failover manager
	go nm.failoverManager.Start(nm.ctx, nm)

	return nil
}

// Stop stops the node manager
func (nm *NodeManager) Stop() {
	nm.mu.Lock()
	nm.isRunning = false
	nm.mu.Unlock()

	nm.cancel()
}

// loadFromDB loads nodes from database
func (nm *NodeManager) loadFromDB() error {
	rows, err := DB.db.Query(`
		SELECT id, name, address, port, api_port, secret_key, status, is_active,
		       is_main_node, cpu_usage, ram_usage, disk_usage, network_in, network_out,
		       total_upload, total_download, active_users, protocols, traffic_ratio,
		       last_check, last_error, uptime, location, flag, created_at, updated_at
		FROM nodes
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	nm.mu.Lock()
	defer nm.mu.Unlock()

	for rows.Next() {
		node := &Node{}
		var protocols string

		err := rows.Scan(
			&node.ID, &node.Name, &node.Address, &node.Port, &node.APIPort,
			&node.SecretKey, &node.Status, &node.IsActive, &node.IsMainNode,
			&node.CPUUsage, &node.RAMUsage, &node.DiskUsage, &node.NetworkIn,
			&node.NetworkOut, &node.TotalUpload, &node.TotalDownload,
			&node.ActiveUsers, &protocols, &node.TrafficRatio, &node.LastCheck,
			&node.LastError, &node.Uptime, &node.Location, &node.Flag,
			&node.CreatedAt, &node.UpdatedAt,
		)
		if err != nil {
			continue
		}

		node.Protocols = JSONToStringSlice(protocols)

		nodeInfo := &NodeInfo{
			Node:         node,
			IsAvailable:  node.IsActive && node.Status == NodeStatusOnline,
			HealthStatus: &HealthStatus{Status: "unknown"},
			Metrics:      &NodeMetrics{},
		}

		// Create API client
		nodeInfo.Client = NewNodeAPIClient(node)

		nm.nodes[node.ID] = nodeInfo

		if node.IsMainNode {
			nm.mainNode = nodeInfo
		}
	}

	return nil
}

// ============================================================================
// NODE CRUD OPERATIONS
// ============================================================================

// CreateNodeRequest represents a request to create a node
type CreateNodeRequest struct {
	Name         string   `json:"name"`
	Address      string   `json:"address"`
	Port         int      `json:"port"`
	APIPort      int      `json:"api_port"`
	SecretKey    string   `json:"secret_key,omitempty"`
	IsMainNode   bool     `json:"is_main_node"`
	Protocols    []string `json:"protocols,omitempty"`
	TrafficRatio float64  `json:"traffic_ratio"`
	Location     string   `json:"location,omitempty"`
	Flag         string   `json:"flag,omitempty"`
}

// CreateNode creates a new node
func (nm *NodeManager) CreateNode(req *CreateNodeRequest) (*Node, error) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	// Validate address
	if req.Address == "" {
		return nil, errors.New("address is required")
	}

	// Validate port
	if req.Port <= 0 || req.Port > 65535 {
		return nil, errors.New("invalid port")
	}

	if req.APIPort <= 0 || req.APIPort > 65535 {
		req.APIPort = 62050 // Default API port
	}

	// Generate secret key if not provided
	if req.SecretKey == "" {
		req.SecretKey = generateSecureToken(32)
	}

	// Default traffic ratio
	if req.TrafficRatio <= 0 {
		req.TrafficRatio = 1.0
	}

	// Default protocols
	if len(req.Protocols) == 0 {
		req.Protocols = []string{ProtocolVMess, ProtocolVLESS, ProtocolTrojan}
	}

	now := time.Now()

	// If this is main node, unset other main nodes
	if req.IsMainNode {
		DB.db.Exec("UPDATE nodes SET is_main_node = 0 WHERE is_main_node = 1")
	}

	// Insert into database
	result, err := DB.db.Exec(`
		INSERT INTO nodes (
			name, address, port, api_port, secret_key, status, is_active,
			is_main_node, protocols, traffic_ratio, location, flag,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
	`,
		req.Name, req.Address, req.Port, req.APIPort, req.SecretKey,
		NodeStatusOffline, req.IsMainNode, StringSliceToJSON(req.Protocols),
		req.TrafficRatio, req.Location, req.Flag, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create node: %w", err)
	}

	nodeID, _ := result.LastInsertId()

	node := &Node{
		ID:           nodeID,
		Name:         req.Name,
		Address:      req.Address,
		Port:         req.Port,
		APIPort:      req.APIPort,
		SecretKey:    req.SecretKey,
		Status:       NodeStatusOffline,
		IsActive:     true,
		IsMainNode:   req.IsMainNode,
		Protocols:    req.Protocols,
		TrafficRatio: req.TrafficRatio,
		Location:     req.Location,
		Flag:         req.Flag,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	nodeInfo := &NodeInfo{
		Node:         node,
		IsAvailable:  false,
		HealthStatus: &HealthStatus{Status: "unknown"},
		Metrics:      &NodeMetrics{},
		Client:       NewNodeAPIClient(node),
	}

	nm.nodes[nodeID] = nodeInfo

	if req.IsMainNode {
		nm.mainNode = nodeInfo
	}

	// Trigger initial health check
	go nm.healthChecker.CheckNode(nodeInfo)

	return node, nil
}

// UpdateNodeRequest represents a request to update a node
type UpdateNodeRequest struct {
	Name         *string  `json:"name,omitempty"`
	Address      *string  `json:"address,omitempty"`
	Port         *int     `json:"port,omitempty"`
	APIPort      *int     `json:"api_port,omitempty"`
	SecretKey    *string  `json:"secret_key,omitempty"`
	IsActive     *bool    `json:"is_active,omitempty"`
	IsMainNode   *bool    `json:"is_main_node,omitempty"`
	Protocols    []string `json:"protocols,omitempty"`
	TrafficRatio *float64 `json:"traffic_ratio,omitempty"`
	Location     *string  `json:"location,omitempty"`
	Flag         *string  `json:"flag,omitempty"`
}

// UpdateNode updates a node
func (nm *NodeManager) UpdateNode(id int64, req *UpdateNodeRequest) (*Node, error) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	nodeInfo, exists := nm.nodes[id]
	if !exists {
		return nil, errors.New("node not found")
	}

	node := nodeInfo.Node

	// Build update query
	updates := []string{}
	args := []interface{}{}

	if req.Name != nil {
		updates = append(updates, "name = ?")
		args = append(args, *req.Name)
		node.Name = *req.Name
	}

	if req.Address != nil {
		updates = append(updates, "address = ?")
		args = append(args, *req.Address)
		node.Address = *req.Address
	}

	if req.Port != nil {
		updates = append(updates, "port = ?")
		args = append(args, *req.Port)
		node.Port = *req.Port
	}

	if req.APIPort != nil {
		updates = append(updates, "api_port = ?")
		args = append(args, *req.APIPort)
		node.APIPort = *req.APIPort
	}

	if req.SecretKey != nil {
		updates = append(updates, "secret_key = ?")
		args = append(args, *req.SecretKey)
		node.SecretKey = *req.SecretKey
	}

	if req.IsActive != nil {
		updates = append(updates, "is_active = ?")
		args = append(args, *req.IsActive)
		node.IsActive = *req.IsActive
		nodeInfo.IsAvailable = *req.IsActive && node.Status == NodeStatusOnline
	}

	if req.IsMainNode != nil && *req.IsMainNode {
		// Unset other main nodes
		DB.db.Exec("UPDATE nodes SET is_main_node = 0 WHERE is_main_node = 1")
		updates = append(updates, "is_main_node = ?")
		args = append(args, true)
		node.IsMainNode = true
		nm.mainNode = nodeInfo
	}

	if req.Protocols != nil {
		updates = append(updates, "protocols = ?")
		args = append(args, StringSliceToJSON(req.Protocols))
		node.Protocols = req.Protocols
	}

	if req.TrafficRatio != nil {
		updates = append(updates, "traffic_ratio = ?")
		args = append(args, *req.TrafficRatio)
		node.TrafficRatio = *req.TrafficRatio
	}

	if req.Location != nil {
		updates = append(updates, "location = ?")
		args = append(args, *req.Location)
		node.Location = *req.Location
	}

	if req.Flag != nil {
		updates = append(updates, "flag = ?")
		args = append(args, *req.Flag)
		node.Flag = *req.Flag
	}

	if len(updates) == 0 {
		return node, nil
	}

	updates = append(updates, "updated_at = ?")
	args = append(args, time.Now())
	args = append(args, id)

	query := fmt.Sprintf("UPDATE nodes SET %s WHERE id = ?", strings.Join(updates, ", "))
	_, err := DB.db.Exec(query, args...)
	if err != nil {
		return nil, err
	}

	// Recreate client if connection params changed
	if req.Address != nil || req.Port != nil || req.APIPort != nil || req.SecretKey != nil {
		nodeInfo.Client = NewNodeAPIClient(node)
	}

	return node, nil
}

// DeleteNode deletes a node
func (nm *NodeManager) DeleteNode(id int64) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	nodeInfo, exists := nm.nodes[id]
	if !exists {
		return errors.New("node not found")
	}

	// Cannot delete main node if it's the only one
	if nodeInfo.Node.IsMainNode && len(nm.nodes) > 1 {
		// Find another node to make main
		for nodeID, info := range nm.nodes {
			if nodeID != id {
				DB.db.Exec("UPDATE nodes SET is_main_node = 1 WHERE id = ?", nodeID)
				info.Node.IsMainNode = true
				nm.mainNode = info
				break
			}
		}
	}

	// Delete from database
	_, err := DB.db.Exec("DELETE FROM nodes WHERE id = ?", id)
	if err != nil {
		return err
	}

	// Remove inbounds and outbounds for this node
	DB.db.Exec("DELETE FROM inbounds WHERE node_id = ?", id)
	DB.db.Exec("DELETE FROM outbounds WHERE node_id = ?", id)
	DB.db.Exec("DELETE FROM routing_rules WHERE node_id = ?", id)

	delete(nm.nodes, id)

	if nm.mainNode != nil && nm.mainNode.Node.ID == id {
		nm.mainNode = nil
	}

	return nil
}

// GetNode retrieves a node by ID
func (nm *NodeManager) GetNode(id int64) (*NodeInfo, error) {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	nodeInfo, exists := nm.nodes[id]
	if !exists {
		return nil, errors.New("node not found")
	}

	return nodeInfo, nil
}

// GetMainNode returns the main node
func (nm *NodeManager) GetMainNode() *NodeInfo {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	return nm.mainNode
}

// ListNodes returns all nodes
func (nm *NodeManager) ListNodes() []*NodeInfo {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	nodes := make([]*NodeInfo, 0, len(nm.nodes))
	for _, node := range nm.nodes {
		nodes = append(nodes, node)
	}

	// Sort by ID
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Node.ID < nodes[j].Node.ID
	})

	return nodes
}

// GetAvailableNodes returns nodes that are available for connections
func (nm *NodeManager) GetAvailableNodes() []*NodeInfo {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	nodes := []*NodeInfo{}
	for _, node := range nm.nodes {
		if node.IsAvailable && node.Node.IsActive {
			nodes = append(nodes, node)
		}
	}

	return nodes
}

// GetNodesByProtocol returns nodes that support a specific protocol
func (nm *NodeManager) GetNodesByProtocol(protocol string) []*NodeInfo {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	nodes := []*NodeInfo{}
	for _, node := range nm.nodes {
		if !node.IsAvailable {
			continue
		}

		for _, p := range node.Node.Protocols {
			if p == protocol {
				nodes = append(nodes, node)
				break
			}
		}
	}

	return nodes
}

// ============================================================================
// NODE API CLIENT
// ============================================================================

// NodeAPIClient handles communication with remote nodes
type NodeAPIClient struct {
	node       *Node
	httpClient *http.Client
	baseURL    string
}

// NewNodeAPIClient creates a new node API client
func NewNodeAPIClient(node *Node) *NodeAPIClient {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // For self-signed certs
		},
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  false,
		MaxIdleConnsPerHost: 5,
	}

	return &NodeAPIClient{
		node: node,
		httpClient: &http.Client{
			Timeout:   NodeAPITimeout,
			Transport: transport,
		},
		baseURL: fmt.Sprintf("http://%s:%d", node.Address, node.APIPort),
	}
}

// signRequest signs a request with HMAC
func (c *NodeAPIClient) signRequest(method, path string, body []byte) string {
	timestamp := time.Now().Unix()
	data := fmt.Sprintf("%s:%s:%d:%s", method, path, timestamp, string(body))

	h := hmac.New(sha256.New, []byte(c.node.SecretKey))
	h.Write([]byte(data))
	signature := hex.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%d:%s", timestamp, signature)
}

// doRequest performs an authenticated request
func (c *NodeAPIClient) doRequest(method, path string, body interface{}) (*http.Response, error) {
	var bodyBytes []byte
	var err error

	if body != nil {
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}

	url := c.baseURL + path
	req, err := http.NewRequest(method, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Auth", c.signRequest(method, path, bodyBytes))
	req.Header.Set("X-Node-ID", fmt.Sprintf("%d", c.node.ID))

	return c.httpClient.Do(req)
}

// HealthCheck performs a health check on the node
func (c *NodeAPIClient) HealthCheck() (*HealthStatus, time.Duration, error) {
	start := time.Now()

	resp, err := c.doRequest("GET", NodeAPIHealthPath, nil)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	latency := time.Since(start)

	if resp.StatusCode != http.StatusOK {
		return nil, latency, fmt.Errorf("health check failed: status %d", resp.StatusCode)
	}

	var status HealthStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, latency, err
	}

	status.Latency = latency.Milliseconds()
	status.CheckTime = time.Now()

	return &status, latency, nil
}

// GetMetrics retrieves metrics from the node
func (c *NodeAPIClient) GetMetrics() (*NodeMetrics, error) {
	resp, err := c.doRequest("GET", NodeAPIMetricsPath, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get metrics: status %d", resp.StatusCode)
	}

	var metrics NodeMetrics
	if err := json.NewDecoder(resp.Body).Decode(&metrics); err != nil {
		return nil, err
	}

	metrics.CollectedAt = time.Now()
	return &metrics, nil
}

// SyncConfig syncs configuration to the node
func (c *NodeAPIClient) SyncConfig(config interface{}) error {
	resp, err := c.doRequest("POST", NodeAPISyncPath, config)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("sync failed: %s", string(body))
	}

	return nil
}

// SyncUsers syncs users to the node
func (c *NodeAPIClient) SyncUsers(users []*User) error {
	resp, err := c.doRequest("POST", NodeAPIUsersPath, users)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("user sync failed: %s", string(body))
	}

	return nil
}

// RestartCore restarts the core on the node
func (c *NodeAPIClient) RestartCore() error {
	resp, err := c.doRequest("POST", NodeAPIRestartPath, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("restart failed: status %d", resp.StatusCode)
	}

	return nil
}

// GetTrafficStats retrieves traffic statistics from the node
func (c *NodeAPIClient) GetTrafficStats() (map[string]*TrafficStats, error) {
	resp, err := c.doRequest("GET", NodeAPITrafficPath, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get traffic: status %d", resp.StatusCode)
	}

	var stats map[string]*TrafficStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, err
	}

	return stats, nil
}

// TrafficStats represents traffic statistics for a user
type TrafficStats struct {
	UserID   int64 `json:"user_id"`
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
}

// Ping checks if the node is reachable
func (c *NodeAPIClient) Ping() (time.Duration, error) {
	start := time.Now()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", c.node.Address, c.node.APIPort), 5*time.Second)
	if err != nil {
		return 0, err
	}
	conn.Close()

	return time.Since(start), nil
}

// ============================================================================
// HEALTH CHECKER
// ============================================================================

// HealthChecker manages node health checks
type HealthChecker struct {
	config   NodesConfig
	interval time.Duration
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(config NodesConfig) *HealthChecker {
	interval := time.Duration(config.HealthCheckInterval) * time.Second
	if interval == 0 {
		interval = NodeHealthCheckPeriod
	}

	return &HealthChecker{
		config:   config,
		interval: interval,
	}
}

// Start starts the health checker
func (hc *HealthChecker) Start(ctx context.Context, nm *NodeManager) {
	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()

	// Initial check
	hc.CheckAllNodes(nm)

	for {
		select {
		case <-ticker.C:
			hc.CheckAllNodes(nm)
		case <-ctx.Done():
			return
		}
	}
}

// CheckAllNodes checks health of all nodes
func (hc *HealthChecker) CheckAllNodes(nm *NodeManager) {
	nodes := nm.ListNodes()

	var wg sync.WaitGroup
	for _, node := range nodes {
		if !node.Node.IsActive {
			continue
		}

		wg.Add(1)
		go func(n *NodeInfo) {
			defer wg.Done()
			hc.CheckNode(n)
		}(node)
	}

	wg.Wait()
}

// CheckNode performs health check on a single node
func (hc *HealthChecker) CheckNode(node *NodeInfo) {
	node.mu.Lock()
	defer node.mu.Unlock()

	var lastErr error
	var status *HealthStatus
	var latency time.Duration

	for i := 0; i < HealthCheckMaxRetries; i++ {
		status, latency, lastErr = node.Client.HealthCheck()
		if lastErr == nil {
			break
		}
		time.Sleep(HealthCheckRetryDelay)
	}

	now := time.Now()
	node.LastHealthCheck = now

	if lastErr != nil {
		node.FailCount++
		node.IsAvailable = false
		node.Node.Status = NodeStatusError
		node.Node.LastError = lastErr.Error()
		node.HealthStatus = &HealthStatus{
			Status:    "unhealthy",
			Message:   lastErr.Error(),
			CheckTime: now,
			Errors:    []string{lastErr.Error()},
		}

		hc.updateNodeStatus(node)
		return
	}

	// Reset fail count on success
	node.FailCount = 0
	node.IsAvailable = true
	node.Node.Status = NodeStatusOnline
	node.Node.LastError = ""
	node.Node.LastCheck = &now

	// Determine overall status
	status.Status = "healthy"
	status.Warnings = []string{}

	if node.Metrics != nil {
		if node.Metrics.CPUUsage >= HealthCheckCriticalCPU {
			status.Status = "degraded"
			status.Warnings = append(status.Warnings, "Critical CPU usage")
		} else if node.Metrics.CPUUsage >= HealthCheckWarningCPU {
			status.Warnings = append(status.Warnings, "High CPU usage")
		}

		if node.Metrics.RAMUsage >= HealthCheckCriticalRAM {
			status.Status = "degraded"
			status.Warnings = append(status.Warnings, "Critical RAM usage")
		} else if node.Metrics.RAMUsage >= HealthCheckWarningRAM {
			status.Warnings = append(status.Warnings, "High RAM usage")
		}

		if node.Metrics.DiskUsage >= HealthCheckCriticalDisk {
			status.Status = "degraded"
			status.Warnings = append(status.Warnings, "Critical disk usage")
		} else if node.Metrics.DiskUsage >= HealthCheckWarningDisk {
			status.Warnings = append(status.Warnings, "High disk usage")
		}
	}

	status.Latency = latency.Milliseconds()
	node.HealthStatus = status

	hc.updateNodeStatus(node)
}

// updateNodeStatus updates node status in database
func (hc *HealthChecker) updateNodeStatus(node *NodeInfo) {
	DB.db.Exec(`
		UPDATE nodes SET status = ?, last_check = ?, last_error = ?, updated_at = ?
		WHERE id = ?
	`, node.Node.Status, node.LastHealthCheck, node.Node.LastError, time.Now(), node.Node.ID)
}

// ============================================================================
// LOAD BALANCER
// ============================================================================

// NodeLoadBalancer manages load balancing across nodes
type NodeLoadBalancer struct {
	config   NodesConfig
	strategy string
	rrIndex  uint64 // Round-robin index
}

// GetConfig returns the load balancer config
func (lb *NodeLoadBalancer) GetConfig() NodesConfig {
	return lb.config
}

// NewNodeLoadBalancer creates a new load balancer
func NewNodeLoadBalancer(config NodesConfig) *NodeLoadBalancer {
	return &NodeLoadBalancer{
		config:   config,
		strategy: LoadBalanceLeastLoad,
	}
}

// SetStrategy sets the load balancing strategy
func (lb *NodeLoadBalancer) SetStrategy(strategy string) {
	lb.strategy = strategy
}

// GetStrategy returns current load balancing strategy
func (lb *NodeLoadBalancer) GetStrategy() string {
	return lb.strategy
}

// SelectNode selects the best node for a new connection
func (lb *NodeLoadBalancer) SelectNode(nodes []*NodeInfo) *NodeInfo {
	if len(nodes) == 0 {
		return nil
	}

	if len(nodes) == 1 {
		return nodes[0]
	}

	switch lb.strategy {
	case LoadBalanceRoundRobin:
		return lb.selectRoundRobin(nodes)
	case LoadBalanceLeastLoad:
		return lb.selectLeastLoad(nodes)
	case LoadBalanceLeastUsers:
		return lb.selectLeastUsers(nodes)
	case LoadBalanceRandom:
		return lb.selectRandom(nodes)
	case LoadBalanceWeighted:
		return lb.selectWeighted(nodes)
	default:
		return lb.selectLeastLoad(nodes)
	}
}

// selectRoundRobin selects node using round-robin
func (lb *NodeLoadBalancer) selectRoundRobin(nodes []*NodeInfo) *NodeInfo {
	index := atomic.AddUint64(&lb.rrIndex, 1) % uint64(len(nodes))
	return nodes[index]
}

// selectLeastLoad selects node with least load
func (lb *NodeLoadBalancer) selectLeastLoad(nodes []*NodeInfo) *NodeInfo {
	var selected *NodeInfo
	minLoad := float64(100)

	for _, node := range nodes {
		if node.Metrics == nil {
			continue
		}

		// Calculate load score (weighted average)
		load := node.Metrics.CPUUsage*0.4 + node.Metrics.RAMUsage*0.3 +
			float64(node.Metrics.ActiveConns)/1000*0.3

		if load < minLoad {
			minLoad = load
			selected = node
		}
	}

	if selected == nil && len(nodes) > 0 {
		return nodes[0]
	}

	return selected
}

// selectLeastUsers selects node with least active users
func (lb *NodeLoadBalancer) selectLeastUsers(nodes []*NodeInfo) *NodeInfo {
	var selected *NodeInfo
	minUsers := int(^uint(0) >> 1) // Max int

	for _, node := range nodes {
		if node.Metrics == nil {
			continue
		}

		if node.Metrics.ActiveUsers < minUsers {
			minUsers = node.Metrics.ActiveUsers
			selected = node
		}
	}

	if selected == nil && len(nodes) > 0 {
		return nodes[0]
	}

	return selected
}

// selectRandom selects a random node
func (lb *NodeLoadBalancer) selectRandom(nodes []*NodeInfo) *NodeInfo {
	index := time.Now().UnixNano() % int64(len(nodes))
	return nodes[index]
}

// selectWeighted selects node based on traffic ratio
func (lb *NodeLoadBalancer) selectWeighted(nodes []*NodeInfo) *NodeInfo {
	// Calculate total weight
	totalWeight := 0.0
	for _, node := range nodes {
		totalWeight += node.Node.TrafficRatio
	}

	if totalWeight == 0 {
		return lb.selectRoundRobin(nodes)
	}

	// Select random point
	point := float64(time.Now().UnixNano()%1000) / 1000 * totalWeight
	currentWeight := 0.0

	for _, node := range nodes {
		currentWeight += node.Node.TrafficRatio
		if point <= currentWeight {
			return node
		}
	}

	return nodes[len(nodes)-1]
}

// SelectNodeForUser selects the best node for a specific user
func (lb *NodeLoadBalancer) SelectNodeForUser(nm *NodeManager, user *User) *NodeInfo {
	// Get available nodes
	nodes := nm.GetAvailableNodes()
	if len(nodes) == 0 {
		return nil
	}

	// Filter by user's enabled protocols
	if len(user.EnabledProtocols) > 0 {
		filtered := []*NodeInfo{}
		for _, node := range nodes {
			for _, protocol := range user.EnabledProtocols {
				for _, nodeProto := range node.Node.Protocols {
					if protocol == nodeProto {
						filtered = append(filtered, node)
						break
					}
				}
			}
		}
		if len(filtered) > 0 {
			nodes = filtered
		}
	}

	return lb.SelectNode(nodes)
}

// GetNodeStats returns load balancer statistics
func (lb *NodeLoadBalancer) GetNodeStats(nm *NodeManager) map[string]interface{} {
	nodes := nm.ListNodes()

	stats := map[string]interface{}{
		"strategy":        lb.strategy,
		"total_nodes":     len(nodes),
		"available_nodes": 0,
		"total_users":     0,
		"total_traffic":   int64(0),
		"node_stats":      []map[string]interface{}{},
	}

	nodeStats := []map[string]interface{}{}

	for _, node := range nodes {
		ns := map[string]interface{}{
			"id":            node.Node.ID,
			"name":          node.Node.Name,
			"status":        node.Node.Status,
			"is_available":  node.IsAvailable,
			"traffic_ratio": node.Node.TrafficRatio,
		}

		if node.IsAvailable {
			stats["available_nodes"] = stats["available_nodes"].(int) + 1
		}

		if node.Metrics != nil {
			ns["cpu_usage"] = node.Metrics.CPUUsage
			ns["ram_usage"] = node.Metrics.RAMUsage
			ns["active_users"] = node.Metrics.ActiveUsers
			ns["active_conns"] = node.Metrics.ActiveConns

			stats["total_users"] = stats["total_users"].(int) + node.Metrics.ActiveUsers
			stats["total_traffic"] = stats["total_traffic"].(int64) + node.Metrics.TotalUpload + node.Metrics.TotalDownload
		}

		if node.HealthStatus != nil {
			ns["health_status"] = node.HealthStatus.Status
			ns["latency"] = node.HealthStatus.Latency
		}

		nodeStats = append(nodeStats, ns)
	}

	stats["node_stats"] = nodeStats

	return stats
}

// ============================================================================
// SYNC MANAGER
// ============================================================================

// SyncManager manages configuration synchronization across nodes
type SyncManager struct {
	lastSync   map[int64]time.Time
	syncErrors map[int64]error
	mu         sync.RWMutex
}

// NewSyncManager creates a new sync manager
func NewSyncManager() *SyncManager {
	return &SyncManager{
		lastSync:   make(map[int64]time.Time),
		syncErrors: make(map[int64]error),
	}
}

// Start starts the sync manager
func (sm *SyncManager) Start(ctx context.Context, nm *NodeManager) {
	ticker := time.NewTicker(NodeSyncPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.SyncAllNodes(nm)
		case <-ctx.Done():
			return
		}
	}
}

// SyncAllNodes synchronizes configuration to all nodes
func (sm *SyncManager) SyncAllNodes(nm *NodeManager) {
	nodes := nm.GetAvailableNodes()

	// Get configuration to sync
	config := sm.buildSyncConfig()

	// Get users to sync
	users, _ := Users.ListUsers(&UserFilter{
		Status: UserStatusActive,
		Limit:  100000,
	})

	var wg sync.WaitGroup
	for _, node := range nodes {
		if node.Node.IsMainNode {
			continue // Don't sync to main node
		}

		wg.Add(1)
		go func(n *NodeInfo) {
			defer wg.Done()
			sm.SyncNode(n, config, users.Users)
		}(node)
	}

	wg.Wait()
}

// SyncNode synchronizes configuration to a single node
func (sm *SyncManager) SyncNode(node *NodeInfo, config interface{}, users []*User) error {
	sm.mu.Lock()
	sm.mu.Unlock()

	// Sync configuration
	if err := node.Client.SyncConfig(config); err != nil {
		sm.mu.Lock()
		sm.syncErrors[node.Node.ID] = err
		sm.mu.Unlock()
		return err
	}

	// Sync users
	if err := node.Client.SyncUsers(users); err != nil {
		sm.mu.Lock()
		sm.syncErrors[node.Node.ID] = err
		sm.mu.Unlock()
		return err
	}

	sm.mu.Lock()
	sm.lastSync[node.Node.ID] = time.Now()
	delete(sm.syncErrors, node.Node.ID)
	sm.mu.Unlock()

	node.LastSync = time.Now()

	return nil
}

// buildSyncConfig builds configuration for synchronization
func (sm *SyncManager) buildSyncConfig() map[string]interface{} {
	config := map[string]interface{}{}

	// Add inbounds
	if Protocols != nil {
		inbounds, _ := Protocols.ListInbounds(0)
		config["inbounds"] = inbounds
	}

	// Add routing
	if Routing != nil {
		config["routing"] = Routing.ExportRoutingConfig()
	}

	return config
}

// ForceSyncNode forces synchronization to a specific node
func (sm *SyncManager) ForceSyncNode(nm *NodeManager, nodeID int64) error {
	node, err := nm.GetNode(nodeID)
	if err != nil {
		return err
	}

	config := sm.buildSyncConfig()

	users, _ := Users.ListUsers(&UserFilter{
		Status: UserStatusActive,
		Limit:  100000,
	})

	return sm.SyncNode(node, config, users.Users)
}

// GetSyncStatus returns sync status for all nodes
func (sm *SyncManager) GetSyncStatus() map[int64]*SyncStatus {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	status := make(map[int64]*SyncStatus)

	for nodeID, lastSync := range sm.lastSync {
		status[nodeID] = &SyncStatus{
			LastSync: lastSync,
		}

		if err, exists := sm.syncErrors[nodeID]; exists {
			status[nodeID].Error = err.Error()
			status[nodeID].Success = false
		} else {
			status[nodeID].Success = true
		}
	}

	return status
}

// SyncStatus represents sync status for a node
type SyncStatus struct {
	LastSync time.Time `json:"last_sync"`
	Success  bool      `json:"success"`
	Error    string    `json:"error,omitempty"`
}

// ============================================================================
// FAILOVER MANAGER
// ============================================================================

// FailoverManager manages node failover
type FailoverManager struct {
	config      NodesConfig
	failedNodes map[int64]*FailoverInfo
	mu          sync.RWMutex
}

// FailoverInfo tracks failover information for a node
type FailoverInfo struct {
	NodeID        int64
	FailedAt      time.Time
	Attempts      int
	LastAttempt   time.Time
	InCooldown    bool
	CooldownUntil time.Time
}

// NewFailoverManager creates a new failover manager
func NewFailoverManager(config NodesConfig) *FailoverManager {
	return &FailoverManager{
		config:      config,
		failedNodes: make(map[int64]*FailoverInfo),
	}
}

// Start starts the failover manager
func (fm *FailoverManager) Start(ctx context.Context, nm *NodeManager) {
	ticker := time.NewTicker(FailoverCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fm.checkFailedNodes(nm)
		case <-ctx.Done():
			return
		}
	}
}

// RecordFailure records a node failure
func (fm *FailoverManager) RecordFailure(nodeID int64) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	now := time.Now()

	info, exists := fm.failedNodes[nodeID]
	if !exists {
		info = &FailoverInfo{
			NodeID:   nodeID,
			FailedAt: now,
		}
		fm.failedNodes[nodeID] = info
	}

	info.Attempts++
	info.LastAttempt = now

	// Check if should enter cooldown
	if info.Attempts >= FailoverMaxAttempts {
		info.InCooldown = true
		info.CooldownUntil = now.Add(FailoverCooldown)
	}
}

// RecordRecovery records a node recovery
func (fm *FailoverManager) RecordRecovery(nodeID int64) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	delete(fm.failedNodes, nodeID)
}

// IsInCooldown checks if a node is in cooldown
func (fm *FailoverManager) IsInCooldown(nodeID int64) bool {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	info, exists := fm.failedNodes[nodeID]
	if !exists {
		return false
	}

	if !info.InCooldown {
		return false
	}

	return time.Now().Before(info.CooldownUntil)
}

// checkFailedNodes checks and attempts to recover failed nodes
func (fm *FailoverManager) checkFailedNodes(nm *NodeManager) {
	fm.mu.Lock()
	nodesToCheck := make([]*FailoverInfo, 0)
	now := time.Now()

	for _, info := range fm.failedNodes {
		// Skip if in cooldown
		if info.InCooldown && now.Before(info.CooldownUntil) {
			continue
		}

		// Reset cooldown if expired
		if info.InCooldown && now.After(info.CooldownUntil) {
			info.InCooldown = false
			info.Attempts = 0
		}

		nodesToCheck = append(nodesToCheck, info)
	}
	fm.mu.Unlock()

	for _, info := range nodesToCheck {
		node, err := nm.GetNode(info.NodeID)
		if err != nil {
			continue
		}

		// Attempt health check
		status, _, err := node.Client.HealthCheck()
		if err == nil && status.Status == "healthy" {
			fm.RecordRecovery(info.NodeID)

			// Update node status
			node.mu.Lock()
			node.IsAvailable = true
			node.Node.Status = NodeStatusOnline
			node.mu.Unlock()

			// Sync node
			if nm.syncManager != nil {
				go nm.syncManager.ForceSyncNode(nm, info.NodeID)
			}
		} else {
			fm.RecordFailure(info.NodeID)
		}
	}
}

// GetFailoverStatus returns failover status for all nodes
func (fm *FailoverManager) GetFailoverStatus() map[int64]*FailoverInfo {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	status := make(map[int64]*FailoverInfo)
	for id, info := range fm.failedNodes {
		status[id] = &FailoverInfo{
			NodeID:        info.NodeID,
			FailedAt:      info.FailedAt,
			Attempts:      info.Attempts,
			LastAttempt:   info.LastAttempt,
			InCooldown:    info.InCooldown,
			CooldownUntil: info.CooldownUntil,
		}
	}

	return status
}

// TriggerFailover triggers failover for users on a failed node
func (fm *FailoverManager) TriggerFailover(nm *NodeManager, failedNodeID int64) error {
	cfg := nm.loadBalancer.GetConfig()
	if !cfg.FailoverEnabled {
		return errors.New("failover is disabled")
	}

	// Get available nodes
	availableNodes := []*NodeInfo{}
	for _, node := range nm.GetAvailableNodes() {
		if node.Node.ID != failedNodeID {
			availableNodes = append(availableNodes, node)
		}
	}

	if len(availableNodes) == 0 {
		return errors.New("no available nodes for failover")
	}

	// For now, just mark the node as failed
	// In a real implementation, this would migrate users
	fm.RecordFailure(failedNodeID)

	return nil
}

// ============================================================================
// METRICS COLLECTOR
// ============================================================================

// MetricsCollector collects metrics from all nodes
type MetricsCollector struct {
	history    map[int64][]*NodeMetrics
	maxHistory int
	mu         sync.RWMutex
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		history:    make(map[int64][]*NodeMetrics),
		maxHistory: 60, // Keep 60 samples (15 minutes at 15s interval)
	}
}

// Start starts the metrics collector
func (mc *MetricsCollector) Start(ctx context.Context, nm *NodeManager) {
	ticker := time.NewTicker(NodeMetricsPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mc.CollectAllMetrics(nm)
		case <-ctx.Done():
			return
		}
	}
}

// CollectAllMetrics collects metrics from all nodes
func (mc *MetricsCollector) CollectAllMetrics(nm *NodeManager) {
	nodes := nm.GetAvailableNodes()

	var wg sync.WaitGroup
	for _, node := range nodes {
		wg.Add(1)
		go func(n *NodeInfo) {
			defer wg.Done()
			mc.CollectNodeMetrics(n)
		}(node)
	}

	wg.Wait()
}

// CollectNodeMetrics collects metrics from a single node
func (mc *MetricsCollector) CollectNodeMetrics(node *NodeInfo) {
	metrics, err := node.Client.GetMetrics()
	if err != nil {
		return
	}

	node.mu.Lock()
	node.Metrics = metrics
	node.Node.CPUUsage = metrics.CPUUsage
	node.Node.RAMUsage = metrics.RAMUsage
	node.Node.DiskUsage = metrics.DiskUsage
	node.Node.NetworkIn = metrics.NetworkIn
	node.Node.NetworkOut = metrics.NetworkOut
	node.Node.ActiveUsers = metrics.ActiveUsers
	node.Node.Uptime = metrics.Uptime
	node.mu.Unlock()

	// Update database
	DB.db.Exec(`
		UPDATE nodes SET 
			cpu_usage = ?, ram_usage = ?, disk_usage = ?,
			network_in = ?, network_out = ?, active_users = ?,
			uptime = ?, updated_at = ?
		WHERE id = ?
	`, metrics.CPUUsage, metrics.RAMUsage, metrics.DiskUsage,
		metrics.NetworkIn, metrics.NetworkOut, metrics.ActiveUsers,
		metrics.Uptime, time.Now(), node.Node.ID)

	// Add to history
	mc.addToHistory(node.Node.ID, metrics)
}

// addToHistory adds metrics to history
func (mc *MetricsCollector) addToHistory(nodeID int64, metrics *NodeMetrics) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.history[nodeID] == nil {
		mc.history[nodeID] = []*NodeMetrics{}
	}

	mc.history[nodeID] = append(mc.history[nodeID], metrics)

	// Trim history
	if len(mc.history[nodeID]) > mc.maxHistory {
		mc.history[nodeID] = mc.history[nodeID][1:]
	}
}

// GetMetricsHistory returns metrics history for a node
func (mc *MetricsCollector) GetMetricsHistory(nodeID int64) []*NodeMetrics {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	if history, exists := mc.history[nodeID]; exists {
		result := make([]*NodeMetrics, len(history))
		copy(result, history)
		return result
	}

	return []*NodeMetrics{}
}

// GetAggregatedMetrics returns aggregated metrics for all nodes
func (mc *MetricsCollector) GetAggregatedMetrics(nm *NodeManager) *AggregatedMetrics {
	nodes := nm.ListNodes()

	agg := &AggregatedMetrics{
		Timestamp: time.Now(),
	}

	for _, node := range nodes {
		if node.Metrics == nil {
			continue
		}

		agg.TotalNodes++
		if node.IsAvailable {
			agg.AvailableNodes++
		}

		agg.TotalCPU += node.Metrics.CPUUsage
		agg.TotalRAM += node.Metrics.RAMUsage
		agg.TotalDisk += node.Metrics.DiskUsage
		agg.TotalNetworkIn += node.Metrics.NetworkIn
		agg.TotalNetworkOut += node.Metrics.NetworkOut
		agg.TotalUpload += node.Metrics.TotalUpload
		agg.TotalDownload += node.Metrics.TotalDownload
		agg.TotalUsers += node.Metrics.ActiveUsers
		agg.TotalConns += node.Metrics.ActiveConns
	}

	if agg.TotalNodes > 0 {
		agg.AvgCPU = agg.TotalCPU / float64(agg.TotalNodes)
		agg.AvgRAM = agg.TotalRAM / float64(agg.TotalNodes)
		agg.AvgDisk = agg.TotalDisk / float64(agg.TotalNodes)
	}

	return agg
}

// AggregatedMetrics represents aggregated metrics for all nodes
type AggregatedMetrics struct {
	Timestamp       time.Time `json:"timestamp"`
	TotalNodes      int       `json:"total_nodes"`
	AvailableNodes  int       `json:"available_nodes"`
	TotalCPU        float64   `json:"total_cpu"`
	AvgCPU          float64   `json:"avg_cpu"`
	TotalRAM        float64   `json:"total_ram"`
	AvgRAM          float64   `json:"avg_ram"`
	TotalDisk       float64   `json:"total_disk"`
	AvgDisk         float64   `json:"avg_disk"`
	TotalNetworkIn  int64     `json:"total_network_in"`
	TotalNetworkOut int64     `json:"total_network_out"`
	TotalUpload     int64     `json:"total_upload"`
	TotalDownload   int64     `json:"total_download"`
	TotalUsers      int       `json:"total_users"`
	TotalConns      int       `json:"total_connections"`
}

// ============================================================================
// NODE OPERATIONS
// ============================================================================

// EnableNode enables a node
func (nm *NodeManager) EnableNode(id int64) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	node, exists := nm.nodes[id]
	if !exists {
		return errors.New("node not found")
	}

	node.Node.IsActive = true
	_, err := DB.db.Exec("UPDATE nodes SET is_active = 1, updated_at = ? WHERE id = ?", time.Now(), id)
	if err != nil {
		return err
	}

	// Trigger health check
	go nm.healthChecker.CheckNode(node)

	return nil
}

// DisableNode disables a node
func (nm *NodeManager) DisableNode(id int64) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	node, exists := nm.nodes[id]
	if !exists {
		return errors.New("node not found")
	}

	node.Node.IsActive = false
	node.IsAvailable = false

	_, err := DB.db.Exec("UPDATE nodes SET is_active = 0, updated_at = ? WHERE id = ?", time.Now(), id)
	return err
}

// RestartNodeCore restarts the core on a node
func (nm *NodeManager) RestartNodeCore(id int64) error {
	node, err := nm.GetNode(id)
	if err != nil {
		return err
	}

	return node.Client.RestartCore()
}

// SetMainNode sets a node as the main node
func (nm *NodeManager) SetMainNode(id int64) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	node, exists := nm.nodes[id]
	if !exists {
		return errors.New("node not found")
	}

	// Unset current main node
	if nm.mainNode != nil {
		nm.mainNode.Node.IsMainNode = false
		DB.db.Exec("UPDATE nodes SET is_main_node = 0 WHERE id = ?", nm.mainNode.Node.ID)
	}

	// Set new main node
	node.Node.IsMainNode = true
	nm.mainNode = node

	_, err := DB.db.Exec("UPDATE nodes SET is_main_node = 1, updated_at = ? WHERE id = ?", time.Now(), id)
	return err
}

// TestNodeConnection tests connection to a node
func (nm *NodeManager) TestNodeConnection(id int64) (*ConnectionTestResult, error) {
	node, err := nm.GetNode(id)
	if err != nil {
		return nil, err
	}

	result := &ConnectionTestResult{
		NodeID:    id,
		Timestamp: time.Now(),
	}

	// Test TCP connection
	tcpStart := time.Now()
	conn, tcpErr := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", node.Node.Address, node.Node.APIPort), 5*time.Second)
	result.TCPLatency = time.Since(tcpStart).Milliseconds()
	result.TCPSuccess = tcpErr == nil
	if conn != nil {
		conn.Close()
	}

	// Test API health
	apiStart := time.Now()
	status, _, apiErr := node.Client.HealthCheck()
	result.APILatency = time.Since(apiStart).Milliseconds()
	result.APISuccess = apiErr == nil
	if status != nil {
		result.CoreRunning = status.CoreRunning
	}

	// Test ping latency
	pingLatency, _ := node.Client.Ping()
	result.PingLatency = pingLatency.Milliseconds()

	return result, nil
}

// ConnectionTestResult represents a connection test result
type ConnectionTestResult struct {
	NodeID      int64     `json:"node_id"`
	Timestamp   time.Time `json:"timestamp"`
	TCPSuccess  bool      `json:"tcp_success"`
	TCPLatency  int64     `json:"tcp_latency"`
	APISuccess  bool      `json:"api_success"`
	APILatency  int64     `json:"api_latency"`
	PingLatency int64     `json:"ping_latency"`
	CoreRunning bool      `json:"core_running"`
}

// ============================================================================
// STATISTICS
// ============================================================================

// GetNodeStats returns statistics for all nodes
func (nm *NodeManager) GetNodeStats() *NodeStats {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	stats := &NodeStats{
		TotalNodes: len(nm.nodes),
		Timestamp:  time.Now(),
	}

	for _, node := range nm.nodes {
		if node.Node.IsActive {
			stats.ActiveNodes++
		}

		switch node.Node.Status {
		case NodeStatusOnline:
			stats.OnlineNodes++
		case NodeStatusOffline:
			stats.OfflineNodes++
		case NodeStatusError:
			stats.ErrorNodes++
		}

		if node.IsAvailable {
			stats.AvailableNodes++
		}

		if node.Metrics != nil {
			stats.TotalTraffic += node.Metrics.TotalUpload + node.Metrics.TotalDownload
			stats.TotalUsers += node.Metrics.ActiveUsers
		}
	}

	return stats
}

// NodeStats represents overall node statistics
type NodeStats struct {
	Timestamp      time.Time `json:"timestamp"`
	TotalNodes     int       `json:"total_nodes"`
	ActiveNodes    int       `json:"active_nodes"`
	OnlineNodes    int       `json:"online_nodes"`
	OfflineNodes   int       `json:"offline_nodes"`
	ErrorNodes     int       `json:"error_nodes"`
	AvailableNodes int       `json:"available_nodes"`
	TotalTraffic   int64     `json:"total_traffic"`
	TotalUsers     int       `json:"total_users"`
}

// GetNodeDetails returns detailed information for a node
func (nm *NodeManager) GetNodeDetails(id int64) (map[string]interface{}, error) {
	node, err := nm.GetNode(id)
	if err != nil {
		return nil, err
	}

	details := map[string]interface{}{
		"node":          node.Node,
		"is_available":  node.IsAvailable,
		"health_status": node.HealthStatus,
		"metrics":       node.Metrics,
		"last_sync":     node.LastSync,
		"fail_count":    node.FailCount,
	}

	// Get sync status
	if nm.syncManager != nil {
		syncStatus := nm.syncManager.GetSyncStatus()
		if status, exists := syncStatus[id]; exists {
			details["sync_status"] = status
		}
	}

	// Get failover status
	if nm.failoverManager != nil {
		failoverStatus := nm.failoverManager.GetFailoverStatus()
		if status, exists := failoverStatus[id]; exists {
			details["failover_status"] = status
		}
	}

	// Get metrics history
	if nm.metricsCollector != nil {
		details["metrics_history"] = nm.metricsCollector.GetMetricsHistory(id)
	}

	// Get inbounds count
	var inboundCount int
	DB.db.QueryRow("SELECT COUNT(*) FROM inbounds WHERE node_id = ?", id).Scan(&inboundCount)
	details["inbound_count"] = inboundCount

	return details, nil
}

// ============================================================================
// QUICK NODE SETUP
// ============================================================================

// QuickNodeSetup represents easy node setup configuration
type QuickNodeSetup struct {
	Address     string `json:"address"`
	SSHPort     int    `json:"ssh_port"`
	SSHUser     string `json:"ssh_user"`
	SSHKey      string `json:"ssh_key,omitempty"`
	SSHPassword string `json:"ssh_password,omitempty"`
}

// GenerateNodeInstallScript generates installation script for a node
func (nm *NodeManager) GenerateNodeInstallScript(nodeID int64) (string, error) {
	node, err := nm.GetNode(nodeID)
	if err != nil {
		return "", err
	}

	// Get main panel address
	mainNode := nm.GetMainNode()
	mainAddress := "localhost"
	if mainNode != nil {
		mainAddress = mainNode.Node.Address
	}

	script := fmt.Sprintf(`#!/bin/bash
# MXUI VPN Panel - Node Installation Script
# Node ID: %d
# Generated: %s

set -e

echo "=== MXUI Node Installation ==="

# Install dependencies
apt-get update
apt-get install -y curl wget unzip

# Download and install Xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Create MXUI node agent directory
mkdir -p /opt/mxui-node
cd /opt/mxui-node

# Download node agent
curl -L -o mxui-node https://example.com/mxui-node-linux-amd64
chmod +x mxui-node

# Create config
cat > config.yaml << 'EOF'
node_id: %d
api_port: %d
secret_key: "%s"
main_panel: "http://%s:%d"
EOF

# Create systemd service
cat > /etc/systemd/system/mxui-node.service << 'EOF'
[Unit]
Description=MXUI VPN Node Agent
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/mxui-node
ExecStart=/opt/mxui-node/mxui-node
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Start service
systemctl daemon-reload
systemctl enable mxui-node
systemctl start mxui-node

echo "=== Installation Complete ==="
echo "Node ID: %d"
echo "API Port: %d"
`,
		node.Node.ID, time.Now().Format(time.RFC3339),
		node.Node.ID, node.Node.APIPort, node.Node.SecretKey,
		mainAddress, 8080,
		node.Node.ID, node.Node.APIPort,
	)

	return script, nil
}

func (nm *NodeManager) RegisterNodeWithMaster(masterAddr, token string) error {
	// POST to master panel to register this node
	_ = map[string]interface{}{
		"address": getServerIP(),
		"port":    nm.config.SyncInterval, // placeholder
		"token":   token,
	}
	// HTTP POST to masterAddr + NodeSyncEndpoint
	return nil
}

// GenerateNodeConnectionString generates a connection string for easy node setup
func (nm *NodeManager) GenerateNodeConnectionString(nodeID int64) (string, error) {
	node, err := nm.GetNode(nodeID)
	if err != nil {
		return "", err
	}

	// Format: mxui://nodeID:secretKey@mainPanelAddress
	mainNode := nm.GetMainNode()
	mainAddress := "localhost:8080"
	if mainNode != nil {
		mainAddress = fmt.Sprintf("%s:8080", mainNode.Node.Address)
	}

	connStr := fmt.Sprintf("mxui://%d:%s@%s", node.Node.ID, node.Node.SecretKey, mainAddress)

	return connStr, nil
}
