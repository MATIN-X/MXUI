// MXUI VPN Panel
// Core/connection_tracker.go
// Real-time Connection Tracking and Session Management

package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"sync"
	"time"
)

// ============================================================================
// CONNECTION TRACKER
// ============================================================================

// ConnectionTracker tracks active connections per user
type ConnectionTracker struct {
	connections    map[string]*UserConnections // email -> connections
	ipToUser       map[string]string           // ip -> email
	sessionHistory []*ConnectionSession
	xrayAPIAddr    string
	singboxAPIAddr string
	httpClient     *http.Client
	mu             sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
}

// UserConnections holds all connections for a user
type UserConnections struct {
	Email          string                `json:"email"`
	UserID         int64                 `json:"user_id"`
	ActiveCount    int                   `json:"active_count"`
	Connections    []*ActiveConnection   `json:"connections"`
	MaxConnections int                   `json:"max_connections"`
	LastUpdated    time.Time             `json:"last_updated"`
}

// ActiveConnection represents a single active connection
type ActiveConnection struct {
	ID          string    `json:"id"`
	IP          string    `json:"ip"`
	Protocol    string    `json:"protocol"`
	Inbound     string    `json:"inbound"`
	Location    string    `json:"location"`
	Device      string    `json:"device"`
	Upload      int64     `json:"upload"`
	Download    int64     `json:"download"`
	ConnectedAt time.Time `json:"connected_at"`
	LastActive  time.Time `json:"last_active"`
}

// ConnectionSession represents a completed connection session
type ConnectionSession struct {
	ID             string    `json:"id"`
	UserID         int64     `json:"user_id"`
	Email          string    `json:"email"`
	IP             string    `json:"ip"`
	Protocol       string    `json:"protocol"`
	Inbound        string    `json:"inbound"`
	Location       string    `json:"location"`
	TotalUpload    int64     `json:"total_upload"`
	TotalDownload  int64     `json:"total_download"`
	Duration       int64     `json:"duration"` // seconds
	ConnectedAt    time.Time `json:"connected_at"`
	DisconnectedAt time.Time `json:"disconnected_at"`
}

// Global connection tracker
var Connections *ConnectionTracker

// ============================================================================
// INITIALIZATION
// ============================================================================

// InitConnectionTracker initializes the connection tracker
func InitConnectionTracker(xrayAddr, singboxAddr string) error {
	ctx, cancel := context.WithCancel(context.Background())

	Connections = &ConnectionTracker{
		connections:    make(map[string]*UserConnections),
		ipToUser:       make(map[string]string),
		sessionHistory: make([]*ConnectionSession, 0),
		xrayAPIAddr:    xrayAddr,
		singboxAPIAddr: singboxAddr,
		httpClient:     &http.Client{Timeout: 5 * time.Second},
		ctx:            ctx,
		cancel:         cancel,
	}

	// Start tracking goroutine
	go Connections.trackingLoop()

	LogInfo("CONN-TRACK", "Connection tracker initialized")
	return nil
}

// ============================================================================
// TRACKING LOOP
// ============================================================================

func (ct *ConnectionTracker) trackingLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ct.ctx.Done():
			return
		case <-ticker.C:
			ct.updateConnections()
		}
	}
}

func (ct *ConnectionTracker) updateConnections() {
	// Get active connections from Xray
	xrayConns := ct.getXrayConnections()

	// Get active connections from Sing-box
	singboxConns := ct.getSingboxConnections()

	// Merge and update
	ct.mu.Lock()
	defer ct.mu.Unlock()

	now := time.Now()

	// Mark all existing connections as potentially stale
	staleIPs := make(map[string]bool)
	for _, uc := range ct.connections {
		for _, conn := range uc.Connections {
			staleIPs[conn.IP] = true
		}
	}

	// Process new connection data
	allConns := append(xrayConns, singboxConns...)

	for _, conn := range allConns {
		delete(staleIPs, conn.IP)
		ct.updateOrAddConnection(conn)
	}

	// Remove stale connections
	for ip := range staleIPs {
		ct.removeConnectionByIP(ip)
	}

	// Update last updated time
	for _, uc := range ct.connections {
		uc.LastUpdated = now
		uc.ActiveCount = len(uc.Connections)
	}
}

func (ct *ConnectionTracker) updateOrAddConnection(conn *ActiveConnection) {
	email := ct.ipToUser[conn.IP]
	if email == "" {
		// Try to find email from inbound tag
		email = ct.extractEmailFromInbound(conn.Inbound)
	}

	if email == "" {
		return // Unknown user
	}

	conn.LastActive = time.Now()
	ct.ipToUser[conn.IP] = email

	if _, exists := ct.connections[email]; !exists {
		ct.connections[email] = &UserConnections{
			Email:       email,
			Connections: make([]*ActiveConnection, 0),
		}
	}

	// Check if connection already exists
	uc := ct.connections[email]
	found := false
	for i, existing := range uc.Connections {
		if existing.IP == conn.IP && existing.Protocol == conn.Protocol {
			// Update existing connection
			uc.Connections[i].Upload = conn.Upload
			uc.Connections[i].Download = conn.Download
			uc.Connections[i].LastActive = conn.LastActive
			found = true
			break
		}
	}

	if !found {
		// Add new connection
		conn.ConnectedAt = time.Now()
		conn.ID = fmt.Sprintf("%s_%d", conn.IP, time.Now().UnixNano())
		uc.Connections = append(uc.Connections, conn)

		LogInfo("CONN-TRACK", "New connection: %s from %s via %s", email, conn.IP, conn.Protocol)
	}
}

func (ct *ConnectionTracker) removeConnectionByIP(ip string) {
	email := ct.ipToUser[ip]
	if email == "" {
		return
	}

	if uc, exists := ct.connections[email]; exists {
		for i, conn := range uc.Connections {
			if conn.IP == ip {
				// Record session history
				session := &ConnectionSession{
					ID:             conn.ID,
					Email:          email,
					IP:             conn.IP,
					Protocol:       conn.Protocol,
					Inbound:        conn.Inbound,
					Location:       conn.Location,
					TotalUpload:    conn.Upload,
					TotalDownload:  conn.Download,
					Duration:       int64(time.Since(conn.ConnectedAt).Seconds()),
					ConnectedAt:    conn.ConnectedAt,
					DisconnectedAt: time.Now(),
				}
				ct.sessionHistory = append(ct.sessionHistory, session)

				// Remove connection
				uc.Connections = append(uc.Connections[:i], uc.Connections[i+1:]...)

				LogInfo("CONN-TRACK", "Connection closed: %s from %s (duration: %ds)",
					email, ip, session.Duration)
				break
			}
		}

		// Remove user if no connections
		if len(uc.Connections) == 0 {
			delete(ct.connections, email)
		}
	}

	delete(ct.ipToUser, ip)
}

func (ct *ConnectionTracker) extractEmailFromInbound(inboundTag string) string {
	// Inbound tags often contain user email: e.g., "user_test@example.com_vless"
	// This is implementation-specific
	return ""
}

// ============================================================================
// XRAY CONNECTION FETCHING
// ============================================================================

func (ct *ConnectionTracker) getXrayConnections() []*ActiveConnection {
	if ct.xrayAPIAddr == "" {
		return nil
	}

	// Xray uses gRPC for stats, but we can also query via HTTP if configured
	// This queries the Xray stats API
	url := fmt.Sprintf("http://%s/debug/vars", ct.xrayAPIAddr)
	resp, err := ct.httpClient.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	// Parse Xray stats response
	var stats map[string]interface{}
	if err := json.Unmarshal(body, &stats); err != nil {
		return nil
	}

	connections := make([]*ActiveConnection, 0)

	// Extract user stats from Xray format
	if statsObj, ok := stats["stats"].(map[string]interface{}); ok {
		if users, ok := statsObj["user"].(map[string]interface{}); ok {
			for email, userData := range users {
				if userStats, ok := userData.(map[string]interface{}); ok {
					conn := &ActiveConnection{
						Protocol: "xray",
					}

					if upload, ok := userStats["uplink"].(float64); ok {
						conn.Upload = int64(upload)
					}
					if download, ok := userStats["downlink"].(float64); ok {
						conn.Download = int64(download)
					}

					// Only add if there's active traffic
					if conn.Upload > 0 || conn.Download > 0 {
						ct.ipToUser["xray_"+email] = email
						conn.IP = "xray_" + email
						connections = append(connections, conn)
					}
				}
			}
		}
	}

	return connections
}

// ============================================================================
// SING-BOX CONNECTION FETCHING
// ============================================================================

func (ct *ConnectionTracker) getSingboxConnections() []*ActiveConnection {
	if ct.singboxAPIAddr == "" {
		return nil
	}

	// Sing-box experimental API
	url := fmt.Sprintf("http://%s/connections", ct.singboxAPIAddr)
	resp, err := ct.httpClient.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	var response struct {
		Connections []struct {
			ID       string `json:"id"`
			Upload   int64  `json:"upload"`
			Download int64  `json:"download"`
			Start    string `json:"start"`
			Metadata struct {
				SourceIP string `json:"sourceIP"`
				Network  string `json:"network"`
				Host     string `json:"host"`
				User     string `json:"user"`
			} `json:"metadata"`
		} `json:"connections"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil
	}

	connections := make([]*ActiveConnection, 0)
	for _, c := range response.Connections {
		conn := &ActiveConnection{
			ID:       c.ID,
			IP:       c.Metadata.SourceIP,
			Protocol: "singbox",
			Upload:   c.Upload,
			Download: c.Download,
		}

		if c.Metadata.User != "" {
			ct.ipToUser[conn.IP] = c.Metadata.User
		}

		connections = append(connections, conn)
	}

	return connections
}

// ============================================================================
// PUBLIC API
// ============================================================================

// GetUserConnectionCount returns the number of active connections for a user
func (ct *ConnectionTracker) GetUserConnectionCount(email string) int {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	if uc, exists := ct.connections[email]; exists {
		return uc.ActiveCount
	}
	return 0
}

// GetUserConnections returns all active connections for a user
func (ct *ConnectionTracker) GetUserConnections(email string) []*ActiveConnection {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	if uc, exists := ct.connections[email]; exists {
		conns := make([]*ActiveConnection, len(uc.Connections))
		copy(conns, uc.Connections)
		return conns
	}
	return nil
}

// GetAllActiveConnections returns all active connections
func (ct *ConnectionTracker) GetAllActiveConnections() map[string]*UserConnections {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	result := make(map[string]*UserConnections)
	for email, uc := range ct.connections {
		ucCopy := &UserConnections{
			Email:          uc.Email,
			UserID:         uc.UserID,
			ActiveCount:    uc.ActiveCount,
			MaxConnections: uc.MaxConnections,
			LastUpdated:    uc.LastUpdated,
			Connections:    make([]*ActiveConnection, len(uc.Connections)),
		}
		copy(ucCopy.Connections, uc.Connections)
		result[email] = ucCopy
	}
	return result
}

// GetTotalActiveConnections returns total number of active connections
func (ct *ConnectionTracker) GetTotalActiveConnections() int {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	total := 0
	for _, uc := range ct.connections {
		total += uc.ActiveCount
	}
	return total
}

// GetActiveUserCount returns number of users with active connections
func (ct *ConnectionTracker) GetActiveUserCount() int {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return len(ct.connections)
}

// IsUserOnline checks if a user has active connections
func (ct *ConnectionTracker) IsUserOnline(email string) bool {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	if uc, exists := ct.connections[email]; exists {
		return uc.ActiveCount > 0
	}
	return false
}

// GetOnlineIPs returns all online IPs for a user
func (ct *ConnectionTracker) GetOnlineIPs(email string) []string {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	ips := make([]string, 0)
	if uc, exists := ct.connections[email]; exists {
		for _, conn := range uc.Connections {
			ips = append(ips, conn.IP)
		}
	}
	return ips
}

// CheckConnectionLimit checks if user has exceeded connection limit
func (ct *ConnectionTracker) CheckConnectionLimit(email string, maxConnections int) (bool, int) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	if uc, exists := ct.connections[email]; exists {
		if maxConnections > 0 && uc.ActiveCount >= maxConnections {
			return false, uc.ActiveCount
		}
		return true, uc.ActiveCount
	}
	return true, 0
}

// DisconnectUser forcefully disconnects all connections for a user
func (ct *ConnectionTracker) DisconnectUser(email string) error {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if uc, exists := ct.connections[email]; exists {
		// Send disconnect command to cores
		for _, conn := range uc.Connections {
			ct.sendDisconnectCommand(conn)
		}

		// Clear from tracking
		for _, conn := range uc.Connections {
			delete(ct.ipToUser, conn.IP)
		}
		delete(ct.connections, email)

		LogInfo("CONN-TRACK", "Force disconnected user: %s", email)
	}

	return nil
}

// DisconnectIP forcefully disconnects a specific IP
func (ct *ConnectionTracker) DisconnectIP(ip string) error {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	email := ct.ipToUser[ip]
	if email == "" {
		return nil
	}

	if uc, exists := ct.connections[email]; exists {
		for i, conn := range uc.Connections {
			if conn.IP == ip {
				ct.sendDisconnectCommand(conn)
				uc.Connections = append(uc.Connections[:i], uc.Connections[i+1:]...)
				delete(ct.ipToUser, ip)

				if len(uc.Connections) == 0 {
					delete(ct.connections, email)
				}

				LogInfo("CONN-TRACK", "Force disconnected IP: %s (user: %s)", ip, email)
				break
			}
		}
	}

	return nil
}

func (ct *ConnectionTracker) sendDisconnectCommand(conn *ActiveConnection) {
	// Send disconnect command based on protocol
	switch conn.Protocol {
	case "xray":
		// Xray doesn't have a direct disconnect API
		// Would need to modify inbound rules
	case "singbox":
		// Sing-box has connection close API
		if ct.singboxAPIAddr != "" {
			url := fmt.Sprintf("http://%s/connections/%s", ct.singboxAPIAddr, conn.ID)
			req, _ := http.NewRequest("DELETE", url, nil)
			ct.httpClient.Do(req)
		}
	}
}

// ============================================================================
// SESSION HISTORY
// ============================================================================

// GetSessionHistory returns connection session history
func (ct *ConnectionTracker) GetSessionHistory(email string, limit int) []*ConnectionSession {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	result := make([]*ConnectionSession, 0)
	for i := len(ct.sessionHistory) - 1; i >= 0 && len(result) < limit; i-- {
		if email == "" || ct.sessionHistory[i].Email == email {
			result = append(result, ct.sessionHistory[i])
		}
	}
	return result
}

// GetRecentSessions returns recent sessions for all users
func (ct *ConnectionTracker) GetRecentSessions(limit int) []*ConnectionSession {
	return ct.GetSessionHistory("", limit)
}

// ============================================================================
// STATISTICS
// ============================================================================

// ConnectionStats represents connection statistics
type ConnectionStats struct {
	TotalActive      int            `json:"total_active"`
	UniqueUsers      int            `json:"unique_users"`
	ByProtocol       map[string]int `json:"by_protocol"`
	ByLocation       map[string]int `json:"by_location"`
	TopUsers         []UserConnStat `json:"top_users"`
	AveragePerUser   float64        `json:"average_per_user"`
	TotalSessions    int            `json:"total_sessions"`
	TotalSessionTime int64          `json:"total_session_time"`
}

// UserConnStat represents user connection statistics
type UserConnStat struct {
	Email       string `json:"email"`
	Connections int    `json:"connections"`
}

// GetConnectionStats returns connection statistics
func (ct *ConnectionTracker) GetConnectionStats() *ConnectionStats {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	stats := &ConnectionStats{
		TotalActive:   0,
		UniqueUsers:   len(ct.connections),
		ByProtocol:    make(map[string]int),
		ByLocation:    make(map[string]int),
		TopUsers:      make([]UserConnStat, 0),
		TotalSessions: len(ct.sessionHistory),
	}

	// Calculate per-user stats
	userStats := make([]UserConnStat, 0)
	for email, uc := range ct.connections {
		stats.TotalActive += uc.ActiveCount
		userStats = append(userStats, UserConnStat{
			Email:       email,
			Connections: uc.ActiveCount,
		})

		for _, conn := range uc.Connections {
			stats.ByProtocol[conn.Protocol]++
			if conn.Location != "" {
				stats.ByLocation[conn.Location]++
			}
		}
	}

	// Sort and get top users
	sort.Slice(userStats, func(i, j int) bool {
		return userStats[i].Connections > userStats[j].Connections
	})
	if len(userStats) > 10 {
		stats.TopUsers = userStats[:10]
	} else {
		stats.TopUsers = userStats
	}

	// Calculate average
	if stats.UniqueUsers > 0 {
		stats.AveragePerUser = float64(stats.TotalActive) / float64(stats.UniqueUsers)
	}

	// Calculate total session time
	for _, session := range ct.sessionHistory {
		stats.TotalSessionTime += session.Duration
	}

	return stats
}

// ============================================================================
// MANUAL REGISTRATION
// ============================================================================

// RegisterConnection manually registers a connection (for external tracking)
func (ct *ConnectionTracker) RegisterConnection(email, ip, protocol, inbound string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	ct.ipToUser[ip] = email

	if _, exists := ct.connections[email]; !exists {
		ct.connections[email] = &UserConnections{
			Email:       email,
			Connections: make([]*ActiveConnection, 0),
		}
	}

	conn := &ActiveConnection{
		ID:          fmt.Sprintf("%s_%d", ip, time.Now().UnixNano()),
		IP:          ip,
		Protocol:    protocol,
		Inbound:     inbound,
		ConnectedAt: time.Now(),
		LastActive:  time.Now(),
	}

	ct.connections[email].Connections = append(ct.connections[email].Connections, conn)
	ct.connections[email].ActiveCount = len(ct.connections[email].Connections)
}

// UnregisterConnection manually unregisters a connection
func (ct *ConnectionTracker) UnregisterConnection(ip string) {
	ct.removeConnectionByIP(ip)
}

// ============================================================================
// SHUTDOWN
// ============================================================================

// Shutdown stops the connection tracker
func (ct *ConnectionTracker) Shutdown() {
	ct.cancel()

	// Save session history to database
	ct.saveSessionHistory()

	LogInfo("CONN-TRACK", "Connection tracker shutdown")
}

func (ct *ConnectionTracker) saveSessionHistory() {
	if DB == nil {
		return
	}

	for _, session := range ct.sessionHistory {
		DB.db.Exec(`
			INSERT INTO connection_logs (user_id, ip, protocol, inbound, location,
				upload, download, duration, connected_at, disconnected_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, session.UserID, session.IP, session.Protocol, session.Inbound,
			session.Location, session.TotalUpload, session.TotalDownload,
			session.Duration, session.ConnectedAt, session.DisconnectedAt)
	}
}

// ============================================================================
// HELPER FUNCTION FOR TRAFFIC COLLECTION
// ============================================================================

// GetActiveConnectionCount returns active connection count for a user
func GetActiveConnectionCount(email string) int {
	if Connections == nil {
		return 0
	}
	return Connections.GetUserConnectionCount(email)
}
