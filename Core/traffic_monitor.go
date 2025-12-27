// MX-UI VPN Panel
// Core/traffic_monitor.go
// Abnormal Traffic Detection & Monitoring

package core

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"
)

// ============================================================================
// CONSTANTS
// ============================================================================

const (
	TrafficCheckInterval = 1 * time.Minute
	TrafficHistorySize   = 1440 // 24 hours of minutes

	// Thresholds
	SpikeThresholdMultiplier   = 3.0 // 3x normal = spike
	AnomalyThresholdMultiplier = 2.5 // 2.5x normal = anomaly
	SustainedHighDuration      = 10 * time.Minute
	MaxConnectionsPerUser      = 100
	MaxTrafficPerMinute        = 100 * 1024 * 1024 // 100 MB/min
)

// ============================================================================
// TRAFFIC MONITOR
// ============================================================================

// TrafficMonitor monitors user traffic for abnormalities
type TrafficMonitor struct {
	enabled       bool
	users         map[int64]*UserTrafficProfile
	alerts        []*TrafficAlert
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	alertCallback func(*TrafficAlert)
}

// UserTrafficProfile tracks traffic patterns for a user
type UserTrafficProfile struct {
	UserID             int64
	History            []TrafficDataPoint
	AverageTraffic     float64
	StandardDeviation  float64
	PeakTraffic        int64
	LastUpdate         time.Time
	AnomalyScore       float64
	SuspiciousPatterns []string
}

// TrafficDataPoint represents a point in traffic history
type TrafficDataPoint struct {
	Timestamp   time.Time
	BytesIn     int64
	BytesOut    int64
	Connections int
}

// TrafficAlert represents an abnormal traffic alert
type TrafficAlert struct {
	AlertID     string
	UserID      int64
	Username    string
	AlertType   string // spike, anomaly, sustained_high, ddos_pattern
	Severity    string // low, medium, high, critical
	Description string
	Timestamp   time.Time
	TrafficData TrafficDataPoint
	Baseline    float64
	Deviation   float64
	Recommended string
	AutoBlocked bool
}

// Global traffic monitor
var TrafficMon *TrafficMonitor

// ============================================================================
// INITIALIZATION
// ============================================================================

// InitTrafficMonitor initializes traffic monitoring
func InitTrafficMonitor(enabled bool) error {
	ctx, cancel := context.WithCancel(context.Background())

	TrafficMon = &TrafficMonitor{
		enabled: enabled,
		users:   make(map[int64]*UserTrafficProfile),
		alerts:  make([]*TrafficAlert, 0),
		ctx:     ctx,
		cancel:  cancel,
	}

	if !enabled {
		LogInfo("TRAFFIC-MON", "Traffic monitoring disabled")
		return nil
	}

	// Start monitoring
	go TrafficMon.monitorLoop()

	LogSuccess("TRAFFIC-MON", "Traffic monitoring initialized")
	return nil
}

// ============================================================================
// MONITORING
// ============================================================================

// monitorLoop continuously monitors traffic
func (tm *TrafficMonitor) monitorLoop() {
	ticker := time.NewTicker(TrafficCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-tm.ctx.Done():
			return
		case <-ticker.C:
			tm.checkAllUsers()
		}
	}
}

// checkAllUsers checks traffic for all users
func (tm *TrafficMonitor) checkAllUsers() {
	// Get all active users
	result, err := Users.ListUsers(&UserFilter{Status: UserStatusActive})
	if err != nil {
		LogError("TRAFFIC-MON", "Failed to get users: %v", err)
		return
	}

	for _, user := range result.Users {
		go tm.analyzeUser(user.ID)
	}
}

// analyzeUser analyzes traffic patterns for a user
func (tm *TrafficMonitor) analyzeUser(userID int64) {
	tm.mu.Lock()
	profile, exists := tm.users[userID]
	if !exists {
		profile = &UserTrafficProfile{
			UserID:  userID,
			History: make([]TrafficDataPoint, 0, TrafficHistorySize),
		}
		tm.users[userID] = profile
	}
	tm.mu.Unlock()

	// Get current traffic stats
	stats, err := tm.getCurrentTrafficStats(userID)
	if err != nil {
		LogError("TRAFFIC-MON", "Failed to get traffic stats for user %d: %v", userID, err)
		return
	}

	// Add to history
	profile.addDataPoint(stats)

	// Update baseline statistics
	profile.updateBaseline()

	// Detect anomalies
	tm.detectAnomalies(profile, stats)
}

// getCurrentTrafficStats gets current traffic stats for a user
func (tm *TrafficMonitor) getCurrentTrafficStats(userID int64) (TrafficDataPoint, error) {
	// Get user email for traffic lookup
	var email string
	query := `SELECT email FROM users WHERE id = ?`
	err := Database.db.QueryRow(query, userID).Scan(&email)
	if err != nil {
		return TrafficDataPoint{
			Timestamp:   time.Now(),
			BytesIn:     0,
			BytesOut:    0,
			Connections: 0,
		}, fmt.Errorf("failed to get user email: %w", err)
	}

	// Use integrated traffic collection system
	return GetCurrentTrafficStats(userID, email)
}

// addDataPoint adds a data point to user history
func (utp *UserTrafficProfile) addDataPoint(point TrafficDataPoint) {
	utp.History = append(utp.History, point)

	// Keep only last N data points
	if len(utp.History) > TrafficHistorySize {
		utp.History = utp.History[len(utp.History)-TrafficHistorySize:]
	}

	utp.LastUpdate = time.Now()
}

// updateBaseline calculates average and standard deviation
func (utp *UserTrafficProfile) updateBaseline() {
	if len(utp.History) < 10 {
		return // Need at least 10 points for baseline
	}

	// Calculate average
	var sum float64
	for _, point := range utp.History {
		sum += float64(point.BytesIn + point.BytesOut)
	}
	utp.AverageTraffic = sum / float64(len(utp.History))

	// Calculate standard deviation
	var variance float64
	for _, point := range utp.History {
		total := float64(point.BytesIn + point.BytesOut)
		variance += math.Pow(total-utp.AverageTraffic, 2)
	}
	variance /= float64(len(utp.History))
	utp.StandardDeviation = math.Sqrt(variance)

	// Update peak
	for _, point := range utp.History {
		total := point.BytesIn + point.BytesOut
		if total > utp.PeakTraffic {
			utp.PeakTraffic = total
		}
	}
}

// ============================================================================
// ANOMALY DETECTION
// ============================================================================

// detectAnomalies detects abnormal traffic patterns
func (tm *TrafficMonitor) detectAnomalies(profile *UserTrafficProfile, current TrafficDataPoint) {
	if profile.AverageTraffic == 0 {
		return // No baseline yet
	}

	currentTotal := float64(current.BytesIn + current.BytesOut)

	// Check for traffic spike
	if currentTotal > profile.AverageTraffic*SpikeThresholdMultiplier {
		tm.createAlert(profile.UserID, "spike", "high", current,
			fmt.Sprintf("Traffic spike detected: %.2f MB (%.1fx normal)",
				currentTotal/1024/1024, currentTotal/profile.AverageTraffic))
	}

	// Check for sustained high traffic
	if tm.checkSustainedHigh(profile) {
		tm.createAlert(profile.UserID, "sustained_high", "medium", current,
			fmt.Sprintf("Sustained high traffic for %v", SustainedHighDuration))
	}

	// Check for too many connections
	if current.Connections > MaxConnectionsPerUser {
		tm.createAlert(profile.UserID, "too_many_connections", "high", current,
			fmt.Sprintf("Too many concurrent connections: %d", current.Connections))
	}

	// Check for DDoS patterns
	if tm.checkDDoSPattern(profile) {
		tm.createAlert(profile.UserID, "ddos_pattern", "critical", current,
			"Potential DDoS attack pattern detected")
	}

	// Calculate anomaly score
	profile.AnomalyScore = tm.calculateAnomalyScore(profile, current)

	// High anomaly score alert
	if profile.AnomalyScore > 0.8 {
		tm.createAlert(profile.UserID, "anomaly", "high", current,
			fmt.Sprintf("High anomaly score: %.2f", profile.AnomalyScore))
	}
}

// checkSustainedHigh checks for sustained high traffic
func (tm *TrafficMonitor) checkSustainedHigh(profile *UserTrafficProfile) bool {
	if len(profile.History) < 10 {
		return false
	}

	// Check last 10 minutes
	recentHistory := profile.History[len(profile.History)-10:]
	highCount := 0

	for _, point := range recentHistory {
		total := float64(point.BytesIn + point.BytesOut)
		if total > profile.AverageTraffic*2 {
			highCount++
		}
	}

	return highCount >= 8 // 8 out of 10 minutes
}

// checkDDoSPattern checks for DDoS attack patterns
func (tm *TrafficMonitor) checkDDoSPattern(profile *UserTrafficProfile) bool {
	if len(profile.History) < 5 {
		return false
	}

	recent := profile.History[len(profile.History)-5:]

	// Check for:
	// 1. Very high connection count
	// 2. Low bytes per connection
	// 3. Rapid connection changes

	var totalConnections int
	var totalBytes int64

	for _, point := range recent {
		totalConnections += point.Connections
		totalBytes += point.BytesIn + point.BytesOut
	}

	avgConnections := totalConnections / len(recent)
	bytesPerConnection := totalBytes / int64(totalConnections)

	// DDoS pattern: many connections, low traffic per connection
	if avgConnections > 50 && bytesPerConnection < 1024 {
		return true
	}

	return false
}

// calculateAnomalyScore calculates overall anomaly score (0-1)
func (tm *TrafficMonitor) calculateAnomalyScore(profile *UserTrafficProfile, current TrafficDataPoint) float64 {
	if profile.StandardDeviation == 0 {
		return 0
	}

	currentTotal := float64(current.BytesIn + current.BytesOut)

	// Z-score based anomaly
	zScore := math.Abs((currentTotal - profile.AverageTraffic) / profile.StandardDeviation)

	// Normalize to 0-1 scale
	score := math.Min(zScore/5.0, 1.0)

	// Adjust for connection count
	if current.Connections > 50 {
		score += 0.2
	}

	return math.Min(score, 1.0)
}

// ============================================================================
// ALERTING
// ============================================================================

// createAlert creates a new traffic alert
func (tm *TrafficMonitor) createAlert(userID int64, alertType, severity string,
	data TrafficDataPoint, description string) {

	user, _ := Users.GetUserByID(userID)
	username := fmt.Sprintf("User-%d", userID)
	if user != nil {
		username = user.Username
	}

	alert := &TrafficAlert{
		AlertID:     fmt.Sprintf("alert-%d-%d", userID, time.Now().Unix()),
		UserID:      userID,
		Username:    username,
		AlertType:   alertType,
		Severity:    severity,
		Description: description,
		Timestamp:   time.Now(),
		TrafficData: data,
		Recommended: tm.getRecommendation(alertType),
	}

	// Auto-block for critical alerts
	if severity == "critical" {
		alert.AutoBlocked = true
		tm.autoBlockUser(userID, alert.Description)
	}

	tm.mu.Lock()
	tm.alerts = append(tm.alerts, alert)
	// Keep only last 1000 alerts
	if len(tm.alerts) > 1000 {
		tm.alerts = tm.alerts[len(tm.alerts)-1000:]
	}
	tm.mu.Unlock()

	// Log alert
	LogWarn("TRAFFIC-MON", "[%s] User %s: %s", severity, username, description)

	// Callback
	if tm.alertCallback != nil {
		go tm.alertCallback(alert)
	}

	// Send notification if AI is enabled
	if AI != nil && AI.enabled {
		go tm.analyzeAlertWithAI(alert)
	}
}

// getRecommendation provides recommendation for alert type
func (tm *TrafficMonitor) getRecommendation(alertType string) string {
	recommendations := map[string]string{
		"spike":                "Monitor user activity. May be legitimate download or attack.",
		"sustained_high":       "Check if user has unlimited plan. May need throttling.",
		"too_many_connections": "Possible torrent usage or attack. Consider limiting connections.",
		"ddos_pattern":         "CRITICAL: Likely DDoS attack. Block user immediately.",
		"anomaly":              "Investigate user behavior. Enable detailed logging.",
	}

	return recommendations[alertType]
}

// autoBlockUser automatically blocks a user
func (tm *TrafficMonitor) autoBlockUser(userID int64, reason string) {
	LogWarn("TRAFFIC-MON", "Auto-blocking user %d: %s", userID, reason)

	// Disable user
	if err := Users.UpdateUserStatus(userID, UserStatusDisabled); err != nil {
		LogError("TRAFFIC-MON", "Failed to block user %d: %v", userID, err)
	}

	// Send admin notification
	NotifyAbnormalTrafficAlert(
		fmt.Sprintf("User#%d", userID),
		"N/A",
		fmt.Sprintf("Auto-blocked: %s", reason),
	)
}

// analyzeAlertWithAI uses AI to analyze the alert
func (tm *TrafficMonitor) analyzeAlertWithAI(alert *TrafficAlert) {
	if AI == nil || !AI.enabled {
		return
	}

	analysis, err := AI.AnalyzeTraffic(alert.UserID, map[string]interface{}{
		"alert_type":  alert.AlertType,
		"severity":    alert.Severity,
		"bytes_in":    alert.TrafficData.BytesIn,
		"bytes_out":   alert.TrafficData.BytesOut,
		"connections": alert.TrafficData.Connections,
		"description": alert.Description,
	})

	if err != nil {
		LogError("TRAFFIC-MON", "AI analysis failed: %v", err)
		return
	}

	if analysis.IsAbnormal {
		LogWarn("TRAFFIC-MON", "AI confirms anomaly for user %d: %s",
			alert.UserID, analysis.Description)

		// Take action based on AI recommendation
		if analysis.ThreatLevel == "high" && analysis.RecommendedAction != "" {
			LogWarn("TRAFFIC-MON", "AI recommends: %s", analysis.RecommendedAction)
		}
	}
}

// ============================================================================
// PUBLIC API
// ============================================================================

// GetAlerts returns recent alerts
func (tm *TrafficMonitor) GetAlerts(limit int) []*TrafficAlert {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	if limit <= 0 || limit > len(tm.alerts) {
		limit = len(tm.alerts)
	}

	result := make([]*TrafficAlert, limit)
	copy(result, tm.alerts[len(tm.alerts)-limit:])

	return result
}

// GetUserProfile returns traffic profile for a user
func (tm *TrafficMonitor) GetUserProfile(userID int64) *UserTrafficProfile {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	return tm.users[userID]
}

// SetAlertCallback sets callback for alerts
func (tm *TrafficMonitor) SetAlertCallback(callback func(*TrafficAlert)) {
	tm.alertCallback = callback
}

// GetStats returns monitoring statistics
func (tm *TrafficMonitor) GetStats() map[string]interface{} {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	criticalCount := 0
	highCount := 0

	for _, alert := range tm.alerts {
		switch alert.Severity {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		}
	}

	return map[string]interface{}{
		"enabled":         tm.enabled,
		"monitored_users": len(tm.users),
		"total_alerts":    len(tm.alerts),
		"critical_alerts": criticalCount,
		"high_alerts":     highCount,
	}
}
