// MX-UI VPN Panel
// Core/monitor.go
// System Monitoring: CPU, RAM, Disk, Network, Traffic Analytics, Alerts, Connection Logs

package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ============================================================================
// CONSTANTS
// ============================================================================

const (
	// Collection intervals
	MetricsCollectionInterval  = 5 * time.Second
	TrafficCollectionInterval  = 10 * time.Second
	AlertCheckInterval         = 30 * time.Second
	CleanupInterval            = 1 * time.Hour
	AnalyticsAggregateInterval = 5 * time.Minute

	// Retention periods
	MetricsRetention       = 24 * time.Hour
	TrafficLogRetention    = 7 * 24 * time.Hour
	ConnectionLogRetention = 30 * 24 * time.Hour
	AlertHistoryRetention  = 7 * 24 * time.Hour

	// Alert thresholds
	AlertCPUWarning      = 70.0
	AlertCPUCritical     = 90.0
	AlertRAMWarning      = 75.0
	AlertRAMCritical     = 90.0
	AlertDiskWarning     = 80.0
	AlertDiskCritical    = 95.0
	AlertNetworkWarning  = 80.0 // percentage of limit
	AlertNetworkCritical = 95.0

	// Alert types
	AlertTypeInfo     = "info"
	AlertTypeWarning  = "warning"
	AlertTypeCritical = "critical"
	AlertTypeRecovery = "recovery"

	// Alert channels
	AlertChannelTelegram = "telegram"
	AlertChannelEmail    = "email"
	AlertChannelWebhook  = "webhook"
	AlertChannelSMS      = "sms"

	// Traffic directions
	TrafficUpload   = "upload"
	TrafficDownload = "download"
)

// ============================================================================
// MONITOR MANAGER
// ============================================================================

// MonitorManager manages system monitoring
type MonitorManager struct {
	config           *Config
	metrics          *MetricsStore
	trafficStats     *TrafficStatsStore
	alertManager     *AlertManager
	analyticsEngine  *AnalyticsEngine
	connectionLogger *ConnectionLogger
	geoIPResolver    *GeoIPResolver
	mu               sync.RWMutex
	ctx              context.Context
	cancel           context.CancelFunc
	isRunning        bool
	lastMetrics      *SystemMetrics
}

// Global monitor instance
var (
	Monitor       *MonitorManager
	SystemMonitor *MonitorManager // Alias
)

// InitMonitor initializes the monitor manager
func InitMonitor(config *Config) error {
	ctx, cancel := context.WithCancel(context.Background())

	Monitor = &MonitorManager{
		config:           config,
		metrics:          NewMetricsStore(),
		trafficStats:     NewTrafficStatsStore(),
		alertManager:     NewAlertManager(config),
		analyticsEngine:  NewAnalyticsEngine(),
		connectionLogger: NewConnectionLogger(),
		geoIPResolver:    NewGeoIPResolver(),
		ctx:              ctx,
		cancel:           cancel,
	}
	SystemMonitor = Monitor // Set alias

	return nil
}

// Start starts the monitor
func (m *MonitorManager) Start() error {
	m.mu.Lock()
	if m.isRunning {
		m.mu.Unlock()
		return nil
	}
	m.isRunning = true
	m.mu.Unlock()

	// Start collectors
	go m.metricsCollector()
	go m.trafficCollector()
	go m.alertChecker()
	go m.analyticsAggregator()
	go m.cleanupRoutine()

	return nil
}

// Stop stops the monitor
func (m *MonitorManager) Stop() {
	m.mu.Lock()
	m.isRunning = false
	m.mu.Unlock()

	m.cancel()
}

// ============================================================================
// SYSTEM METRICS
// ============================================================================

// SystemMetrics represents system metrics at a point in time
type SystemMetrics struct {
	Timestamp time.Time `json:"timestamp"`

	// CPU
	CPUUsage  float64 `json:"cpu_usage"`
	CPUCores  int     `json:"cpu_cores"`
	CPUModel  string  `json:"cpu_model,omitempty"`
	LoadAvg1  float64 `json:"load_avg_1"`
	LoadAvg5  float64 `json:"load_avg_5"`
	LoadAvg15 float64 `json:"load_avg_15"`

	// Memory
	RAMTotal   uint64  `json:"ram_total"`
	RAMUsed    uint64  `json:"ram_used"`
	RAMFree    uint64  `json:"ram_free"`
	RAMUsage   float64 `json:"ram_usage"`
	RAMBuffers uint64  `json:"ram_buffers"`
	RAMCached  uint64  `json:"ram_cached"`
	SwapTotal  uint64  `json:"swap_total"`
	SwapUsed   uint64  `json:"swap_used"`
	SwapUsage  float64 `json:"swap_usage"`

	// Disk
	DiskTotal   uint64  `json:"disk_total"`
	DiskUsed    uint64  `json:"disk_used"`
	DiskFree    uint64  `json:"disk_free"`
	DiskUsage   float64 `json:"disk_usage"`
	DiskIORead  uint64  `json:"disk_io_read"`
	DiskIOWrite uint64  `json:"disk_io_write"`

	// Network
	NetworkIn      uint64 `json:"network_in"`       // Total bytes received
	NetworkOut     uint64 `json:"network_out"`      // Total bytes sent
	NetworkInRate  uint64 `json:"network_in_rate"`  // Bytes per second
	NetworkOutRate uint64 `json:"network_out_rate"` // Bytes per second
	TCPConnections int    `json:"tcp_connections"`
	UDPConnections int    `json:"udp_connections"`

	// Process
	Goroutines    int    `json:"goroutines"`
	ProcessMemory uint64 `json:"process_memory"`
	OpenFiles     int    `json:"open_files"`

	// System
	Uptime        uint64 `json:"uptime"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	KernelVersion string `json:"kernel_version,omitempty"`
}

// CPUInfo represents CPU information
type CPUInfo struct {
	Model     string  `json:"model"`
	Cores     int     `json:"cores"`
	Threads   int     `json:"threads"`
	Frequency float64 `json:"frequency"` // MHz
	Cache     int     `json:"cache"`     // KB
}

// DiskInfo represents disk information
type DiskInfo struct {
	Device     string  `json:"device"`
	MountPoint string  `json:"mount_point"`
	FSType     string  `json:"fs_type"`
	Total      uint64  `json:"total"`
	Used       uint64  `json:"used"`
	Free       uint64  `json:"free"`
	Usage      float64 `json:"usage"`
}

// NetworkInterface represents a network interface
type NetworkInterface struct {
	Name      string   `json:"name"`
	IPv4      []string `json:"ipv4"`
	IPv6      []string `json:"ipv6"`
	MAC       string   `json:"mac"`
	MTU       int      `json:"mtu"`
	RxBytes   uint64   `json:"rx_bytes"`
	TxBytes   uint64   `json:"tx_bytes"`
	RxPackets uint64   `json:"rx_packets"`
	TxPackets uint64   `json:"tx_packets"`
	RxErrors  uint64   `json:"rx_errors"`
	TxErrors  uint64   `json:"tx_errors"`
	IsUp      bool     `json:"is_up"`
}

// CollectSystemMetrics collects current system metrics
func (m *MonitorManager) CollectSystemMetrics() (*SystemMetrics, error) {
	metrics := &SystemMetrics{
		Timestamp:  time.Now(),
		CPUCores:   runtime.NumCPU(),
		Goroutines: runtime.NumGoroutine(),
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
	}

	// Hostname
	metrics.Hostname, _ = os.Hostname()

	// CPU Usage
	metrics.CPUUsage = m.getCPUUsage()
	metrics.LoadAvg1, metrics.LoadAvg5, metrics.LoadAvg15 = m.getLoadAverage()
	metrics.CPUModel = m.getCPUModel()

	// Memory
	m.getMemoryInfo(metrics)

	// Disk
	m.getDiskInfo(metrics)

	// Network
	m.getNetworkInfo(metrics)

	// Process info
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	metrics.ProcessMemory = memStats.Alloc

	// Open files
	metrics.OpenFiles = m.getOpenFilesCount()

	// Uptime
	metrics.Uptime = m.getSystemUptime()

	// Kernel version
	metrics.KernelVersion = m.getKernelVersion()

	// Store metrics
	m.metrics.Add(metrics)

	// Calculate rates
	if m.lastMetrics != nil {
		elapsed := metrics.Timestamp.Sub(m.lastMetrics.Timestamp).Seconds()
		if elapsed > 0 {
			metrics.NetworkInRate = uint64(float64(metrics.NetworkIn-m.lastMetrics.NetworkIn) / elapsed)
			metrics.NetworkOutRate = uint64(float64(metrics.NetworkOut-m.lastMetrics.NetworkOut) / elapsed)
		}
	}

	m.lastMetrics = metrics

	return metrics, nil
}

// getCPUUsage calculates CPU usage percentage
func (m *MonitorManager) getCPUUsage() float64 {
	if runtime.GOOS != "linux" {
		return 0
	}

	// Read /proc/stat
	data, err := ioutil.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return 0
	}

	// Parse first line (cpu aggregate)
	fields := strings.Fields(lines[0])
	if len(fields) < 5 {
		return 0
	}

	var total, idle uint64
	for i := 1; i < len(fields); i++ {
		val, _ := strconv.ParseUint(fields[i], 10, 64)
		total += val
		if i == 4 { // idle is 4th field
			idle = val
		}
	}

	if total == 0 {
		return 0
	}

	return float64(total-idle) / float64(total) * 100
}

// getLoadAverage gets system load average
func (m *MonitorManager) getLoadAverage() (float64, float64, float64) {
	if runtime.GOOS != "linux" {
		return 0, 0, 0
	}

	data, err := ioutil.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0
	}

	load1, _ := strconv.ParseFloat(fields[0], 64)
	load5, _ := strconv.ParseFloat(fields[1], 64)
	load15, _ := strconv.ParseFloat(fields[2], 64)

	return load1, load5, load15
}

// getCPUModel gets CPU model name
func (m *MonitorManager) getCPUModel() string {
	if runtime.GOOS != "linux" {
		return ""
	}

	data, err := ioutil.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}

	re := regexp.MustCompile(`model name\s*:\s*(.+)`)
	matches := re.FindStringSubmatch(string(data))
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}

	return ""
}

// getMemoryInfo gets memory information
func (m *MonitorManager) getMemoryInfo(metrics *SystemMetrics) {
	if runtime.GOOS != "linux" {
		return
	}

	data, err := ioutil.ReadFile("/proc/meminfo")
	if err != nil {
		return
	}

	memInfo := make(map[string]uint64)
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			key := strings.TrimSuffix(fields[0], ":")
			val, _ := strconv.ParseUint(fields[1], 10, 64)
			memInfo[key] = val * 1024 // Convert from KB to bytes
		}
	}

	metrics.RAMTotal = memInfo["MemTotal"]
	metrics.RAMFree = memInfo["MemFree"]
	metrics.RAMBuffers = memInfo["Buffers"]
	metrics.RAMCached = memInfo["Cached"]
	metrics.RAMUsed = metrics.RAMTotal - metrics.RAMFree - metrics.RAMBuffers - metrics.RAMCached

	if metrics.RAMTotal > 0 {
		metrics.RAMUsage = float64(metrics.RAMUsed) / float64(metrics.RAMTotal) * 100
	}

	metrics.SwapTotal = memInfo["SwapTotal"]
	metrics.SwapUsed = memInfo["SwapTotal"] - memInfo["SwapFree"]
	if metrics.SwapTotal > 0 {
		metrics.SwapUsage = float64(metrics.SwapUsed) / float64(metrics.SwapTotal) * 100
	}
}

// getDiskInfo gets disk information
func (m *MonitorManager) getDiskInfo(metrics *SystemMetrics) {
	var stat syscall.Statfs_t
	err := syscall.Statfs("/", &stat)
	if err != nil {
		return
	}

	metrics.DiskTotal = stat.Blocks * uint64(stat.Bsize)
	metrics.DiskFree = stat.Bfree * uint64(stat.Bsize)
	metrics.DiskUsed = metrics.DiskTotal - metrics.DiskFree

	if metrics.DiskTotal > 0 {
		metrics.DiskUsage = float64(metrics.DiskUsed) / float64(metrics.DiskTotal) * 100
	}

	// Disk I/O
	m.getDiskIO(metrics)
}

// getDiskIO gets disk I/O statistics
func (m *MonitorManager) getDiskIO(metrics *SystemMetrics) {
	if runtime.GOOS != "linux" {
		return
	}

	data, err := ioutil.ReadFile("/proc/diskstats")
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 14 {
			continue
		}

		// Skip partitions, only count whole disks
		device := fields[2]
		if strings.HasPrefix(device, "sd") && len(device) == 3 ||
			strings.HasPrefix(device, "vd") && len(device) == 3 ||
			strings.HasPrefix(device, "nvme") && strings.Contains(device, "n") && !strings.Contains(device, "p") {

			sectorsRead, _ := strconv.ParseUint(fields[5], 10, 64)
			sectorsWrite, _ := strconv.ParseUint(fields[9], 10, 64)

			metrics.DiskIORead += sectorsRead * 512
			metrics.DiskIOWrite += sectorsWrite * 512
		}
	}
}

// getNetworkInfo gets network information
func (m *MonitorManager) getNetworkInfo(metrics *SystemMetrics) {
	if runtime.GOOS != "linux" {
		return
	}

	// Network bytes
	data, err := ioutil.ReadFile("/proc/net/dev")
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if !strings.Contains(line, ":") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 17 {
			continue
		}

		iface := strings.TrimSuffix(fields[0], ":")
		if iface == "lo" {
			continue // Skip loopback
		}

		rxBytes, _ := strconv.ParseUint(fields[1], 10, 64)
		txBytes, _ := strconv.ParseUint(fields[9], 10, 64)

		metrics.NetworkIn += rxBytes
		metrics.NetworkOut += txBytes
	}

	// TCP/UDP connections
	metrics.TCPConnections = m.countConnections("/proc/net/tcp") + m.countConnections("/proc/net/tcp6")
	metrics.UDPConnections = m.countConnections("/proc/net/udp") + m.countConnections("/proc/net/udp6")
}

// countConnections counts connections in /proc/net files
func (m *MonitorManager) countConnections(path string) int {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return 0
	}

	lines := strings.Split(string(data), "\n")
	count := 0
	for i, line := range lines {
		if i == 0 { // Skip header
			continue
		}
		if strings.TrimSpace(line) != "" {
			count++
		}
	}

	return count
}

// getOpenFilesCount gets the number of open files
func (m *MonitorManager) getOpenFilesCount() int {
	pid := os.Getpid()
	path := fmt.Sprintf("/proc/%d/fd", pid)

	files, err := ioutil.ReadDir(path)
	if err != nil {
		return 0
	}

	return len(files)
}

// getSystemUptime gets system uptime in seconds
func (m *MonitorManager) getSystemUptime() uint64 {
	if runtime.GOOS != "linux" {
		return 0
	}

	data, err := ioutil.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}

	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}

	uptime, _ := strconv.ParseFloat(fields[0], 64)
	return uint64(uptime)
}

// getKernelVersion gets the kernel version
func (m *MonitorManager) getKernelVersion() string {
	if runtime.GOOS != "linux" {
		return ""
	}

	data, err := ioutil.ReadFile("/proc/version")
	if err != nil {
		return ""
	}

	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		return fields[2]
	}

	return ""
}

// GetAllDisks gets information about all disks
func (m *MonitorManager) GetAllDisks() ([]DiskInfo, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("unsupported OS")
	}

	// Read /etc/mtab or /proc/mounts
	data, err := ioutil.ReadFile("/proc/mounts")
	if err != nil {
		return nil, err
	}

	disks := []DiskInfo{}
	seen := make(map[string]bool)

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		device := fields[0]
		mountPoint := fields[1]
		fsType := fields[2]

		// Skip virtual filesystems
		if !strings.HasPrefix(device, "/dev/") {
			continue
		}

		// Skip duplicates
		if seen[device] {
			continue
		}
		seen[device] = true

		var stat syscall.Statfs_t
		if err := syscall.Statfs(mountPoint, &stat); err != nil {
			continue
		}

		disk := DiskInfo{
			Device:     device,
			MountPoint: mountPoint,
			FSType:     fsType,
			Total:      stat.Blocks * uint64(stat.Bsize),
			Free:       stat.Bfree * uint64(stat.Bsize),
		}
		disk.Used = disk.Total - disk.Free
		if disk.Total > 0 {
			disk.Usage = float64(disk.Used) / float64(disk.Total) * 100
		}

		disks = append(disks, disk)
	}

	return disks, nil
}

// GetNetworkInterfaces gets all network interfaces
func (m *MonitorManager) GetNetworkInterfaces() ([]NetworkInterface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	result := []NetworkInterface{}

	for _, iface := range interfaces {
		ni := NetworkInterface{
			Name: iface.Name,
			MAC:  iface.HardwareAddr.String(),
			MTU:  iface.MTU,
			IsUp: iface.Flags&net.FlagUp != 0,
			IPv4: []string{},
			IPv6: []string{},
		}

		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}

			if ip.To4() != nil {
				ni.IPv4 = append(ni.IPv4, addr.String())
			} else {
				ni.IPv6 = append(ni.IPv6, addr.String())
			}
		}

		// Get interface statistics
		m.getInterfaceStats(&ni)

		result = append(result, ni)
	}

	return result, nil
}

// getInterfaceStats gets interface statistics
func (m *MonitorManager) getInterfaceStats(ni *NetworkInterface) {
	if runtime.GOOS != "linux" {
		return
	}

	basePath := fmt.Sprintf("/sys/class/net/%s/statistics/", ni.Name)

	readUint64 := func(name string) uint64 {
		data, err := ioutil.ReadFile(basePath + name)
		if err != nil {
			return 0
		}
		val, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		return val
	}

	ni.RxBytes = readUint64("rx_bytes")
	ni.TxBytes = readUint64("tx_bytes")
	ni.RxPackets = readUint64("rx_packets")
	ni.TxPackets = readUint64("tx_packets")
	ni.RxErrors = readUint64("rx_errors")
	ni.TxErrors = readUint64("tx_errors")
}

// GetPublicIP gets the server's public IP address
func (m *MonitorManager) GetPublicIP() (ipv4, ipv6 string) {
	// IPv4
	resp, err := http.Get("https://api.ipify.org")
	if err == nil {
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		ipv4 = strings.TrimSpace(string(body))
	}

	// IPv6
	resp, err = http.Get("https://api6.ipify.org")
	if err == nil {
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		ipv6 = strings.TrimSpace(string(body))
	}

	return
}

// ============================================================================
// METRICS STORE
// ============================================================================

// MetricsStore stores metrics history
type MetricsStore struct {
	metrics []*SystemMetrics
	maxSize int
	mu      sync.RWMutex
}

// NewMetricsStore creates a new metrics store
func NewMetricsStore() *MetricsStore {
	return &MetricsStore{
		metrics: []*SystemMetrics{},
		maxSize: 8640, // 24 hours at 10s intervals
	}
}

// Add adds metrics to the store
func (ms *MetricsStore) Add(m *SystemMetrics) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.metrics = append(ms.metrics, m)

	// Trim if exceeded max size
	if len(ms.metrics) > ms.maxSize {
		ms.metrics = ms.metrics[len(ms.metrics)-ms.maxSize:]
	}
}

// GetLast gets the last n metrics
func (ms *MetricsStore) GetLast(n int) []*SystemMetrics {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	if n > len(ms.metrics) {
		n = len(ms.metrics)
	}

	result := make([]*SystemMetrics, n)
	copy(result, ms.metrics[len(ms.metrics)-n:])
	return result
}

// GetRange gets metrics in a time range
func (ms *MetricsStore) GetRange(start, end time.Time) []*SystemMetrics {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	result := []*SystemMetrics{}
	for _, m := range ms.metrics {
		if m.Timestamp.After(start) && m.Timestamp.Before(end) {
			result = append(result, m)
		}
	}
	return result
}

// GetAverage gets average metrics over a duration
func (ms *MetricsStore) GetAverage(duration time.Duration) *SystemMetrics {
	now := time.Now()
	metrics := ms.GetRange(now.Add(-duration), now)

	if len(metrics) == 0 {
		return nil
	}

	avg := &SystemMetrics{Timestamp: now}
	n := float64(len(metrics))

	for _, m := range metrics {
		avg.CPUUsage += m.CPUUsage
		avg.RAMUsage += m.RAMUsage
		avg.DiskUsage += m.DiskUsage
		avg.NetworkInRate += m.NetworkInRate
		avg.NetworkOutRate += m.NetworkOutRate
		avg.LoadAvg1 += m.LoadAvg1
	}

	avg.CPUUsage /= n
	avg.RAMUsage /= n
	avg.DiskUsage /= n
	avg.NetworkInRate = uint64(float64(avg.NetworkInRate) / n)
	avg.NetworkOutRate = uint64(float64(avg.NetworkOutRate) / n)
	avg.LoadAvg1 /= n

	return avg
}

// Cleanup removes old metrics
func (ms *MetricsStore) Cleanup(maxAge time.Duration) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	newMetrics := []*SystemMetrics{}

	for _, m := range ms.metrics {
		if m.Timestamp.After(cutoff) {
			newMetrics = append(newMetrics, m)
		}
	}

	ms.metrics = newMetrics
}

// ============================================================================
// TRAFFIC STATISTICS
// ============================================================================

// TrafficStatsStore stores traffic statistics
type TrafficStatsStore struct {
	userTraffic   map[int64]*UserTrafficStats
	protocolStats map[string]*ProtocolStats
	nodeTraffic   map[int64]*NodeTrafficStats
	hourlyStats   []*HourlyStats
	dailyStats    []*DailyStats
	mu            sync.RWMutex
}

// UserTrafficStats represents traffic stats for a user
type UserTrafficStats struct {
	UserID       int64          `json:"user_id"`
	Username     string         `json:"username"`
	Upload       int64          `json:"upload"`
	Download     int64          `json:"download"`
	Total        int64          `json:"total"`
	Connections  int            `json:"connections"`
	LastActivity time.Time      `json:"last_activity"`
	History      []TrafficPoint `json:"history,omitempty"`
}

// ProtocolStats represents traffic stats per protocol
type ProtocolStats struct {
	Protocol    string  `json:"protocol"`
	Upload      int64   `json:"upload"`
	Download    int64   `json:"download"`
	Total       int64   `json:"total"`
	Users       int     `json:"users"`
	Connections int     `json:"connections"`
	Percentage  float64 `json:"percentage"`
}

// NodeTrafficStats represents traffic stats per node
type NodeTrafficStats struct {
	NodeID      int64  `json:"node_id"`
	NodeName    string `json:"node_name"`
	Upload      int64  `json:"upload"`
	Download    int64  `json:"download"`
	Total       int64  `json:"total"`
	ActiveUsers int    `json:"active_users"`
}

// TrafficPoint represents a traffic data point
type TrafficPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Upload    int64     `json:"upload"`
	Download  int64     `json:"download"`
}

// HourlyStats represents hourly statistics
type HourlyStats struct {
	Hour        time.Time `json:"hour"`
	Upload      int64     `json:"upload"`
	Download    int64     `json:"download"`
	Total       int64     `json:"total"`
	Users       int       `json:"users"`
	Connections int       `json:"connections"`
	NewUsers    int       `json:"new_users"`
}

// DailyStats represents daily statistics
type DailyStats struct {
	Date        time.Time `json:"date"`
	Upload      int64     `json:"upload"`
	Download    int64     `json:"download"`
	Total       int64     `json:"total"`
	UniqueUsers int       `json:"unique_users"`
	NewUsers    int       `json:"new_users"`
	PeakOnline  int       `json:"peak_online"`
	AvgOnline   int       `json:"avg_online"`
}

// NewTrafficStatsStore creates a new traffic stats store
func NewTrafficStatsStore() *TrafficStatsStore {
	return &TrafficStatsStore{
		userTraffic:   make(map[int64]*UserTrafficStats),
		protocolStats: make(map[string]*ProtocolStats),
		nodeTraffic:   make(map[int64]*NodeTrafficStats),
		hourlyStats:   []*HourlyStats{},
		dailyStats:    []*DailyStats{},
	}
}

// RecordUserTraffic records traffic for a user
func (ts *TrafficStatsStore) RecordUserTraffic(userID int64, username string, upload, download int64) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	stats, exists := ts.userTraffic[userID]
	if !exists {
		stats = &UserTrafficStats{
			UserID:   userID,
			Username: username,
			History:  []TrafficPoint{},
		}
		ts.userTraffic[userID] = stats
	}

	stats.Upload += upload
	stats.Download += download
	stats.Total = stats.Upload + stats.Download
	stats.LastActivity = time.Now()

	// Add to history
	stats.History = append(stats.History, TrafficPoint{
		Timestamp: time.Now(),
		Upload:    upload,
		Download:  download,
	})

	// Keep only last 60 points
	if len(stats.History) > 60 {
		stats.History = stats.History[len(stats.History)-60:]
	}
}

// RecordProtocolTraffic records traffic for a protocol
func (ts *TrafficStatsStore) RecordProtocolTraffic(protocol string, upload, download int64, userID int64) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	stats, exists := ts.protocolStats[protocol]
	if !exists {
		stats = &ProtocolStats{Protocol: protocol}
		ts.protocolStats[protocol] = stats
	}

	stats.Upload += upload
	stats.Download += download
	stats.Total = stats.Upload + stats.Download
	stats.Connections++
}

// RecordNodeTraffic records traffic for a node
func (ts *TrafficStatsStore) RecordNodeTraffic(nodeID int64, nodeName string, upload, download int64) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	stats, exists := ts.nodeTraffic[nodeID]
	if !exists {
		stats = &NodeTrafficStats{
			NodeID:   nodeID,
			NodeName: nodeName,
		}
		ts.nodeTraffic[nodeID] = stats
	}

	stats.Upload += upload
	stats.Download += download
	stats.Total = stats.Upload + stats.Download
}

// GetTopUsers returns top users by traffic
func (ts *TrafficStatsStore) GetTopUsers(limit int) []*UserTrafficStats {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	users := make([]*UserTrafficStats, 0, len(ts.userTraffic))
	for _, u := range ts.userTraffic {
		users = append(users, u)
	}

	sort.Slice(users, func(i, j int) bool {
		return users[i].Total > users[j].Total
	})

	if limit > len(users) {
		limit = len(users)
	}

	return users[:limit]
}

// GetProtocolStats returns protocol statistics
func (ts *TrafficStatsStore) GetProtocolStats() []*ProtocolStats {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	stats := make([]*ProtocolStats, 0, len(ts.protocolStats))
	totalTraffic := int64(0)

	for _, p := range ts.protocolStats {
		stats = append(stats, p)
		totalTraffic += p.Total
	}

	// Calculate percentages
	for _, p := range stats {
		if totalTraffic > 0 {
			p.Percentage = float64(p.Total) / float64(totalTraffic) * 100
		}
	}

	// Sort by total traffic
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Total > stats[j].Total
	})

	return stats
}

// GetNodeStats returns node traffic statistics
func (ts *TrafficStatsStore) GetNodeStats() []*NodeTrafficStats {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	stats := make([]*NodeTrafficStats, 0, len(ts.nodeTraffic))
	for _, n := range ts.nodeTraffic {
		stats = append(stats, n)
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Total > stats[j].Total
	})

	return stats
}

// GetHourlyStats returns hourly statistics
func (ts *TrafficStatsStore) GetHourlyStats(hours int) []*HourlyStats {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if hours > len(ts.hourlyStats) {
		hours = len(ts.hourlyStats)
	}

	result := make([]*HourlyStats, hours)
	copy(result, ts.hourlyStats[len(ts.hourlyStats)-hours:])
	return result
}

// GetDailyStats returns daily statistics
func (ts *TrafficStatsStore) GetDailyStats(days int) []*DailyStats {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if days > len(ts.dailyStats) {
		days = len(ts.dailyStats)
	}

	result := make([]*DailyStats, days)
	copy(result, ts.dailyStats[len(ts.dailyStats)-days:])
	return result
}

// ============================================================================
// ALERT MANAGER
// ============================================================================

// AlertManager manages system alerts
type AlertManager struct {
	config       *Config
	alerts       []*Alert
	activeAlerts map[string]*Alert
	alertHistory []*Alert
	subscribers  []AlertSubscriber
	cooldowns    map[string]time.Time
	mu           sync.RWMutex
}

// Alert represents a system alert
type Alert struct {
	ID           string     `json:"id"`
	Type         string     `json:"type"`     // info, warning, critical, recovery
	Category     string     `json:"category"` // cpu, ram, disk, network, node, user
	Title        string     `json:"title"`
	Message      string     `json:"message"`
	Value        float64    `json:"value,omitempty"`
	Threshold    float64    `json:"threshold,omitempty"`
	NodeID       int64      `json:"node_id,omitempty"`
	UserID       int64      `json:"user_id,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	ResolvedAt   *time.Time `json:"resolved_at,omitempty"`
	Acknowledged bool       `json:"acknowledged"`
	NotifiedVia  []string   `json:"notified_via,omitempty"`
}

// AlertSubscriber represents an alert subscriber
type AlertSubscriber interface {
	SendAlert(alert *Alert) error
	GetChannel() string
}

// AlertRule represents an alert rule
type AlertRule struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Category  string   `json:"category"`
	Metric    string   `json:"metric"`
	Operator  string   `json:"operator"` // gt, lt, eq, gte, lte
	Threshold float64  `json:"threshold"`
	Duration  int      `json:"duration"` // seconds
	Severity  string   `json:"severity"` // warning, critical
	Enabled   bool     `json:"enabled"`
	Cooldown  int      `json:"cooldown"` // seconds between alerts
	Channels  []string `json:"channels"`
}

// NewAlertManager creates a new alert manager
func NewAlertManager(config *Config) *AlertManager {
	return &AlertManager{
		config:       config,
		alerts:       []*Alert{},
		activeAlerts: make(map[string]*Alert),
		alertHistory: []*Alert{},
		cooldowns:    make(map[string]time.Time),
	}
}

// AddSubscriber adds an alert subscriber
func (am *AlertManager) AddSubscriber(s AlertSubscriber) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.subscribers = append(am.subscribers, s)
}

// CreateAlert creates and sends an alert
func (am *AlertManager) CreateAlert(alertType, category, title, message string, value, threshold float64) *Alert {
	am.mu.Lock()
	defer am.mu.Unlock()

	alertKey := fmt.Sprintf("%s_%s", category, title)

	// Check cooldown
	if lastAlert, exists := am.cooldowns[alertKey]; exists {
		if time.Since(lastAlert) < 5*time.Minute {
			return nil
		}
	}

	alert := &Alert{
		ID:        fmt.Sprintf("%d_%s", time.Now().UnixNano(), category),
		Type:      alertType,
		Category:  category,
		Title:     title,
		Message:   message,
		Value:     value,
		Threshold: threshold,
		CreatedAt: time.Now(),
	}

	am.alerts = append(am.alerts, alert)
	am.alertHistory = append(am.alertHistory, alert)

	// Mark as active if critical or warning
	if alertType == AlertTypeWarning || alertType == AlertTypeCritical {
		am.activeAlerts[alertKey] = alert
	}

	// Update cooldown
	am.cooldowns[alertKey] = time.Now()

	// Send to subscribers
	go am.notifySubscribers(alert)

	return alert
}

// ResolveAlert resolves an active alert
func (am *AlertManager) ResolveAlert(category, title string) {
	am.mu.Lock()
	defer am.mu.Unlock()

	alertKey := fmt.Sprintf("%s_%s", category, title)

	if alert, exists := am.activeAlerts[alertKey]; exists {
		now := time.Now()
		alert.ResolvedAt = &now
		delete(am.activeAlerts, alertKey)

		// Create recovery alert
		recoveryAlert := &Alert{
			ID:        fmt.Sprintf("%d_%s_recovery", time.Now().UnixNano(), category),
			Type:      AlertTypeRecovery,
			Category:  category,
			Title:     fmt.Sprintf("Resolved: %s", title),
			Message:   fmt.Sprintf("Alert resolved after %s", now.Sub(alert.CreatedAt).Round(time.Second)),
			CreatedAt: now,
		}

		am.alertHistory = append(am.alertHistory, recoveryAlert)
		go am.notifySubscribers(recoveryAlert)
	}
}

// GetActiveAlerts returns active alerts
func (am *AlertManager) GetActiveAlerts() []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	alerts := make([]*Alert, 0, len(am.activeAlerts))
	for _, a := range am.activeAlerts {
		alerts = append(alerts, a)
	}

	// Sort by created time
	sort.Slice(alerts, func(i, j int) bool {
		return alerts[i].CreatedAt.After(alerts[j].CreatedAt)
	})

	return alerts
}

// GetAlertHistory returns alert history
func (am *AlertManager) GetAlertHistory(limit int) []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if limit > len(am.alertHistory) {
		limit = len(am.alertHistory)
	}

	result := make([]*Alert, limit)
	copy(result, am.alertHistory[len(am.alertHistory)-limit:])

	// Reverse to get newest first
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return result
}

// AcknowledgeAlert acknowledges an alert
func (am *AlertManager) AcknowledgeAlert(id string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	for _, alert := range am.alerts {
		if alert.ID == id {
			alert.Acknowledged = true
			return nil
		}
	}

	return errors.New("alert not found")
}

// notifySubscribers notifies all subscribers about an alert
func (am *AlertManager) notifySubscribers(alert *Alert) {
	am.mu.RLock()
	subscribers := make([]AlertSubscriber, len(am.subscribers))
	copy(subscribers, am.subscribers)
	am.mu.RUnlock()

	for _, sub := range subscribers {
		if err := sub.SendAlert(alert); err == nil {
			am.mu.Lock()
			alert.NotifiedVia = append(alert.NotifiedVia, sub.GetChannel())
			am.mu.Unlock()
		}
	}
}

// CheckThresholds checks metrics against thresholds
func (am *AlertManager) CheckThresholds(metrics *SystemMetrics) {
	// CPU
	if metrics.CPUUsage >= AlertCPUCritical {
		am.CreateAlert(AlertTypeCritical, "cpu", "Critical CPU Usage",
			fmt.Sprintf("CPU usage is at %.1f%% (threshold: %.1f%%)", metrics.CPUUsage, AlertCPUCritical),
			metrics.CPUUsage, AlertCPUCritical)
	} else if metrics.CPUUsage >= AlertCPUWarning {
		am.CreateAlert(AlertTypeWarning, "cpu", "High CPU Usage",
			fmt.Sprintf("CPU usage is at %.1f%% (threshold: %.1f%%)", metrics.CPUUsage, AlertCPUWarning),
			metrics.CPUUsage, AlertCPUWarning)
	} else if metrics.CPUUsage < AlertCPUWarning {
		am.ResolveAlert("cpu", "High CPU Usage")
		am.ResolveAlert("cpu", "Critical CPU Usage")
	}

	// RAM
	if metrics.RAMUsage >= AlertRAMCritical {
		am.CreateAlert(AlertTypeCritical, "ram", "Critical Memory Usage",
			fmt.Sprintf("Memory usage is at %.1f%% (threshold: %.1f%%)", metrics.RAMUsage, AlertRAMCritical),
			metrics.RAMUsage, AlertRAMCritical)
	} else if metrics.RAMUsage >= AlertRAMWarning {
		am.CreateAlert(AlertTypeWarning, "ram", "High Memory Usage",
			fmt.Sprintf("Memory usage is at %.1f%% (threshold: %.1f%%)", metrics.RAMUsage, AlertRAMWarning),
			metrics.RAMUsage, AlertRAMWarning)
	} else if metrics.RAMUsage < AlertRAMWarning {
		am.ResolveAlert("ram", "High Memory Usage")
		am.ResolveAlert("ram", "Critical Memory Usage")
	}

	// Disk
	if metrics.DiskUsage >= AlertDiskCritical {
		am.CreateAlert(AlertTypeCritical, "disk", "Critical Disk Usage",
			fmt.Sprintf("Disk usage is at %.1f%% (threshold: %.1f%%)", metrics.DiskUsage, AlertDiskCritical),
			metrics.DiskUsage, AlertDiskCritical)
	} else if metrics.DiskUsage >= AlertDiskWarning {
		am.CreateAlert(AlertTypeWarning, "disk", "High Disk Usage",
			fmt.Sprintf("Disk usage is at %.1f%% (threshold: %.1f%%)", metrics.DiskUsage, AlertDiskWarning),
			metrics.DiskUsage, AlertDiskWarning)
	} else if metrics.DiskUsage < AlertDiskWarning {
		am.ResolveAlert("disk", "High Disk Usage")
		am.ResolveAlert("disk", "Critical Disk Usage")
	}
}

// Cleanup removes old alerts
func (am *AlertManager) Cleanup(maxAge time.Duration) {
	am.mu.Lock()
	defer am.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	newHistory := []*Alert{}

	for _, alert := range am.alertHistory {
		if alert.CreatedAt.After(cutoff) {
			newHistory = append(newHistory, alert)
		}
	}

	am.alertHistory = newHistory
}

// ============================================================================
// TELEGRAM ALERT SUBSCRIBER
// ============================================================================

// TelegramAlertSubscriber sends alerts to Telegram
type TelegramAlertSubscriber struct {
	bot     *TelegramBot
	chatIDs []int64
}

// NewTelegramAlertSubscriber creates a new Telegram alert subscriber
func NewTelegramAlertSubscriber(bot *TelegramBot, chatIDs []int64) *TelegramAlertSubscriber {
	return &TelegramAlertSubscriber{
		bot:     bot,
		chatIDs: chatIDs,
	}
}

// SendAlert sends an alert via Telegram
func (t *TelegramAlertSubscriber) SendAlert(alert *Alert) error {
	if t.bot == nil || len(t.chatIDs) == 0 {
		return errors.New("telegram not configured")
	}

	icon := "â„¹ï¸"
	switch alert.Type {
	case AlertTypeWarning:
		icon = "âš ï¸"
	case AlertTypeCritical:
		icon = "ðŸš¨"
	case AlertTypeRecovery:
		icon = "âœ…"
	}

	text := fmt.Sprintf(`
%s *%s*

ðŸ“‹ %s

ðŸ• %s
`, icon, alert.Title, alert.Message, alert.CreatedAt.Format("2006-01-02 15:04:05"))

	for _, chatID := range t.chatIDs {
		t.bot.SendMessage(chatID, text, &SendMessageOptions{ParseMode: "Markdown"})
	}

	return nil
}

// GetChannel returns the channel name
func (t *TelegramAlertSubscriber) GetChannel() string {
	return AlertChannelTelegram
}

// ============================================================================
// CONNECTION LOGGER
// ============================================================================

// ConnectionLogger logs user connections
type ConnectionLogger struct {
	logs    []*ConnectionLogEntry
	maxSize int
	mu      sync.RWMutex
}

// ConnectionLogEntry represents a connection log entry
type ConnectionLogEntry struct {
	ID             int64        `json:"id"`
	UserID         int64        `json:"user_id"`
	Username       string       `json:"username"`
	NodeID         int64        `json:"node_id"`
	NodeName       string       `json:"node_name"`
	IP             string       `json:"ip"`
	Location       *GeoLocation `json:"location,omitempty"`
	Protocol       string       `json:"protocol"`
	Inbound        string       `json:"inbound"`
	Upload         int64        `json:"upload"`
	Download       int64        `json:"download"`
	Duration       int64        `json:"duration"` // seconds
	ConnectedAt    time.Time    `json:"connected_at"`
	DisconnectedAt *time.Time   `json:"disconnected_at,omitempty"`
}

// NewConnectionLogger creates a new connection logger
func NewConnectionLogger() *ConnectionLogger {
	return &ConnectionLogger{
		logs:    []*ConnectionLogEntry{},
		maxSize: 10000,
	}
}

// LogConnection logs a new connection
func (cl *ConnectionLogger) LogConnection(entry *ConnectionLogEntry) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	entry.ID = time.Now().UnixNano()
	entry.ConnectedAt = time.Now()

	cl.logs = append(cl.logs, entry)

	// Trim if exceeded max size
	if len(cl.logs) > cl.maxSize {
		cl.logs = cl.logs[len(cl.logs)-cl.maxSize:]
	}

	// Also save to database
	go cl.saveToDatabase(entry)
}

// LogDisconnection logs a disconnection
func (cl *ConnectionLogger) LogDisconnection(userID int64, ip string, upload, download int64) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	now := time.Now()

	for i := len(cl.logs) - 1; i >= 0; i-- {
		if cl.logs[i].UserID == userID && cl.logs[i].IP == ip && cl.logs[i].DisconnectedAt == nil {
			cl.logs[i].DisconnectedAt = &now
			cl.logs[i].Upload = upload
			cl.logs[i].Download = download
			cl.logs[i].Duration = int64(now.Sub(cl.logs[i].ConnectedAt).Seconds())

			go cl.updateDatabase(cl.logs[i])
			break
		}
	}
}

// saveToDatabase saves connection to database
func (cl *ConnectionLogger) saveToDatabase(entry *ConnectionLogEntry) {
	if DB == nil {
		return
	}

	_, err := DB.db.Exec(`
		INSERT INTO connection_logs (user_id, node_id, ip, location, protocol, inbound, connected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, entry.UserID, entry.NodeID, entry.IP,
		func() string {
			if entry.Location != nil {
				return entry.Location.Country
			}
			return ""
		}(),
		entry.Protocol, entry.Inbound, entry.ConnectedAt)

	if err == nil && entry.ID == 0 {
		// Get the inserted ID
		// Implementation depends on database driver
	}
}

// updateDatabase updates connection in database
func (cl *ConnectionLogger) updateDatabase(entry *ConnectionLogEntry) {
	if DB == nil {
		return
	}

	DB.db.Exec(`
		UPDATE connection_logs SET 
			upload = ?, download = ?, duration = ?, disconnected_at = ?
		WHERE user_id = ? AND ip = ? AND disconnected_at IS NULL
		ORDER BY connected_at DESC LIMIT 1
	`, entry.Upload, entry.Download, entry.Duration, entry.DisconnectedAt,
		entry.UserID, entry.IP)
}

// GetRecentLogs returns recent connection logs
func (cl *ConnectionLogger) GetRecentLogs(limit int) []*ConnectionLogEntry {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	if limit > len(cl.logs) {
		limit = len(cl.logs)
	}

	result := make([]*ConnectionLogEntry, limit)
	copy(result, cl.logs[len(cl.logs)-limit:])

	// Reverse to get newest first
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return result
}

// GetUserLogs returns logs for a specific user
func (cl *ConnectionLogger) GetUserLogs(userID int64, limit int) []*ConnectionLogEntry {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	result := []*ConnectionLogEntry{}

	for i := len(cl.logs) - 1; i >= 0 && len(result) < limit; i-- {
		if cl.logs[i].UserID == userID {
			result = append(result, cl.logs[i])
		}
	}

	return result
}

// GetActiveConnections returns currently active connections
func (cl *ConnectionLogger) GetActiveConnections() []*ConnectionLogEntry {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	result := []*ConnectionLogEntry{}

	for _, log := range cl.logs {
		if log.DisconnectedAt == nil {
			result = append(result, log)
		}
	}

	return result
}

// Cleanup removes old logs
func (cl *ConnectionLogger) Cleanup(maxAge time.Duration) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	newLogs := []*ConnectionLogEntry{}

	for _, log := range cl.logs {
		if log.ConnectedAt.After(cutoff) {
			newLogs = append(newLogs, log)
		}
	}

	cl.logs = newLogs
}

// ============================================================================
// GEO IP RESOLVER
// ============================================================================

// GeoIPResolver resolves IP addresses to locations
type GeoIPResolver struct {
	cache    map[string]*GeoLocation
	cacheTTL time.Duration
	mu       sync.RWMutex
}

// GeoLocation represents a geographic location
type GeoLocation struct {
	IP          string    `json:"ip"`
	Country     string    `json:"country"`
	CountryCode string    `json:"country_code"`
	Region      string    `json:"region"`
	City        string    `json:"city"`
	Latitude    float64   `json:"latitude"`
	Longitude   float64   `json:"longitude"`
	ISP         string    `json:"isp"`
	Timezone    string    `json:"timezone"`
	ResolvedAt  time.Time `json:"resolved_at"`
}

// NewGeoIPResolver creates a new GeoIP resolver
func NewGeoIPResolver() *GeoIPResolver {
	return &GeoIPResolver{
		cache:    make(map[string]*GeoLocation),
		cacheTTL: 24 * time.Hour,
	}
}

// Resolve resolves an IP address to a location
func (g *GeoIPResolver) Resolve(ip string) (*GeoLocation, error) {
	// Check cache
	g.mu.RLock()
	if loc, exists := g.cache[ip]; exists {
		if time.Since(loc.ResolvedAt) < g.cacheTTL {
			g.mu.RUnlock()
			return loc, nil
		}
	}
	g.mu.RUnlock()

	// Skip private IPs
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil || parsedIP.IsPrivate() || parsedIP.IsLoopback() {
		return &GeoLocation{
			IP:      ip,
			Country: "Local",
		}, nil
	}

	// Query external API
	loc, err := g.queryAPI(ip)
	if err != nil {
		return nil, err
	}

	// Cache result
	g.mu.Lock()
	g.cache[ip] = loc
	g.mu.Unlock()

	return loc, nil
}

// queryAPI queries a GeoIP API
func (g *GeoIPResolver) queryAPI(ip string) (*GeoLocation, error) {
	// Using ip-api.com (free tier)
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,region,city,lat,lon,isp,timezone", ip)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Status      string  `json:"status"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		Region      string  `json:"region"`
		City        string  `json:"city"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		ISP         string  `json:"isp"`
		Timezone    string  `json:"timezone"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.Status != "success" {
		return nil, errors.New("failed to resolve IP")
	}

	return &GeoLocation{
		IP:          ip,
		Country:     result.Country,
		CountryCode: result.CountryCode,
		Region:      result.Region,
		City:        result.City,
		Latitude:    result.Lat,
		Longitude:   result.Lon,
		ISP:         result.ISP,
		Timezone:    result.Timezone,
		ResolvedAt:  time.Now(),
	}, nil
}

// GetCountryDistribution returns user distribution by country
func (g *GeoIPResolver) GetCountryDistribution(connections []*ConnectionLogEntry) map[string]int {
	distribution := make(map[string]int)

	for _, conn := range connections {
		if conn.Location != nil && conn.Location.Country != "" {
			distribution[conn.Location.Country]++
		}
	}

	return distribution
}

// Cleanup removes old cache entries
func (g *GeoIPResolver) Cleanup() {
	g.mu.Lock()
	defer g.mu.Unlock()

	for ip, loc := range g.cache {
		if time.Since(loc.ResolvedAt) > g.cacheTTL {
			delete(g.cache, ip)
		}
	}
}

// ============================================================================
// ANALYTICS ENGINE
// ============================================================================

// AnalyticsEngine provides analytics and insights
type AnalyticsEngine struct {
	hourlyData map[string]*HourlyAnalytics
	dailyData  map[string]*DailyAnalytics
	anomalies  []*Anomaly
	mu         sync.RWMutex
}

// HourlyAnalytics represents hourly analytics data
type HourlyAnalytics struct {
	Hour               time.Time        `json:"hour"`
	TotalTraffic       int64            `json:"total_traffic"`
	TotalConnections   int              `json:"total_connections"`
	UniqueUsers        int              `json:"unique_users"`
	PeakConcurrent     int              `json:"peak_concurrent"`
	AvgSessionDuration float64          `json:"avg_session_duration"`
	TopProtocols       map[string]int64 `json:"top_protocols"`
	TopCountries       map[string]int   `json:"top_countries"`
}

// DailyAnalytics represents daily analytics data
type DailyAnalytics struct {
	Date               time.Time `json:"date"`
	TotalTraffic       int64     `json:"total_traffic"`
	TotalConnections   int       `json:"total_connections"`
	UniqueUsers        int       `json:"unique_users"`
	NewUsers           int       `json:"new_users"`
	ChurnedUsers       int       `json:"churned_users"`
	PeakConcurrent     int       `json:"peak_concurrent"`
	AvgConcurrent      float64   `json:"avg_concurrent"`
	AvgSessionDuration float64   `json:"avg_session_duration"`
	RevenueEstimate    float64   `json:"revenue_estimate,omitempty"`
}

// Anomaly represents a detected anomaly
type Anomaly struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // traffic_spike, unusual_pattern, security_threat
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Metric      string    `json:"metric"`
	Value       float64   `json:"value"`
	Expected    float64   `json:"expected"`
	Deviation   float64   `json:"deviation"`
	DetectedAt  time.Time `json:"detected_at"`
	Resolved    bool      `json:"resolved"`
}

// NewAnalyticsEngine creates a new analytics engine
func NewAnalyticsEngine() *AnalyticsEngine {
	return &AnalyticsEngine{
		hourlyData: make(map[string]*HourlyAnalytics),
		dailyData:  make(map[string]*DailyAnalytics),
		anomalies:  []*Anomaly{},
	}
}

// AggregateHourly aggregates data for the current hour
func (ae *AnalyticsEngine) AggregateHourly() *HourlyAnalytics {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	now := time.Now().Truncate(time.Hour)
	key := now.Format("2006-01-02-15")

	analytics, exists := ae.hourlyData[key]
	if !exists {
		analytics = &HourlyAnalytics{
			Hour:         now,
			TopProtocols: make(map[string]int64),
			TopCountries: make(map[string]int),
		}
		ae.hourlyData[key] = analytics
	}

	// Update analytics from current data
	// Implementation would gather data from various sources

	return analytics
}

// AggregateDaily aggregates data for the current day
func (ae *AnalyticsEngine) AggregateDaily() *DailyAnalytics {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	today := time.Now().Truncate(24 * time.Hour)
	key := today.Format("2006-01-02")

	analytics, exists := ae.dailyData[key]
	if !exists {
		analytics = &DailyAnalytics{
			Date: today,
		}
		ae.dailyData[key] = analytics
	}

	// Update analytics
	// Implementation would gather data from various sources

	return analytics
}

// DetectAnomalies detects traffic anomalies
func (ae *AnalyticsEngine) DetectAnomalies(metrics *SystemMetrics) []*Anomaly {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	detected := []*Anomaly{}

	// Get historical data for comparison
	if Monitor != nil && Monitor.metrics != nil {
		avg := Monitor.metrics.GetAverage(1 * time.Hour)
		if avg != nil {
			// Check for CPU spike
			if metrics.CPUUsage > avg.CPUUsage*2 && metrics.CPUUsage > 50 {
				anomaly := &Anomaly{
					ID:          fmt.Sprintf("cpu_spike_%d", time.Now().Unix()),
					Type:        "traffic_spike",
					Severity:    "warning",
					Description: "Unusual CPU usage spike detected",
					Metric:      "cpu_usage",
					Value:       metrics.CPUUsage,
					Expected:    avg.CPUUsage,
					Deviation:   (metrics.CPUUsage - avg.CPUUsage) / avg.CPUUsage * 100,
					DetectedAt:  time.Now(),
				}
				detected = append(detected, anomaly)
				ae.anomalies = append(ae.anomalies, anomaly)
			}

			// Check for network spike
			avgNetworkRate := float64(avg.NetworkInRate + avg.NetworkOutRate)
			currentNetworkRate := float64(metrics.NetworkInRate + metrics.NetworkOutRate)

			if avgNetworkRate > 0 && currentNetworkRate > avgNetworkRate*3 {
				anomaly := &Anomaly{
					ID:          fmt.Sprintf("network_spike_%d", time.Now().Unix()),
					Type:        "traffic_spike",
					Severity:    "warning",
					Description: "Unusual network traffic spike detected",
					Metric:      "network_rate",
					Value:       currentNetworkRate,
					Expected:    avgNetworkRate,
					Deviation:   (currentNetworkRate - avgNetworkRate) / avgNetworkRate * 100,
					DetectedAt:  time.Now(),
				}
				detected = append(detected, anomaly)
				ae.anomalies = append(ae.anomalies, anomaly)
			}
		}
	}

	return detected
}

// GetAnomalies returns detected anomalies
func (ae *AnalyticsEngine) GetAnomalies(limit int) []*Anomaly {
	ae.mu.RLock()
	defer ae.mu.RUnlock()

	if limit > len(ae.anomalies) {
		limit = len(ae.anomalies)
	}

	result := make([]*Anomaly, limit)
	copy(result, ae.anomalies[len(ae.anomalies)-limit:])

	// Reverse to get newest first
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return result
}

// GetTrends calculates trends from historical data
func (ae *AnalyticsEngine) GetTrends() map[string]interface{} {
	ae.mu.RLock()
	defer ae.mu.RUnlock()

	trends := map[string]interface{}{
		"traffic_trend": "stable",
		"user_trend":    "stable",
		"error_trend":   "stable",
	}

	// Calculate trends from daily data
	if len(ae.dailyData) >= 7 {
		// Implementation would calculate actual trends
	}

	return trends
}

// Cleanup removes old analytics data
func (ae *AnalyticsEngine) Cleanup(maxAge time.Duration) {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)

	// Clean hourly data
	for key, data := range ae.hourlyData {
		if data.Hour.Before(cutoff) {
			delete(ae.hourlyData, key)
		}
	}

	// Clean anomalies
	newAnomalies := []*Anomaly{}
	for _, a := range ae.anomalies {
		if a.DetectedAt.After(cutoff) {
			newAnomalies = append(newAnomalies, a)
		}
	}
	ae.anomalies = newAnomalies
}

// ============================================================================
// COLLECTOR ROUTINES
// ============================================================================

// metricsCollector collects system metrics periodically
func (m *MonitorManager) metricsCollector() {
	ticker := time.NewTicker(MetricsCollectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			metrics, err := m.CollectSystemMetrics()
			if err == nil {
				// Check thresholds and create alerts
				m.alertManager.CheckThresholds(metrics)

				// Detect anomalies
				m.analyticsEngine.DetectAnomalies(metrics)
			}
		case <-m.ctx.Done():
			return
		}
	}
}

// trafficCollector collects traffic statistics
func (m *MonitorManager) trafficCollector() {
	ticker := time.NewTicker(TrafficCollectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.collectTrafficStats()
		case <-m.ctx.Done():
			return
		}
	}
}

// collectTrafficStats collects traffic statistics from cores
func (m *MonitorManager) collectTrafficStats() {
	// Get online users
	if Users != nil {
		onlineUsers := Users.GetOnlineUsers()
		for _, ou := range onlineUsers {
			// Record connection
			m.connectionLogger.LogConnection(&ConnectionLogEntry{
				UserID:   ou.UserID,
				Username: ou.Username,
				NodeID:   ou.NodeID,
				IP:       ou.IP,
				Protocol: ou.Protocol,
				Inbound:  ou.Inbound,
			})

			// Resolve location
			if _, err := m.geoIPResolver.Resolve(ou.IP); err == nil {
				m.mu.Lock()
				// Store location for the connection
				m.mu.Unlock()
			}
		}
	}
}

// alertChecker checks for alert conditions
func (m *MonitorManager) alertChecker() {
	ticker := time.NewTicker(AlertCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.checkAlertConditions()
		case <-m.ctx.Done():
			return
		}
	}
}

// checkAlertConditions checks various alert conditions
func (m *MonitorManager) checkAlertConditions() {
	// Check node status
	if Nodes != nil {
		for _, node := range Nodes.ListNodes() {
			if node.Node.IsActive && node.Node.Status == NodeStatusError {
				m.alertManager.CreateAlert(
					AlertTypeCritical, "node",
					fmt.Sprintf("Node Offline: %s", node.Node.Name),
					fmt.Sprintf("Node %s (%s) is offline. Last error: %s",
						node.Node.Name, node.Node.Address, node.Node.LastError),
					0, 0)
			}
		}
	}

	// Check database health
	if DB != nil {
		if err := DB.HealthCheck(); err != nil {
			m.alertManager.CreateAlert(
				AlertTypeCritical, "database",
				"Database Health Check Failed",
				fmt.Sprintf("Database health check failed: %s", err.Error()),
				0, 0)
		}
	}
}

// analyticsAggregator aggregates analytics data
func (m *MonitorManager) analyticsAggregator() {
	ticker := time.NewTicker(AnalyticsAggregateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.analyticsEngine.AggregateHourly()
		case <-m.ctx.Done():
			return
		}
	}
}

// cleanupRoutine cleans up old data
func (m *MonitorManager) cleanupRoutine() {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.metrics.Cleanup(MetricsRetention)
			m.connectionLogger.Cleanup(ConnectionLogRetention)
			m.alertManager.Cleanup(AlertHistoryRetention)
			m.analyticsEngine.Cleanup(7 * 24 * time.Hour)
			m.geoIPResolver.Cleanup()

			// Cleanup old database logs
			if DB != nil {
				DB.CleanupOldLogs(ConnectionLogRetention)
				DB.CleanupOldAuditLogs(30 * 24 * time.Hour)
			}
		case <-m.ctx.Done():
			return
		}
	}
}

// ============================================================================
// PUBLIC API
// ============================================================================

// GetCurrentMetrics returns current system metrics
func (m *MonitorManager) GetCurrentMetrics() *SystemMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastMetrics
}

// GetMetricsHistory returns metrics history
func (m *MonitorManager) GetMetricsHistory(count int) []*SystemMetrics {
	return m.metrics.GetLast(count)
}

// GetTrafficStats returns traffic statistics
func (m *MonitorManager) GetTrafficStats() *TrafficStatsStore {
	return m.trafficStats
}

// GetActiveAlerts returns active alerts
func (m *MonitorManager) GetActiveAlerts() []*Alert {
	return m.alertManager.GetActiveAlerts()
}

// GetAlertHistory returns alert history
func (m *MonitorManager) GetAlertHistory(limit int) []*Alert {
	return m.alertManager.GetAlertHistory(limit)
}

// GetConnectionLogs returns connection logs
func (m *MonitorManager) GetConnectionLogs(limit int) []*ConnectionLogEntry {
	return m.connectionLogger.GetRecentLogs(limit)
}

// GetActiveConnections returns active connections
func (m *MonitorManager) GetActiveConnections() []*ConnectionLogEntry {
	return m.connectionLogger.GetActiveConnections()
}

// GetAnomalies returns detected anomalies
func (m *MonitorManager) GetAnomalies(limit int) []*Anomaly {
	return m.analyticsEngine.GetAnomalies(limit)
}

// GetDashboardData returns all data for dashboard
func (m *MonitorManager) GetDashboardData() map[string]interface{} {
	data := map[string]interface{}{}

	// Current metrics
	if m.lastMetrics != nil {
		data["metrics"] = m.lastMetrics
	}

	// Recent metrics history (last 60 points)
	data["metrics_history"] = m.metrics.GetLast(60)

	// Active alerts
	data["active_alerts"] = m.alertManager.GetActiveAlerts()
	data["alert_count"] = len(m.alertManager.GetActiveAlerts())

	// Traffic stats
	data["top_users"] = m.trafficStats.GetTopUsers(10)
	data["protocol_stats"] = m.trafficStats.GetProtocolStats()
	data["node_stats"] = m.trafficStats.GetNodeStats()

	// Active connections
	data["active_connections"] = len(m.connectionLogger.GetActiveConnections())

	// Anomalies
	data["anomalies"] = m.analyticsEngine.GetAnomalies(5)

	// Trends
	data["trends"] = m.analyticsEngine.GetTrends()

	return data
}

// ResolveIP resolves an IP to location
func (m *MonitorManager) ResolveIP(ip string) (*GeoLocation, error) {
	return m.geoIPResolver.Resolve(ip)
}

// GetGeoDistribution returns geographic distribution of users
func (m *MonitorManager) GetGeoDistribution() map[string]int {
	connections := m.connectionLogger.GetActiveConnections()
	return m.geoIPResolver.GetCountryDistribution(connections)
}
