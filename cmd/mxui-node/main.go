package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// mxui-node: lightweight node agent (no UI)
// - Exposes agent HTTP API for master panel
// - Applies config (xray/sing-box/etc) by writing files and restarting services
// This is Phase-1 minimal implementation.

type AgentConfig struct {
	ListenAddr   string   `json:"listen_addr"`
	Token        string   `json:"token"`
	NodeID       string   `json:"node_id"`
	MasterURL    string   `json:"master_url"`
	XrayPath     string   `json:"xray_path"`
	XrayConfig   string   `json:"xray_config"`
	DataDir      string   `json:"data_dir"`
	LogPath      string   `json:"log_path"`
	LastApplied  int64    `json:"last_applied"`
	Version      string   `json:"version"`
	Capabilities []string `json:"capabilities"`
}

type Agent struct {
	mu     sync.RWMutex
	cfg    AgentConfig
	logger *log.Logger
	logf   *os.File

	cpuMu        sync.Mutex
	lastCPURead  time.Time
	lastCPUIdle  uint64
	lastCPUTotal uint64
}

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "/opt/mxui-node/config.json", "agent config path")
	flag.Parse()

	agent, err := newAgent(configPath)
	if err != nil {
		log.Fatalf("agent init failed: %v", err)
	}
	defer agent.close()

	agent.logger.Printf("mxui-node starting on %s", agent.cfg.ListenAddr)

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/v1/health", agent.handleHealth)
	mux.HandleFunc("/agent/v1/metrics", agent.handleMetrics)
	mux.HandleFunc("/agent/v1/logs", agent.handleLogs)
	mux.HandleFunc("/agent/v1/handshake", agent.handleHandshake)
	mux.HandleFunc("/agent/v1/apply-config", agent.handleApplyConfig)
	mux.HandleFunc("/agent/v1/restart", agent.handleRestart)

	srv := &http.Server{
		Addr:              agent.cfg.ListenAddr,
		Handler:           agent.recoverMiddleware(agent.authMiddleware(mux)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("agent server failed: %v", err)
	}
}

func newAgent(configPath string) (*Agent, error) {
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return nil, err
	}

	cfg := AgentConfig{
		ListenAddr:   ":9080",
		XrayPath:     "/opt/mxui-node/bin/xray",
		XrayConfig:   "/opt/mxui-node/data/xray_config.json",
		DataDir:      "/opt/mxui-node",
		LogPath:      "/opt/mxui-node/logs/agent.log",
		Version:      "1.0.0",
		Capabilities: []string{"xray"},
	}

	// Load if exists
	if b, err := os.ReadFile(configPath); err == nil {
		_ = json.Unmarshal(b, &cfg)
	}

	if cfg.Token == "" {
		cfg.Token = randomHex(32)
	}
	if cfg.NodeID == "" {
		cfg.NodeID = "node_" + randomHex(8)
	}

	// Ensure dirs
	_ = os.MkdirAll(filepath.Dir(cfg.LogPath), 0755)
	_ = os.MkdirAll(cfg.DataDir, 0755)

	f, err := os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	a := &Agent{cfg: cfg, logf: f, logger: log.New(io.MultiWriter(os.Stdout, f), "[mxui-node] ", log.LstdFlags|log.Lshortfile)}

	// Persist config
	if err := a.save(configPath); err != nil {
		return nil, err
	}

	// Initialize CPU baseline
	a.cpuUsagePercent()

	return a, nil
}

func (a *Agent) close() {
	if a.logf != nil {
		_ = a.logf.Close()
	}
}

func (a *Agent) save(path string) error {
	a.mu.RLock()
	b, _ := json.MarshalIndent(a.cfg, "", "  ")
	a.mu.RUnlock()
	return os.WriteFile(path, b, 0600)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (a *Agent) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				a.logger.Printf("panic: %v", rec)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (a *Agent) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Public endpoints
		if r.URL.Path == "/agent/v1/health" {
			next.ServeHTTP(w, r)
			return
		}

		token := strings.TrimSpace(r.Header.Get("X-MXUI-Node-Token"))
		if token == "" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		a.mu.RLock()
		expected := a.cfg.Token
		a.mu.RUnlock()
		if token != expected {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Agent) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *Agent) handleHealth(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	cfg := a.cfg
	a.mu.RUnlock()
	// best-effort xray status
	xrayOK := false
	if _, err := os.Stat(cfg.XrayPath); err == nil {
		xrayOK = true
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"node_id":      cfg.NodeID,
		"version":      cfg.Version,
		"capabilities": cfg.Capabilities,
		"time":         time.Now().Unix(),
		"os":           runtime.GOOS,
		"arch":         runtime.GOARCH,
		"xray_present": xrayOK,
	})
}

func (a *Agent) handleHandshake(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	cfg := a.cfg
	a.mu.RUnlock()
	// Returns agent identity for master registration.
	a.writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"node_id":      cfg.NodeID,
		"token":        cfg.Token,
		"capabilities": cfg.Capabilities,
		"agent_listen": cfg.ListenAddr,
		"xray_path":    cfg.XrayPath,
		"xray_config":  cfg.XrayConfig,
	})
}

func (a *Agent) handleMetrics(w http.ResponseWriter, r *http.Request) {
	// Phase-1: real basic metrics (Linux best-effort)
	memTotal, memAvail := readMemInfo()
	diskTotal, diskFree := readDiskUsage("/")
	rx, tx := readNetDevTotals()
	cpuPct := a.cpuUsagePercent()

	a.writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"cpu": map[string]any{
			"usage_percent": cpuPct,
		},
		"ram": map[string]any{
			"total_bytes": memTotal,
			"avail_bytes": memAvail,
			"used_bytes":  maxInt64(memTotal-memAvail, 0),
		},
		"disk": map[string]any{
			"path":        "/",
			"total_bytes": diskTotal,
			"free_bytes":  diskFree,
			"used_bytes":  maxInt64(diskTotal-diskFree, 0),
		},
		"net": map[string]any{
			"rx_bytes": rx,
			"tx_bytes": tx,
		},
		"time": time.Now().Unix(),
	})
}

func (a *Agent) handleLogs(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	path := a.cfg.LogPath
	a.mu.RUnlock()
	b, err := os.ReadFile(path)
	if err != nil {
		a.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "lines": []string{}})
		return
	}
	content := strings.ReplaceAll(string(b), "\r\n", "\n")
	lines := strings.Split(content, "\n")
	if len(lines) > 200 {
		lines = lines[len(lines)-200:]
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": path, "lines": lines})
}

func (a *Agent) handleApplyConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		XrayConfigJSON string `json:"xray_config_json"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.XrayConfigJSON == "" {
		http.Error(w, "xray_config_json required", http.StatusBadRequest)
		return
	}

	a.mu.RLock()
	cfgPath := a.cfg.XrayConfig
	a.mu.RUnlock()
	_ = os.MkdirAll(filepath.Dir(cfgPath), 0755)
	if err := os.WriteFile(cfgPath, []byte(req.XrayConfigJSON), 0644); err != nil {
		http.Error(w, "failed to write config", http.StatusInternalServerError)
		return
	}

	a.mu.Lock()
	a.cfg.LastApplied = time.Now().Unix()
	a.mu.Unlock()

	a.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "config applied", "path": cfgPath})
}

func (a *Agent) cpuUsagePercent() float64 {
	// Linux: /proc/stat first line: cpu  user nice system idle iowait irq softirq steal guest guest_nice
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	if len(lines) == 0 {
		return 0
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0
	}
	vals := make([]uint64, 0, len(fields)-1)
	for i := 1; i < len(fields); i++ {
		var v uint64
		_, _ = fmt.Sscanf(fields[i], "%d", &v)
		vals = append(vals, v)
	}
	var idle uint64
	idle = vals[3]
	if len(vals) > 4 {
		idle += vals[4] // iowait
	}
	var total uint64
	for _, v := range vals {
		total += v
	}

	a.cpuMu.Lock()
	defer a.cpuMu.Unlock()

	now := time.Now()
	// first sample
	if a.lastCPURead.IsZero() {
		a.lastCPURead = now
		a.lastCPUIdle = idle
		a.lastCPUTotal = total
		return 0
	}

	dIdle := float64(idle - a.lastCPUIdle)
	dTotal := float64(total - a.lastCPUTotal)
	a.lastCPURead = now
	a.lastCPUIdle = idle
	a.lastCPUTotal = total
	if dTotal <= 0 {
		return 0
	}
	usage := (1.0 - (dIdle / dTotal)) * 100.0
	if usage < 0 {
		usage = 0
	}
	if usage > 100 {
		usage = 100
	}
	return usage
}

func maxInt64(v int64, min int64) int64 {
	if v < min {
		return min
	}
	return v
}

func readMemInfo() (total int64, available int64) {
	// Linux: /proc/meminfo
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	var memTotalKB, memAvailKB int64
	for _, ln := range lines {
		if strings.HasPrefix(ln, "MemTotal:") {
			fmtSscanfInt64(ln, &memTotalKB)
		}
		if strings.HasPrefix(ln, "MemAvailable:") {
			fmtSscanfInt64(ln, &memAvailKB)
		}
	}
	return memTotalKB * 1024, memAvailKB * 1024
}

func fmtSscanfInt64(line string, out *int64) {
	// e.g. "MemTotal:       16384256 kB"
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		var v int64
		// parse int
		_, _ = fmt.Sscanf(fields[1], "%d", &v)
		*out = v
	}
}

func readDiskUsage(path string) (total int64, free int64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0
	}
	// Blocks * size
	total = int64(st.Blocks) * int64(st.Bsize)
	free = int64(st.Bavail) * int64(st.Bsize)
	return total, free
}

func readNetDevTotals() (rx int64, tx int64) {
	// Linux: /proc/net/dev totals across interfaces
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "Inter-") || strings.HasPrefix(ln, "face") {
			continue
		}
		parts := strings.Split(ln, ":")
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		// skip loopback
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(parts[1]))
		if len(fields) < 16 {
			continue
		}
		var rxi, txi int64
		_, _ = fmt.Sscanf(fields[0], "%d", &rxi)
		_, _ = fmt.Sscanf(fields[8], "%d", &txi)
		rx += rxi
		tx += txi
	}
	return rx, tx
}

func (a *Agent) handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Phase-1: restart xray if systemd exists; otherwise best-effort run.
	cmd := exec.Command("systemctl", "restart", "xray")
	_ = cmd.Run()
	a.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "restart triggered"})
}
