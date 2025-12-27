// MXUI VPN Panel
// Core/metrics.go
// Prometheus Metrics

package core

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	MetricsNamespace = "mxui"
	MetricsSubsystem = "panel"
)

type MetricsRegistry struct {
	counters   map[string]*Counter
	gauges     map[string]*Gauge
	histograms map[string]*Histogram
	mu         sync.RWMutex
}

type Counter struct {
	name  string
	help  string
	value int64
}

type Gauge struct {
	name  string
	help  string
	value float64
	mu    sync.RWMutex
}

type Histogram struct {
	name    string
	help    string
	buckets []float64
	counts  []int64
	sum     float64
	count   int64
	mu      sync.RWMutex
}

var Metrics *MetricsRegistry

func InitMetrics() error {
	Metrics = &MetricsRegistry{
		counters:   make(map[string]*Counter),
		gauges:     make(map[string]*Gauge),
		histograms: make(map[string]*Histogram),
	}
	Metrics.registerDefaults()
	return nil
}

func (mr *MetricsRegistry) registerDefaults() {
	mr.NewCounter("http_requests_total", "Total HTTP requests")
	mr.NewCounter("http_errors_total", "Total HTTP errors")
	mr.NewGauge("users_total", "Total users")
	mr.NewGauge("users_online", "Online users")
	mr.NewGauge("nodes_total", "Total nodes")
	mr.NewGauge("nodes_online", "Online nodes")
	mr.NewCounter("traffic_upload_bytes", "Upload traffic")
	mr.NewCounter("traffic_download_bytes", "Download traffic")
	mr.NewGauge("system_cpu_usage", "CPU usage")
	mr.NewGauge("system_memory_usage", "Memory usage")
	mr.NewGauge("system_uptime_seconds", "Uptime")
}

func (mr *MetricsRegistry) NewCounter(name, help string) *Counter {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	c := &Counter{name: name, help: help}
	mr.counters[name] = c
	return c
}

func (c *Counter) Inc()         { atomic.AddInt64(&c.value, 1) }
func (c *Counter) Add(v int64)  { atomic.AddInt64(&c.value, v) }
func (c *Counter) Value() int64 { return atomic.LoadInt64(&c.value) }

func (mr *MetricsRegistry) NewGauge(name, help string) *Gauge {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	g := &Gauge{name: name, help: help}
	mr.gauges[name] = g
	return g
}

func (g *Gauge) Set(v float64) {
	g.mu.Lock()
	g.value = v
	g.mu.Unlock()
}

func (g *Gauge) Value() float64 {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.value
}

func (mr *MetricsRegistry) NewHistogram(name, help string, buckets []float64) *Histogram {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	h := &Histogram{name: name, help: help, buckets: buckets, counts: make([]int64, len(buckets)+1)}
	mr.histograms[name] = h
	return h
}

func (h *Histogram) Observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sum += v
	h.count++
	for i, b := range h.buckets {
		if v <= b {
			h.counts[i]++
			return
		}
	}
	h.counts[len(h.buckets)]++
}

func (mr *MetricsRegistry) GetCounter(name string) *Counter {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	return mr.counters[name]
}

func (mr *MetricsRegistry) GetGauge(name string) *Gauge {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	return mr.gauges[name]
}

func (mr *MetricsRegistry) SetGauge(name string, v float64) {
	if g := mr.GetGauge(name); g != nil {
		g.Set(v)
	}
}

func (mr *MetricsRegistry) IncCounter(name string) {
	if c := mr.GetCounter(name); c != nil {
		c.Inc()
	}
}

func (mr *MetricsRegistry) Export() string {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	var out string
	for name, c := range mr.counters {
		out += fmt.Sprintf("# HELP %s_%s_%s %s\n", MetricsNamespace, MetricsSubsystem, name, c.help)
		out += fmt.Sprintf("# TYPE %s_%s_%s counter\n", MetricsNamespace, MetricsSubsystem, name)
		out += fmt.Sprintf("%s_%s_%s %d\n", MetricsNamespace, MetricsSubsystem, name, c.Value())
	}
	for name, g := range mr.gauges {
		out += fmt.Sprintf("# HELP %s_%s_%s %s\n", MetricsNamespace, MetricsSubsystem, name, g.help)
		out += fmt.Sprintf("# TYPE %s_%s_%s gauge\n", MetricsNamespace, MetricsSubsystem, name)
		out += fmt.Sprintf("%s_%s_%s %.6f\n", MetricsNamespace, MetricsSubsystem, name, g.Value())
	}
	return out
}

func MetricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		updateSystemMetricsForExport()
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(Metrics.Export()))
	}
}

func updateSystemMetricsForExport() {
	if Metrics == nil {
		return
	}
	if startTime.Unix() > 0 {
		Metrics.SetGauge("system_uptime_seconds", time.Since(startTime).Seconds())
	}
}

func RecordHTTPRequest(duration time.Duration, code int) {
	if Metrics == nil {
		return
	}
	Metrics.IncCounter("http_requests_total")
	if code >= 400 {
		Metrics.IncCounter("http_errors_total")
	}
}

func RecordTrafficMetrics(upload, download int64) {
	if Metrics == nil {
		return
	}
	if c := Metrics.GetCounter("traffic_upload_bytes"); c != nil {
		c.Add(upload)
	}
	if c := Metrics.GetCounter("traffic_download_bytes"); c != nil {
		c.Add(download)
	}
}
