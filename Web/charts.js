/**
 * MX-UI VPN Panel - Charts
 * charts.js - Live Charts using Canvas
 */

'use strict';

// ============================================================================
// BASE CHART CLASS
// ============================================================================

class Chart {
    constructor(canvas, options = {}) {
        this.canvas = typeof canvas === 'string' ? document.querySelector(canvas) : canvas;
        this.ctx = this.canvas?.getContext('2d');
        this.options = {
            padding: 40,
            colors: ['#6366f1', '#ec4899', '#10b981', '#f59e0b', '#3b82f6'],
            animate: true,
            ...options
        };
        this.data = [];
    }

    clear() {
        if (this.ctx) {
            this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
        }
    }

    setData(data) {
        this.data = data;
        this.render();
    }

    render() {
        // Override in subclasses
    }
}

// ============================================================================
// LINE CHART
// ============================================================================

class LineChart extends Chart {
    constructor(canvas, options = {}) {
        super(canvas, options);
        this.options = {
            ...this.options,
            showGrid: true,
            showPoints: true,
            smooth: true,
            fill: true,
            ...options
        };
    }

    render() {
        if (!this.ctx || !this.data.length) return;
        this.clear();

        const { width, height } = this.canvas;
        const { padding, colors, showGrid, showPoints, smooth, fill } = this.options;
        const chartWidth = width - padding * 2;
        const chartHeight = height - padding * 2;

        // Find min/max
        const allValues = this.data.flatMap(d => d.values);
        const maxVal = Math.max(...allValues) || 100;
        const minVal = Math.min(...allValues, 0);
        const range = maxVal - minVal || 1;

        // Draw grid
        if (showGrid) {
            this.ctx.strokeStyle = 'rgba(255,255,255,0.1)';
            this.ctx.lineWidth = 1;
            for (let i = 0; i <= 5; i++) {
                const y = padding + (chartHeight / 5) * i;
                this.ctx.beginPath();
                this.ctx.moveTo(padding, y);
                this.ctx.lineTo(width - padding, y);
                this.ctx.stroke();
            }
        }

        // Draw lines
        this.data.forEach((series, seriesIdx) => {
            const color = colors[seriesIdx % colors.length];
            const points = series.values.map((val, i) => ({
                x: padding + (chartWidth / (series.values.length - 1)) * i,
                y: padding + chartHeight - ((val - minVal) / range) * chartHeight
            }));

            // Fill area
            if (fill) {
                this.ctx.beginPath();
                this.ctx.moveTo(points[0].x, height - padding);
                points.forEach(p => this.ctx.lineTo(p.x, p.y));
                this.ctx.lineTo(points[points.length - 1].x, height - padding);
                this.ctx.fillStyle = color + '20';
                this.ctx.fill();
            }

            // Draw line
            this.ctx.beginPath();
            this.ctx.strokeStyle = color;
            this.ctx.lineWidth = 2;

            if (smooth && points.length > 2) {
                this.ctx.moveTo(points[0].x, points[0].y);
                for (let i = 1; i < points.length - 1; i++) {
                    const xc = (points[i].x + points[i + 1].x) / 2;
                    const yc = (points[i].y + points[i + 1].y) / 2;
                    this.ctx.quadraticCurveTo(points[i].x, points[i].y, xc, yc);
                }
                this.ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);
            } else {
                points.forEach((p, i) => i === 0 ? this.ctx.moveTo(p.x, p.y) : this.ctx.lineTo(p.x, p.y));
            }
            this.ctx.stroke();

            // Draw points
            if (showPoints) {
                points.forEach(p => {
                    this.ctx.beginPath();
                    this.ctx.arc(p.x, p.y, 4, 0, Math.PI * 2);
                    this.ctx.fillStyle = color;
                    this.ctx.fill();
                });
            }
        });

        // Draw labels
        if (this.data[0]?.labels) {
            this.ctx.fillStyle = 'rgba(255,255,255,0.6)';
            this.ctx.font = '11px sans-serif';
            this.ctx.textAlign = 'center';
            const labels = this.data[0].labels;
            labels.forEach((label, i) => {
                const x = padding + (chartWidth / (labels.length - 1)) * i;
                this.ctx.fillText(label, x, height - 10);
            });
        }
    }

    addPoint(seriesIdx, value, label) {
        if (this.data[seriesIdx]) {
            this.data[seriesIdx].values.push(value);
            if (label) this.data[seriesIdx].labels?.push(label);
            if (this.data[seriesIdx].values.length > 60) {
                this.data[seriesIdx].values.shift();
                this.data[seriesIdx].labels?.shift();
            }
            this.render();
        }
    }
}

// ============================================================================
// BAR CHART
// ============================================================================

class BarChart extends Chart {
    constructor(canvas, options = {}) {
        super(canvas, options);
        this.options = {
            ...this.options,
            barWidth: 0.8,
            horizontal: false,
            ...options
        };
    }

    render() {
        if (!this.ctx || !this.data.length) return;
        this.clear();

        const { width, height } = this.canvas;
        const { padding, colors, barWidth, horizontal } = this.options;
        const chartWidth = width - padding * 2;
        const chartHeight = height - padding * 2;

        const maxVal = Math.max(...this.data.map(d => d.value)) || 100;
        const barCount = this.data.length;
        const gap = horizontal ? chartHeight / barCount : chartWidth / barCount;
        const barSize = gap * barWidth;

        this.data.forEach((item, i) => {
            const color = item.color || colors[i % colors.length];
            const ratio = item.value / maxVal;

            if (horizontal) {
                const y = padding + gap * i + (gap - barSize) / 2;
                const w = chartWidth * ratio;
                this.ctx.fillStyle = color;
                this.ctx.fillRect(padding, y, w, barSize);

                this.ctx.fillStyle = 'rgba(255,255,255,0.8)';
                this.ctx.font = '12px sans-serif';
                this.ctx.textAlign = 'right';
                this.ctx.fillText(item.label, padding - 5, y + barSize / 2 + 4);
                this.ctx.textAlign = 'left';
                this.ctx.fillText(item.value, padding + w + 5, y + barSize / 2 + 4);
            } else {
                const x = padding + gap * i + (gap - barSize) / 2;
                const h = chartHeight * ratio;
                this.ctx.fillStyle = color;
                this.ctx.fillRect(x, height - padding - h, barSize, h);

                this.ctx.fillStyle = 'rgba(255,255,255,0.8)';
                this.ctx.font = '11px sans-serif';
                this.ctx.textAlign = 'center';
                this.ctx.fillText(item.label, x + barSize / 2, height - 10);
                this.ctx.fillText(item.value, x + barSize / 2, height - padding - h - 5);
            }
        });
    }
}

// ============================================================================
// DONUT CHART
// ============================================================================

class DonutChart extends Chart {
    constructor(canvas, options = {}) {
        super(canvas, options);
        this.options = {
            ...this.options,
            innerRadius: 0.6,
            ...options
        };
    }

    render() {
        if (!this.ctx || !this.data.length) return;
        this.clear();

        const { width, height } = this.canvas;
        const { colors, innerRadius } = this.options;
        const cx = width / 2;
        const cy = height / 2;
        const radius = Math.min(cx, cy) - 20;
        const inner = radius * innerRadius;

        const total = this.data.reduce((sum, d) => sum + d.value, 0) || 1;
        let startAngle = -Math.PI / 2;

        this.data.forEach((item, i) => {
            const slice = (item.value / total) * Math.PI * 2;
            const color = item.color || colors[i % colors.length];

            this.ctx.beginPath();
            this.ctx.arc(cx, cy, radius, startAngle, startAngle + slice);
            this.ctx.arc(cx, cy, inner, startAngle + slice, startAngle, true);
            this.ctx.closePath();
            this.ctx.fillStyle = color;
            this.ctx.fill();

            startAngle += slice;
        });

        // Center text
        if (this.options.centerText) {
            this.ctx.fillStyle = 'rgba(255,255,255,0.9)';
            this.ctx.font = 'bold 24px sans-serif';
            this.ctx.textAlign = 'center';
            this.ctx.fillText(this.options.centerText, cx, cy + 8);
        }
    }
}

// ============================================================================
// GAUGE CHART
// ============================================================================

class GaugeChart extends Chart {
    constructor(canvas, options = {}) {
        super(canvas, options);
        this.options = {
            ...this.options,
            min: 0,
            max: 100,
            value: 0,
            ...options
        };
    }

    setValue(value) {
        this.options.value = Math.max(this.options.min, Math.min(this.options.max, value));
        this.render();
    }

    render() {
        if (!this.ctx) return;
        this.clear();

        const { width, height } = this.canvas;
        const { min, max, value, colors } = this.options;
        const cx = width / 2;
        const cy = height - 30;
        const radius = Math.min(cx, cy) - 20;

        // Background arc
        this.ctx.beginPath();
        this.ctx.arc(cx, cy, radius, Math.PI, 0);
        this.ctx.lineWidth = 20;
        this.ctx.strokeStyle = 'rgba(255,255,255,0.1)';
        this.ctx.stroke();

        // Value arc
        const ratio = (value - min) / (max - min);
        const endAngle = Math.PI + ratio * Math.PI;
        const color = ratio < 0.5 ? colors[2] : ratio < 0.8 ? colors[3] : colors[0];

        this.ctx.beginPath();
        this.ctx.arc(cx, cy, radius, Math.PI, endAngle);
        this.ctx.lineWidth = 20;
        this.ctx.strokeStyle = color;
        this.ctx.lineCap = 'round';
        this.ctx.stroke();

        // Value text
        this.ctx.fillStyle = 'rgba(255,255,255,0.9)';
        this.ctx.font = 'bold 32px sans-serif';
        this.ctx.textAlign = 'center';
        this.ctx.fillText(`${Math.round(value)}%`, cx, cy - 10);

        // Label
        if (this.options.label) {
            this.ctx.font = '14px sans-serif';
            this.ctx.fillStyle = 'rgba(255,255,255,0.6)';
            this.ctx.fillText(this.options.label, cx, cy + 20);
        }
    }
}

// ============================================================================
// LIVE DATA MANAGER
// ============================================================================

class LiveChartManager {
    constructor() {
        this.charts = new Map();
        this.interval = null;
    }

    register(id, chart, updateFn) {
        this.charts.set(id, { chart, updateFn });
    }

    unregister(id) {
        this.charts.delete(id);
    }

    start(intervalMs = 3000) {
        if (this.interval) return;
        this.interval = setInterval(() => this.updateAll(), intervalMs);
        this.updateAll();
    }

    stop() {
        if (this.interval) {
            clearInterval(this.interval);
            this.interval = null;
        }
    }

    async updateAll() {
        for (const [id, { chart, updateFn }] of this.charts) {
            try {
                const data = await updateFn();
                if (data) chart.setData(data);
            } catch (e) {
                console.error(`Chart ${id} update failed:`, e);
            }
        }
    }
}

// ============================================================================
// EXPORTS
// ============================================================================

window.Chart = Chart;
window.LineChart = LineChart;
window.BarChart = BarChart;
window.DonutChart = DonutChart;
window.GaugeChart = GaugeChart;
window.LiveChartManager = LiveChartManager;
