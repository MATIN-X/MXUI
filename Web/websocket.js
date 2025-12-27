/**
 * MX-UI VPN Panel - WebSocket
 * websocket.js - Real-time Updates, Events
 */

'use strict';

// ============================================================================
// WEBSOCKET MANAGER
// ============================================================================

class WebSocketManager {
    constructor(options = {}) {
        this.url = options.url || this.getDefaultURL();
        this.socket = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = options.maxReconnect || 10;
        this.reconnectDelay = options.reconnectDelay || 3000;
        this.handlers = new Map();
        this.connected = false;
        this.autoReconnect = options.autoReconnect !== false;
        this.pingInterval = null;
        this.messageQueue = [];
    }

    getDefaultURL() {
        const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        return `${protocol}//${location.host}/ws`;
    }

    // Connect to WebSocket server
    connect() {
        if (this.socket?.readyState === WebSocket.OPEN) return;

        try {
            this.socket = new WebSocket(this.url);
            this.bindEvents();
        } catch (error) {
            console.error('WebSocket connection error:', error);
            this.handleReconnect();
        }
    }

    // Bind socket events
    bindEvents() {
        this.socket.onopen = () => {
            console.log('WebSocket connected');
            this.connected = true;
            this.reconnectAttempts = 0;
            this.emit('connected');
            this.startPing();
            this.flushQueue();
        };

        this.socket.onclose = (event) => {
            console.log('WebSocket closed:', event.code, event.reason);
            this.connected = false;
            this.stopPing();
            this.emit('disconnected', { code: event.code, reason: event.reason });
            
            if (this.autoReconnect && event.code !== 1000) {
                this.handleReconnect();
            }
        };

        this.socket.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.emit('error', error);
        };

        this.socket.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                this.handleMessage(message);
            } catch (e) {
                console.error('Failed to parse message:', e);
            }
        };
    }

    // Handle incoming message
    handleMessage(message) {
        const { type, data } = message;

        // Handle ping/pong
        if (type === 'pong') return;

        // Emit to specific handlers
        if (this.handlers.has(type)) {
            this.handlers.get(type).forEach(handler => {
                try {
                    handler(data);
                } catch (e) {
                    console.error(`Handler error for ${type}:`, e);
                }
            });
        }

        // Emit to wildcard handlers
        if (this.handlers.has('*')) {
            this.handlers.get('*').forEach(handler => handler(type, data));
        }
    }

    // Subscribe to event
    on(type, handler) {
        if (!this.handlers.has(type)) {
            this.handlers.set(type, new Set());
        }
        this.handlers.get(type).add(handler);
        return () => this.off(type, handler);
    }

    // Unsubscribe from event
    off(type, handler) {
        if (this.handlers.has(type)) {
            this.handlers.get(type).delete(handler);
        }
    }

    // Emit event (for internal use)
    emit(type, data) {
        this.handleMessage({ type, data });
    }

    // Send message
    send(type, data) {
        const message = JSON.stringify({ type, data });
        
        if (this.connected && this.socket?.readyState === WebSocket.OPEN) {
            this.socket.send(message);
        } else {
            this.messageQueue.push(message);
        }
    }

    // Flush queued messages
    flushQueue() {
        while (this.messageQueue.length > 0 && this.connected) {
            const message = this.messageQueue.shift();
            this.socket.send(message);
        }
    }

    // Start ping interval
    startPing() {
        this.pingInterval = setInterval(() => {
            if (this.connected) {
                this.send('ping', { timestamp: Date.now() });
            }
        }, 30000);
    }

    // Stop ping interval
    stopPing() {
        if (this.pingInterval) {
            clearInterval(this.pingInterval);
            this.pingInterval = null;
        }
    }

    // Handle reconnection
    handleReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('Max reconnection attempts reached');
            this.emit('reconnect_failed');
            return;
        }

        this.reconnectAttempts++;
        const delay = this.reconnectDelay * Math.pow(1.5, this.reconnectAttempts - 1);
        
        console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
        this.emit('reconnecting', { attempt: this.reconnectAttempts, delay });

        setTimeout(() => this.connect(), delay);
    }

    // Disconnect
    disconnect() {
        this.autoReconnect = false;
        this.stopPing();
        if (this.socket) {
            this.socket.close(1000, 'Client disconnect');
            this.socket = null;
        }
        this.connected = false;
    }

    // Check connection status
    isConnected() {
        return this.connected && this.socket?.readyState === WebSocket.OPEN;
    }
}

// ============================================================================
// REAL-TIME UPDATES
// ============================================================================

class RealtimeUpdater {
    constructor(ws) {
        this.ws = ws;
        this.subscriptions = new Set();
        this.setupHandlers();
    }

    setupHandlers() {
        // System stats update
        this.ws.on('stats', (data) => {
            if (window.state) {
                state.set('systemStats', data);
            }
            this.updateUI('stats', data);
        });

        // Online users update
        this.ws.on('online_users', (data) => {
            if (window.state) {
                state.set('onlineUsers', data);
            }
            this.updateUI('online_users', data);
        });

        // Node status update
        this.ws.on('nodes', (data) => {
            if (window.state) {
                state.set('nodes', data);
            }
            this.updateUI('nodes', data);
        });

        // Traffic update
        this.ws.on('traffic', (data) => {
            this.updateUI('traffic', data);
        });

        // Notification
        this.ws.on('notification', (data) => {
            if (window.Notification) {
                Notification[data.type || 'info'](data.message);
            }
        });

        // User connection/disconnection
        this.ws.on('user_connected', (data) => {
            this.updateUI('user_connected', data);
        });

        this.ws.on('user_disconnected', (data) => {
            this.updateUI('user_disconnected', data);
        });
    }

    // Subscribe to updates
    subscribe(channel) {
        if (!this.subscriptions.has(channel)) {
            this.subscriptions.add(channel);
            this.ws.send('subscribe', { channel });
        }
    }

    // Unsubscribe from updates
    unsubscribe(channel) {
        if (this.subscriptions.has(channel)) {
            this.subscriptions.delete(channel);
            this.ws.send('unsubscribe', { channel });
        }
    }

    // Update UI element
    updateUI(type, data) {
        const event = new CustomEvent(`realtime:${type}`, { detail: data });
        document.dispatchEvent(event);
    }
}

// ============================================================================
// CONNECTION INDICATOR
// ============================================================================

class ConnectionIndicator {
    constructor(ws) {
        this.ws = ws;
        this.element = null;
        this.setupListeners();
    }

    setupListeners() {
        this.ws.on('connected', () => this.setStatus('connected'));
        this.ws.on('disconnected', () => this.setStatus('disconnected'));
        this.ws.on('reconnecting', () => this.setStatus('reconnecting'));
        this.ws.on('error', () => this.setStatus('error'));
    }

    mount(selector) {
        this.element = document.querySelector(selector);
        if (!this.element) {
            this.element = document.createElement('div');
            this.element.className = 'connection-indicator';
            document.body.appendChild(this.element);
        }
        this.setStatus(this.ws.isConnected() ? 'connected' : 'disconnected');
    }

    setStatus(status) {
        if (!this.element) return;

        const statusText = {
            connected: 'متصل',
            disconnected: 'قطع شده',
            reconnecting: 'در حال اتصال...',
            error: 'خطا'
        };

        this.element.className = `connection-indicator status-${status}`;
        this.element.innerHTML = `
            <span class="indicator-dot"></span>
            <span class="indicator-text">${statusText[status]}</span>
        `;
    }
}

// ============================================================================
// EXPORTS
// ============================================================================

window.WebSocketManager = WebSocketManager;
window.RealtimeUpdater = RealtimeUpdater;
window.ConnectionIndicator = ConnectionIndicator;
