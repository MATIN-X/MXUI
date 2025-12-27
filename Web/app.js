/**
 * ============================================================================
 * MX-UI VPN Panel - Main Application
 * app.js - Router, State Management, Authentication, App Initialization
 * ============================================================================
 */

'use strict';

// ============================================================================
// APPLICATION STATE MANAGEMENT
// ============================================================================

class AppState {
    constructor() {
        this.state = {
            user: null,
            admin: null,
            isAuthenticated: false,
            isOwner: false,
            isReseller: false,
            theme: storage.get('theme') || 'dark',
            language: storage.get('language') || 'fa',
            sidebarCollapsed: storage.get('sidebarCollapsed') || false,
            notifications: [],
            loading: false,
            error: null,
            systemStats: null,
            onlineUsers: [],
            nodes: [],
            currentPage: 'home'
        };
        this.listeners = new Map();
        this.prevState = {};
    }

    /**
     * Get state value by path
     */
    get(path) {
        if (!path) return this.state;
        return path.split('.').reduce((obj, key) => obj?.[key], this.state);
    }

    /**
     * Set state value
     */
    set(path, value) {
        this.prevState = JSON.parse(JSON.stringify(this.state));
        
        if (typeof path === 'object') {
            Object.assign(this.state, path);
        } else {
            const keys = path.split('.');
            let obj = this.state;
            for (let i = 0; i < keys.length - 1; i++) {
                if (!obj[keys[i]]) obj[keys[i]] = {};
                obj = obj[keys[i]];
            }
            obj[keys[keys.length - 1]] = value;
        }
        
        this.notify(path);
        return this;
    }

    /**
     * Subscribe to state changes
     */
    subscribe(path, callback) {
        if (!this.listeners.has(path)) {
            this.listeners.set(path, new Set());
        }
        this.listeners.get(path).add(callback);
        
        return () => this.listeners.get(path)?.delete(callback);
    }

    /**
     * Notify listeners of state change
     */
    notify(path) {
        this.listeners.forEach((callbacks, key) => {
            if (path === '*' || key === '*' || key === path || path.startsWith(key + '.')) {
                callbacks.forEach(cb => cb(this.get(key), this.prevState));
            }
        });
    }

    /**
     * Reset state
     */
    reset() {
        this.state = {
            ...this.state,
            user: null,
            admin: null,
            isAuthenticated: false,
            isOwner: false,
            isReseller: false,
            notifications: [],
            error: null
        };
        this.notify('*');
    }
}

// Global state instance
const appState = new AppState();

// ============================================================================
// ROUTER
// ============================================================================

class Router {
    constructor() {
        this.routes = new Map();
        this.currentRoute = null;
        this.beforeHooks = [];
        this.afterHooks = [];
        this.notFoundHandler = null;
        
        window.addEventListener('popstate', () => this.handleRoute());
        window.addEventListener('hashchange', () => this.handleRoute());
    }

    /**
     * Register route
     */
    register(path, config) {
        this.routes.set(path, {
            path,
            component: config.component,
            title: config.title,
            requiresAuth: config.requiresAuth !== false,
            requiresOwner: config.requiresOwner || false,
            onEnter: config.onEnter,
            onLeave: config.onLeave
        });
        return this;
    }

    /**
     * Navigate to path
     */
    navigate(path, options = {}) {
        if (options.replace) {
            history.replaceState({ path }, '', `#${path}`);
        } else {
            history.pushState({ path }, '', `#${path}`);
        }
        this.handleRoute();
    }

    /**
     * Handle route change
     */
    async handleRoute() {
        const hash = window.location.hash.slice(1) || '/home';
        const [path, queryString] = hash.split('?');
        const params = new URLSearchParams(queryString || '');
        
        // Find matching route
        let route = this.routes.get(path);
        let routeParams = {};
        
        if (!route) {
            // Check for dynamic routes
            for (const [pattern, r] of this.routes) {
                const match = this.matchRoute(pattern, path);
                if (match) {
                    route = r;
                    routeParams = match;
                    break;
                }
            }
        }
        
        if (!route) {
            if (this.notFoundHandler) {
                this.notFoundHandler();
            } else {
                this.navigate('/home', { replace: true });
            }
            return;
        }
        
        // Before hooks
        for (const hook of this.beforeHooks) {
            const result = await hook(route, this.currentRoute);
            if (result === false) return;
            if (typeof result === 'string') {
                this.navigate(result, { replace: true });
                return;
            }
        }
        
        // Auth check
        if (route.requiresAuth && !appState.get('isAuthenticated')) {
            this.navigate('/login', { replace: true });
            return;
        }
        
        // Owner check
        if (route.requiresOwner && !appState.get('isOwner')) {
            this.navigate('/home', { replace: true });
            Notify.error(i18n.t('errors.accessDenied'));
            return;
        }
        
        // Leave current route
        if (this.currentRoute?.onLeave) {
            await this.currentRoute.onLeave();
        }
        
        // Enter new route
        this.currentRoute = route;
        appState.set('currentPage', path.replace('/', '') || 'home');
        
        if (route.onEnter) {
            await route.onEnter({ params: routeParams, query: params });
        }
        
        // Update title
        document.title = `${route.title || 'MX-UI'} | MX-UI VPN Panel`;
        
        // Render component
        if (route.component) {
            const container = document.getElementById('app-content');
            if (container) {
                if (typeof route.component === 'function') {
                    container.innerHTML = await route.component({ params: routeParams, query: params });
                } else {
                    container.innerHTML = route.component;
                }
            }
        }
        
        // After hooks
        for (const hook of this.afterHooks) {
            await hook(route);
        }
        
        // Update active nav
        this.updateActiveNav(path);
    }

    /**
     * Match dynamic route
     */
    matchRoute(pattern, path) {
        const patternParts = pattern.split('/');
        const pathParts = path.split('/');
        
        if (patternParts.length !== pathParts.length) return null;
        
        const params = {};
        for (let i = 0; i < patternParts.length; i++) {
            if (patternParts[i].startsWith(':')) {
                params[patternParts[i].slice(1)] = pathParts[i];
            } else if (patternParts[i] !== pathParts[i]) {
                return null;
            }
        }
        return params;
    }

    /**
     * Update active navigation
     */
    updateActiveNav(path) {
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
            if (item.dataset.route === path) {
                item.classList.add('active');
            }
        });
    }

    /**
     * Add before navigation hook
     */
    beforeEach(hook) {
        this.beforeHooks.push(hook);
        return this;
    }

    /**
     * Add after navigation hook
     */
    afterEach(hook) {
        this.afterHooks.push(hook);
        return this;
    }

    /**
     * Set 404 handler
     */
    setNotFound(handler) {
        this.notFoundHandler = handler;
        return this;
    }
}

// Global router instance
const router = new Router();

// ============================================================================
// AUTHENTICATION
// ============================================================================

class Auth {
    static TOKEN_KEY = 'auth_token';
    static REFRESH_KEY = 'refresh_token';
    static ADMIN_KEY = 'admin_data';

    /**
     * Login admin
     */
    static async login(username, password, twoFactorCode = null) {
        try {
            appState.set('loading', true);
            
            const response = await api.post('/auth/login', {
                username,
                password,
                two_factor_code: twoFactorCode
            });
            
            if (response.requires_2fa) {
                return { requires2FA: true };
            }
            
            // Store tokens
            storage.set(this.TOKEN_KEY, response.token, 60 * 24); // 24 hours
            if (response.refresh_token) {
                storage.set(this.REFRESH_KEY, response.refresh_token, 60 * 24 * 7); // 7 days
            }
            
            // Store admin data
            storage.set(this.ADMIN_KEY, response.admin);
            
            // Update state
            appState.set({
                admin: response.admin,
                isAuthenticated: true,
                isOwner: response.admin.role === 'owner',
                isReseller: response.admin.role === 'reseller'
            });
            
            // Set API token
            api.setToken(response.token);
            
            return { success: true, admin: response.admin };
        } catch (error) {
            throw error;
        } finally {
            appState.set('loading', false);
        }
    }

    /**
     * Logout admin
     */
    static async logout() {
        try {
            await api.post('/auth/logout');
        } catch (e) {
            // Ignore logout errors
        }
        
        // Clear storage
        storage.remove(this.TOKEN_KEY);
        storage.remove(this.REFRESH_KEY);
        storage.remove(this.ADMIN_KEY);
        
        // Clear state
        appState.reset();
        api.setToken(null);
        
        // Redirect to login
        router.navigate('/login');
    }

    /**
     * Check if authenticated
     */
    static isAuthenticated() {
        const token = storage.get(this.TOKEN_KEY);
        return !!token;
    }

    /**
     * Get current admin
     */
    static getAdmin() {
        return storage.get(this.ADMIN_KEY);
    }

    /**
     * Refresh token
     */
    static async refreshToken() {
        const refreshToken = storage.get(this.REFRESH_KEY);
        if (!refreshToken) {
            throw new Error('No refresh token');
        }
        
        try {
            const response = await api.post('/auth/refresh', {
                refresh_token: refreshToken
            });
            
            storage.set(this.TOKEN_KEY, response.token, 60 * 24);
            api.setToken(response.token);
            
            return response.token;
        } catch (error) {
            this.logout();
            throw error;
        }
    }

    /**
     * Initialize auth from storage
     */
    static async init() {
        const token = storage.get(this.TOKEN_KEY);
        const admin = storage.get(this.ADMIN_KEY);
        
        if (token && admin) {
            api.setToken(token);
            appState.set({
                admin,
                isAuthenticated: true,
                isOwner: admin.role === 'owner',
                isReseller: admin.role === 'reseller'
            });
            
            // Verify token is still valid
            try {
                const response = await api.get('/auth/me');
                storage.set(this.ADMIN_KEY, response.admin);
                appState.set('admin', response.admin);
            } catch (error) {
                if (error.status === 401) {
                    // Try refresh
                    try {
                        await this.refreshToken();
                    } catch {
                        this.logout();
                    }
                }
            }
        }
    }

    /**
     * Change password
     */
    static async changePassword(currentPassword, newPassword) {
        return api.post('/auth/change-password', {
            current_password: currentPassword,
            new_password: newPassword
        });
    }

    /**
     * Setup 2FA
     */
    static async setup2FA() {
        return api.post('/auth/2fa/setup');
    }

    /**
     * Enable 2FA
     */
    static async enable2FA(code) {
        return api.post('/auth/2fa/enable', { code });
    }

    /**
     * Disable 2FA
     */
    static async disable2FA(code) {
        return api.post('/auth/2fa/disable', { code });
    }
}

// ============================================================================
// INTERNATIONALIZATION
// ============================================================================

class I18n {
    constructor() {
        this.translations = {};
        this.currentLang = storage.get('language') || 'fa';
        this.fallbackLang = 'en';
        this.rtlLanguages = ['fa', 'ar', 'he'];
    }

    /**
     * Load translations
     */
    async load(lang) {
        if (this.translations[lang]) return;
        
        try {
            const response = await fetch(`/lang_${lang}.json`);
            this.translations[lang] = await response.json();
        } catch (error) {
            console.error(`Failed to load language: ${lang}`, error);
        }
    }

    /**
     * Set current language
     */
    async setLanguage(lang) {
        await this.load(lang);
        this.currentLang = lang;
        storage.set('language', lang);
        
        // Update document direction
        document.documentElement.dir = this.isRTL() ? 'rtl' : 'ltr';
        document.documentElement.lang = lang;
        
        // Update state
        appState.set('language', lang);
        
        // Trigger UI update
        document.dispatchEvent(new CustomEvent('languageChanged', { detail: { lang } }));
    }

    /**
     * Check if current language is RTL
     */
    isRTL() {
        return this.rtlLanguages.includes(this.currentLang);
    }

    /**
     * Translate key
     */
    t(key, params = {}) {
        const keys = key.split('.');
        let value = this.translations[this.currentLang];
        
        for (const k of keys) {
            value = value?.[k];
            if (value === undefined) break;
        }
        
        // Fallback to fallback language
        if (value === undefined && this.currentLang !== this.fallbackLang) {
            value = this.translations[this.fallbackLang];
            for (const k of keys) {
                value = value?.[k];
                if (value === undefined) break;
            }
        }
        
        // Return key if not found
        if (value === undefined) return key;
        
        // Replace params
        if (typeof value === 'string') {
            return value.replace(/\{(\w+)\}/g, (match, param) => params[param] ?? match);
        }
        
        return value;
    }

    /**
     * Initialize i18n
     */
    async init() {
        await this.load(this.currentLang);
        if (this.currentLang !== this.fallbackLang) {
            await this.load(this.fallbackLang);
        }
        
        document.documentElement.dir = this.isRTL() ? 'rtl' : 'ltr';
        document.documentElement.lang = this.currentLang;
    }
}

// Global i18n instance
const i18n = new I18n();

// ============================================================================
// THEME MANAGER
// ============================================================================

class ThemeManager {
    constructor() {
        this.currentTheme = storage.get('theme') || 'dark';
        this.mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    }

    /**
     * Initialize theme
     */
    init() {
        this.applyTheme(this.currentTheme);
        
        // Listen for system theme changes
        this.mediaQuery.addEventListener('change', (e) => {
            if (storage.get('theme') === 'system') {
                this.applyTheme(e.matches ? 'dark' : 'light');
            }
        });
    }

    /**
     * Set theme
     */
    setTheme(theme) {
        this.currentTheme = theme;
        storage.set('theme', theme);
        this.applyTheme(theme);
        appState.set('theme', theme);
    }

    /**
     * Apply theme to document
     */
    applyTheme(theme) {
        let effectiveTheme = theme;
        
        if (theme === 'system') {
            effectiveTheme = this.mediaQuery.matches ? 'dark' : 'light';
        }
        
        document.documentElement.setAttribute('data-theme', effectiveTheme);
        document.body.className = document.body.className.replace(/theme-\w+/, '');
        document.body.classList.add(`theme-${effectiveTheme}`);
        
        // Update meta theme-color
        const metaThemeColor = document.querySelector('meta[name="theme-color"]');
        if (metaThemeColor) {
            metaThemeColor.content = effectiveTheme === 'dark' ? '#1a1a2e' : '#ffffff';
        }
    }

    /**
     * Toggle theme
     */
    toggle() {
        const newTheme = this.currentTheme === 'dark' ? 'light' : 'dark';
        this.setTheme(newTheme);
        return newTheme;
    }

    /**
     * Get current theme
     */
    getTheme() {
        return this.currentTheme;
    }
}

// Global theme manager
const themeManager = new ThemeManager();

// ============================================================================
// NOTIFICATION SYSTEM
// ============================================================================

class Notify {
    static container = null;
    static queue = [];
    static maxVisible = 5;

    /**
     * Initialize notification container
     */
    static init() {
        if (!this.container) {
            this.container = document.createElement('div');
            this.container.id = 'notification-container';
            this.container.className = 'notification-container';
            document.body.appendChild(this.container);
        }
    }

    /**
     * Show notification
     */
    static show(message, type = 'info', options = {}) {
        this.init();
        
        const notification = document.createElement('div');
        notification.className = `notification notification-${type} notification-enter`;
        
        const icon = this.getIcon(type);
        const duration = options.duration ?? 5000;
        
        notification.innerHTML = `
            <div class="notification-icon">${icon}</div>
            <div class="notification-content">
                ${options.title ? `<div class="notification-title">${options.title}</div>` : ''}
                <div class="notification-message">${message}</div>
            </div>
            <button class="notification-close" onclick="Notify.close(this.parentElement)">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M18 6L6 18M6 6l12 12"/>
                </svg>
            </button>
            ${duration > 0 ? '<div class="notification-progress"></div>' : ''}
        `;
        
        this.container.appendChild(notification);
        
        // Trigger animation
        requestAnimationFrame(() => {
            notification.classList.remove('notification-enter');
        });
        
        // Progress bar animation
        if (duration > 0) {
            const progress = notification.querySelector('.notification-progress');
            if (progress) {
                progress.style.animationDuration = `${duration}ms`;
            }
            
            setTimeout(() => this.close(notification), duration);
        }
        
        return notification;
    }

    /**
     * Close notification
     */
    static close(notification) {
        if (!notification || notification.classList.contains('notification-exit')) return;
        
        notification.classList.add('notification-exit');
        setTimeout(() => notification.remove(), 300);
    }

    /**
     * Get icon for type
     */
    static getIcon(type) {
        const icons = {
            success: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>',
            error: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>',
            warning: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4M12 17h.01"/><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>',
            info: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>'
        };
        return icons[type] || icons.info;
    }

    static success(message, options) { return this.show(message, 'success', options); }
    static error(message, options) { return this.show(message, 'error', options); }
    static warning(message, options) { return this.show(message, 'warning', options); }
    static info(message, options) { return this.show(message, 'info', options); }
}

// ============================================================================
// WEBSOCKET MANAGER
// ============================================================================

class WebSocketManager {
    constructor() {
        this.ws = null;
        this.url = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 10;
        this.reconnectDelay = 1000;
        this.handlers = new Map();
        this.isConnected = false;
        this.heartbeatInterval = null;
    }

    /**
     * Connect to WebSocket server
     */
    connect(url) {
        this.url = url || `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`;
        
        try {
            this.ws = new WebSocket(this.url);
            
            this.ws.onopen = () => {
                console.log('WebSocket connected');
                this.isConnected = true;
                this.reconnectAttempts = 0;
                this.startHeartbeat();
                this.emit('connected');
            };
            
            this.ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleMessage(data);
                } catch (e) {
                    console.error('WebSocket message parse error:', e);
                }
            };
            
            this.ws.onclose = () => {
                console.log('WebSocket disconnected');
                this.isConnected = false;
                this.stopHeartbeat();
                this.emit('disconnected');
                this.attemptReconnect();
            };
            
            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.emit('error', error);
            };
        } catch (error) {
            console.error('WebSocket connection failed:', error);
        }
    }

    /**
     * Handle incoming message
     */
    handleMessage(data) {
        const { type, payload } = data;
        
        if (this.handlers.has(type)) {
            this.handlers.get(type).forEach(handler => handler(payload));
        }
        
        // Handle common events
        switch (type) {
            case 'user_online':
                this.emit('userOnline', payload);
                break;
            case 'user_offline':
                this.emit('userOffline', payload);
                break;
            case 'traffic_update':
                this.emit('trafficUpdate', payload);
                break;
            case 'node_status':
                this.emit('nodeStatus', payload);
                break;
            case 'notification':
                Notify.show(payload.message, payload.type);
                break;
        }
    }

    /**
     * Send message
     */
    send(type, payload) {
        if (!this.isConnected) return false;
        
        this.ws.send(JSON.stringify({ type, payload }));
        return true;
    }

    /**
     * Subscribe to message type
     */
    on(type, handler) {
        if (!this.handlers.has(type)) {
            this.handlers.set(type, new Set());
        }
        this.handlers.get(type).add(handler);
        
        return () => this.handlers.get(type)?.delete(handler);
    }

    /**
     * Emit event
     */
    emit(type, data) {
        if (this.handlers.has(type)) {
            this.handlers.get(type).forEach(handler => handler(data));
        }
    }

    /**
     * Attempt reconnection
     */
    attemptReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('Max reconnect attempts reached');
            return;
        }
        
        this.reconnectAttempts++;
        const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
        
        console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
        setTimeout(() => this.connect(this.url), delay);
    }

    /**
     * Start heartbeat
     */
    startHeartbeat() {
        this.heartbeatInterval = setInterval(() => {
            this.send('ping', { timestamp: Date.now() });
        }, 30000);
    }

    /**
     * Stop heartbeat
     */
    stopHeartbeat() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
    }

    /**
     * Disconnect
     */
    disconnect() {
        this.stopHeartbeat();
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }
}

// Global WebSocket manager
const wsManager = new WebSocketManager();

// ============================================================================
// ROUTE DEFINITIONS
// ============================================================================

function registerRoutes() {
    // Login page
    router.register('/login', {
        title: i18n.t('pages.login'),
        requiresAuth: false,
        component: renderLoginPage
    });

    // Home/Dashboard
    router.register('/home', {
        title: i18n.t('pages.home'),
        component: renderHomePage
    });

    // Users
    router.register('/users', {
        title: i18n.t('pages.users'),
        component: renderUsersPage
    });

    router.register('/users/:id', {
        title: i18n.t('pages.userDetail'),
        component: renderUserDetailPage
    });

    // Admins (Owner only)
    router.register('/admins', {
        title: i18n.t('pages.admins'),
        requiresOwner: true,
        component: renderAdminsPage
    });

    // Core settings (Owner only)
    router.register('/core', {
        title: i18n.t('pages.core'),
        requiresOwner: true,
        component: renderCorePage
    });

    // Panel settings (Owner only)
    router.register('/panel', {
        title: i18n.t('pages.panel'),
        requiresOwner: true,
        component: renderPanelPage
    });

    // Templates (Owner only)
    router.register('/templates', {
        title: i18n.t('pages.templates'),
        requiresOwner: true,
        component: renderTemplatesPage
    });

    // Bot settings (Owner only)
    router.register('/bot', {
        title: i18n.t('pages.bot'),
        requiresOwner: true,
        component: renderBotPage
    });

    // AI settings (Owner only)
    router.register('/ai', {
        title: i18n.t('pages.ai'),
        requiresOwner: true,
        component: renderAIPage
    });

    // Navigation hooks
    router.beforeEach(async (to, from) => {
        // Show loading
        appState.set('loading', true);
        return true;
    });

    router.afterEach(async () => {
        // Hide loading
        appState.set('loading', false);
    });
}

// ============================================================================
// PAGE RENDER FUNCTIONS
// ============================================================================

async function renderLoginPage() {
    if (appState.get('isAuthenticated')) {
        router.navigate('/home', { replace: true });
        return '';
    }
    
    return `
        <div class="login-page">
            <div class="login-container">
                <div class="login-logo">
                    <img src="/assets/logo.svg" alt="MX-UI" />
                    <h1>MX-UI VPN Panel</h1>
                </div>
                <form id="login-form" class="login-form" onsubmit="handleLogin(event)">
                    <div class="form-group">
                        <label for="username">${i18n.t('auth.username')}</label>
                        <input type="text" id="username" name="username" required autofocus
                            placeholder="${i18n.t('auth.usernamePlaceholder')}">
                    </div>
                    <div class="form-group">
                        <label for="password">${i18n.t('auth.password')}</label>
                        <input type="password" id="password" name="password" required
                            placeholder="${i18n.t('auth.passwordPlaceholder')}">
                    </div>
                    <div id="2fa-group" class="form-group hidden">
                        <label for="two-factor">${i18n.t('auth.twoFactor')}</label>
                        <input type="text" id="two-factor" name="two_factor" maxlength="6"
                            placeholder="${i18n.t('auth.twoFactorPlaceholder')}">
                    </div>
                    <button type="submit" class="btn btn-primary btn-block" id="login-btn">
                        ${i18n.t('auth.login')}
                    </button>
                </form>
                <div class="login-footer">
                    <a href="https://github.com/MX-UI-Panel" target="_blank">GitHub</a>
                    <span>|</span>
                    <span>v${MXUI.VERSION}</span>
                </div>
            </div>
        </div>
    `;
}

async function renderHomePage() {
    // Load system stats
    try {
        const stats = await api.get('/system/stats');
        appState.set('systemStats', stats);
    } catch (e) {
        console.error('Failed to load stats:', e);
    }
    
    const stats = appState.get('systemStats') || {};
    const admin = appState.get('admin');
    const isOwner = appState.get('isOwner');
    
    return `
        <div class="page-header">
            <h1>${i18n.t('pages.home')}</h1>
            <div class="page-actions">
                <button class="btn btn-outline" onclick="refreshStats()">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M23 4v6h-6M1 20v-6h6"/>
                        <path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/>
                    </svg>
                    ${i18n.t('common.refresh')}
                </button>
            </div>
        </div>
        
        <div class="stats-grid">
            ${isOwner ? `
                <div class="stat-card">
                    <div class="stat-icon system">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="2" y="3" width="20" height="14" rx="2"/>
                            <path d="M8 21h8M12 17v4"/>
                        </svg>
                    </div>
                    <div class="stat-info">
                        <div class="stat-label">${i18n.t('stats.cpu')}</div>
                        <div class="stat-value">${stats.cpu || 0}%</div>
                    </div>
                    <div class="stat-progress">
                        <div class="stat-progress-bar" style="width: ${stats.cpu || 0}%"></div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon memory">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M6 19v2M10 19v2M14 19v2M18 19v2M4 19h16a2 2 0 002-2V7a2 2 0 00-2-2H4a2 2 0 00-2 2v10a2 2 0 002 2z"/>
                        </svg>
                    </div>
                    <div class="stat-info">
                        <div class="stat-label">${i18n.t('stats.ram')}</div>
                        <div class="stat-value">${stats.ram || 0}%</div>
                    </div>
                    <div class="stat-progress">
                        <div class="stat-progress-bar" style="width: ${stats.ram || 0}%"></div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon storage">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/>
                        </svg>
                    </div>
                    <div class="stat-info">
                        <div class="stat-label">${i18n.t('stats.storage')}</div>
                        <div class="stat-value">${formatBytes(stats.storage_used || 0)} / ${formatBytes(stats.storage_total || 0)}</div>
                    </div>
                    <div class="stat-progress">
                        <div class="stat-progress-bar" style="width: ${stats.storage_percent || 0}%"></div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon network">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M5 12.55a11 11 0 0114.08 0M1.42 9a16 16 0 0121.16 0M8.53 16.11a6 6 0 016.95 0M12 20h.01"/>
                        </svg>
                    </div>
                    <div class="stat-info">
                        <div class="stat-label">${i18n.t('stats.bandwidth')}</div>
                        <div class="stat-value">
                            <span class="upload">â†‘ ${formatBytes(stats.upload_speed || 0)}/s</span>
                            <span class="download">â†“ ${formatBytes(stats.download_speed || 0)}/s</span>
                        </div>
                    </div>
                </div>
            ` : ''}
            
            <div class="stat-card">
                <div class="stat-icon users">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
                        <circle cx="9" cy="7" r="4"/>
                        <path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/>
                    </svg>
                </div>
                <div class="stat-info">
                    <div class="stat-label">${i18n.t('stats.totalUsers')}</div>
                    <div class="stat-value">${stats.total_users || 0}</div>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon online">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"/>
                        <path d="M2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/>
                    </svg>
                </div>
                <div class="stat-info">
                    <div class="stat-label">${i18n.t('stats.onlineUsers')}</div>
                    <div class="stat-value">${stats.online_users || 0}</div>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon traffic">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                    </svg>
                </div>
                <div class="stat-info">
                    <div class="stat-label">${i18n.t('stats.totalTraffic')}</div>
                    <div class="stat-value">${formatBytes(stats.total_traffic || 0)}</div>
                </div>
            </div>
        </div>
        
        ${isOwner ? `
        <div class="dashboard-grid">
            <div class="dashboard-card">
                <div class="card-header">
                    <h3>${i18n.t('home.quickActions')}</h3>
                </div>
                <div class="card-body">
                    <div class="quick-actions">
                        <button class="quick-action" onclick="router.navigate('/users')">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M16 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
                                <circle cx="8.5" cy="7" r="4"/>
                                <path d="M20 8v6M23 11h-6"/>
                            </svg>
                            ${i18n.t('home.addUser')}
                        </button>
                        <button class="quick-action" onclick="createBackup()">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12"/>
                            </svg>
                            ${i18n.t('home.backup')}
                        </button>
                        <button class="quick-action" onclick="rebootSystem()">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M23 4v6h-6M1 20v-6h6"/>
                                <path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/>
                            </svg>
                            ${i18n.t('home.reboot')}
                        </button>
                        <button class="quick-action" onclick="viewLogs()">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                                <polyline points="14 2 14 8 20 8"/>
                                <line x1="16" y1="13" x2="8" y2="13"/>
                                <line x1="16" y1="17" x2="8" y2="17"/>
                            </svg>
                            ${i18n.t('home.logs')}
                        </button>
                    </div>
                </div>
            </div>
            
            <div class="dashboard-card">
                <div class="card-header">
                    <h3>${i18n.t('home.serverInfo')}</h3>
                </div>
                <div class="card-body">
                    <div class="info-list">
                        <div class="info-item">
                            <span class="info-label">IPv4:</span>
                            <span class="info-value">${stats.ipv4 || '-'}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">IPv6:</span>
                            <span class="info-value">${stats.ipv6 || '-'}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">${i18n.t('home.uptime')}:</span>
                            <span class="info-value">${formatUptime(stats.uptime || 0)}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">${i18n.t('home.version')}:</span>
                            <span class="info-value">v${MXUI.VERSION}</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="dashboard-card full-width">
            <div class="card-header">
                <h3>${i18n.t('home.trafficChart')}</h3>
                <div class="card-actions">
                    <select id="chart-period" onchange="updateTrafficChart(this.value)">
                        <option value="day">${i18n.t('common.day')}</option>
                        <option value="week">${i18n.t('common.week')}</option>
                        <option value="month">${i18n.t('common.month')}</option>
                    </select>
                </div>
            </div>
            <div class="card-body">
                <canvas id="traffic-chart" height="200"></canvas>
            </div>
        </div>
        ` : ''}
    `;
}

async function renderUsersPage({ params, query }) {
    return `
        <div class="page-header">
            <h1>${i18n.t('pages.users')}</h1>
            <div class="page-actions">
                <button class="btn btn-primary" onclick="openCreateUserModal()">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M16 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
                        <circle cx="8.5" cy="7" r="4"/>
                        <path d="M20 8v6M23 11h-6"/>
                    </svg>
                    ${i18n.t('users.create')}
                </button>
            </div>
        </div>
        
        <div class="filter-bar">
            <div class="search-box">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="11" cy="11" r="8"/>
                    <path d="M21 21l-4.35-4.35"/>
                </svg>
                <input type="text" id="user-search" placeholder="${i18n.t('users.searchPlaceholder')}"
                    oninput="debounce(filterUsers, 300)(this.value)">
            </div>
            <div class="filter-group">
                <select id="user-status" onchange="filterUsers()">
                    <option value="">${i18n.t('users.allStatus')}</option>
                    <option value="active">${i18n.t('status.active')}</option>
                    <option value="expired">${i18n.t('status.expired')}</option>
                    <option value="limited">${i18n.t('status.limited')}</option>
                    <option value="disabled">${i18n.t('status.disabled')}</option>
                    <option value="on_hold">${i18n.t('status.onHold')}</option>
                </select>
            </div>
            <div class="bulk-actions hidden" id="bulk-actions">
                <button class="btn btn-sm btn-outline" onclick="bulkEnableUsers()">
                    ${i18n.t('users.enable')}
                </button>
                <button class="btn btn-sm btn-outline" onclick="bulkDisableUsers()">
                    ${i18n.t('users.disable')}
                </button>
                <button class="btn btn-sm btn-danger" onclick="bulkDeleteUsers()">
                    ${i18n.t('users.delete')}
                </button>
            </div>
        </div>
        
        <div class="table-container">
            <table class="data-table" id="users-table">
                <thead>
                    <tr>
                        <th><input type="checkbox" id="select-all" onchange="toggleSelectAll(this)"></th>
                        <th>${i18n.t('users.username')}</th>
                        <th>${i18n.t('users.status')}</th>
                        <th>${i18n.t('users.traffic')}</th>
                        <th>${i18n.t('users.expiry')}</th>
                        <th>${i18n.t('users.online')}</th>
                        <th>${i18n.t('common.actions')}</th>
                    </tr>
                </thead>
                <tbody id="users-tbody">
                    <tr><td colspan="7" class="loading">${i18n.t('common.loading')}</td></tr>
                </tbody>
            </table>
        </div>
        
        <div class="pagination" id="users-pagination"></div>
    `;
}

async function renderUserDetailPage({ params }) {
    return `<div class="page-content">User Detail: ${params.id}</div>`;
}

async function renderAdminsPage() {
    return `<div class="page-content">Admins Page - Owner Only</div>`;
}

async function renderCorePage() {
    return `<div class="page-content">Core Settings Page - Owner Only</div>`;
}

async function renderPanelPage() {
    return `<div class="page-content">Panel Settings Page - Owner Only</div>`;
}

async function renderTemplatesPage() {
    return `<div class="page-content">Templates Page - Owner Only</div>`;
}

async function renderBotPage() {
    return `<div class="page-content">Bot Settings Page - Owner Only</div>`;
}

async function renderAIPage() {
    return `<div class="page-content">AI Settings Page - Owner Only</div>`;
}

// ============================================================================
// EVENT HANDLERS
// ============================================================================

async function handleLogin(event) {
    event.preventDefault();
    
    const form = event.target;
    const username = form.username.value;
    const password = form.password.value;
    const twoFactor = form.two_factor?.value;
    
    const submitBtn = form.querySelector('#login-btn');
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span class="spinner"></span> ${i18n.t('common.loading')}`;
    
    try {
        const result = await Auth.login(username, password, twoFactor);
        
        if (result.requires2FA) {
            document.getElementById('2fa-group').classList.remove('hidden');
            document.getElementById('two-factor').focus();
            Notify.info(i18n.t('auth.enterTwoFactor'));
        } else if (result.success) {
            Notify.success(i18n.t('auth.loginSuccess'));
            router.navigate('/home');
        }
    } catch (error) {
        Notify.error(error.message || i18n.t('auth.loginFailed'));
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = i18n.t('auth.login');
    }
}

async function refreshStats() {
    try {
        const stats = await api.get('/system/stats');
        appState.set('systemStats', stats);
        router.handleRoute();
        Notify.success(i18n.t('common.refreshed'));
    } catch (error) {
        Notify.error(i18n.t('errors.refreshFailed'));
    }
}

async function createBackup() {
    try {
        const result = await api.post('/backup/create');
        Notify.success(i18n.t('backup.created'));
    } catch (error) {
        Notify.error(i18n.t('backup.failed'));
    }
}

async function rebootSystem() {
    const confirmed = await Modal.confirm({
        title: i18n.t('home.reboot'),
        message: i18n.t('home.rebootConfirm'),
        confirmText: i18n.t('home.reboot'),
        type: 'warning'
    });
    
    if (confirmed) {
        try {
            await api.post('/system/reboot');
            Notify.warning(i18n.t('home.rebooting'));
        } catch (error) {
            Notify.error(i18n.t('errors.rebootFailed'));
        }
    }
}

function viewLogs() {
    Modal.open({
        title: i18n.t('home.logs'),
        size: 'large',
        content: `<div class="log-viewer" id="log-viewer"><pre>${i18n.t('common.loading')}</pre></div>`,
        onOpen: async () => {
            try {
                const logs = await api.get('/system/logs');
                document.getElementById('log-viewer').innerHTML = `<pre>${logs.content}</pre>`;
            } catch (error) {
                document.getElementById('log-viewer').innerHTML = `<pre class="error">${error.message}</pre>`;
            }
        }
    });
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    const parts = [];
    if (days > 0) parts.push(`${days}d`);
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    
    return parts.join(' ') || '0m';
}

// ============================================================================
// APPLICATION INITIALIZATION
// ============================================================================

async function initApp() {
    console.log('ðŸš€ Initializing MX-UI VPN Panel...');
    
    // Initialize theme
    themeManager.init();
    
    // Initialize i18n
    await i18n.init();
    
    // Initialize authentication
    await Auth.init();
    
    // Register routes
    registerRoutes();
    
    // Initialize WebSocket
    if (appState.get('isAuthenticated')) {
        wsManager.connect();
    }
    
    // Subscribe to auth changes
    appState.subscribe('isAuthenticated', (isAuth) => {
        if (isAuth) {
            wsManager.connect();
        } else {
            wsManager.disconnect();
        }
    });
    
    // Handle initial route
    router.handleRoute();
    
    // Setup global event listeners
    document.addEventListener('keydown', (e) => {
        // Escape to close modals
        if (e.key === 'Escape') {
            Modal.closeAll();
        }
    });
    
    console.log('âœ… MX-UI VPN Panel initialized');
}

// Start app when DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
} else {
    initApp();
}

// Export for global access
window.MXUI = MXUI;
window.appState = appState;
window.router = router;
window.i18n = i18n;
window.themeManager = themeManager;
window.Notify = Notify;
window.Auth = Auth;
window.wsManager = wsManager;
