/**
 * ============================================================================
 * MX-UI VPN Panel - API Client
 * Part 1: HTTP Client, Request/Response Handling, Interceptors, Auth
 * ============================================================================
 */

'use strict';

// ============================================================================
// API CONFIGURATION
// ============================================================================

const API_CONFIG = {
    baseURL: window.MXUI_API_URL || '/api/v1',
    timeout: 30000,
    retries: 3,
    retryDelay: 1000,
    headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
};

// API Error Codes
const API_ERRORS = {
    NETWORK_ERROR: 'NETWORK_ERROR',
    TIMEOUT: 'TIMEOUT',
    UNAUTHORIZED: 'UNAUTHORIZED',
    FORBIDDEN: 'FORBIDDEN',
    NOT_FOUND: 'NOT_FOUND',
    VALIDATION_ERROR: 'VALIDATION_ERROR',
    SERVER_ERROR: 'SERVER_ERROR',
    RATE_LIMITED: 'RATE_LIMITED',
    UNKNOWN: 'UNKNOWN'
};

// ============================================================================
// API ERROR CLASS
// ============================================================================

class APIError extends Error {
    constructor(message, code, status, data = null) {
        super(message);
        this.name = 'APIError';
        this.code = code;
        this.status = status;
        this.data = data;
        this.timestamp = new Date();
    }

    /**
     * Check if error is specific type
     */
    is(code) {
        return this.code === code;
    }

    /**
     * Check if unauthorized
     */
    isUnauthorized() {
        return this.code === API_ERRORS.UNAUTHORIZED || this.status === 401;
    }

    /**
     * Check if network error
     */
    isNetworkError() {
        return this.code === API_ERRORS.NETWORK_ERROR;
    }

    /**
     * Check if validation error
     */
    isValidationError() {
        return this.code === API_ERRORS.VALIDATION_ERROR || this.status === 422;
    }

    /**
     * Get validation errors
     */
    getValidationErrors() {
        if (this.isValidationError() && this.data?.errors) {
            return this.data.errors;
        }
        return {};
    }

    /**
     * Convert to JSON
     */
    toJSON() {
        return {
            name: this.name,
            message: this.message,
            code: this.code,
            status: this.status,
            data: this.data,
            timestamp: this.timestamp
        };
    }
}

// ============================================================================
// REQUEST QUEUE & RATE LIMITING
// ============================================================================

class RequestQueue {
    constructor(options = {}) {
        this.maxConcurrent = options.maxConcurrent || 10;
        this.queue = [];
        this.running = 0;
        this.rateLimitDelay = 0;
        this.rateLimitUntil = 0;
    }

    /**
     * Add request to queue
     */
    add(requestFn) {
        return new Promise((resolve, reject) => {
            this.queue.push({ requestFn, resolve, reject });
            this.process();
        });
    }

    /**
     * Process queue
     */
    async process() {
        if (this.running >= this.maxConcurrent || this.queue.length === 0) {
            return;
        }

        // Check rate limit
        if (Date.now() < this.rateLimitUntil) {
            setTimeout(() => this.process(), this.rateLimitUntil - Date.now());
            return;
        }

        const { requestFn, resolve, reject } = this.queue.shift();
        this.running++;

        try {
            const result = await requestFn();
            resolve(result);
        } catch (error) {
            // Handle rate limiting
            if (error.status === 429) {
                const retryAfter = error.data?.retry_after || 60;
                this.rateLimitUntil = Date.now() + (retryAfter * 1000);
            }
            reject(error);
        } finally {
            this.running--;
            this.process();
        }
    }

    /**
     * Clear queue
     */
    clear() {
        this.queue.forEach(({ reject }) => {
            reject(new APIError('Request cancelled', 'CANCELLED', 0));
        });
        this.queue = [];
    }

    /**
     * Get queue size
     */
    size() {
        return this.queue.length;
    }
}

// ============================================================================
// REQUEST CACHE
// ============================================================================

class RequestCache {
    constructor(options = {}) {
        this.cache = new Map();
        this.defaultTTL = options.ttl || 5 * 60 * 1000; // 5 minutes
        this.maxSize = options.maxSize || 100;
    }

    /**
     * Generate cache key
     */
    key(url, options = {}) {
        const params = options.params ? JSON.stringify(options.params) : '';
        return `${options.method || 'GET'}:${url}:${params}`;
    }

    /**
     * Get cached response
     */
    get(key) {
        const cached = this.cache.get(key);
        
        if (!cached) return null;
        
        if (Date.now() > cached.expiry) {
            this.cache.delete(key);
            return null;
        }
        
        return cached.data;
    }

    /**
     * Set cache entry
     */
    set(key, data, ttl = this.defaultTTL) {
        // Evict oldest if max size reached
        if (this.cache.size >= this.maxSize) {
            const oldestKey = this.cache.keys().next().value;
            this.cache.delete(oldestKey);
        }

        this.cache.set(key, {
            data,
            expiry: Date.now() + ttl,
            timestamp: Date.now()
        });
    }

    /**
     * Delete cache entry
     */
    delete(key) {
        this.cache.delete(key);
    }

    /**
     * Delete entries matching pattern
     */
    deletePattern(pattern) {
        const regex = new RegExp(pattern);
        for (const key of this.cache.keys()) {
            if (regex.test(key)) {
                this.cache.delete(key);
            }
        }
    }

    /**
     * Clear all cache
     */
    clear() {
        this.cache.clear();
    }

    /**
     * Get cache stats
     */
    stats() {
        let valid = 0;
        let expired = 0;
        const now = Date.now();

        for (const cached of this.cache.values()) {
            if (now > cached.expiry) {
                expired++;
            } else {
                valid++;
            }
        }

        return { total: this.cache.size, valid, expired };
    }
}

// ============================================================================
// INTERCEPTORS
// ============================================================================

class InterceptorManager {
    constructor() {
        this.handlers = [];
    }

    /**
     * Add interceptor
     */
    use(fulfilled, rejected) {
        const id = this.handlers.length;
        this.handlers.push({ fulfilled, rejected, id });
        return id;
    }

    /**
     * Remove interceptor
     */
    eject(id) {
        const index = this.handlers.findIndex(h => h.id === id);
        if (index !== -1) {
            this.handlers.splice(index, 1);
        }
    }

    /**
     * Execute interceptors
     */
    async execute(value, type = 'fulfilled') {
        let result = value;
        
        for (const handler of this.handlers) {
            if (handler[type]) {
                try {
                    result = await handler[type](result);
                } catch (error) {
                    if (handler.rejected) {
                        result = await handler.rejected(error);
                    } else {
                        throw error;
                    }
                }
            }
        }
        
        return result;
    }

    /**
     * Clear all interceptors
     */
    clear() {
        this.handlers = [];
    }
}

// ============================================================================
// HTTP CLIENT
// ============================================================================

class HttpClient {
    constructor(config = {}) {
        this.config = { ...API_CONFIG, ...config };
        this.requestInterceptors = new InterceptorManager();
        this.responseInterceptors = new InterceptorManager();
        this.queue = new RequestQueue();
        this.cache = new RequestCache();
        this.abortControllers = new Map();

        // Setup default interceptors
        this._setupDefaultInterceptors();
    }

    /**
     * Setup default interceptors
     */
    _setupDefaultInterceptors() {
        // Request: Add auth token
        this.requestInterceptors.use(async (config) => {
            const token = auth.getToken();
            if (token) {
                config.headers = config.headers || {};
                config.headers['Authorization'] = `Bearer ${token}`;
            }
            return config;
        });

        // Request: Add request ID
        this.requestInterceptors.use(async (config) => {
            config.headers = config.headers || {};
            config.headers['X-Request-ID'] = str.uuid();
            return config;
        });

        // Response: Handle common errors
        this.responseInterceptors.use(
            (response) => response,
            async (error) => {
                // Handle 401 - Unauthorized
                if (error.status === 401) {
                    const refreshed = await auth.refreshToken();
                    if (refreshed && error.config) {
                        // Retry original request
                        return this.request(error.config);
                    }
                    auth.logout();
                }
                throw error;
            }
        );
    }

    /**
     * Build full URL
     */
    _buildURL(url, params = {}) {
        // Handle absolute URLs
        if (url.startsWith('http://') || url.startsWith('https://')) {
            return url;
        }

        let fullURL = this.config.baseURL + url;

        // Add query params
        if (Object.keys(params).length > 0) {
            const searchParams = new URLSearchParams();
            Object.entries(params).forEach(([key, value]) => {
                if (value !== null && value !== undefined) {
                    if (Array.isArray(value)) {
                        value.forEach(v => searchParams.append(key, v));
                    } else {
                        searchParams.append(key, value);
                    }
                }
            });
            fullURL += '?' + searchParams.toString();
        }

        return fullURL;
    }

    /**
     * Make HTTP request
     */
    async request(config) {
        // Merge with defaults
        config = {
            method: 'GET',
            headers: { ...this.config.headers },
            timeout: this.config.timeout,
            retries: this.config.retries,
            cache: false,
            ...config
        };

        // Run request interceptors
        config = await this.requestInterceptors.execute(config);

        // Check cache for GET requests
        if (config.method === 'GET' && config.cache) {
            const cacheKey = this.cache.key(config.url, config);
            const cached = this.cache.get(cacheKey);
            if (cached) {
                return cached;
            }
        }

        // Build URL
        const url = this._buildURL(config.url, config.params);

        // Create abort controller
        const requestId = config.headers['X-Request-ID'] || str.uuid();
        const abortController = new AbortController();
        this.abortControllers.set(requestId, abortController);

        // Setup timeout
        const timeoutId = setTimeout(() => {
            abortController.abort();
        }, config.timeout);

        // Prepare fetch options
        const fetchOptions = {
            method: config.method,
            headers: config.headers,
            signal: abortController.signal
        };

        // Add body for non-GET requests
        if (config.body && config.method !== 'GET') {
            if (config.body instanceof FormData) {
                delete fetchOptions.headers['Content-Type'];
                fetchOptions.body = config.body;
            } else if (typeof config.body === 'object') {
                fetchOptions.body = JSON.stringify(config.body);
            } else {
                fetchOptions.body = config.body;
            }
        }

        // Execute request with retries
        let lastError;
        let attempt = 0;

        while (attempt <= config.retries) {
            try {
                const response = await fetch(url, fetchOptions);
                clearTimeout(timeoutId);
                this.abortControllers.delete(requestId);

                // Parse response
                const result = await this._parseResponse(response, config);

                // Run response interceptors
                const finalResult = await this.responseInterceptors.execute(result);

                // Cache successful GET responses
                if (config.method === 'GET' && config.cache && response.ok) {
                    const cacheKey = this.cache.key(config.url, config);
                    const ttl = typeof config.cache === 'number' ? config.cache : undefined;
                    this.cache.set(cacheKey, finalResult, ttl);
                }

                return finalResult;
            } catch (error) {
                lastError = error;

                // Don't retry on certain errors
                if (
                    error.name === 'AbortError' ||
                    error.status === 401 ||
                    error.status === 403 ||
                    error.status === 422
                ) {
                    break;
                }

                attempt++;
                if (attempt <= config.retries) {
                    await this._delay(this.config.retryDelay * attempt);
                }
            }
        }

        clearTimeout(timeoutId);
        this.abortControllers.delete(requestId);

        // Handle abort error
        if (lastError?.name === 'AbortError') {
            throw new APIError(
                'Request timeout',
                API_ERRORS.TIMEOUT,
                0
            );
        }

        throw lastError;
    }

    /**
     * Parse response
     */
    async _parseResponse(response, config) {
        let data = null;

        // Parse body
        const contentType = response.headers.get('content-type') || '';
        
        if (contentType.includes('application/json')) {
            try {
                data = await response.json();
            } catch {
                data = null;
            }
        } else if (contentType.includes('text/')) {
            data = await response.text();
        } else if (config.responseType === 'blob') {
            data = await response.blob();
        } else if (config.responseType === 'arraybuffer') {
            data = await response.arrayBuffer();
        } else {
            try {
                data = await response.json();
            } catch {
                data = await response.text();
            }
        }

        // Handle errors
        if (!response.ok) {
            const message = data?.message || data?.error || response.statusText || 'Request failed';
            const code = this._getErrorCode(response.status);
            
            const error = new APIError(message, code, response.status, data);
            error.config = config;
            
            throw await this.responseInterceptors.execute(error, 'rejected');
        }

        return data;
    }

    /**
     * Get error code from status
     */
    _getErrorCode(status) {
        switch (status) {
            case 401: return API_ERRORS.UNAUTHORIZED;
            case 403: return API_ERRORS.FORBIDDEN;
            case 404: return API_ERRORS.NOT_FOUND;
            case 422: return API_ERRORS.VALIDATION_ERROR;
            case 429: return API_ERRORS.RATE_LIMITED;
            default:
                if (status >= 500) return API_ERRORS.SERVER_ERROR;
                return API_ERRORS.UNKNOWN;
        }
    }

    /**
     * Delay helper
     */
    _delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Abort request by ID
     */
    abort(requestId) {
        const controller = this.abortControllers.get(requestId);
        if (controller) {
            controller.abort();
            this.abortControllers.delete(requestId);
        }
    }

    /**
     * Abort all requests
     */
    abortAll() {
        this.abortControllers.forEach(controller => controller.abort());
        this.abortControllers.clear();
    }

    // ========================================================================
    // HTTP METHOD SHORTCUTS
    // ========================================================================

    /**
     * GET request
     */
    get(url, params = {}, config = {}) {
        return this.request({ ...config, method: 'GET', url, params });
    }

    /**
     * POST request
     */
    post(url, body = {}, config = {}) {
        return this.request({ ...config, method: 'POST', url, body });
    }

    /**
     * PUT request
     */
    put(url, body = {}, config = {}) {
        return this.request({ ...config, method: 'PUT', url, body });
    }

    /**
     * PATCH request
     */
    patch(url, body = {}, config = {}) {
        return this.request({ ...config, method: 'PATCH', url, body });
    }

    /**
     * DELETE request
     */
    delete(url, config = {}) {
        return this.request({ ...config, method: 'DELETE', url });
    }

    /**
     * Upload file(s)
     */
    upload(url, files, data = {}, config = {}) {
        const formData = new FormData();

        // Add files
        if (files instanceof FileList) {
            Array.from(files).forEach((file, index) => {
                formData.append(`files[${index}]`, file);
            });
        } else if (files instanceof File) {
            formData.append('file', files);
        } else if (typeof files === 'object') {
            Object.entries(files).forEach(([key, file]) => {
                formData.append(key, file);
            });
        }

        // Add additional data
        Object.entries(data).forEach(([key, value]) => {
            formData.append(key, typeof value === 'object' ? JSON.stringify(value) : value);
        });

        return this.request({
            ...config,
            method: 'POST',
            url,
            body: formData
        });
    }

    /**
     * Download file
     */
    async download(url, filename, config = {}) {
        const response = await this.request({
            ...config,
            method: 'GET',
            url,
            responseType: 'blob'
        });

        // Create download link
        const blob = response instanceof Blob ? response : new Blob([response]);
        const downloadUrl = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = downloadUrl;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(downloadUrl);

        return true;
    }
}

// ============================================================================
// AUTH MANAGER
// ============================================================================

const auth = {
    _token: null,
    _refreshToken: null,
    _user: null,
    _tokenKey: 'auth_token',
    _refreshTokenKey: 'auth_refresh_token',
    _userKey: 'auth_user',
    _refreshPromise: null,

    /**
     * Initialize auth from storage
     */
    init() {
        this._token = storage.get(this._tokenKey);
        this._refreshToken = storage.get(this._refreshTokenKey);
        this._user = storage.get(this._userKey);
        return this;
    },

    /**
     * Login
     */
    async login(credentials) {
        const response = await http.post('/auth/login', credentials);
        
        if (response.token) {
            this.setToken(response.token, response.refresh_token);
            this.setUser(response.user);
        }

        return response;
    },

    /**
     * Login with 2FA
     */
    async loginWith2FA(credentials, code) {
        const response = await http.post('/auth/login/2fa', {
            ...credentials,
            code
        });
        
        if (response.token) {
            this.setToken(response.token, response.refresh_token);
            this.setUser(response.user);
        }

        return response;
    },

    /**
     * Logout
     */
    async logout(callAPI = true) {
        if (callAPI && this._token) {
            try {
                await http.post('/auth/logout');
            } catch (e) {
                // Ignore logout API errors
            }
        }

        this.clearAuth();
        
        // Trigger logout event
        events.trigger(document, 'auth:logout');
        
        // Redirect to login
        if (typeof router !== 'undefined') {
            router.push('/login');
        } else {
            window.location.href = '/login.html';
        }
    },

    /**
     * Register
     */
    async register(userData) {
        const response = await http.post('/auth/register', userData);
        
        if (response.token) {
            this.setToken(response.token, response.refresh_token);
            this.setUser(response.user);
        }

        return response;
    },

    /**
     * Refresh token
     */
    async refreshToken() {
        // Prevent multiple simultaneous refresh requests
        if (this._refreshPromise) {
            return this._refreshPromise;
        }

        if (!this._refreshToken) {
            return false;
        }

        this._refreshPromise = (async () => {
            try {
                const response = await http.post('/auth/refresh', {
                    refresh_token: this._refreshToken
                });

                if (response.token) {
                    this.setToken(response.token, response.refresh_token);
                    return true;
                }
                return false;
            } catch (error) {
                this.clearAuth();
                return false;
            } finally {
                this._refreshPromise = null;
            }
        })();

        return this._refreshPromise;
    },

    /**
     * Set tokens
     */
    setToken(token, refreshToken = null) {
        this._token = token;
        storage.set(this._tokenKey, token);

        if (refreshToken) {
            this._refreshToken = refreshToken;
            storage.set(this._refreshTokenKey, refreshToken);
        }
    },

    /**
     * Get token
     */
    getToken() {
        return this._token;
    },

    /**
     * Set user
     */
    setUser(user) {
        this._user = user;
        storage.set(this._userKey, user);
        events.trigger(document, 'auth:user', { user });
    },

    /**
     * Get user
     */
    getUser() {
        return this._user;
    },

    /**
     * Update user data
     */
    updateUser(data) {
        this._user = { ...this._user, ...data };
        storage.set(this._userKey, this._user);
        events.trigger(document, 'auth:user', { user: this._user });
    },

    /**
     * Check if authenticated
     */
    isAuthenticated() {
        return !!this._token;
    },

    /**
     * Check if user is admin
     */
    isAdmin() {
        return this._user?.role === 'admin' || this._user?.role === 'owner';
    },

    /**
     * Check if user is owner
     */
    isOwner() {
        return this._user?.role === 'owner';
    },

    /**
     * Check if user is reseller
     */
    isReseller() {
        return this._user?.role === 'reseller';
    },

    /**
     * Check permission
     */
    can(permission) {
        if (!this._user) return false;
        if (this.isOwner()) return true;
        return this._user.permissions?.includes(permission);
    },

    /**
     * Clear auth data
     */
    clearAuth() {
        this._token = null;
        this._refreshToken = null;
        this._user = null;
        storage.remove(this._tokenKey);
        storage.remove(this._refreshTokenKey);
        storage.remove(this._userKey);
    },

    /**
     * Get auth headers
     */
    getHeaders() {
        if (!this._token) return {};
        return { 'Authorization': `Bearer ${this._token}` };
    },

    /**
     * Request password reset
     */
    async forgotPassword(email) {
        return http.post('/auth/forgot-password', { email });
    },

    /**
     * Reset password
     */
    async resetPassword(token, password, passwordConfirmation) {
        return http.post('/auth/reset-password', {
            token,
            password,
            password_confirmation: passwordConfirmation
        });
    },

    /**
     * Change password
     */
    async changePassword(currentPassword, newPassword, confirmPassword) {
        return http.post('/auth/change-password', {
            current_password: currentPassword,
            new_password: newPassword,
            confirm_password: confirmPassword
        });
    },

    /**
     * Enable 2FA
     */
    async enable2FA() {
        return http.post('/auth/2fa/enable');
    },

    /**
     * Confirm 2FA
     */
    async confirm2FA(code) {
        return http.post('/auth/2fa/confirm', { code });
    },

    /**
     * Disable 2FA
     */
    async disable2FA(code) {
        return http.post('/auth/2fa/disable', { code });
    },

    /**
     * Get 2FA backup codes
     */
    async get2FABackupCodes() {
        return http.get('/auth/2fa/backup-codes');
    },

    /**
     * Regenerate 2FA backup codes
     */
    async regenerate2FABackupCodes() {
        return http.post('/auth/2fa/backup-codes/regenerate');
    },

    /**
     * Verify email
     */
    async verifyEmail(token) {
        return http.post('/auth/verify-email', { token });
    },

    /**
     * Resend verification email
     */
    async resendVerification() {
        return http.post('/auth/resend-verification');
    },

    /**
     * Get active sessions
     */
    async getSessions() {
        return http.get('/auth/sessions');
    },

    /**
     * Revoke session
     */
    async revokeSession(sessionId) {
        return http.delete(`/auth/sessions/${sessionId}`);
    },

    /**
     * Revoke all other sessions
     */
    async revokeOtherSessions() {
        return http.post('/auth/sessions/revoke-others');
    },

    /**
     * Parse JWT token
     */
    parseToken(token = null) {
        const t = token || this._token;
        if (!t) return null;

        try {
            const base64Url = t.split('.')[1];
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const jsonPayload = decodeURIComponent(
                atob(base64).split('').map(c => 
                    '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
                ).join('')
            );
            return JSON.parse(jsonPayload);
        } catch {
            return null;
        }
    },

    /**
     * Check if token is expired
     */
    isTokenExpired(token = null) {
        const payload = this.parseToken(token);
        if (!payload || !payload.exp) return true;
        return Date.now() >= payload.exp * 1000;
    },

    /**
     * Get token expiry time
     */
    getTokenExpiry(token = null) {
        const payload = this.parseToken(token);
        if (!payload || !payload.exp) return null;
        return new Date(payload.exp * 1000);
    }
};

// ============================================================================
// CREATE HTTP CLIENT INSTANCE
// ============================================================================

const http = new HttpClient();

// Initialize auth
auth.init();

// ============================================================================
// API RESPONSE HELPERS
// ============================================================================

const apiHelpers = {
    /**
     * Handle API response
     */
    async handle(promise, options = {}) {
        const {
            loading: loadingMessage = null,
            success: successMessage = null,
            error: errorMessage = null,
            throwError = false
        } = options;

        if (loadingMessage) {
            loading.show(loadingMessage);
        }

        try {
            const response = await promise;

            if (successMessage) {
                notify.success(successMessage);
            }

            return { success: true, data: response, error: null };
        } catch (error) {
            const message = errorMessage || error.message || 'An error occurred';
            
            notify.error(message);

            if (throwError) {
                throw error;
            }

            return { success: false, data: null, error };
        } finally {
            if (loadingMessage) {
                loading.hide();
            }
        }
    },

    /**
     * Paginate response
     */
    paginate(response) {
        return {
            data: response.data || [],
            total: response.total || 0,
            page: response.page || 1,
            perPage: response.per_page || 10,
            lastPage: response.last_page || 1,
            from: response.from || 0,
            to: response.to || 0,
            hasMore: response.page < response.last_page
        };
    },

    /**
     * Build query params for list endpoints
     */
    buildListParams(options = {}) {
        const {
            page = 1,
            perPage = 10,
            search = '',
            sort = '',
            order = 'asc',
            filters = {}
        } = options;

        const params = {
            page,
            per_page: perPage
        };

        if (search) {
            params.search = search;
        }

        if (sort) {
            params.sort = sort;
            params.order = order;
        }

        // Add filters
        Object.entries(filters).forEach(([key, value]) => {
            if (value !== null && value !== undefined && value !== '') {
                params[`filter[${key}]`] = value;
            }
        });

        return params;
    }
};

// ============================================================================
// EXPORT
// ============================================================================

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        API_CONFIG,
        API_ERRORS,
        APIError,
        HttpClient,
        http,
        auth,
        apiHelpers,
        RequestCache,
        RequestQueue
    };
}

// Global export
Object.assign(window, {
    API_CONFIG,
    API_ERRORS,
    APIError,
    HttpClient,
    http,
    auth,
    apiHelpers
});
/**
 * ============================================================================
 * MX-UI VPN Panel - API Client
 * Part 2: Users, Admins, Nodes, Core, Inbounds, Settings APIs
 * ============================================================================
 */

// ============================================================================
// USERS API
// ============================================================================

const usersAPI = {
    /**
     * Get all users (with pagination)
     */
    async list(options = {}) {
        const params = apiHelpers.buildListParams(options);
        const response = await http.get('/users', params);
        return apiHelpers.paginate(response);
    },

    /**
     * Get single user
     */
    async get(userId) {
        return http.get(`/users/${userId}`);
    },

    /**
     * Get user by username
     */
    async getByUsername(username) {
        return http.get(`/users/username/${username}`);
    },

    /**
     * Create user
     */
    async create(userData) {
        return http.post('/users', userData);
    },

    /**
     * Update user
     */
    async update(userId, userData) {
        return http.put(`/users/${userId}`, userData);
    },

    /**
     * Delete user
     */
    async delete(userId) {
        return http.delete(`/users/${userId}`);
    },

    /**
     * Bulk delete users
     */
    async bulkDelete(userIds) {
        return http.post('/users/bulk-delete', { ids: userIds });
    },

    /**
     * Reset user traffic
     */
    async resetTraffic(userId) {
        return http.post(`/users/${userId}/reset-traffic`);
    },

    /**
     * Bulk reset traffic
     */
    async bulkResetTraffic(userIds) {
        return http.post('/users/bulk-reset-traffic', { ids: userIds });
    },

    /**
     * Enable user
     */
    async enable(userId) {
        return http.post(`/users/${userId}/enable`);
    },

    /**
     * Disable user
     */
    async disable(userId) {
        return http.post(`/users/${userId}/disable`);
    },

    /**
     * Bulk enable users
     */
    async bulkEnable(userIds) {
        return http.post('/users/bulk-enable', { ids: userIds });
    },

    /**
     * Bulk disable users
     */
    async bulkDisable(userIds) {
        return http.post('/users/bulk-disable', { ids: userIds });
    },

    /**
     * Extend user subscription
     */
    async extend(userId, days) {
        return http.post(`/users/${userId}/extend`, { days });
    },

    /**
     * Bulk extend subscriptions
     */
    async bulkExtend(userIds, days) {
        return http.post('/users/bulk-extend', { ids: userIds, days });
    },

    /**
     * Set user on hold
     */
    async setOnHold(userId, onHold = true) {
        return http.post(`/users/${userId}/on-hold`, { on_hold: onHold });
    },

    /**
     * Get user subscription link
     */
    async getSubscriptionLink(userId) {
        return http.get(`/users/${userId}/subscription`);
    },

    /**
     * Regenerate user subscription link
     */
    async regenerateSubscription(userId) {
        return http.post(`/users/${userId}/subscription/regenerate`);
    },

    /**
     * Get user QR code
     */
    async getQRCode(userId, format = 'png') {
        return http.get(`/users/${userId}/qr`, { format });
    },

    /**
     * Get user configs/links
     */
    async getConfigs(userId) {
        return http.get(`/users/${userId}/configs`);
    },

    /**
     * Get user traffic statistics
     */
    async getTrafficStats(userId, period = '7d') {
        return http.get(`/users/${userId}/traffic`, { period });
    },

    /**
     * Get user connection logs
     */
    async getConnectionLogs(userId, options = {}) {
        const params = apiHelpers.buildListParams(options);
        return http.get(`/users/${userId}/connections`, params);
    },

    /**
     * Get user online IPs
     */
    async getOnlineIPs(userId) {
        return http.get(`/users/${userId}/online-ips`);
    },

    /**
     * Kick user (disconnect all connections)
     */
    async kick(userId) {
        return http.post(`/users/${userId}/kick`);
    },

    /**
     * Get all online users
     */
    async getOnlineUsers() {
        return http.get('/users/online');
    },

    /**
     * Get users statistics
     */
    async getStats() {
        return http.get('/users/stats');
    },

    /**
     * Get expired users
     */
    async getExpired(options = {}) {
        const params = apiHelpers.buildListParams(options);
        return http.get('/users/expired', params);
    },

    /**
     * Get expiring soon users
     */
    async getExpiringSoon(days = 7, options = {}) {
        const params = { ...apiHelpers.buildListParams(options), days };
        return http.get('/users/expiring-soon', params);
    },

    /**
     * Get limited traffic users
     */
    async getLimitedTraffic(options = {}) {
        const params = apiHelpers.buildListParams(options);
        return http.get('/users/limited-traffic', params);
    },

    /**
     * Import users from file
     */
    async import(file, options = {}) {
        return http.upload('/users/import', file, options);
    },

    /**
     * Export users
     */
    async export(format = 'csv', filters = {}) {
        return http.download('/users/export', `users.${format}`, {
            params: { format, ...filters }
        });
    },

    /**
     * Get user templates
     */
    async getTemplates() {
        return http.get('/users/templates');
    },

    /**
     * Create user from template
     */
    async createFromTemplate(templateId, userData) {
        return http.post(`/users/templates/${templateId}/create`, userData);
    },

    /**
     * Generate trial user
     */
    async generateTrial(options = {}) {
        return http.post('/users/trial', options);
    },

    /**
     * Revoke user
     */
    async revoke(userId) {
        return http.post(`/users/${userId}/revoke`);
    },

    /**
     * Add note to user
     */
    async addNote(userId, note) {
        return http.post(`/users/${userId}/notes`, { note });
    },

    /**
     * Get user notes
     */
    async getNotes(userId) {
        return http.get(`/users/${userId}/notes`);
    },

    /**
     * Add tag to user
     */
    async addTag(userId, tag) {
        return http.post(`/users/${userId}/tags`, { tag });
    },

    /**
     * Remove tag from user
     */
    async removeTag(userId, tag) {
        return http.delete(`/users/${userId}/tags/${tag}`);
    },

    /**
     * Set user inbounds
     */
    async setInbounds(userId, inboundIds) {
        return http.put(`/users/${userId}/inbounds`, { inbound_ids: inboundIds });
    }
};

// ============================================================================
// ADMINS API
// ============================================================================

const adminsAPI = {
    /**
     * Get all admins
     */
    async list(options = {}) {
        const params = apiHelpers.buildListParams(options);
        const response = await http.get('/admins', params);
        return apiHelpers.paginate(response);
    },

    /**
     * Get single admin
     */
    async get(adminId) {
        return http.get(`/admins/${adminId}`);
    },

    /**
     * Get current admin
     */
    async me() {
        return http.get('/admins/me');
    },

    /**
     * Create admin
     */
    async create(adminData) {
        return http.post('/admins', adminData);
    },

    /**
     * Update admin
     */
    async update(adminId, adminData) {
        return http.put(`/admins/${adminId}`, adminData);
    },

    /**
     * Update current admin profile
     */
    async updateProfile(profileData) {
        return http.put('/admins/me', profileData);
    },

    /**
     * Delete admin
     */
    async delete(adminId) {
        return http.delete(`/admins/${adminId}`);
    },

    /**
     * Enable admin
     */
    async enable(adminId) {
        return http.post(`/admins/${adminId}/enable`);
    },

    /**
     * Disable admin
     */
    async disable(adminId) {
        return http.post(`/admins/${adminId}/disable`);
    },

    /**
     * Reset admin traffic
     */
    async resetTraffic(adminId) {
        return http.post(`/admins/${adminId}/reset-traffic`);
    },

    /**
     * Get admin statistics
     */
    async getStats(adminId) {
        return http.get(`/admins/${adminId}/stats`);
    },

    /**
     * Get admin users
     */
    async getUsers(adminId, options = {}) {
        const params = apiHelpers.buildListParams(options);
        return http.get(`/admins/${adminId}/users`, params);
    },

    /**
     * Get admin traffic stats
     */
    async getTrafficStats(adminId, period = '30d') {
        return http.get(`/admins/${adminId}/traffic`, { period });
    },

    /**
     * Get admin audit logs
     */
    async getAuditLogs(adminId, options = {}) {
        const params = apiHelpers.buildListParams(options);
        return http.get(`/admins/${adminId}/audit-logs`, params);
    },

    /**
     * Switch to admin (owner only)
     */
    async switchTo(adminId) {
        return http.post(`/admins/${adminId}/switch`);
    },

    /**
     * Switch back to owner
     */
    async switchBack() {
        return http.post('/admins/switch-back');
    },

    /**
     * Get all admin roles
     */
    async getRoles() {
        return http.get('/admins/roles');
    },

    /**
     * Get admin permissions
     */
    async getPermissions() {
        return http.get('/admins/permissions');
    },

    /**
     * Set admin permissions
     */
    async setPermissions(adminId, permissions) {
        return http.put(`/admins/${adminId}/permissions`, { permissions });
    },

    /**
     * Set admin traffic limit
     */
    async setTrafficLimit(adminId, limit) {
        return http.put(`/admins/${adminId}/traffic-limit`, { limit });
    },

    /**
     * Set admin user limit
     */
    async setUserLimit(adminId, limit) {
        return http.put(`/admins/${adminId}/user-limit`, { limit });
    },

    /**
     * Get reseller pricing
     */
    async getPricing(adminId) {
        return http.get(`/admins/${adminId}/pricing`);
    },

    /**
     * Set reseller pricing
     */
    async setPricing(adminId, pricing) {
        return http.put(`/admins/${adminId}/pricing`, pricing);
    }
};

// ============================================================================
// NODES API
// ============================================================================

const nodesAPI = {
    /**
     * Get all nodes
     */
    async list(options = {}) {
        const params = apiHelpers.buildListParams(options);
        const response = await http.get('/nodes', params);
        return apiHelpers.paginate(response);
    },

    /**
     * Get single node
     */
    async get(nodeId) {
        return http.get(`/nodes/${nodeId}`);
    },

    /**
     * Create node
     */
    async create(nodeData) {
        return http.post('/nodes', nodeData);
    },

    /**
     * Update node
     */
    async update(nodeId, nodeData) {
        return http.put(`/nodes/${nodeId}`, nodeData);
    },

    /**
     * Delete node
     */
    async delete(nodeId) {
        return http.delete(`/nodes/${nodeId}`);
    },

    /**
     * Enable node
     */
    async enable(nodeId) {
        return http.post(`/nodes/${nodeId}/enable`);
    },

    /**
     * Disable node
     */
    async disable(nodeId) {
        return http.post(`/nodes/${nodeId}/disable`);
    },

    /**
     * Get node status
     */
    async getStatus(nodeId) {
        return http.get(`/nodes/${nodeId}/status`);
    },

    /**
     * Get all nodes status
     */
    async getAllStatus() {
        return http.get('/nodes/status');
    },

    /**
     * Check node health
     */
    async healthCheck(nodeId) {
        return http.post(`/nodes/${nodeId}/health-check`);
    },

    /**
     * Check all nodes health
     */
    async healthCheckAll() {
        return http.post('/nodes/health-check');
    },

    /**
     * Sync node
     */
    async sync(nodeId) {
        return http.post(`/nodes/${nodeId}/sync`);
    },

    /**
     * Sync all nodes
     */
    async syncAll() {
        return http.post('/nodes/sync');
    },

    /**
     * Restart node core
     */
    async restart(nodeId) {
        return http.post(`/nodes/${nodeId}/restart`);
    },

    /**
     * Get node metrics
     */
    async getMetrics(nodeId, period = '1h') {
        return http.get(`/nodes/${nodeId}/metrics`, { period });
    },

    /**
     * Get node traffic stats
     */
    async getTrafficStats(nodeId, period = '24h') {
        return http.get(`/nodes/${nodeId}/traffic`, { period });
    },

    /**
     * Get node logs
     */
    async getLogs(nodeId, options = {}) {
        const params = apiHelpers.buildListParams(options);
        return http.get(`/nodes/${nodeId}/logs`, params);
    },

    /**
     * Get node connected users
     */
    async getConnectedUsers(nodeId) {
        return http.get(`/nodes/${nodeId}/users`);
    },

    /**
     * Get node config
     */
    async getConfig(nodeId) {
        return http.get(`/nodes/${nodeId}/config`);
    },

    /**
     * Update node config
     */
    async updateConfig(nodeId, config) {
        return http.put(`/nodes/${nodeId}/config`, config);
    },

    /**
     * Get node connection command
     */
    async getConnectionCommand(nodeId) {
        return http.get(`/nodes/${nodeId}/connection-command`);
    },

    /**
     * Regenerate node API key
     */
    async regenerateApiKey(nodeId) {
        return http.post(`/nodes/${nodeId}/regenerate-key`);
    },

    /**
     * Test node connection
     */
    async testConnection(nodeData) {
        return http.post('/nodes/test-connection', nodeData);
    },

    /**
     * Get node certificate
     */
    async getCertificate(nodeId) {
        return http.get(`/nodes/${nodeId}/certificate`);
    },

    /**
     * Update node certificate
     */
    async updateCertificate(nodeId, certData) {
        return http.put(`/nodes/${nodeId}/certificate`, certData);
    },

    /**
     * Set node weight (for load balancing)
     */
    async setWeight(nodeId, weight) {
        return http.put(`/nodes/${nodeId}/weight`, { weight });
    },

    /**
     * Get load balancing stats
     */
    async getLoadBalancingStats() {
        return http.get('/nodes/load-balancing');
    }
};

// ============================================================================
// INBOUNDS API
// ============================================================================

const inboundsAPI = {
    /**
     * Get all inbounds
     */
    async list() {
        return http.get('/inbounds');
    },

    /**
     * Get single inbound
     */
    async get(inboundId) {
        return http.get(`/inbounds/${inboundId}`);
    },

    /**
     * Create inbound
     */
    async create(inboundData) {
        return http.post('/inbounds', inboundData);
    },

    /**
     * Update inbound
     */
    async update(inboundId, inboundData) {
        return http.put(`/inbounds/${inboundId}`, inboundData);
    },

    /**
     * Delete inbound
     */
    async delete(inboundId) {
        return http.delete(`/inbounds/${inboundId}`);
    },

    /**
     * Enable inbound
     */
    async enable(inboundId) {
        return http.post(`/inbounds/${inboundId}/enable`);
    },

    /**
     * Disable inbound
     */
    async disable(inboundId) {
        return http.post(`/inbounds/${inboundId}/disable`);
    },

    /**
     * Get inbound users
     */
    async getUsers(inboundId) {
        return http.get(`/inbounds/${inboundId}/users`);
    },

    /**
     * Get inbound traffic stats
     */
    async getTrafficStats(inboundId, period = '24h') {
        return http.get(`/inbounds/${inboundId}/traffic`, { period });
    },

    /**
     * Get available protocols
     */
    async getProtocols() {
        return http.get('/inbounds/protocols');
    },

    /**
     * Get protocol settings schema
     */
    async getProtocolSchema(protocol) {
        return http.get(`/inbounds/protocols/${protocol}/schema`);
    },

    /**
     * Validate inbound config
     */
    async validate(inboundData) {
        return http.post('/inbounds/validate', inboundData);
    },

    /**
     * Get inbound template
     */
    async getTemplate(protocol) {
        return http.get(`/inbounds/templates/${protocol}`);
    },

    /**
     * Duplicate inbound
     */
    async duplicate(inboundId) {
        return http.post(`/inbounds/${inboundId}/duplicate`);
    }
};

// ============================================================================
// OUTBOUNDS API
// ============================================================================

const outboundsAPI = {
    /**
     * Get all outbounds
     */
    async list() {
        return http.get('/outbounds');
    },

    /**
     * Get single outbound
     */
    async get(outboundId) {
        return http.get(`/outbounds/${outboundId}`);
    },

    /**
     * Create outbound
     */
    async create(outboundData) {
        return http.post('/outbounds', outboundData);
    },

    /**
     * Update outbound
     */
    async update(outboundId, outboundData) {
        return http.put(`/outbounds/${outboundId}`, outboundData);
    },

    /**
     * Delete outbound
     */
    async delete(outboundId) {
        return http.delete(`/outbounds/${outboundId}`);
    },

    /**
     * Enable outbound
     */
    async enable(outboundId) {
        return http.post(`/outbounds/${outboundId}/enable`);
    },

    /**
     * Disable outbound
     */
    async disable(outboundId) {
        return http.post(`/outbounds/${outboundId}/disable`);
    },

    /**
     * Test outbound connection
     */
    async test(outboundId) {
        return http.post(`/outbounds/${outboundId}/test`);
    },

    /**
     * Get outbound latency
     */
    async getLatency(outboundId) {
        return http.get(`/outbounds/${outboundId}/latency`);
    }
};

// ============================================================================
// ROUTING API
// ============================================================================

const routingAPI = {
    /**
     * Get routing rules
     */
    async getRules() {
        return http.get('/routing/rules');
    },

    /**
     * Update routing rules
     */
    async updateRules(rules) {
        return http.put('/routing/rules', { rules });
    },

    /**
     * Add routing rule
     */
    async addRule(rule) {
        return http.post('/routing/rules', rule);
    },

    /**
     * Delete routing rule
     */
    async deleteRule(ruleId) {
        return http.delete(`/routing/rules/${ruleId}`);
    },

    /**
     * Get DNS settings
     */
    async getDNS() {
        return http.get('/routing/dns');
    },

    /**
     * Update DNS settings
     */
    async updateDNS(dnsSettings) {
        return http.put('/routing/dns', dnsSettings);
    },

    /**
     * Get geo files
     */
    async getGeoFiles() {
        return http.get('/routing/geofiles');
    },

    /**
     * Update geo files
     */
    async updateGeoFiles() {
        return http.post('/routing/geofiles/update');
    },

    /**
     * Get blocked hosts
     */
    async getBlockedHosts() {
        return http.get('/routing/blocked-hosts');
    },

    /**
     * Update blocked hosts
     */
    async updateBlockedHosts(hosts) {
        return http.put('/routing/blocked-hosts', { hosts });
    },

    /**
     * Get direct routes
     */
    async getDirectRoutes() {
        return http.get('/routing/direct-routes');
    },

    /**
     * Update direct routes
     */
    async updateDirectRoutes(routes) {
        return http.put('/routing/direct-routes', { routes });
    },

    /**
     * Get WARP settings
     */
    async getWarpSettings() {
        return http.get('/routing/warp');
    },

    /**
     * Update WARP settings
     */
    async updateWarpSettings(settings) {
        return http.put('/routing/warp', settings);
    },

    /**
     * Get WARP status
     */
    async getWarpStatus() {
        return http.get('/routing/warp/status');
    },

    /**
     * Connect WARP
     */
    async connectWarp() {
        return http.post('/routing/warp/connect');
    },

    /**
     * Disconnect WARP
     */
    async disconnectWarp() {
        return http.post('/routing/warp/disconnect');
    },

    /**
     * Register WARP
     */
    async registerWarp(licenseKey = null) {
        return http.post('/routing/warp/register', { license_key: licenseKey });
    }
};

// ============================================================================
// CORE API
// ============================================================================

const coreAPI = {
    /**
     * Get core status
     */
    async getStatus() {
        return http.get('/core/status');
    },

    /**
     * Start core
     */
    async start() {
        return http.post('/core/start');
    },

    /**
     * Stop core
     */
    async stop() {
        return http.post('/core/stop');
    },

    /**
     * Restart core
     */
    async restart() {
        return http.post('/core/restart');
    },

    /**
     * Get core version
     */
    async getVersion() {
        return http.get('/core/version');
    },

    /**
     * Check for core updates
     */
    async checkUpdate() {
        return http.get('/core/update/check');
    },

    /**
     * Update core
     */
    async update() {
        return http.post('/core/update');
    },

    /**
     * Get core config
     */
    async getConfig() {
        return http.get('/core/config');
    },

    /**
     * Update core config
     */
    async updateConfig(config) {
        return http.put('/core/config', config);
    },

    /**
     * Validate core config
     */
    async validateConfig(config) {
        return http.post('/core/config/validate', config);
    },

    /**
     * Get core logs
     */
    async getLogs(options = {}) {
        const { lines = 100, level = 'all' } = options;
        return http.get('/core/logs', { lines, level });
    },

    /**
     * Clear core logs
     */
    async clearLogs() {
        return http.delete('/core/logs');
    },

    /**
     * Get supported protocols
     */
    async getProtocols() {
        return http.get('/core/protocols');
    },

    /**
     * Get xray config
     */
    async getXrayConfig() {
        return http.get('/core/xray/config');
    },

    /**
     * Get sing-box config
     */
    async getSingboxConfig() {
        return http.get('/core/singbox/config');
    },

    /**
     * Get active core type
     */
    async getActiveCore() {
        return http.get('/core/active');
    },

    /**
     * Set active core type
     */
    async setActiveCore(coreType) {
        return http.post('/core/active', { core: coreType });
    },

    /**
     * Generate Reality keys
     */
    async generateRealityKeys() {
        return http.post('/core/reality/generate-keys');
    },

    /**
     * Test Reality config
     */
    async testReality(config) {
        return http.post('/core/reality/test', config);
    }
};

// ============================================================================
// SYSTEM API
// ============================================================================

const systemAPI = {
    /**
     * Get system info
     */
    async getInfo() {
        return http.get('/system/info');
    },

    /**
     * Get system stats
     */
    async getStats() {
        return http.get('/system/stats');
    },

    /**
     * Get real-time stats
     */
    async getRealTimeStats() {
        return http.get('/system/stats/realtime');
    },

    /**
     * Get CPU usage
     */
    async getCPU() {
        return http.get('/system/cpu');
    },

    /**
     * Get memory usage
     */
    async getMemory() {
        return http.get('/system/memory');
    },

    /**
     * Get disk usage
     */
    async getDisk() {
        return http.get('/system/disk');
    },

    /**
     * Get network stats
     */
    async getNetwork() {
        return http.get('/system/network');
    },

    /**
     * Get bandwidth usage
     */
    async getBandwidth(period = '24h') {
        return http.get('/system/bandwidth', { period });
    },

    /**
     * Get server IPs
     */
    async getIPs() {
        return http.get('/system/ips');
    },

    /**
     * Reboot server
     */
    async reboot() {
        return http.post('/system/reboot');
    },

    /**
     * Shutdown server
     */
    async shutdown() {
        return http.post('/system/shutdown');
    },

    /**
     * Get system logs
     */
    async getLogs(options = {}) {
        const params = apiHelpers.buildListParams(options);
        return http.get('/system/logs', params);
    },

    /**
     * Get system services status
     */
    async getServices() {
        return http.get('/system/services');
    },

    /**
     * Restart service
     */
    async restartService(serviceName) {
        return http.post(`/system/services/${serviceName}/restart`);
    },

    /**
     * Get SSL certificates
     */
    async getCertificates() {
        return http.get('/system/certificates');
    },

    /**
     * Generate SSL certificate
     */
    async generateCertificate(domain) {
        return http.post('/system/certificates/generate', { domain });
    },

    /**
     * Renew SSL certificate
     */
    async renewCertificate(domain) {
        return http.post('/system/certificates/renew', { domain });
    },

    /**
     * Upload SSL certificate
     */
    async uploadCertificate(certFile, keyFile, domain) {
        return http.upload('/system/certificates/upload', {
            cert: certFile,
            key: keyFile
        }, { domain });
    },

    /**
     * Get firewall rules
     */
    async getFirewallRules() {
        return http.get('/system/firewall');
    },

    /**
     * Update firewall rules
     */
    async updateFirewallRules(rules) {
        return http.put('/system/firewall', { rules });
    },

    /**
     * Run diagnostics
     */
    async runDiagnostics() {
        return http.post('/system/diagnostics');
    },

    /**
     * Get health report
     */
    async getHealthReport() {
        return http.get('/system/health');
    },

    /**
     * Auto-fix issues
     */
    async autoFix(issueId = null) {
        return http.post('/system/autofix', { issue_id: issueId });
    },

    /**
     * Get speed test result
     */
    async speedTest() {
        return http.post('/system/speedtest');
    },

    /**
     * Ping host
     */
    async ping(host) {
        return http.post('/system/ping', { host });
    },

    /**
     * Traceroute to host
     */
    async traceroute(host) {
        return http.post('/system/traceroute', { host });
    },

    /**
     * Get timezone
     */
    async getTimezone() {
        return http.get('/system/timezone');
    },

    /**
     * Set timezone
     */
    async setTimezone(timezone) {
        return http.put('/system/timezone', { timezone });
    }
};

// ============================================================================
// SETTINGS API
// ============================================================================

const settingsAPI = {
    /**
     * Get all settings
     */
    async getAll() {
        return http.get('/settings');
    },

    /**
     * Get setting by key
     */
    async get(key) {
        return http.get(`/settings/${key}`);
    },

    /**
     * Update setting
     */
    async set(key, value) {
        return http.put(`/settings/${key}`, { value });
    },

    /**
     * Update multiple settings
     */
    async setMultiple(settings) {
        return http.put('/settings', settings);
    },

    /**
     * Reset setting to default
     */
    async reset(key) {
        return http.delete(`/settings/${key}`);
    },

    /**
     * Reset all settings to default
     */
    async resetAll() {
        return http.post('/settings/reset');
    },

    /**
     * Get panel settings
     */
    async getPanelSettings() {
        return http.get('/settings/panel');
    },

    /**
     * Update panel settings
     */
    async updatePanelSettings(settings) {
        return http.put('/settings/panel', settings);
    },

    /**
     * Get subscription settings
     */
    async getSubscriptionSettings() {
        return http.get('/settings/subscription');
    },

    /**
     * Update subscription settings
     */
    async updateSubscriptionSettings(settings) {
        return http.put('/settings/subscription', settings);
    },

    /**
     * Get Telegram bot settings
     */
    async getTelegramSettings() {
        return http.get('/settings/telegram');
    },

    /**
     * Update Telegram bot settings
     */
    async updateTelegramSettings(settings) {
        return http.put('/settings/telegram', settings);
    },

    /**
     * Test Telegram bot
     */
    async testTelegram() {
        return http.post('/settings/telegram/test');
    },

    /**
     * Get notification settings
     */
    async getNotificationSettings() {
        return http.get('/settings/notifications');
    },

    /**
     * Update notification settings
     */
    async updateNotificationSettings(settings) {
        return http.put('/settings/notifications', settings);
    },

    /**
     * Get security settings
     */
    async getSecuritySettings() {
        return http.get('/settings/security');
    },

    /**
     * Update security settings
     */
    async updateSecuritySettings(settings) {
        return http.put('/settings/security', settings);
    },

    /**
     * Get AI settings
     */
    async getAISettings() {
        return http.get('/settings/ai');
    },

    /**
     * Update AI settings
     */
    async updateAISettings(settings) {
        return http.put('/settings/ai', settings);
    },

    /**
     * Test AI connection
     */
    async testAI() {
        return http.post('/settings/ai/test');
    }
};

// ============================================================================
// BACKUP API
// ============================================================================

const backupAPI = {
    /**
     * Get all backups
     */
    async list() {
        return http.get('/backups');
    },

    /**
     * Create backup
     */
    async create(options = {}) {
        return http.post('/backups', options);
    },

    /**
     * Restore backup
     */
    async restore(backupId) {
        return http.post(`/backups/${backupId}/restore`);
    },

    /**
     * Delete backup
     */
    async delete(backupId) {
        return http.delete(`/backups/${backupId}`);
    },

    /**
     * Download backup
     */
    async download(backupId) {
        return http.download(`/backups/${backupId}/download`, `backup-${backupId}.zip`);
    },

    /**
     * Upload backup
     */
    async upload(file) {
        return http.upload('/backups/upload', file);
    },

    /**
     * Get backup settings
     */
    async getSettings() {
        return http.get('/backups/settings');
    },

    /**
     * Update backup settings
     */
    async updateSettings(settings) {
        return http.put('/backups/settings', settings);
    },

    /**
     * Get scheduled backups
     */
    async getSchedule() {
        return http.get('/backups/schedule');
    },

    /**
     * Update backup schedule
     */
    async updateSchedule(schedule) {
        return http.put('/backups/schedule', schedule);
    },

    /**
     * Backup to Telegram
     */
    async backupToTelegram() {
        return http.post('/backups/telegram');
    },

    /**
     * Backup to cloud (Google Drive/S3)
     */
    async backupToCloud(provider) {
        return http.post('/backups/cloud', { provider });
    },

    /**
     * Get cloud backup settings
     */
    async getCloudSettings() {
        return http.get('/backups/cloud/settings');
    },

    /**
     * Update cloud backup settings
     */
    async updateCloudSettings(settings) {
        return http.put('/backups/cloud/settings', settings);
    }
};

// ============================================================================
// TEMPLATES API
// ============================================================================

const templatesAPI = {
    /**
     * Get subscription page template
     */
    async getSubscriptionTemplate() {
        return http.get('/templates/subscription');
    },

    /**
     * Update subscription page template
     */
    async updateSubscriptionTemplate(template) {
        return http.put('/templates/subscription', template);
    },

    /**
     * Preview subscription page
     */
    async previewSubscription(template) {
        return http.post('/templates/subscription/preview', template);
    },

    /**
     * Get admin page templates
     */
    async getAdminTemplates() {
        return http.get('/templates/admin');
    },

    /**
     * Update admin page template
     */
    async updateAdminTemplate(template) {
        return http.put('/templates/admin', template);
    },

    /**
     * Reset template to default
     */
    async resetTemplate(type) {
        return http.post(`/templates/${type}/reset`);
    },

    /**
     * Get available template variables
     */
    async getVariables(type) {
        return http.get(`/templates/${type}/variables`);
    }
};

// ============================================================================
// LOGS & AUDIT API
// ============================================================================

const logsAPI = {
    /**
     * Get audit logs
     */
    async getAuditLogs(options = {}) {
        const params = apiHelpers.buildListParams(options);
        const response = await http.get('/logs/audit', params);
        return apiHelpers.paginate(response);
    },

    /**
     * Get connection logs
     */
    async getConnectionLogs(options = {}) {
        const params = apiHelpers.buildListParams(options);
        const response = await http.get('/logs/connections', params);
        return apiHelpers.paginate(response);
    },

    /**
     * Get error logs
     */
    async getErrorLogs(options = {}) {
        const params = apiHelpers.buildListParams(options);
        return http.get('/logs/errors', params);
    },

    /**
     * Get access logs
     */
    async getAccessLogs(options = {}) {
        const params = apiHelpers.buildListParams(options);
        return http.get('/logs/access', params);
    },

    /**
     * Export logs
     */
    async export(type, format = 'csv', filters = {}) {
        return http.download(`/logs/${type}/export`, `${type}-logs.${format}`, {
            params: { format, ...filters }
        });
    },

    /**
     * Clear logs
     */
    async clear(type, olderThan = null) {
        return http.delete(`/logs/${type}`, {
            params: { older_than: olderThan }
        });
    },

    /**
     * Get log retention settings
     */
    async getRetentionSettings() {
        return http.get('/logs/retention');
    },

    /**
     * Update log retention settings
     */
    async updateRetentionSettings(settings) {
        return http.put('/logs/retention', settings);
    }
};

// ============================================================================
// ANALYTICS API
// ============================================================================

const analyticsAPI = {
    /**
     * Get dashboard stats
     */
    async getDashboardStats() {
        return http.get('/analytics/dashboard');
    },

    /**
     * Get traffic analytics
     */
    async getTrafficAnalytics(period = '7d') {
        return http.get('/analytics/traffic', { period });
    },

    /**
     * Get user analytics
     */
    async getUserAnalytics(period = '7d') {
        return http.get('/analytics/users', { period });
    },

    /**
     * Get protocol usage stats
     */
    async getProtocolStats(period = '7d') {
        return http.get('/analytics/protocols', { period });
    },

    /**
     * Get geographic distribution
     */
    async getGeoDistribution() {
        return http.get('/analytics/geo');
    },

    /**
     * Get top users by traffic
     */
    async getTopUsers(limit = 10, period = '7d') {
        return http.get('/analytics/top-users', { limit, period });
    },

    /**
     * Get connection statistics
     */
    async getConnectionStats(period = '24h') {
        return http.get('/analytics/connections', { period });
    },

    /**
     * Get revenue analytics (for resellers)
     */
    async getRevenueAnalytics(period = '30d') {
        return http.get('/analytics/revenue', { period });
    },

    /**
     * Get node performance analytics
     */
    async getNodeAnalytics(period = '24h') {
        return http.get('/analytics/nodes', { period });
    },

    /**
     * Export analytics report
     */
    async exportReport(type, period, format = 'pdf') {
        return http.download(`/analytics/${type}/export`, `${type}-report.${format}`, {
            params: { period, format }
        });
    }
};

// ============================================================================
// PAYMENT API
// ============================================================================

const paymentAPI = {
    /**
     * Get payment methods
     */
    async getMethods() {
        return http.get('/payments/methods');
    },

    /**
     * Get payment history
     */
    async getHistory(options = {}) {
        const params = apiHelpers.buildListParams(options);
        const response = await http.get('/payments/history', params);
        return apiHelpers.paginate(response);
    },

    /**
     * Create payment
     */
    async create(paymentData) {
        return http.post('/payments', paymentData);
    },

    /**
     * Verify payment
     */
    async verify(paymentId, data) {
        return http.post(`/payments/${paymentId}/verify`, data);
    },

    /**
     * Get payment details
     */
    async get(paymentId) {
        return http.get(`/payments/${paymentId}`);
    },

    /**
     * Refund payment
     */
    async refund(paymentId, reason = '') {
        return http.post(`/payments/${paymentId}/refund`, { reason });
    },

    /**
     * Get wallet balance
     */
    async getWalletBalance() {
        return http.get('/payments/wallet/balance');
    },

    /**
     * Add credit to wallet
     */
    async addCredit(amount, paymentMethod) {
        return http.post('/payments/wallet/credit', { amount, payment_method: paymentMethod });
    },

    /**
     * Get wallet transactions
     */
    async getWalletTransactions(options = {}) {
        const params = apiHelpers.buildListParams(options);
        return http.get('/payments/wallet/transactions', params);
    },

    /**
     * Get subscription plans
     */
    async getPlans() {
        return http.get('/payments/plans');
    },

    /**
     * Purchase plan
     */
    async purchasePlan(planId, paymentMethod) {
        return http.post('/payments/plans/purchase', {
            plan_id: planId,
            payment_method: paymentMethod
        });
    },

    /**
     * Get invoices
     */
    async getInvoices(options = {}) {
        const params = apiHelpers.buildListParams(options);
        return http.get('/payments/invoices', params);
    },

    /**
     * Download invoice
     */
    async downloadInvoice(invoiceId) {
        return http.download(`/payments/invoices/${invoiceId}/download`, `invoice-${invoiceId}.pdf`);
    }
};

// ============================================================================
// TELEGRAM BOT API
// ============================================================================

const telegramAPI = {
    /**
     * Get bot info
     */
    async getBotInfo() {
        return http.get('/telegram/bot');
    },

    /**
     * Set webhook
     */
    async setWebhook(url) {
        return http.post('/telegram/webhook', { url });
    },

    /**
     * Remove webhook
     */
    async removeWebhook() {
        return http.delete('/telegram/webhook');
    },

    /**
     * Get webhook info
     */
    async getWebhookInfo() {
        return http.get('/telegram/webhook');
    },

    /**
     * Send message
     */
    async sendMessage(chatId, text, options = {}) {
        return http.post('/telegram/send', { chat_id: chatId, text, ...options });
    },

    /**
     * Send notification to all admins
     */
    async notifyAdmins(message) {
        return http.post('/telegram/notify-admins', { message });
    },

    /**
     * Get bot commands
     */
    async getCommands() {
        return http.get('/telegram/commands');
    },

    /**
     * Set bot commands
     */
    async setCommands(commands) {
        return http.post('/telegram/commands', { commands });
    },

    /**
     * Get bot users
     */
    async getBotUsers(options = {}) {
        const params = apiHelpers.buildListParams(options);
        return http.get('/telegram/users', params);
    },

    /**
     * Block bot user
     */
    async blockUser(chatId) {
        return http.post(`/telegram/users/${chatId}/block`);
    },

    /**
     * Unblock bot user
     */
    async unblockUser(chatId) {
        return http.post(`/telegram/users/${chatId}/unblock`);
    },

    /**
     * Get bot statistics
     */
    async getStats() {
        return http.get('/telegram/stats');
    }
};

// ============================================================================
// PUBLIC/SUBSCRIPTION API (No auth required)
// ============================================================================

const subscriptionAPI = {
    /**
     * Get subscription info
     */
    async getInfo(token) {
        return http.get(`/sub/${token}/info`);
    },

    /**
     * Get subscription configs
     */
    async getConfigs(token, clientType = 'auto') {
        return http.get(`/sub/${token}`, { client: clientType });
    },

    /**
     * Get Clash config
     */
    async getClashConfig(token) {
        return http.get(`/sub/${token}/clash`);
    },

    /**
     * Get Sing-box config
     */
    async getSingboxConfig(token) {
        return http.get(`/sub/${token}/singbox`);
    },

    /**
     * Get V2Ray config
     */
    async getV2RayConfig(token) {
        return http.get(`/sub/${token}/v2ray`);
    },

    /**
     * Get usage stats
     */
    async getUsage(token) {
        return http.get(`/sub/${token}/usage`);
    },

    /**
     * Get client download links
     */
    async getClientLinks(token) {
        return http.get(`/sub/${token}/clients`);
    }
};

// ============================================================================
// COMBINED API OBJECT
// ============================================================================

const api = {
    // Core
    http,
    auth,
    helpers: apiHelpers,

    // Resources
    users: usersAPI,
    admins: adminsAPI,
    nodes: nodesAPI,
    inbounds: inboundsAPI,
    outbounds: outboundsAPI,
    routing: routingAPI,
    core: coreAPI,
    system: systemAPI,
    settings: settingsAPI,
    backup: backupAPI,
    templates: templatesAPI,
    logs: logsAPI,
    analytics: analyticsAPI,
    payment: paymentAPI,
    telegram: telegramAPI,
    subscription: subscriptionAPI,

    // Shortcuts
    get: http.get.bind(http),
    post: http.post.bind(http),
    put: http.put.bind(http),
    patch: http.patch.bind(http),
    delete: http.delete.bind(http),
    upload: http.upload.bind(http),
    download: http.download.bind(http)
};

// ============================================================================
// EXPORT
// ============================================================================

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        api,
        usersAPI,
        adminsAPI,
        nodesAPI,
        inboundsAPI,
        outboundsAPI,
        routingAPI,
        coreAPI,
        systemAPI,
        settingsAPI,
        backupAPI,
        templatesAPI,
        logsAPI,
        analyticsAPI,
        paymentAPI,
        telegramAPI,
        subscriptionAPI
    };
}

// Global export
window.api = api;