// MX-UI VPN Panel
// Core/api.go
// REST API: Server, Routes, Handlers, Middleware, Response, Webhooks

package core

import (
	"compress/gzip"
	_ "context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	_ "regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// CONSTANTS
// ============================================================================

const (
	// API paths
	APIBasePath   = "/api/v1"
	PanelBasePath = "/"

	// Content types
	ContentTypeJSON = "application/json"
	ContentTypeHTML = "text/html"
	ContentTypeCSS  = "text/css"
	ContentTypeJS   = "application/javascript"

	// Request limits
	MaxRequestBodySize = 10 * 1024 * 1024 // 10MB
	MaxFileUploadSize  = 50 * 1024 * 1024 // 50MB

	// Timeouts
	RequestTimeout  = 30 * time.Second
	ShutdownTimeout = 30 * time.Second
)

// ============================================================================
// API SERVER
// ============================================================================

// APIServer represents the REST API server
type APIServer struct {
	config     *Config
	router     *Router
	httpServer *http.Server
	webhooks   *WebhookManager
	mu         sync.RWMutex
	isRunning  bool
}

// Router handles HTTP routing
type Router struct {
	routes     map[string]map[string]HandlerFunc // method -> path -> handler
	middleware []Middleware
	mu         sync.RWMutex
}

// HandlerFunc is the handler function type
type HandlerFunc func(*Context)

// Middleware is the middleware function type
type Middleware func(HandlerFunc) HandlerFunc

// Context represents request context
type Context struct {
	Writer     http.ResponseWriter
	Request    *http.Request
	Params     map[string]string
	Query      map[string]string
	Claims     *JWTClaims
	Admin      *Admin
	StartTime  time.Time
	StatusCode int
	aborted    bool
}

// Global API server instance
var API *APIServer

// InitAPIServer initializes the API server
func InitAPIServer(config *Config) error {
	API = &APIServer{
		config:   config,
		router:   NewRouter(),
		webhooks: NewWebhookManager(),
	}

	// Setup routes
	API.setupRoutes()

	return nil
}

// NewRouter creates a new router
func NewRouter() *Router {
	return &Router{
		routes:     make(map[string]map[string]HandlerFunc),
		middleware: []Middleware{},
	}
}

// ============================================================================
// ROUTER METHODS
// ============================================================================

// Use adds middleware to the router
func (r *Router) Use(mw Middleware) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.middleware = append(r.middleware, mw)
}

// Handle registers a route
func (r *Router) Handle(method, path string, handler HandlerFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.routes[method] == nil {
		r.routes[method] = make(map[string]HandlerFunc)
	}
	r.routes[method][path] = handler
}

// GET registers a GET route
func (r *Router) GET(path string, handler HandlerFunc) {
	r.Handle("GET", path, handler)
}

// POST registers a POST route
func (r *Router) POST(path string, handler HandlerFunc) {
	r.Handle("POST", path, handler)
}

// PUT registers a PUT route
func (r *Router) PUT(path string, handler HandlerFunc) {
	r.Handle("PUT", path, handler)
}

// DELETE registers a DELETE route
func (r *Router) DELETE(path string, handler HandlerFunc) {
	r.Handle("DELETE", path, handler)
}

// PATCH registers a PATCH route
func (r *Router) PATCH(path string, handler HandlerFunc) {
	r.Handle("PATCH", path, handler)
}

// Group creates a route group with prefix
func (r *Router) Group(prefix string) *RouteGroup {
	return &RouteGroup{
		router: r,
		prefix: prefix,
	}
}

// RouteGroup represents a group of routes with common prefix
type RouteGroup struct {
	router     *Router
	prefix     string
	middleware []Middleware
}

// Use adds middleware to the group
func (g *RouteGroup) Use(mw Middleware) *RouteGroup {
	g.middleware = append(g.middleware, mw)
	return g
}

// applyMiddleware wraps handler with group middleware
func (g *RouteGroup) applyMiddleware(handler HandlerFunc) HandlerFunc {
	return func(ctx *Context) {
		// Apply middleware chain
		for _, mw := range g.middleware {
			mw(func(c *Context) {
				// Continue chain
			})(ctx)
		}
		handler(ctx)
	}
}

// GET registers a GET route in the group
func (g *RouteGroup) GET(path string, handler HandlerFunc) {
	g.router.Handle("GET", g.prefix+path, g.applyMiddleware(handler))
}

// POST registers a POST route in the group
func (g *RouteGroup) POST(path string, handler HandlerFunc) {
	g.router.Handle("POST", g.prefix+path, g.applyMiddleware(handler))
}

// PUT registers a PUT route in the group
func (g *RouteGroup) PUT(path string, handler HandlerFunc) {
	g.router.Handle("PUT", g.prefix+path, g.applyMiddleware(handler))
}

// DELETE registers a DELETE route in the group
func (g *RouteGroup) DELETE(path string, handler HandlerFunc) {
	g.router.Handle("DELETE", g.prefix+path, g.applyMiddleware(handler))
}

// FallbackConfig for single port fallback
type FallbackConfig struct {
	Dest string `json:"dest"`
	Path string `json:"path,omitempty"`
	Xver int    `json:"xver,omitempty"`
}

// PATCH registers a PATCH route in the group
func (g *RouteGroup) PATCH(path string, handler HandlerFunc) {
	g.router.Handle("PATCH", g.prefix+path, g.applyMiddleware(handler))
}

// ServeHTTP implements http.Handler
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := &Context{
		Writer:    w,
		Request:   req,
		Params:    make(map[string]string),
		Query:     make(map[string]string),
		StartTime: time.Now(),
	}

	// Parse query parameters
	for key, values := range req.URL.Query() {
		if len(values) > 0 {
			ctx.Query[key] = values[0]
		}
	}

	// Find handler
	handler := r.findHandler(req.Method, req.URL.Path, ctx)
	if handler == nil {
		ctx.JSON(http.StatusNotFound, Response{
			Success: false,
			Message: "Not Found",
		})
		return
	}

	// Apply global middleware
	for i := len(r.middleware) - 1; i >= 0; i-- {
		handler = r.middleware[i](handler)
	}

	// Execute handler
	handler(ctx)
}

// findHandler finds a handler for a path with parameter extraction
func (r *Router) findHandler(method, path string, ctx *Context) HandlerFunc {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if routes, ok := r.routes[method]; ok {
		// Exact match
		if handler, ok := routes[path]; ok {
			return handler
		}

		// Pattern matching
		for pattern, handler := range routes {
			if params, ok := matchPath(pattern, path); ok {
				for k, v := range params {
					ctx.Params[k] = v
				}
				return handler
			}
		}
	}

	return nil
}

// matchPath matches a path pattern and extracts parameters
func matchPath(pattern, path string) (map[string]string, bool) {
	patternParts := strings.Split(pattern, "/")
	pathParts := strings.Split(path, "/")

	if len(patternParts) != len(pathParts) {
		return nil, false
	}

	params := make(map[string]string)

	for i, part := range patternParts {
		if strings.HasPrefix(part, ":") {
			params[part[1:]] = pathParts[i]
		} else if part != pathParts[i] {
			return nil, false
		}
	}

	return params, true
}

// ============================================================================
// CONTEXT METHODS
// ============================================================================

// JSON sends a JSON response
func (c *Context) JSON(status int, data interface{}) {
	c.StatusCode = status
	c.Writer.Header().Set("Content-Type", ContentTypeJSON)
	c.Writer.WriteHeader(status)

	if data != nil {
		json.NewEncoder(c.Writer).Encode(data)
	}
}

// Success sends a success response
func (c *Context) Success(data interface{}) {
	c.JSON(http.StatusOK, Response{
		Success: true,
		Data:    data,
	})
}

// SuccessMessage sends a success response with message
func (c *Context) SuccessMessage(message string) {
	c.JSON(http.StatusOK, Response{
		Success: true,
		Message: message,
	})
}

// Created sends a created response
func (c *Context) Created(data interface{}) {
	c.JSON(http.StatusCreated, Response{
		Success: true,
		Data:    data,
	})
}

// Error sends an error response
func (c *Context) Error(status int, message string) {
	c.JSON(status, Response{
		Success: false,
		Message: message,
	})
}

// BadRequest sends a bad request response
func (c *Context) BadRequest(message string) {
	c.Error(http.StatusBadRequest, message)
}

// Unauthorized sends an unauthorized response
func (c *Context) Unauthorized(message string) {
	if message == "" {
		message = "Unauthorized"
	}
	c.Error(http.StatusUnauthorized, message)
}

// Forbidden sends a forbidden response
func (c *Context) Forbidden(message string) {
	if message == "" {
		message = "Forbidden"
	}
	c.Error(http.StatusForbidden, message)
}

// NotFound sends a not found response
func (c *Context) NotFound(message string) {
	if message == "" {
		message = "Not Found"
	}
	c.Error(http.StatusNotFound, message)
}

// InternalError sends an internal error response
func (c *Context) InternalError(message string) {
	if message == "" {
		message = "Internal Server Error"
	}
	c.Error(http.StatusInternalServerError, message)
}

// Bind binds JSON body to a struct
func (c *Context) Bind(v interface{}) error {
	defer c.Request.Body.Close()
	return json.NewDecoder(c.Request.Body).Decode(v)
}

// BindQuery binds query parameters to a struct
func (c *Context) BindQuery(v interface{}) error {
	data, err := json.Marshal(c.Query)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// Param returns a path parameter
func (c *Context) Param(key string) string {
	return c.Params[key]
}

// ParamInt returns a path parameter as int64
func (c *Context) ParamInt(key string) (int64, error) {
	return strconv.ParseInt(c.Params[key], 10, 64)
}

// QueryParam returns a query parameter
func (c *Context) QueryParam(key string) string {
	return c.Query[key]
}

// QueryParamDefault returns a query parameter with default
func (c *Context) QueryParamDefault(key, defaultValue string) string {
	if v, ok := c.Query[key]; ok && v != "" {
		return v
	}
	return defaultValue
}

// QueryParamInt returns a query parameter as int
func (c *Context) QueryParamInt(key string, defaultValue int) int {
	if v, ok := c.Query[key]; ok {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return defaultValue
}

// Abort stops the handler chain
func (c *Context) Abort() {
	c.aborted = true
}

// IsAborted returns whether the chain is aborted
func (c *Context) IsAborted() bool {
	return c.aborted
}

// GetClientIP returns the client IP address
func (c *Context) GetClientIP() string {
	return GetClientIP(c.Request)
}

// HTML sends an HTML response
func (c *Context) HTML(status int, html string) {
	c.StatusCode = status
	c.Writer.Header().Set("Content-Type", ContentTypeHTML)
	c.Writer.WriteHeader(status)
	c.Writer.Write([]byte(html))
}

// File sends a file response
func (c *Context) File(filepath string) {
	http.ServeFile(c.Writer, c.Request, filepath)
}

// Redirect redirects to a URL
func (c *Context) Redirect(status int, url string) {
	http.Redirect(c.Writer, c.Request, url, status)
}

// SetHeader sets a response header
func (c *Context) SetHeader(key, value string) {
	c.Writer.Header().Set(key, value)
}

// GetHeader gets a request header
func (c *Context) GetHeader(key string) string {
	return c.Request.Header.Get(key)
}

// ============================================================================
// RESPONSE TYPES
// ============================================================================

// Response represents a standard API response
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Meta    *Meta       `json:"meta,omitempty"`
}

// Meta represents response metadata
type Meta struct {
	Total      int   `json:"total,omitempty"`
	Page       int   `json:"page,omitempty"`
	Limit      int   `json:"limit,omitempty"`
	TotalPages int   `json:"total_pages,omitempty"`
	Timestamp  int64 `json:"timestamp,omitempty"`
}

// PaginatedResponse creates a paginated response
func PaginatedResponse(data interface{}, total, page, limit int) Response {
	totalPages := (total + limit - 1) / limit
	return Response{
		Success: true,
		Data:    data,
		Meta: &Meta{
			Total:      total,
			Page:       page,
			Limit:      limit,
			TotalPages: totalPages,
			Timestamp:  time.Now().Unix(),
		},
	}
}

// ============================================================================
// MIDDLEWARE
// ============================================================================

// LoggerMiddleware logs requests
func LoggerMiddleware() Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(c *Context) {
			start := time.Now()

			next(c)

			duration := time.Since(start)
			fmt.Printf("[%s] %s %s %d %v\n",
				time.Now().Format("2006-01-02 15:04:05"),
				c.Request.Method,
				c.Request.URL.Path,
				c.StatusCode,
				duration,
			)
		}
	}
}

// RecoveryMiddleware recovers from panics
func RecoveryMiddleware() Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(c *Context) {
			defer func() {
				if err := recover(); err != nil {
					fmt.Printf("[PANIC] %v\n", err)
					c.InternalError("Internal Server Error")
				}
			}()

			next(c)
		}
	}
}

// CORSMiddlewareHandler handles CORS
func CORSMiddlewareHandler(origins []string) Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(c *Context) {
			origin := c.GetHeader("Origin")

			allowed := false
			for _, o := range origins {
				if o == "*" || o == origin {
					allowed = true
					break
				}
			}

			if allowed && origin != "" {
				c.SetHeader("Access-Control-Allow-Origin", origin)
				c.SetHeader("Access-Control-Allow-Credentials", "true")
				c.SetHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
				c.SetHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
				c.SetHeader("Access-Control-Max-Age", "86400")
			}

			if c.Request.Method == "OPTIONS" {
				c.StatusCode = http.StatusNoContent
				c.Writer.WriteHeader(http.StatusNoContent)
				return
			}

			next(c)
		}
	}
}

// AuthMiddlewareHandler handles authentication
func AuthMiddlewareHandler() Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(c *Context) {
			token := extractToken(c.Request)
			if token == "" {
				c.Unauthorized("Missing authentication token")
				c.Abort()
				return
			}

			claims, err := Security.ValidateToken(token)
			if err != nil {
				c.Unauthorized("Invalid token")
				c.Abort()
				return
			}

			// Check 2FA if required
			if Security.config.Enable2FA {
				session, _ := Security.GetSession(claims.SessionID)
				if session != nil && !session.Is2FAVerified && Security.Is2FAEnabled(claims.AdminID) {
					c.Error(http.StatusForbidden, "2FA verification required")
					c.Abort()
					return
				}
			}

			// Get admin
			admin, err := Admins.GetAdminByID(claims.AdminID)
			if err != nil {
				c.Unauthorized("Admin not found")
				c.Abort()
				return
			}

			if !admin.IsActive {
				c.Unauthorized("Account is disabled")
				c.Abort()
				return
			}

			c.Claims = claims
			c.Admin = admin

			// Update session activity
			Security.UpdateSessionActivity(claims.SessionID)

			next(c)
		}
	}
}

// OwnerOnlyMiddlewareHandler restricts to owner admins
func OwnerOnlyMiddlewareHandler() Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(c *Context) {
			if c.Admin == nil || c.Admin.Role != AdminRoleOwner {
				c.Forbidden("Owner access required")
				c.Abort()
				return
			}
			next(c)
		}
	}
}

// RateLimitMiddlewareHandler handles rate limiting
func RateLimitMiddlewareHandler() Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(c *Context) {
			ip := c.GetClientIP()

			if Security.IsRateLimited(ip) {
				c.SetHeader("Retry-After", "60")
				c.Error(http.StatusTooManyRequests, "Rate limit exceeded")
				c.Abort()
				return
			}

			next(c)
		}
	}
}

// GzipMiddleware compresses responses
func GzipMiddleware() Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(c *Context) {
			if !strings.Contains(c.Request.Header.Get("Accept-Encoding"), "gzip") {
				next(c)
				return
			}

			gz := gzip.NewWriter(c.Writer)
			defer gz.Close()

			c.SetHeader("Content-Encoding", "gzip")
			c.Writer = &gzipResponseWriter{Writer: gz, ResponseWriter: c.Writer}

			next(c)
		}
	}
}

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

// SecurityHeadersMiddleware adds security headers
func SecurityHeadersMiddleware() Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(c *Context) {
			c.SetHeader("X-Frame-Options", "DENY")
			c.SetHeader("X-Content-Type-Options", "nosniff")
			c.SetHeader("X-XSS-Protection", "1; mode=block")
			c.SetHeader("Referrer-Policy", "strict-origin-when-cross-origin")

			next(c)
		}
	}
}

// extractToken extracts JWT token from request
func extractToken(r *http.Request) string {
	// From Authorization header
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	// From cookie
	cookie, err := r.Cookie(SessionCookieName)
	if err == nil {
		return cookie.Value
	}

	// From query parameter
	return r.URL.Query().Get("token")
}

// ============================================================================
// ROUTE SETUP
// ============================================================================

func (api *APIServer) setupRoutes() {
	r := api.router

	// Global middleware
	r.Use(RecoveryMiddleware())
	r.Use(LoggerMiddleware())
	r.Use(SecurityHeadersMiddleware())
	r.Use(CORSMiddlewareHandler(api.config.API.AllowedOrigins))
	r.Use(RateLimitMiddlewareHandler())

	// Public routes
	r.GET("/health", api.healthHandler)
	r.GET("/api/health", api.healthHandler)
	r.POST("/api/v1/auth/login", api.loginHandler)
	r.POST("/api/v1/auth/refresh", api.refreshTokenHandler)

	// Subscription routes (public with token)
	r.GET("/sub/:token", api.subscriptionHandler)
	r.GET("/sub/:token/info", api.subscriptionInfoHandler)
	r.GET("/sub/:token/clash", api.subscriptionClashHandler)
	r.GET("/sub/:token/singbox", api.subscriptionSingboxHandler)

	// Protected API routes
	apiV1 := r.Group(APIBasePath)
	apiV1.Use(AuthMiddlewareHandler())

	// Auth
	apiV1.POST("/auth/logout", api.logoutHandler)
	apiV1.POST("/auth/change-password", api.changePasswordHandler)
	apiV1.GET("/auth/me", api.getMeHandler)
	apiV1.GET("/auth/sessions", api.getSessionsHandler)
	apiV1.DELETE("/auth/sessions/:id", api.deleteSessionHandler)
	apiV1.POST("/auth/2fa/setup", api.setup2FAHandler)
	apiV1.POST("/auth/2fa/verify", api.verify2FAHandler)
	apiV1.POST("/auth/2fa/disable", api.disable2FAHandler)
	apiV1.POST("/auth/first-login-setup", api.firstLoginSetupHandler)

	// Dashboard
	apiV1.GET("/dashboard", api.dashboardHandler)
	apiV1.GET("/dashboard/stats", api.dashboardStatsHandler)

	// Users
	apiV1.GET("/users", api.listUsersHandler)
	apiV1.POST("/users", api.createUserHandler)
	apiV1.GET("/users/:id", api.getUserHandler)
	apiV1.PUT("/users/:id", api.updateUserHandler)
	apiV1.DELETE("/users/:id", api.deleteUserHandler)
	apiV1.POST("/users/:id/reset-traffic", api.resetUserTrafficHandler)
	apiV1.POST("/users/:id/extend", api.extendUserHandler)
	apiV1.POST("/users/:id/enable", api.enableUserHandler)
	apiV1.POST("/users/:id/disable", api.disableUserHandler)
	apiV1.POST("/users/:id/regenerate-subscription", api.regenerateSubscriptionHandler)
	apiV1.GET("/users/:id/online", api.getUserOnlineHandler)
	apiV1.GET("/users/:id/devices", api.getUserDevicesHandler)
	apiV1.DELETE("/users/:id/devices/:deviceId", api.deleteUserDeviceHandler)
	apiV1.GET("/users/:id/logs", api.getUserLogsHandler)
	apiV1.GET("/users/online", api.getOnlineUsersHandler)
	apiV1.POST("/users/bulk/delete", api.bulkDeleteUsersHandler)
	apiV1.POST("/users/bulk/enable", api.bulkEnableUsersHandler)
	apiV1.POST("/users/bulk/disable", api.bulkDisableUsersHandler)
	apiV1.POST("/users/bulk/reset-traffic", api.bulkResetTrafficHandler)
	apiV1.POST("/users/bulk/extend", api.bulkExtendUsersHandler)

	// Owner-only routes
	ownerApi := r.Group(APIBasePath)
	ownerApi.Use(AuthMiddlewareHandler())
	ownerApi.Use(OwnerOnlyMiddlewareHandler())

	// Admins (Owner only)
	ownerApi.GET("/admins", api.listAdminsHandler)
	ownerApi.POST("/admins", api.createAdminHandler)
	ownerApi.GET("/admins/:id", api.getAdminHandler)
	ownerApi.PUT("/admins/:id", api.updateAdminHandler)
	ownerApi.DELETE("/admins/:id", api.deleteAdminHandler)
	ownerApi.POST("/admins/:id/enable", api.enableAdminHandler)
	ownerApi.POST("/admins/:id/disable", api.disableAdminHandler)
	ownerApi.POST("/admins/:id/reset-password", api.resetAdminPasswordHandler)
	ownerApi.POST("/admins/:id/reset-traffic", api.resetAdminTrafficHandler)
	ownerApi.POST("/admins/switch/:id", api.switchAdminHandler)

	// Nodes (Owner only)
	ownerApi.GET("/nodes", api.listNodesHandler)
	ownerApi.POST("/nodes", api.createNodeHandler)
	ownerApi.GET("/nodes/:id", api.getNodeHandler)
	ownerApi.PUT("/nodes/:id", api.updateNodeHandler)
	ownerApi.DELETE("/nodes/:id", api.deleteNodeHandler)
	ownerApi.POST("/nodes/:id/enable", api.enableNodeHandler)
	ownerApi.POST("/nodes/:id/disable", api.disableNodeHandler)
	ownerApi.POST("/nodes/:id/restart", api.restartNodeHandler)
	ownerApi.POST("/nodes/:id/sync", api.syncNodeHandler)
	ownerApi.GET("/nodes/:id/test", api.testNodeHandler)
	ownerApi.GET("/nodes/:id/metrics", api.getNodeMetricsHandler)
	ownerApi.GET("/nodes/:id/install-script", api.getNodeInstallScriptHandler)
	ownerApi.GET("/nodes/stats", api.getNodeStatsHandler)

	// Inbounds (Owner only)
	ownerApi.GET("/inbounds", api.listInboundsHandler)
	ownerApi.POST("/inbounds", api.createInboundHandler)
	ownerApi.GET("/inbounds/:id", api.getInboundHandler)
	ownerApi.PUT("/inbounds/:id", api.updateInboundHandler)
	ownerApi.DELETE("/inbounds/:id", api.deleteInboundHandler)

	// Routing (Owner only)
	ownerApi.GET("/routing/rules", api.listRoutingRulesHandler)
	ownerApi.POST("/routing/rules", api.createRoutingRuleHandler)
	ownerApi.PUT("/routing/rules/:id", api.updateRoutingRuleHandler)
	ownerApi.DELETE("/routing/rules/:id", api.deleteRoutingRuleHandler)
	ownerApi.GET("/routing/dns", api.getDNSConfigHandler)
	ownerApi.PUT("/routing/dns", api.updateDNSConfigHandler)
	ownerApi.GET("/routing/warp", api.getWARPConfigHandler)
	ownerApi.PUT("/routing/warp", api.updateWARPConfigHandler)
	ownerApi.POST("/routing/warp/register", api.registerWARPHandler)
	ownerApi.GET("/routing/blocklists", api.getBlockListsHandler)
	ownerApi.PUT("/routing/blocklists", api.updateBlockListsHandler)
	ownerApi.GET("/routing/direct", api.getDirectRulesHandler)
	ownerApi.PUT("/routing/direct", api.updateDirectRulesHandler)
	ownerApi.POST("/routing/geofiles/update", api.updateGeoFilesHandler)

	// Core (Owner only)
	ownerApi.GET("/core/status", api.getCoreStatusHandler)
	ownerApi.POST("/core/restart", api.restartCoreHandler)
	ownerApi.POST("/core/update", api.updateCoreHandler)
	ownerApi.GET("/core/config", api.getCoreConfigHandler)

	// Panel Settings (Owner only)
	ownerApi.GET("/settings", api.getSettingsHandler)
	ownerApi.PUT("/settings", api.updateSettingsHandler)
	ownerApi.GET("/settings/:category", api.getSettingsCategoryHandler)
	ownerApi.PUT("/settings/:category", api.updateSettingsCategoryHandler)

	// Backup (Owner only)
	ownerApi.GET("/backup", api.listBackupsHandler)
	ownerApi.POST("/backup", api.createBackupHandler)
	ownerApi.POST("/backup/restore", api.restoreBackupHandler)
	ownerApi.DELETE("/backup/:id", api.deleteBackupHandler)
	ownerApi.GET("/backup/:id/download", api.downloadBackupHandler)

	// Logs (Owner only)
	ownerApi.GET("/logs/audit", api.getAuditLogsHandler)
	ownerApi.GET("/logs/connection", api.getConnectionLogsHandler)
	ownerApi.GET("/logs/system", api.getSystemLogsHandler)

	// System (Owner only)
	ownerApi.GET("/system/info", api.getSystemInfoHandler)
	ownerApi.GET("/system/stats", api.getSystemStatsHandler)
	ownerApi.POST("/system/reboot", api.rebootSystemHandler)

	// Telegram Bot (Owner only)
	ownerApi.GET("/bot/config", api.getBotConfigHandler)
	ownerApi.PUT("/bot/config", api.updateBotConfigHandler)
	ownerApi.POST("/bot/start", api.startBotHandler)
	ownerApi.POST("/bot/stop", api.stopBotHandler)

	// AI (Owner only)
	ownerApi.GET("/ai/config", api.getAIConfigHandler)
	ownerApi.PUT("/ai/config", api.updateAIConfigHandler)
	ownerApi.POST("/ai/suggest", api.getAISuggestionHandler)

	// Templates (Owner only)
	ownerApi.GET("/templates", api.listTemplatesHandler)
	ownerApi.GET("/templates/:id", api.getTemplateHandler)
	ownerApi.PUT("/templates/:id", api.updateTemplateHandler)

	// Webhook endpoints
	r.POST("/webhook/telegram", api.telegramWebhookHandler)
	r.POST("/webhook/payment", api.paymentWebhookHandler)

	// Static files
	r.GET("/", api.serveIndexHandler)
	r.GET("/login", api.serveLoginHandler)
	r.GET("/dashboard", api.serveDashboardHandler)
}

// ============================================================================
// AUTH HANDLERS
// ============================================================================

// LoginRequest represents login request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TwoFA    string `json:"2fa_code,omitempty"`
}

// LoginResponse represents login response
type LoginResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
	Admin        *Admin    `json:"admin"`
	Requires2FA  bool      `json:"requires_2fa,omitempty"`
}

func (api *APIServer) loginHandler(c *Context) {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		c.BadRequest("Invalid request body")
		return
	}

	ip := c.GetClientIP()

	// Check brute force
	if blocked, remaining := Security.IsLoginBlocked(ip); blocked {
		c.Error(http.StatusTooManyRequests, fmt.Sprintf("Too many attempts. Try again in %v", remaining))
		return
	}

	// Authenticate
	admin, err := Admins.AuthenticateAdmin(req.Username, req.Password)
	if err != nil {
		Security.RecordLoginAttempt(ip, false)
		c.Unauthorized(err.Error())
		return
	}

	// Check 2FA
	if Security.Is2FAEnabled(admin.ID) {
		if req.TwoFA == "" {
			c.JSON(http.StatusOK, Response{
				Success: true,
				Data: LoginResponse{
					Requires2FA: true,
				},
			})
			return
		}

		if !Security.Verify2FAForAdmin(admin.ID, req.TwoFA) {
			c.Unauthorized("Invalid 2FA code")
			return
		}
	}

	// Create session
	session, err := Security.CreateSession(admin, ip, c.Request.UserAgent())
	if err != nil {
		c.InternalError("Failed to create session")
		return
	}

	// Mark 2FA as verified if applicable
	if Security.Is2FAEnabled(admin.ID) {
		Security.Mark2FAVerified(session.ID)
	}

	// Generate tokens
	tokens, err := Security.GenerateTokenPair(admin, session.ID)
	if err != nil {
		c.InternalError("Failed to generate tokens")
		return
	}

	Security.RecordLoginAttempt(ip, true)
	Admins.UpdateLoginInfo(admin.ID, ip)

	// Set cookie
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     SessionCookieName,
		Value:    tokens.AccessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   api.config.Panel.SSL,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(JWTAccessTokenExp.Seconds()),
	})

	// Log audit
	if Security != nil {
		Security.LogAuditEvent(admin.ID, admin.Username, "login", "session", 0,
			nil, nil, c.Request)
	}

	c.Success(LoginResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    tokens.ExpiresAt,
		TokenType:    tokens.TokenType,
		Admin:        admin,
	})
}

func (api *APIServer) refreshTokenHandler(c *Context) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.Bind(&req); err != nil {
		c.BadRequest("Invalid request")
		return
	}

	tokens, err := Security.RefreshAccessToken(req.RefreshToken)
	if err != nil {
		c.Unauthorized(err.Error())
		return
	}

	c.Success(tokens)
}

func (api *APIServer) logoutHandler(c *Context) {
	if c.Claims != nil {
		Security.InvalidateSession(c.Claims.SessionID)
	}

	// Clear cookie
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	c.SuccessMessage("Logged out successfully")
}

func (api *APIServer) changePasswordHandler(c *Context) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := c.Bind(&req); err != nil {
		c.BadRequest("Invalid request")
		return
	}

	if err := Admins.ChangePassword(c.Admin.ID, req.CurrentPassword, req.NewPassword); err != nil {
		c.BadRequest(err.Error())
		return
	}

	// Invalidate all sessions
	Security.InvalidateAllSessions(c.Admin.ID)

	c.SuccessMessage("Password changed successfully")
}

func (api *APIServer) getMeHandler(c *Context) {
	admin, err := Admins.GetAdminByID(c.Admin.ID)
	if err != nil {
		c.NotFound("Admin not found")
		return
	}

	c.Success(admin)
}

func (api *APIServer) getSessionsHandler(c *Context) {
	sessions := Security.GetActiveSessions(c.Admin.ID)
	c.Success(sessions)
}

func (api *APIServer) deleteSessionHandler(c *Context) {
	sessionID := c.Param("id")
	Security.InvalidateSession(sessionID)
	c.SuccessMessage("Session deleted")
}

func (api *APIServer) setup2FAHandler(c *Context) {
	secret, err := Security.Generate2FASecret(c.Admin.Username)
	if err != nil {
		c.InternalError("Failed to generate 2FA secret")
		return
	}

	c.Success(secret)
}

func (api *APIServer) verify2FAHandler(c *Context) {
	var req struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}
	if err := c.Bind(&req); err != nil {
		c.BadRequest("Invalid request")
		return
	}

	if !Security.Verify2FACode(req.Secret, req.Code) {
		c.BadRequest("Invalid 2FA code")
		return
	}

	if err := Security.Enable2FA(c.Admin.ID, req.Secret); err != nil {
		c.InternalError("Failed to enable 2FA")
		return
	}

	c.SuccessMessage("2FA enabled successfully")
}

func (api *APIServer) disable2FAHandler(c *Context) {
	var req struct {
		Code string `json:"code"`
	}
	if err := c.Bind(&req); err != nil {
		c.BadRequest("Invalid request")
		return
	}

	if !Security.Verify2FAForAdmin(c.Admin.ID, req.Code) {
		c.BadRequest("Invalid 2FA code")
		return
	}

	if err := Security.Disable2FA(c.Admin.ID); err != nil {
		c.InternalError("Failed to disable 2FA")
		return
	}

	c.SuccessMessage("2FA disabled successfully")
}

// FirstLoginSetupRequest represents first login setup request
type FirstLoginSetupRequest struct {
	NewUsername string `json:"new_username"`
	NewPassword string `json:"new_password"`
	NewPath     string `json:"new_path"`
}

func (api *APIServer) firstLoginSetupHandler(c *Context) {
	// Only allow if admin has is_first_login = true
	if !c.Admin.IsFirstLogin {
		c.Forbidden("First login setup already completed")
		return
	}

	var req FirstLoginSetupRequest
	if err := c.Bind(&req); err != nil {
		c.BadRequest("Invalid request body")
		return
	}

	// Validate new username
	if req.NewUsername != "" && req.NewUsername != c.Admin.Username {
		if err := ValidateUsername(req.NewUsername); err != nil {
			c.BadRequest(err.Error())
			return
		}
		// Check if username already exists
		existing, _ := Admins.GetAdminByUsername(req.NewUsername)
		if existing != nil && existing.ID != c.Admin.ID {
			c.BadRequest("Username already exists")
			return
		}
	}

	// Validate new password
	if req.NewPassword != "" {
		if err := ValidatePassword(req.NewPassword); err != nil {
			c.BadRequest(err.Error())
			return
		}
	}

	// Validate new path
	if req.NewPath != "" {
		if len(req.NewPath) < 4 || len(req.NewPath) > 64 {
			c.BadRequest("Path must be between 4 and 64 characters")
			return
		}
	}

	// Update admin credentials
	updates := []string{}
	args := []interface{}{}

	if req.NewUsername != "" && req.NewUsername != c.Admin.Username {
		updates = append(updates, "username = ?")
		args = append(args, req.NewUsername)
	}

	if req.NewPassword != "" {
		hashedPassword, err := HashPassword(req.NewPassword)
		if err != nil {
			c.InternalError("Failed to hash password")
			return
		}
		updates = append(updates, "password = ?")
		args = append(args, hashedPassword)
	}

	// Mark first login as completed
	updates = append(updates, "is_first_login = 0")
	updates = append(updates, "updated_at = ?")
	args = append(args, time.Now())
	args = append(args, c.Admin.ID)

	if len(updates) > 0 {
		query := fmt.Sprintf("UPDATE admins SET %s WHERE id = ?", strings.Join(updates, ", "))
		if _, err := DB.db.Exec(query, args...); err != nil {
			c.InternalError("Failed to update admin")
			return
		}
	}

	// Update panel path if provided
	if req.NewPath != "" {
		api.config.Panel.Path = "/" + strings.TrimPrefix(req.NewPath, "/")
		SaveConfig()
	}

	// Clear admin cache
	Admins.ClearCache(c.Admin.ID)

	// Invalidate all sessions to require re-login with new credentials
	Security.InvalidateAllSessions(c.Admin.ID)

	c.Success(map[string]interface{}{
		"message":  "Setup completed successfully",
		"new_path": api.config.Panel.Path,
		"relogin":  true,
	})
}

// ============================================================================
// DASHBOARD HANDLERS
// ============================================================================

func (api *APIServer) dashboardHandler(c *Context) {
	var data map[string]interface{}
	var err error

	if c.Admin.Role == AdminRoleOwner {
		data, err = Admins.GetOwnerDashboard()
	} else {
		data, err = Admins.GetResellerDashboard(c.Admin.ID)
	}

	if err != nil {
		c.InternalError("Failed to get dashboard data")
		return
	}

	c.Success(data)
}

func (api *APIServer) dashboardStatsHandler(c *Context) {
	stats, err := Users.GetUserStats()
	if err != nil {
		c.InternalError("Failed to get stats")
		return
	}

	c.Success(stats)
}

// ============================================================================
// USER HANDLERS
// ============================================================================

func (api *APIServer) listUsersHandler(c *Context) {
	filter := &UserFilter{
		Search:    c.QueryParam("search"),
		Status:    c.QueryParam("status"),
		SortBy:    c.QueryParamDefault("sort_by", "created_at"),
		SortOrder: c.QueryParamDefault("sort_order", "desc"),
		Limit:     c.QueryParamInt("limit", 50),
		Offset:    c.QueryParamInt("offset", 0),
	}

	// Resellers can only see their own users
	if c.Admin.Role == AdminRoleReseller {
		filter.AdminID = c.Admin.ID
	} else if adminID := c.QueryParam("admin_id"); adminID != "" {
		id, _ := strconv.ParseInt(adminID, 10, 64)
		filter.AdminID = id
	}

	result, err := Users.ListUsers(filter)
	if err != nil {
		c.InternalError("Failed to list users")
		return
	}

	c.JSON(http.StatusOK, PaginatedResponse(result.Users, result.Total, filter.Offset/filter.Limit+1, filter.Limit))
}

func (api *APIServer) createUserHandler(c *Context) {
	var req CreateUserRequest
	if err := c.Bind(&req); err != nil {
		c.BadRequest("Invalid request body")
		return
	}

	req.CreatedByAdminID = c.Admin.ID

	// Check reseller limits
	if c.Admin.Role == AdminRoleReseller {
		canCreate, remaining := Admins.CheckResellerUserLimit(c.Admin)
		if !canCreate {
			c.Forbidden(fmt.Sprintf("User limit reached. Remaining: %d", remaining))
			return
		}
	}

	user, err := Users.CreateUser(&req)
	if err != nil {
		c.BadRequest(err.Error())
		return
	}

	// Add user to inbounds
	if Protocols != nil {
		Protocols.SyncUsersToInbounds()
	}

	c.Created(user)
}

func (api *APIServer) getUserHandler(c *Context) {
	id, err := c.ParamInt("id")
	if err != nil {
		c.BadRequest("Invalid user ID")
		return
	}

	user, err := Users.GetUserByID(id)
	if err != nil {
		c.NotFound("User not found")
		return
	}

	// Check permission
	if c.Admin.Role == AdminRoleReseller && user.CreatedByAdminID != c.Admin.ID {
		c.Forbidden("Access denied")
		return
	}

	c.Success(user)
}

func (api *APIServer) updateUserHandler(c *Context) {
	id, err := c.ParamInt("id")
	if err != nil {
		c.BadRequest("Invalid user ID")
		return
	}

	// Check permission
	user, err := Users.GetUserByID(id)
	if err != nil {
		c.NotFound("User not found")
		return
	}

	if c.Admin.Role == AdminRoleReseller && user.CreatedByAdminID != c.Admin.ID {
		c.Forbidden("Access denied")
		return
	}

	var req UpdateUserRequest
	if err := c.Bind(&req); err != nil {
		c.BadRequest("Invalid request body")
		return
	}

	updatedUser, err := Users.UpdateUser(id, &req)
	if err != nil {
		c.BadRequest(err.Error())
		return
	}

	// Sync to inbounds
	if Protocols != nil {
		Protocols.SyncUsersToInbounds()
	}

	c.Success(updatedUser)
}

func (api *APIServer) deleteUserHandler(c *Context) {
	id, err := c.ParamInt("id")
	if err != nil {
		c.BadRequest("Invalid user ID")
		return
	}

	// Check permission
	user, err := Users.GetUserByID(id)
	if err != nil {
		c.NotFound("User not found")
		return
	}

	if c.Admin.Role == AdminRoleReseller && user.CreatedByAdminID != c.Admin.ID {
		c.Forbidden("Access denied")
		return
	}

	if err := Users.DeleteUser(id); err != nil {
		c.InternalError("Failed to delete user")
		return
	}

	// Sync to inbounds
	if Protocols != nil {
		Protocols.SyncUsersToInbounds()
	}

	c.SuccessMessage("User deleted successfully")
}

func (api *APIServer) resetUserTrafficHandler(c *Context) {
	id, err := c.ParamInt("id")
	if err != nil {
		c.BadRequest("Invalid user ID")
		return
	}

	if err := Users.ResetUserTraffic(id); err != nil {
		c.InternalError("Failed to reset traffic")
		return
	}

	c.SuccessMessage("Traffic reset successfully")
}

func (api *APIServer) extendUserHandler(c *Context) {
	id, err := c.ParamInt("id")
	if err != nil {
		c.BadRequest("Invalid user ID")
		return
	}

	var req struct {
		Days    int   `json:"days"`
		Traffic int64 `json:"traffic"`
	}
	if err := c.Bind(&req); err != nil {
		c.BadRequest("Invalid request")
		return
	}

	if err := Users.ExtendSubscription(id, req.Days, req.Traffic); err != nil {
		c.InternalError("Failed to extend subscription")
		return
	}

	c.SuccessMessage("Subscription extended successfully")
}

func (api *APIServer) enableUserHandler(c *Context) {
	id, _ := c.ParamInt("id")
	if err := Users.EnableUser(id); err != nil {
		c.InternalError("Failed to enable user")
		return
	}
	c.SuccessMessage("User enabled")
}

func (api *APIServer) disableUserHandler(c *Context) {
	id, _ := c.ParamInt("id")
	if err := Users.DisableUser(id); err != nil {
		c.InternalError("Failed to disable user")
		return
	}
	c.SuccessMessage("User disabled")
}

func (api *APIServer) regenerateSubscriptionHandler(c *Context) {
	id, _ := c.ParamInt("id")
	newURL, err := Users.RegenerateSubscriptionURL(id)
	if err != nil {
		c.InternalError("Failed to regenerate subscription")
		return
	}
	c.Success(map[string]string{"subscription_url": newURL})
}

func (api *APIServer) getUserOnlineHandler(c *Context) {
	id, _ := c.ParamInt("id")
	ips := Users.GetUserOnlineIPs(id)
	c.Success(ips)
}

func (api *APIServer) getUserDevicesHandler(c *Context) {
	id, _ := c.ParamInt("id")
	devices, err := Users.GetUserDevices(id)
	if err != nil {
		c.InternalError("Failed to get devices")
		return
	}
	c.Success(devices)
}

func (api *APIServer) deleteUserDeviceHandler(c *Context) {
	userID, _ := c.ParamInt("id")
	deviceID := c.Param("deviceId")

	if err := Users.DeactivateDevice(userID, deviceID); err != nil {
		c.InternalError("Failed to delete device")
		return
	}
	c.SuccessMessage("Device deleted")
}

func (api *APIServer) getUserLogsHandler(c *Context) {
	id, _ := c.ParamInt("id")
	limit := c.QueryParamInt("limit", 100)
	offset := c.QueryParamInt("offset", 0)

	rows, err := DB.db.Query(`
		SELECT id, user_id, node_id, ip, location, protocol, inbound,
		       upload, download, duration, connected_at, disconnected_at
		FROM connection_logs WHERE user_id = ?
		ORDER BY connected_at DESC LIMIT ? OFFSET ?
	`, id, limit, offset)
	if err != nil {
		c.InternalError("Failed to get logs")
		return
	}
	defer rows.Close()

	logs := []ConnectionLog{}
	for rows.Next() {
		var log ConnectionLog
		rows.Scan(&log.ID, &log.UserID, &log.NodeID, &log.IP, &log.Location,
			&log.Protocol, &log.Inbound, &log.Upload, &log.Download,
			&log.Duration, &log.ConnectedAt, &log.DisconnectedAt)
		logs = append(logs, log)
	}

	c.Success(logs)
}

func (api *APIServer) getOnlineUsersHandler(c *Context) {
	var users []*OnlineUser

	if c.Admin.Role == AdminRoleOwner {
		users = Users.GetOnlineUsers()
	} else {
		users = Users.GetOnlineUsersForAdmin(c.Admin.ID)
	}

	c.Success(users)
}

func (api *APIServer) bulkDeleteUsersHandler(c *Context) {
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if err := c.Bind(&req); err != nil {
		c.BadRequest("Invalid request")
		return
	}

	count, err := Users.BulkDeleteUsers(req.IDs)
	if err != nil {
		c.InternalError("Failed to delete users")
		return
	}

	c.Success(map[string]int{"deleted": count})
}

func (api *APIServer) bulkEnableUsersHandler(c *Context) {
	var req struct {
		IDs []int64 `json:"ids"`
	}
	c.Bind(&req)

	count, _ := Users.BulkUpdateStatus(req.IDs, UserStatusActive)
	c.Success(map[string]int{"updated": count})
}

func (api *APIServer) bulkDisableUsersHandler(c *Context) {
	var req struct {
		IDs []int64 `json:"ids"`
	}
	c.Bind(&req)

	count, _ := Users.BulkUpdateStatus(req.IDs, UserStatusDisabled)
	c.Success(map[string]int{"updated": count})
}

func (api *APIServer) bulkResetTrafficHandler(c *Context) {
	var req struct {
		IDs []int64 `json:"ids"`
	}
	c.Bind(&req)

	count, _ := Users.BulkResetTraffic(req.IDs)
	c.Success(map[string]int{"updated": count})
}

func (api *APIServer) bulkExtendUsersHandler(c *Context) {
	var req struct {
		IDs  []int64 `json:"ids"`
		Days int     `json:"days"`
	}
	c.Bind(&req)

	count, _ := Users.BulkExtendSubscription(req.IDs, req.Days)
	c.Success(map[string]int{"updated": count})
}

// ============================================================================
// ADMIN HANDLERS
// ============================================================================

func (api *APIServer) listAdminsHandler(c *Context) {
	filter := &AdminFilter{
		Search: c.QueryParam("search"),
		Role:   c.QueryParam("role"),
		Limit:  c.QueryParamInt("limit", 50),
		Offset: c.QueryParamInt("offset", 0),
	}

	result, err := Admins.ListAdmins(filter)
	if err != nil {
		c.InternalError("Failed to list admins")
		return
	}

	c.JSON(http.StatusOK, PaginatedResponse(result.Admins, result.Total, filter.Offset/filter.Limit+1, filter.Limit))
}

func (api *APIServer) createAdminHandler(c *Context) {
	var req CreateAdminRequest
	if err := c.Bind(&req); err != nil {
		c.BadRequest("Invalid request body")
		return
	}

	admin, err := Admins.CreateAdmin(&req, c.Admin.ID)
	if err != nil {
		c.BadRequest(err.Error())
		return
	}

	c.Created(admin)
}

func (api *APIServer) getAdminHandler(c *Context) {
	id, _ := c.ParamInt("id")

	stats, err := Admins.GetAdminDetailedStats(id)
	if err != nil {
		c.NotFound("Admin not found")
		return
	}

	c.Success(stats)
}

func (api *APIServer) updateAdminHandler(c *Context) {
	id, _ := c.ParamInt("id")

	var req UpdateAdminRequest
	if err := c.Bind(&req); err != nil {
		c.BadRequest("Invalid request body")
		return
	}

	admin, err := Admins.UpdateAdmin(id, &req)
	if err != nil {
		c.BadRequest(err.Error())
		return
	}

	c.Success(admin)
}

func (api *APIServer) deleteAdminHandler(c *Context) {
	id, _ := c.ParamInt("id")

	if err := Admins.DeleteAdmin(id, c.Admin.ID); err != nil {
		c.BadRequest(err.Error())
		return
	}

	c.SuccessMessage("Admin deleted successfully")
}

func (api *APIServer) enableAdminHandler(c *Context) {
	id, _ := c.ParamInt("id")
	Admins.EnableAdmin(id)
	c.SuccessMessage("Admin enabled")
}

func (api *APIServer) disableAdminHandler(c *Context) {
	id, _ := c.ParamInt("id")
	Admins.DisableAdmin(id)
	c.SuccessMessage("Admin disabled")
}

func (api *APIServer) resetAdminPasswordHandler(c *Context) {
	id, _ := c.ParamInt("id")

	var req struct {
		NewPassword string `json:"new_password"`
	}
	c.Bind(&req)

	if err := Admins.ResetPassword(id, req.NewPassword); err != nil {
		c.BadRequest(err.Error())
		return
	}

	c.SuccessMessage("Password reset successfully")
}

func (api *APIServer) resetAdminTrafficHandler(c *Context) {
	id, _ := c.ParamInt("id")
	Admins.ResetTrafficUsage(id)
	c.SuccessMessage("Traffic reset successfully")
}

func (api *APIServer) switchAdminHandler(c *Context) {
	id, _ := c.ParamInt("id")

	admin, err := Admins.SwitchToAdmin(c.Admin, id)
	if err != nil {
		c.BadRequest(err.Error())
		return
	}

	c.Success(admin)
}

// ============================================================================
// NODE HANDLERS
// ============================================================================

func (api *APIServer) listNodesHandler(c *Context) {
	nodes := Nodes.ListNodes()

	nodeList := []map[string]interface{}{}
	for _, node := range nodes {
		nodeList = append(nodeList, map[string]interface{}{
			"node":          node.Node,
			"is_available":  node.IsAvailable,
			"health_status": node.HealthStatus,
			"metrics":       node.Metrics,
		})
	}

	c.Success(nodeList)
}

func (api *APIServer) createNodeHandler(c *Context) {
	var req CreateNodeRequest
	if err := c.Bind(&req); err != nil {
		c.BadRequest("Invalid request body")
		return
	}

	node, err := Nodes.CreateNode(&req)
	if err != nil {
		c.BadRequest(err.Error())
		return
	}

	c.Created(node)
}

func (api *APIServer) getNodeHandler(c *Context) {
	id, _ := c.ParamInt("id")

	details, err := Nodes.GetNodeDetails(id)
	if err != nil {
		c.NotFound("Node not found")
		return
	}

	c.Success(details)
}

func (api *APIServer) updateNodeHandler(c *Context) {
	id, _ := c.ParamInt("id")

	var req UpdateNodeRequest
	if err := c.Bind(&req); err != nil {
		c.BadRequest("Invalid request body")
		return
	}

	node, err := Nodes.UpdateNode(id, &req)
	if err != nil {
		c.BadRequest(err.Error())
		return
	}

	c.Success(node)
}

func (api *APIServer) deleteNodeHandler(c *Context) {
	id, _ := c.ParamInt("id")

	if err := Nodes.DeleteNode(id); err != nil {
		c.BadRequest(err.Error())
		return
	}

	c.SuccessMessage("Node deleted successfully")
}

func (api *APIServer) enableNodeHandler(c *Context) {
	id, _ := c.ParamInt("id")
	Nodes.EnableNode(id)
	c.SuccessMessage("Node enabled")
}

func (api *APIServer) disableNodeHandler(c *Context) {
	id, _ := c.ParamInt("id")
	Nodes.DisableNode(id)
	c.SuccessMessage("Node disabled")
}

func (api *APIServer) restartNodeHandler(c *Context) {
	id, _ := c.ParamInt("id")

	if err := Nodes.RestartNodeCore(id); err != nil {
		c.InternalError("Failed to restart node")
		return
	}

	c.SuccessMessage("Node restarted")
}

func (api *APIServer) syncNodeHandler(c *Context) {
	id, _ := c.ParamInt("id")

	if err := Nodes.syncManager.ForceSyncNode(Nodes, id); err != nil {
		c.InternalError("Failed to sync node")
		return
	}

	c.SuccessMessage("Node synced")
}

func (api *APIServer) testNodeHandler(c *Context) {
	id, _ := c.ParamInt("id")

	result, err := Nodes.TestNodeConnection(id)
	if err != nil {
		c.InternalError("Failed to test node")
		return
	}

	c.Success(result)
}

func (api *APIServer) getNodeMetricsHandler(c *Context) {
	id, _ := c.ParamInt("id")

	history := Nodes.metricsCollector.GetMetricsHistory(id)
	c.Success(history)
}

func (api *APIServer) getNodeInstallScriptHandler(c *Context) {
	id, _ := c.ParamInt("id")

	script, err := Nodes.GenerateNodeInstallScript(id)
	if err != nil {
		c.InternalError("Failed to generate script")
		return
	}

	c.SetHeader("Content-Type", "text/plain")
	c.SetHeader("Content-Disposition", fmt.Sprintf("attachment; filename=install-node-%d.sh", id))
	c.Writer.Write([]byte(script))
}

func (api *APIServer) getNodeStatsHandler(c *Context) {
	stats := Nodes.GetNodeStats()
	c.Success(stats)
}

// ============================================================================
// INBOUND HANDLERS
// ============================================================================

func (api *APIServer) listInboundsHandler(c *Context) {
	nodeID := int64(c.QueryParamInt("node_id", 0))

	inbounds, err := Protocols.ListInbounds(nodeID)
	if err != nil {
		c.InternalError("Failed to list inbounds")
		return
	}

	c.Success(inbounds)
}

func (api *APIServer) createInboundHandler(c *Context) {
	var req InboundConfig
	if err := c.Bind(&req); err != nil {
		c.BadRequest("Invalid request body")
		return
	}

	if err := Protocols.CreateInbound(&req); err != nil {
		c.BadRequest(err.Error())
		return
	}

	c.Created(req)
}

func (api *APIServer) getInboundHandler(c *Context) {
	id, _ := c.ParamInt("id")

	inbound, err := Protocols.GetInbound(id)
	if err != nil {
		c.NotFound("Inbound not found")
		return
	}

	c.Success(inbound)
}

func (api *APIServer) updateInboundHandler(c *Context) {
	id, _ := c.ParamInt("id")

	var req InboundConfig
	if err := c.Bind(&req); err != nil {
		c.BadRequest("Invalid request body")
		return
	}

	if err := Protocols.UpdateInbound(id, &req); err != nil {
		c.BadRequest(err.Error())
		return
	}

	c.Success(req)
}

func (api *APIServer) deleteInboundHandler(c *Context) {
	id, _ := c.ParamInt("id")

	if err := Protocols.DeleteInbound(id); err != nil {
		c.InternalError("Failed to delete inbound")
		return
	}

	c.SuccessMessage("Inbound deleted")
}

// ============================================================================
// ROUTING HANDLERS
// ============================================================================

func (api *APIServer) listRoutingRulesHandler(c *Context) {
	nodeID := int64(c.QueryParamInt("node_id", 0))

	rules, err := Routing.ListRules(nodeID)
	if err != nil {
		c.InternalError("Failed to list rules")
		return
	}

	c.Success(rules)
}

func (api *APIServer) createRoutingRuleHandler(c *Context) {
	var req CreateRuleRequest
	if err := c.Bind(&req); err != nil {
		c.BadRequest("Invalid request body")
		return
	}

	rule, err := Routing.CreateRule(&req)
	if err != nil {
		c.BadRequest(err.Error())
		return
	}

	c.Created(rule)
}

func (api *APIServer) updateRoutingRuleHandler(c *Context) {
	id, _ := c.ParamInt("id")

	var req CreateRuleRequest
	if err := c.Bind(&req); err != nil {
		c.BadRequest("Invalid request body")
		return
	}

	rule, err := Routing.UpdateRule(id, &req)
	if err != nil {
		c.BadRequest(err.Error())
		return
	}

	c.Success(rule)
}

func (api *APIServer) deleteRoutingRuleHandler(c *Context) {
	id, _ := c.ParamInt("id")

	if err := Routing.DeleteRule(id); err != nil {
		c.InternalError("Failed to delete rule")
		return
	}

	c.SuccessMessage("Rule deleted")
}

func (api *APIServer) getDNSConfigHandler(c *Context) {
	c.Success(Routing.GetDNSConfig())
}

func (api *APIServer) updateDNSConfigHandler(c *Context) {
	var config DNSConfig
	if err := c.Bind(&config); err != nil {
		c.BadRequest("Invalid request body")
		return
	}

	if err := Routing.SetDNSConfig(&config); err != nil {
		c.InternalError("Failed to update DNS config")
		return
	}

	c.SuccessMessage("DNS config updated")
}

func (api *APIServer) getWARPConfigHandler(c *Context) {
	c.Success(Routing.GetWARPConfig())
}

func (api *APIServer) updateWARPConfigHandler(c *Context) {
	var config WARPConfiguration
	if err := c.Bind(&config); err != nil {
		c.BadRequest("Invalid request body")
		return
	}

	if err := Routing.SetWARPConfig(&config); err != nil {
		c.InternalError("Failed to update WARP config")
		return
	}

	c.SuccessMessage("WARP config updated")
}

func (api *APIServer) registerWARPHandler(c *Context) {
	config, err := Routing.RegisterWARP()
	if err != nil {
		c.InternalError(err.Error())
		return
	}

	c.Success(config)
}

func (api *APIServer) getBlockListsHandler(c *Context) {
	c.Success(Routing.GetBlockLists())
}

func (api *APIServer) updateBlockListsHandler(c *Context) {
	var req map[string]*BlockList
	if err := c.Bind(&req); err != nil {
		c.BadRequest("Invalid request body")
		return
	}

	for name, list := range req {
		if list.IsActive {
			Routing.EnableBlockList(name)
		} else {
			Routing.DisableBlockList(name)
		}
	}

	c.SuccessMessage("Block lists updated")
}

func (api *APIServer) getDirectRulesHandler(c *Context) {
	c.Success(Routing.GetDirectRules())
}

func (api *APIServer) updateDirectRulesHandler(c *Context) {
	var rules DirectRules
	if err := c.Bind(&rules); err != nil {
		c.BadRequest("Invalid request body")
		return
	}

	if err := Routing.SetDirectRules(&rules); err != nil {
		c.InternalError("Failed to update direct rules")
		return
	}

	c.SuccessMessage("Direct rules updated")
}

func (api *APIServer) updateGeoFilesHandler(c *Context) {
	if err := Routing.UpdateGeoFiles(); err != nil {
		c.InternalError(err.Error())
		return
	}

	c.SuccessMessage("GeoFiles updated successfully")
}

// ============================================================================
// CORE HANDLERS
// ============================================================================

func (api *APIServer) getCoreStatusHandler(c *Context) {
	status := Protocols.GetCoreStatus()
	c.Success(status)
}

func (api *APIServer) restartCoreHandler(c *Context) {
	coreName := c.QueryParam("core")

	var err error
	if coreName != "" {
		err = Protocols.RestartCore(coreName)
	} else {
		err = Protocols.Restart()
	}

	if err != nil {
		c.InternalError(err.Error())
		return
	}

	c.SuccessMessage("Core restarted successfully")
}

func (api *APIServer) updateCoreHandler(c *Context) {
	coreName := c.QueryParamDefault("core", CoreXray)

	if err := Protocols.UpdateCore(coreName); err != nil {
		c.InternalError(err.Error())
		return
	}

	c.SuccessMessage("Core updated successfully")
}

func (api *APIServer) getCoreConfigHandler(c *Context) {
	config, err := Protocols.GenerateXrayConfig()
	if err != nil {
		c.InternalError("Failed to generate config")
		return
	}

	c.Success(config)
}

// ============================================================================
// SETTINGS HANDLERS
// ============================================================================

func (api *APIServer) getSettingsHandler(c *Context) {
	settings, err := DB.GetAllSettings("")
	if err != nil {
		c.InternalError("Failed to get settings")
		return
	}

	c.Success(settings)
}

func (api *APIServer) updateSettingsHandler(c *Context) {
	var settings map[string]string
	if err := c.Bind(&settings); err != nil {
		c.BadRequest("Invalid request body")
		return
	}

	for key, value := range settings {
		DB.SetSetting(key, value, "string", "general", false)
	}

	c.SuccessMessage("Settings updated")
}

func (api *APIServer) getSettingsCategoryHandler(c *Context) {
	category := c.Param("category")

	settings, err := DB.GetAllSettings(category)
	if err != nil {
		c.InternalError("Failed to get settings")
		return
	}

	c.Success(settings)
}

func (api *APIServer) updateSettingsCategoryHandler(c *Context) {
	category := c.Param("category")

	var settings map[string]string
	if err := c.Bind(&settings); err != nil {
		c.BadRequest("Invalid request body")
		return
	}

	for key, value := range settings {
		DB.SetSetting(key, value, "string", category, false)
	}

	c.SuccessMessage("Settings updated")
}

// ============================================================================
// BACKUP HANDLERS
// ============================================================================

func (api *APIServer) listBackupsHandler(c *Context) {
	rows, err := DB.db.Query(`
		SELECT id, file_name, file_path, file_size, type, destination, status, error, created_at
		FROM backups ORDER BY created_at DESC
	`)
	if err != nil {
		c.InternalError("Failed to list backups")
		return
	}
	defer rows.Close()

	backups := []Backup{}
	for rows.Next() {
		var b Backup
		rows.Scan(&b.ID, &b.FileName, &b.FilePath, &b.FileSize, &b.Type,
			&b.Destination, &b.Status, &b.Error, &b.CreatedAt)
		backups = append(backups, b)
	}

	c.Success(backups)
}

func (api *APIServer) createBackupHandler(c *Context) {
	backupPath := filepath.Join(api.config.Backup.BackupPath,
		fmt.Sprintf("backup_%s.db", time.Now().Format("20060102_150405")))

	if err := DB.BackupDatabase(backupPath); err != nil {
		c.InternalError("Failed to create backup")
		return
	}

	info, _ := os.Stat(backupPath)
	backup := Backup{
		FileName:    filepath.Base(backupPath),
		FilePath:    backupPath,
		FileSize:    info.Size(),
		Type:        "manual",
		Destination: "local",
		Status:      "completed",
		CreatedAt:   time.Now(),
	}

	DB.db.Exec(`
		INSERT INTO backups (file_name, file_path, file_size, type, destination, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, backup.FileName, backup.FilePath, backup.FileSize, backup.Type,
		backup.Destination, backup.Status, backup.CreatedAt)

	c.Success(backup)
}

func (api *APIServer) restoreBackupHandler(c *Context) {
	var req struct {
		BackupID int64  `json:"backup_id"`
		FilePath string `json:"file_path"`
	}
	c.Bind(&req)

	var backupPath string
	if req.BackupID > 0 {
		DB.db.QueryRow("SELECT file_path FROM backups WHERE id = ?", req.BackupID).Scan(&backupPath)
	} else {
		backupPath = req.FilePath
	}

	if err := DB.RestoreDatabase(backupPath); err != nil {
		c.InternalError("Failed to restore backup")
		return
	}

	c.SuccessMessage("Backup restored successfully. Please restart the panel.")
}

func (api *APIServer) deleteBackupHandler(c *Context) {
	id, _ := c.ParamInt("id")

	var filePath string
	DB.db.QueryRow("SELECT file_path FROM backups WHERE id = ?", id).Scan(&filePath)

	os.Remove(filePath)
	DB.db.Exec("DELETE FROM backups WHERE id = ?", id)

	c.SuccessMessage("Backup deleted")
}

func (api *APIServer) downloadBackupHandler(c *Context) {
	id, _ := c.ParamInt("id")

	var filePath, fileName string
	DB.db.QueryRow("SELECT file_path, file_name FROM backups WHERE id = ?", id).Scan(&filePath, &fileName)

	c.SetHeader("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
	c.File(filePath)
}

// ============================================================================
// LOG HANDLERS
// ============================================================================

func (api *APIServer) getAuditLogsHandler(c *Context) {
	adminID := int64(c.QueryParamInt("admin_id", 0))
	limit := c.QueryParamInt("limit", 100)
	offset := c.QueryParamInt("offset", 0)

	logs, total, err := Security.GetAuditLogs(adminID, limit, offset)
	if err != nil {
		c.InternalError("Failed to get audit logs")
		return
	}

	c.JSON(http.StatusOK, PaginatedResponse(logs, total, offset/limit+1, limit))
}

func (api *APIServer) getConnectionLogsHandler(c *Context) {
	limit := c.QueryParamInt("limit", 100)
	offset := c.QueryParamInt("offset", 0)
	userID := int64(c.QueryParamInt("user_id", 0))

	query := `SELECT id, user_id, node_id, ip, location, protocol, inbound,
	          upload, download, duration, connected_at, disconnected_at
	          FROM connection_logs`
	args := []interface{}{}

	if userID > 0 {
		query += " WHERE user_id = ?"
		args = append(args, userID)
	}

	query += " ORDER BY connected_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := DB.db.Query(query, args...)
	if err != nil {
		c.InternalError("Failed to get connection logs")
		return
	}
	defer rows.Close()

	logs := []ConnectionLog{}
	for rows.Next() {
		var log ConnectionLog
		rows.Scan(&log.ID, &log.UserID, &log.NodeID, &log.IP, &log.Location,
			&log.Protocol, &log.Inbound, &log.Upload, &log.Download,
			&log.Duration, &log.ConnectedAt, &log.DisconnectedAt)
		logs = append(logs, log)
	}

	c.Success(logs)
}

func (api *APIServer) getSystemLogsHandler(c *Context) {
	lines := c.QueryParamInt("lines", 100)

	logPath := api.config.Logging.FilePath
	if logPath == "" {
		logPath = "./Data/logs/mxui.log"
	}

	content, err := readLastLines(logPath, lines)
	if err != nil {
		c.InternalError("Failed to read logs")
		return
	}

	c.Success(map[string]string{"logs": content})
}

// ============================================================================
// SYSTEM HANDLERS
// ============================================================================

func (api *APIServer) getSystemInfoHandler(c *Context) {
	info := map[string]interface{}{
		"version":    Version,
		"go_version": runtime.Version(),
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"cpus":       runtime.NumCPU(),
		"goroutines": runtime.NumGoroutine(),
		"panel_port": api.config.Panel.Port,
		"api_port":   api.config.API.Port,
	}

	c.Success(info)
}

func (api *APIServer) getSystemStatsHandler(c *Context) {
	stats, err := DB.GetSystemStats()
	if err != nil {
		c.InternalError("Failed to get system stats")
		return
	}

	c.Success(stats)
}

func (api *APIServer) rebootSystemHandler(c *Context) {
	// Schedule reboot
	go func() {
		time.Sleep(2 * time.Second)
		os.Exit(0) // Systemd will restart the service
	}()

	c.SuccessMessage("System will reboot in 2 seconds")
}

// ============================================================================
// BOT HANDLERS
// ============================================================================

func (api *APIServer) getBotConfigHandler(c *Context) {
	c.Success(api.config.Telegram)
}

func (api *APIServer) updateBotConfigHandler(c *Context) {
	var config TelegramConfig
	if err := c.Bind(&config); err != nil {
		c.BadRequest("Invalid request body")
		return
	}

	api.config.Telegram = config
	SaveConfig()

	c.SuccessMessage("Bot config updated")
}

func (api *APIServer) startBotHandler(c *Context) {
	c.SuccessMessage("Bot started")
}

func (api *APIServer) stopBotHandler(c *Context) {
	c.SuccessMessage("Bot stopped")
}

// ============================================================================
// AI HANDLERS
// ============================================================================

func (api *APIServer) getAIConfigHandler(c *Context) {
	c.Success(api.config.AI)
}

func (api *APIServer) updateAIConfigHandler(c *Context) {
	var config AIConfig
	if err := c.Bind(&config); err != nil {
		c.BadRequest("Invalid request body")
		return
	}

	api.config.AI = config
	SaveConfig()

	c.SuccessMessage("AI config updated")
}

func (api *APIServer) getAISuggestionHandler(c *Context) {
	var req struct {
		Query string `json:"query"`
	}
	c.Bind(&req)

	// Placeholder for AI suggestion
	c.Success(map[string]string{
		"suggestion": "AI suggestions would appear here based on your query.",
	})
}

// ============================================================================
// TEMPLATE HANDLERS
// ============================================================================

func (api *APIServer) listTemplatesHandler(c *Context) {
	rows, err := DB.db.Query(`
		SELECT id, name, type, content, is_active, is_default, created_at, updated_at
		FROM templates
	`)
	if err != nil {
		c.InternalError("Failed to list templates")
		return
	}
	defer rows.Close()

	templates := []Template{}
	for rows.Next() {
		var t Template
		rows.Scan(&t.ID, &t.Name, &t.Type, &t.Content, &t.IsActive,
			&t.IsDefault, &t.CreatedAt, &t.UpdatedAt)
		templates = append(templates, t)
	}

	c.Success(templates)
}

func (api *APIServer) getTemplateHandler(c *Context) {
	id, _ := c.ParamInt("id")

	var t Template
	err := DB.db.QueryRow(`
		SELECT id, name, type, content, is_active, is_default, created_at, updated_at
		FROM templates WHERE id = ?
	`, id).Scan(&t.ID, &t.Name, &t.Type, &t.Content, &t.IsActive,
		&t.IsDefault, &t.CreatedAt, &t.UpdatedAt)

	if err != nil {
		c.NotFound("Template not found")
		return
	}

	c.Success(t)
}

func (api *APIServer) updateTemplateHandler(c *Context) {
	id, _ := c.ParamInt("id")

	var req struct {
		Content  string `json:"content"`
		IsActive bool   `json:"is_active"`
	}
	c.Bind(&req)

	DB.db.Exec("UPDATE templates SET content = ?, is_active = ?, updated_at = ? WHERE id = ?",
		req.Content, req.IsActive, time.Now(), id)

	c.SuccessMessage("Template updated")
}

// ============================================================================
// SUBSCRIPTION HANDLERS
// ============================================================================

func (api *APIServer) subscriptionHandler(c *Context) {
	token := c.Param("token")

	user, err := Users.GetUserBySubscriptionURL(token)
	if err != nil {
		c.NotFound("Invalid subscription")
		return
	}

	// Validate access
	valid, msg := Users.ValidateUserAccess(user)
	if !valid {
		c.Error(http.StatusForbidden, msg)
		return
	}

	// Generate subscription content
	format := c.QueryParamDefault("format", "base64")
	clientType := c.QueryParam("client")

	var content string
	switch clientType {
	case "clash":
		content = api.generateClashConfig(user)
		c.SetHeader("Content-Type", "text/yaml")
	case "singbox":
		content = api.generateSingboxConfig(user)
		c.SetHeader("Content-Type", "application/json")
	default:
		content = api.generateV2rayLinks(user, format)
		c.SetHeader("Content-Type", "text/plain")
	}

	c.SetHeader("Subscription-Userinfo", fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d",
		user.UploadUsed, user.DownloadUsed, user.DataLimit,
		func() int64 {
			if user.ExpiryTime != nil {
				return user.ExpiryTime.Unix()
			}
			return 0
		}()))

	c.Writer.Write([]byte(content))
}

func (api *APIServer) subscriptionInfoHandler(c *Context) {
	token := c.Param("token")

	user, err := Users.GetUserBySubscriptionURL(token)
	if err != nil {
		c.NotFound("Invalid subscription")
		return
	}

	info, _ := Users.GetSubscriptionInfo(user.ID)
	c.Success(info)
}

func (api *APIServer) subscriptionClashHandler(c *Context) {
	token := c.Param("token")

	user, err := Users.GetUserBySubscriptionURL(token)
	if err != nil {
		c.NotFound("Invalid subscription")
		return
	}

	content := api.generateClashConfig(user)
	c.SetHeader("Content-Type", "text/yaml")
	c.Writer.Write([]byte(content))
}

func (api *APIServer) subscriptionSingboxHandler(c *Context) {
	token := c.Param("token")

	user, err := Users.GetUserBySubscriptionURL(token)
	if err != nil {
		c.NotFound("Invalid subscription")
		return
	}

	content := api.generateSingboxConfig(user)
	c.SetHeader("Content-Type", "application/json")
	c.Writer.Write([]byte(content))
}

func (api *APIServer) generateV2rayLinks(user *User, format string) string {
	// Generate V2Ray links for all inbounds
	// This is a placeholder - actual implementation would generate proper links
	return "vmess://..."
}

func (api *APIServer) generateClashConfig(user *User) string {
	// Generate Clash config
	// This is a placeholder
	return `
port: 7890
socks-port: 7891
proxies:
  - name: "MX-UI"
    type: vmess
    server: example.com
    port: 443
`
}

func (api *APIServer) generateSingboxConfig(user *User) string {
	// Generate Sing-box config
	config := map[string]interface{}{
		"outbounds": []interface{}{},
	}
	data, _ := json.MarshalIndent(config, "", "  ")
	return string(data)
}

// ============================================================================
// WEBHOOK HANDLERS
// ============================================================================

func (api *APIServer) telegramWebhookHandler(c *Context) {
	// Handle Telegram webhook
	body, _ := ioutil.ReadAll(c.Request.Body)

	// Process update
	// Placeholder - would be handled by bot module
	_ = body

	c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (api *APIServer) paymentWebhookHandler(c *Context) {
	// Handle payment webhook
	body, _ := ioutil.ReadAll(c.Request.Body)

	// Process payment
	// Placeholder - would be handled by payment module
	_ = body

	c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

// ============================================================================
// STATIC FILE HANDLERS
// ============================================================================

func (api *APIServer) healthHandler(c *Context) {
	status := "healthy"
	if DB != nil {
		if err := DB.HealthCheck(); err != nil {
			status = "degraded"
		}
	}

	c.Success(map[string]interface{}{
		"status":    status,
		"timestamp": time.Now(),
		"version":   Version,
	})
}

func (api *APIServer) serveIndexHandler(c *Context) {
	c.File("./Web/index.html")
}

func (api *APIServer) serveLoginHandler(c *Context) {
	c.File("./Web/login.html")
}

func (api *APIServer) serveDashboardHandler(c *Context) {
	c.File("./Web/dashboard.html")
}

// ============================================================================
// WEBHOOK MANAGER
// ============================================================================

// WebhookManager manages webhooks
type WebhookManager struct {
	webhooks map[string]*Webhook
	mu       sync.RWMutex
}

// Webhook represents a webhook configuration
type Webhook struct {
	ID      string            `json:"id"`
	URL     string            `json:"url"`
	Events  []string          `json:"events"`
	Secret  string            `json:"secret"`
	Headers map[string]string `json:"headers"`
	Active  bool              `json:"active"`
}

// NewWebhookManager creates a new webhook manager
func NewWebhookManager() *WebhookManager {
	return &WebhookManager{
		webhooks: make(map[string]*Webhook),
	}
}

// Trigger sends a webhook
func (wm *WebhookManager) Trigger(event string, data interface{}) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	for _, webhook := range wm.webhooks {
		if !webhook.Active {
			continue
		}

		for _, e := range webhook.Events {
			if e == event || e == "*" {
				go wm.send(webhook, event, data)
				break
			}
		}
	}
}

func (wm *WebhookManager) send(webhook *Webhook, event string, data interface{}) {
	payload := map[string]interface{}{
		"event":     event,
		"data":      data,
		"timestamp": time.Now().Unix(),
	}

	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", webhook.URL, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Event", event)

	if webhook.Secret != "" {
		signature := generateWebhookSignature(body, webhook.Secret)
		req.Header.Set("X-Webhook-Signature", signature)
	}

	for k, v := range webhook.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	client.Do(req)
}

func generateWebhookSignature(payload []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(payload)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// SetupPanelRoutes sets up panel routes (called from main.go)
func SetupPanelRoutes(mux *http.ServeMux) {
	if API == nil {
		return
	}

	// Serve static files
	fs := http.FileServer(http.Dir("./Web"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("./Web/assets"))))

	// Serve API
	mux.Handle("/", API.router)
}

func decoyHandler(w http.ResponseWriter, r *http.Request) {
	// Serve fake nginx/apache page
	decoyType := "nginx" // default
	if API != nil && API.config != nil {
		decoyType = API.config.Panel.DecoyType
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	switch decoyType {
	case "nginx":
		w.Write([]byte(nginxDecoyHTML))
	case "apache":
		w.Write([]byte(apacheDecoyHTML))
	default:
		w.Write([]byte(defaultDecoyHTML))
	}
}

const nginxDecoyHTML = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;}</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working.</p>
</body>
</html>`

const apacheDecoyHTML = `<!DOCTYPE html>
<html>
<head>
<title>Apache2 Ubuntu Default Page</title>
<style>body{font-family:'DejaVu Sans',sans-serif;font-size:13px;line-height:1.5;margin:0;padding:0;}</style>
</head>
<body>
<div style="padding:20px;text-align:center;">
<h1>Apache2 Ubuntu Default Page</h1>
<p>This is the default welcome page used to test the correct operation of the Apache2 server.</p>
</div>
</body>
</html>`

const defaultDecoyHTML = `<!DOCTYPE html>
<html>
<head>
<title>Welcome</title>
</head>
<body>
<h1>It works!</h1>
<p>This is the default web page for this server.</p>
</body>
</html>`

// SetupAPIRoutes sets up API routes (called from main.go)
func SetupAPIRoutes(mux *http.ServeMux) {
	if API == nil {
		return
	}

	mux.Handle("/", API.router)
}

// readLastLines reads the last n lines from a file
func readLastLines(filepath string, n int) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	stat, _ := file.Stat()
	size := stat.Size()

	if size == 0 {
		return "", nil
	}

	bufSize := int64(n * 200) // Estimate 200 bytes per line
	if bufSize > size {
		bufSize = size
	}

	buf := make([]byte, bufSize)
	file.Seek(-bufSize, 2)
	file.Read(buf)

	content := string(buf)
	lines := strings.Split(content, "\n")

	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}

	return strings.Join(lines, "\n"), nil
}

// generateSecureToken generates a secure random token
func generateSecureToken(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
