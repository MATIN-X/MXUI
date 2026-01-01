package core

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// ============================================================================
// CLIENT API - Endpoints for MXUI Flutter Client
// ============================================================================

// ClientMessage represents a message from panel to client
type ClientMessage struct {
	ID         int64      `json:"id" db:"id"`
	Title      string     `json:"title" db:"title"`
	Message    string     `json:"message" db:"message"`
	Type       string     `json:"type" db:"type"` // info, warning, alert, promo
	Recipients string     `json:"recipients" db:"recipients"` // all, active, expired, user_id
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty" db:"expires_at"`
}

// ClientNotificationResponse response for client notifications
type ClientNotificationResponse struct {
	Notifications []ClientNotification `json:"notifications"`
}

// ClientNotification notification for client
type ClientNotification struct {
	ID        int64                  `json:"id"`
	Title     string                 `json:"title"`
	Message   string                 `json:"message"`
	Type      string                 `json:"type"`
	CreatedAt string                 `json:"created_at"`
	IsRead    bool                   `json:"is_read"`
	Extra     map[string]interface{} `json:"extra,omitempty"`
}

// ============================================================================
// CLIENT API HANDLERS
// ============================================================================

// RegisterClientRoutes registers client-specific API routes
func (api *APIServer) RegisterClientRoutes(router *Router) {
	// Public endpoints (for subscription link access)
	router.GET("/api/v1/sub/:token", api.handleGetSubscription)
	router.GET("/api/v1/sub/:token/configs", api.handleGetSubscriptionConfigs)

	// Create authenticated client group
	clientGroup := router.Group("/api/v1/client")
	clientGroup.Use(AuthMiddlewareHandler())

	clientGroup.GET("/notifications", api.handleClientNotifications)
	clientGroup.POST("/notifications/:id/read", api.handleMarkNotificationRead)
	clientGroup.GET("/status", api.handleClientStatus)
	clientGroup.GET("/servers", api.handleClientServers)
	clientGroup.POST("/ping", api.handleClientPing)

	// Admin endpoints for managing client messages
	adminGroup := router.Group("/api/v1/admin/client")
	adminGroup.Use(AuthMiddlewareHandler())
	adminGroup.Use(OwnerOnlyMiddlewareHandler())

	adminGroup.POST("/messages", api.handleSendClientMessage)
	adminGroup.GET("/messages", api.handleGetClientMessages)
}

// handleGetSubscription returns subscription info for a user token
func (api *APIServer) handleGetSubscription(c *Context) {
	token := c.Params["token"]
	if token == "" {
		c.JSON(http.StatusBadRequest, Response{Error: "Token required"})
		return
	}

	if Users == nil {
		c.JSON(http.StatusInternalServerError, Response{Error: "User manager not initialized"})
		return
	}

	user, err := Users.GetUserBySubscriptionURL(token)
	if err != nil || user == nil {
		c.JSON(http.StatusNotFound, Response{Error: "Subscription not found"})
		return
	}

	// Check if user is active
	if user.Status != UserStatusActive {
		c.JSON(http.StatusForbidden, Response{Error: "Subscription inactive"})
		return
	}

	// Calculate expire timestamp
	var expireTS int64
	if user.ExpiryTime != nil {
		expireTS = user.ExpiryTime.Unix()
	}

	response := map[string]interface{}{
		"username":     user.Username,
		"status":       user.Status,
		"expire":       expireTS,
		"data_limit":   user.DataLimit,
		"used_traffic": user.DataUsed,
		"created_at":   user.CreatedAt.Unix(),
	}

	c.JSON(http.StatusOK, response)
}

// handleGetSubscriptionConfigs returns VPN configs for a subscription
func (api *APIServer) handleGetSubscriptionConfigs(c *Context) {
	token := c.Params["token"]
	if token == "" {
		c.JSON(http.StatusBadRequest, Response{Error: "Token required"})
		return
	}

	if Users == nil {
		c.JSON(http.StatusInternalServerError, Response{Error: "User manager not initialized"})
		return
	}

	user, err := Users.GetUserBySubscriptionURL(token)
	if err != nil || user == nil {
		c.JSON(http.StatusNotFound, Response{Error: "Subscription not found"})
		return
	}

	// Generate configs for the user
	configs := api.generateUserConfigs(user)

	c.JSON(http.StatusOK, map[string]interface{}{
		"configs": configs,
	})
}

// handleClientNotifications returns notifications for the client
func (api *APIServer) handleClientNotifications(c *Context) {
	// Get since parameter
	sinceID := int64(0)
	if sinceStr := c.Query["since"]; sinceStr != "" {
		if parsed, err := strconv.ParseInt(sinceStr, 10, 64); err == nil {
			sinceID = parsed
		}
	}

	// Get admin from context (set by auth middleware)
	adminID := c.Claims.AdminID

	// Get notifications from database
	notifications, err := getClientNotifications(adminID, sinceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Error: "Failed to get notifications"})
		return
	}

	c.JSON(http.StatusOK, ClientNotificationResponse{
		Notifications: notifications,
	})
}

// handleMarkNotificationRead marks a notification as read
func (api *APIServer) handleMarkNotificationRead(c *Context) {
	notificationID, err := strconv.ParseInt(c.Params["id"], 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, Response{Error: "Invalid notification ID"})
		return
	}

	adminID := c.Claims.AdminID

	err = markNotificationRead(adminID, notificationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Error: "Failed to mark as read"})
		return
	}

	c.JSON(http.StatusOK, Response{Success: true})
}

// handleClientStatus returns current status for the client
func (api *APIServer) handleClientStatus(c *Context) {
	adminID := c.Claims.AdminID

	if Users == nil {
		c.JSON(http.StatusInternalServerError, Response{Error: "User manager not initialized"})
		return
	}

	user, err := Users.GetUserByID(adminID)
	if err != nil || user == nil {
		c.JSON(http.StatusNotFound, Response{Error: "User not found"})
		return
	}

	// Calculate remaining data and days
	remainingData := int64(0)
	if user.DataLimit > 0 {
		remainingData = user.DataLimit - user.DataUsed
		if remainingData < 0 {
			remainingData = 0
		}
	}

	remainingDays := 0
	if user.ExpiryTime != nil {
		remainingDays = int(time.Until(*user.ExpiryTime).Hours() / 24)
		if remainingDays < 0 {
			remainingDays = 0
		}
	}

	var expireTS int64
	if user.ExpiryTime != nil {
		expireTS = user.ExpiryTime.Unix()
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"username":       user.Username,
		"status":         user.Status,
		"used_traffic":   user.DataUsed,
		"data_limit":     user.DataLimit,
		"remaining_data": remainingData,
		"expire":         expireTS,
		"remaining_days": remainingDays,
		"active_devices": user.ActiveDevices,
		"ip_limit":       user.IPLimit,
	})
}

// handleClientServers returns available servers for the client
func (api *APIServer) handleClientServers(c *Context) {
	servers := make([]map[string]interface{}, 0)

	// Add master node
	servers = append(servers, map[string]interface{}{
		"id":       "master",
		"name":     "Master Node",
		"location": "Auto",
		"status":   "online",
		"ping":     0,
		"load":     0,
	})

	// Get available nodes if nodes manager is initialized
	if Nodes != nil {
		nodeList := Nodes.ListNodes()
		for _, node := range nodeList {
			if node.Status == "online" {
				servers = append(servers, map[string]interface{}{
					"id":       node.ID,
					"name":     node.Name,
					"location": node.Address,
					"status":   node.Status,
					"ping":     0,
					"load":     node.CPUUsage,
				})
			}
		}
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"servers": servers,
	})
}

// handleClientPing handles client ping/heartbeat
func (api *APIServer) handleClientPing(c *Context) {
	c.JSON(http.StatusOK, map[string]interface{}{
		"status": "ok",
		"time":   time.Now().Unix(),
	})
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// generateUserConfigs generates VPN configs for a user
func (api *APIServer) generateUserConfigs(user *User) []map[string]interface{} {
	configs := make([]map[string]interface{}, 0)

	// Basic config info from user
	configs = append(configs, map[string]interface{}{
		"id":               1,
		"username":         user.Username,
		"uuid":             user.UUID,
		"subscription_url": user.SubscriptionURL,
	})

	return configs
}

// getClientNotifications gets notifications for a client user
func getClientNotifications(userID int64, sinceID int64) ([]ClientNotification, error) {
	notifications := make([]ClientNotification, 0)

	if DB == nil || DB.db == nil {
		return notifications, nil
	}

	query := `
		SELECT id, title, message, type, created_at
		FROM client_messages
		WHERE id > ? AND (recipients = 'all' OR recipients = ?)
		AND (expires_at IS NULL OR expires_at > ?)
		ORDER BY id DESC
		LIMIT 50
	`

	rows, err := DB.db.Query(query, sinceID, strconv.FormatInt(userID, 10), time.Now())
	if err != nil {
		return notifications, err
	}
	defer rows.Close()

	for rows.Next() {
		var msg ClientMessage
		err := rows.Scan(&msg.ID, &msg.Title, &msg.Message, &msg.Type, &msg.CreatedAt)
		if err != nil {
			continue
		}

		notifications = append(notifications, ClientNotification{
			ID:        msg.ID,
			Title:     msg.Title,
			Message:   msg.Message,
			Type:      msg.Type,
			CreatedAt: msg.CreatedAt.Format(time.RFC3339),
			IsRead:    false,
		})
	}

	return notifications, nil
}

// markNotificationRead marks a notification as read for a user
func markNotificationRead(userID int64, notificationID int64) error {
	if DB == nil || DB.db == nil {
		return nil
	}

	query := `
		INSERT INTO notification_reads (user_id, notification_id, read_at)
		VALUES (?, ?, ?)
		ON CONFLICT DO NOTHING
	`
	_, err := DB.db.Exec(query, userID, notificationID, time.Now())
	return err
}

// ============================================================================
// ADMIN API - Send messages to clients
// ============================================================================

// CreateClientMessage creates a new message for clients
func CreateClientMessage(title, message, msgType, recipients string, expiresAt *time.Time) (*ClientMessage, error) {
	if DB == nil || DB.db == nil {
		return nil, nil
	}

	msg := &ClientMessage{
		Title:      title,
		Message:    message,
		Type:       msgType,
		Recipients: recipients,
		CreatedAt:  time.Now(),
		ExpiresAt:  expiresAt,
	}

	query := `
		INSERT INTO client_messages (title, message, type, recipients, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`

	result, err := DB.db.Exec(query, msg.Title, msg.Message, msg.Type, msg.Recipients, msg.CreatedAt, msg.ExpiresAt)
	if err != nil {
		return nil, err
	}

	msg.ID, _ = result.LastInsertId()
	return msg, nil
}

// GetClientMessages gets all client messages
func GetClientMessages(limit int) ([]ClientMessage, error) {
	messages := make([]ClientMessage, 0)

	if DB == nil || DB.db == nil {
		return messages, nil
	}

	query := `
		SELECT id, title, message, type, recipients, created_at, expires_at
		FROM client_messages
		ORDER BY id DESC
		LIMIT ?
	`

	rows, err := DB.db.Query(query, limit)
	if err != nil {
		return messages, err
	}
	defer rows.Close()

	for rows.Next() {
		var msg ClientMessage
		err := rows.Scan(&msg.ID, &msg.Title, &msg.Message, &msg.Type, &msg.Recipients, &msg.CreatedAt, &msg.ExpiresAt)
		if err != nil {
			continue
		}
		messages = append(messages, msg)
	}

	return messages, nil
}

// handleSendClientMessage handles sending a message to clients (admin endpoint)
func (api *APIServer) handleSendClientMessage(c *Context) {
	var req struct {
		Title      string `json:"title"`
		Message    string `json:"message"`
		Type       string `json:"type"`
		Recipients string `json:"recipients"`
		ExpiresIn  int    `json:"expires_in"` // hours
	}

	if err := json.NewDecoder(c.Request.Body).Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{Error: "Invalid request"})
		return
	}

	if req.Title == "" || req.Message == "" {
		c.JSON(http.StatusBadRequest, Response{Error: "Title and message required"})
		return
	}

	if req.Type == "" {
		req.Type = "info"
	}
	if req.Recipients == "" {
		req.Recipients = "all"
	}

	var expiresAt *time.Time
	if req.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresIn) * time.Hour)
		expiresAt = &t
	}

	msg, err := CreateClientMessage(req.Title, req.Message, req.Type, req.Recipients, expiresAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Error: "Failed to create message"})
		return
	}

	c.JSON(http.StatusCreated, msg)
}

// handleGetClientMessages handles getting all client messages (admin endpoint)
func (api *APIServer) handleGetClientMessages(c *Context) {
	limitStr := c.Query["limit"]
	limit := 50
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	messages, err := GetClientMessages(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Error: "Failed to get messages"})
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"messages": messages,
	})
}
