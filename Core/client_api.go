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
	ID        int64     `json:"id" db:"id"`
	Title     string    `json:"title" db:"title"`
	Message   string    `json:"message" db:"message"`
	Type      string    `json:"type" db:"type"` // info, warning, alert, promo
	Recipients string   `json:"recipients" db:"recipients"` // all, active, expired, user_id
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" db:"expires_at"`
}

// ClientNotificationResponse response for client notifications
type ClientNotificationResponse struct {
	Notifications []ClientNotification `json:"notifications"`
}

// ClientNotification notification for client
type ClientNotification struct {
	ID        int64     `json:"id"`
	Title     string    `json:"title"`
	Message   string    `json:"message"`
	Type      string    `json:"type"`
	CreatedAt string    `json:"created_at"`
	IsRead    bool      `json:"is_read"`
	Extra     map[string]interface{} `json:"extra,omitempty"`
}

// ============================================================================
// CLIENT API HANDLERS
// ============================================================================

// registerClientRoutes registers client-specific API routes
func registerClientRoutes(r *Router) {
	// Public endpoints (for subscription link access)
	r.GET("/api/v1/sub/:token", handleGetSubscription)
	r.GET("/api/v1/sub/:token/configs", handleGetSubscriptionConfigs)

	// Authenticated client endpoints
	r.GET("/api/v1/client/notifications", authMiddleware(handleClientNotifications))
	r.POST("/api/v1/client/notifications/:id/read", authMiddleware(handleMarkNotificationRead))
	r.GET("/api/v1/client/status", authMiddleware(handleClientStatus))
	r.GET("/api/v1/client/servers", authMiddleware(handleClientServers))
	r.POST("/api/v1/client/ping", authMiddleware(handleClientPing))
}

// handleGetSubscription returns subscription info for a user token
func handleGetSubscription(c *Context) {
	token := c.Params["token"]
	if token == "" {
		c.JSON(http.StatusBadRequest, APIResponse{Error: "Token required"})
		return
	}

	user := Users.GetUserBySubToken(token)
	if user == nil {
		c.JSON(http.StatusNotFound, APIResponse{Error: "Subscription not found"})
		return
	}

	// Check if user is active
	if user.Status != UserStatusActive {
		c.JSON(http.StatusForbidden, APIResponse{Error: "Subscription inactive"})
		return
	}

	response := map[string]interface{}{
		"username":    user.Username,
		"status":      user.Status,
		"expire":      user.Expire,
		"data_limit":  user.DataLimit,
		"used_traffic": user.UsedTraffic,
		"created_at":  user.CreatedAt,
	}

	c.JSON(http.StatusOK, response)
}

// handleGetSubscriptionConfigs returns VPN configs for a subscription
func handleGetSubscriptionConfigs(c *Context) {
	token := c.Params["token"]
	if token == "" {
		c.JSON(http.StatusBadRequest, APIResponse{Error: "Token required"})
		return
	}

	user := Users.GetUserBySubToken(token)
	if user == nil {
		c.JSON(http.StatusNotFound, APIResponse{Error: "Subscription not found"})
		return
	}

	// Generate configs for the user
	configs := generateUserConfigs(user)

	c.JSON(http.StatusOK, map[string]interface{}{
		"configs": configs,
	})
}

// handleClientNotifications returns notifications for the client
func handleClientNotifications(c *Context) {
	// Get since parameter
	sinceID := int64(0)
	if sinceStr := c.Query["since"]; sinceStr != "" {
		if parsed, err := strconv.ParseInt(sinceStr, 10, 64); err == nil {
			sinceID = parsed
		}
	}

	// Get user from context (set by auth middleware)
	userID := c.Claims.UserID

	// Get notifications from database
	notifications, err := getClientNotifications(userID, sinceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Error: "Failed to get notifications"})
		return
	}

	c.JSON(http.StatusOK, ClientNotificationResponse{
		Notifications: notifications,
	})
}

// handleMarkNotificationRead marks a notification as read
func handleMarkNotificationRead(c *Context) {
	notificationID, err := strconv.ParseInt(c.Params["id"], 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Error: "Invalid notification ID"})
		return
	}

	userID := c.Claims.UserID

	err = markNotificationRead(userID, notificationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Error: "Failed to mark as read"})
		return
	}

	c.JSON(http.StatusOK, APIResponse{Success: true})
}

// handleClientStatus returns current status for the client
func handleClientStatus(c *Context) {
	userID := c.Claims.UserID

	user, err := Users.GetUserByID(userID)
	if err != nil || user == nil {
		c.JSON(http.StatusNotFound, APIResponse{Error: "User not found"})
		return
	}

	// Calculate remaining data and days
	remainingData := int64(0)
	if user.DataLimit > 0 {
		remainingData = user.DataLimit - user.UsedTraffic
		if remainingData < 0 {
			remainingData = 0
		}
	}

	remainingDays := 0
	if user.Expire > 0 {
		expireTime := time.Unix(user.Expire, 0)
		remainingDays = int(time.Until(expireTime).Hours() / 24)
		if remainingDays < 0 {
			remainingDays = 0
		}
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"username":       user.Username,
		"status":         user.Status,
		"used_traffic":   user.UsedTraffic,
		"data_limit":     user.DataLimit,
		"remaining_data": remainingData,
		"expire":         user.Expire,
		"remaining_days": remainingDays,
		"online_count":   user.OnlineCount,
		"ip_limit":       user.IPLimit,
	})
}

// handleClientServers returns available servers for the client
func handleClientServers(c *Context) {
	userID := c.Claims.UserID

	user, err := Users.GetUserByID(userID)
	if err != nil || user == nil {
		c.JSON(http.StatusNotFound, APIResponse{Error: "User not found"})
		return
	}

	// Get available nodes
	nodes, err := Nodes.ListNodes(&NodeFilter{Status: "online"})
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Error: "Failed to get servers"})
		return
	}

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

	// Add other nodes
	for _, node := range nodes.Nodes {
		servers = append(servers, map[string]interface{}{
			"id":       node.ID,
			"name":     node.Name,
			"location": node.Address,
			"status":   node.Status,
			"ping":     node.Ping,
			"load":     node.Load,
		})
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"servers": servers,
	})
}

// handleClientPing handles client ping/heartbeat
func handleClientPing(c *Context) {
	userID := c.Claims.UserID

	// Update last seen
	_ = Users.UpdateLastSeen(userID)

	c.JSON(http.StatusOK, map[string]interface{}{
		"status": "ok",
		"time":   time.Now().Unix(),
	})
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// generateUserConfigs generates VPN configs for a user
func generateUserConfigs(user *User) []map[string]interface{} {
	configs := make([]map[string]interface{}, 0)

	// Get subscription links
	subLinks := Users.GetUserLinks(user.ID)

	for i, link := range subLinks {
		configs = append(configs, map[string]interface{}{
			"id":       i + 1,
			"name":     link.Name,
			"protocol": link.Protocol,
			"address":  link.Address,
			"port":     link.Port,
			"link":     link.Link,
		})
	}

	return configs
}

// getClientNotifications gets notifications for a client user
func getClientNotifications(userID int64, sinceID int64) ([]ClientNotification, error) {
	notifications := make([]ClientNotification, 0)

	query := `
		SELECT id, title, message, type, created_at
		FROM client_messages
		WHERE id > ? AND (recipients = 'all' OR recipients = ?)
		AND (expires_at IS NULL OR expires_at > ?)
		ORDER BY id DESC
		LIMIT 50
	`

	rows, err := DB.Query(query, sinceID, strconv.FormatInt(userID, 10), time.Now())
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
	query := `
		INSERT INTO notification_reads (user_id, notification_id, read_at)
		VALUES (?, ?, ?)
		ON CONFLICT DO NOTHING
	`
	_, err := DB.Exec(query, userID, notificationID, time.Now())
	return err
}

// ============================================================================
// ADMIN API - Send messages to clients
// ============================================================================

// CreateClientMessage creates a new message for clients
func CreateClientMessage(title, message, msgType, recipients string, expiresAt *time.Time) (*ClientMessage, error) {
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

	result, err := DB.Exec(query, msg.Title, msg.Message, msg.Type, msg.Recipients, msg.CreatedAt, msg.ExpiresAt)
	if err != nil {
		return nil, err
	}

	msg.ID, _ = result.LastInsertId()
	return msg, nil
}

// GetClientMessages gets all client messages
func GetClientMessages(limit int) ([]ClientMessage, error) {
	messages := make([]ClientMessage, 0)

	query := `
		SELECT id, title, message, type, recipients, created_at, expires_at
		FROM client_messages
		ORDER BY id DESC
		LIMIT ?
	`

	rows, err := DB.Query(query, limit)
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
func handleSendClientMessage(c *Context) {
	var req struct {
		Title      string `json:"title"`
		Message    string `json:"message"`
		Type       string `json:"type"`
		Recipients string `json:"recipients"`
		ExpiresIn  int    `json:"expires_in"` // hours
	}

	if err := json.NewDecoder(c.Request.Body).Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Error: "Invalid request"})
		return
	}

	if req.Title == "" || req.Message == "" {
		c.JSON(http.StatusBadRequest, APIResponse{Error: "Title and message required"})
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
		c.JSON(http.StatusInternalServerError, APIResponse{Error: "Failed to create message"})
		return
	}

	c.JSON(http.StatusCreated, msg)
}

// handleGetClientMessages handles getting all client messages (admin endpoint)
func handleGetClientMessages(c *Context) {
	limitStr := c.Query["limit"]
	limit := 50
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	messages, err := GetClientMessages(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Error: "Failed to get messages"})
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"messages": messages,
	})
}
