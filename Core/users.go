// MXUI VPN Panel
// Core/users.go
// User Management: CRUD, Subscription, Traffic, Device Limit, Online Users, Trial, OnHold

package core

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// CONSTANTS
// ============================================================================

const (
	// Subscription URL prefix
	SubscriptionURLPrefix = "sub"
	SubscriptionURLLength = 16

	// Default limits
	DefaultDataLimit   = 0 // 0 = unlimited
	DefaultDeviceLimit = 0 // 0 = unlimited
	DefaultIPLimit     = 0 // 0 = unlimited

	// Trial defaults
	DefaultTrialDuration = 24 * time.Hour
	DefaultTrialTraffic  = 1 * 1024 * 1024 * 1024 // 1 GB

	// Cleanup intervals
	OnlineUserTimeout    = 2 * time.Minute
	DeviceCleanupTimeout = 30 * 24 * time.Hour // 30 days
)

// ============================================================================
// USER MANAGER
// ============================================================================

// UserManager handles all user operations
type UserManager struct {
	onlineUsers   map[int64]map[string]*OnlineUser // userID -> IP -> OnlineUser
	userDevices   map[int64]map[string]*UserDevice // userID -> deviceID -> Device
	trafficCache  map[int64]*TrafficInfo           // userID -> traffic info
	mu            sync.RWMutex
	onlineMu      sync.RWMutex
	deviceMu      sync.RWMutex
	trafficMu     sync.RWMutex
	cleanupTicker *time.Ticker
	trafficTicker *time.Ticker
	stopChan      chan struct{}
}

// TrafficInfo holds cached traffic information
type TrafficInfo struct {
	Upload    int64
	Download  int64
	UpdatedAt time.Time
}

// Global user manager instance
var Users *UserManager

// InitUserManager initializes the user manager
func InitUserManager() error {
	Users = &UserManager{
		onlineUsers:  make(map[int64]map[string]*OnlineUser),
		userDevices:  make(map[int64]map[string]*UserDevice),
		trafficCache: make(map[int64]*TrafficInfo),
		stopChan:     make(chan struct{}),
	}

	// Start background tasks
	go Users.startCleanupRoutine()
	go Users.startTrafficResetRoutine()

	return nil
}

// Stop stops the user manager
func (um *UserManager) Stop() {
	close(um.stopChan)
	if um.cleanupTicker != nil {
		um.cleanupTicker.Stop()
	}
	if um.trafficTicker != nil {
		um.trafficTicker.Stop()
	}
}

// ============================================================================
// USER CRUD OPERATIONS
// ============================================================================

// CreateUserRequest represents a request to create a user
type CreateUserRequest struct {
	Username           string     `json:"username"`
	Email              string     `json:"email,omitempty"`
	Note               string     `json:"note,omitempty"`
	Tags               []string   `json:"tags,omitempty"`
	DataLimit          int64      `json:"data_limit"`  // bytes, 0 = unlimited
	ExpiryDays         int        `json:"expiry_days"` // 0 = never expires
	ExpiryTime         *time.Time `json:"expiry_time,omitempty"`
	DeviceLimit        int        `json:"device_limit"`         // 0 = unlimited
	IPLimit            int        `json:"ip_limit"`             // 0 = unlimited
	TrafficResetPeriod string     `json:"traffic_reset_period"` // none, daily, weekly, monthly, yearly
	OnHoldExpireDays   int        `json:"on_hold_expire_days"`  // days to expire after first connect
	EnabledProtocols   []string   `json:"enabled_protocols,omitempty"`
	EnabledInbounds    []string   `json:"enabled_inbounds,omitempty"`
	TelegramID         int64      `json:"telegram_id,omitempty"`
	SubscriptionPath   string     `json:"subscription_path,omitempty"`
	TemplateID         int64      `json:"template_id,omitempty"` // Create from template
	AdminNote          string     `json:"admin_note,omitempty"`  // Private note for admin

	CreatedByAdminID int64 `json:"created_by_admin_id"`
	IsTrial          bool  `json:"is_trial"`
}

// NextPlanConfig represents a queued subscription plan
type NextPlanConfig struct {
	ID          int64      `json:"id"`
	UserID      int64      `json:"user_id"`
	DataLimit   int64      `json:"data_limit"`
	ExpiryDays  int        `json:"expiry_days"`
	DeviceLimit int        `json:"device_limit"`
	IPLimit     int        `json:"ip_limit"`
	ActivateAt  *time.Time `json:"activate_at,omitempty"` // nil = activate after current expires
	CreatedAt   time.Time  `json:"created_at"`
	Activated   bool       `json:"activated"`
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
}

// UserNote represents an admin note for a user
type UserNote struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	AdminID   int64     `json:"admin_id"`
	Content   string    `json:"content"`
	IsPrivate bool      `json:"is_private"` // Only visible to admin who created it
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UpdateUserRequest represents a request to update a user
type UpdateUserRequest struct {
	Email              *string    `json:"email,omitempty"`
	Note               *string    `json:"note,omitempty"`
	Tags               []string   `json:"tags,omitempty"`
	DataLimit          *int64     `json:"data_limit,omitempty"`
	ExpiryTime         *time.Time `json:"expiry_time,omitempty"`
	DeviceLimit        *int       `json:"device_limit,omitempty"`
	IPLimit            *int       `json:"ip_limit,omitempty"`
	TrafficResetPeriod *string    `json:"traffic_reset_period,omitempty"`
	OnHoldExpireDays   *int       `json:"on_hold_expire_days,omitempty"`
	EnabledProtocols   []string   `json:"enabled_protocols,omitempty"`
	EnabledInbounds    []string   `json:"enabled_inbounds,omitempty"`
	Status             *string    `json:"status,omitempty"`
	IsActive           *bool      `json:"is_active,omitempty"`
}

// CreateUser creates a new VPN user
func (um *UserManager) CreateUser(req *CreateUserRequest) (*User, error) {
	// Validate username
	if err := ValidateUsername(req.Username); err != nil {
		return nil, err
	}

	// Check if username exists
	var count int
	DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", req.Username).Scan(&count)
	if count > 0 {
		return nil, errors.New("username already exists")
	}

	// Validate email if provided
	if req.Email != "" {
		if err := ValidateEmail(req.Email); err != nil {
			return nil, err
		}
	}

	// Generate UUID and subscription URL
	userUUID := uuid.New().String()

	// Use custom subscription path if provided, otherwise generate
	subscriptionURL := req.SubscriptionPath
	if subscriptionURL == "" {
		subscriptionURL = generateSubscriptionURL()
	}

	// Calculate expiry time
	var expiryTime *time.Time
	if req.ExpiryTime != nil {
		expiryTime = req.ExpiryTime
	} else if req.ExpiryDays > 0 {
		t := time.Now().AddDate(0, 0, req.ExpiryDays)
		expiryTime = &t
	}

	// Set trial defaults
	if req.IsTrial {
		if req.DataLimit == 0 {
			req.DataLimit = DefaultTrialTraffic
		}
		if expiryTime == nil {
			t := time.Now().Add(DefaultTrialDuration)
			expiryTime = &t
		}
	}

	// Default traffic reset period
	if req.TrafficResetPeriod == "" {
		req.TrafficResetPeriod = TrafficResetNone
	}

	// Determine initial status
	status := UserStatusActive
	if req.OnHoldExpireDays > 0 {
		status = UserStatusOnHold
	}

	now := time.Now()

	// Insert user
	result, err := DB.db.Exec(`
		INSERT INTO users (
			uuid, username, email, note, tags, status, is_active,
			subscription_url, expiry_time, on_hold_expire_days,
			data_limit, device_limit, ip_limit, traffic_reset_period,
			enabled_protocols, enabled_inbounds, created_by_admin_id,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		userUUID, req.Username, req.Email, req.Note, StringSliceToJSON(req.Tags),
		status, true, subscriptionURL, expiryTime, req.OnHoldExpireDays,
		req.DataLimit, req.DeviceLimit, req.IPLimit, req.TrafficResetPeriod,
		StringSliceToJSON(req.EnabledProtocols), StringSliceToJSON(req.EnabledInbounds),
		req.CreatedByAdminID, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	userID, _ := result.LastInsertId()

	// Update admin's user count
	DB.db.Exec("UPDATE admins SET users_created = users_created + 1 WHERE id = ?", req.CreatedByAdminID)

	// Create wallet for user
	DB.db.Exec("INSERT INTO wallets (user_id, balance, currency) VALUES (?, 0, 'USD')", userID)

	return um.GetUserByID(userID)
}

// GetUserByID retrieves a user by ID
func (um *UserManager) GetUserByID(id int64) (*User, error) {
	user := &User{}
	var tags, protocols, inbounds string

	err := DB.db.QueryRow(`
		SELECT id, uuid, username, email, note, tags, status, is_active,
		       subscription_url, expiry_time, on_hold_expire_days, on_hold_timeout,
		       data_limit, data_used, upload_used, download_used,
		       traffic_reset_period, last_traffic_reset,
		       device_limit, ip_limit, enabled_protocols, enabled_inbounds,
		       created_by_admin_id, last_online, last_ip, created_at, updated_at
		FROM users WHERE id = ?
	`, id).Scan(
		&user.ID, &user.UUID, &user.Username, &user.Email, &user.Note, &tags,
		&user.Status, &user.IsActive, &user.SubscriptionURL, &user.ExpiryTime,
		&user.OnHoldExpireDays, &user.OnHoldTimeout, &user.DataLimit, &user.DataUsed,
		&user.UploadUsed, &user.DownloadUsed, &user.TrafficResetPeriod,
		&user.LastTrafficReset, &user.DeviceLimit, &user.IPLimit,
		&protocols, &inbounds, &user.CreatedByAdminID,
		&user.LastOnline, &user.LastIP, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	user.Tags = JSONToStringSlice(tags)
	user.EnabledProtocols = JSONToStringSlice(protocols)
	user.EnabledInbounds = JSONToStringSlice(inbounds)

	return user, nil
}

// GetUserByUUID retrieves a user by UUID
func (um *UserManager) GetUserByUUID(uuid string) (*User, error) {
	var id int64
	err := DB.db.QueryRow("SELECT id FROM users WHERE uuid = ?", uuid).Scan(&id)
	if err != nil {
		return nil, err
	}
	return um.GetUserByID(id)
}

// GetUserByUsername retrieves a user by username
func (um *UserManager) GetUserByUsername(username string) (*User, error) {
	var id int64
	err := DB.db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&id)
	if err != nil {
		return nil, err
	}
	return um.GetUserByID(id)
}

// GetUserBySubscriptionURL retrieves a user by subscription URL
func (um *UserManager) GetUserBySubscriptionURL(subURL string) (*User, error) {
	var id int64
	err := DB.db.QueryRow("SELECT id FROM users WHERE subscription_url = ?", subURL).Scan(&id)
	if err != nil {
		return nil, err
	}
	return um.GetUserByID(id)
}

// UpdateUser updates a user
func (um *UserManager) UpdateUser(id int64, req *UpdateUserRequest) (*User, error) {
	// Build update query dynamically
	updates := []string{}
	args := []interface{}{}

	if req.Email != nil {
		if *req.Email != "" {
			if err := ValidateEmail(*req.Email); err != nil {
				return nil, err
			}
		}
		updates = append(updates, "email = ?")
		args = append(args, *req.Email)
	}

	if req.Note != nil {
		updates = append(updates, "note = ?")
		args = append(args, *req.Note)
	}

	if req.Tags != nil {
		updates = append(updates, "tags = ?")
		args = append(args, StringSliceToJSON(req.Tags))
	}

	if req.DataLimit != nil {
		updates = append(updates, "data_limit = ?")
		args = append(args, *req.DataLimit)
	}

	if req.ExpiryTime != nil {
		updates = append(updates, "expiry_time = ?")
		args = append(args, *req.ExpiryTime)
	}

	if req.DeviceLimit != nil {
		updates = append(updates, "device_limit = ?")
		args = append(args, *req.DeviceLimit)
	}

	if req.IPLimit != nil {
		updates = append(updates, "ip_limit = ?")
		args = append(args, *req.IPLimit)
	}

	if req.TrafficResetPeriod != nil {
		updates = append(updates, "traffic_reset_period = ?")
		args = append(args, *req.TrafficResetPeriod)
	}

	if req.OnHoldExpireDays != nil {
		updates = append(updates, "on_hold_expire_days = ?")
		args = append(args, *req.OnHoldExpireDays)
	}

	if req.EnabledProtocols != nil {
		updates = append(updates, "enabled_protocols = ?")
		args = append(args, StringSliceToJSON(req.EnabledProtocols))
	}

	if req.EnabledInbounds != nil {
		updates = append(updates, "enabled_inbounds = ?")
		args = append(args, StringSliceToJSON(req.EnabledInbounds))
	}

	if req.Status != nil {
		updates = append(updates, "status = ?")
		args = append(args, *req.Status)
	}

	if req.IsActive != nil {
		updates = append(updates, "is_active = ?")
		args = append(args, *req.IsActive)
	}

	if len(updates) == 0 {
		return um.GetUserByID(id)
	}

	updates = append(updates, "updated_at = ?")
	args = append(args, time.Now())
	args = append(args, id)

	query := fmt.Sprintf("UPDATE users SET %s WHERE id = ?", strings.Join(updates, ", "))
	_, err := DB.db.Exec(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return um.GetUserByID(id)
}

// DeleteUser deletes a user
func (um *UserManager) DeleteUser(id int64) error {
	// Get user first for admin reference
	user, err := um.GetUserByID(id)
	if err != nil {
		return err
	}

	// Delete user
	_, err = DB.db.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		return err
	}

	// Update admin's user count
	DB.db.Exec("UPDATE admins SET users_created = users_created - 1 WHERE id = ? AND users_created > 0", user.CreatedByAdminID)

	// Clear from online users cache
	um.onlineMu.Lock()
	delete(um.onlineUsers, id)
	um.onlineMu.Unlock()

	// Clear from device cache
	um.deviceMu.Lock()
	delete(um.userDevices, id)
	um.deviceMu.Unlock()

	return nil
}

// ============================================================================
// USER LISTING & SEARCH
// ============================================================================

// UserFilter represents filters for user listing
type UserFilter struct {
	Search          string     `json:"search,omitempty"`
	Status          string     `json:"status,omitempty"`
	AdminID         int64      `json:"admin_id,omitempty"`
	Tags            []string   `json:"tags,omitempty"`
	IsOnline        *bool      `json:"is_online,omitempty"`
	IsExpired       *bool      `json:"is_expired,omitempty"`
	IsLimited       *bool      `json:"is_limited,omitempty"`
	ExpiringInDays  int        `json:"expiring_in_days,omitempty"`
	TrafficUsageMin int        `json:"traffic_usage_min,omitempty"` // percentage
	TrafficUsageMax int        `json:"traffic_usage_max,omitempty"` // percentage
	CreatedAfter    *time.Time `json:"created_after,omitempty"`
	CreatedBefore   *time.Time `json:"created_before,omitempty"`
	SortBy          string     `json:"sort_by,omitempty"`    // username, created_at, expiry_time, data_used
	SortOrder       string     `json:"sort_order,omitempty"` // asc, desc
	Limit           int        `json:"limit,omitempty"`
	Offset          int        `json:"offset,omitempty"`
}

// UserListResult represents paginated user list result
type UserListResult struct {
	Users      []*User `json:"users"`
	Total      int     `json:"total"`
	Limit      int     `json:"limit"`
	Offset     int     `json:"offset"`
	TotalPages int     `json:"total_pages"`
}

// ListUsers lists users with filtering and pagination
func (um *UserManager) ListUsers(filter *UserFilter) (*UserListResult, error) {
	// Build query
	baseQuery := `
		SELECT id, uuid, username, email, note, tags, status, is_active,
		       subscription_url, expiry_time, on_hold_expire_days, on_hold_timeout,
		       data_limit, data_used, upload_used, download_used,
		       traffic_reset_period, last_traffic_reset,
		       device_limit, ip_limit, enabled_protocols, enabled_inbounds,
		       created_by_admin_id, last_online, last_ip, created_at, updated_at
		FROM users
	`
	countQuery := "SELECT COUNT(*) FROM users"

	where := []string{}
	args := []interface{}{}

	// Search filter
	if filter.Search != "" {
		where = append(where, "(username LIKE ? OR email LIKE ? OR note LIKE ? OR uuid LIKE ?)")
		searchTerm := "%" + filter.Search + "%"
		args = append(args, searchTerm, searchTerm, searchTerm, searchTerm)
	}

	// Status filter
	if filter.Status != "" {
		where = append(where, "status = ?")
		args = append(args, filter.Status)
	}

	// Admin filter
	if filter.AdminID > 0 {
		where = append(where, "created_by_admin_id = ?")
		args = append(args, filter.AdminID)
	}

	// Tags filter
	if len(filter.Tags) > 0 {
		for _, tag := range filter.Tags {
			where = append(where, "tags LIKE ?")
			args = append(args, "%"+tag+"%")
		}
	}

	// Expired filter
	if filter.IsExpired != nil {
		if *filter.IsExpired {
			where = append(where, "expiry_time IS NOT NULL AND expiry_time < ?")
		} else {
			where = append(where, "(expiry_time IS NULL OR expiry_time >= ?)")
		}
		args = append(args, time.Now())
	}

	// Limited filter (traffic exceeded)
	if filter.IsLimited != nil {
		if *filter.IsLimited {
			where = append(where, "data_limit > 0 AND data_used >= data_limit")
		} else {
			where = append(where, "(data_limit = 0 OR data_used < data_limit)")
		}
	}

	// Expiring soon filter
	if filter.ExpiringInDays > 0 {
		expiryDate := time.Now().AddDate(0, 0, filter.ExpiringInDays)
		where = append(where, "expiry_time IS NOT NULL AND expiry_time BETWEEN ? AND ?")
		args = append(args, time.Now(), expiryDate)
	}

	// Traffic usage percentage filter
	if filter.TrafficUsageMin > 0 {
		where = append(where, "data_limit > 0 AND (data_used * 100 / data_limit) >= ?")
		args = append(args, filter.TrafficUsageMin)
	}
	if filter.TrafficUsageMax > 0 {
		where = append(where, "data_limit > 0 AND (data_used * 100 / data_limit) <= ?")
		args = append(args, filter.TrafficUsageMax)
	}

	// Date range filter
	if filter.CreatedAfter != nil {
		where = append(where, "created_at >= ?")
		args = append(args, *filter.CreatedAfter)
	}
	if filter.CreatedBefore != nil {
		where = append(where, "created_at <= ?")
		args = append(args, *filter.CreatedBefore)
	}

	// Build WHERE clause
	whereClause := ""
	if len(where) > 0 {
		whereClause = " WHERE " + strings.Join(where, " AND ")
	}

	// Get total count
	var total int
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)
	DB.db.QueryRow(countQuery+whereClause, countArgs...).Scan(&total)

	// Add sorting
	sortBy := "created_at"
	sortOrder := "DESC"
	if filter.SortBy != "" {
		validSorts := map[string]bool{"username": true, "created_at": true, "expiry_time": true, "data_used": true, "last_online": true}
		if validSorts[filter.SortBy] {
			sortBy = filter.SortBy
		}
	}
	if filter.SortOrder != "" && (filter.SortOrder == "asc" || filter.SortOrder == "ASC") {
		sortOrder = "ASC"
	}

	// Add pagination
	limit := 50
	if filter.Limit > 0 && filter.Limit <= 100 {
		limit = filter.Limit
	}
	offset := filter.Offset

	query := fmt.Sprintf("%s%s ORDER BY %s %s LIMIT ? OFFSET ?", baseQuery, whereClause, sortBy, sortOrder)
	args = append(args, limit, offset)

	rows, err := DB.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := []*User{}
	for rows.Next() {
		user := &User{}
		var tags, protocols, inbounds string

		err := rows.Scan(
			&user.ID, &user.UUID, &user.Username, &user.Email, &user.Note, &tags,
			&user.Status, &user.IsActive, &user.SubscriptionURL, &user.ExpiryTime,
			&user.OnHoldExpireDays, &user.OnHoldTimeout, &user.DataLimit, &user.DataUsed,
			&user.UploadUsed, &user.DownloadUsed, &user.TrafficResetPeriod,
			&user.LastTrafficReset, &user.DeviceLimit, &user.IPLimit,
			&protocols, &inbounds, &user.CreatedByAdminID,
			&user.LastOnline, &user.LastIP, &user.CreatedAt, &user.UpdatedAt,
		)
		if err != nil {
			continue
		}

		user.Tags = JSONToStringSlice(tags)
		user.EnabledProtocols = JSONToStringSlice(protocols)
		user.EnabledInbounds = JSONToStringSlice(inbounds)

		users = append(users, user)
	}

	totalPages := (total + limit - 1) / limit

	return &UserListResult{
		Users:      users,
		Total:      total,
		Limit:      limit,
		Offset:     offset,
		TotalPages: totalPages,
	}, nil
}

// GetAllUsersByAdmin retrieves all users created by an admin
func (um *UserManager) GetAllUsersByAdmin(adminID int64) ([]*User, error) {
	result, err := um.ListUsers(&UserFilter{
		AdminID: adminID,
		Limit:   10000,
	})
	if err != nil {
		return nil, err
	}
	return result.Users, nil
}

// ============================================================================
// STATUS MANAGEMENT
// ============================================================================

// UpdateUserStatus updates user status
func (um *UserManager) UpdateUserStatus(id int64, status string) error {
	validStatuses := map[string]bool{
		UserStatusActive:   true,
		UserStatusExpired:  true,
		UserStatusDisabled: true,
		UserStatusLimited:  true,
		UserStatusOnHold:   true,
	}

	if !validStatuses[status] {
		return errors.New("invalid status")
	}

	_, err := DB.db.Exec("UPDATE users SET status = ?, updated_at = ? WHERE id = ?",
		status, time.Now(), id)
	return err
}

// EnableUser enables a user
func (um *UserManager) EnableUser(id int64) error {
	_, err := DB.db.Exec("UPDATE users SET is_active = 1, status = ?, updated_at = ? WHERE id = ?",
		UserStatusActive, time.Now(), id)
	return err
}

// DisableUser disables a user
func (um *UserManager) DisableUser(id int64) error {
	_, err := DB.db.Exec("UPDATE users SET is_active = 0, status = ?, updated_at = ? WHERE id = ?",
		UserStatusDisabled, time.Now(), id)

	// Disconnect user if online
	um.DisconnectUser(id)

	return err
}

// SuspendUser puts user on hold
func (um *UserManager) SuspendUser(id int64) error {
	_, err := DB.db.Exec("UPDATE users SET status = ?, updated_at = ? WHERE id = ?",
		UserStatusOnHold, time.Now(), id)

	um.DisconnectUser(id)
	return err
}

// CheckAndUpdateUserStatus checks and updates user status based on conditions
func (um *UserManager) CheckAndUpdateUserStatus(user *User) string {
	now := time.Now()
	newStatus := user.Status

	// Check if disabled
	if !user.IsActive {
		newStatus = UserStatusDisabled
	} else if user.Status == UserStatusOnHold {
		// On hold user - check if should activate
		if user.OnHoldTimeout != nil && now.After(*user.OnHoldTimeout) {
			newStatus = UserStatusExpired
		}
	} else {
		// Check expiry
		if user.ExpiryTime != nil && now.After(*user.ExpiryTime) {
			newStatus = UserStatusExpired
		} else if user.DataLimit > 0 && user.DataUsed >= user.DataLimit {
			// Check traffic limit
			newStatus = UserStatusLimited
		} else {
			newStatus = UserStatusActive
		}
	}

	// Update if changed
	if newStatus != user.Status {
		um.UpdateUserStatus(user.ID, newStatus)
	}

	return newStatus
}

// ActivateOnHoldUser activates an on-hold user (called on first connection)
func (um *UserManager) ActivateOnHoldUser(id int64) error {
	user, err := um.GetUserByID(id)
	if err != nil {
		return err
	}

	if user.Status != UserStatusOnHold {
		return nil // Not on hold
	}

	now := time.Now()
	var expiryTime *time.Time
	var onHoldTimeout *time.Time

	if user.OnHoldExpireDays > 0 {
		t := now.AddDate(0, 0, user.OnHoldExpireDays)
		expiryTime = &t
		onHoldTimeout = &t
	}

	_, err = DB.db.Exec(`
		UPDATE users SET 
			status = ?, 
			expiry_time = ?, 
			on_hold_timeout = ?,
			updated_at = ?
		WHERE id = ?
	`, UserStatusActive, expiryTime, onHoldTimeout, now, id)

	return err
}

// ============================================================================
// TRAFFIC MANAGEMENT
// ============================================================================

// AddTraffic adds traffic to a user
func (um *UserManager) AddTraffic(id int64, upload, download int64) error {
	um.trafficMu.Lock()
	defer um.trafficMu.Unlock()

	// Update cache
	if _, exists := um.trafficCache[id]; !exists {
		um.trafficCache[id] = &TrafficInfo{}
	}
	um.trafficCache[id].Upload += upload
	um.trafficCache[id].Download += download
	um.trafficCache[id].UpdatedAt = time.Now()

	// Update database
	_, err := DB.db.Exec(`
		UPDATE users SET 
			data_used = data_used + ?,
			upload_used = upload_used + ?,
			download_used = download_used + ?,
			updated_at = ?
		WHERE id = ?
	`, upload+download, upload, download, time.Now(), id)

	if err != nil {
		return err
	}

	// Check if traffic limit exceeded
	go um.checkTrafficLimit(id)

	// Update admin traffic
	go um.updateAdminTraffic(id, upload+download)

	return nil
}

// checkTrafficLimit checks if user exceeded traffic limit
func (um *UserManager) checkTrafficLimit(id int64) {
	user, err := um.GetUserByID(id)
	if err != nil {
		return
	}

	if user.DataLimit > 0 && user.DataUsed >= user.DataLimit {
		um.UpdateUserStatus(id, UserStatusLimited)
		um.DisconnectUser(id)
	}
}

// updateAdminTraffic updates admin's total traffic
func (um *UserManager) updateAdminTraffic(userID, traffic int64) {
	var adminID int64
	DB.db.QueryRow("SELECT created_by_admin_id FROM users WHERE id = ?", userID).Scan(&adminID)
	if adminID > 0 {
		DB.db.Exec("UPDATE admins SET traffic_used = traffic_used + ? WHERE id = ?", traffic, adminID)
	}
}

// ResetUserTraffic resets user traffic to zero
func (um *UserManager) ResetUserTraffic(id int64) error {
	now := time.Now()
	_, err := DB.db.Exec(`
		UPDATE users SET 
			data_used = 0,
			upload_used = 0,
			download_used = 0,
			last_traffic_reset = ?,
			status = CASE WHEN status = ? THEN ? ELSE status END,
			updated_at = ?
		WHERE id = ?
	`, now, UserStatusLimited, UserStatusActive, now, id)

	// Clear cache
	um.trafficMu.Lock()
	delete(um.trafficCache, id)
	um.trafficMu.Unlock()

	return err
}

// GetUserTraffic returns user traffic info
func (um *UserManager) GetUserTraffic(id int64) (used, limit, upload, download int64, err error) {
	err = DB.db.QueryRow(`
		SELECT data_used, data_limit, upload_used, download_used
		FROM users WHERE id = ?
	`, id).Scan(&used, &limit, &upload, &download)
	return
}

// GetTrafficUsagePercent returns traffic usage percentage
func (um *UserManager) GetTrafficUsagePercent(user *User) float64 {
	if user.DataLimit == 0 {
		return 0
	}
	return float64(user.DataUsed) / float64(user.DataLimit) * 100
}

// ============================================================================
// TRAFFIC RESET SCHEDULER
// ============================================================================

// startTrafficResetRoutine starts the periodic traffic reset routine
func (um *UserManager) startTrafficResetRoutine() {
	um.trafficTicker = time.NewTicker(1 * time.Hour)
	defer um.trafficTicker.Stop()

	for {
		select {
		case <-um.trafficTicker.C:
			um.processTrafficResets()
		case <-um.stopChan:
			return
		}
	}
}

// processTrafficResets resets traffic for users based on their reset period
func (um *UserManager) processTrafficResets() {
	now := time.Now()

	// Daily reset
	rows, err := DB.db.Query(`
		SELECT id FROM users 
		WHERE traffic_reset_period = ? 
		AND (last_traffic_reset IS NULL OR last_traffic_reset < ?)
	`, TrafficResetDaily, now.Truncate(24*time.Hour))
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id int64
			rows.Scan(&id)
			um.ResetUserTraffic(id)
		}
	}

	// Weekly reset (Monday)
	if now.Weekday() == time.Monday {
		weekStart := now.Truncate(24 * time.Hour)
		rows, err := DB.db.Query(`
			SELECT id FROM users 
			WHERE traffic_reset_period = ? 
			AND (last_traffic_reset IS NULL OR last_traffic_reset < ?)
		`, TrafficResetWeekly, weekStart)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id int64
				rows.Scan(&id)
				um.ResetUserTraffic(id)
			}
		}
	}

	// Monthly reset (1st of month)
	if now.Day() == 1 {
		monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
		rows, err := DB.db.Query(`
			SELECT id FROM users 
			WHERE traffic_reset_period = ? 
			AND (last_traffic_reset IS NULL OR last_traffic_reset < ?)
		`, TrafficResetMonthly, monthStart)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id int64
				rows.Scan(&id)
				um.ResetUserTraffic(id)
			}
		}
	}
}

// ============================================================================
// SUBSCRIPTION MANAGEMENT
// ============================================================================

// RegenerateSubscriptionURL regenerates subscription URL for a user
func (um *UserManager) RegenerateSubscriptionURL(id int64) (string, error) {
	newURL := generateSubscriptionURL()

	_, err := DB.db.Exec("UPDATE users SET subscription_url = ?, updated_at = ? WHERE id = ?",
		newURL, time.Now(), id)
	if err != nil {
		return "", err
	}

	return newURL, nil
}

// ExtendSubscription extends user subscription
func (um *UserManager) ExtendSubscription(id int64, days int, additionalTraffic int64) error {
	user, err := um.GetUserByID(id)
	if err != nil {
		return err
	}

	now := time.Now()
	var newExpiry time.Time

	if user.ExpiryTime != nil && user.ExpiryTime.After(now) {
		newExpiry = user.ExpiryTime.AddDate(0, 0, days)
	} else {
		newExpiry = now.AddDate(0, 0, days)
	}

	// Calculate new data limit
	newDataLimit := user.DataLimit
	if additionalTraffic > 0 {
		if user.DataLimit == 0 {
			newDataLimit = additionalTraffic
		} else {
			newDataLimit = user.DataLimit + additionalTraffic
		}
	}

	// Update status if was expired or limited
	newStatus := user.Status
	if user.Status == UserStatusExpired || user.Status == UserStatusLimited {
		newStatus = UserStatusActive
	}

	_, err = DB.db.Exec(`
		UPDATE users SET 
			expiry_time = ?,
			data_limit = ?,
			status = ?,
			updated_at = ?
		WHERE id = ?
	`, newExpiry, newDataLimit, newStatus, now, id)

	return err
}

// GetSubscriptionInfo returns subscription information for a user
func (um *UserManager) GetSubscriptionInfo(id int64) (map[string]interface{}, error) {
	user, err := um.GetUserByID(id)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	info := map[string]interface{}{
		"username":         user.Username,
		"status":           user.Status,
		"is_active":        user.IsActive,
		"subscription_url": user.SubscriptionURL,
		"data_limit":       user.DataLimit,
		"data_used":        user.DataUsed,
		"upload_used":      user.UploadUsed,
		"download_used":    user.DownloadUsed,
		"device_limit":     user.DeviceLimit,
		"ip_limit":         user.IPLimit,
		"created_at":       user.CreatedAt,
	}

	// Expiry info
	if user.ExpiryTime != nil {
		info["expiry_time"] = user.ExpiryTime
		info["days_remaining"] = int(user.ExpiryTime.Sub(now).Hours() / 24)
		info["is_expired"] = now.After(*user.ExpiryTime)
	} else {
		info["days_remaining"] = -1 // unlimited
		info["is_expired"] = false
	}

	// Traffic percentage
	if user.DataLimit > 0 {
		info["traffic_percent"] = float64(user.DataUsed) / float64(user.DataLimit) * 100
		info["data_remaining"] = user.DataLimit - user.DataUsed
	} else {
		info["traffic_percent"] = 0
		info["data_remaining"] = -1 // unlimited
	}

	// Online status
	info["is_online"] = um.IsUserOnline(id)

	// Active devices
	info["active_devices"] = um.GetActiveDeviceCount(id)

	return info, nil
}

// ============================================================================
// DEVICE MANAGEMENT
// ============================================================================

// RegisterDevice registers a new device for a user
func (um *UserManager) RegisterDevice(userID int64, deviceID, deviceName, deviceType, ip string) error {
	user, err := um.GetUserByID(userID)
	if err != nil {
		return err
	}

	// Check device limit
	if user.DeviceLimit > 0 {
		activeCount := um.GetActiveDeviceCount(userID)
		if activeCount >= user.DeviceLimit {
			// Check if this device is already registered
			um.deviceMu.RLock()
			devices, exists := um.userDevices[userID]
			um.deviceMu.RUnlock()

			if !exists || devices[deviceID] == nil {
				return errors.New("device limit exceeded")
			}
		}
	}

	now := time.Now()
	location := GetIPLocation(ip)

	// Update cache
	um.deviceMu.Lock()
	if um.userDevices[userID] == nil {
		um.userDevices[userID] = make(map[string]*UserDevice)
	}
	um.userDevices[userID][deviceID] = &UserDevice{
		UserID:     userID,
		DeviceID:   deviceID,
		DeviceName: deviceName,
		DeviceType: deviceType,
		IP:         ip,
		Location:   location,
		LastSeen:   now,
		IsActive:   true,
	}
	um.deviceMu.Unlock()

	// Update database
	_, err = DB.db.Exec(`
		INSERT INTO user_devices (user_id, device_id, device_name, device_type, ip, location, last_seen, is_active, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
		ON CONFLICT(user_id, device_id) DO UPDATE SET
			device_name = excluded.device_name,
			device_type = excluded.device_type,
			ip = excluded.ip,
			location = excluded.location,
			last_seen = excluded.last_seen,
			is_active = 1
	`, userID, deviceID, deviceName, deviceType, ip, location, now, now)

	return err
}

// UpdateDeviceActivity updates device last seen time
func (um *UserManager) UpdateDeviceActivity(userID int64, deviceID, ip string) {
	now := time.Now()

	um.deviceMu.Lock()
	if um.userDevices[userID] != nil && um.userDevices[userID][deviceID] != nil {
		um.userDevices[userID][deviceID].LastSeen = now
		um.userDevices[userID][deviceID].IP = ip
	}
	um.deviceMu.Unlock()

	DB.db.Exec("UPDATE user_devices SET last_seen = ?, ip = ? WHERE user_id = ? AND device_id = ?",
		now, ip, userID, deviceID)
}

// DeactivateDevice deactivates a device
func (um *UserManager) DeactivateDevice(userID int64, deviceID string) error {
	um.deviceMu.Lock()
	if um.userDevices[userID] != nil {
		delete(um.userDevices[userID], deviceID)
	}
	um.deviceMu.Unlock()

	_, err := DB.db.Exec("UPDATE user_devices SET is_active = 0 WHERE user_id = ? AND device_id = ?",
		userID, deviceID)
	return err
}

// GetUserDevices returns all devices for a user
func (um *UserManager) GetUserDevices(userID int64) ([]*UserDevice, error) {
	rows, err := DB.db.Query(`
		SELECT id, user_id, device_id, device_name, device_type, ip, location, last_seen, is_active, created_at
		FROM user_devices WHERE user_id = ? ORDER BY last_seen DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	devices := []*UserDevice{}
	for rows.Next() {
		d := &UserDevice{}
		rows.Scan(&d.ID, &d.UserID, &d.DeviceID, &d.DeviceName, &d.DeviceType,
			&d.IP, &d.Location, &d.LastSeen, &d.IsActive, &d.CreatedAt)
		devices = append(devices, d)
	}
	return devices, nil
}

// GetActiveDeviceCount returns count of active devices
func (um *UserManager) GetActiveDeviceCount(userID int64) int {
	um.deviceMu.RLock()
	defer um.deviceMu.RUnlock()

	if devices, exists := um.userDevices[userID]; exists {
		count := 0
		cutoff := time.Now().Add(-OnlineUserTimeout)
		for _, d := range devices {
			if d.IsActive && d.LastSeen.After(cutoff) {
				count++
			}
		}
		return count
	}

	// Fallback to database
	var count int
	DB.db.QueryRow(`
		SELECT COUNT(*) FROM user_devices 
		WHERE user_id = ? AND is_active = 1 AND last_seen > ?
	`, userID, time.Now().Add(-OnlineUserTimeout)).Scan(&count)
	return count
}

// ============================================================================
// ONLINE USER TRACKING
// ============================================================================

// RecordUserOnline records a user as online
func (um *UserManager) RecordUserOnline(userID int64, ip, protocol, inbound string, nodeID int64) error {
	user, err := um.GetUserByID(userID)
	if err != nil {
		return err
	}

	// Check IP limit
	if user.IPLimit > 0 {
		currentIPs := um.GetOnlineIPCount(userID)
		if currentIPs >= user.IPLimit {
			// Check if this IP is already registered
			if !um.IsIPOnlineForUser(userID, ip) {
				return errors.New("IP limit exceeded")
			}
		}
	}

	now := time.Now()
	location := GetIPLocation(ip)

	// Update cache
	um.onlineMu.Lock()
	if um.onlineUsers[userID] == nil {
		um.onlineUsers[userID] = make(map[string]*OnlineUser)
	}
	um.onlineUsers[userID][ip] = &OnlineUser{
		UserID:      userID,
		Username:    user.Username,
		IP:          ip,
		Location:    location,
		Protocol:    protocol,
		Inbound:     inbound,
		NodeID:      nodeID,
		ConnectedAt: now,
	}
	um.onlineMu.Unlock()

	// Update database
	_, err = DB.db.Exec(`
		INSERT INTO online_users (user_id, ip, location, protocol, inbound, node_id, connected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id, ip) DO UPDATE SET
			protocol = excluded.protocol,
			inbound = excluded.inbound,
			node_id = excluded.node_id,
			connected_at = excluded.connected_at
	`, userID, ip, location, protocol, inbound, nodeID, now)

	// Update user last online
	DB.db.Exec("UPDATE users SET last_online = ?, last_ip = ? WHERE id = ?", now, ip, userID)

	// Activate on-hold user on first connection
	if user.Status == UserStatusOnHold {
		um.ActivateOnHoldUser(userID)
	}

	return err
}

// RecordUserOffline removes a user from online list
func (um *UserManager) RecordUserOffline(userID int64, ip string) {
	um.onlineMu.Lock()
	if um.onlineUsers[userID] != nil {
		delete(um.onlineUsers[userID], ip)
		if len(um.onlineUsers[userID]) == 0 {
			delete(um.onlineUsers, userID)
		}
	}
	um.onlineMu.Unlock()

	DB.db.Exec("DELETE FROM online_users WHERE user_id = ? AND ip = ?", userID, ip)
}

// DisconnectUser disconnects all sessions for a user
func (um *UserManager) DisconnectUser(userID int64) {
	um.onlineMu.Lock()
	delete(um.onlineUsers, userID)
	um.onlineMu.Unlock()

	DB.db.Exec("DELETE FROM online_users WHERE user_id = ?", userID)
}

// IsUserOnline checks if a user is online
func (um *UserManager) IsUserOnline(userID int64) bool {
	um.onlineMu.RLock()
	defer um.onlineMu.RUnlock()

	return len(um.onlineUsers[userID]) > 0
}

// IsIPOnlineForUser checks if an IP is already online for a user
func (um *UserManager) IsIPOnlineForUser(userID int64, ip string) bool {
	um.onlineMu.RLock()
	defer um.onlineMu.RUnlock()

	if um.onlineUsers[userID] != nil {
		_, exists := um.onlineUsers[userID][ip]
		return exists
	}
	return false
}

// GetOnlineIPCount returns count of online IPs for a user
func (um *UserManager) GetOnlineIPCount(userID int64) int {
	um.onlineMu.RLock()
	defer um.onlineMu.RUnlock()

	if ips, exists := um.onlineUsers[userID]; exists {
		return len(ips)
	}
	return 0
}

// GetOnlineUsers returns all online users
func (um *UserManager) GetOnlineUsers() []*OnlineUser {
	um.onlineMu.RLock()
	defer um.onlineMu.RUnlock()

	users := []*OnlineUser{}
	for _, ips := range um.onlineUsers {
		for _, u := range ips {
			users = append(users, u)
		}
	}
	return users
}

// GetOnlineUsersForAdmin returns online users created by an admin
func (um *UserManager) GetOnlineUsersForAdmin(adminID int64) []*OnlineUser {
	allOnline := um.GetOnlineUsers()
	filtered := []*OnlineUser{}

	for _, ou := range allOnline {
		user, err := um.GetUserByID(ou.UserID)
		if err == nil && user.CreatedByAdminID == adminID {
			filtered = append(filtered, ou)
		}
	}

	return filtered
}

// GetOnlineUserCount returns total online user count
func (um *UserManager) GetOnlineUserCount() int {
	um.onlineMu.RLock()
	defer um.onlineMu.RUnlock()

	return len(um.onlineUsers)
}

// GetUserOnlineIPs returns all online IPs for a user
func (um *UserManager) GetUserOnlineIPs(userID int64) []string {
	um.onlineMu.RLock()
	defer um.onlineMu.RUnlock()

	ips := []string{}
	if userIPs, exists := um.onlineUsers[userID]; exists {
		for ip := range userIPs {
			ips = append(ips, ip)
		}
	}
	return ips
}

// ============================================================================
// CLEANUP ROUTINES
// ============================================================================

// startCleanupRoutine starts the cleanup routine
func (um *UserManager) startCleanupRoutine() {
	um.cleanupTicker = time.NewTicker(1 * time.Minute)
	defer um.cleanupTicker.Stop()

	for {
		select {
		case <-um.cleanupTicker.C:
			um.cleanupExpiredOnlineUsers()
			um.checkExpiredUsers()
		case <-um.stopChan:
			return
		}
	}
}

// cleanupExpiredOnlineUsers removes stale online user entries
func (um *UserManager) cleanupExpiredOnlineUsers() {
	cutoff := time.Now().Add(-OnlineUserTimeout)

	// Clean database
	DB.db.Exec("DELETE FROM online_users WHERE connected_at < ?", cutoff)

	// Note: Cache cleanup happens naturally as entries are refreshed
}

// checkExpiredUsers checks and updates expired users
func (um *UserManager) checkExpiredUsers() {
	now := time.Now()

	// Update expired users
	DB.db.Exec(`
		UPDATE users SET status = ? 
		WHERE status = ? AND expiry_time IS NOT NULL AND expiry_time < ?
	`, UserStatusExpired, UserStatusActive, now)

	// Update limited users
	DB.db.Exec(`
		UPDATE users SET status = ? 
		WHERE status = ? AND data_limit > 0 AND data_used >= data_limit
	`, UserStatusLimited, UserStatusActive)
}

// ============================================================================
// BULK OPERATIONS
// ============================================================================

// BulkDeleteUsers deletes multiple users
func (um *UserManager) BulkDeleteUsers(ids []int64) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}

	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}

	result, err := DB.db.Exec(
		fmt.Sprintf("DELETE FROM users WHERE id IN (%s)", strings.Join(placeholders, ",")),
		args...,
	)
	if err != nil {
		return 0, err
	}

	affected, _ := result.RowsAffected()
	return int(affected), nil
}

// BulkUpdateStatus updates status for multiple users
func (um *UserManager) BulkUpdateStatus(ids []int64, status string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}

	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids)+2)
	args[0] = status
	args[1] = time.Now()
	for i, id := range ids {
		placeholders[i] = "?"
		args[i+2] = id
	}

	result, err := DB.db.Exec(
		fmt.Sprintf("UPDATE users SET status = ?, updated_at = ? WHERE id IN (%s)",
			strings.Join(placeholders, ",")),
		args...,
	)
	if err != nil {
		return 0, err
	}

	affected, _ := result.RowsAffected()
	return int(affected), nil
}

// BulkResetTraffic resets traffic for multiple users
func (um *UserManager) BulkResetTraffic(ids []int64) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}

	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids)+1)
	args[0] = time.Now()
	for i, id := range ids {
		placeholders[i] = "?"
		args[i+1] = id
	}

	result, err := DB.db.Exec(
		fmt.Sprintf(`
			UPDATE users SET 
				data_used = 0, upload_used = 0, download_used = 0,
				last_traffic_reset = ?,
				status = CASE WHEN status = 'limited' THEN 'active' ELSE status END
			WHERE id IN (%s)
		`, strings.Join(placeholders, ",")),
		args...,
	)
	if err != nil {
		return 0, err
	}

	affected, _ := result.RowsAffected()
	return int(affected), nil
}

// BulkExtendSubscription extends subscription for multiple users
func (um *UserManager) BulkExtendSubscription(ids []int64, days int) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}

	count := 0
	for _, id := range ids {
		err := um.ExtendSubscription(id, days, 0)
		if err == nil {
			count++
		}
	}

	return count, nil
}

// ============================================================================
// STATISTICS
// ============================================================================

// UserStats represents user statistics
type UserStats struct {
	TotalUsers    int   `json:"total_users"`
	ActiveUsers   int   `json:"active_users"`
	ExpiredUsers  int   `json:"expired_users"`
	LimitedUsers  int   `json:"limited_users"`
	DisabledUsers int   `json:"disabled_users"`
	OnHoldUsers   int   `json:"on_hold_users"`
	OnlineUsers   int   `json:"online_users"`
	TotalTraffic  int64 `json:"total_traffic"`
	TotalUpload   int64 `json:"total_upload"`
	TotalDownload int64 `json:"total_download"`
	ExpiringToday int   `json:"expiring_today"`
	ExpiringWeek  int   `json:"expiring_week"`
	NewUsersToday int   `json:"new_users_today"`
	NewUsersWeek  int   `json:"new_users_week"`
}

// GetUserStats returns user statistics
func (um *UserManager) GetUserStats() (*UserStats, error) {
	stats := &UserStats{}
	now := time.Now()
	today := now.Truncate(24 * time.Hour)
	weekAgo := now.AddDate(0, 0, -7)
	weekLater := now.AddDate(0, 0, 7)

	DB.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&stats.TotalUsers)
	DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE status = ?", UserStatusActive).Scan(&stats.ActiveUsers)
	DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE status = ?", UserStatusExpired).Scan(&stats.ExpiredUsers)
	DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE status = ?", UserStatusLimited).Scan(&stats.LimitedUsers)
	DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE status = ?", UserStatusDisabled).Scan(&stats.DisabledUsers)
	DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE status = ?", UserStatusOnHold).Scan(&stats.OnHoldUsers)

	stats.OnlineUsers = um.GetOnlineUserCount()

	DB.db.QueryRow("SELECT COALESCE(SUM(data_used), 0), COALESCE(SUM(upload_used), 0), COALESCE(SUM(download_used), 0) FROM users").
		Scan(&stats.TotalTraffic, &stats.TotalUpload, &stats.TotalDownload)

	DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE expiry_time BETWEEN ? AND ?",
		now, today.Add(24*time.Hour)).Scan(&stats.ExpiringToday)
	DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE expiry_time BETWEEN ? AND ?",
		now, weekLater).Scan(&stats.ExpiringWeek)

	DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE created_at >= ?", today).Scan(&stats.NewUsersToday)
	DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE created_at >= ?", weekAgo).Scan(&stats.NewUsersWeek)

	return stats, nil
}

// GetUserStatsForAdmin returns user statistics for a specific admin
func (um *UserManager) GetUserStatsForAdmin(adminID int64) (*UserStats, error) {
	stats := &UserStats{}
	now := time.Now()
	today := now.Truncate(24 * time.Hour)
	weekAgo := now.AddDate(0, 0, -7)
	weekLater := now.AddDate(0, 0, 7)

	DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE created_by_admin_id = ?", adminID).Scan(&stats.TotalUsers)
	DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE created_by_admin_id = ? AND status = ?", adminID, UserStatusActive).Scan(&stats.ActiveUsers)
	DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE created_by_admin_id = ? AND status = ?", adminID, UserStatusExpired).Scan(&stats.ExpiredUsers)
	DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE created_by_admin_id = ? AND status = ?", adminID, UserStatusLimited).Scan(&stats.LimitedUsers)
	DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE created_by_admin_id = ? AND status = ?", adminID, UserStatusDisabled).Scan(&stats.DisabledUsers)

	stats.OnlineUsers = len(um.GetOnlineUsersForAdmin(adminID))

	DB.db.QueryRow(`
		SELECT COALESCE(SUM(data_used), 0), COALESCE(SUM(upload_used), 0), COALESCE(SUM(download_used), 0) 
		FROM users WHERE created_by_admin_id = ?
	`, adminID).Scan(&stats.TotalTraffic, &stats.TotalUpload, &stats.TotalDownload)

	DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE created_by_admin_id = ? AND expiry_time BETWEEN ? AND ?",
		adminID, now, today.Add(24*time.Hour)).Scan(&stats.ExpiringToday)
	DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE created_by_admin_id = ? AND expiry_time BETWEEN ? AND ?",
		adminID, now, weekLater).Scan(&stats.ExpiringWeek)

	DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE created_by_admin_id = ? AND created_at >= ?",
		adminID, today).Scan(&stats.NewUsersToday)
	DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE created_by_admin_id = ? AND created_at >= ?",
		adminID, weekAgo).Scan(&stats.NewUsersWeek)

	return stats, nil
}

// GetTopUsers returns top users by traffic usage
func (um *UserManager) GetTopUsers(limit int) ([]*User, error) {
	result, err := um.ListUsers(&UserFilter{
		SortBy:    "data_used",
		SortOrder: "desc",
		Limit:     limit,
	})
	if err != nil {
		return nil, err
	}
	return result.Users, nil
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// generateSubscriptionURL generates a unique subscription URL
func generateSubscriptionURL() string {
	bytes := make([]byte, SubscriptionURLLength)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// ValidateUserAccess checks if a user can access the VPN
func (um *UserManager) ValidateUserAccess(user *User) (bool, string) {
	if user == nil {
		return false, "user not found"
	}

	if !user.IsActive {
		return false, "account is disabled"
	}

	switch user.Status {
	case UserStatusExpired:
		return false, "subscription has expired"
	case UserStatusLimited:
		return false, "traffic limit exceeded"
	case UserStatusDisabled:
		return false, "account is disabled"
	case UserStatusOnHold:
		// On-hold users can connect (will be activated)
		return true, ""
	case UserStatusActive:
		// Check expiry
		if user.ExpiryTime != nil && time.Now().After(*user.ExpiryTime) {
			um.UpdateUserStatus(user.ID, UserStatusExpired)
			return false, "subscription has expired"
		}
		// Check traffic
		if user.DataLimit > 0 && user.DataUsed >= user.DataLimit {
			um.UpdateUserStatus(user.ID, UserStatusLimited)
			return false, "traffic limit exceeded"
		}
		return true, ""
	}

	return false, "invalid status"
}

// GetRemainingDays returns remaining days until expiry
func GetRemainingDays(expiryTime *time.Time) int {
	if expiryTime == nil {
		return -1 // unlimited
	}
	remaining := time.Until(*expiryTime)
	if remaining < 0 {
		return 0
	}
	return int(remaining.Hours() / 24)
}

// GetRemainingTraffic returns remaining traffic in bytes
func GetRemainingTraffic(dataLimit, dataUsed int64) int64 {
	if dataLimit == 0 {
		return -1 // unlimited
	}
	remaining := dataLimit - dataUsed
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ParseBytes parses human readable size to bytes
func ParseBytes(size string) (int64, error) {
	size = strings.TrimSpace(strings.ToUpper(size))

	units := map[string]int64{
		"B":  1,
		"KB": 1024,
		"MB": 1024 * 1024,
		"GB": 1024 * 1024 * 1024,
		"TB": 1024 * 1024 * 1024 * 1024,
	}

	for suffix, multiplier := range units {
		if strings.HasSuffix(size, suffix) {
			numStr := strings.TrimSuffix(size, suffix)
			numStr = strings.TrimSpace(numStr)
			var num float64
			_, err := fmt.Sscanf(numStr, "%f", &num)
			if err != nil {
				return 0, err
			}
			return int64(num * float64(multiplier)), nil
		}
	}

	// Try parsing as plain number (bytes)
	var bytes int64
	_, err := fmt.Sscanf(size, "%d", &bytes)
	return bytes, err
}

// NewUserManager creates a new UserManager for testing
func NewUserManager(db interface{}) *UserManager {
	return &UserManager{
		onlineUsers:  make(map[int64]map[string]*OnlineUser),
		userDevices:  make(map[int64]map[string]*UserDevice),
		trafficCache: make(map[int64]*TrafficInfo),
		stopChan:     make(chan struct{}),
	}
}
