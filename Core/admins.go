// MXUI VPN Panel
// Core/admins.go
// Admin Management: CRUD, Owner, Reseller, Permissions, Audit, Switch Admin

package core

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// CONSTANTS
// ============================================================================

const (
	// Permission constants
	PermissionAll            = "*"
	PermissionUserCreate     = "user:create"
	PermissionUserRead       = "user:read"
	PermissionUserUpdate     = "user:update"
	PermissionUserDelete     = "user:delete"
	PermissionAdminCreate    = "admin:create"
	PermissionAdminRead      = "admin:read"
	PermissionAdminUpdate    = "admin:update"
	PermissionAdminDelete    = "admin:delete"
	PermissionNodeManage     = "node:manage"
	PermissionCoreManage     = "core:manage"
	PermissionPanelManage    = "panel:manage"
	PermissionBackupManage   = "backup:manage"
	PermissionTemplateManage = "template:manage"
	PermissionBotManage      = "bot:manage"
	PermissionAIManage       = "ai:manage"
	PermissionLogsView       = "logs:view"
	PermissionAnalyticsView  = "analytics:view"

	// Admin limits
	DefaultResellerUserLimit    = 100
	DefaultResellerTrafficLimit = 100 * 1024 * 1024 * 1024 // 100 GB
)

// ============================================================================
// PERMISSION DEFINITIONS
// ============================================================================
// IsOwner checks if admin is owner
func (a *Admin) IsOwner() bool {
	return a.Role == AdminRoleOwner
}
func (am *AdminManager) CanAccessFeature(adminID int64, feature string) bool {
	admin, _ := am.GetAdminByID(adminID)
	if admin == nil {
		return false
	}
	if admin.Role == AdminRoleOwner {
		return true
	}
	// Reseller limited features
	allowed := []string{"users", "users_own", "traffic_own"}
	for _, f := range allowed {
		if f == feature {
			return true
		}
	}
	return false
}

// CanAccessSettings checks if admin can access settings
func (a *Admin) CanAccessSettings() bool {
	return a.Role == AdminRoleOwner
}

// RolePermissions defines permissions for each role
var RolePermissions = map[string][]string{
	AdminRoleOwner: {
		PermissionAll, // Owner has all permissions
	},
	AdminRoleReseller: {
		PermissionUserCreate,
		PermissionUserRead,
		PermissionUserUpdate,
		PermissionUserDelete,
		PermissionAnalyticsView,
	},
}

// ============================================================================
// ADMIN MANAGER
// ============================================================================

// AdminManager handles all admin operations
type AdminManager struct {
	currentAdmin *Admin
	adminCache   map[int64]*Admin
	mu           sync.RWMutex
}

// Global admin manager instance
var Admins *AdminManager

// InitAdminManager initializes the admin manager
func InitAdminManager() error {
	Admins = &AdminManager{
		adminCache: make(map[int64]*Admin),
	}

	// Load admins into cache
	return Admins.loadAdminCache()
}

// loadAdminCache loads all admins into memory cache
func (am *AdminManager) loadAdminCache() error {
	rows, err := DB.db.Query(`
		SELECT id, username, password, email, role, is_active,
		       telegram_id, telegram_username, parent_admin_id,
		       traffic_limit, user_limit, traffic_used, users_created,
		       last_login, last_ip, created_at, updated_at
		FROM admins
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	am.mu.Lock()
	defer am.mu.Unlock()

	for rows.Next() {
		admin := &Admin{}
		err := rows.Scan(
			&admin.ID, &admin.Username, &admin.Password, &admin.Email,
			&admin.Role, &admin.IsActive, &admin.TelegramID, &admin.TelegramUsername,
			&admin.ParentAdminID, &admin.TrafficLimit, &admin.UserLimit,
			&admin.TrafficUsed, &admin.UsersCreated, &admin.LastLogin,
			&admin.LastIP, &admin.CreatedAt, &admin.UpdatedAt,
		)
		if err != nil {
			continue
		}
		am.adminCache[admin.ID] = admin
	}

	return nil
}

// ============================================================================
// ADMIN CRUD OPERATIONS
// ============================================================================

// CreateAdminRequest represents a request to create an admin
type CreateAdminRequest struct {
	Username         string `json:"username"`
	Password         string `json:"password"`
	Email            string `json:"email,omitempty"`
	Role             string `json:"role"`
	TelegramID       int64  `json:"telegram_id,omitempty"`
	TelegramUsername string `json:"telegram_username,omitempty"`
	TrafficLimit     int64  `json:"traffic_limit,omitempty"` // For resellers, bytes
	UserLimit        int    `json:"user_limit,omitempty"`    // For resellers
	ParentAdminID    int64  `json:"parent_admin_id,omitempty"`
}

// UpdateAdminRequest represents a request to update an admin
type UpdateAdminRequest struct {
	Email            *string `json:"email,omitempty"`
	Password         *string `json:"password,omitempty"`
	TelegramID       *int64  `json:"telegram_id,omitempty"`
	TelegramUsername *string `json:"telegram_username,omitempty"`
	TrafficLimit     *int64  `json:"traffic_limit,omitempty"`
	UserLimit        *int    `json:"user_limit,omitempty"`
	IsActive         *bool   `json:"is_active,omitempty"`
}

// CreateAdmin creates a new admin
func (am *AdminManager) CreateAdmin(req *CreateAdminRequest, createdByID int64) (*Admin, error) {
	// Validate username
	if err := ValidateUsername(req.Username); err != nil {
		return nil, err
	}

	// Check if username exists
	var count int
	DB.db.QueryRow("SELECT COUNT(*) FROM admins WHERE username = ?", req.Username).Scan(&count)
	if count > 0 {
		return nil, errors.New("username already exists")
	}

	// Validate password
	if err := ValidatePassword(req.Password); err != nil {
		return nil, err
	}

	// Validate email if provided
	if req.Email != "" {
		if err := ValidateEmail(req.Email); err != nil {
			return nil, err
		}
	}

	// Validate role
	if req.Role != AdminRoleOwner && req.Role != AdminRoleReseller {
		return nil, errors.New("invalid role")
	}

	// Only owner can create other owners
	creator, _ := am.GetAdminByID(createdByID)
	if creator != nil && creator.Role != AdminRoleOwner && req.Role == AdminRoleOwner {
		return nil, errors.New("only owner can create owner admins")
	}

	// Hash password
	hashedPassword, err := HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Set defaults for reseller
	if req.Role == AdminRoleReseller {
		if req.TrafficLimit == 0 {
			req.TrafficLimit = DefaultResellerTrafficLimit
		}
		if req.UserLimit == 0 {
			req.UserLimit = DefaultResellerUserLimit
		}
		if req.ParentAdminID == 0 {
			req.ParentAdminID = createdByID
		}
	}

	now := time.Now()

	// Insert admin
	result, err := DB.db.Exec(`
		INSERT INTO admins (
			username, password, email, role, is_active,
			telegram_id, telegram_username, parent_admin_id,
			traffic_limit, user_limit, traffic_used, users_created,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, 0, 0, ?, ?)
	`,
		req.Username, hashedPassword, req.Email, req.Role,
		req.TelegramID, req.TelegramUsername, req.ParentAdminID,
		req.TrafficLimit, req.UserLimit, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create admin: %w", err)
	}

	adminID, _ := result.LastInsertId()

	// Update cache
	admin, err := am.GetAdminByID(adminID)
	if err != nil {
		return nil, err
	}

	am.mu.Lock()
	am.adminCache[adminID] = admin
	am.mu.Unlock()

	return admin, nil
}

// GetAdminByID retrieves an admin by ID
func (am *AdminManager) GetAdminByID(id int64) (*Admin, error) {
	// Check cache first
	am.mu.RLock()
	if admin, exists := am.adminCache[id]; exists {
		am.mu.RUnlock()
		return admin, nil
	}
	am.mu.RUnlock()

	// Query database
	admin := &Admin{}
	err := DB.db.QueryRow(`
		SELECT id, username, password, email, role, is_active,
		       telegram_id, telegram_username, parent_admin_id,
		       traffic_limit, user_limit, traffic_used, users_created,
		       last_login, last_ip, COALESCE(is_first_login, 1) as is_first_login,
		       created_at, updated_at
		FROM admins WHERE id = ?
	`, id).Scan(
		&admin.ID, &admin.Username, &admin.Password, &admin.Email,
		&admin.Role, &admin.IsActive, &admin.TelegramID, &admin.TelegramUsername,
		&admin.ParentAdminID, &admin.TrafficLimit, &admin.UserLimit,
		&admin.TrafficUsed, &admin.UsersCreated, &admin.LastLogin,
		&admin.LastIP, &admin.IsFirstLogin, &admin.CreatedAt, &admin.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Update cache
	am.mu.Lock()
	am.adminCache[id] = admin
	am.mu.Unlock()

	return admin, nil
}

// GetAdminByUsername retrieves an admin by username
func (am *AdminManager) GetAdminByUsername(username string) (*Admin, error) {
	// Check cache first
	am.mu.RLock()
	for _, admin := range am.adminCache {
		if admin.Username == username {
			am.mu.RUnlock()
			return admin, nil
		}
	}
	am.mu.RUnlock()

	// Query database
	var id int64
	err := DB.db.QueryRow("SELECT id FROM admins WHERE username = ?", username).Scan(&id)
	if err != nil {
		return nil, err
	}

	return am.GetAdminByID(id)
}

// GetAdminByTelegramID retrieves an admin by Telegram ID
func (am *AdminManager) GetAdminByTelegramID(telegramID int64) (*Admin, error) {
	am.mu.RLock()
	for _, admin := range am.adminCache {
		if admin.TelegramID == telegramID {
			am.mu.RUnlock()
			return admin, nil
		}
	}
	am.mu.RUnlock()

	var id int64
	err := DB.db.QueryRow("SELECT id FROM admins WHERE telegram_id = ?", telegramID).Scan(&id)
	if err != nil {
		return nil, err
	}

	return am.GetAdminByID(id)
}

// UpdateAdmin updates an admin
func (am *AdminManager) UpdateAdmin(id int64, req *UpdateAdminRequest) (*Admin, error) {
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

	if req.Password != nil {
		if err := ValidatePassword(*req.Password); err != nil {
			return nil, err
		}
		hashedPassword, err := HashPassword(*req.Password)
		if err != nil {
			return nil, err
		}
		updates = append(updates, "password = ?")
		args = append(args, hashedPassword)
	}

	if req.TelegramID != nil {
		updates = append(updates, "telegram_id = ?")
		args = append(args, *req.TelegramID)
	}

	if req.TelegramUsername != nil {
		updates = append(updates, "telegram_username = ?")
		args = append(args, *req.TelegramUsername)
	}

	if req.TrafficLimit != nil {
		updates = append(updates, "traffic_limit = ?")
		args = append(args, *req.TrafficLimit)
	}

	if req.UserLimit != nil {
		updates = append(updates, "user_limit = ?")
		args = append(args, *req.UserLimit)
	}

	if req.IsActive != nil {
		updates = append(updates, "is_active = ?")
		args = append(args, *req.IsActive)
	}

	if len(updates) == 0 {
		return am.GetAdminByID(id)
	}

	updates = append(updates, "updated_at = ?")
	args = append(args, time.Now())
	args = append(args, id)

	query := fmt.Sprintf("UPDATE admins SET %s WHERE id = ?", strings.Join(updates, ", "))
	_, err := DB.db.Exec(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to update admin: %w", err)
	}

	// Clear cache entry to force refresh
	am.mu.Lock()
	delete(am.adminCache, id)
	am.mu.Unlock()

	return am.GetAdminByID(id)
}

// ClearCache clears the cache for a specific admin
func (am *AdminManager) ClearCache(id int64) {
	am.mu.Lock()
	delete(am.adminCache, id)
	am.mu.Unlock()
}

// DeleteAdmin deletes an admin
func (am *AdminManager) DeleteAdmin(id int64, deletedByID int64) error {
	admin, err := am.GetAdminByID(id)
	if err != nil {
		return err
	}

	// Cannot delete yourself
	if id == deletedByID {
		return errors.New("cannot delete yourself")
	}

	// Cannot delete the last owner
	if admin.Role == AdminRoleOwner {
		var ownerCount int
		DB.db.QueryRow("SELECT COUNT(*) FROM admins WHERE role = ?", AdminRoleOwner).Scan(&ownerCount)
		if ownerCount <= 1 {
			return errors.New("cannot delete the last owner admin")
		}
	}

	// Check if admin has users
	var userCount int
	DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE created_by_admin_id = ?", id).Scan(&userCount)
	if userCount > 0 {
		return fmt.Errorf("admin has %d users, reassign or delete them first", userCount)
	}

	// Delete admin
	_, err = DB.db.Exec("DELETE FROM admins WHERE id = ?", id)
	if err != nil {
		return err
	}

	// Clear cache
	am.mu.Lock()
	delete(am.adminCache, id)
	am.mu.Unlock()

	return nil
}

// ============================================================================
// ADMIN LISTING
// ============================================================================

// AdminFilter represents filters for admin listing
type AdminFilter struct {
	Search    string `json:"search,omitempty"`
	Role      string `json:"role,omitempty"`
	IsActive  *bool  `json:"is_active,omitempty"`
	ParentID  int64  `json:"parent_id,omitempty"`
	SortBy    string `json:"sort_by,omitempty"`
	SortOrder string `json:"sort_order,omitempty"`
	Limit     int    `json:"limit,omitempty"`
	Offset    int    `json:"offset,omitempty"`
}

// AdminListResult represents paginated admin list result
type AdminListResult struct {
	Admins     []*Admin `json:"admins"`
	Total      int      `json:"total"`
	Limit      int      `json:"limit"`
	Offset     int      `json:"offset"`
	TotalPages int      `json:"total_pages"`
}

// ListAdmins lists admins with filtering and pagination
func (am *AdminManager) ListAdmins(filter *AdminFilter) (*AdminListResult, error) {
	baseQuery := `
		SELECT id, username, password, email, role, is_active,
		       telegram_id, telegram_username, parent_admin_id,
		       traffic_limit, user_limit, traffic_used, users_created,
		       last_login, last_ip, created_at, updated_at
		FROM admins
	`
	countQuery := "SELECT COUNT(*) FROM admins"

	where := []string{}
	args := []interface{}{}

	// Search filter
	if filter.Search != "" {
		where = append(where, "(username LIKE ? OR email LIKE ? OR telegram_username LIKE ?)")
		searchTerm := "%" + filter.Search + "%"
		args = append(args, searchTerm, searchTerm, searchTerm)
	}

	// Role filter
	if filter.Role != "" {
		where = append(where, "role = ?")
		args = append(args, filter.Role)
	}

	// Active filter
	if filter.IsActive != nil {
		where = append(where, "is_active = ?")
		args = append(args, *filter.IsActive)
	}

	// Parent filter
	if filter.ParentID > 0 {
		where = append(where, "parent_admin_id = ?")
		args = append(args, filter.ParentID)
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
		validSorts := map[string]bool{"username": true, "created_at": true, "last_login": true, "traffic_used": true}
		if validSorts[filter.SortBy] {
			sortBy = filter.SortBy
		}
	}
	if filter.SortOrder == "asc" || filter.SortOrder == "ASC" {
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

	admins := []*Admin{}
	for rows.Next() {
		admin := &Admin{}
		err := rows.Scan(
			&admin.ID, &admin.Username, &admin.Password, &admin.Email,
			&admin.Role, &admin.IsActive, &admin.TelegramID, &admin.TelegramUsername,
			&admin.ParentAdminID, &admin.TrafficLimit, &admin.UserLimit,
			&admin.TrafficUsed, &admin.UsersCreated, &admin.LastLogin,
			&admin.LastIP, &admin.CreatedAt, &admin.UpdatedAt,
		)
		if err != nil {
			continue
		}
		admins = append(admins, admin)
	}

	totalPages := (total + limit - 1) / limit

	return &AdminListResult{
		Admins:     admins,
		Total:      total,
		Limit:      limit,
		Offset:     offset,
		TotalPages: totalPages,
	}, nil
}

// GetAllAdmins returns all admins
func (am *AdminManager) GetAllAdmins() ([]*Admin, error) {
	result, err := am.ListAdmins(&AdminFilter{Limit: 10000})
	if err != nil {
		return nil, err
	}
	return result.Admins, nil
}

// GetOwnerAdmins returns all owner admins
func (am *AdminManager) GetOwnerAdmins() ([]*Admin, error) {
	role := AdminRoleOwner
	result, err := am.ListAdmins(&AdminFilter{Role: role, Limit: 100})
	if err != nil {
		return nil, err
	}
	return result.Admins, nil
}

// GetResellerAdmins returns all reseller admins
func (am *AdminManager) GetResellerAdmins() ([]*Admin, error) {
	role := AdminRoleReseller
	result, err := am.ListAdmins(&AdminFilter{Role: role, Limit: 10000})
	if err != nil {
		return nil, err
	}
	return result.Admins, nil
}

// GetSubAdmins returns admins created by a specific admin
func (am *AdminManager) GetSubAdmins(parentID int64) ([]*Admin, error) {
	result, err := am.ListAdmins(&AdminFilter{ParentID: parentID, Limit: 10000})
	if err != nil {
		return nil, err
	}
	return result.Admins, nil
}

// ============================================================================
// AUTHENTICATION
// ============================================================================

// AuthenticateAdmin authenticates an admin by username and password
func (am *AdminManager) AuthenticateAdmin(username, password string) (*Admin, error) {
	admin, err := am.GetAdminByUsername(username)
	if err != nil {
		return nil, errors.New("invalid username or password")
	}

	if !admin.IsActive {
		return nil, errors.New("account is disabled")
	}

	if !VerifyPassword(password, admin.Password) {
		return nil, errors.New("invalid username or password")
	}

	return admin, nil
}

// UpdateLoginInfo updates admin's login information
func (am *AdminManager) UpdateLoginInfo(id int64, ip string) error {
	now := time.Now()
	_, err := DB.db.Exec(`
		UPDATE admins SET last_login = ?, last_ip = ?, updated_at = ?
		WHERE id = ?
	`, now, ip, now, id)

	if err != nil {
		return err
	}

	// Update cache
	am.mu.Lock()
	if admin, exists := am.adminCache[id]; exists {
		admin.LastLogin = &now
		admin.LastIP = ip
	}
	am.mu.Unlock()

	return nil
}

// ChangePassword changes admin's password
func (am *AdminManager) ChangePassword(id int64, currentPassword, newPassword string) error {
	admin, err := am.GetAdminByID(id)
	if err != nil {
		return err
	}

	// Verify current password
	if !VerifyPassword(currentPassword, admin.Password) {
		return errors.New("current password is incorrect")
	}

	// Validate new password
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}

	// Hash new password
	hashedPassword, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	// Update password
	_, err = DB.db.Exec("UPDATE admins SET password = ?, updated_at = ? WHERE id = ?",
		hashedPassword, time.Now(), id)

	if err != nil {
		return err
	}

	// Clear cache
	am.mu.Lock()
	delete(am.adminCache, id)
	am.mu.Unlock()

	return nil
}

// ResetPassword resets admin's password (admin action)
func (am *AdminManager) ResetPassword(id int64, newPassword string) error {
	// Validate new password
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}

	// Hash new password
	hashedPassword, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	// Update password
	_, err = DB.db.Exec("UPDATE admins SET password = ?, updated_at = ? WHERE id = ?",
		hashedPassword, time.Now(), id)

	if err != nil {
		return err
	}

	// Clear cache
	am.mu.Lock()
	delete(am.adminCache, id)
	am.mu.Unlock()

	return nil
}

// ============================================================================
// PERMISSIONS
// ============================================================================

// HasPermission checks if an admin has a specific permission
func (am *AdminManager) HasPermission(admin *Admin, permission string) bool {
	if admin == nil {
		return false
	}

	permissions, exists := RolePermissions[admin.Role]
	if !exists {
		return false
	}

	for _, p := range permissions {
		if p == PermissionAll || p == permission {
			return true
		}

		// Check wildcard permissions (e.g., "user:*" matches "user:create")
		if strings.HasSuffix(p, ":*") {
			prefix := strings.TrimSuffix(p, "*")
			if strings.HasPrefix(permission, prefix) {
				return true
			}
		}
	}

	return false
}

// HasAnyPermission checks if admin has any of the given permissions
func (am *AdminManager) HasAnyPermission(admin *Admin, permissions ...string) bool {
	for _, p := range permissions {
		if am.HasPermission(admin, p) {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if admin has all of the given permissions
func (am *AdminManager) HasAllPermissions(admin *Admin, permissions ...string) bool {
	for _, p := range permissions {
		if !am.HasPermission(admin, p) {
			return false
		}
	}
	return true
}

// IsOwner checks if admin is an owner
func (am *AdminManager) IsOwner(admin *Admin) bool {
	return admin != nil && admin.Role == AdminRoleOwner
}

// IsReseller checks if admin is a reseller
func (am *AdminManager) IsReseller(admin *Admin) bool {
	return admin != nil && admin.Role == AdminRoleReseller
}

// CanManageUser checks if admin can manage a specific user
func (am *AdminManager) CanManageUser(admin *Admin, userAdminID int64) bool {
	if admin == nil {
		return false
	}

	// Owner can manage all users
	if admin.Role == AdminRoleOwner {
		return true
	}

	// Reseller can only manage their own users
	return admin.ID == userAdminID
}

// CanManageAdmin checks if admin can manage another admin
func (am *AdminManager) CanManageAdmin(admin *Admin, targetAdminID int64) bool {
	if admin == nil {
		return false
	}

	// Only owner can manage admins
	if admin.Role != AdminRoleOwner {
		return false
	}

	// Cannot manage yourself through this function
	return admin.ID != targetAdminID
}

// ============================================================================
// RESELLER LIMITS
// ============================================================================

// CheckResellerUserLimit checks if reseller can create more users
func (am *AdminManager) CheckResellerUserLimit(admin *Admin) (bool, int) {
	if admin.Role != AdminRoleReseller {
		return true, -1 // Owners have no limit
	}

	if admin.UserLimit == 0 {
		return true, -1 // Unlimited
	}

	remaining := admin.UserLimit - admin.UsersCreated
	return remaining > 0, remaining
}

// CheckResellerTrafficLimit checks if reseller has traffic quota remaining
func (am *AdminManager) CheckResellerTrafficLimit(admin *Admin) (bool, int64) {
	if admin.Role != AdminRoleReseller {
		return true, -1 // Owners have no limit
	}

	if admin.TrafficLimit == 0 {
		return true, -1 // Unlimited
	}

	remaining := admin.TrafficLimit - admin.TrafficUsed
	return remaining > 0, remaining
}

// IncrementUserCount increments admin's user count
func (am *AdminManager) IncrementUserCount(adminID int64) error {
	_, err := DB.db.Exec("UPDATE admins SET users_created = users_created + 1 WHERE id = ?", adminID)

	// Update cache
	am.mu.Lock()
	if admin, exists := am.adminCache[adminID]; exists {
		admin.UsersCreated++
	}
	am.mu.Unlock()

	return err
}

// DecrementUserCount decrements admin's user count
func (am *AdminManager) DecrementUserCount(adminID int64) error {
	_, err := DB.db.Exec("UPDATE admins SET users_created = users_created - 1 WHERE id = ? AND users_created > 0", adminID)

	// Update cache
	am.mu.Lock()
	if admin, exists := am.adminCache[adminID]; exists && admin.UsersCreated > 0 {
		admin.UsersCreated--
	}
	am.mu.Unlock()

	return err
}

// AddTrafficUsage adds to admin's traffic usage
func (am *AdminManager) AddTrafficUsage(adminID int64, bytes int64) error {
	_, err := DB.db.Exec("UPDATE admins SET traffic_used = traffic_used + ? WHERE id = ?", bytes, adminID)

	// Update cache
	am.mu.Lock()
	if admin, exists := am.adminCache[adminID]; exists {
		admin.TrafficUsed += bytes
	}
	am.mu.Unlock()

	return err
}

// ResetTrafficUsage resets admin's traffic usage
func (am *AdminManager) ResetTrafficUsage(adminID int64) error {
	_, err := DB.db.Exec("UPDATE admins SET traffic_used = 0 WHERE id = ?", adminID)

	// Update cache
	am.mu.Lock()
	if admin, exists := am.adminCache[adminID]; exists {
		admin.TrafficUsed = 0
	}
	am.mu.Unlock()

	return err
}

// GetResellerUsagePercent returns percentage of used quota
func (am *AdminManager) GetResellerUsagePercent(admin *Admin) (userPercent, trafficPercent float64) {
	if admin.Role != AdminRoleReseller {
		return 0, 0
	}

	if admin.UserLimit > 0 {
		userPercent = float64(admin.UsersCreated) / float64(admin.UserLimit) * 100
	}

	if admin.TrafficLimit > 0 {
		trafficPercent = float64(admin.TrafficUsed) / float64(admin.TrafficLimit) * 100
	}

	return
}

// ============================================================================
// ADMIN SWITCHING (Owner Only)
// ============================================================================

// SetCurrentAdmin sets the current operating admin (for owner switching)
func (am *AdminManager) SetCurrentAdmin(admin *Admin) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.currentAdmin = admin
}

// GetCurrentAdmin returns the current operating admin
func (am *AdminManager) GetCurrentAdmin() *Admin {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.currentAdmin
}

// SwitchToAdmin switches to operate as another admin (owner only)
func (am *AdminManager) SwitchToAdmin(ownerAdmin *Admin, targetAdminID int64) (*Admin, error) {
	if ownerAdmin.Role != AdminRoleOwner {
		return nil, errors.New("only owner can switch admin")
	}

	targetAdmin, err := am.GetAdminByID(targetAdminID)
	if err != nil {
		return nil, err
	}

	am.SetCurrentAdmin(targetAdmin)
	return targetAdmin, nil
}

// SwitchBackToOwner switches back to owner admin
func (am *AdminManager) SwitchBackToOwner(ownerAdmin *Admin) {
	am.SetCurrentAdmin(ownerAdmin)
}

// ============================================================================
// ADMIN STATUS
// ============================================================================

// EnableAdmin enables an admin
func (am *AdminManager) EnableAdmin(id int64) error {
	_, err := DB.db.Exec("UPDATE admins SET is_active = 1, updated_at = ? WHERE id = ?",
		time.Now(), id)

	// Update cache
	am.mu.Lock()
	if admin, exists := am.adminCache[id]; exists {
		admin.IsActive = true
	}
	am.mu.Unlock()

	return err
}

// DisableAdmin disables an admin
func (am *AdminManager) DisableAdmin(id int64) error {
	admin, err := am.GetAdminByID(id)
	if err != nil {
		return err
	}

	// Cannot disable the last owner
	if admin.Role == AdminRoleOwner {
		var activeOwnerCount int
		DB.db.QueryRow("SELECT COUNT(*) FROM admins WHERE role = ? AND is_active = 1", AdminRoleOwner).Scan(&activeOwnerCount)
		if activeOwnerCount <= 1 {
			return errors.New("cannot disable the last active owner admin")
		}
	}

	_, err = DB.db.Exec("UPDATE admins SET is_active = 0, updated_at = ? WHERE id = ?",
		time.Now(), id)

	// Update cache
	am.mu.Lock()
	if admin, exists := am.adminCache[id]; exists {
		admin.IsActive = false
	}
	am.mu.Unlock()

	// Invalidate all sessions for this admin
	if Security != nil {
		Security.InvalidateAllSessions(id)
	}

	return err
}

// ============================================================================
// TELEGRAM INTEGRATION
// ============================================================================

// LinkTelegram links a Telegram account to an admin
func (am *AdminManager) LinkTelegram(adminID int64, telegramID int64, telegramUsername string) error {
	// Check if Telegram ID is already linked
	var existingID int64
	err := DB.db.QueryRow("SELECT id FROM admins WHERE telegram_id = ? AND id != ?", telegramID, adminID).Scan(&existingID)
	if err == nil {
		return errors.New("telegram account already linked to another admin")
	}

	_, err = DB.db.Exec(`
		UPDATE admins SET telegram_id = ?, telegram_username = ?, updated_at = ?
		WHERE id = ?
	`, telegramID, telegramUsername, time.Now(), adminID)

	// Update cache
	am.mu.Lock()
	if admin, exists := am.adminCache[adminID]; exists {
		admin.TelegramID = telegramID
		admin.TelegramUsername = telegramUsername
	}
	am.mu.Unlock()

	return err
}

// UnlinkTelegram unlinks Telegram account from an admin
func (am *AdminManager) UnlinkTelegram(adminID int64) error {
	_, err := DB.db.Exec(`
		UPDATE admins SET telegram_id = NULL, telegram_username = NULL, updated_at = ?
		WHERE id = ?
	`, time.Now(), adminID)

	// Update cache
	am.mu.Lock()
	if admin, exists := am.adminCache[adminID]; exists {
		admin.TelegramID = 0
		admin.TelegramUsername = ""
	}
	am.mu.Unlock()

	return err
}

// ============================================================================
// STATISTICS
// ============================================================================

// AdminStats represents admin statistics
type AdminStats struct {
	TotalAdmins       int   `json:"total_admins"`
	OwnerAdmins       int   `json:"owner_admins"`
	ResellerAdmins    int   `json:"reseller_admins"`
	ActiveAdmins      int   `json:"active_admins"`
	DisabledAdmins    int   `json:"disabled_admins"`
	TotalTrafficUsed  int64 `json:"total_traffic_used"`
	TotalUsersCreated int   `json:"total_users_created"`
}

// GetAdminStats returns admin statistics
func (am *AdminManager) GetAdminStats() (*AdminStats, error) {
	stats := &AdminStats{}

	DB.db.QueryRow("SELECT COUNT(*) FROM admins").Scan(&stats.TotalAdmins)
	DB.db.QueryRow("SELECT COUNT(*) FROM admins WHERE role = ?", AdminRoleOwner).Scan(&stats.OwnerAdmins)
	DB.db.QueryRow("SELECT COUNT(*) FROM admins WHERE role = ?", AdminRoleReseller).Scan(&stats.ResellerAdmins)
	DB.db.QueryRow("SELECT COUNT(*) FROM admins WHERE is_active = 1").Scan(&stats.ActiveAdmins)
	DB.db.QueryRow("SELECT COUNT(*) FROM admins WHERE is_active = 0").Scan(&stats.DisabledAdmins)
	DB.db.QueryRow("SELECT COALESCE(SUM(traffic_used), 0) FROM admins").Scan(&stats.TotalTrafficUsed)
	DB.db.QueryRow("SELECT COALESCE(SUM(users_created), 0) FROM admins").Scan(&stats.TotalUsersCreated)

	return stats, nil
}

// GetAdminDetailedStats returns detailed stats for a specific admin
func (am *AdminManager) GetAdminDetailedStats(adminID int64) (map[string]interface{}, error) {
	admin, err := am.GetAdminByID(adminID)
	if err != nil {
		return nil, err
	}

	stats := map[string]interface{}{
		"id":            admin.ID,
		"username":      admin.Username,
		"role":          admin.Role,
		"is_active":     admin.IsActive,
		"users_created": admin.UsersCreated,
		"traffic_used":  admin.TrafficUsed,
		"traffic_limit": admin.TrafficLimit,
		"user_limit":    admin.UserLimit,
		"last_login":    admin.LastLogin,
		"created_at":    admin.CreatedAt,
	}

	// Get user stats
	var activeUsers, expiredUsers, limitedUsers int
	var totalUserTraffic int64

	DB.db.QueryRow(`
		SELECT COUNT(*) FROM users 
		WHERE created_by_admin_id = ? AND status = ?
	`, adminID, UserStatusActive).Scan(&activeUsers)

	DB.db.QueryRow(`
		SELECT COUNT(*) FROM users 
		WHERE created_by_admin_id = ? AND status = ?
	`, adminID, UserStatusExpired).Scan(&expiredUsers)

	DB.db.QueryRow(`
		SELECT COUNT(*) FROM users 
		WHERE created_by_admin_id = ? AND status = ?
	`, adminID, UserStatusLimited).Scan(&limitedUsers)

	DB.db.QueryRow(`
		SELECT COALESCE(SUM(data_used), 0) FROM users 
		WHERE created_by_admin_id = ?
	`, adminID).Scan(&totalUserTraffic)

	stats["active_users"] = activeUsers
	stats["expired_users"] = expiredUsers
	stats["limited_users"] = limitedUsers
	stats["total_user_traffic"] = totalUserTraffic

	// Online users count
	if Users != nil {
		stats["online_users"] = len(Users.GetOnlineUsersForAdmin(adminID))
	}

	// Usage percentages for resellers
	if admin.Role == AdminRoleReseller {
		userPercent, trafficPercent := am.GetResellerUsagePercent(admin)
		stats["user_usage_percent"] = userPercent
		stats["traffic_usage_percent"] = trafficPercent

		if admin.UserLimit > 0 {
			stats["remaining_users"] = admin.UserLimit - admin.UsersCreated
		}
		if admin.TrafficLimit > 0 {
			stats["remaining_traffic"] = admin.TrafficLimit - admin.TrafficUsed
		}
	}

	return stats, nil
}

// GetTopResellers returns top resellers by user count or traffic
func (am *AdminManager) GetTopResellers(sortBy string, limit int) ([]*Admin, error) {
	validSorts := map[string]string{
		"users":   "users_created",
		"traffic": "traffic_used",
	}

	orderBy, ok := validSorts[sortBy]
	if !ok {
		orderBy = "users_created"
	}

	if limit <= 0 || limit > 100 {
		limit = 10
	}

	query := fmt.Sprintf(`
		SELECT id, username, password, email, role, is_active,
		       telegram_id, telegram_username, parent_admin_id,
		       traffic_limit, user_limit, traffic_used, users_created,
		       last_login, last_ip, created_at, updated_at
		FROM admins 
		WHERE role = ? 
		ORDER BY %s DESC 
		LIMIT ?
	`, orderBy)

	rows, err := DB.db.Query(query, AdminRoleReseller, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	admins := []*Admin{}
	for rows.Next() {
		admin := &Admin{}
		err := rows.Scan(
			&admin.ID, &admin.Username, &admin.Password, &admin.Email,
			&admin.Role, &admin.IsActive, &admin.TelegramID, &admin.TelegramUsername,
			&admin.ParentAdminID, &admin.TrafficLimit, &admin.UserLimit,
			&admin.TrafficUsed, &admin.UsersCreated, &admin.LastLogin,
			&admin.LastIP, &admin.CreatedAt, &admin.UpdatedAt,
		)
		if err != nil {
			continue
		}
		admins = append(admins, admin)
	}

	return admins, nil
}

// ============================================================================
// USER REASSIGNMENT
// ============================================================================

// ReassignUsers transfers users from one admin to another
func (am *AdminManager) ReassignUsers(fromAdminID, toAdminID int64) (int, error) {
	// Verify both admins exist
	_, err := am.GetAdminByID(fromAdminID)
	if err != nil {
		return 0, fmt.Errorf("source admin not found: %w", err)
	}

	toAdmin, err := am.GetAdminByID(toAdminID)
	if err != nil {
		return 0, fmt.Errorf("target admin not found: %w", err)
	}

	// Check if target is a reseller with limits
	if toAdmin.Role == AdminRoleReseller && toAdmin.UserLimit > 0 {
		var userCount int
		DB.db.QueryRow("SELECT COUNT(*) FROM users WHERE created_by_admin_id = ?", fromAdminID).Scan(&userCount)

		if toAdmin.UsersCreated+userCount > toAdmin.UserLimit {
			return 0, errors.New("target admin does not have enough user quota")
		}
	}

	// Perform reassignment
	result, err := DB.db.Exec(`
		UPDATE users SET created_by_admin_id = ?, updated_at = ?
		WHERE created_by_admin_id = ?
	`, toAdminID, time.Now(), fromAdminID)
	if err != nil {
		return 0, err
	}

	affected, _ := result.RowsAffected()
	count := int(affected)

	// Update admin user counts
	DB.db.Exec("UPDATE admins SET users_created = users_created - ? WHERE id = ?", count, fromAdminID)
	DB.db.Exec("UPDATE admins SET users_created = users_created + ? WHERE id = ?", count, toAdminID)

	// Update cache
	am.mu.Lock()
	if admin, exists := am.adminCache[fromAdminID]; exists {
		admin.UsersCreated -= count
		if admin.UsersCreated < 0 {
			admin.UsersCreated = 0
		}
	}
	if admin, exists := am.adminCache[toAdminID]; exists {
		admin.UsersCreated += count
	}
	am.mu.Unlock()

	return count, nil
}

// ============================================================================
// AUDIT HELPERS
// ============================================================================

// LogAdminAction logs an admin action
func (am *AdminManager) LogAdminAction(admin *Admin, action, resource string, resourceID int64, oldValue, newValue interface{}, ip, userAgent string) error {
	if admin == nil {
		return nil
	}

	var oldJSON, newJSON sql.NullString

	if oldValue != nil {
		data, _ := json.Marshal(oldValue)
		oldJSON = sql.NullString{String: string(data), Valid: true}
	}
	if newValue != nil {
		data, _ := json.Marshal(newValue)
		newJSON = sql.NullString{String: string(data), Valid: true}
	}

	_, err := DB.db.Exec(`
		INSERT INTO audit_logs (admin_id, admin_username, action, resource, resource_id, old_value, new_value, ip, user_agent, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, admin.ID, admin.Username, action, resource, resourceID, oldJSON, newJSON, ip, userAgent, time.Now())

	return err
}

// GetAdminAuditLogs returns audit logs for an admin
func (am *AdminManager) GetAdminAuditLogs(adminID int64, limit, offset int) ([]AuditLog, int, error) {
	var total int
	DB.db.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE admin_id = ?", adminID).Scan(&total)

	if limit <= 0 {
		limit = 50
	}

	rows, err := DB.db.Query(`
		SELECT id, admin_id, admin_username, action, resource, resource_id,
		       old_value, new_value, ip, user_agent, created_at
		FROM audit_logs
		WHERE admin_id = ?
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`, adminID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	logs := []AuditLog{}
	for rows.Next() {
		log := AuditLog{}
		var oldValue, newValue sql.NullString
		err := rows.Scan(
			&log.ID, &log.AdminID, &log.AdminUsername, &log.Action,
			&log.Resource, &log.ResourceID, &oldValue, &newValue,
			&log.IP, &log.UserAgent, &log.CreatedAt,
		)
		if err != nil {
			continue
		}
		if oldValue.Valid {
			log.OldValue = oldValue.String
		}
		if newValue.Valid {
			log.NewValue = newValue.String
		}
		logs = append(logs, log)
	}

	return logs, total, nil
}

// ============================================================================
// NOTIFICATIONS
// ============================================================================

// AdminNotification represents a notification for admins
type AdminNotification struct {
	ID        int64     `json:"id"`
	AdminID   int64     `json:"admin_id"`
	Type      string    `json:"type"`
	Title     string    `json:"title"`
	Message   string    `json:"message"`
	IsRead    bool      `json:"is_read"`
	Data      string    `json:"data,omitempty"` // JSON
	CreatedAt time.Time `json:"created_at"`
}

// SendNotification sends a notification to an admin
func (am *AdminManager) SendNotification(adminID int64, notificationType, title, message string, data interface{}) error {
	var dataJSON string
	if data != nil {
		bytes, _ := json.Marshal(data)
		dataJSON = string(bytes)
	}

	_, err := DB.db.Exec(`
		INSERT INTO admin_notifications (admin_id, type, title, message, data, is_read, created_at)
		VALUES (?, ?, ?, ?, ?, 0, ?)
	`, adminID, notificationType, title, message, dataJSON, time.Now())

	return err
}

// SendNotificationToAllOwners sends notification to all owner admins
func (am *AdminManager) SendNotificationToAllOwners(notificationType, title, message string, data interface{}) error {
	owners, err := am.GetOwnerAdmins()
	if err != nil {
		return err
	}

	for _, owner := range owners {
		am.SendNotification(owner.ID, notificationType, title, message, data)
	}

	return nil
}

// ============================================================================
// IMPORT/EXPORT HELPERS
// ============================================================================

// AdminExport represents exported admin data
type AdminExport struct {
	Username         string `json:"username"`
	Email            string `json:"email,omitempty"`
	Role             string `json:"role"`
	TelegramUsername string `json:"telegram_username,omitempty"`
	TrafficLimit     int64  `json:"traffic_limit,omitempty"`
	UserLimit        int    `json:"user_limit,omitempty"`
}

// ExportAdmins exports admins to a list
func (am *AdminManager) ExportAdmins() ([]*AdminExport, error) {
	admins, err := am.GetAllAdmins()
	if err != nil {
		return nil, err
	}

	exports := make([]*AdminExport, len(admins))
	for i, admin := range admins {
		exports[i] = &AdminExport{
			Username:         admin.Username,
			Email:            admin.Email,
			Role:             admin.Role,
			TelegramUsername: admin.TelegramUsername,
			TrafficLimit:     admin.TrafficLimit,
			UserLimit:        admin.UserLimit,
		}
	}

	return exports, nil
}

// ============================================================================
// DASHBOARD DATA
// ============================================================================

// GetOwnerDashboard returns dashboard data for owner
func (am *AdminManager) GetOwnerDashboard() (map[string]interface{}, error) {
	data := make(map[string]interface{})

	// Admin stats
	adminStats, _ := am.GetAdminStats()
	data["admin_stats"] = adminStats

	// User stats
	if Users != nil {
		userStats, _ := Users.GetUserStats()
		data["user_stats"] = userStats
	}

	// System stats
	if DB != nil {
		sysStats, _ := DB.GetSystemStats()
		data["system_stats"] = sysStats
	}

	// Top resellers
	topResellers, _ := am.GetTopResellers("users", 5)
	data["top_resellers"] = topResellers

	// Recent activity
	logs, _, _ := am.GetAdminAuditLogs(0, 10, 0) // All admins
	data["recent_activity"] = logs

	return data, nil
}

// GetResellerDashboard returns dashboard data for reseller
func (am *AdminManager) GetResellerDashboard(adminID int64) (map[string]interface{}, error) {
	data := make(map[string]interface{})

	// Admin details
	adminStats, _ := am.GetAdminDetailedStats(adminID)
	data["admin_stats"] = adminStats

	// User stats for this admin
	if Users != nil {
		userStats, _ := Users.GetUserStatsForAdmin(adminID)
		data["user_stats"] = userStats
	}

	// Recent users
	if Users != nil {
		result, _ := Users.ListUsers(&UserFilter{
			AdminID:   adminID,
			SortBy:    "created_at",
			SortOrder: "desc",
			Limit:     10,
		})
		if result != nil {
			data["recent_users"] = result.Users
		}
	}

	// Online users
	if Users != nil {
		data["online_users"] = Users.GetOnlineUsersForAdmin(adminID)
	}

	return data, nil
}
