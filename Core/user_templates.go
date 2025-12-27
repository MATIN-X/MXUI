package core

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// UserTemplate represents a user template for quick user creation
type UserTemplate struct {
	ID             int64     `json:"id"`
	Name           string    `json:"name"`
	TrafficLimit   uint64    `json:"traffic_limit"`
	ExpiryDays     int       `json:"expiry_days"`
	MaxConnections int       `json:"max_connections"`
	Protocol       string    `json:"protocol"`
	Enabled        bool      `json:"enabled"`
	Description    string    `json:"description"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// TemplateManager manages user templates
type TemplateManager struct {
	db *sql.DB
}

// NewTemplateManager creates a new template manager
func NewTemplateManager(db *sql.DB) *TemplateManager {
	return &TemplateManager{db: db}
}

// CreateTemplate creates a new user template
func (tm *TemplateManager) CreateTemplate(template *UserTemplate) error {
	template.CreatedAt = time.Now()
	template.UpdatedAt = time.Now()

	result, err := tm.db.Exec(`
		INSERT INTO user_templates 
		(name, traffic_limit, expiry_days, max_connections, protocol, enabled, description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		template.Name,
		template.TrafficLimit,
		template.ExpiryDays,
		template.MaxConnections,
		template.Protocol,
		template.Enabled,
		template.Description,
		template.CreatedAt,
		template.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create template: %w", err)
	}

	template.ID, _ = result.LastInsertId()
	return nil
}

// GetTemplate retrieves a template by ID
func (tm *TemplateManager) GetTemplate(id int64) (*UserTemplate, error) {
	template := &UserTemplate{}

	err := tm.db.QueryRow(`
		SELECT id, name, traffic_limit, expiry_days, max_connections, protocol, enabled, description, created_at, updated_at
		FROM user_templates
		WHERE id = ?
	`, id).Scan(
		&template.ID,
		&template.Name,
		&template.TrafficLimit,
		&template.ExpiryDays,
		&template.MaxConnections,
		&template.Protocol,
		&template.Enabled,
		&template.Description,
		&template.CreatedAt,
		&template.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return template, nil
}

// GetAllTemplates retrieves all templates
func (tm *TemplateManager) GetAllTemplates() ([]UserTemplate, error) {
	rows, err := tm.db.Query(`
		SELECT id, name, traffic_limit, expiry_days, max_connections, protocol, enabled, description, created_at, updated_at
		FROM user_templates
		ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	templates := []UserTemplate{}
	for rows.Next() {
		var template UserTemplate
		err := rows.Scan(
			&template.ID,
			&template.Name,
			&template.TrafficLimit,
			&template.ExpiryDays,
			&template.MaxConnections,
			&template.Protocol,
			&template.Enabled,
			&template.Description,
			&template.CreatedAt,
			&template.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		templates = append(templates, template)
	}

	return templates, nil
}

// UpdateTemplate updates a template
func (tm *TemplateManager) UpdateTemplate(template *UserTemplate) error {
	template.UpdatedAt = time.Now()

	_, err := tm.db.Exec(`
		UPDATE user_templates
		SET name = ?, traffic_limit = ?, expiry_days = ?, max_connections = ?, 
		    protocol = ?, enabled = ?, description = ?, updated_at = ?
		WHERE id = ?
	`,
		template.Name,
		template.TrafficLimit,
		template.ExpiryDays,
		template.MaxConnections,
		template.Protocol,
		template.Enabled,
		template.Description,
		template.UpdatedAt,
		template.ID,
	)

	return err
}

// DeleteTemplate deletes a template
func (tm *TemplateManager) DeleteTemplate(id int64) error {
	_, err := tm.db.Exec("DELETE FROM user_templates WHERE id = ?", id)
	return err
}

// CreateUserFromTemplate creates a new user based on a template
func (tm *TemplateManager) CreateUserFromTemplate(templateID int64, username, password string) error {
	// Get template
	template, err := tm.GetTemplate(templateID)
	if err != nil {
		return fmt.Errorf("template not found: %w", err)
	}

	// Calculate expiry date
	var expiryDate *time.Time
	if template.ExpiryDays > 0 {
		expiry := time.Now().AddDate(0, 0, template.ExpiryDays)
		expiryDate = &expiry
	}

	// Create user
	// TODO: Use actual user creation function
	_, err = tm.db.Exec(`
		INSERT INTO users 
		(username, password, traffic_limit, expiry_date, max_connections, protocol, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		username,
		password, // Should be hashed
		template.TrafficLimit,
		expiryDate,
		template.MaxConnections,
		template.Protocol,
		template.Enabled,
		time.Now(),
		time.Now(),
	)

	return err
}

// BulkAction represents an action to perform on multiple users
type BulkAction struct {
	Action    string                 `json:"action"` // disable, enable, delete, reset_traffic, extend_expiry
	UserIDs   []int64                `json:"user_ids"`
	ExtraData map[string]interface{} `json:"extra_data,omitempty"`
}

// BulkUserManager manages bulk user operations
type BulkUserManager struct {
	db *sql.DB
}

// NewBulkUserManager creates a new bulk user manager
func NewBulkUserManager(db *sql.DB) *BulkUserManager {
	return &BulkUserManager{db: db}
}

// ExecuteBulkAction executes a bulk action on users
func (bum *BulkUserManager) ExecuteBulkAction(action *BulkAction) (int, error) {
	if len(action.UserIDs) == 0 {
		return 0, fmt.Errorf("no user IDs provided")
	}

	affected := 0

	switch action.Action {
	case "disable":
		affected, err := bum.bulkDisable(action.UserIDs)
		return affected, err

	case "enable":
		affected, err := bum.bulkEnable(action.UserIDs)
		return affected, err

	case "delete":
		affected, err := bum.bulkDelete(action.UserIDs)
		return affected, err

	case "reset_traffic":
		affected, err := bum.bulkResetTraffic(action.UserIDs)
		return affected, err

	case "extend_expiry":
		days, ok := action.ExtraData["days"].(float64)
		if !ok {
			return 0, fmt.Errorf("days parameter required for extend_expiry action")
		}
		affected, err := bum.bulkExtendExpiry(action.UserIDs, int(days))
		return affected, err

	case "add_traffic":
		traffic, ok := action.ExtraData["traffic"].(float64)
		if !ok {
			return 0, fmt.Errorf("traffic parameter required for add_traffic action")
		}
		affected, err := bum.bulkAddTraffic(action.UserIDs, uint64(traffic))
		return affected, err

	default:
		return 0, fmt.Errorf("unknown action: %s", action.Action)
	}

	return affected, nil
}

// bulkDisable disables multiple users
func (bum *BulkUserManager) bulkDisable(userIDs []int64) (int, error) {
	// Create placeholders for IN clause
	placeholders := make([]interface{}, len(userIDs))
	for i, id := range userIDs {
		placeholders[i] = id
	}

	query := "UPDATE users SET enabled = 0 WHERE id IN (?" + repeatPlaceholders(len(userIDs)-1) + ")"
	result, err := bum.db.Exec(query, placeholders...)
	if err != nil {
		return 0, err
	}

	affected, _ := result.RowsAffected()
	return int(affected), nil
}

// bulkEnable enables multiple users
func (bum *BulkUserManager) bulkEnable(userIDs []int64) (int, error) {
	placeholders := make([]interface{}, len(userIDs))
	for i, id := range userIDs {
		placeholders[i] = id
	}

	query := "UPDATE users SET enabled = 1 WHERE id IN (?" + repeatPlaceholders(len(userIDs)-1) + ")"
	result, err := bum.db.Exec(query, placeholders...)
	if err != nil {
		return 0, err
	}

	affected, _ := result.RowsAffected()
	return int(affected), nil
}

// bulkDelete deletes multiple users
func (bum *BulkUserManager) bulkDelete(userIDs []int64) (int, error) {
	placeholders := make([]interface{}, len(userIDs))
	for i, id := range userIDs {
		placeholders[i] = id
	}

	query := "DELETE FROM users WHERE id IN (?" + repeatPlaceholders(len(userIDs)-1) + ")"
	result, err := bum.db.Exec(query, placeholders...)
	if err != nil {
		return 0, err
	}

	affected, _ := result.RowsAffected()
	return int(affected), nil
}

// bulkResetTraffic resets traffic usage for multiple users
func (bum *BulkUserManager) bulkResetTraffic(userIDs []int64) (int, error) {
	placeholders := make([]interface{}, len(userIDs))
	for i, id := range userIDs {
		placeholders[i] = id
	}

	query := "UPDATE users SET traffic_used = 0 WHERE id IN (?" + repeatPlaceholders(len(userIDs)-1) + ")"
	result, err := bum.db.Exec(query, placeholders...)
	if err != nil {
		return 0, err
	}

	affected, _ := result.RowsAffected()
	return int(affected), nil
}

// bulkExtendExpiry extends expiry date for multiple users
func (bum *BulkUserManager) bulkExtendExpiry(userIDs []int64, days int) (int, error) {
	placeholders := make([]interface{}, len(userIDs)+1)
	placeholders[0] = days
	for i, id := range userIDs {
		placeholders[i+1] = id
	}

	query := "UPDATE users SET expiry_date = datetime(expiry_date, '+' || ? || ' days') WHERE id IN (?" + repeatPlaceholders(len(userIDs)-1) + ")"
	result, err := bum.db.Exec(query, placeholders...)
	if err != nil {
		return 0, err
	}

	affected, _ := result.RowsAffected()
	return int(affected), nil
}

// bulkAddTraffic adds traffic limit to multiple users
func (bum *BulkUserManager) bulkAddTraffic(userIDs []int64, traffic uint64) (int, error) {
	placeholders := make([]interface{}, len(userIDs)+1)
	placeholders[0] = traffic
	for i, id := range userIDs {
		placeholders[i+1] = id
	}

	query := "UPDATE users SET traffic_limit = traffic_limit + ? WHERE id IN (?" + repeatPlaceholders(len(userIDs)-1) + ")"
	result, err := bum.db.Exec(query, placeholders...)
	if err != nil {
		return 0, err
	}

	affected, _ := result.RowsAffected()
	return int(affected), nil
}

// repeatPlaceholders generates repeated SQL placeholders
func repeatPlaceholders(count int) string {
	if count <= 0 {
		return ""
	}
	result := ""
	for i := 0; i < count; i++ {
		result += ", ?"
	}
	return result
}

// ExportUsers exports users to JSON
func (bum *BulkUserManager) ExportUsers(userIDs []int64) (string, error) {
	placeholders := make([]interface{}, len(userIDs))
	for i, id := range userIDs {
		placeholders[i] = id
	}

	query := "SELECT * FROM users WHERE id IN (?" + repeatPlaceholders(len(userIDs)-1) + ")"
	rows, err := bum.db.Query(query, placeholders...)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	users := []map[string]interface{}{}
	columns, _ := rows.Columns()

	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return "", err
		}

		user := make(map[string]interface{})
		for i, col := range columns {
			user[col] = values[i]
		}
		users = append(users, user)
	}

	data, err := json.MarshalIndent(users, "", "  ")
	return string(data), err
}

// InitTemplateTable initializes the user template table
func InitTemplateTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS user_templates (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name VARCHAR(100) NOT NULL UNIQUE,
			traffic_limit BIGINT NOT NULL DEFAULT 0,
			expiry_days INTEGER NOT NULL DEFAULT 30,
			max_connections INTEGER NOT NULL DEFAULT 2,
			protocol VARCHAR(20) NOT NULL DEFAULT 'vmess',
			enabled BOOLEAN NOT NULL DEFAULT 1,
			description TEXT,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)
	`)
	return err
}
