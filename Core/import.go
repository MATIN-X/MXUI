// MXUI VPN Panel
// Core/import.go
// Panel Import: Import users and settings from other panels (Marzban, 3x-ui, Hiddify)

package core

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

// PanelImporter handles importing data from other VPN panels
type PanelImporter struct {
	db        *DatabaseManager
	imported  ImportResult
	errors    []string
	onProgress func(phase string, current, total int)
}

// ImportResult contains statistics about the import
type ImportResult struct {
	PanelType     string    `json:"panel_type"`
	UsersImported int       `json:"users_imported"`
	UsersFailed   int       `json:"users_failed"`
	AdminsImported int      `json:"admins_imported"`
	InboundsImported int    `json:"inbounds_imported"`
	StartTime     time.Time `json:"start_time"`
	EndTime       time.Time `json:"end_time"`
	Errors        []string  `json:"errors,omitempty"`
}

// NewPanelImporter creates a new importer
func NewPanelImporter(db *DatabaseManager) *PanelImporter {
	return &PanelImporter{
		db:     db,
		errors: []string{},
	}
}

// SetProgressCallback sets a callback for progress updates
func (pi *PanelImporter) SetProgressCallback(fn func(phase string, current, total int)) {
	pi.onProgress = fn
}

func (pi *PanelImporter) reportProgress(phase string, current, total int) {
	if pi.onProgress != nil {
		pi.onProgress(phase, current, total)
	}
}

func (pi *PanelImporter) addError(err string) {
	pi.errors = append(pi.errors, err)
	pi.imported.UsersFailed++
}

// hasTable checks if a table exists in the database
func (pi *PanelImporter) hasTable(db *sql.DB, tableName string) bool {
	query := "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
	var name string
	err := db.QueryRow(query, tableName).Scan(&name)
	return err == nil
}

// hasColumn checks if a column exists in a table
func (pi *PanelImporter) hasColumn(db *sql.DB, tableName, columnName string) bool {
	query := "PRAGMA table_info(" + tableName + ")"
	rows, err := db.Query(query)
	if err != nil {
		return false
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name string
		var dataType string
		var notNull int
		var dfltValue interface{}
		var pk int
		rows.Scan(&cid, &name, &dataType, &notNull, &dfltValue, &pk)
		if name == columnName {
			return true
		}
	}
	return false
}

// DetectPanelType detects the type of panel from database structure
func (pi *PanelImporter) DetectPanelType(dbPath string) string {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return "unknown"
	}
	defer db.Close()

	// Check for Marzban tables
	if pi.hasTable(db, "users") && pi.hasTable(db, "admins") {
		if pi.hasColumn(db, "users", "data_limit_reset_strategy") {
			return "marzban"
		}
	}

	// Check for 3x-ui tables
	if pi.hasTable(db, "inbounds") && pi.hasTable(db, "settings") {
		if pi.hasColumn(db, "inbounds", "stream_settings") {
			return "3xui"
		}
	}

	// Check for Hiddify tables
	if pi.hasTable(db, "domain") && pi.hasTable(db, "child") {
		return "hiddify"
	}

	// Check for x-ui (older version)
	if pi.hasTable(db, "inbounds") && !pi.hasColumn(db, "inbounds", "stream_settings") {
		return "xui"
	}

	return "unknown"
}

// Import imports data from any supported panel
func (pi *PanelImporter) Import(dbPath string) (*ImportResult, error) {
	pi.imported = ImportResult{
		StartTime: time.Now(),
	}

	// Check if file exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("database file not found: %s", dbPath)
	}

	// Detect panel type
	panelType := pi.DetectPanelType(dbPath)
	pi.imported.PanelType = panelType

	var err error
	switch panelType {
	case "marzban":
		err = pi.ImportFromMarzban(dbPath)
	case "3xui":
		err = pi.ImportFrom3XUI(dbPath)
	case "hiddify":
		err = pi.ImportFromHiddify(dbPath)
	case "xui":
		err = pi.ImportFromXUI(dbPath)
	default:
		return nil, fmt.Errorf("unknown panel type, cannot import")
	}

	pi.imported.EndTime = time.Now()
	pi.imported.Errors = pi.errors

	return &pi.imported, err
}

// ============================================================================
// MARZBAN IMPORT
// ============================================================================

// MarzbanUser represents a user in Marzban database
type MarzbanUser struct {
	ID                     int64
	Username               string
	ProxySettings          string
	Status                 string
	UsedTrafficBytes       int64
	DataLimit              int64
	DataLimitResetStrategy string
	ExpireDate             *int64
	CreatedAt              time.Time
	AdminID                int64
	Note                   string
}

// ImportFromMarzban imports users from Marzban database
func (pi *PanelImporter) ImportFromMarzban(dbPath string) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open Marzban database: %w", err)
	}
	defer db.Close()

	// Import admins first
	if err := pi.importMarzbanAdmins(db); err != nil {
		pi.addError(fmt.Sprintf("Failed to import admins: %v", err))
	}

	// Import users
	if err := pi.importMarzbanUsers(db); err != nil {
		return fmt.Errorf("failed to import users: %w", err)
	}

	return nil
}

func (pi *PanelImporter) importMarzbanAdmins(db *sql.DB) error {
	rows, err := db.Query(`
		SELECT id, username, hashed_password, is_sudo, created_at
		FROM admins
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id int64
		var username, hashedPassword string
		var isSudo bool
		var createdAt time.Time

		if err := rows.Scan(&id, &username, &hashedPassword, &isSudo, &createdAt); err != nil {
			continue
		}

		// Skip if admin already exists
		if _, err := Admins.GetAdminByUsername(username); err == nil {
			continue
		}

		role := "admin"
		if isSudo {
			role = "owner"
		}

		// Create admin in MXUI
		_, err := DB.db.Exec(`
			INSERT INTO admins (username, password_hash, role, is_active, created_at)
			VALUES (?, ?, ?, 1, ?)
		`, username, hashedPassword, role, createdAt)

		if err == nil {
			pi.imported.AdminsImported++
		}
	}

	return nil
}

func (pi *PanelImporter) importMarzbanUsers(db *sql.DB) error {
	rows, err := db.Query(`
		SELECT id, username, proxies, status, used_traffic, data_limit,
		       data_limit_reset_strategy, expire, created_at, admin_id, note
		FROM users
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var users []MarzbanUser
	for rows.Next() {
		var user MarzbanUser
		var proxies sql.NullString
		var note sql.NullString
		var expireDate sql.NullInt64

		err := rows.Scan(
			&user.ID, &user.Username, &proxies, &user.Status,
			&user.UsedTrafficBytes, &user.DataLimit, &user.DataLimitResetStrategy,
			&expireDate, &user.CreatedAt, &user.AdminID, &note,
		)
		if err != nil {
			pi.addError(fmt.Sprintf("Failed to scan user: %v", err))
			continue
		}

		if proxies.Valid {
			user.ProxySettings = proxies.String
		}
		if note.Valid {
			user.Note = note.String
		}
		if expireDate.Valid {
			user.ExpireDate = &expireDate.Int64
		}

		users = append(users, user)
	}

	total := len(users)
	for i, user := range users {
		pi.reportProgress("Importing Marzban users", i+1, total)

		if err := pi.createUserFromMarzban(user); err != nil {
			pi.addError(fmt.Sprintf("Failed to import user %s: %v", user.Username, err))
		} else {
			pi.imported.UsersImported++
		}
	}

	return nil
}

func (pi *PanelImporter) createUserFromMarzban(mUser MarzbanUser) error {
	// Extract UUID from proxy settings
	userUUID := uuid.New().String()
	if mUser.ProxySettings != "" {
		var proxies map[string]interface{}
		if err := json.Unmarshal([]byte(mUser.ProxySettings), &proxies); err == nil {
			// Try to extract UUID from vmess, vless, or trojan
			for _, v := range proxies {
				if proxy, ok := v.(map[string]interface{}); ok {
					if id, exists := proxy["id"]; exists {
						userUUID = fmt.Sprintf("%v", id)
						break
					}
					if password, exists := proxy["password"]; exists {
						userUUID = fmt.Sprintf("%v", password)
						break
					}
				}
			}
		}
	}

	// Map status
	status := UserStatusActive
	switch mUser.Status {
	case "disabled", "limited", "expired":
		status = UserStatusDisabled
	}

	// Calculate expiry
	var expiryTime *time.Time
	if mUser.ExpireDate != nil && *mUser.ExpireDate > 0 {
		t := time.Unix(*mUser.ExpireDate, 0)
		expiryTime = &t
	}

	// Create user in MXUI
	req := &CreateUserRequest{
		Username:    mUser.Username,
		DataLimit:   mUser.DataLimit,
		Note:        mUser.Note,
	}

	user, err := Users.CreateUser(req)
	if err != nil {
		return err
	}

	// Update with imported data
	_, err = DB.db.Exec(`
		UPDATE users SET
			uuid = ?,
			status = ?,
			upload = 0,
			download = ?,
			expiry_time = ?,
			note = ?
		WHERE id = ?
	`, userUUID, status, mUser.UsedTrafficBytes, expiryTime, mUser.Note, user.ID)

	return err
}

// ============================================================================
// 3X-UI IMPORT
// ============================================================================

// XUIInbound represents an inbound in 3x-ui
type XUIInbound struct {
	ID             int64
	UserID         int64
	Up             int64
	Down           int64
	Total          int64
	Remark         string
	Enable         bool
	ExpiryTime     int64
	Listen         string
	Port           int
	Protocol       string
	Settings       string
	StreamSettings string
	Tag            string
	Sniffing       string
}

// ImportFrom3XUI imports users and inbounds from 3x-ui database
func (pi *PanelImporter) ImportFrom3XUI(dbPath string) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open 3x-ui database: %w", err)
	}
	defer db.Close()

	// Import inbounds and extract users
	rows, err := db.Query(`
		SELECT id, user_id, up, down, total, remark, enable, expiry_time,
		       listen, port, protocol, settings, stream_settings, tag, sniffing
		FROM inbounds
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var inbounds []XUIInbound
	for rows.Next() {
		var inbound XUIInbound
		var listen, sniffing sql.NullString

		err := rows.Scan(
			&inbound.ID, &inbound.UserID, &inbound.Up, &inbound.Down,
			&inbound.Total, &inbound.Remark, &inbound.Enable, &inbound.ExpiryTime,
			&listen, &inbound.Port, &inbound.Protocol, &inbound.Settings,
			&inbound.StreamSettings, &inbound.Tag, &sniffing,
		)
		if err != nil {
			pi.addError(fmt.Sprintf("Failed to scan inbound: %v", err))
			continue
		}

		if listen.Valid {
			inbound.Listen = listen.String
		}
		if sniffing.Valid {
			inbound.Sniffing = sniffing.String
		}

		inbounds = append(inbounds, inbound)
	}

	// Process each inbound
	total := len(inbounds)
	for i, inbound := range inbounds {
		pi.reportProgress("Importing 3x-ui inbounds", i+1, total)

		if err := pi.importXUIInbound(inbound); err != nil {
			pi.addError(fmt.Sprintf("Failed to import inbound %s: %v", inbound.Remark, err))
		} else {
			pi.imported.InboundsImported++
		}
	}

	return nil
}

func (pi *PanelImporter) importXUIInbound(inbound XUIInbound) error {
	// Parse settings to extract clients
	var settings map[string]interface{}
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		return fmt.Errorf("failed to parse settings: %w", err)
	}

	// Extract clients
	clients, ok := settings["clients"].([]interface{})
	if !ok {
		return nil // No clients in this inbound
	}

	for _, c := range clients {
		client, ok := c.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract user info
		email, _ := client["email"].(string)
		if email == "" {
			email = fmt.Sprintf("user_%d", time.Now().UnixNano())
		}

		userUUID := ""
		if id, exists := client["id"]; exists {
			userUUID = fmt.Sprintf("%v", id)
		} else if password, exists := client["password"]; exists {
			userUUID = fmt.Sprintf("%v", password)
		} else {
			userUUID = uuid.New().String()
		}

		// Check if user already exists
		if _, err := Users.GetUserByUsername(email); err == nil {
			continue
		}

		// Create user
		req := &CreateUserRequest{
			Username:  email,
			DataLimit: inbound.Total,
		}

		user, err := Users.CreateUser(req)
		if err != nil {
			pi.addError(fmt.Sprintf("Failed to create user %s: %v", email, err))
			continue
		}

		// Update with imported data
		status := UserStatusActive
		if !inbound.Enable {
			status = UserStatusDisabled
		}

		var expiryTime *time.Time
		if inbound.ExpiryTime > 0 {
			t := time.Unix(inbound.ExpiryTime/1000, 0)
			expiryTime = &t
		}

		_, err = DB.db.Exec(`
			UPDATE users SET
				uuid = ?,
				status = ?,
				upload = ?,
				download = ?,
				expiry_time = ?
			WHERE id = ?
		`, userUUID, status, inbound.Up, inbound.Down, expiryTime, user.ID)

		if err == nil {
			pi.imported.UsersImported++
		}
	}

	return nil
}

// ============================================================================
// HIDDIFY IMPORT
// ============================================================================

// HiddifyUser represents a user in Hiddify
type HiddifyUser struct {
	UUID         string
	Name         string
	UsageLimitGB float64
	PackageDays  int
	Mode         string
	StartDate    time.Time
	CurrentUsage float64
	LastOnline   *time.Time
	Comment      string
	Enable       bool
}

// ImportFromHiddify imports users from Hiddify database
func (pi *PanelImporter) ImportFromHiddify(dbPath string) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open Hiddify database: %w", err)
	}
	defer db.Close()

	// Query users from Hiddify
	rows, err := db.Query(`
		SELECT uuid, name, usage_limit_GB, package_days, mode,
		       start_date, current_usage_GB, last_online, comment, enable
		FROM user
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var users []HiddifyUser
	for rows.Next() {
		var user HiddifyUser
		var lastOnline sql.NullTime
		var comment sql.NullString

		err := rows.Scan(
			&user.UUID, &user.Name, &user.UsageLimitGB, &user.PackageDays,
			&user.Mode, &user.StartDate, &user.CurrentUsage, &lastOnline,
			&comment, &user.Enable,
		)
		if err != nil {
			pi.addError(fmt.Sprintf("Failed to scan user: %v", err))
			continue
		}

		if lastOnline.Valid {
			user.LastOnline = &lastOnline.Time
		}
		if comment.Valid {
			user.Comment = comment.String
		}

		users = append(users, user)
	}

	total := len(users)
	for i, user := range users {
		pi.reportProgress("Importing Hiddify users", i+1, total)

		if err := pi.createUserFromHiddify(user); err != nil {
			pi.addError(fmt.Sprintf("Failed to import user %s: %v", user.Name, err))
		} else {
			pi.imported.UsersImported++
		}
	}

	return nil
}

func (pi *PanelImporter) createUserFromHiddify(hUser HiddifyUser) error {
	// Check if user already exists
	if _, err := Users.GetUserByUsername(hUser.Name); err == nil {
		return fmt.Errorf("user already exists")
	}

	// Calculate data limit in bytes
	dataLimit := int64(hUser.UsageLimitGB * 1024 * 1024 * 1024)

	// Calculate expiry
	var expiryTime *time.Time
	if hUser.PackageDays > 0 {
		t := hUser.StartDate.AddDate(0, 0, hUser.PackageDays)
		expiryTime = &t
	}

	// Create user
	req := &CreateUserRequest{
		Username:  hUser.Name,
		DataLimit: dataLimit,
		Note:      hUser.Comment,
	}

	user, err := Users.CreateUser(req)
	if err != nil {
		return err
	}

	// Update with imported data
	status := UserStatusActive
	if !hUser.Enable {
		status = UserStatusDisabled
	}

	currentUsage := int64(hUser.CurrentUsage * 1024 * 1024 * 1024)

	_, err = DB.db.Exec(`
		UPDATE users SET
			uuid = ?,
			status = ?,
			download = ?,
			expiry_time = ?,
			last_online = ?,
			note = ?
		WHERE id = ?
	`, hUser.UUID, status, currentUsage, expiryTime, hUser.LastOnline, hUser.Comment, user.ID)

	return err
}

// ============================================================================
// X-UI (ORIGINAL) IMPORT
// ============================================================================

// ImportFromXUI imports from original x-ui (older version)
func (pi *PanelImporter) ImportFromXUI(dbPath string) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open x-ui database: %w", err)
	}
	defer db.Close()

	// Similar to 3x-ui but with different structure
	rows, err := db.Query(`
		SELECT id, up, down, total, remark, enable, expiry_time,
		       port, protocol, settings, tag
		FROM inbounds
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id int64
		var up, down, total, expiryTime int64
		var remark, protocol, settings, tag string
		var port int
		var enable bool

		err := rows.Scan(
			&id, &up, &down, &total, &remark, &enable, &expiryTime,
			&port, &protocol, &settings, &tag,
		)
		if err != nil {
			continue
		}

		// Parse and import clients from settings
		var settingsMap map[string]interface{}
		if err := json.Unmarshal([]byte(settings), &settingsMap); err != nil {
			continue
		}

		clients, ok := settingsMap["clients"].([]interface{})
		if !ok {
			continue
		}

		for _, c := range clients {
			client, ok := c.(map[string]interface{})
			if !ok {
				continue
			}

			email, _ := client["email"].(string)
			if email == "" {
				email = fmt.Sprintf("user_%s_%d", tag, time.Now().UnixNano())
			}

			userUUID := ""
			if id, exists := client["id"]; exists {
				userUUID = fmt.Sprintf("%v", id)
			} else {
				userUUID = uuid.New().String()
			}

			// Create user
			req := &CreateUserRequest{
				Username:  email,
				DataLimit: total,
			}

			user, err := Users.CreateUser(req)
			if err != nil {
				continue
			}

			status := UserStatusActive
			if !enable {
				status = UserStatusDisabled
			}

			DB.db.Exec(`
				UPDATE users SET uuid = ?, status = ?, upload = ?, download = ?
				WHERE id = ?
			`, userUUID, status, up, down, user.ID)

			pi.imported.UsersImported++
		}
	}

	return nil
}

// ============================================================================
// EXPORT FUNCTIONALITY
// ============================================================================

// ExportUsers exports all users to a JSON file
func (pi *PanelImporter) ExportUsers(outputPath string) error {
	result, err := Users.ListUsers(&UserFilter{Limit: 100000})
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(result.Users, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0644)
}

// ExportConfig exports all configuration to a JSON file
func (pi *PanelImporter) ExportConfig(outputPath string) error {
	config := map[string]interface{}{
		"version":   Version,
		"exported":  time.Now(),
		"config":    AppConfig,
	}

	// Get inbounds
	if Protocols != nil {
		inbounds, _ := Protocols.ListInbounds(0)
		config["inbounds"] = inbounds
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0644)
}

// ============================================================================
// HTTP HANDLERS
// ============================================================================

// RegisterImportRoutes registers import-related HTTP routes
func RegisterImportRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/import/detect", detectPanelHandler)
	mux.HandleFunc("/api/v1/import/marzban", importMarzbanHandler)
	mux.HandleFunc("/api/v1/import/3xui", import3XUIHandler)
	mux.HandleFunc("/api/v1/import/hiddify", importHiddifyHandler)
	mux.HandleFunc("/api/v1/export/users", exportUsersHandler)
}

func detectPanelHandler(w http.ResponseWriter, r *http.Request) {
	dbPath := r.URL.Query().Get("path")
	if dbPath == "" {
		respondJSON(w, 400, map[string]interface{}{
			"success": false,
			"message": "Database path required",
		})
		return
	}

	importer := NewPanelImporter(DB)
	panelType := importer.DetectPanelType(dbPath)

	respondJSON(w, 200, map[string]interface{}{
		"success":    true,
		"panel_type": panelType,
	})
}

func importMarzbanHandler(w http.ResponseWriter, r *http.Request) {
	handleImport(w, r, "marzban")
}

func import3XUIHandler(w http.ResponseWriter, r *http.Request) {
	handleImport(w, r, "3xui")
}

func importHiddifyHandler(w http.ResponseWriter, r *http.Request) {
	handleImport(w, r, "hiddify")
}

func handleImport(w http.ResponseWriter, r *http.Request, expectedType string) {
	var req struct {
		DBPath string `json:"db_path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, 400, map[string]interface{}{
			"success": false,
			"message": "Invalid request",
		})
		return
	}

	importer := NewPanelImporter(DB)

	// Verify panel type
	detectedType := importer.DetectPanelType(req.DBPath)
	if detectedType != expectedType {
		respondJSON(w, 400, map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("Database is not %s format (detected: %s)", expectedType, detectedType),
		})
		return
	}

	result, err := importer.Import(req.DBPath)
	if err != nil {
		respondJSON(w, 500, map[string]interface{}{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	respondJSON(w, 200, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

func exportUsersHandler(w http.ResponseWriter, r *http.Request) {
	importer := NewPanelImporter(DB)

	outputPath := filepath.Join(os.TempDir(), fmt.Sprintf("mxui_users_%d.json", time.Now().Unix()))
	if err := importer.ExportUsers(outputPath); err != nil {
		respondJSON(w, 500, map[string]interface{}{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	// Serve file for download
	w.Header().Set("Content-Disposition", "attachment; filename=users.json")
	w.Header().Set("Content-Type", "application/json")
	http.ServeFile(w, r, outputPath)

	// Clean up
	defer os.Remove(outputPath)
}

// respondJSON is a helper (already defined in main.go, but needed for standalone use)
func respondJSONImport(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
