package core

import (
	"database/sql"
)

type PanelImporter struct{}

func (pi *PanelImporter) hasTable(db *sql.DB, tableName string) bool {
	query := "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
	var name string
	err := db.QueryRow(query, tableName).Scan(&name)
	return err == nil
}

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

func (pi *PanelImporter) DetectPanelType(dbPath string) string {
	// Check database structure
	db, _ := sql.Open("sqlite3", dbPath)
	defer db.Close()

	// Check for marzban tables
	if pi.hasTable(db, "users") && pi.hasTable(db, "admins") {
		if pi.hasColumn(db, "users", "data_limit_reset_strategy") {
			return "marzban"
		}
	}
	// Check 3x-ui
	if pi.hasTable(db, "inbounds") && pi.hasTable(db, "settings") {
		return "3xui"
	}
	// Check hiddify
	if pi.hasTable(db, "domain") && pi.hasTable(db, "child") {
		return "hiddify"
	}
	return "unknown"
}

func (pi *PanelImporter) ImportFromMarzban(dbPath string) error {
	// Import users from marzban database
	return nil
}

func (pi *PanelImporter) ImportFrom3XUI(dbPath string) error {
	// Import from 3x-ui
	return nil
}
