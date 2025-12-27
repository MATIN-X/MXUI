// Core/migrations/migration_manager.go
// Database Migration Manager with versioning and rollback support
// Production-grade migration system

package migrations

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ====================================================================================
// MIGRATION STRUCTURES
// ====================================================================================

// Migration represents a database migration
type Migration struct {
	Version     int
	Name        string
	UpSQL       string
	DownSQL     string
	ExecutedAt  time.Time
	Description string
}

// MigrationManager manages database migrations
type MigrationManager struct {
	db             *sql.DB
	migrationsPath string
	tableName      string
}

// MigrationRecord represents a migration record in database
type MigrationRecord struct {
	ID         int
	Version    int
	Name       string
	AppliedAt  time.Time
	Success    bool
	ErrorMsg   string
}

// ====================================================================================
// MIGRATION MANAGER
// ====================================================================================

// NewMigrationManager creates a new migration manager
func NewMigrationManager(db *sql.DB, migrationsPath string) *MigrationManager {
	return &MigrationManager{
		db:             db,
		migrationsPath: migrationsPath,
		tableName:      "schema_migrations",
	}
}

// Initialize creates migrations table if not exists
func (mm *MigrationManager) Initialize() error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			version INTEGER NOT NULL UNIQUE,
			name TEXT NOT NULL,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			success BOOLEAN DEFAULT TRUE,
			error_msg TEXT,
			checksum TEXT
		)
	`

	_, err := mm.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	return nil
}

// GetAppliedMigrations returns list of applied migrations
func (mm *MigrationManager) GetAppliedMigrations() ([]MigrationRecord, error) {
	query := `
		SELECT id, version, name, applied_at, success, COALESCE(error_msg, '')
		FROM schema_migrations
		ORDER BY version ASC
	`

	rows, err := mm.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var migrations []MigrationRecord
	for rows.Next() {
		var m MigrationRecord
		err := rows.Scan(&m.ID, &m.Version, &m.Name, &m.AppliedAt, &m.Success, &m.ErrorMsg)
		if err != nil {
			return nil, err
		}
		migrations = append(migrations, m)
	}

	return migrations, nil
}

// GetPendingMigrations returns migrations that haven't been applied
func (mm *MigrationManager) GetPendingMigrations() ([]*Migration, error) {
	// Get all migrations from files
	allMigrations, err := mm.LoadMigrations()
	if err != nil {
		return nil, err
	}

	// Get applied migrations
	applied, err := mm.GetAppliedMigrations()
	if err != nil {
		return nil, err
	}

	// Create map of applied versions
	appliedMap := make(map[int]bool)
	for _, m := range applied {
		appliedMap[m.Version] = true
	}

	// Filter pending
	var pending []*Migration
	for _, m := range allMigrations {
		if !appliedMap[m.Version] {
			pending = append(pending, m)
		}
	}

	return pending, nil
}

// LoadMigrations loads all migration files
func (mm *MigrationManager) LoadMigrations() ([]*Migration, error) {
	files, err := ioutil.ReadDir(mm.migrationsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read migrations directory: %w", err)
	}

	var migrations []*Migration

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".sql") {
			continue
		}

		migration, err := mm.parseMigrationFile(filepath.Join(mm.migrationsPath, file.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to parse migration %s: %w", file.Name(), err)
		}

		migrations = append(migrations, migration)
	}

	// Sort by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// parseMigrationFile parses a migration SQL file
func (mm *MigrationManager) parseMigrationFile(path string) (*Migration, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Parse filename: 001_initial_schema.sql
	filename := filepath.Base(path)
	parts := strings.SplitN(filename, "_", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid migration filename format: %s", filename)
	}

	var version int
	_, err = fmt.Sscanf(parts[0], "%d", &version)
	if err != nil {
		return nil, fmt.Errorf("invalid version number in filename: %s", filename)
	}

	name := strings.TrimSuffix(parts[1], ".sql")

	// Split UP and DOWN sections
	sqlContent := string(content)
	upSQL, downSQL := mm.splitMigration(sqlContent)

	return &Migration{
		Version: version,
		Name:    name,
		UpSQL:   upSQL,
		DownSQL: downSQL,
	}, nil
}

// splitMigration splits migration into UP and DOWN parts
func (mm *MigrationManager) splitMigration(content string) (up, down string) {
	// Look for -- +migrate Up and -- +migrate Down markers
	lines := strings.Split(content, "\n")

	var upLines []string
	var downLines []string
	var inUp bool
	var inDown bool

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.Contains(trimmed, "-- +migrate Up") {
			inUp = true
			inDown = false
			continue
		}

		if strings.Contains(trimmed, "-- +migrate Down") {
			inUp = false
			inDown = true
			continue
		}

		if inUp {
			upLines = append(upLines, line)
		} else if inDown {
			downLines = append(downLines, line)
		}
	}

	up = strings.Join(upLines, "\n")
	down = strings.Join(downLines, "\n")

	return up, down
}

// ApplyMigration applies a single migration
func (mm *MigrationManager) ApplyMigration(migration *Migration) error {
	tx, err := mm.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}

	// Execute migration SQL
	_, err = tx.Exec(migration.UpSQL)
	if err != nil {
		tx.Rollback()
		// Record failed migration
		mm.recordMigration(migration, false, err.Error())
		return fmt.Errorf("migration %d failed: %w", migration.Version, err)
	}

	// Record successful migration
	err = mm.recordMigrationInTx(tx, migration, true, "")
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to record migration: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migration: %w", err)
	}

	fmt.Printf("✓ Applied migration %d: %s\n", migration.Version, migration.Name)
	return nil
}

// RollbackMigration rolls back a migration
func (mm *MigrationManager) RollbackMigration(migration *Migration) error {
	if migration.DownSQL == "" {
		return fmt.Errorf("migration %d has no rollback SQL", migration.Version)
	}

	tx, err := mm.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}

	// Execute rollback SQL
	_, err = tx.Exec(migration.DownSQL)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("rollback failed: %w", err)
	}

	// Remove migration record
	_, err = tx.Exec("DELETE FROM schema_migrations WHERE version = ?", migration.Version)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to remove migration record: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit rollback: %w", err)
	}

	fmt.Printf("✓ Rolled back migration %d: %s\n", migration.Version, migration.Name)
	return nil
}

// recordMigration records migration execution
func (mm *MigrationManager) recordMigration(migration *Migration, success bool, errorMsg string) error {
	query := `
		INSERT INTO schema_migrations (version, name, success, error_msg)
		VALUES (?, ?, ?, ?)
	`

	_, err := mm.db.Exec(query, migration.Version, migration.Name, success, errorMsg)
	return err
}

// recordMigrationInTx records migration in transaction
func (mm *MigrationManager) recordMigrationInTx(tx *sql.Tx, migration *Migration, success bool, errorMsg string) error {
	query := `
		INSERT INTO schema_migrations (version, name, success, error_msg)
		VALUES (?, ?, ?, ?)
	`

	_, err := tx.Exec(query, migration.Version, migration.Name, success, errorMsg)
	return err
}

// MigrateUp applies all pending migrations
func (mm *MigrationManager) MigrateUp() error {
	pending, err := mm.GetPendingMigrations()
	if err != nil {
		return err
	}

	if len(pending) == 0 {
		fmt.Println("✓ No pending migrations")
		return nil
	}

	fmt.Printf("Applying %d pending migrations...\n", len(pending))

	for _, migration := range pending {
		if err := mm.ApplyMigration(migration); err != nil {
			return err
		}
	}

	fmt.Println("✓ All migrations applied successfully")
	return nil
}

// MigrateDown rolls back the last N migrations
func (mm *MigrationManager) MigrateDown(steps int) error {
	applied, err := mm.GetAppliedMigrations()
	if err != nil {
		return err
	}

	if len(applied) == 0 {
		fmt.Println("No migrations to rollback")
		return nil
	}

	// Get migrations to rollback
	toRollback := steps
	if toRollback > len(applied) {
		toRollback = len(applied)
	}

	// Load migration files
	allMigrations, err := mm.LoadMigrations()
	if err != nil {
		return err
	}

	// Create version -> migration map
	migrationMap := make(map[int]*Migration)
	for _, m := range allMigrations {
		migrationMap[m.Version] = m
	}

	// Rollback in reverse order
	for i := len(applied) - 1; i >= len(applied)-toRollback; i-- {
		record := applied[i]
		migration, exists := migrationMap[record.Version]
		if !exists {
			fmt.Printf("⚠ Migration file not found for version %d, skipping\n", record.Version)
			continue
		}

		if err := mm.RollbackMigration(migration); err != nil {
			return err
		}
	}

	fmt.Printf("✓ Rolled back %d migrations\n", toRollback)
	return nil
}

// GetCurrentVersion returns current migration version
func (mm *MigrationManager) GetCurrentVersion() (int, error) {
	var version int
	err := mm.db.QueryRow(`
		SELECT COALESCE(MAX(version), 0)
		FROM schema_migrations
		WHERE success = 1
	`).Scan(&version)

	if err != nil {
		return 0, err
	}

	return version, nil
}

// Status prints migration status
func (mm *MigrationManager) Status() error {
	currentVersion, err := mm.GetCurrentVersion()
	if err != nil {
		return err
	}

	pending, err := mm.GetPendingMigrations()
	if err != nil {
		return err
	}

	applied, err := mm.GetAppliedMigrations()
	if err != nil {
		return err
	}

	fmt.Println("\n=== Migration Status ===")
	fmt.Printf("Current Version: %d\n", currentVersion)
	fmt.Printf("Applied Migrations: %d\n", len(applied))
	fmt.Printf("Pending Migrations: %d\n\n", len(pending))

	if len(applied) > 0 {
		fmt.Println("Applied:")
		for _, m := range applied {
			status := "✓"
			if !m.Success {
				status = "✗"
			}
			fmt.Printf("  %s %d: %s (applied: %s)\n", status, m.Version, m.Name, m.AppliedAt.Format("2006-01-02 15:04:05"))
		}
		fmt.Println()
	}

	if len(pending) > 0 {
		fmt.Println("Pending:")
		for _, m := range pending {
			fmt.Printf("  ○ %d: %s\n", m.Version, m.Name)
		}
	}

	return nil
}
