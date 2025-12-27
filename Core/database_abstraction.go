// Core/database_abstraction.go
// Database Abstraction Layer - PostgreSQL, MySQL, SQLite support
// Production-grade multi-database support with proper connection pooling

package core

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

// ====================================================================================
// DATABASE TYPES
// ====================================================================================

type DatabaseType string

const (
	DatabaseSQLite     DatabaseType = "sqlite"
	DatabasePostgreSQL DatabaseType = "postgres"
	DatabaseMySQL      DatabaseType = "mysql"
)

// ====================================================================================
// DATABASE CONFIGURATION
// ====================================================================================

// EnhancedDatabaseConfig holds database configuration
type EnhancedDatabaseConfig struct {
	// Database type
	Type DatabaseType `yaml:"type" json:"type"`

	// SQLite specific
	Path string `yaml:"path" json:"path"`

	// PostgreSQL/MySQL specific
	Host     string `yaml:"host" json:"host"`
	Port     int    `yaml:"port" json:"port"`
	Database string `yaml:"database" json:"database"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
	SSLMode  string `yaml:"ssl_mode" json:"ssl_mode"` // postgres: disable, require, verify-full

	// Connection pool settings
	MaxOpenConns    int           `yaml:"max_open_conns" json:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns" json:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime" json:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `yaml:"conn_max_idle_time" json:"conn_max_idle_time"`

	// Performance settings
	Charset         string `yaml:"charset" json:"charset"`           // mysql: utf8mb4
	Timezone        string `yaml:"timezone" json:"timezone"`         // mysql: UTC
	ParseTime       bool   `yaml:"parse_time" json:"parse_time"`     // mysql: true
	MultiStatements bool   `yaml:"multi_statements" json:"multi_statements"`
}

// DefaultEnhancedDatabaseConfig returns default configuration
func DefaultEnhancedDatabaseConfig() *EnhancedDatabaseConfig {
	return &EnhancedDatabaseConfig{
		Type:            DatabaseSQLite,
		Path:            "./Data/database.db",
		MaxOpenConns:    25,
		MaxIdleConns:    5,
		ConnMaxLifetime: 5 * time.Minute,
		ConnMaxIdleTime: 10 * time.Minute,
		Charset:         "utf8mb4",
		Timezone:        "UTC",
		ParseTime:       true,
	}
}

// ====================================================================================
// DATABASE INTERFACE
// ====================================================================================

// DBInterface defines database operations interface
type DBInterface interface {
	Connect() error
	Close() error
	Ping(ctx context.Context) error
	Begin() (*sql.Tx, error)
	Exec(query string, args ...interface{}) (sql.Result, error)
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
	GetDB() *sql.DB
	GetType() DatabaseType
	GetPlaceholder(index int) string // Returns ? for MySQL/SQLite, $1 for PostgreSQL
	MigrateSchema() error
}

// ====================================================================================
// BASE DATABASE IMPLEMENTATION
// ====================================================================================

// BaseDatabase implements common database operations
type BaseDatabase struct {
	config *EnhancedDatabaseConfig
	db     *sql.DB
	dbType DatabaseType
}

// Connect connects to database
func (bd *BaseDatabase) Connect() error {
	var dsn string
	var err error

	switch bd.config.Type {
	case DatabaseSQLite:
		dsn = fmt.Sprintf("%s?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on", bd.config.Path)
		bd.db, err = sql.Open("sqlite3", dsn)

	case DatabasePostgreSQL:
		sslMode := bd.config.SSLMode
		if sslMode == "" {
			sslMode = "disable"
		}
		dsn = fmt.Sprintf(
			"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			bd.config.Host,
			bd.config.Port,
			bd.config.Username,
			bd.config.Password,
			bd.config.Database,
			sslMode,
		)
		bd.db, err = sql.Open("postgres", dsn)

	case DatabaseMySQL:
		charset := bd.config.Charset
		if charset == "" {
			charset = "utf8mb4"
		}
		timezone := bd.config.Timezone
		if timezone == "" {
			timezone = "UTC"
		}

		dsn = fmt.Sprintf(
			"%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=%t&loc=%s",
			bd.config.Username,
			bd.config.Password,
			bd.config.Host,
			bd.config.Port,
			bd.config.Database,
			charset,
			bd.config.ParseTime,
			timezone,
		)

		if bd.config.MultiStatements {
			dsn += "&multiStatements=true"
		}

		bd.db, err = sql.Open("mysql", dsn)

	default:
		return fmt.Errorf("unsupported database type: %s", bd.config.Type)
	}

	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Set connection pool parameters
	bd.db.SetMaxOpenConns(bd.config.MaxOpenConns)
	bd.db.SetMaxIdleConns(bd.config.MaxIdleConns)
	bd.db.SetConnMaxLifetime(bd.config.ConnMaxLifetime)
	bd.db.SetConnMaxIdleTime(bd.config.ConnMaxIdleTime)

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := bd.db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	bd.dbType = bd.config.Type
	LogInfo("DATABASE", "Connected to %s database", bd.config.Type)

	return nil
}

// Close closes database connection
func (bd *BaseDatabase) Close() error {
	if bd.db != nil {
		return bd.db.Close()
	}
	return nil
}

// Ping checks database connection
func (bd *BaseDatabase) Ping(ctx context.Context) error {
	return bd.db.PingContext(ctx)
}

// Begin starts a transaction
func (bd *BaseDatabase) Begin() (*sql.Tx, error) {
	return bd.db.Begin()
}

// Exec executes a query
func (bd *BaseDatabase) Exec(query string, args ...interface{}) (sql.Result, error) {
	return bd.db.Exec(query, args...)
}

// Query executes a query that returns rows
func (bd *BaseDatabase) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return bd.db.Query(query, args...)
}

// QueryRow executes a query that returns at most one row
func (bd *BaseDatabase) QueryRow(query string, args ...interface{}) *sql.Row {
	return bd.db.QueryRow(query, args...)
}

// GetDB returns underlying *sql.DB
func (bd *BaseDatabase) GetDB() *sql.DB {
	return bd.db
}

// GetType returns database type
func (bd *BaseDatabase) GetType() DatabaseType {
	return bd.dbType
}

// GetPlaceholder returns placeholder for parameterized queries
func (bd *BaseDatabase) GetPlaceholder(index int) string {
	switch bd.dbType {
	case DatabasePostgreSQL:
		return fmt.Sprintf("$%d", index)
	case DatabaseMySQL, DatabaseSQLite:
		return "?"
	default:
		return "?"
	}
}

// ====================================================================================
// QUERY BUILDER
// ====================================================================================

// QueryBuilder helps build cross-database compatible queries
type QueryBuilder struct {
	dbType DatabaseType
}

// NewQueryBuilder creates a new query builder
func NewQueryBuilder(dbType DatabaseType) *QueryBuilder {
	return &QueryBuilder{dbType: dbType}
}

// Placeholder returns the appropriate placeholder
func (qb *QueryBuilder) Placeholder(index int) string {
	switch qb.dbType {
	case DatabasePostgreSQL:
		return fmt.Sprintf("$%d", index)
	default:
		return "?"
	}
}

// AutoIncrement returns AUTO_INCREMENT syntax
func (qb *QueryBuilder) AutoIncrement() string {
	switch qb.dbType {
	case DatabasePostgreSQL:
		return "SERIAL PRIMARY KEY"
	case DatabaseMySQL:
		return "INT AUTO_INCREMENT PRIMARY KEY"
	case DatabaseSQLite:
		return "INTEGER PRIMARY KEY AUTOINCREMENT"
	default:
		return "INTEGER PRIMARY KEY AUTOINCREMENT"
	}
}

// CurrentTimestamp returns current timestamp function
func (qb *QueryBuilder) CurrentTimestamp() string {
	switch qb.dbType {
	case DatabasePostgreSQL:
		return "CURRENT_TIMESTAMP"
	case DatabaseMySQL:
		return "CURRENT_TIMESTAMP"
	case DatabaseSQLite:
		return "CURRENT_TIMESTAMP"
	default:
		return "CURRENT_TIMESTAMP"
	}
}

// BoolType returns boolean column type
func (qb *QueryBuilder) BoolType() string {
	switch qb.dbType {
	case DatabasePostgreSQL:
		return "BOOLEAN"
	case DatabaseMySQL:
		return "TINYINT(1)"
	case DatabaseSQLite:
		return "INTEGER" // 0 or 1
	default:
		return "INTEGER"
	}
}

// TextType returns large text column type
func (qb *QueryBuilder) TextType() string {
	switch qb.dbType {
	case DatabasePostgreSQL:
		return "TEXT"
	case DatabaseMySQL:
		return "LONGTEXT"
	case DatabaseSQLite:
		return "TEXT"
	default:
		return "TEXT"
	}
}

// JSONType returns JSON column type
func (qb *QueryBuilder) JSONType() string {
	switch qb.dbType {
	case DatabasePostgreSQL:
		return "JSONB"
	case DatabaseMySQL:
		return "JSON"
	case DatabaseSQLite:
		return "TEXT" // Store as JSON string
	default:
		return "TEXT"
	}
}

// ====================================================================================
// ENHANCED DATABASE MANAGER
// ====================================================================================

// NewEnhancedDatabaseManager creates a new database manager with multi-DB support
func NewEnhancedDatabaseManager(config *EnhancedDatabaseConfig) (*DatabaseManager, error) {
	baseDB := &BaseDatabase{
		config: config,
	}

	if err := baseDB.Connect(); err != nil {
		return nil, err
	}

	dm := &DatabaseManager{
		db:          baseDB.db,
		dbPath:      config.Path,
		dbType:      config.Type,
		queryBuilder: NewQueryBuilder(config.Type),
	}

	return dm, nil
}

// RewriteQuery rewrites query for specific database type
func (dm *DatabaseManager) RewriteQuery(query string) string {
	// This is a simplified version
	// In production, use a proper query rewriter or ORM

	// Example: Convert ? to $1, $2, etc. for PostgreSQL
	if dm.dbType == DatabasePostgreSQL {
		result := ""
		paramIndex := 1
		for i, char := range query {
			if char == '?' {
				result += fmt.Sprintf("$%d", paramIndex)
				paramIndex++
			} else {
				result += string(query[i])
			}
		}
		return result
	}

	return query
}

// ====================================================================================
// CONNECTION POOL MONITORING
// ====================================================================================

// DatabaseStats holds database statistics
type DatabaseStats struct {
	MaxOpenConnections int
	OpenConnections    int
	InUse              int
	Idle               int
	WaitCount          int64
	WaitDuration       time.Duration
	MaxIdleClosed      int64
	MaxLifetimeClosed  int64
}

// GetStats returns database connection pool statistics
func (dm *DatabaseManager) GetStats() DatabaseStats {
	stats := dm.db.Stats()

	return DatabaseStats{
		MaxOpenConnections: stats.MaxOpenConnections,
		OpenConnections:    stats.OpenConnections,
		InUse:              stats.InUse,
		Idle:               stats.Idle,
		WaitCount:          stats.WaitCount,
		WaitDuration:       stats.WaitDuration,
		MaxIdleClosed:      stats.MaxIdleClosed,
		MaxLifetimeClosed:  stats.MaxLifetimeClosed,
	}
}
