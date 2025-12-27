-- +migrate Up
-- Initial database schema for MXUI VPN Panel
-- Version: 1.0.0

-- Admins table
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT NOT NULL DEFAULT 'reseller',
    is_active BOOLEAN DEFAULT 1,
    is_owner BOOLEAN DEFAULT 0,
    two_factor_enabled BOOLEAN DEFAULT 0,
    two_factor_secret TEXT,

    -- Limits for resellers
    max_users INTEGER DEFAULT 100,
    max_traffic_gb INTEGER DEFAULT 1000,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password TEXT,

    -- Subscription
    subscription_plan_id INTEGER,
    status TEXT DEFAULT 'active',
    expiry_date TIMESTAMP,

    -- Traffic
    upload INTEGER DEFAULT 0,
    download INTEGER DEFAULT 0,
    total_traffic INTEGER DEFAULT 0,
    traffic_limit INTEGER DEFAULT 10737418240,
    last_traffic_reset TIMESTAMP,

    -- Limits
    device_limit INTEGER DEFAULT 3,
    ip_limit INTEGER DEFAULT 0,

    -- Owner
    admin_id INTEGER,

    -- Settings
    enable_traffic_notification BOOLEAN DEFAULT 1,
    enable_expiry_notification BOOLEAN DEFAULT 1,

    -- Telegram
    telegram_id INTEGER,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE,
    FOREIGN KEY (subscription_plan_id) REFERENCES subscription_plans(id)
);

-- Nodes table
CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    port INTEGER DEFAULT 443,
    api_port INTEGER DEFAULT 62050,
    secret_key TEXT NOT NULL,

    -- Status
    status TEXT DEFAULT 'offline',
    is_active BOOLEAN DEFAULT 1,
    is_main_node BOOLEAN DEFAULT 0,

    -- Metrics
    cpu_usage REAL DEFAULT 0,
    ram_usage REAL DEFAULT 0,
    disk_usage REAL DEFAULT 0,
    network_in INTEGER DEFAULT 0,
    network_out INTEGER DEFAULT 0,
    total_upload INTEGER DEFAULT 0,
    total_download INTEGER DEFAULT 0,
    active_users INTEGER DEFAULT 0,

    -- Configuration
    protocols TEXT,
    traffic_ratio REAL DEFAULT 1.0,

    -- Health
    last_check TIMESTAMP,
    last_error TEXT,
    uptime INTEGER DEFAULT 0,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Subscription plans table
CREATE TABLE IF NOT EXISTS subscription_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,

    -- Pricing
    price REAL NOT NULL,
    currency TEXT DEFAULT 'USD',

    -- Limits
    traffic_limit INTEGER,
    device_limit INTEGER DEFAULT 3,
    duration_days INTEGER DEFAULT 30,

    -- Features
    protocols TEXT,
    max_speed INTEGER,

    -- Status
    is_active BOOLEAN DEFAULT 1,
    is_visible BOOLEAN DEFAULT 1,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Payments table
CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    admin_id INTEGER,

    -- Payment details
    amount REAL NOT NULL,
    currency TEXT DEFAULT 'USD',
    gateway TEXT NOT NULL,
    transaction_id TEXT,

    -- Status
    status TEXT DEFAULT 'pending',

    -- Details
    plan_id INTEGER,
    description TEXT,
    metadata TEXT,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    paid_at TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE SET NULL,
    FOREIGN KEY (plan_id) REFERENCES subscription_plans(id)
);

-- Wallets table
CREATE TABLE IF NOT EXISTS wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,

    -- Balance
    balance REAL DEFAULT 0,
    frozen_balance REAL DEFAULT 0,
    currency TEXT DEFAULT 'USD',

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Connection logs table
CREATE TABLE IF NOT EXISTS connection_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    node_id INTEGER,

    -- Connection details
    ip_address TEXT,
    device_name TEXT,
    protocol TEXT,

    -- Traffic
    upload INTEGER DEFAULT 0,
    download INTEGER DEFAULT 0,

    -- Timestamps
    connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    disconnected_at TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE SET NULL
);

-- Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER,
    user_id INTEGER,

    -- Action details
    action TEXT NOT NULL,
    entity_type TEXT,
    entity_id INTEGER,
    details TEXT,

    -- Request info
    ip_address TEXT,
    user_agent TEXT,

    -- Timestamp
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE SET NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Settings table
CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    value TEXT,
    type TEXT DEFAULT 'string',
    description TEXT,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Backups table
CREATE TABLE IF NOT EXISTS backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    path TEXT NOT NULL,
    size INTEGER DEFAULT 0,
    type TEXT DEFAULT 'full',

    -- Destinations
    local_path TEXT,
    remote_path TEXT,

    -- Status
    status TEXT DEFAULT 'completed',
    error_message TEXT,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- +migrate Down
DROP TABLE IF EXISTS backups;
DROP TABLE IF EXISTS settings;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS connection_logs;
DROP TABLE IF EXISTS wallets;
DROP TABLE IF EXISTS payments;
DROP TABLE IF EXISTS subscription_plans;
DROP TABLE IF EXISTS nodes;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS admins;
