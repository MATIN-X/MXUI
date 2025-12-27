-- +migrate Up
-- Add indexes for performance optimization

-- Users table indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_admin_id ON users(admin_id);
CREATE INDEX IF NOT EXISTS idx_users_expiry_date ON users(expiry_date);
CREATE INDEX IF NOT EXISTS idx_users_telegram_id ON users(telegram_id);

-- Admins table indexes
CREATE INDEX IF NOT EXISTS idx_admins_username ON admins(username);
CREATE INDEX IF NOT EXISTS idx_admins_email ON admins(email);
CREATE INDEX IF NOT EXISTS idx_admins_role ON admins(role);
CREATE INDEX IF NOT EXISTS idx_admins_is_active ON admins(is_active);

-- Nodes table indexes
CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status);
CREATE INDEX IF NOT EXISTS idx_nodes_is_active ON nodes(is_active);
CREATE INDEX IF NOT EXISTS idx_nodes_is_main_node ON nodes(is_main_node);

-- Payments table indexes
CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);
CREATE INDEX IF NOT EXISTS idx_payments_gateway ON payments(gateway);
CREATE INDEX IF NOT EXISTS idx_payments_transaction_id ON payments(transaction_id);
CREATE INDEX IF NOT EXISTS idx_payments_created_at ON payments(created_at);

-- Connection logs indexes
CREATE INDEX IF NOT EXISTS idx_connection_logs_user_id ON connection_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_connection_logs_node_id ON connection_logs(node_id);
CREATE INDEX IF NOT EXISTS idx_connection_logs_connected_at ON connection_logs(connected_at);
CREATE INDEX IF NOT EXISTS idx_connection_logs_ip_address ON connection_logs(ip_address);

-- Audit logs indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_admin_id ON audit_logs(admin_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);

-- Wallets table indexes
CREATE INDEX IF NOT EXISTS idx_wallets_user_id ON wallets(user_id);

-- Subscription plans indexes
CREATE INDEX IF NOT EXISTS idx_subscription_plans_is_active ON subscription_plans(is_active);
CREATE INDEX IF NOT EXISTS idx_subscription_plans_is_visible ON subscription_plans(is_visible);

-- Settings indexes
CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(key);

-- +migrate Down
DROP INDEX IF EXISTS idx_settings_key;
DROP INDEX IF EXISTS idx_subscription_plans_is_visible;
DROP INDEX IF EXISTS idx_subscription_plans_is_active;
DROP INDEX IF EXISTS idx_wallets_user_id;
DROP INDEX IF EXISTS idx_audit_logs_created_at;
DROP INDEX IF EXISTS idx_audit_logs_action;
DROP INDEX IF EXISTS idx_audit_logs_user_id;
DROP INDEX IF EXISTS idx_audit_logs_admin_id;
DROP INDEX IF EXISTS idx_connection_logs_ip_address;
DROP INDEX IF EXISTS idx_connection_logs_connected_at;
DROP INDEX IF EXISTS idx_connection_logs_node_id;
DROP INDEX IF EXISTS idx_connection_logs_user_id;
DROP INDEX IF EXISTS idx_payments_created_at;
DROP INDEX IF EXISTS idx_payments_transaction_id;
DROP INDEX IF EXISTS idx_payments_gateway;
DROP INDEX IF EXISTS idx_payments_status;
DROP INDEX IF EXISTS idx_payments_user_id;
DROP INDEX IF EXISTS idx_nodes_is_main_node;
DROP INDEX IF EXISTS idx_nodes_is_active;
DROP INDEX IF EXISTS idx_nodes_status;
DROP INDEX IF EXISTS idx_admins_is_active;
DROP INDEX IF EXISTS idx_admins_role;
DROP INDEX IF EXISTS idx_admins_email;
DROP INDEX IF EXISTS idx_admins_username;
DROP INDEX IF EXISTS idx_users_telegram_id;
DROP INDEX IF EXISTS idx_users_expiry_date;
DROP INDEX IF EXISTS idx_users_admin_id;
DROP INDEX IF EXISTS idx_users_status;
DROP INDEX IF EXISTS idx_users_username;
DROP INDEX IF EXISTS idx_users_email;
