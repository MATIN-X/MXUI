-- +migrate Up
-- Client Messages table for MXUI Panel to Client communication
-- Version: 1.1.0

-- Client messages table
CREATE TABLE IF NOT EXISTS client_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'info',
    recipients TEXT NOT NULL DEFAULT 'all',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

-- Notification reads tracking
CREATE TABLE IF NOT EXISTS notification_reads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    notification_id INTEGER NOT NULL,
    read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, notification_id)
);

-- Index for faster queries
CREATE INDEX IF NOT EXISTS idx_client_messages_created ON client_messages(created_at);
CREATE INDEX IF NOT EXISTS idx_notification_reads_user ON notification_reads(user_id);

-- +migrate Down
DROP TABLE IF EXISTS notification_reads;
DROP TABLE IF EXISTS client_messages;
