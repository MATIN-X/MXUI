package core

import (
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

// ==================== Models ====================

// ReferralCode represents a user's referral code
type ReferralCode struct {
	ID              int64     `json:"id"`
	UserID          int64     `json:"user_id"`
	Code            string    `json:"code"`
	CommissionRate  float64   `json:"commission_rate"` // percentage
	ClickCount      int       `json:"click_count"`
	SignupCount     int       `json:"signup_count"`
	ConversionCount int       `json:"conversion_count"` // successful payments
	TotalEarned     float64   `json:"total_earned"`
	IsActive        bool      `json:"is_active"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// ReferralClick represents a click on referral link
type ReferralClick struct {
	ID         int64     `json:"id"`
	ReferralID int64     `json:"referral_id"`
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
	Referrer   string    `json:"referrer"`
	ClickedAt  time.Time `json:"clicked_at"`
}

// ReferralConversion represents a successful conversion
type ReferralConversion struct {
	ID             int64      `json:"id"`
	ReferralID     int64      `json:"referral_id"`
	ReferredUserID int64      `json:"referred_user_id"`
	OrderID        int64      `json:"order_id"`
	OrderAmount    float64    `json:"order_amount"`
	Commission     float64    `json:"commission"`
	Status         string     `json:"status"` // pending, paid, cancelled
	PaidAt         *time.Time `json:"paid_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// ReferralPayout represents a payout to affiliate
type ReferralPayout struct {
	ID          int64      `json:"id"`
	UserID      int64      `json:"user_id"`
	Amount      float64    `json:"amount"`
	Method      string     `json:"method"` // wallet, bank_transfer
	Status      string     `json:"status"` // pending, processing, completed, failed
	Details     string     `json:"details"`
	ProcessedBy int64      `json:"processed_by"`
	ProcessedAt *time.Time `json:"processed_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// ReferralStats represents referral statistics
type ReferralStats struct {
	TotalClicks      int                `json:"total_clicks"`
	TotalSignups     int                `json:"total_signups"`
	TotalConversions int                `json:"total_conversions"`
	TotalEarnings    float64            `json:"total_earnings"`
	PendingEarnings  float64            `json:"pending_earnings"`
	PaidEarnings     float64            `json:"paid_earnings"`
	ConversionRate   float64            `json:"conversion_rate"`
	TopReferrers     []TopReferrer      `json:"top_referrers"`
	EarningsByMonth  map[string]float64 `json:"earnings_by_month"`
}

// TopReferrer represents top performing referrer
type TopReferrer struct {
	UserID      int64   `json:"user_id"`
	Username    string  `json:"username"`
	Code        string  `json:"code"`
	Conversions int     `json:"conversions"`
	TotalEarned float64 `json:"total_earned"`
}

// ==================== Referral System ====================

type ReferralSystem struct {
	db                *sql.DB
	defaultCommission float64
	cookieExpiry      int // days
}

func NewReferralSystem(db *sql.DB, defaultCommission float64, cookieExpiry int) *ReferralSystem {
	rs := &ReferralSystem{
		db:                db,
		defaultCommission: defaultCommission,
		cookieExpiry:      cookieExpiry,
	}
	rs.initTables()
	return rs
}

func (rs *ReferralSystem) initTables() {
	// Referral codes table
	rs.db.Exec(`
		CREATE TABLE IF NOT EXISTS referral_codes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER UNIQUE NOT NULL,
			code TEXT UNIQUE NOT NULL,
			commission_rate REAL DEFAULT 10.0,
			click_count INTEGER DEFAULT 0,
			signup_count INTEGER DEFAULT 0,
			conversion_count INTEGER DEFAULT 0,
			total_earned REAL DEFAULT 0,
			is_active BOOLEAN DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)
	`)

	// Referral clicks table
	rs.db.Exec(`
		CREATE TABLE IF NOT EXISTS referral_clicks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			referral_id INTEGER NOT NULL,
			ip_address TEXT,
			user_agent TEXT,
			referrer TEXT,
			clicked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (referral_id) REFERENCES referral_codes(id)
		)
	`)

	// Referral conversions table
	rs.db.Exec(`
		CREATE TABLE IF NOT EXISTS referral_conversions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			referral_id INTEGER NOT NULL,
			referred_user_id INTEGER NOT NULL,
			order_id INTEGER NOT NULL,
			order_amount REAL NOT NULL,
			commission REAL NOT NULL,
			status TEXT DEFAULT 'pending',
			paid_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (referral_id) REFERENCES referral_codes(id),
			FOREIGN KEY (referred_user_id) REFERENCES users(id),
			FOREIGN KEY (order_id) REFERENCES orders(id)
		)
	`)

	// Referral payouts table
	rs.db.Exec(`
		CREATE TABLE IF NOT EXISTS referral_payouts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			amount REAL NOT NULL,
			method TEXT NOT NULL,
			status TEXT DEFAULT 'pending',
			details TEXT,
			processed_by INTEGER,
			processed_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (processed_by) REFERENCES admins(id)
		)
	`)

	// Create indexes
	rs.db.Exec(`CREATE INDEX IF NOT EXISTS idx_referral_codes_code ON referral_codes(code)`)
	rs.db.Exec(`CREATE INDEX IF NOT EXISTS idx_referral_codes_user ON referral_codes(user_id)`)
	rs.db.Exec(`CREATE INDEX IF NOT EXISTS idx_referral_clicks_referral ON referral_clicks(referral_id)`)
	rs.db.Exec(`CREATE INDEX IF NOT EXISTS idx_referral_conversions_referral ON referral_conversions(referral_id)`)
	rs.db.Exec(`CREATE INDEX IF NOT EXISTS idx_referral_conversions_user ON referral_conversions(referred_user_id)`)
	rs.db.Exec(`CREATE INDEX IF NOT EXISTS idx_referral_payouts_user ON referral_payouts(user_id)`)

	log.Println("🤝 Referral system tables initialized")
}

// ==================== Referral Code Management ====================

func (rs *ReferralSystem) CreateReferralCode(userID int64, customCode string) (*ReferralCode, error) {
	// Check if user already has a code
	var existingID int64
	err := rs.db.QueryRow("SELECT id FROM referral_codes WHERE user_id = ?", userID).Scan(&existingID)
	if err == nil {
		return nil, errors.New("user already has a referral code")
	}

	// Generate code if not provided
	code := customCode
	if code == "" {
		code = rs.generateReferralCode()
	}

	// Validate code format
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) < 4 || len(code) > 20 {
		return nil, errors.New("code must be between 4 and 20 characters")
	}

	// Check if code is available
	var count int
	rs.db.QueryRow("SELECT COUNT(*) FROM referral_codes WHERE code = ?", code).Scan(&count)
	if count > 0 {
		return nil, errors.New("code is already in use")
	}

	// Create referral code
	result, err := rs.db.Exec(`
		INSERT INTO referral_codes (user_id, code, commission_rate)
		VALUES (?, ?, ?)
	`, userID, code, rs.defaultCommission)

	if err != nil {
		return nil, err
	}

	referralID, _ := result.LastInsertId()
	return rs.GetReferralCodeByID(referralID)
}

func (rs *ReferralSystem) GetReferralCode(code string) (*ReferralCode, error) {
	var ref ReferralCode
	err := rs.db.QueryRow(`
		SELECT id, user_id, code, commission_rate, click_count, signup_count,
		       conversion_count, total_earned, is_active, created_at, updated_at
		FROM referral_codes WHERE code = ?
	`, code).Scan(
		&ref.ID, &ref.UserID, &ref.Code, &ref.CommissionRate, &ref.ClickCount,
		&ref.SignupCount, &ref.ConversionCount, &ref.TotalEarned, &ref.IsActive,
		&ref.CreatedAt, &ref.UpdatedAt,
	)
	return &ref, err
}

func (rs *ReferralSystem) GetReferralCodeByID(referralID int64) (*ReferralCode, error) {
	var ref ReferralCode
	err := rs.db.QueryRow(`
		SELECT id, user_id, code, commission_rate, click_count, signup_count,
		       conversion_count, total_earned, is_active, created_at, updated_at
		FROM referral_codes WHERE id = ?
	`, referralID).Scan(
		&ref.ID, &ref.UserID, &ref.Code, &ref.CommissionRate, &ref.ClickCount,
		&ref.SignupCount, &ref.ConversionCount, &ref.TotalEarned, &ref.IsActive,
		&ref.CreatedAt, &ref.UpdatedAt,
	)
	return &ref, err
}

func (rs *ReferralSystem) GetUserReferralCode(userID int64) (*ReferralCode, error) {
	var ref ReferralCode
	err := rs.db.QueryRow(`
		SELECT id, user_id, code, commission_rate, click_count, signup_count,
		       conversion_count, total_earned, is_active, created_at, updated_at
		FROM referral_codes WHERE user_id = ?
	`, userID).Scan(
		&ref.ID, &ref.UserID, &ref.Code, &ref.CommissionRate, &ref.ClickCount,
		&ref.SignupCount, &ref.ConversionCount, &ref.TotalEarned, &ref.IsActive,
		&ref.CreatedAt, &ref.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		// Auto-create referral code for user
		return rs.CreateReferralCode(userID, "")
	}

	return &ref, err
}

func (rs *ReferralSystem) UpdateCommissionRate(referralID int64, rate float64) error {
	if rate < 0 || rate > 100 {
		return errors.New("commission rate must be between 0 and 100")
	}

	_, err := rs.db.Exec(`
		UPDATE referral_codes 
		SET commission_rate = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, rate, referralID)
	return err
}

func (rs *ReferralSystem) ToggleReferralCode(referralID int64, active bool) error {
	_, err := rs.db.Exec(`
		UPDATE referral_codes 
		SET is_active = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, active, referralID)
	return err
}

// ==================== Click Tracking ====================

func (rs *ReferralSystem) TrackClick(code, ipAddress, userAgent, referrer string) error {
	ref, err := rs.GetReferralCode(code)
	if err != nil {
		return errors.New("invalid referral code")
	}

	if !ref.IsActive {
		return errors.New("referral code is not active")
	}

	tx, err := rs.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Record click
	_, err = tx.Exec(`
		INSERT INTO referral_clicks (referral_id, ip_address, user_agent, referrer)
		VALUES (?, ?, ?, ?)
	`, ref.ID, ipAddress, userAgent, referrer)
	if err != nil {
		return err
	}

	// Increment click count
	_, err = tx.Exec(`
		UPDATE referral_codes 
		SET click_count = click_count + 1, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, ref.ID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// ==================== Conversion Tracking ====================

func (rs *ReferralSystem) TrackSignup(code string, newUserID int64) error {
	ref, err := rs.GetReferralCode(code)
	if err != nil {
		return err
	}

	// Don't allow self-referral
	if ref.UserID == newUserID {
		return errors.New("self-referral not allowed")
	}

	// Store referral relationship in users table (add referred_by column if needed)
	_, err = rs.db.Exec(`
		UPDATE users SET referred_by = ? WHERE id = ?
	`, ref.UserID, newUserID)

	// Increment signup count
	_, err = rs.db.Exec(`
		UPDATE referral_codes 
		SET signup_count = signup_count + 1, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, ref.ID)

	return err
}

func (rs *ReferralSystem) TrackConversion(orderID int64) error {
	// Get order details
	var userID int64
	var amount float64
	err := rs.db.QueryRow(`
		SELECT user_id, final_amount FROM orders WHERE id = ? AND status = 'completed'
	`, orderID).Scan(&userID, &amount)

	if err != nil {
		return errors.New("order not found or not completed")
	}

	// Get user's referrer
	var referredBy sql.NullInt64
	err = rs.db.QueryRow("SELECT referred_by FROM users WHERE id = ?", userID).Scan(&referredBy)
	if err != nil || !referredBy.Valid {
		return errors.New("user was not referred")
	}

	// Get referral code
	ref, err := rs.GetUserReferralCode(referredBy.Int64)
	if err != nil {
		return err
	}

	// Calculate commission
	commission := amount * (ref.CommissionRate / 100)

	tx, err := rs.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Record conversion
	_, err = tx.Exec(`
		INSERT INTO referral_conversions (referral_id, referred_user_id, order_id, order_amount, commission)
		VALUES (?, ?, ?, ?, ?)
	`, ref.ID, userID, orderID, amount, commission)
	if err != nil {
		return err
	}

	// Update referral code stats
	_, err = tx.Exec(`
		UPDATE referral_codes 
		SET conversion_count = conversion_count + 1,
		    total_earned = total_earned + ?,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, commission, ref.ID)
	if err != nil {
		return err
	}

	// Credit referrer's wallet
	// Note: Payment manager integration - implement when needed
	_ = ref.UserID
	_ = commission
	_ = orderID

	return tx.Commit()
}

// ==================== Payout Management ====================

func (rs *ReferralSystem) RequestPayout(userID int64, amount float64, method string) (*ReferralPayout, error) {
	// Check minimum payout amount
	minPayout := 100000.0 // 100,000 Toman
	if amount < minPayout {
		return nil, fmt.Errorf("minimum payout amount is %f", minPayout)
	}

	// Check available balance
	ref, err := rs.GetUserReferralCode(userID)
	if err != nil {
		return nil, errors.New("referral code not found")
	}

	// Calculate available balance (total earned - already paid)
	var totalPaid float64
	rs.db.QueryRow(`
		SELECT COALESCE(SUM(amount), 0) FROM referral_payouts 
		WHERE user_id = ? AND status IN ('completed', 'processing')
	`, userID).Scan(&totalPaid)

	available := ref.TotalEarned - totalPaid
	if amount > available {
		return nil, fmt.Errorf("insufficient balance, available: %f", available)
	}

	// Create payout request
	result, err := rs.db.Exec(`
		INSERT INTO referral_payouts (user_id, amount, method)
		VALUES (?, ?, ?)
	`, userID, amount, method)

	if err != nil {
		return nil, err
	}

	payoutID, _ := result.LastInsertId()
	return rs.GetPayout(payoutID)
}

func (rs *ReferralSystem) GetPayout(payoutID int64) (*ReferralPayout, error) {
	var payout ReferralPayout
	var processedAt sql.NullTime

	err := rs.db.QueryRow(`
		SELECT id, user_id, amount, method, status, details, processed_by, processed_at, created_at
		FROM referral_payouts WHERE id = ?
	`, payoutID).Scan(
		&payout.ID, &payout.UserID, &payout.Amount, &payout.Method,
		&payout.Status, &payout.Details, &payout.ProcessedBy, &processedAt, &payout.CreatedAt,
	)

	if processedAt.Valid {
		payout.ProcessedAt = &processedAt.Time
	}

	return &payout, err
}

func (rs *ReferralSystem) ProcessPayout(payoutID, adminID int64, status, details string) error {
	now := time.Now()
	_, err := rs.db.Exec(`
		UPDATE referral_payouts 
		SET status = ?, details = ?, processed_by = ?, processed_at = ?
		WHERE id = ?
	`, status, details, adminID, now, payoutID)
	return err
}

func (rs *ReferralSystem) ListPayouts(userID int64) ([]ReferralPayout, error) {
	query := "SELECT id, user_id, amount, method, status, details, processed_by, processed_at, created_at FROM referral_payouts"
	args := []interface{}{}

	if userID > 0 {
		query += " WHERE user_id = ?"
		args = append(args, userID)
	}

	query += " ORDER BY created_at DESC"

	rows, err := rs.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var payouts []ReferralPayout
	for rows.Next() {
		var payout ReferralPayout
		var processedAt sql.NullTime
		rows.Scan(&payout.ID, &payout.UserID, &payout.Amount, &payout.Method,
			&payout.Status, &payout.Details, &payout.ProcessedBy, &processedAt, &payout.CreatedAt)

		if processedAt.Valid {
			payout.ProcessedAt = &processedAt.Time
		}
		payouts = append(payouts, payout)
	}

	return payouts, nil
}

// ==================== Statistics ====================

func (rs *ReferralSystem) GetUserStats(userID int64) (*ReferralStats, error) {
	stats := &ReferralStats{
		EarningsByMonth: make(map[string]float64),
	}

	// Get referral code
	ref, err := rs.GetUserReferralCode(userID)
	if err != nil {
		return nil, err
	}

	stats.TotalClicks = ref.ClickCount
	stats.TotalSignups = ref.SignupCount
	stats.TotalConversions = ref.ConversionCount
	stats.TotalEarnings = ref.TotalEarned

	// Calculate conversion rate
	if ref.SignupCount > 0 {
		stats.ConversionRate = (float64(ref.ConversionCount) / float64(ref.SignupCount)) * 100
	}

	// Pending earnings
	rs.db.QueryRow(`
		SELECT COALESCE(SUM(commission), 0) FROM referral_conversions 
		WHERE referral_id = ? AND status = 'pending'
	`, ref.ID).Scan(&stats.PendingEarnings)

	// Paid earnings
	rs.db.QueryRow(`
		SELECT COALESCE(SUM(amount), 0) FROM referral_payouts 
		WHERE user_id = ? AND status = 'completed'
	`, userID).Scan(&stats.PaidEarnings)

	// Earnings by month
	rows, _ := rs.db.Query(`
		SELECT strftime('%Y-%m', created_at) as month, SUM(commission)
		FROM referral_conversions
		WHERE referral_id = ?
		GROUP BY month
		ORDER BY month DESC
		LIMIT 12
	`, ref.ID)
	defer rows.Close()

	for rows.Next() {
		var month string
		var earnings float64
		rows.Scan(&month, &earnings)
		stats.EarningsByMonth[month] = earnings
	}

	return stats, nil
}

func (rs *ReferralSystem) GetGlobalStats() (*ReferralStats, error) {
	stats := &ReferralStats{
		TopReferrers:    []TopReferrer{},
		EarningsByMonth: make(map[string]float64),
	}

	// Total statistics
	rs.db.QueryRow("SELECT COALESCE(SUM(click_count), 0) FROM referral_codes").Scan(&stats.TotalClicks)
	rs.db.QueryRow("SELECT COALESCE(SUM(signup_count), 0) FROM referral_codes").Scan(&stats.TotalSignups)
	rs.db.QueryRow("SELECT COALESCE(SUM(conversion_count), 0) FROM referral_codes").Scan(&stats.TotalConversions)
	rs.db.QueryRow("SELECT COALESCE(SUM(total_earned), 0) FROM referral_codes").Scan(&stats.TotalEarnings)

	// Top referrers
	rows, _ := rs.db.Query(`
		SELECT rc.user_id, u.username, rc.code, rc.conversion_count, rc.total_earned
		FROM referral_codes rc
		JOIN users u ON rc.user_id = u.id
		WHERE rc.conversion_count > 0
		ORDER BY rc.total_earned DESC
		LIMIT 10
	`)
	defer rows.Close()

	for rows.Next() {
		var tr TopReferrer
		rows.Scan(&tr.UserID, &tr.Username, &tr.Code, &tr.Conversions, &tr.TotalEarned)
		stats.TopReferrers = append(stats.TopReferrers, tr)
	}

	return stats, nil
}

// ==================== Helper Functions ====================

func (rs *ReferralSystem) generateReferralCode() string {
	// Generate 8-character code
	b := make([]byte, 5)
	rand.Read(b)
	code := base32.StdEncoding.EncodeToString(b)
	code = strings.TrimRight(code, "=")
	return code[:8]
}

// ==================== Global Referral System ====================

var globalReferralSystem *ReferralSystem

func InitReferralSystem(db *sql.DB, defaultCommission float64, cookieExpiry int) error {
	log.Println("🤝 Initializing referral system...")

	// Add referred_by column to users table if not exists
	db.Exec(`
		ALTER TABLE users ADD COLUMN referred_by INTEGER REFERENCES users(id)
	`)

	globalReferralSystem = NewReferralSystem(db, defaultCommission, cookieExpiry)
	log.Println("✅ Referral system initialized successfully")
	return nil
}

func GetReferralSystem() *ReferralSystem {
	return globalReferralSystem
}
