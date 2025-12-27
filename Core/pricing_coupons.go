package core

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"time"
)

// ==================== Pricing Models ====================

// PricingPlan represents a subscription plan
type PricingPlan struct {
	ID          int64                  `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Price       float64                `json:"price"`
	Currency    string                 `json:"currency"`
	Duration    int                    `json:"duration"` // days
	Traffic     int64                  `json:"traffic"`  // bytes
	MaxDevices  int                    `json:"max_devices"`
	MaxServers  int                    `json:"max_servers"`
	Features    []string               `json:"features"`
	IsPublic    bool                   `json:"is_public"`
	IsPopular   bool                   `json:"is_popular"`
	SortOrder   int                    `json:"sort_order"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// Coupon represents a discount coupon
type Coupon struct {
	ID           int64     `json:"id"`
	Code         string    `json:"code"`
	Type         string    `json:"type"` // percentage, fixed
	Value        float64   `json:"value"`
	MinPurchase  float64   `json:"min_purchase"`
	MaxDiscount  float64   `json:"max_discount"`
	UsageLimit   int       `json:"usage_limit"`
	UsedCount    int       `json:"used_count"`
	PerUserLimit int       `json:"per_user_limit"`
	ValidFrom    time.Time `json:"valid_from"`
	ValidUntil   time.Time `json:"valid_until"`
	IsActive     bool      `json:"is_active"`
	CreatedBy    int64     `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// CouponUsage represents coupon usage record
type CouponUsage struct {
	ID       int64     `json:"id"`
	CouponID int64     `json:"coupon_id"`
	UserID   int64     `json:"user_id"`
	OrderID  int64     `json:"order_id"`
	Discount float64   `json:"discount"`
	UsedAt   time.Time `json:"used_at"`
}

// Order represents a purchase order
type Order struct {
	ID          int64      `json:"id"`
	UserID      int64      `json:"user_id"`
	PlanID      int64      `json:"plan_id"`
	Amount      float64    `json:"amount"`
	Discount    float64    `json:"discount"`
	FinalAmount float64    `json:"final_amount"`
	CouponCode  string     `json:"coupon_code"`
	Status      string     `json:"status"`
	PaymentID   string     `json:"payment_id"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// ==================== Pricing Plan Manager ====================

type PricingManager struct {
	db *sql.DB
}

func NewPricingManager(db *sql.DB) *PricingManager {
	pm := &PricingManager{db: db}
	pm.initTables()
	return pm
}

func (pm *PricingManager) initTables() {
	// Pricing plans table
	pm.db.Exec(`
		CREATE TABLE IF NOT EXISTS pricing_plans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			description TEXT,
			price REAL NOT NULL,
			currency TEXT DEFAULT 'IRR',
			duration INTEGER NOT NULL,
			traffic INTEGER NOT NULL,
			max_devices INTEGER DEFAULT 2,
			max_servers INTEGER DEFAULT 1,
			features TEXT,
			is_public BOOLEAN DEFAULT 1,
			is_popular BOOLEAN DEFAULT 0,
			sort_order INTEGER DEFAULT 0,
			metadata TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)

	// Coupons table
	pm.db.Exec(`
		CREATE TABLE IF NOT EXISTS coupons (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			code TEXT UNIQUE NOT NULL,
			type TEXT NOT NULL,
			value REAL NOT NULL,
			min_purchase REAL DEFAULT 0,
			max_discount REAL DEFAULT 0,
			usage_limit INTEGER DEFAULT 0,
			used_count INTEGER DEFAULT 0,
			per_user_limit INTEGER DEFAULT 1,
			valid_from DATETIME,
			valid_until DATETIME,
			is_active BOOLEAN DEFAULT 1,
			created_by INTEGER,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)

	// Coupon usage table
	pm.db.Exec(`
		CREATE TABLE IF NOT EXISTS coupon_usage (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			coupon_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			order_id INTEGER,
			discount REAL NOT NULL,
			used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (coupon_id) REFERENCES coupons(id),
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (order_id) REFERENCES orders(id)
		)
	`)

	// Orders table
	pm.db.Exec(`
		CREATE TABLE IF NOT EXISTS orders (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			plan_id INTEGER NOT NULL,
			amount REAL NOT NULL,
			discount REAL DEFAULT 0,
			final_amount REAL NOT NULL,
			coupon_code TEXT,
			status TEXT DEFAULT 'pending',
			payment_id TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			completed_at DATETIME,
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (plan_id) REFERENCES pricing_plans(id)
		)
	`)

	// Create indexes
	pm.db.Exec(`CREATE INDEX IF NOT EXISTS idx_pricing_plans_public ON pricing_plans(is_public)`)
	pm.db.Exec(`CREATE INDEX IF NOT EXISTS idx_coupons_code ON coupons(code)`)
	pm.db.Exec(`CREATE INDEX IF NOT EXISTS idx_coupon_usage_user ON coupon_usage(user_id)`)
	pm.db.Exec(`CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id)`)
	pm.db.Exec(`CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status)`)

	log.Println("💰 Pricing and coupon tables initialized")
}

// ==================== Pricing Plan CRUD ====================

func (pm *PricingManager) CreatePlan(plan *PricingPlan) error {
	featuresJSON, _ := json.Marshal(plan.Features)
	metadataJSON, _ := json.Marshal(plan.Metadata)

	result, err := pm.db.Exec(`
		INSERT INTO pricing_plans (name, description, price, currency, duration, traffic,
		                          max_devices, max_servers, features, is_public, is_popular,
		                          sort_order, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, plan.Name, plan.Description, plan.Price, plan.Currency, plan.Duration, plan.Traffic,
		plan.MaxDevices, plan.MaxServers, string(featuresJSON), plan.IsPublic, plan.IsPopular,
		plan.SortOrder, string(metadataJSON))

	if err != nil {
		return err
	}

	plan.ID, _ = result.LastInsertId()
	return nil
}

func (pm *PricingManager) GetPlan(planID int64) (*PricingPlan, error) {
	var plan PricingPlan
	var featuresJSON, metadataJSON string

	err := pm.db.QueryRow(`
		SELECT id, name, description, price, currency, duration, traffic,
		       max_devices, max_servers, COALESCE(features, '[]'), is_public, is_popular,
		       sort_order, COALESCE(metadata, '{}'), created_at, updated_at
		FROM pricing_plans WHERE id = ?
	`, planID).Scan(
		&plan.ID, &plan.Name, &plan.Description, &plan.Price, &plan.Currency,
		&plan.Duration, &plan.Traffic, &plan.MaxDevices, &plan.MaxServers,
		&featuresJSON, &plan.IsPublic, &plan.IsPopular, &plan.SortOrder,
		&metadataJSON, &plan.CreatedAt, &plan.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(featuresJSON), &plan.Features)
	json.Unmarshal([]byte(metadataJSON), &plan.Metadata)

	return &plan, nil
}

func (pm *PricingManager) ListPlans(publicOnly bool) ([]PricingPlan, error) {
	query := `
		SELECT id, name, description, price, currency, duration, traffic,
		       max_devices, max_servers, COALESCE(features, '[]'), is_public, is_popular,
		       sort_order, COALESCE(metadata, '{}'), created_at, updated_at
		FROM pricing_plans
	`

	if publicOnly {
		query += " WHERE is_public = 1"
	}

	query += " ORDER BY sort_order, price"

	rows, err := pm.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var plans []PricingPlan
	for rows.Next() {
		var plan PricingPlan
		var featuresJSON, metadataJSON string

		rows.Scan(
			&plan.ID, &plan.Name, &plan.Description, &plan.Price, &plan.Currency,
			&plan.Duration, &plan.Traffic, &plan.MaxDevices, &plan.MaxServers,
			&featuresJSON, &plan.IsPublic, &plan.IsPopular, &plan.SortOrder,
			&metadataJSON, &plan.CreatedAt, &plan.UpdatedAt,
		)

		json.Unmarshal([]byte(featuresJSON), &plan.Features)
		json.Unmarshal([]byte(metadataJSON), &plan.Metadata)

		plans = append(plans, plan)
	}

	return plans, nil
}

func (pm *PricingManager) UpdatePlan(planID int64, updates map[string]interface{}) error {
	allowedFields := map[string]bool{
		"name": true, "description": true, "price": true, "currency": true,
		"duration": true, "traffic": true, "max_devices": true, "max_servers": true,
		"features": true, "is_public": true, "is_popular": true, "sort_order": true,
		"metadata": true,
	}

	query := "UPDATE pricing_plans SET updated_at = CURRENT_TIMESTAMP"
	args := []interface{}{}

	for field, value := range updates {
		if !allowedFields[field] {
			continue
		}

		query += fmt.Sprintf(", %s = ?", field)

		// Special handling for JSON fields
		if field == "features" || field == "metadata" {
			jsonValue, _ := json.Marshal(value)
			args = append(args, string(jsonValue))
		} else {
			args = append(args, value)
		}
	}

	query += " WHERE id = ?"
	args = append(args, planID)

	_, err := pm.db.Exec(query, args...)
	return err
}

func (pm *PricingManager) DeletePlan(planID int64) error {
	// Check if plan is used in any orders
	var orderCount int
	pm.db.QueryRow("SELECT COUNT(*) FROM orders WHERE plan_id = ?", planID).Scan(&orderCount)

	if orderCount > 0 {
		return errors.New("cannot delete plan with existing orders")
	}

	_, err := pm.db.Exec("DELETE FROM pricing_plans WHERE id = ?", planID)
	return err
}

// ==================== Coupon Manager ====================

type CouponManager struct {
	db *sql.DB
}

func NewCouponManager(db *sql.DB) *CouponManager {
	return &CouponManager{db: db}
}

func (cm *CouponManager) CreateCoupon(coupon *Coupon) error {
	// Generate code if not provided
	if coupon.Code == "" {
		coupon.Code = cm.generateCouponCode()
	}

	// Validate type
	if coupon.Type != "percentage" && coupon.Type != "fixed" {
		return errors.New("invalid coupon type, must be 'percentage' or 'fixed'")
	}

	// Validate value
	if coupon.Type == "percentage" && (coupon.Value < 0 || coupon.Value > 100) {
		return errors.New("percentage value must be between 0 and 100")
	}

	result, err := cm.db.Exec(`
		INSERT INTO coupons (code, type, value, min_purchase, max_discount, usage_limit,
		                     per_user_limit, valid_from, valid_until, is_active, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, coupon.Code, coupon.Type, coupon.Value, coupon.MinPurchase, coupon.MaxDiscount,
		coupon.UsageLimit, coupon.PerUserLimit, coupon.ValidFrom, coupon.ValidUntil,
		coupon.IsActive, coupon.CreatedBy)

	if err != nil {
		return err
	}

	coupon.ID, _ = result.LastInsertId()
	return nil
}

func (cm *CouponManager) GetCoupon(code string) (*Coupon, error) {
	var coupon Coupon

	err := cm.db.QueryRow(`
		SELECT id, code, type, value, min_purchase, max_discount, usage_limit, used_count,
		       per_user_limit, valid_from, valid_until, is_active, created_by,
		       created_at, updated_at
		FROM coupons WHERE code = ?
	`, code).Scan(
		&coupon.ID, &coupon.Code, &coupon.Type, &coupon.Value, &coupon.MinPurchase,
		&coupon.MaxDiscount, &coupon.UsageLimit, &coupon.UsedCount, &coupon.PerUserLimit,
		&coupon.ValidFrom, &coupon.ValidUntil, &coupon.IsActive, &coupon.CreatedBy,
		&coupon.CreatedAt, &coupon.UpdatedAt,
	)

	return &coupon, err
}

func (cm *CouponManager) ValidateCoupon(code string, userID int64, amount float64) (*Coupon, error) {
	coupon, err := cm.GetCoupon(code)
	if err != nil {
		return nil, errors.New("invalid coupon code")
	}

	// Check if active
	if !coupon.IsActive {
		return nil, errors.New("coupon is not active")
	}

	// Check validity period
	now := time.Now()
	if now.Before(coupon.ValidFrom) {
		return nil, errors.New("coupon is not yet valid")
	}
	if now.After(coupon.ValidUntil) {
		return nil, errors.New("coupon has expired")
	}

	// Check usage limit
	if coupon.UsageLimit > 0 && coupon.UsedCount >= coupon.UsageLimit {
		return nil, errors.New("coupon usage limit exceeded")
	}

	// Check per-user limit
	if coupon.PerUserLimit > 0 {
		var userUsageCount int
		cm.db.QueryRow(`
			SELECT COUNT(*) FROM coupon_usage WHERE coupon_id = ? AND user_id = ?
		`, coupon.ID, userID).Scan(&userUsageCount)

		if userUsageCount >= coupon.PerUserLimit {
			return nil, errors.New("you have already used this coupon maximum times")
		}
	}

	// Check minimum purchase
	if amount < coupon.MinPurchase {
		return nil, fmt.Errorf("minimum purchase amount is %f", coupon.MinPurchase)
	}

	return coupon, nil
}

func (cm *CouponManager) CalculateDiscount(coupon *Coupon, amount float64) float64 {
	var discount float64

	if coupon.Type == "percentage" {
		discount = amount * (coupon.Value / 100)
	} else {
		discount = coupon.Value
	}

	// Apply max discount limit
	if coupon.MaxDiscount > 0 && discount > coupon.MaxDiscount {
		discount = coupon.MaxDiscount
	}

	// Discount cannot exceed amount
	if discount > amount {
		discount = amount
	}

	return discount
}

func (cm *CouponManager) UseCoupon(couponID, userID, orderID int64, discount float64) error {
	tx, err := cm.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Record usage
	_, err = tx.Exec(`
		INSERT INTO coupon_usage (coupon_id, user_id, order_id, discount)
		VALUES (?, ?, ?, ?)
	`, couponID, userID, orderID, discount)
	if err != nil {
		return err
	}

	// Increment used count
	_, err = tx.Exec(`
		UPDATE coupons SET used_count = used_count + 1, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, couponID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (cm *CouponManager) ListCoupons(activeOnly bool) ([]Coupon, error) {
	query := "SELECT id, code, type, value, min_purchase, max_discount, usage_limit, used_count, per_user_limit, valid_from, valid_until, is_active, created_by, created_at, updated_at FROM coupons"

	if activeOnly {
		query += " WHERE is_active = 1 AND valid_until > CURRENT_TIMESTAMP"
	}

	query += " ORDER BY created_at DESC"

	rows, err := cm.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var coupons []Coupon
	for rows.Next() {
		var coupon Coupon
		rows.Scan(&coupon.ID, &coupon.Code, &coupon.Type, &coupon.Value, &coupon.MinPurchase,
			&coupon.MaxDiscount, &coupon.UsageLimit, &coupon.UsedCount, &coupon.PerUserLimit,
			&coupon.ValidFrom, &coupon.ValidUntil, &coupon.IsActive, &coupon.CreatedBy,
			&coupon.CreatedAt, &coupon.UpdatedAt)
		coupons = append(coupons, coupon)
	}

	return coupons, nil
}

func (cm *CouponManager) DeleteCoupon(couponID int64) error {
	// Soft delete - just deactivate
	_, err := cm.db.Exec("UPDATE coupons SET is_active = 0 WHERE id = ?", couponID)
	return err
}

func (cm *CouponManager) generateCouponCode() string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 10

	code := make([]byte, length)
	for i := range code {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		code[i] = charset[n.Int64()]
	}

	return string(code)
}

// ==================== Order Management ====================

func (pm *PricingManager) CreateOrder(userID, planID int64, couponCode string) (*Order, error) {
	// Get plan
	plan, err := pm.GetPlan(planID)
	if err != nil {
		return nil, errors.New("invalid plan")
	}

	order := &Order{
		UserID:      userID,
		PlanID:      planID,
		Amount:      plan.Price,
		Discount:    0,
		FinalAmount: plan.Price,
		CouponCode:  couponCode,
		Status:      "pending",
	}

	// Apply coupon if provided
	if couponCode != "" {
		cm := NewCouponManager(pm.db)
		coupon, err := cm.ValidateCoupon(couponCode, userID, plan.Price)
		if err != nil {
			return nil, fmt.Errorf("coupon validation failed: %v", err)
		}

		order.Discount = cm.CalculateDiscount(coupon, plan.Price)
		order.FinalAmount = plan.Price - order.Discount
	}

	// Create order
	result, err := pm.db.Exec(`
		INSERT INTO orders (user_id, plan_id, amount, discount, final_amount, coupon_code, status)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, order.UserID, order.PlanID, order.Amount, order.Discount, order.FinalAmount,
		order.CouponCode, order.Status)

	if err != nil {
		return nil, err
	}

	order.ID, _ = result.LastInsertId()
	return order, nil
}

func (pm *PricingManager) CompleteOrder(orderID int64, paymentID string) error {
	tx, err := pm.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Update order status
	now := time.Now()
	_, err = tx.Exec(`
		UPDATE orders 
		SET status = 'completed', payment_id = ?, completed_at = ?
		WHERE id = ?
	`, paymentID, now, orderID)
	if err != nil {
		return err
	}

	// Get order details
	var userID, planID int64
	var couponCode sql.NullString
	var discount float64
	err = tx.QueryRow(`
		SELECT user_id, plan_id, coupon_code, discount
		FROM orders WHERE id = ?
	`, orderID).Scan(&userID, &planID, &couponCode, &discount)
	if err != nil {
		return err
	}

	// Record coupon usage if applicable
	if couponCode.Valid {
		cm := NewCouponManager(pm.db)
		coupon, _ := cm.GetCoupon(couponCode.String)
		if coupon != nil {
			cm.UseCoupon(coupon.ID, userID, orderID, discount)
		}
	}

	// Apply plan to user (extend service, add traffic, etc.)
	plan, _ := pm.GetPlan(planID)
	if plan != nil {
		// Update user subscription
		_, err = tx.Exec(`
			UPDATE users 
			SET traffic_limit = traffic_limit + ?,
			    max_connections = ?,
			    expiry_date = CASE 
			        WHEN expiry_date > CURRENT_TIMESTAMP THEN datetime(expiry_date, '+' || ? || ' days')
			        ELSE datetime(CURRENT_TIMESTAMP, '+' || ? || ' days')
			    END
			WHERE id = ?
		`, plan.Traffic, plan.MaxDevices, plan.Duration, plan.Duration, userID)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (pm *PricingManager) GetOrder(orderID int64) (*Order, error) {
	var order Order
	var completedAt sql.NullTime

	err := pm.db.QueryRow(`
		SELECT id, user_id, plan_id, amount, discount, final_amount, coupon_code,
		       status, payment_id, created_at, completed_at
		FROM orders WHERE id = ?
	`, orderID).Scan(
		&order.ID, &order.UserID, &order.PlanID, &order.Amount, &order.Discount,
		&order.FinalAmount, &order.CouponCode, &order.Status, &order.PaymentID,
		&order.CreatedAt, &completedAt,
	)

	if completedAt.Valid {
		order.CompletedAt = &completedAt.Time
	}

	return &order, err
}

// ==================== Global Instances ====================

var (
	globalPricingManager *PricingManager
	globalCouponManager  *CouponManager
)

func InitPricingSystem(db *sql.DB) error {
	log.Println("💰 Initializing pricing and coupon system...")

	globalPricingManager = NewPricingManager(db)
	globalCouponManager = NewCouponManager(db)

	// Create default plans if none exist
	var count int
	db.QueryRow("SELECT COUNT(*) FROM pricing_plans").Scan(&count)
	if count == 0 {
		defaultPlans := []*PricingPlan{
			{
				Name:        "Bronze",
				Description: "پلن مقرون به صرفه برای استفاده شخصی",
				Price:       50000,
				Currency:    "IRR",
				Duration:    30,
				Traffic:     30 * 1024 * 1024 * 1024,
				MaxDevices:  2,
				Features:    []string{"تمامی پروتکل‌ها", "پشتیبانی 24/7"},
				IsPublic:    true,
				SortOrder:   1,
			},
			{
				Name:        "Silver",
				Description: "پلن محبوب برای خانواده",
				Price:       150000,
				Currency:    "IRR",
				Duration:    30,
				Traffic:     100 * 1024 * 1024 * 1024,
				MaxDevices:  3,
				Features:    []string{"تمامی پروتکل‌ها", "پشتیبانی اختصاصی", "تخفیف تمدید"},
				IsPublic:    true,
				IsPopular:   true,
				SortOrder:   2,
			},
			{
				Name:        "Gold",
				Description: "پلن حرفه‌ای با امکانات کامل",
				Price:       400000,
				Currency:    "IRR",
				Duration:    90,
				Traffic:     500 * 1024 * 1024 * 1024,
				MaxDevices:  5,
				Features:    []string{"تمامی پروتکل‌ها", "پشتیبانی VIP", "تخفیف ویژه", "سرور اختصاصی"},
				IsPublic:    true,
				SortOrder:   3,
			},
		}

		for _, plan := range defaultPlans {
			globalPricingManager.CreatePlan(plan)
		}
		log.Println("✓ Created default pricing plans")
	}

	log.Println("✅ Pricing and coupon system initialized successfully")
	return nil
}

func GetPricingManager() *PricingManager {
	return globalPricingManager
}

func GetCouponManager() *CouponManager {
	return globalCouponManager
}
