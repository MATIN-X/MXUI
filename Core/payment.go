// Core/payment.go
// MXUI VPN Panel - Payment & Financial System
// Part 1: Constants, Structures, Wallet System, Currency Management

package core

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ==================== Constants ====================

// Currency codes
const (
	CurrencyUSD  Currency = "USD"  // US Dollar
	CurrencyEUR  Currency = "EUR"  // Euro
	CurrencyGBP  Currency = "GBP"  // British Pound
	CurrencyIRR  Currency = "IRR"  // Iranian Rial
	CurrencyTRY  Currency = "TRY"  // Turkish Lira
	CurrencyRUB  Currency = "RUB"  // Russian Ruble
	CurrencyCNY  Currency = "CNY"  // Chinese Yuan
	CurrencyAED  Currency = "AED"  // UAE Dirham
	CurrencyBTC  Currency = "BTC"  // Bitcoin
	CurrencyETH  Currency = "ETH"  // Ethereum
	CurrencyUSDT Currency = "USDT" // Tether
	CurrencyTRX  Currency = "TRX"  // Tron
)

// Transaction types
const (
	TxTypeDeposit           TransactionType = "deposit"
	TxTypeWithdraw          TransactionType = "withdraw"
	TxTypePurchase          TransactionType = "purchase"
	TxTypeRefund            TransactionType = "refund"
	TxTypeCommission        TransactionType = "commission"
	TxTypeTransfer          TransactionType = "transfer"
	TxTypeBonus             TransactionType = "bonus"
	TxTypeAdjustment        TransactionType = "adjustment"
	TxTypeSubscriptionRenew TransactionType = "subscription_renew"
)

// Transaction statuses
const (
	TxStatusPending   TransactionStatus = "pending"
	TxStatusCompleted TransactionStatus = "completed"
	TxStatusFailed    TransactionStatus = "failed"
	TxStatusCancelled TransactionStatus = "cancelled"
	TxStatusRefunded  TransactionStatus = "refunded"
)

// Invoice statuses
const (
	InvoiceStatusDraft     InvoiceStatus = "draft"
	InvoiceStatusPending   InvoiceStatus = "pending"
	InvoiceStatusPaid      InvoiceStatus = "paid"
	InvoiceStatusCancelled InvoiceStatus = "cancelled"
	InvoiceStatusExpired   InvoiceStatus = "expired"
	InvoiceStatusRefunded  InvoiceStatus = "refunded"
	InvoiceStatusPartial   InvoiceStatus = "partial"
)

// Payment gateway types
const (
	GatewayZarinpal     PaymentGateway = "zarinpal"
	GatewayNextpay      PaymentGateway = "nextpay"
	GatewayIdpay        PaymentGateway = "idpay"
	GatewayPaypal       PaymentGateway = "paypal"
	GatewayStripe       PaymentGateway = "stripe"
	GatewayPerfectMoney PaymentGateway = "perfectmoney"
	GatewayCrypto       PaymentGateway = "crypto"
	GatewayNowPayments  PaymentGateway = "nowpayments"
	GatewayManual       PaymentGateway = "manual"
	GatewayWallet       PaymentGateway = "wallet"
	GatewayTelegram     PaymentGateway = "telegram"
	GatewayCard         PaymentGateway = "card_to_card"
)

// Plan duration types
const (
	DurationDaily    PlanDuration = "daily"
	DurationWeekly   PlanDuration = "weekly"
	DurationMonthly  PlanDuration = "monthly"
	DurationYearly   PlanDuration = "yearly"
	DurationCustom   PlanDuration = "custom"
	DurationLifetime PlanDuration = "lifetime"
)

// ==================== Type Definitions ====================

type Currency string
type TransactionType string
type TransactionStatus string
type InvoiceStatus string
type PaymentGateway string
type PlanDuration string

// ==================== Core Structures ====================

// Wallet represents user's wallet
type Wallet struct {
	ID             string                 `json:"id"`
	UserID         string                 `json:"user_id"`
	AdminID        string                 `json:"admin_id,omitempty"` // For admin wallets
	Balance        float64                `json:"balance"`
	Currency       Currency               `json:"currency"`
	FrozenBalance  float64                `json:"frozen_balance"` // Reserved for pending transactions
	TotalDeposited float64                `json:"total_deposited"`
	TotalWithdrawn float64                `json:"total_withdrawn"`
	TotalSpent     float64                `json:"total_spent"`
	TotalEarned    float64                `json:"total_earned"` // For resellers
	IsActive       bool                   `json:"is_active"`
	Limits         WalletLimits           `json:"limits"`
	Meta           map[string]interface{} `json:"meta,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// WalletLimits defines wallet operation limits
type WalletLimits struct {
	MaxBalance           float64 `json:"max_balance"`
	MinDeposit           float64 `json:"min_deposit"`
	MaxDeposit           float64 `json:"max_deposit"`
	MinWithdraw          float64 `json:"min_withdraw"`
	MaxWithdraw          float64 `json:"max_withdraw"`
	DailyWithdrawLimit   float64 `json:"daily_withdraw_limit"`
	DailyDepositLimit    float64 `json:"daily_deposit_limit"`
	MonthlyWithdrawLimit float64 `json:"monthly_withdraw_limit"`
}

// Transaction represents a financial transaction
type Transaction struct {
	ID            string                 `json:"id"`
	WalletID      string                 `json:"wallet_id"`
	UserID        string                 `json:"user_id,omitempty"`
	AdminID       string                 `json:"admin_id,omitempty"`
	Type          TransactionType        `json:"type"`
	Status        TransactionStatus      `json:"status"`
	Amount        float64                `json:"amount"`
	Currency      Currency               `json:"currency"`
	AmountUSD     float64                `json:"amount_usd"` // Converted to USD for reports
	BalanceBefore float64                `json:"balance_before"`
	BalanceAfter  float64                `json:"balance_after"`
	Fee           float64                `json:"fee,omitempty"`
	Gateway       PaymentGateway         `json:"gateway,omitempty"`
	GatewayTxID   string                 `json:"gateway_tx_id,omitempty"`
	ReferenceID   string                 `json:"reference_id,omitempty"` // Invoice/Order ID
	Description   string                 `json:"description,omitempty"`
	Meta          map[string]interface{} `json:"meta,omitempty"`
	IP            string                 `json:"ip,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
	CompletedAt   *time.Time             `json:"completed_at,omitempty"`
}

// Invoice represents a payment invoice
type Invoice struct {
	ID            string                 `json:"id"`
	InvoiceNumber string                 `json:"invoice_number"`
	UserID        string                 `json:"user_id"`
	AdminID       string                 `json:"admin_id,omitempty"` // Creator admin
	Status        InvoiceStatus          `json:"status"`
	Items         []InvoiceItem          `json:"items"`
	Subtotal      float64                `json:"subtotal"`
	Discount      float64                `json:"discount"`
	DiscountCode  string                 `json:"discount_code,omitempty"`
	Tax           float64                `json:"tax"`
	TaxRate       float64                `json:"tax_rate"`
	Total         float64                `json:"total"`
	PaidAmount    float64                `json:"paid_amount"`
	Currency      Currency               `json:"currency"`
	Gateway       PaymentGateway         `json:"gateway,omitempty"`
	GatewayData   map[string]interface{} `json:"gateway_data,omitempty"`
	PaymentURL    string                 `json:"payment_url,omitempty"`
	Notes         string                 `json:"notes,omitempty"`
	DueDate       time.Time              `json:"due_date"`
	PaidAt        *time.Time             `json:"paid_at,omitempty"`
	Meta          map[string]interface{} `json:"meta,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

// InvoiceItem represents an item in invoice
type InvoiceItem struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // subscription, addon, custom
	PlanID      string                 `json:"plan_id,omitempty"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Quantity    int                    `json:"quantity"`
	UnitPrice   float64                `json:"unit_price"`
	Total       float64                `json:"total"`
	Meta        map[string]interface{} `json:"meta,omitempty"`
}

// SubscriptionPlan represents a VPN subscription plan
type SubscriptionPlan struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	NameFA          string                 `json:"name_fa,omitempty"`
	Description     string                 `json:"description,omitempty"`
	DescriptionFA   string                 `json:"description_fa,omitempty"`
	Duration        PlanDuration           `json:"duration"`
	DurationDays    int                    `json:"duration_days"`
	TrafficGB       int64                  `json:"traffic_gb"` // 0 = unlimited
	DeviceLimit     int                    `json:"device_limit"`
	ConcurrentLimit int                    `json:"concurrent_limit"`
	Protocols       []string               `json:"protocols,omitempty"` // Empty = all
	Nodes           []string               `json:"nodes,omitempty"`     // Empty = all
	Prices          map[Currency]float64   `json:"prices"`
	OriginalPrices  map[Currency]float64   `json:"original_prices,omitempty"` // For showing discount
	Features        []string               `json:"features,omitempty"`
	FeaturesFA      []string               `json:"features_fa,omitempty"`
	IsActive        bool                   `json:"is_active"`
	IsPopular       bool                   `json:"is_popular"`
	IsTrial         bool                   `json:"is_trial"`
	TrialOnce       bool                   `json:"trial_once"` // Can use trial only once
	SortOrder       int                    `json:"sort_order"`
	AdminID         string                 `json:"admin_id,omitempty"` // If specific to admin
	Meta            map[string]interface{} `json:"meta,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// DiscountCode represents a discount/coupon code
type DiscountCode struct {
	ID              string    `json:"id"`
	Code            string    `json:"code"`
	Description     string    `json:"description,omitempty"`
	Type            string    `json:"type"` // percent, fixed
	Value           float64   `json:"value"`
	Currency        Currency  `json:"currency,omitempty"` // For fixed discount
	MinPurchase     float64   `json:"min_purchase,omitempty"`
	MaxDiscount     float64   `json:"max_discount,omitempty"`
	UsageLimit      int       `json:"usage_limit"` // 0 = unlimited
	UsageCount      int       `json:"usage_count"`
	PerUserLimit    int       `json:"per_user_limit"`             // 0 = unlimited
	ApplicablePlans []string  `json:"applicable_plans,omitempty"` // Empty = all
	AdminID         string    `json:"admin_id,omitempty"`
	IsActive        bool      `json:"is_active"`
	StartsAt        time.Time `json:"starts_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	CreatedAt       time.Time `json:"created_at"`
}

// CurrencyRate stores exchange rates
type CurrencyRate struct {
	FromCurrency Currency  `json:"from_currency"`
	ToCurrency   Currency  `json:"to_currency"`
	Rate         float64   `json:"rate"`
	Source       string    `json:"source,omitempty"` // API source
	UpdatedAt    time.Time `json:"updated_at"`
}

// PaymentGatewayConfig stores gateway configuration
type PaymentGatewayConfig struct {
	Gateway     PaymentGateway         `json:"gateway"`
	Name        string                 `json:"name"`
	IsActive    bool                   `json:"is_active"`
	Currencies  []Currency             `json:"currencies"`
	MinAmount   float64                `json:"min_amount"`
	MaxAmount   float64                `json:"max_amount"`
	Fee         float64                `json:"fee"` // Percentage
	FixedFee    float64                `json:"fixed_fee"`
	Config      map[string]interface{} `json:"config"` // API keys, etc.
	WebhookURL  string                 `json:"webhook_url,omitempty"`
	CallbackURL string                 `json:"callback_url,omitempty"`
	SortOrder   int                    `json:"sort_order"`
	Meta        map[string]interface{} `json:"meta,omitempty"`
}

// PaymentSession stores temporary payment session
type PaymentSession struct {
	ID          string                 `json:"id"`
	InvoiceID   string                 `json:"invoice_id"`
	UserID      string                 `json:"user_id"`
	Gateway     PaymentGateway         `json:"gateway"`
	Amount      float64                `json:"amount"`
	Currency    Currency               `json:"currency"`
	Status      string                 `json:"status"`
	PaymentURL  string                 `json:"payment_url,omitempty"`
	GatewayData map[string]interface{} `json:"gateway_data,omitempty"`
	IP          string                 `json:"ip,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	ExpiresAt   time.Time              `json:"expires_at"`
	CreatedAt   time.Time              `json:"created_at"`
}

// CommissionRule defines reseller commission rules
type CommissionRule struct {
	ID        string    `json:"id"`
	AdminID   string    `json:"admin_id"`
	Type      string    `json:"type"` // percent, fixed
	Value     float64   `json:"value"`
	PlanID    string    `json:"plan_id,omitempty"` // Empty = all plans
	MinSales  int       `json:"min_sales"`         // Minimum sales to get this rate
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
}

// ==================== Payment Manager ====================

// PaymentManager handles all payment operations
type PaymentManager struct {
	db              *sql.DB
	config          *PaymentConfig
	walletCache     sync.Map // walletID -> *Wallet
	rateCache       sync.Map // currency pair -> rate
	gatewayHandlers map[PaymentGateway]GatewayHandler
	mu              sync.RWMutex
	eventChan       chan PaymentEvent
	ctx             context.Context
	cancel          context.CancelFunc
}

// PaymentConfig holds payment system configuration
type PaymentConfig struct {
	DefaultCurrency     Currency               `json:"default_currency"`
	SupportedCurrencies []Currency             `json:"supported_currencies"`
	AutoConvert         bool                   `json:"auto_convert"`
	TaxEnabled          bool                   `json:"tax_enabled"`
	TaxRate             float64                `json:"tax_rate"`
	InvoicePrefix       string                 `json:"invoice_prefix"`
	InvoiceExpiry       time.Duration          `json:"invoice_expiry"`
	WalletEnabled       bool                   `json:"wallet_enabled"`
	DefaultLimits       WalletLimits           `json:"default_limits"`
	Gateways            []PaymentGatewayConfig `json:"gateways"`
	RateUpdateInterval  time.Duration          `json:"rate_update_interval"`
	RateAPIKey          string                 `json:"rate_api_key,omitempty"`
}

// PaymentEvent represents payment-related events
type PaymentEvent struct {
	Type      string      `json:"type"`
	UserID    string      `json:"user_id,omitempty"`
	AdminID   string      `json:"admin_id,omitempty"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// GatewayHandler interface for payment gateways
type GatewayHandler interface {
	Name() string
	CreatePayment(ctx context.Context, invoice *Invoice) (*PaymentSession, error)
	VerifyPayment(ctx context.Context, session *PaymentSession, data map[string]string) (bool, error)
	RefundPayment(ctx context.Context, transaction *Transaction) error
	GetStatus(ctx context.Context, session *PaymentSession) (string, error)
	ParseWebhook(r *http.Request) (map[string]interface{}, error)
	SupportedCurrencies() []Currency
}

// ==================== Payment Manager Methods ====================

// NewPaymentManager creates new payment manager
func NewPaymentManager(db *sql.DB, config *PaymentConfig) *PaymentManager {
	ctx, cancel := context.WithCancel(context.Background())

	pm := &PaymentManager{
		db:              db,
		config:          config,
		gatewayHandlers: make(map[PaymentGateway]GatewayHandler),
		eventChan:       make(chan PaymentEvent, 1000),
		ctx:             ctx,
		cancel:          cancel,
	}

	// Initialize gateway handlers
	pm.initGateways()

	// Start background workers
	go pm.eventProcessor()
	go pm.rateUpdater()
	go pm.invoiceExpiryChecker()

	return pm
}

// initGateways initializes payment gateway handlers
func (pm *PaymentManager) initGateways() {
	for _, gc := range pm.config.Gateways {
		if !gc.IsActive {
			continue
		}

		switch gc.Gateway {
		case GatewayZarinpal:
			pm.gatewayHandlers[gc.Gateway] = NewZarinpalHandler(gc)
		case GatewayStripe:
			pm.gatewayHandlers[gc.Gateway] = NewStripeHandler(gc)
		case GatewayNowPayments:
			pm.gatewayHandlers[gc.Gateway] = NewNowPaymentsHandler(gc)
		case GatewayManual:
			pm.gatewayHandlers[gc.Gateway] = NewManualHandler(gc)
		case GatewayCard:
			pm.gatewayHandlers[gc.Gateway] = NewCardToCardHandler(gc)
		}
	}
}

// Close shuts down payment manager
func (pm *PaymentManager) Close() {
	pm.cancel()
	close(pm.eventChan)
}

// ==================== Wallet Operations ====================

// CreateWallet creates a new wallet for user or admin
func (pm *PaymentManager) CreateWallet(userID, adminID string, currency Currency) (*Wallet, error) {
	wallet := &Wallet{
		ID:        uuid.New().String(),
		UserID:    userID,
		AdminID:   adminID,
		Balance:   0,
		Currency:  currency,
		IsActive:  true,
		Limits:    pm.config.DefaultLimits,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	query := `INSERT INTO wallets (
		id, user_id, admin_id, balance, currency, frozen_balance,
		total_deposited, total_withdrawn, total_spent, total_earned,
		is_active, limits_json, meta_json, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	limitsJSON, _ := json.Marshal(wallet.Limits)
	metaJSON, _ := json.Marshal(wallet.Meta)

	_, err := pm.db.Exec(query,
		wallet.ID, wallet.UserID, wallet.AdminID, wallet.Balance, wallet.Currency,
		wallet.FrozenBalance, wallet.TotalDeposited, wallet.TotalWithdrawn,
		wallet.TotalSpent, wallet.TotalEarned, wallet.IsActive,
		string(limitsJSON), string(metaJSON), wallet.CreatedAt, wallet.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create wallet: %w", err)
	}

	pm.walletCache.Store(wallet.ID, wallet)
	pm.emitEvent("wallet_created", userID, adminID, wallet)

	return wallet, nil
}

// GetWallet retrieves wallet by ID
func (pm *PaymentManager) GetWallet(walletID string) (*Wallet, error) {
	// Check cache first
	if cached, ok := pm.walletCache.Load(walletID); ok {
		return cached.(*Wallet), nil
	}

	wallet := &Wallet{}
	var limitsJSON, metaJSON string

	query := `SELECT id, user_id, admin_id, balance, currency, frozen_balance,
		total_deposited, total_withdrawn, total_spent, total_earned,
		is_active, limits_json, meta_json, created_at, updated_at
		FROM wallets WHERE id = ?`

	err := pm.db.QueryRow(query, walletID).Scan(
		&wallet.ID, &wallet.UserID, &wallet.AdminID, &wallet.Balance, &wallet.Currency,
		&wallet.FrozenBalance, &wallet.TotalDeposited, &wallet.TotalWithdrawn,
		&wallet.TotalSpent, &wallet.TotalEarned, &wallet.IsActive,
		&limitsJSON, &metaJSON, &wallet.CreatedAt, &wallet.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("wallet not found: %w", err)
	}

	json.Unmarshal([]byte(limitsJSON), &wallet.Limits)
	json.Unmarshal([]byte(metaJSON), &wallet.Meta)

	pm.walletCache.Store(wallet.ID, wallet)
	return wallet, nil
}

// GetWalletByUser retrieves wallet by user ID
func (pm *PaymentManager) GetWalletByUser(userID string) (*Wallet, error) {
	var walletID string
	err := pm.db.QueryRow("SELECT id FROM wallets WHERE user_id = ?", userID).Scan(&walletID)
	if err != nil {
		// Create wallet if not exists
		return pm.CreateWallet(userID, "", pm.config.DefaultCurrency)
	}
	return pm.GetWallet(walletID)
}

// GetWalletByAdmin retrieves wallet by admin ID
func (pm *PaymentManager) GetWalletByAdmin(adminID string) (*Wallet, error) {
	var walletID string
	err := pm.db.QueryRow("SELECT id FROM wallets WHERE admin_id = ?", adminID).Scan(&walletID)
	if err != nil {
		return pm.CreateWallet("", adminID, pm.config.DefaultCurrency)
	}
	return pm.GetWallet(walletID)
}

// Deposit adds funds to wallet
func (pm *PaymentManager) Deposit(walletID string, amount float64, currency Currency,
	gateway PaymentGateway, gatewayTxID, description string) (*Transaction, error) {

	if amount <= 0 {
		return nil, errors.New("invalid deposit amount")
	}

	wallet, err := pm.GetWallet(walletID)
	if err != nil {
		return nil, err
	}

	if !wallet.IsActive {
		return nil, errors.New("wallet is not active")
	}

	// Check limits
	if wallet.Limits.MaxDeposit > 0 && amount > wallet.Limits.MaxDeposit {
		return nil, fmt.Errorf("deposit exceeds maximum limit of %.2f", wallet.Limits.MaxDeposit)
	}

	if wallet.Limits.MinDeposit > 0 && amount < wallet.Limits.MinDeposit {
		return nil, fmt.Errorf("deposit below minimum limit of %.2f", wallet.Limits.MinDeposit)
	}

	// Convert to wallet currency if different
	convertedAmount := amount
	if currency != wallet.Currency {
		convertedAmount, err = pm.ConvertCurrency(amount, currency, wallet.Currency)
		if err != nil {
			return nil, err
		}
	}

	// Convert to USD for reports
	amountUSD, _ := pm.ConvertCurrency(amount, currency, CurrencyUSD)

	// Check max balance
	if wallet.Limits.MaxBalance > 0 && (wallet.Balance+convertedAmount) > wallet.Limits.MaxBalance {
		return nil, errors.New("deposit would exceed maximum balance")
	}

	// Start transaction
	tx, err := pm.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Create transaction record
	transaction := &Transaction{
		ID:            uuid.New().String(),
		WalletID:      walletID,
		UserID:        wallet.UserID,
		AdminID:       wallet.AdminID,
		Type:          TxTypeDeposit,
		Status:        TxStatusCompleted,
		Amount:        convertedAmount,
		Currency:      wallet.Currency,
		AmountUSD:     amountUSD,
		BalanceBefore: wallet.Balance,
		BalanceAfter:  wallet.Balance + convertedAmount,
		Gateway:       gateway,
		GatewayTxID:   gatewayTxID,
		Description:   description,
		CreatedAt:     time.Now(),
	}

	now := time.Now()
	transaction.CompletedAt = &now

	// Insert transaction
	_, err = tx.Exec(`INSERT INTO transactions (
		id, wallet_id, user_id, admin_id, type, status, amount, currency,
		amount_usd, balance_before, balance_after, fee, gateway, gateway_tx_id,
		reference_id, description, meta_json, ip, created_at, completed_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		transaction.ID, transaction.WalletID, transaction.UserID, transaction.AdminID,
		transaction.Type, transaction.Status, transaction.Amount, transaction.Currency,
		transaction.AmountUSD, transaction.BalanceBefore, transaction.BalanceAfter,
		transaction.Fee, transaction.Gateway, transaction.GatewayTxID,
		transaction.ReferenceID, transaction.Description, "{}", transaction.IP,
		transaction.CreatedAt, transaction.CompletedAt,
	)
	if err != nil {
		return nil, err
	}

	// Update wallet
	_, err = tx.Exec(`UPDATE wallets SET 
		balance = balance + ?, 
		total_deposited = total_deposited + ?,
		updated_at = ? WHERE id = ?`,
		convertedAmount, convertedAmount, time.Now(), walletID)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	// Update cache
	wallet.Balance += convertedAmount
	wallet.TotalDeposited += convertedAmount
	wallet.UpdatedAt = time.Now()
	pm.walletCache.Store(walletID, wallet)

	pm.emitEvent("deposit_completed", wallet.UserID, wallet.AdminID, transaction)

	return transaction, nil
}

// Withdraw removes funds from wallet
func (pm *PaymentManager) Withdraw(walletID string, amount float64, description string) (*Transaction, error) {
	if amount <= 0 {
		return nil, errors.New("invalid withdraw amount")
	}

	wallet, err := pm.GetWallet(walletID)
	if err != nil {
		return nil, err
	}

	if !wallet.IsActive {
		return nil, errors.New("wallet is not active")
	}

	// Check balance
	if wallet.Balance < amount {
		return nil, errors.New("insufficient balance")
	}

	// Check limits
	if wallet.Limits.MaxWithdraw > 0 && amount > wallet.Limits.MaxWithdraw {
		return nil, fmt.Errorf("withdraw exceeds maximum limit of %.2f", wallet.Limits.MaxWithdraw)
	}

	if wallet.Limits.MinWithdraw > 0 && amount < wallet.Limits.MinWithdraw {
		return nil, fmt.Errorf("withdraw below minimum limit of %.2f", wallet.Limits.MinWithdraw)
	}

	// Check daily limit
	if wallet.Limits.DailyWithdrawLimit > 0 {
		dailyTotal, _ := pm.getDailyWithdrawTotal(walletID)
		if (dailyTotal + amount) > wallet.Limits.DailyWithdrawLimit {
			return nil, errors.New("daily withdraw limit exceeded")
		}
	}

	amountUSD, _ := pm.ConvertCurrency(amount, wallet.Currency, CurrencyUSD)

	tx, err := pm.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	transaction := &Transaction{
		ID:            uuid.New().String(),
		WalletID:      walletID,
		UserID:        wallet.UserID,
		AdminID:       wallet.AdminID,
		Type:          TxTypeWithdraw,
		Status:        TxStatusCompleted,
		Amount:        -amount,
		Currency:      wallet.Currency,
		AmountUSD:     -amountUSD,
		BalanceBefore: wallet.Balance,
		BalanceAfter:  wallet.Balance - amount,
		Description:   description,
		CreatedAt:     time.Now(),
	}

	now := time.Now()
	transaction.CompletedAt = &now

	_, err = tx.Exec(`INSERT INTO transactions (
		id, wallet_id, user_id, admin_id, type, status, amount, currency,
		amount_usd, balance_before, balance_after, description, created_at, completed_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		transaction.ID, transaction.WalletID, transaction.UserID, transaction.AdminID,
		transaction.Type, transaction.Status, transaction.Amount, transaction.Currency,
		transaction.AmountUSD, transaction.BalanceBefore, transaction.BalanceAfter,
		transaction.Description, transaction.CreatedAt, transaction.CompletedAt,
	)
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec(`UPDATE wallets SET 
		balance = balance - ?, 
		total_withdrawn = total_withdrawn + ?,
		updated_at = ? WHERE id = ?`,
		amount, amount, time.Now(), walletID)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	wallet.Balance -= amount
	wallet.TotalWithdrawn += amount
	wallet.UpdatedAt = time.Now()
	pm.walletCache.Store(walletID, wallet)

	pm.emitEvent("withdraw_completed", wallet.UserID, wallet.AdminID, transaction)

	return transaction, nil
}

// Transfer moves funds between wallets
func (pm *PaymentManager) Transfer(fromWalletID, toWalletID string, amount float64, description string) (*Transaction, *Transaction, error) {
	if fromWalletID == toWalletID {
		return nil, nil, errors.New("cannot transfer to same wallet")
	}

	fromWallet, err := pm.GetWallet(fromWalletID)
	if err != nil {
		return nil, nil, fmt.Errorf("source wallet error: %w", err)
	}

	toWallet, err := pm.GetWallet(toWalletID)
	if err != nil {
		return nil, nil, fmt.Errorf("destination wallet error: %w", err)
	}

	if fromWallet.Balance < amount {
		return nil, nil, errors.New("insufficient balance")
	}

	// Convert if different currencies
	toAmount := amount
	if fromWallet.Currency != toWallet.Currency {
		toAmount, err = pm.ConvertCurrency(amount, fromWallet.Currency, toWallet.Currency)
		if err != nil {
			return nil, nil, err
		}
	}

	tx, err := pm.db.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()

	now := time.Now()

	// From transaction
	fromTx := &Transaction{
		ID:            uuid.New().String(),
		WalletID:      fromWalletID,
		UserID:        fromWallet.UserID,
		AdminID:       fromWallet.AdminID,
		Type:          TxTypeTransfer,
		Status:        TxStatusCompleted,
		Amount:        -amount,
		Currency:      fromWallet.Currency,
		BalanceBefore: fromWallet.Balance,
		BalanceAfter:  fromWallet.Balance - amount,
		ReferenceID:   toWalletID,
		Description:   description,
		CreatedAt:     now,
		CompletedAt:   &now,
	}

	// To transaction
	toTx := &Transaction{
		ID:            uuid.New().String(),
		WalletID:      toWalletID,
		UserID:        toWallet.UserID,
		AdminID:       toWallet.AdminID,
		Type:          TxTypeTransfer,
		Status:        TxStatusCompleted,
		Amount:        toAmount,
		Currency:      toWallet.Currency,
		BalanceBefore: toWallet.Balance,
		BalanceAfter:  toWallet.Balance + toAmount,
		ReferenceID:   fromWalletID,
		Description:   description,
		CreatedAt:     now,
		CompletedAt:   &now,
	}

	// Insert transactions
	for _, t := range []*Transaction{fromTx, toTx} {
		_, err = tx.Exec(`INSERT INTO transactions (
			id, wallet_id, user_id, admin_id, type, status, amount, currency,
			balance_before, balance_after, reference_id, description, created_at, completed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			t.ID, t.WalletID, t.UserID, t.AdminID, t.Type, t.Status, t.Amount, t.Currency,
			t.BalanceBefore, t.BalanceAfter, t.ReferenceID, t.Description, t.CreatedAt, t.CompletedAt,
		)
		if err != nil {
			return nil, nil, err
		}
	}

	// Update wallets
	_, err = tx.Exec("UPDATE wallets SET balance = balance - ?, updated_at = ? WHERE id = ?",
		amount, now, fromWalletID)
	if err != nil {
		return nil, nil, err
	}

	_, err = tx.Exec("UPDATE wallets SET balance = balance + ?, updated_at = ? WHERE id = ?",
		toAmount, now, toWalletID)
	if err != nil {
		return nil, nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, nil, err
	}

	// Update cache
	fromWallet.Balance -= amount
	toWallet.Balance += toAmount
	pm.walletCache.Store(fromWalletID, fromWallet)
	pm.walletCache.Store(toWalletID, toWallet)

	pm.emitEvent("transfer_completed", fromWallet.UserID, fromWallet.AdminID, map[string]interface{}{
		"from_tx": fromTx,
		"to_tx":   toTx,
	})

	return fromTx, toTx, nil
}

// FreezeBalance freezes amount in wallet (for pending transactions)
func (pm *PaymentManager) FreezeBalance(walletID string, amount float64) error {
	wallet, err := pm.GetWallet(walletID)
	if err != nil {
		return err
	}

	availableBalance := wallet.Balance - wallet.FrozenBalance
	if availableBalance < amount {
		return errors.New("insufficient available balance")
	}

	_, err = pm.db.Exec("UPDATE wallets SET frozen_balance = frozen_balance + ?, updated_at = ? WHERE id = ?",
		amount, time.Now(), walletID)
	if err != nil {
		return err
	}

	wallet.FrozenBalance += amount
	pm.walletCache.Store(walletID, wallet)

	return nil
}

// UnfreezeBalance unfreezes amount in wallet
func (pm *PaymentManager) UnfreezeBalance(walletID string, amount float64) error {
	wallet, err := pm.GetWallet(walletID)
	if err != nil {
		return err
	}

	if wallet.FrozenBalance < amount {
		amount = wallet.FrozenBalance
	}

	_, err = pm.db.Exec("UPDATE wallets SET frozen_balance = frozen_balance - ?, updated_at = ? WHERE id = ?",
		amount, time.Now(), walletID)
	if err != nil {
		return err
	}

	wallet.FrozenBalance -= amount
	pm.walletCache.Store(walletID, wallet)

	return nil
}

// GetAvailableBalance returns available balance (total - frozen)
func (pm *PaymentManager) GetAvailableBalance(walletID string) (float64, error) {
	wallet, err := pm.GetWallet(walletID)
	if err != nil {
		return 0, err
	}
	return wallet.Balance - wallet.FrozenBalance, nil
}

// GetTransactionHistory retrieves transactions for a wallet
func (pm *PaymentManager) GetTransactionHistory(walletID string, limit, offset int, txType TransactionType) ([]*Transaction, int, error) {
	var transactions []*Transaction
	var total int

	// Count query
	countQuery := "SELECT COUNT(*) FROM transactions WHERE wallet_id = ?"
	args := []interface{}{walletID}

	if txType != "" {
		countQuery += " AND type = ?"
		args = append(args, txType)
	}

	pm.db.QueryRow(countQuery, args...).Scan(&total)

	// Data query
	query := `SELECT id, wallet_id, user_id, admin_id, type, status, amount, currency,
		amount_usd, balance_before, balance_after, fee, gateway, gateway_tx_id,
		reference_id, description, meta_json, ip, created_at, completed_at
		FROM transactions WHERE wallet_id = ?`

	if txType != "" {
		query += " AND type = ?"
	}

	query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := pm.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	for rows.Next() {
		tx := &Transaction{}
		var metaJSON string
		var completedAt sql.NullTime

		err := rows.Scan(
			&tx.ID, &tx.WalletID, &tx.UserID, &tx.AdminID, &tx.Type, &tx.Status,
			&tx.Amount, &tx.Currency, &tx.AmountUSD, &tx.BalanceBefore, &tx.BalanceAfter,
			&tx.Fee, &tx.Gateway, &tx.GatewayTxID, &tx.ReferenceID, &tx.Description,
			&metaJSON, &tx.IP, &tx.CreatedAt, &completedAt,
		)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(metaJSON), &tx.Meta)
		if completedAt.Valid {
			tx.CompletedAt = &completedAt.Time
		}

		transactions = append(transactions, tx)
	}

	return transactions, total, nil
}

// getDailyWithdrawTotal gets total withdraw for today
func (pm *PaymentManager) getDailyWithdrawTotal(walletID string) (float64, error) {
	var total float64
	today := time.Now().Truncate(24 * time.Hour)

	err := pm.db.QueryRow(`SELECT COALESCE(SUM(ABS(amount)), 0) FROM transactions 
		WHERE wallet_id = ? AND type = ? AND created_at >= ?`,
		walletID, TxTypeWithdraw, today).Scan(&total)

	return total, err
}

// ==================== Currency Operations ====================

// ConvertCurrency converts amount between currencies
func (pm *PaymentManager) ConvertCurrency(amount float64, from, to Currency) (float64, error) {
	if from == to {
		return amount, nil
	}

	rate, err := pm.GetExchangeRate(from, to)
	if err != nil {
		return 0, err
	}

	return amount * rate, nil
}

// GetExchangeRate retrieves exchange rate between currencies
func (pm *PaymentManager) GetExchangeRate(from, to Currency) (float64, error) {
	cacheKey := fmt.Sprintf("%s_%s", from, to)

	// Check cache
	if cached, ok := pm.rateCache.Load(cacheKey); ok {
		rate := cached.(*CurrencyRate)
		if time.Since(rate.UpdatedAt) < pm.config.RateUpdateInterval {
			return rate.Rate, nil
		}
	}

	// Get from database
	var rate float64
	var updatedAt time.Time

	err := pm.db.QueryRow(`SELECT rate, updated_at FROM currency_rates 
		WHERE from_currency = ? AND to_currency = ?`, from, to).Scan(&rate, &updatedAt)

	if err == nil && time.Since(updatedAt) < pm.config.RateUpdateInterval {
		pm.rateCache.Store(cacheKey, &CurrencyRate{
			FromCurrency: from,
			ToCurrency:   to,
			Rate:         rate,
			UpdatedAt:    updatedAt,
		})
		return rate, nil
	}

	// Fetch from API
	rate, err = pm.fetchExchangeRate(from, to)
	if err != nil {
		return 0, err
	}

	// Save to database
	pm.db.Exec(`INSERT OR REPLACE INTO currency_rates (from_currency, to_currency, rate, updated_at)
		VALUES (?, ?, ?, ?)`, from, to, rate, time.Now())

	pm.rateCache.Store(cacheKey, &CurrencyRate{
		FromCurrency: from,
		ToCurrency:   to,
		Rate:         rate,
		UpdatedAt:    time.Now(),
	})

	return rate, nil
}

// fetchExchangeRate fetches rate from external API
func (pm *PaymentManager) fetchExchangeRate(from, to Currency) (float64, error) {
	// Try multiple sources
	sources := []func(Currency, Currency) (float64, error){
		pm.fetchRateExchangeRateAPI,
		pm.fetchRateCoinGecko,
		pm.fetchRateNavasan, // For IRR
	}

	for _, source := range sources {
		rate, err := source(from, to)
		if err == nil && rate > 0 {
			return rate, nil
		}
	}

	return 0, errors.New("failed to fetch exchange rate")
}

// fetchRateExchangeRateAPI fetches from exchangerate-api.com
func (pm *PaymentManager) fetchRateExchangeRateAPI(from, to Currency) (float64, error) {
	// Skip crypto currencies
	if isCrypto(from) || isCrypto(to) {
		return 0, errors.New("not supported")
	}

	url := fmt.Sprintf("https://api.exchangerate-api.com/v4/latest/%s", from)

	resp, err := http.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var result struct {
		Rates map[string]float64 `json:"rates"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	rate, ok := result.Rates[string(to)]
	if !ok {
		return 0, errors.New("currency not found")
	}

	return rate, nil
}

// fetchRateCoinGecko fetches crypto rates from CoinGecko
func (pm *PaymentManager) fetchRateCoinGecko(from, to Currency) (float64, error) {
	if !isCrypto(from) && !isCrypto(to) {
		return 0, errors.New("not crypto")
	}

	coinID := cryptoCoinID(from)
	if coinID == "" {
		return 0, errors.New("unknown crypto")
	}

	url := fmt.Sprintf("https://api.coingecko.com/api/v3/simple/price?ids=%s&vs_currencies=%s",
		coinID, strings.ToLower(string(to)))

	resp, err := http.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var result map[string]map[string]float64
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	if rates, ok := result[coinID]; ok {
		if rate, ok := rates[strings.ToLower(string(to))]; ok {
			return rate, nil
		}
	}

	return 0, errors.New("rate not found")
}

// fetchRateNavasan fetches IRR rates from navasan.tech
func (pm *PaymentManager) fetchRateNavasan(from, to Currency) (float64, error) {
	if from != CurrencyIRR && to != CurrencyIRR {
		return 0, errors.New("not IRR")
	}

	url := "https://api.navasan.tech/latest/?api_key=" + pm.config.RateAPIKey

	resp, err := http.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var result map[string]struct {
		Value float64 `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	// Handle conversion logic
	// This is simplified - real implementation would be more complex
	if to == CurrencyIRR {
		if rate, ok := result[strings.ToLower(string(from))]; ok {
			return rate.Value, nil
		}
	} else {
		if rate, ok := result[strings.ToLower(string(to))]; ok {
			return 1 / rate.Value, nil
		}
	}

	return 0, errors.New("rate not found")
}

// isCrypto checks if currency is cryptocurrency
func isCrypto(c Currency) bool {
	cryptos := map[Currency]bool{
		CurrencyBTC:  true,
		CurrencyETH:  true,
		CurrencyUSDT: true,
		CurrencyTRX:  true,
	}
	return cryptos[c]
}

// cryptoCoinID returns CoinGecko coin ID
func cryptoCoinID(c Currency) string {
	ids := map[Currency]string{
		CurrencyBTC:  "bitcoin",
		CurrencyETH:  "ethereum",
		CurrencyUSDT: "tether",
		CurrencyTRX:  "tron",
	}
	return ids[c]
}

// GetAllRates retrieves all exchange rates
func (pm *PaymentManager) GetAllRates() (map[string]float64, error) {
	rates := make(map[string]float64)

	rows, err := pm.db.Query("SELECT from_currency, to_currency, rate FROM currency_rates")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var from, to Currency
		var rate float64
		rows.Scan(&from, &to, &rate)
		rates[fmt.Sprintf("%s_%s", from, to)] = rate
	}

	return rates, nil
}

// UpdateAllRates updates all currency rates
func (pm *PaymentManager) UpdateAllRates() error {
	currencies := pm.config.SupportedCurrencies
	baseCurrency := pm.config.DefaultCurrency

	for _, currency := range currencies {
		if currency == baseCurrency {
			continue
		}

		// Base to currency
		rate, err := pm.fetchExchangeRate(baseCurrency, currency)
		if err == nil {
			pm.db.Exec(`INSERT OR REPLACE INTO currency_rates 
				(from_currency, to_currency, rate, updated_at) VALUES (?, ?, ?, ?)`,
				baseCurrency, currency, rate, time.Now())

			// Reverse rate
			pm.db.Exec(`INSERT OR REPLACE INTO currency_rates 
				(from_currency, to_currency, rate, updated_at) VALUES (?, ?, ?, ?)`,
				currency, baseCurrency, 1/rate, time.Now())
		}
	}

	return nil
}

// FormatCurrency formats amount with currency symbol
func FormatCurrency(amount float64, currency Currency) string {
	symbols := map[Currency]string{
		CurrencyUSD:  "$",
		CurrencyEUR:  "â‚¬",
		CurrencyGBP:  "Â£",
		CurrencyIRR:  "ï·¼",
		CurrencyTRY:  "â‚º",
		CurrencyRUB:  "â‚½",
		CurrencyCNY:  "Â¥",
		CurrencyAED:  "Ø¯.Ø¥",
		CurrencyBTC:  "â‚¿",
		CurrencyETH:  "Îž",
		CurrencyUSDT: "â‚®",
		CurrencyTRX:  "TRX",
	}

	symbol := symbols[currency]
	if symbol == "" {
		symbol = string(currency)
	}

	// Format based on currency
	var formatted string
	switch currency {
	case CurrencyBTC, CurrencyETH:
		formatted = fmt.Sprintf("%.8f", amount)
	case CurrencyIRR:
		formatted = fmt.Sprintf("%.0f", amount)
	default:
		formatted = fmt.Sprintf("%.2f", amount)
	}

	return symbol + " " + formatted
}

// RoundCurrency rounds amount based on currency precision
func RoundCurrency(amount float64, currency Currency) float64 {
	precision := map[Currency]int{
		CurrencyBTC:  8,
		CurrencyETH:  8,
		CurrencyUSDT: 2,
		CurrencyIRR:  0,
		CurrencyUSD:  2,
		CurrencyEUR:  2,
	}

	p := precision[currency]
	if p == 0 {
		p = 2
	}

	multiplier := math.Pow(10, float64(p))
	return math.Round(amount*multiplier) / multiplier
}

// ==================== Background Workers ====================

// eventProcessor processes payment events
func (pm *PaymentManager) eventProcessor() {
	for {
		select {
		case <-pm.ctx.Done():
			return
		case event := <-pm.eventChan:
			pm.processEvent(event)
		}
	}
}

// processEvent handles a single payment event
func (pm *PaymentManager) processEvent(event PaymentEvent) {
	// Log event
	logData, _ := json.Marshal(event)
	pm.db.Exec(`INSERT INTO payment_events (type, user_id, admin_id, data, timestamp)
		VALUES (?, ?, ?, ?, ?)`,
		event.Type, event.UserID, event.AdminID, string(logData), event.Timestamp)

	// Handle specific events
	switch event.Type {
	case "deposit_completed":
		// Notify via Telegram
		// pm.notifyTelegram(event)
	case "purchase_completed":
		// Activate subscription
		// pm.activateSubscription(event)
	case "invoice_expired":
		// Cancel pending invoice
		// pm.cancelInvoice(event)
	}
}

// rateUpdater periodically updates exchange rates
func (pm *PaymentManager) rateUpdater() {
	ticker := time.NewTicker(pm.config.RateUpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.UpdateAllRates()
		}
	}
}

// invoiceExpiryChecker checks for expired invoices
func (pm *PaymentManager) invoiceExpiryChecker() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.expireOldInvoices()
		}
	}
}

// expireOldInvoices marks old pending invoices as expired
func (pm *PaymentManager) expireOldInvoices() {
	result, _ := pm.db.Exec(`UPDATE invoices SET status = ?, updated_at = ?
		WHERE status = ? AND due_date < ?`,
		InvoiceStatusExpired, time.Now(), InvoiceStatusPending, time.Now())

	if affected, _ := result.RowsAffected(); affected > 0 {
		pm.emitEvent("invoices_expired", "", "", map[string]int64{"count": affected})
	}
}

// emitEvent sends event to processor
func (pm *PaymentManager) emitEvent(eventType, userID, adminID string, data interface{}) {
	select {
	case pm.eventChan <- PaymentEvent{
		Type:      eventType,
		UserID:    userID,
		AdminID:   adminID,
		Data:      data,
		Timestamp: time.Now(),
	}:
	default:
		// Channel full, log error
	}
}

// ==================== Helper Functions ====================

// GenerateInvoiceNumber generates unique invoice number
func (pm *PaymentManager) GenerateInvoiceNumber() string {
	prefix := pm.config.InvoicePrefix
	if prefix == "" {
		prefix = "INV"
	}

	timestamp := time.Now().Format("20060102")
	random := uuid.New().String()[:6]

	return fmt.Sprintf("%s-%s-%s", prefix, timestamp, strings.ToUpper(random))
}

// ValidateSignature validates payment gateway signature
func ValidateSignature(payload string, signature string, secret string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expected))
}

// GetCurrencyInfo returns currency details
func GetCurrencyInfo(currency Currency) map[string]interface{} {
	info := map[Currency]map[string]interface{}{
		CurrencyUSD:  {"name": "US Dollar", "symbol": "$", "decimal": 2, "crypto": false},
		CurrencyEUR:  {"name": "Euro", "symbol": "â‚¬", "decimal": 2, "crypto": false},
		CurrencyGBP:  {"name": "British Pound", "symbol": "Â£", "decimal": 2, "crypto": false},
		CurrencyIRR:  {"name": "Iranian Rial", "symbol": "ï·¼", "decimal": 0, "crypto": false},
		CurrencyTRY:  {"name": "Turkish Lira", "symbol": "â‚º", "decimal": 2, "crypto": false},
		CurrencyRUB:  {"name": "Russian Ruble", "symbol": "â‚½", "decimal": 2, "crypto": false},
		CurrencyCNY:  {"name": "Chinese Yuan", "symbol": "Â¥", "decimal": 2, "crypto": false},
		CurrencyAED:  {"name": "UAE Dirham", "symbol": "Ø¯.Ø¥", "decimal": 2, "crypto": false},
		CurrencyBTC:  {"name": "Bitcoin", "symbol": "â‚¿", "decimal": 8, "crypto": true},
		CurrencyETH:  {"name": "Ethereum", "symbol": "Îž", "decimal": 8, "crypto": true},
		CurrencyUSDT: {"name": "Tether", "symbol": "â‚®", "decimal": 2, "crypto": true},
		CurrencyTRX:  {"name": "Tron", "symbol": "TRX", "decimal": 6, "crypto": true},
	}

	if i, ok := info[currency]; ok {
		return i
	}
	return map[string]interface{}{"name": string(currency), "symbol": string(currency), "decimal": 2, "crypto": false}
}

// GetSupportedCurrencies returns list of supported currencies
func (pm *PaymentManager) GetSupportedCurrencies() []map[string]interface{} {
	var currencies []map[string]interface{}

	for _, c := range pm.config.SupportedCurrencies {
		info := GetCurrencyInfo(c)
		info["code"] = string(c)
		currencies = append(currencies, info)
	}

	return currencies
}

// ==================== Database Schema ====================

// InitPaymentTables creates payment-related database tables
func InitPaymentTables(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS wallets (
			id TEXT PRIMARY KEY,
			user_id TEXT,
			admin_id TEXT,
			balance REAL DEFAULT 0,
			currency TEXT DEFAULT 'USD',
			frozen_balance REAL DEFAULT 0,
			total_deposited REAL DEFAULT 0,
			total_withdrawn REAL DEFAULT 0,
			total_spent REAL DEFAULT 0,
			total_earned REAL DEFAULT 0,
			is_active INTEGER DEFAULT 1,
			limits_json TEXT DEFAULT '{}',
			meta_json TEXT DEFAULT '{}',
			created_at DATETIME,
			updated_at DATETIME,
			UNIQUE(user_id),
			UNIQUE(admin_id)
		)`,

		`CREATE TABLE IF NOT EXISTS transactions (
			id TEXT PRIMARY KEY,
			wallet_id TEXT NOT NULL,
			user_id TEXT,
			admin_id TEXT,
			type TEXT NOT NULL,
			status TEXT NOT NULL,
			amount REAL NOT NULL,
			currency TEXT NOT NULL,
			amount_usd REAL DEFAULT 0,
			balance_before REAL DEFAULT 0,
			balance_after REAL DEFAULT 0,
			fee REAL DEFAULT 0,
			gateway TEXT,
			gateway_tx_id TEXT,
			reference_id TEXT,
			description TEXT,
			meta_json TEXT DEFAULT '{}',
			ip TEXT,
			created_at DATETIME,
			completed_at DATETIME,
			FOREIGN KEY (wallet_id) REFERENCES wallets(id)
		)`,

		`CREATE TABLE IF NOT EXISTS invoices (
			id TEXT PRIMARY KEY,
			invoice_number TEXT UNIQUE,
			user_id TEXT NOT NULL,
			admin_id TEXT,
			status TEXT NOT NULL,
			items_json TEXT DEFAULT '[]',
			subtotal REAL DEFAULT 0,
			discount REAL DEFAULT 0,
			discount_code TEXT,
			tax REAL DEFAULT 0,
			tax_rate REAL DEFAULT 0,
			total REAL NOT NULL,
			paid_amount REAL DEFAULT 0,
			currency TEXT NOT NULL,
			gateway TEXT,
			gateway_data_json TEXT DEFAULT '{}',
			payment_url TEXT,
			notes TEXT,
			due_date DATETIME,
			paid_at DATETIME,
			meta_json TEXT DEFAULT '{}',
			created_at DATETIME,
			updated_at DATETIME
		)`,

		`CREATE TABLE IF NOT EXISTS subscription_plans (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			name_fa TEXT,
			description TEXT,
			description_fa TEXT,
			duration TEXT NOT NULL,
			duration_days INTEGER NOT NULL,
			traffic_gb INTEGER DEFAULT 0,
			device_limit INTEGER DEFAULT 1,
			concurrent_limit INTEGER DEFAULT 1,
			protocols_json TEXT DEFAULT '[]',
			nodes_json TEXT DEFAULT '[]',
			prices_json TEXT NOT NULL,
			original_prices_json TEXT,
			features_json TEXT DEFAULT '[]',
			features_fa_json TEXT DEFAULT '[]',
			is_active INTEGER DEFAULT 1,
			is_popular INTEGER DEFAULT 0,
			is_trial INTEGER DEFAULT 0,
			trial_once INTEGER DEFAULT 1,
			sort_order INTEGER DEFAULT 0,
			admin_id TEXT,
			meta_json TEXT DEFAULT '{}',
			created_at DATETIME,
			updated_at DATETIME
		)`,

		`CREATE TABLE IF NOT EXISTS discount_codes (
			id TEXT PRIMARY KEY,
			code TEXT UNIQUE NOT NULL,
			description TEXT,
			type TEXT NOT NULL,
			value REAL NOT NULL,
			currency TEXT,
			min_purchase REAL DEFAULT 0,
			max_discount REAL DEFAULT 0,
			usage_limit INTEGER DEFAULT 0,
			usage_count INTEGER DEFAULT 0,
			per_user_limit INTEGER DEFAULT 0,
			applicable_plans_json TEXT DEFAULT '[]',
			admin_id TEXT,
			is_active INTEGER DEFAULT 1,
			starts_at DATETIME,
			expires_at DATETIME,
			created_at DATETIME
		)`,

		`CREATE TABLE IF NOT EXISTS discount_usage (
			id TEXT PRIMARY KEY,
			discount_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			invoice_id TEXT,
			amount REAL NOT NULL,
			used_at DATETIME,
			FOREIGN KEY (discount_id) REFERENCES discount_codes(id)
		)`,

		`CREATE TABLE IF NOT EXISTS currency_rates (
			from_currency TEXT NOT NULL,
			to_currency TEXT NOT NULL,
			rate REAL NOT NULL,
			source TEXT,
			updated_at DATETIME,
			PRIMARY KEY (from_currency, to_currency)
		)`,

		`CREATE TABLE IF NOT EXISTS payment_gateways (
			gateway TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			is_active INTEGER DEFAULT 0,
			currencies_json TEXT DEFAULT '[]',
			min_amount REAL DEFAULT 0,
			max_amount REAL DEFAULT 0,
			fee REAL DEFAULT 0,
			fixed_fee REAL DEFAULT 0,
			config_json TEXT DEFAULT '{}',
			webhook_url TEXT,
			callback_url TEXT,
			sort_order INTEGER DEFAULT 0,
			meta_json TEXT DEFAULT '{}'
		)`,

		`CREATE TABLE IF NOT EXISTS payment_sessions (
			id TEXT PRIMARY KEY,
			invoice_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			gateway TEXT NOT NULL,
			amount REAL NOT NULL,
			currency TEXT NOT NULL,
			status TEXT NOT NULL,
			payment_url TEXT,
			gateway_data_json TEXT DEFAULT '{}',
			ip TEXT,
			user_agent TEXT,
			expires_at DATETIME,
			created_at DATETIME,
			FOREIGN KEY (invoice_id) REFERENCES invoices(id)
		)`,

		`CREATE TABLE IF NOT EXISTS commission_rules (
			id TEXT PRIMARY KEY,
			admin_id TEXT NOT NULL,
			type TEXT NOT NULL,
			value REAL NOT NULL,
			plan_id TEXT,
			min_sales INTEGER DEFAULT 0,
			is_active INTEGER DEFAULT 1,
			created_at DATETIME
		)`,

		`CREATE TABLE IF NOT EXISTS payment_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			type TEXT NOT NULL,
			user_id TEXT,
			admin_id TEXT,
			data TEXT,
			timestamp DATETIME
		)`,

		// Indexes
		`CREATE INDEX IF NOT EXISTS idx_transactions_wallet ON transactions(wallet_id)`,
		`CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_transactions_created ON transactions(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_invoices_user ON invoices(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_invoices_status ON invoices(status)`,
		`CREATE INDEX IF NOT EXISTS idx_invoices_due ON invoices(due_date)`,
		`CREATE INDEX IF NOT EXISTS idx_plans_active ON subscription_plans(is_active)`,
		`CREATE INDEX IF NOT EXISTS idx_discount_code ON discount_codes(code)`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %w", err)
		}
	}

	return nil
}

// ==================== Wallet Statistics ====================

// WalletStats represents wallet statistics
type WalletStats struct {
	TotalBalance     float64  `json:"total_balance"`
	TotalDeposits    float64  `json:"total_deposits"`
	TotalWithdrawals float64  `json:"total_withdrawals"`
	TotalSpent       float64  `json:"total_spent"`
	TotalEarned      float64  `json:"total_earned"`
	TransactionCount int      `json:"transaction_count"`
	Currency         Currency `json:"currency"`
}

// GetWalletStats retrieves wallet statistics
func (pm *PaymentManager) GetWalletStats(walletID string) (*WalletStats, error) {
	wallet, err := pm.GetWallet(walletID)
	if err != nil {
		return nil, err
	}

	var txCount int
	pm.db.QueryRow("SELECT COUNT(*) FROM transactions WHERE wallet_id = ?", walletID).Scan(&txCount)

	return &WalletStats{
		TotalBalance:     wallet.Balance,
		TotalDeposits:    wallet.TotalDeposited,
		TotalWithdrawals: wallet.TotalWithdrawn,
		TotalSpent:       wallet.TotalSpent,
		TotalEarned:      wallet.TotalEarned,
		TransactionCount: txCount,
		Currency:         wallet.Currency,
	}, nil
}

// GetAllWallets retrieves all wallets with pagination
func (pm *PaymentManager) GetAllWallets(limit, offset int, currency Currency, minBalance float64) ([]*Wallet, int, error) {
	var wallets []*Wallet
	var total int

	// Build query
	countQuery := "SELECT COUNT(*) FROM wallets WHERE 1=1"
	query := `SELECT id, user_id, admin_id, balance, currency, frozen_balance,
		total_deposited, total_withdrawn, total_spent, total_earned,
		is_active, limits_json, meta_json, created_at, updated_at
		FROM wallets WHERE 1=1`

	var args []interface{}

	if currency != "" {
		countQuery += " AND currency = ?"
		query += " AND currency = ?"
		args = append(args, currency)
	}

	if minBalance > 0 {
		countQuery += " AND balance >= ?"
		query += " AND balance >= ?"
		args = append(args, minBalance)
	}

	// Count
	pm.db.QueryRow(countQuery, args...).Scan(&total)

	// Get data
	query += " ORDER BY balance DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := pm.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	for rows.Next() {
		wallet := &Wallet{}
		var limitsJSON, metaJSON string

		err := rows.Scan(
			&wallet.ID, &wallet.UserID, &wallet.AdminID, &wallet.Balance, &wallet.Currency,
			&wallet.FrozenBalance, &wallet.TotalDeposited, &wallet.TotalWithdrawn,
			&wallet.TotalSpent, &wallet.TotalEarned, &wallet.IsActive,
			&limitsJSON, &metaJSON, &wallet.CreatedAt, &wallet.UpdatedAt,
		)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(limitsJSON), &wallet.Limits)
		json.Unmarshal([]byte(metaJSON), &wallet.Meta)

		wallets = append(wallets, wallet)
	}

	return wallets, total, nil
}

// GetTopWalletsByBalance returns wallets with highest balance
func (pm *PaymentManager) GetTopWalletsByBalance(limit int) ([]*Wallet, error) {
	wallets, _, err := pm.GetAllWallets(limit, 0, "", 0)
	return wallets, err
}

// ==================== Wallet Limits Management ====================

// UpdateWalletLimits updates wallet limits
func (pm *PaymentManager) UpdateWalletLimits(walletID string, limits WalletLimits) error {
	limitsJSON, err := json.Marshal(limits)
	if err != nil {
		return err
	}

	_, err = pm.db.Exec("UPDATE wallets SET limits_json = ?, updated_at = ? WHERE id = ?",
		string(limitsJSON), time.Now(), walletID)
	if err != nil {
		return err
	}

	// Update cache
	if wallet, err := pm.GetWallet(walletID); err == nil {
		wallet.Limits = limits
		pm.walletCache.Store(walletID, wallet)
	}

	return nil
}

// SetDefaultLimits sets default limits for new wallets
func (pm *PaymentManager) SetDefaultLimits(limits WalletLimits) {
	pm.mu.Lock()
	pm.config.DefaultLimits = limits
	pm.mu.Unlock()
}

// ==================== Bonus & Adjustment ====================

// AddBonus adds bonus amount to wallet
func (pm *PaymentManager) AddBonus(walletID string, amount float64, description string) (*Transaction, error) {
	wallet, err := pm.GetWallet(walletID)
	if err != nil {
		return nil, err
	}

	tx, err := pm.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	now := time.Now()
	transaction := &Transaction{
		ID:            uuid.New().String(),
		WalletID:      walletID,
		UserID:        wallet.UserID,
		AdminID:       wallet.AdminID,
		Type:          TxTypeBonus,
		Status:        TxStatusCompleted,
		Amount:        amount,
		Currency:      wallet.Currency,
		BalanceBefore: wallet.Balance,
		BalanceAfter:  wallet.Balance + amount,
		Description:   description,
		CreatedAt:     now,
		CompletedAt:   &now,
	}

	_, err = tx.Exec(`INSERT INTO transactions (
		id, wallet_id, user_id, admin_id, type, status, amount, currency,
		balance_before, balance_after, description, created_at, completed_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		transaction.ID, transaction.WalletID, transaction.UserID, transaction.AdminID,
		transaction.Type, transaction.Status, transaction.Amount, transaction.Currency,
		transaction.BalanceBefore, transaction.BalanceAfter, transaction.Description,
		transaction.CreatedAt, transaction.CompletedAt,
	)
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec("UPDATE wallets SET balance = balance + ?, updated_at = ? WHERE id = ?",
		amount, now, walletID)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	wallet.Balance += amount
	pm.walletCache.Store(walletID, wallet)

	pm.emitEvent("bonus_added", wallet.UserID, wallet.AdminID, transaction)

	return transaction, nil
}

// AdjustBalance manually adjusts wallet balance (admin only)
func (pm *PaymentManager) AdjustBalance(walletID string, amount float64, reason string, adminID string) (*Transaction, error) {
	wallet, err := pm.GetWallet(walletID)
	if err != nil {
		return nil, err
	}

	newBalance := wallet.Balance + amount
	if newBalance < 0 {
		return nil, errors.New("adjustment would result in negative balance")
	}

	tx, err := pm.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	now := time.Now()
	transaction := &Transaction{
		ID:            uuid.New().String(),
		WalletID:      walletID,
		UserID:        wallet.UserID,
		AdminID:       adminID,
		Type:          TxTypeAdjustment,
		Status:        TxStatusCompleted,
		Amount:        amount,
		Currency:      wallet.Currency,
		BalanceBefore: wallet.Balance,
		BalanceAfter:  newBalance,
		Description:   reason,
		CreatedAt:     now,
		CompletedAt:   &now,
	}

	_, err = tx.Exec(`INSERT INTO transactions (
		id, wallet_id, user_id, admin_id, type, status, amount, currency,
		balance_before, balance_after, description, created_at, completed_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		transaction.ID, transaction.WalletID, transaction.UserID, transaction.AdminID,
		transaction.Type, transaction.Status, transaction.Amount, transaction.Currency,
		transaction.BalanceBefore, transaction.BalanceAfter, transaction.Description,
		transaction.CreatedAt, transaction.CompletedAt,
	)
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec("UPDATE wallets SET balance = ?, updated_at = ? WHERE id = ?",
		newBalance, now, walletID)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	wallet.Balance = newBalance
	pm.walletCache.Store(walletID, wallet)

	pm.emitEvent("balance_adjusted", wallet.UserID, adminID, transaction)

	return transaction, nil
}

// ==================== Transaction Search ====================

// TransactionFilter for searching transactions
type TransactionFilter struct {
	WalletID  string            `json:"wallet_id,omitempty"`
	UserID    string            `json:"user_id,omitempty"`
	AdminID   string            `json:"admin_id,omitempty"`
	Type      TransactionType   `json:"type,omitempty"`
	Status    TransactionStatus `json:"status,omitempty"`
	Gateway   PaymentGateway    `json:"gateway,omitempty"`
	Currency  Currency          `json:"currency,omitempty"`
	MinAmount float64           `json:"min_amount,omitempty"`
	MaxAmount float64           `json:"max_amount,omitempty"`
	FromDate  time.Time         `json:"from_date,omitempty"`
	ToDate    time.Time         `json:"to_date,omitempty"`
	Limit     int               `json:"limit,omitempty"`
	Offset    int               `json:"offset,omitempty"`
	SortBy    string            `json:"sort_by,omitempty"`
	SortOrder string            `json:"sort_order,omitempty"`
}

// SearchTransactions searches transactions with filters
func (pm *PaymentManager) SearchTransactions(filter TransactionFilter) ([]*Transaction, int, error) {
	var transactions []*Transaction
	var args []interface{}

	whereClause := "WHERE 1=1"

	if filter.WalletID != "" {
		whereClause += " AND wallet_id = ?"
		args = append(args, filter.WalletID)
	}
	if filter.UserID != "" {
		whereClause += " AND user_id = ?"
		args = append(args, filter.UserID)
	}
	if filter.AdminID != "" {
		whereClause += " AND admin_id = ?"
		args = append(args, filter.AdminID)
	}
	if filter.Type != "" {
		whereClause += " AND type = ?"
		args = append(args, filter.Type)
	}
	if filter.Status != "" {
		whereClause += " AND status = ?"
		args = append(args, filter.Status)
	}
	if filter.Gateway != "" {
		whereClause += " AND gateway = ?"
		args = append(args, filter.Gateway)
	}
	if filter.Currency != "" {
		whereClause += " AND currency = ?"
		args = append(args, filter.Currency)
	}
	if filter.MinAmount > 0 {
		whereClause += " AND ABS(amount) >= ?"
		args = append(args, filter.MinAmount)
	}
	if filter.MaxAmount > 0 {
		whereClause += " AND ABS(amount) <= ?"
		args = append(args, filter.MaxAmount)
	}
	if !filter.FromDate.IsZero() {
		whereClause += " AND created_at >= ?"
		args = append(args, filter.FromDate)
	}
	if !filter.ToDate.IsZero() {
		whereClause += " AND created_at <= ?"
		args = append(args, filter.ToDate)
	}

	// Count
	var total int
	pm.db.QueryRow("SELECT COUNT(*) FROM transactions "+whereClause, args...).Scan(&total)

	// Sort
	sortBy := "created_at"
	if filter.SortBy != "" {
		sortBy = filter.SortBy
	}
	sortOrder := "DESC"
	if filter.SortOrder == "asc" {
		sortOrder = "ASC"
	}

	// Limit
	limit := 50
	if filter.Limit > 0 && filter.Limit <= 200 {
		limit = filter.Limit
	}

	query := fmt.Sprintf(`SELECT id, wallet_id, user_id, admin_id, type, status,
		amount, currency, amount_usd, balance_before, balance_after, fee,
		gateway, gateway_tx_id, reference_id, description, meta_json, ip,
		created_at, completed_at
		FROM transactions %s ORDER BY %s %s LIMIT ? OFFSET ?`,
		whereClause, sortBy, sortOrder)

	args = append(args, limit, filter.Offset)

	rows, err := pm.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	for rows.Next() {
		tx := &Transaction{}
		var metaJSON string
		var completedAt sql.NullTime

		err := rows.Scan(
			&tx.ID, &tx.WalletID, &tx.UserID, &tx.AdminID, &tx.Type, &tx.Status,
			&tx.Amount, &tx.Currency, &tx.AmountUSD, &tx.BalanceBefore, &tx.BalanceAfter,
			&tx.Fee, &tx.Gateway, &tx.GatewayTxID, &tx.ReferenceID, &tx.Description,
			&metaJSON, &tx.IP, &tx.CreatedAt, &completedAt,
		)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(metaJSON), &tx.Meta)
		if completedAt.Valid {
			tx.CompletedAt = &completedAt.Time
		}

		transactions = append(transactions, tx)
	}

	return transactions, total, nil
}

// GetTransaction retrieves single transaction by ID
func (pm *PaymentManager) GetTransaction(transactionID string) (*Transaction, error) {
	tx := &Transaction{}
	var metaJSON string
	var completedAt sql.NullTime

	err := pm.db.QueryRow(`SELECT id, wallet_id, user_id, admin_id, type, status,
		amount, currency, amount_usd, balance_before, balance_after, fee,
		gateway, gateway_tx_id, reference_id, description, meta_json, ip,
		created_at, completed_at
		FROM transactions WHERE id = ?`, transactionID).Scan(
		&tx.ID, &tx.WalletID, &tx.UserID, &tx.AdminID, &tx.Type, &tx.Status,
		&tx.Amount, &tx.Currency, &tx.AmountUSD, &tx.BalanceBefore, &tx.BalanceAfter,
		&tx.Fee, &tx.Gateway, &tx.GatewayTxID, &tx.ReferenceID, &tx.Description,
		&metaJSON, &tx.IP, &tx.CreatedAt, &completedAt,
	)

	if err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(metaJSON), &tx.Meta)
	if completedAt.Valid {
		tx.CompletedAt = &completedAt.Time
	}

	return tx, nil
}

// Core/payment.go
// MXUI VPN Panel - Payment & Financial System
// Part 2: Invoice System, Subscription Plans, Discount Codes, Commission

// ==================== Invoice System ====================

// CreateInvoice creates a new invoice
func (pm *PaymentManager) CreateInvoice(userID string, items []InvoiceItem, currency Currency, adminID string) (*Invoice, error) {
	if len(items) == 0 {
		return nil, errors.New("invoice must have at least one item")
	}

	// Calculate totals
	var subtotal float64
	for i := range items {
		items[i].ID = uuid.New().String()
		items[i].Total = float64(items[i].Quantity) * items[i].UnitPrice
		subtotal += items[i].Total
	}

	// Calculate tax if enabled
	var tax float64
	if pm.config.TaxEnabled && pm.config.TaxRate > 0 {
		tax = subtotal * (pm.config.TaxRate / 100)
	}

	total := subtotal + tax

	invoice := &Invoice{
		ID:            uuid.New().String(),
		InvoiceNumber: pm.GenerateInvoiceNumber(),
		UserID:        userID,
		AdminID:       adminID,
		Status:        InvoiceStatusPending,
		Items:         items,
		Subtotal:      subtotal,
		Discount:      0,
		Tax:           tax,
		TaxRate:       pm.config.TaxRate,
		Total:         total,
		PaidAmount:    0,
		Currency:      currency,
		DueDate:       time.Now().Add(pm.config.InvoiceExpiry),
		Meta:          make(map[string]interface{}),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	itemsJSON, _ := json.Marshal(invoice.Items)
	metaJSON, _ := json.Marshal(invoice.Meta)
	gatewayDataJSON, _ := json.Marshal(invoice.GatewayData)

	_, err := pm.db.Exec(`INSERT INTO invoices (
		id, invoice_number, user_id, admin_id, status, items_json,
		subtotal, discount, discount_code, tax, tax_rate, total, paid_amount,
		currency, gateway, gateway_data_json, payment_url, notes, due_date,
		paid_at, meta_json, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		invoice.ID, invoice.InvoiceNumber, invoice.UserID, invoice.AdminID,
		invoice.Status, string(itemsJSON), invoice.Subtotal, invoice.Discount,
		invoice.DiscountCode, invoice.Tax, invoice.TaxRate, invoice.Total,
		invoice.PaidAmount, invoice.Currency, invoice.Gateway,
		string(gatewayDataJSON), invoice.PaymentURL, invoice.Notes,
		invoice.DueDate, invoice.PaidAt, string(metaJSON),
		invoice.CreatedAt, invoice.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create invoice: %w", err)
	}

	pm.emitEvent("invoice_created", userID, adminID, invoice)

	return invoice, nil
}

// GetInvoice retrieves invoice by ID
func (pm *PaymentManager) GetInvoice(invoiceID string) (*Invoice, error) {
	invoice := &Invoice{}
	var itemsJSON, metaJSON, gatewayDataJSON string
	var paidAt sql.NullTime

	err := pm.db.QueryRow(`SELECT 
		id, invoice_number, user_id, admin_id, status, items_json,
		subtotal, discount, discount_code, tax, tax_rate, total, paid_amount,
		currency, gateway, gateway_data_json, payment_url, notes, due_date,
		paid_at, meta_json, created_at, updated_at
		FROM invoices WHERE id = ?`, invoiceID).Scan(
		&invoice.ID, &invoice.InvoiceNumber, &invoice.UserID, &invoice.AdminID,
		&invoice.Status, &itemsJSON, &invoice.Subtotal, &invoice.Discount,
		&invoice.DiscountCode, &invoice.Tax, &invoice.TaxRate, &invoice.Total,
		&invoice.PaidAmount, &invoice.Currency, &invoice.Gateway,
		&gatewayDataJSON, &invoice.PaymentURL, &invoice.Notes,
		&invoice.DueDate, &paidAt, &metaJSON,
		&invoice.CreatedAt, &invoice.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("invoice not found: %w", err)
	}

	json.Unmarshal([]byte(itemsJSON), &invoice.Items)
	json.Unmarshal([]byte(metaJSON), &invoice.Meta)
	json.Unmarshal([]byte(gatewayDataJSON), &invoice.GatewayData)

	if paidAt.Valid {
		invoice.PaidAt = &paidAt.Time
	}

	return invoice, nil
}

// GetInvoiceByNumber retrieves invoice by invoice number
func (pm *PaymentManager) GetInvoiceByNumber(invoiceNumber string) (*Invoice, error) {
	var invoiceID string
	err := pm.db.QueryRow("SELECT id FROM invoices WHERE invoice_number = ?", invoiceNumber).Scan(&invoiceID)
	if err != nil {
		return nil, err
	}
	return pm.GetInvoice(invoiceID)
}

// UpdateInvoiceStatus updates invoice status
func (pm *PaymentManager) UpdateInvoiceStatus(invoiceID string, status InvoiceStatus) error {
	_, err := pm.db.Exec("UPDATE invoices SET status = ?, updated_at = ? WHERE id = ?",
		status, time.Now(), invoiceID)
	return err
}

// ApplyDiscountToInvoice applies a discount code to invoice
func (pm *PaymentManager) ApplyDiscountToInvoice(invoiceID, discountCode string) (*Invoice, error) {
	invoice, err := pm.GetInvoice(invoiceID)
	if err != nil {
		return nil, err
	}

	if invoice.Status != InvoiceStatusPending {
		return nil, errors.New("can only apply discount to pending invoices")
	}

	if invoice.DiscountCode != "" {
		return nil, errors.New("discount already applied")
	}

	// Validate discount code
	discount, err := pm.ValidateDiscountCode(discountCode, invoice.UserID, invoice.Subtotal)
	if err != nil {
		return nil, err
	}

	// Check applicable plans
	if len(discount.ApplicablePlans) > 0 {
		hasApplicablePlan := false
		for _, item := range invoice.Items {
			for _, planID := range discount.ApplicablePlans {
				if item.PlanID == planID {
					hasApplicablePlan = true
					break
				}
			}
		}
		if !hasApplicablePlan {
			return nil, errors.New("discount not applicable to selected plans")
		}
	}

	// Calculate discount amount
	var discountAmount float64
	if discount.Type == "percent" {
		discountAmount = invoice.Subtotal * (discount.Value / 100)
		if discount.MaxDiscount > 0 && discountAmount > discount.MaxDiscount {
			discountAmount = discount.MaxDiscount
		}
	} else {
		discountAmount = discount.Value
		if discount.Currency != "" && discount.Currency != invoice.Currency {
			discountAmount, _ = pm.ConvertCurrency(discountAmount, discount.Currency, invoice.Currency)
		}
	}

	// Apply discount
	invoice.Discount = discountAmount
	invoice.DiscountCode = discountCode
	invoice.Total = invoice.Subtotal - discountAmount + invoice.Tax
	if invoice.Total < 0 {
		invoice.Total = 0
	}
	invoice.UpdatedAt = time.Now()

	// Update database
	_, err = pm.db.Exec(`UPDATE invoices SET 
		discount = ?, discount_code = ?, total = ?, updated_at = ? 
		WHERE id = ?`,
		invoice.Discount, invoice.DiscountCode, invoice.Total, invoice.UpdatedAt, invoiceID)

	if err != nil {
		return nil, err
	}

	// Record discount usage
	pm.RecordDiscountUsage(discount.ID, invoice.UserID, invoiceID, discountAmount)

	pm.emitEvent("discount_applied", invoice.UserID, "", map[string]interface{}{
		"invoice_id": invoiceID,
		"discount":   discountAmount,
		"code":       discountCode,
	})

	return invoice, nil
}

// PayInvoice processes payment for an invoice
func (pm *PaymentManager) PayInvoice(invoiceID string, gateway PaymentGateway, payerIP string) (*PaymentSession, error) {
	invoice, err := pm.GetInvoice(invoiceID)
	if err != nil {
		return nil, err
	}

	if invoice.Status == InvoiceStatusPaid {
		return nil, errors.New("invoice already paid")
	}

	if invoice.Status == InvoiceStatusCancelled || invoice.Status == InvoiceStatusExpired {
		return nil, errors.New("invoice is no longer valid")
	}

	if time.Now().After(invoice.DueDate) {
		pm.UpdateInvoiceStatus(invoiceID, InvoiceStatusExpired)
		return nil, errors.New("invoice has expired")
	}

	// Check if paying with wallet
	if gateway == GatewayWallet {
		return pm.payWithWallet(invoice, payerIP)
	}

	// Get gateway handler
	handler, ok := pm.gatewayHandlers[gateway]
	if !ok {
		return nil, fmt.Errorf("payment gateway %s not available", gateway)
	}

	// Create payment session
	session := &PaymentSession{
		ID:        uuid.New().String(),
		InvoiceID: invoiceID,
		UserID:    invoice.UserID,
		Gateway:   gateway,
		Amount:    invoice.Total - invoice.PaidAmount,
		Currency:  invoice.Currency,
		Status:    "pending",
		IP:        payerIP,
		ExpiresAt: time.Now().Add(30 * time.Minute),
		CreatedAt: time.Now(),
	}

	// Create payment with gateway
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	session, err = handler.CreatePayment(ctx, invoice)
	if err != nil {
		return nil, fmt.Errorf("failed to create payment: %w", err)
	}

	session.ID = uuid.New().String()
	session.IP = payerIP
	session.ExpiresAt = time.Now().Add(30 * time.Minute)
	session.CreatedAt = time.Now()

	// Save session
	gatewayDataJSON, _ := json.Marshal(session.GatewayData)
	_, err = pm.db.Exec(`INSERT INTO payment_sessions (
		id, invoice_id, user_id, gateway, amount, currency, status,
		payment_url, gateway_data_json, ip, expires_at, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID, session.InvoiceID, session.UserID, session.Gateway,
		session.Amount, session.Currency, session.Status, session.PaymentURL,
		string(gatewayDataJSON), session.IP, session.ExpiresAt, session.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	// Update invoice with gateway info
	pm.db.Exec(`UPDATE invoices SET gateway = ?, payment_url = ?, updated_at = ? WHERE id = ?`,
		gateway, session.PaymentURL, time.Now(), invoiceID)

	pm.emitEvent("payment_initiated", invoice.UserID, "", session)

	return session, nil
}

// payWithWallet pays invoice using wallet balance
func (pm *PaymentManager) payWithWallet(invoice *Invoice, payerIP string) (*PaymentSession, error) {
	wallet, err := pm.GetWalletByUser(invoice.UserID)
	if err != nil {
		return nil, err
	}

	amountToPay := invoice.Total - invoice.PaidAmount

	// Convert if needed
	if wallet.Currency != invoice.Currency {
		amountToPay, err = pm.ConvertCurrency(amountToPay, invoice.Currency, wallet.Currency)
		if err != nil {
			return nil, err
		}
	}

	availableBalance := wallet.Balance - wallet.FrozenBalance
	if availableBalance < amountToPay {
		return nil, fmt.Errorf("insufficient wallet balance. Need %s, have %s",
			FormatCurrency(amountToPay, wallet.Currency),
			FormatCurrency(availableBalance, wallet.Currency))
	}

	// Start transaction
	tx, err := pm.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	now := time.Now()

	// Create wallet transaction
	walletTx := &Transaction{
		ID:            uuid.New().String(),
		WalletID:      wallet.ID,
		UserID:        wallet.UserID,
		Type:          TxTypePurchase,
		Status:        TxStatusCompleted,
		Amount:        -amountToPay,
		Currency:      wallet.Currency,
		BalanceBefore: wallet.Balance,
		BalanceAfter:  wallet.Balance - amountToPay,
		Gateway:       GatewayWallet,
		ReferenceID:   invoice.ID,
		Description:   fmt.Sprintf("Payment for invoice %s", invoice.InvoiceNumber),
		IP:            payerIP,
		CreatedAt:     now,
		CompletedAt:   &now,
	}

	_, err = tx.Exec(`INSERT INTO transactions (
		id, wallet_id, user_id, type, status, amount, currency,
		balance_before, balance_after, gateway, reference_id, description, ip,
		created_at, completed_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		walletTx.ID, walletTx.WalletID, walletTx.UserID, walletTx.Type,
		walletTx.Status, walletTx.Amount, walletTx.Currency,
		walletTx.BalanceBefore, walletTx.BalanceAfter, walletTx.Gateway,
		walletTx.ReferenceID, walletTx.Description, walletTx.IP,
		walletTx.CreatedAt, walletTx.CompletedAt,
	)
	if err != nil {
		return nil, err
	}

	// Update wallet
	_, err = tx.Exec(`UPDATE wallets SET 
		balance = balance - ?, total_spent = total_spent + ?, updated_at = ? 
		WHERE id = ?`, amountToPay, amountToPay, now, wallet.ID)
	if err != nil {
		return nil, err
	}

	// Update invoice
	_, err = tx.Exec(`UPDATE invoices SET 
		status = ?, paid_amount = ?, gateway = ?, paid_at = ?, updated_at = ? 
		WHERE id = ?`,
		InvoiceStatusPaid, invoice.Total, GatewayWallet, now, now, invoice.ID)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	// Update cache
	wallet.Balance -= amountToPay
	wallet.TotalSpent += amountToPay
	pm.walletCache.Store(wallet.ID, wallet)

	// Process commission for reseller
	if invoice.AdminID != "" {
		go pm.ProcessCommission(invoice)
	}

	// Create session for response
	session := &PaymentSession{
		ID:        uuid.New().String(),
		InvoiceID: invoice.ID,
		UserID:    invoice.UserID,
		Gateway:   GatewayWallet,
		Amount:    amountToPay,
		Currency:  wallet.Currency,
		Status:    "completed",
		IP:        payerIP,
		CreatedAt: now,
	}

	pm.emitEvent("payment_completed", invoice.UserID, invoice.AdminID, map[string]interface{}{
		"invoice":     invoice,
		"transaction": walletTx,
	})

	// Activate subscription
	go pm.ActivateSubscriptionFromInvoice(invoice)

	return session, nil
}

// VerifyPayment verifies payment callback from gateway
func (pm *PaymentManager) VerifyPayment(sessionID string, callbackData map[string]string) (*Invoice, error) {
	// Get session
	session := &PaymentSession{}
	var gatewayDataJSON string

	err := pm.db.QueryRow(`SELECT 
		id, invoice_id, user_id, gateway, amount, currency, status,
		payment_url, gateway_data_json, ip, expires_at, created_at
		FROM payment_sessions WHERE id = ?`, sessionID).Scan(
		&session.ID, &session.InvoiceID, &session.UserID, &session.Gateway,
		&session.Amount, &session.Currency, &session.Status,
		&session.PaymentURL, &gatewayDataJSON, &session.IP,
		&session.ExpiresAt, &session.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("payment session not found: %w", err)
	}

	json.Unmarshal([]byte(gatewayDataJSON), &session.GatewayData)

	if session.Status == "completed" {
		return pm.GetInvoice(session.InvoiceID)
	}

	if time.Now().After(session.ExpiresAt) {
		pm.db.Exec("UPDATE payment_sessions SET status = ? WHERE id = ?", "expired", sessionID)
		return nil, errors.New("payment session expired")
	}

	// Get gateway handler
	handler, ok := pm.gatewayHandlers[session.Gateway]
	if !ok {
		return nil, errors.New("gateway handler not found")
	}

	// Verify with gateway
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	verified, err := handler.VerifyPayment(ctx, session, callbackData)
	if err != nil {
		pm.db.Exec("UPDATE payment_sessions SET status = ? WHERE id = ?", "failed", sessionID)
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	if !verified {
		pm.db.Exec("UPDATE payment_sessions SET status = ? WHERE id = ?", "failed", sessionID)
		return nil, errors.New("payment verification failed")
	}

	// Get invoice
	invoice, err := pm.GetInvoice(session.InvoiceID)
	if err != nil {
		return nil, err
	}

	// Start transaction
	tx, err := pm.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	now := time.Now()

	// Update session
	_, err = tx.Exec("UPDATE payment_sessions SET status = ? WHERE id = ?", "completed", sessionID)
	if err != nil {
		return nil, err
	}

	// Update invoice
	_, err = tx.Exec(`UPDATE invoices SET 
		status = ?, paid_amount = total, paid_at = ?, updated_at = ? 
		WHERE id = ?`,
		InvoiceStatusPaid, now, now, invoice.ID)
	if err != nil {
		return nil, err
	}

	// Create deposit transaction for tracking
	wallet, _ := pm.GetWalletByUser(invoice.UserID)
	if wallet != nil {
		gatewayTxID := ""
		if v, ok := callbackData["transaction_id"]; ok {
			gatewayTxID = v
		}

		// Record as deposit + immediate purchase
		// This is for tracking purposes
		pm.db.Exec(`INSERT INTO transactions (
			id, wallet_id, user_id, type, status, amount, currency,
			gateway, gateway_tx_id, reference_id, description, ip, created_at, completed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			uuid.New().String(), wallet.ID, invoice.UserID, TxTypePurchase,
			TxStatusCompleted, -invoice.Total, invoice.Currency,
			session.Gateway, gatewayTxID, invoice.ID,
			fmt.Sprintf("Payment for invoice %s", invoice.InvoiceNumber),
			session.IP, now, now,
		)
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	// Process commission
	if invoice.AdminID != "" {
		go pm.ProcessCommission(invoice)
	}

	// Activate subscription
	go pm.ActivateSubscriptionFromInvoice(invoice)

	pm.emitEvent("payment_verified", invoice.UserID, invoice.AdminID, invoice)

	// Refresh invoice
	return pm.GetInvoice(invoice.ID)
}

// RefundInvoice refunds a paid invoice
func (pm *PaymentManager) RefundInvoice(invoiceID string, amount float64, reason string, adminID string) error {
	invoice, err := pm.GetInvoice(invoiceID)
	if err != nil {
		return err
	}

	if invoice.Status != InvoiceStatusPaid {
		return errors.New("can only refund paid invoices")
	}

	if amount <= 0 {
		amount = invoice.PaidAmount
	}

	if amount > invoice.PaidAmount {
		return errors.New("refund amount exceeds paid amount")
	}

	// Refund to wallet
	wallet, err := pm.GetWalletByUser(invoice.UserID)
	if err != nil {
		return err
	}

	// Convert if needed
	refundAmount := amount
	if wallet.Currency != invoice.Currency {
		refundAmount, _ = pm.ConvertCurrency(amount, invoice.Currency, wallet.Currency)
	}

	tx, err := pm.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now()

	// Create refund transaction
	refundTx := &Transaction{
		ID:            uuid.New().String(),
		WalletID:      wallet.ID,
		UserID:        wallet.UserID,
		AdminID:       adminID,
		Type:          TxTypeRefund,
		Status:        TxStatusCompleted,
		Amount:        refundAmount,
		Currency:      wallet.Currency,
		BalanceBefore: wallet.Balance,
		BalanceAfter:  wallet.Balance + refundAmount,
		ReferenceID:   invoice.ID,
		Description:   fmt.Sprintf("Refund for invoice %s: %s", invoice.InvoiceNumber, reason),
		CreatedAt:     now,
		CompletedAt:   &now,
	}

	_, err = tx.Exec(`INSERT INTO transactions (
		id, wallet_id, user_id, admin_id, type, status, amount, currency,
		balance_before, balance_after, reference_id, description, created_at, completed_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		refundTx.ID, refundTx.WalletID, refundTx.UserID, refundTx.AdminID,
		refundTx.Type, refundTx.Status, refundTx.Amount, refundTx.Currency,
		refundTx.BalanceBefore, refundTx.BalanceAfter, refundTx.ReferenceID,
		refundTx.Description, refundTx.CreatedAt, refundTx.CompletedAt,
	)
	if err != nil {
		return err
	}

	// Update wallet
	_, err = tx.Exec("UPDATE wallets SET balance = balance + ?, updated_at = ? WHERE id = ?",
		refundAmount, now, wallet.ID)
	if err != nil {
		return err
	}

	// Update invoice
	newStatus := InvoiceStatusRefunded
	if amount < invoice.PaidAmount {
		newStatus = InvoiceStatusPartial
	}

	_, err = tx.Exec(`UPDATE invoices SET 
		status = ?, paid_amount = paid_amount - ?, 
		notes = COALESCE(notes, '') || ?, updated_at = ? 
		WHERE id = ?`,
		newStatus, amount, fmt.Sprintf("\nRefund: %s - %s", FormatCurrency(amount, invoice.Currency), reason),
		now, invoice.ID)
	if err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return err
	}

	// Update cache
	wallet.Balance += refundAmount
	pm.walletCache.Store(wallet.ID, wallet)

	pm.emitEvent("invoice_refunded", invoice.UserID, adminID, map[string]interface{}{
		"invoice": invoice,
		"amount":  amount,
		"reason":  reason,
	})

	return nil
}

// CancelInvoice cancels a pending invoice
func (pm *PaymentManager) CancelInvoice(invoiceID string, reason string) error {
	invoice, err := pm.GetInvoice(invoiceID)
	if err != nil {
		return err
	}

	if invoice.Status != InvoiceStatusPending && invoice.Status != InvoiceStatusDraft {
		return errors.New("can only cancel pending or draft invoices")
	}

	_, err = pm.db.Exec(`UPDATE invoices SET 
		status = ?, notes = COALESCE(notes, '') || ?, updated_at = ? 
		WHERE id = ?`,
		InvoiceStatusCancelled, fmt.Sprintf("\nCancelled: %s", reason), time.Now(), invoiceID)

	if err != nil {
		return err
	}

	pm.emitEvent("invoice_cancelled", invoice.UserID, "", map[string]interface{}{
		"invoice_id": invoiceID,
		"reason":     reason,
	})

	return nil
}

// GetUserInvoices retrieves invoices for a user
func (pm *PaymentManager) GetUserInvoices(userID string, status InvoiceStatus, limit, offset int) ([]*Invoice, int, error) {
	var invoices []*Invoice
	var total int

	// Count
	countQuery := "SELECT COUNT(*) FROM invoices WHERE user_id = ?"
	args := []interface{}{userID}

	if status != "" {
		countQuery += " AND status = ?"
		args = append(args, status)
	}

	pm.db.QueryRow(countQuery, args...).Scan(&total)

	// Query
	query := `SELECT id, invoice_number, user_id, admin_id, status, items_json,
		subtotal, discount, discount_code, tax, tax_rate, total, paid_amount,
		currency, gateway, payment_url, notes, due_date, paid_at, created_at, updated_at
		FROM invoices WHERE user_id = ?`

	if status != "" {
		query += " AND status = ?"
	}

	query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := pm.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	for rows.Next() {
		inv := &Invoice{}
		var itemsJSON string
		var paidAt sql.NullTime

		err := rows.Scan(
			&inv.ID, &inv.InvoiceNumber, &inv.UserID, &inv.AdminID, &inv.Status,
			&itemsJSON, &inv.Subtotal, &inv.Discount, &inv.DiscountCode,
			&inv.Tax, &inv.TaxRate, &inv.Total, &inv.PaidAmount,
			&inv.Currency, &inv.Gateway, &inv.PaymentURL, &inv.Notes,
			&inv.DueDate, &paidAt, &inv.CreatedAt, &inv.UpdatedAt,
		)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(itemsJSON), &inv.Items)
		if paidAt.Valid {
			inv.PaidAt = &paidAt.Time
		}

		invoices = append(invoices, inv)
	}

	return invoices, total, nil
}

// GetAllInvoices retrieves all invoices with filters
func (pm *PaymentManager) GetAllInvoices(filter InvoiceFilter) ([]*Invoice, int, error) {
	var invoices []*Invoice
	var total int
	var args []interface{}

	whereClause := "WHERE 1=1"

	if filter.UserID != "" {
		whereClause += " AND user_id = ?"
		args = append(args, filter.UserID)
	}
	if filter.AdminID != "" {
		whereClause += " AND admin_id = ?"
		args = append(args, filter.AdminID)
	}
	if filter.Status != "" {
		whereClause += " AND status = ?"
		args = append(args, filter.Status)
	}
	if filter.Currency != "" {
		whereClause += " AND currency = ?"
		args = append(args, filter.Currency)
	}
	if filter.Gateway != "" {
		whereClause += " AND gateway = ?"
		args = append(args, filter.Gateway)
	}
	if filter.MinAmount > 0 {
		whereClause += " AND total >= ?"
		args = append(args, filter.MinAmount)
	}
	if filter.MaxAmount > 0 {
		whereClause += " AND total <= ?"
		args = append(args, filter.MaxAmount)
	}
	if !filter.FromDate.IsZero() {
		whereClause += " AND created_at >= ?"
		args = append(args, filter.FromDate)
	}
	if !filter.ToDate.IsZero() {
		whereClause += " AND created_at <= ?"
		args = append(args, filter.ToDate)
	}

	// Count
	pm.db.QueryRow("SELECT COUNT(*) FROM invoices "+whereClause, args...).Scan(&total)

	// Sort
	sortBy := "created_at"
	sortOrder := "DESC"
	if filter.SortBy != "" {
		sortBy = filter.SortBy
	}
	if filter.SortOrder == "asc" {
		sortOrder = "ASC"
	}

	limit := 50
	if filter.Limit > 0 && filter.Limit <= 200 {
		limit = filter.Limit
	}

	query := fmt.Sprintf(`SELECT id, invoice_number, user_id, admin_id, status, items_json,
		subtotal, discount, discount_code, tax, tax_rate, total, paid_amount,
		currency, gateway, payment_url, notes, due_date, paid_at, created_at, updated_at
		FROM invoices %s ORDER BY %s %s LIMIT ? OFFSET ?`,
		whereClause, sortBy, sortOrder)

	args = append(args, limit, filter.Offset)

	rows, err := pm.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	for rows.Next() {
		inv := &Invoice{}
		var itemsJSON string
		var paidAt sql.NullTime

		err := rows.Scan(
			&inv.ID, &inv.InvoiceNumber, &inv.UserID, &inv.AdminID, &inv.Status,
			&itemsJSON, &inv.Subtotal, &inv.Discount, &inv.DiscountCode,
			&inv.Tax, &inv.TaxRate, &inv.Total, &inv.PaidAmount,
			&inv.Currency, &inv.Gateway, &inv.PaymentURL, &inv.Notes,
			&inv.DueDate, &paidAt, &inv.CreatedAt, &inv.UpdatedAt,
		)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(itemsJSON), &inv.Items)
		if paidAt.Valid {
			inv.PaidAt = &paidAt.Time
		}

		invoices = append(invoices, inv)
	}

	return invoices, total, nil
}

// InvoiceFilter for searching invoices
type InvoiceFilter struct {
	UserID    string         `json:"user_id,omitempty"`
	AdminID   string         `json:"admin_id,omitempty"`
	Status    InvoiceStatus  `json:"status,omitempty"`
	Currency  Currency       `json:"currency,omitempty"`
	Gateway   PaymentGateway `json:"gateway,omitempty"`
	MinAmount float64        `json:"min_amount,omitempty"`
	MaxAmount float64        `json:"max_amount,omitempty"`
	FromDate  time.Time      `json:"from_date,omitempty"`
	ToDate    time.Time      `json:"to_date,omitempty"`
	Limit     int            `json:"limit,omitempty"`
	Offset    int            `json:"offset,omitempty"`
	SortBy    string         `json:"sort_by,omitempty"`
	SortOrder string         `json:"sort_order,omitempty"`
}

// ==================== Subscription Plans ====================

// CreatePlan creates a new subscription plan
func (pm *PaymentManager) CreatePlan(plan *SubscriptionPlan) error {
	plan.ID = uuid.New().String()
	plan.CreatedAt = time.Now()
	plan.UpdatedAt = time.Now()

	if plan.Prices == nil || len(plan.Prices) == 0 {
		return errors.New("plan must have at least one price")
	}

	protocolsJSON, _ := json.Marshal(plan.Protocols)
	nodesJSON, _ := json.Marshal(plan.Nodes)
	pricesJSON, _ := json.Marshal(plan.Prices)
	originalPricesJSON, _ := json.Marshal(plan.OriginalPrices)
	featuresJSON, _ := json.Marshal(plan.Features)
	featuresFaJSON, _ := json.Marshal(plan.FeaturesFA)
	metaJSON, _ := json.Marshal(plan.Meta)

	_, err := pm.db.Exec(`INSERT INTO subscription_plans (
		id, name, name_fa, description, description_fa,
		duration, duration_days, traffic_gb, device_limit, concurrent_limit,
		protocols_json, nodes_json, prices_json, original_prices_json,
		features_json, features_fa_json, is_active, is_popular, is_trial,
		trial_once, sort_order, admin_id, meta_json, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		plan.ID, plan.Name, plan.NameFA, plan.Description, plan.DescriptionFA,
		plan.Duration, plan.DurationDays, plan.TrafficGB, plan.DeviceLimit, plan.ConcurrentLimit,
		string(protocolsJSON), string(nodesJSON), string(pricesJSON), string(originalPricesJSON),
		string(featuresJSON), string(featuresFaJSON), plan.IsActive, plan.IsPopular, plan.IsTrial,
		plan.TrialOnce, plan.SortOrder, plan.AdminID, string(metaJSON), plan.CreatedAt, plan.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create plan: %w", err)
	}

	pm.emitEvent("plan_created", "", plan.AdminID, plan)

	return nil
}

// GetPlan retrieves a subscription plan by ID
func (pm *PaymentManager) GetPlan(planID string) (*SubscriptionPlan, error) {
	plan := &SubscriptionPlan{}
	var protocolsJSON, nodesJSON, pricesJSON, originalPricesJSON string
	var featuresJSON, featuresFaJSON, metaJSON string

	err := pm.db.QueryRow(`SELECT 
		id, name, name_fa, description, description_fa,
		duration, duration_days, traffic_gb, device_limit, concurrent_limit,
		protocols_json, nodes_json, prices_json, original_prices_json,
		features_json, features_fa_json, is_active, is_popular, is_trial,
		trial_once, sort_order, admin_id, meta_json, created_at, updated_at
		FROM subscription_plans WHERE id = ?`, planID).Scan(
		&plan.ID, &plan.Name, &plan.NameFA, &plan.Description, &plan.DescriptionFA,
		&plan.Duration, &plan.DurationDays, &plan.TrafficGB, &plan.DeviceLimit, &plan.ConcurrentLimit,
		&protocolsJSON, &nodesJSON, &pricesJSON, &originalPricesJSON,
		&featuresJSON, &featuresFaJSON, &plan.IsActive, &plan.IsPopular, &plan.IsTrial,
		&plan.TrialOnce, &plan.SortOrder, &plan.AdminID, &metaJSON, &plan.CreatedAt, &plan.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("plan not found: %w", err)
	}

	json.Unmarshal([]byte(protocolsJSON), &plan.Protocols)
	json.Unmarshal([]byte(nodesJSON), &plan.Nodes)
	json.Unmarshal([]byte(pricesJSON), &plan.Prices)
	json.Unmarshal([]byte(originalPricesJSON), &plan.OriginalPrices)
	json.Unmarshal([]byte(featuresJSON), &plan.Features)
	json.Unmarshal([]byte(featuresFaJSON), &plan.FeaturesFA)
	json.Unmarshal([]byte(metaJSON), &plan.Meta)

	return plan, nil
}

// UpdatePlan updates a subscription plan
func (pm *PaymentManager) UpdatePlan(plan *SubscriptionPlan) error {
	plan.UpdatedAt = time.Now()

	protocolsJSON, _ := json.Marshal(plan.Protocols)
	nodesJSON, _ := json.Marshal(plan.Nodes)
	pricesJSON, _ := json.Marshal(plan.Prices)
	originalPricesJSON, _ := json.Marshal(plan.OriginalPrices)
	featuresJSON, _ := json.Marshal(plan.Features)
	featuresFaJSON, _ := json.Marshal(plan.FeaturesFA)
	metaJSON, _ := json.Marshal(plan.Meta)

	_, err := pm.db.Exec(`UPDATE subscription_plans SET 
		name = ?, name_fa = ?, description = ?, description_fa = ?,
		duration = ?, duration_days = ?, traffic_gb = ?, device_limit = ?, concurrent_limit = ?,
		protocols_json = ?, nodes_json = ?, prices_json = ?, original_prices_json = ?,
		features_json = ?, features_fa_json = ?, is_active = ?, is_popular = ?, is_trial = ?,
		trial_once = ?, sort_order = ?, meta_json = ?, updated_at = ?
		WHERE id = ?`,
		plan.Name, plan.NameFA, plan.Description, plan.DescriptionFA,
		plan.Duration, plan.DurationDays, plan.TrafficGB, plan.DeviceLimit, plan.ConcurrentLimit,
		string(protocolsJSON), string(nodesJSON), string(pricesJSON), string(originalPricesJSON),
		string(featuresJSON), string(featuresFaJSON), plan.IsActive, plan.IsPopular, plan.IsTrial,
		plan.TrialOnce, plan.SortOrder, string(metaJSON), plan.UpdatedAt, plan.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update plan: %w", err)
	}

	pm.emitEvent("plan_updated", "", plan.AdminID, plan)

	return nil
}

// DeletePlan deletes a subscription plan
func (pm *PaymentManager) DeletePlan(planID string) error {
	// Check if plan is used in any unpaid invoices
	var count int
	pm.db.QueryRow(`SELECT COUNT(*) FROM invoices 
		WHERE status = 'pending' AND items_json LIKE ?`, "%"+planID+"%").Scan(&count)

	if count > 0 {
		return errors.New("cannot delete plan with pending invoices")
	}

	_, err := pm.db.Exec("DELETE FROM subscription_plans WHERE id = ?", planID)
	if err != nil {
		return err
	}

	pm.emitEvent("plan_deleted", "", "", map[string]string{"plan_id": planID})

	return nil
}

// GetActivePlans retrieves all active subscription plans
func (pm *PaymentManager) GetActivePlans(adminID string) ([]*SubscriptionPlan, error) {
	var plans []*SubscriptionPlan

	query := `SELECT 
		id, name, name_fa, description, description_fa,
		duration, duration_days, traffic_gb, device_limit, concurrent_limit,
		protocols_json, nodes_json, prices_json, original_prices_json,
		features_json, features_fa_json, is_active, is_popular, is_trial,
		trial_once, sort_order, admin_id, meta_json, created_at, updated_at
		FROM subscription_plans WHERE is_active = 1`

	var args []interface{}

	if adminID != "" {
		query += " AND (admin_id = ? OR admin_id = '' OR admin_id IS NULL)"
		args = append(args, adminID)
	}

	query += " ORDER BY sort_order ASC, created_at ASC"

	rows, err := pm.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		plan := &SubscriptionPlan{}
		var protocolsJSON, nodesJSON, pricesJSON, originalPricesJSON string
		var featuresJSON, featuresFaJSON, metaJSON string

		err := rows.Scan(
			&plan.ID, &plan.Name, &plan.NameFA, &plan.Description, &plan.DescriptionFA,
			&plan.Duration, &plan.DurationDays, &plan.TrafficGB, &plan.DeviceLimit, &plan.ConcurrentLimit,
			&protocolsJSON, &nodesJSON, &pricesJSON, &originalPricesJSON,
			&featuresJSON, &featuresFaJSON, &plan.IsActive, &plan.IsPopular, &plan.IsTrial,
			&plan.TrialOnce, &plan.SortOrder, &plan.AdminID, &metaJSON, &plan.CreatedAt, &plan.UpdatedAt,
		)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(protocolsJSON), &plan.Protocols)
		json.Unmarshal([]byte(nodesJSON), &plan.Nodes)
		json.Unmarshal([]byte(pricesJSON), &plan.Prices)
		json.Unmarshal([]byte(originalPricesJSON), &plan.OriginalPrices)
		json.Unmarshal([]byte(featuresJSON), &plan.Features)
		json.Unmarshal([]byte(featuresFaJSON), &plan.FeaturesFA)
		json.Unmarshal([]byte(metaJSON), &plan.Meta)

		plans = append(plans, plan)
	}

	return plans, nil
}

// GetAllPlans retrieves all plans (including inactive)
func (pm *PaymentManager) GetAllPlans() ([]*SubscriptionPlan, error) {
	var plans []*SubscriptionPlan

	rows, err := pm.db.Query(`SELECT 
		id, name, name_fa, description, description_fa,
		duration, duration_days, traffic_gb, device_limit, concurrent_limit,
		protocols_json, nodes_json, prices_json, original_prices_json,
		features_json, features_fa_json, is_active, is_popular, is_trial,
		trial_once, sort_order, admin_id, meta_json, created_at, updated_at
		FROM subscription_plans ORDER BY sort_order ASC, created_at ASC`)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		plan := &SubscriptionPlan{}
		var protocolsJSON, nodesJSON, pricesJSON, originalPricesJSON string
		var featuresJSON, featuresFaJSON, metaJSON string

		err := rows.Scan(
			&plan.ID, &plan.Name, &plan.NameFA, &plan.Description, &plan.DescriptionFA,
			&plan.Duration, &plan.DurationDays, &plan.TrafficGB, &plan.DeviceLimit, &plan.ConcurrentLimit,
			&protocolsJSON, &nodesJSON, &pricesJSON, &originalPricesJSON,
			&featuresJSON, &featuresFaJSON, &plan.IsActive, &plan.IsPopular, &plan.IsTrial,
			&plan.TrialOnce, &plan.SortOrder, &plan.AdminID, &metaJSON, &plan.CreatedAt, &plan.UpdatedAt,
		)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(protocolsJSON), &plan.Protocols)
		json.Unmarshal([]byte(nodesJSON), &plan.Nodes)
		json.Unmarshal([]byte(pricesJSON), &plan.Prices)
		json.Unmarshal([]byte(originalPricesJSON), &plan.OriginalPrices)
		json.Unmarshal([]byte(featuresJSON), &plan.Features)
		json.Unmarshal([]byte(featuresFaJSON), &plan.FeaturesFA)
		json.Unmarshal([]byte(metaJSON), &plan.Meta)

		plans = append(plans, plan)
	}

	return plans, nil
}

// GetPlanPrice gets price in specific currency
func (pm *PaymentManager) GetPlanPrice(planID string, currency Currency) (float64, error) {
	plan, err := pm.GetPlan(planID)
	if err != nil {
		return 0, err
	}

	// Direct price
	if price, ok := plan.Prices[currency]; ok {
		return price, nil
	}

	// Convert from first available price
	for fromCurrency, price := range plan.Prices {
		converted, err := pm.ConvertCurrency(price, fromCurrency, currency)
		if err == nil {
			return converted, nil
		}
	}

	return 0, errors.New("no price available for currency")
}

// CreateInvoiceFromPlan creates invoice from a subscription plan
func (pm *PaymentManager) CreateInvoiceFromPlan(userID, planID string, currency Currency, adminID string) (*Invoice, error) {
	plan, err := pm.GetPlan(planID)
	if err != nil {
		return nil, err
	}

	if !plan.IsActive {
		return nil, errors.New("plan is not active")
	}

	// Check trial restrictions
	if plan.IsTrial && plan.TrialOnce {
		var trialCount int
		pm.db.QueryRow(`SELECT COUNT(*) FROM invoices 
			WHERE user_id = ? AND status = 'paid' AND items_json LIKE ?`,
			userID, "%"+planID+"%").Scan(&trialCount)

		if trialCount > 0 {
			return nil, errors.New("trial already used")
		}
	}

	// Get price
	price, err := pm.GetPlanPrice(planID, currency)
	if err != nil {
		return nil, err
	}

	// Create invoice item
	item := InvoiceItem{
		Type:        "subscription",
		PlanID:      planID,
		Name:        plan.Name,
		Description: plan.Description,
		Quantity:    1,
		UnitPrice:   price,
		Meta: map[string]interface{}{
			"duration_days":    plan.DurationDays,
			"traffic_gb":       plan.TrafficGB,
			"device_limit":     plan.DeviceLimit,
			"concurrent_limit": plan.ConcurrentLimit,
		},
	}

	return pm.CreateInvoice(userID, []InvoiceItem{item}, currency, adminID)
}

// ==================== Discount Codes ====================

// CreateDiscountCode creates a new discount code
func (pm *PaymentManager) CreateDiscountCode(discount *DiscountCode) error {
	discount.ID = uuid.New().String()
	discount.Code = strings.ToUpper(strings.TrimSpace(discount.Code))
	discount.CreatedAt = time.Now()

	if discount.Code == "" {
		return errors.New("discount code cannot be empty")
	}

	// Check uniqueness
	var existing int
	pm.db.QueryRow("SELECT COUNT(*) FROM discount_codes WHERE code = ?", discount.Code).Scan(&existing)
	if existing > 0 {
		return errors.New("discount code already exists")
	}

	applicablePlansJSON, _ := json.Marshal(discount.ApplicablePlans)

	_, err := pm.db.Exec(`INSERT INTO discount_codes (
		id, code, description, type, value, currency, min_purchase, max_discount,
		usage_limit, usage_count, per_user_limit, applicable_plans_json, admin_id,
		is_active, starts_at, expires_at, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		discount.ID, discount.Code, discount.Description, discount.Type, discount.Value,
		discount.Currency, discount.MinPurchase, discount.MaxDiscount,
		discount.UsageLimit, discount.UsageCount, discount.PerUserLimit,
		string(applicablePlansJSON), discount.AdminID, discount.IsActive,
		discount.StartsAt, discount.ExpiresAt, discount.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create discount code: %w", err)
	}

	pm.emitEvent("discount_created", "", discount.AdminID, discount)

	return nil
}

// GetDiscountCode retrieves discount code by code string
func (pm *PaymentManager) GetDiscountCode(code string) (*DiscountCode, error) {
	code = strings.ToUpper(strings.TrimSpace(code))

	discount := &DiscountCode{}
	var applicablePlansJSON string

	err := pm.db.QueryRow(`SELECT 
		id, code, description, type, value, currency, min_purchase, max_discount,
		usage_limit, usage_count, per_user_limit, applicable_plans_json, admin_id,
		is_active, starts_at, expires_at, created_at
		FROM discount_codes WHERE code = ?`, code).Scan(
		&discount.ID, &discount.Code, &discount.Description, &discount.Type, &discount.Value,
		&discount.Currency, &discount.MinPurchase, &discount.MaxDiscount,
		&discount.UsageLimit, &discount.UsageCount, &discount.PerUserLimit,
		&applicablePlansJSON, &discount.AdminID, &discount.IsActive,
		&discount.StartsAt, &discount.ExpiresAt, &discount.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("discount code not found: %w", err)
	}

	json.Unmarshal([]byte(applicablePlansJSON), &discount.ApplicablePlans)

	return discount, nil
}

// ValidateDiscountCode validates a discount code for a user
func (pm *PaymentManager) ValidateDiscountCode(code, userID string, purchaseAmount float64) (*DiscountCode, error) {
	discount, err := pm.GetDiscountCode(code)
	if err != nil {
		return nil, err
	}

	// Check if active
	if !discount.IsActive {
		return nil, errors.New("discount code is not active")
	}

	// Check date range
	now := time.Now()
	if now.Before(discount.StartsAt) {
		return nil, errors.New("discount code is not yet valid")
	}
	if now.After(discount.ExpiresAt) {
		return nil, errors.New("discount code has expired")
	}

	// Check usage limit
	if discount.UsageLimit > 0 && discount.UsageCount >= discount.UsageLimit {
		return nil, errors.New("discount code usage limit reached")
	}

	// Check per-user limit
	if discount.PerUserLimit > 0 && userID != "" {
		var userUsage int
		pm.db.QueryRow(`SELECT COUNT(*) FROM discount_usage 
			WHERE discount_id = ? AND user_id = ?`, discount.ID, userID).Scan(&userUsage)

		if userUsage >= discount.PerUserLimit {
			return nil, errors.New("you have already used this discount code")
		}
	}

	// Check minimum purchase
	if discount.MinPurchase > 0 && purchaseAmount < discount.MinPurchase {
		return nil, fmt.Errorf("minimum purchase amount is %s",
			FormatCurrency(discount.MinPurchase, discount.Currency))
	}

	return discount, nil
}

// RecordDiscountUsage records usage of discount code
func (pm *PaymentManager) RecordDiscountUsage(discountID, userID, invoiceID string, amount float64) error {
	// Insert usage record
	_, err := pm.db.Exec(`INSERT INTO discount_usage (id, discount_id, user_id, invoice_id, amount, used_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		uuid.New().String(), discountID, userID, invoiceID, amount, time.Now())

	if err != nil {
		return err
	}

	// Update usage count
	_, err = pm.db.Exec("UPDATE discount_codes SET usage_count = usage_count + 1 WHERE id = ?", discountID)

	return err
}

// UpdateDiscountCode updates a discount code
func (pm *PaymentManager) UpdateDiscountCode(discount *DiscountCode) error {
	applicablePlansJSON, _ := json.Marshal(discount.ApplicablePlans)

	_, err := pm.db.Exec(`UPDATE discount_codes SET 
		description = ?, type = ?, value = ?, currency = ?, min_purchase = ?,
		max_discount = ?, usage_limit = ?, per_user_limit = ?,
		applicable_plans_json = ?, is_active = ?, starts_at = ?, expires_at = ?
		WHERE id = ?`,
		discount.Description, discount.Type, discount.Value, discount.Currency,
		discount.MinPurchase, discount.MaxDiscount, discount.UsageLimit,
		discount.PerUserLimit, string(applicablePlansJSON), discount.IsActive,
		discount.StartsAt, discount.ExpiresAt, discount.ID,
	)

	return err
}

// DeleteDiscountCode deletes a discount code
func (pm *PaymentManager) DeleteDiscountCode(discountID string) error {
	_, err := pm.db.Exec("DELETE FROM discount_codes WHERE id = ?", discountID)
	return err
}

// GetAllDiscountCodes retrieves all discount codes
func (pm *PaymentManager) GetAllDiscountCodes(activeOnly bool) ([]*DiscountCode, error) {
	var discounts []*DiscountCode

	query := `SELECT 
		id, code, description, type, value, currency, min_purchase, max_discount,
		usage_limit, usage_count, per_user_limit, applicable_plans_json, admin_id,
		is_active, starts_at, expires_at, created_at
		FROM discount_codes`

	if activeOnly {
		query += " WHERE is_active = 1 AND expires_at > datetime('now')"
	}

	query += " ORDER BY created_at DESC"

	rows, err := pm.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		discount := &DiscountCode{}
		var applicablePlansJSON string

		err := rows.Scan(
			&discount.ID, &discount.Code, &discount.Description, &discount.Type, &discount.Value,
			&discount.Currency, &discount.MinPurchase, &discount.MaxDiscount,
			&discount.UsageLimit, &discount.UsageCount, &discount.PerUserLimit,
			&applicablePlansJSON, &discount.AdminID, &discount.IsActive,
			&discount.StartsAt, &discount.ExpiresAt, &discount.CreatedAt,
		)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(applicablePlansJSON), &discount.ApplicablePlans)
		discounts = append(discounts, discount)
	}

	return discounts, nil
}

// GenerateRandomDiscountCode generates a random discount code
func GenerateRandomDiscountCode(prefix string, length int) string {
	chars := "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	code := make([]byte, length)
	for i := range code {
		code[i] = chars[time.Now().UnixNano()%int64(len(chars))]
		time.Sleep(time.Nanosecond)
	}

	if prefix != "" {
		return prefix + "-" + string(code)
	}
	return string(code)
}

// ==================== Commission System ====================

// CreateCommissionRule creates a commission rule for an admin
func (pm *PaymentManager) CreateCommissionRule(rule *CommissionRule) error {
	rule.ID = uuid.New().String()
	rule.CreatedAt = time.Now()

	if rule.Value <= 0 {
		return errors.New("commission value must be positive")
	}

	if rule.Type != "percent" && rule.Type != "fixed" {
		return errors.New("commission type must be 'percent' or 'fixed'")
	}

	_, err := pm.db.Exec(`INSERT INTO commission_rules (
		id, admin_id, type, value, plan_id, min_sales, is_active, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rule.ID, rule.AdminID, rule.Type, rule.Value, rule.PlanID,
		rule.MinSales, rule.IsActive, rule.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create commission rule: %w", err)
	}

	return nil
}

// GetCommissionRules retrieves commission rules for an admin
func (pm *PaymentManager) GetCommissionRules(adminID string) ([]*CommissionRule, error) {
	var rules []*CommissionRule

	rows, err := pm.db.Query(`SELECT 
		id, admin_id, type, value, plan_id, min_sales, is_active, created_at
		FROM commission_rules WHERE admin_id = ? AND is_active = 1
		ORDER BY min_sales DESC`, adminID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		rule := &CommissionRule{}
		rows.Scan(
			&rule.ID, &rule.AdminID, &rule.Type, &rule.Value, &rule.PlanID,
			&rule.MinSales, &rule.IsActive, &rule.CreatedAt,
		)
		rules = append(rules, rule)
	}

	return rules, nil
}

// CalculateCommission calculates commission for an invoice
func (pm *PaymentManager) CalculateCommission(invoice *Invoice, adminID string) (float64, error) {
	if adminID == "" {
		return 0, nil
	}

	rules, err := pm.GetCommissionRules(adminID)
	if err != nil {
		return 0, err
	}

	if len(rules) == 0 {
		return 0, nil
	}

	// Get admin's total sales count
	var salesCount int
	pm.db.QueryRow(`SELECT COUNT(*) FROM invoices 
		WHERE admin_id = ? AND status = 'paid'`, adminID).Scan(&salesCount)

	// Find applicable rule (highest min_sales that qualifies)
	var applicableRule *CommissionRule
	for _, rule := range rules {
		if salesCount >= rule.MinSales {
			// Check if rule applies to specific plan
			if rule.PlanID != "" {
				hasMatchingPlan := false
				for _, item := range invoice.Items {
					if item.PlanID == rule.PlanID {
						hasMatchingPlan = true
						break
					}
				}
				if !hasMatchingPlan {
					continue
				}
			}
			applicableRule = rule
			break
		}
	}

	if applicableRule == nil {
		return 0, nil
	}

	// Calculate commission
	var commission float64
	if applicableRule.Type == "percent" {
		commission = invoice.Total * (applicableRule.Value / 100)
	} else {
		commission = applicableRule.Value
	}

	return commission, nil
}

// ProcessCommission processes commission payment for an invoice
func (pm *PaymentManager) ProcessCommission(invoice *Invoice) error {
	if invoice.AdminID == "" {
		return nil
	}

	commission, err := pm.CalculateCommission(invoice, invoice.AdminID)
	if err != nil || commission <= 0 {
		return err
	}

	// Get admin's wallet
	adminWallet, err := pm.GetWalletByAdmin(invoice.AdminID)
	if err != nil {
		return err
	}

	// Convert commission to admin's wallet currency if needed
	if adminWallet.Currency != invoice.Currency {
		commission, _ = pm.ConvertCurrency(commission, invoice.Currency, adminWallet.Currency)
	}

	// Create commission transaction
	tx, err := pm.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now()
	transaction := &Transaction{
		ID:            uuid.New().String(),
		WalletID:      adminWallet.ID,
		AdminID:       invoice.AdminID,
		Type:          TxTypeCommission,
		Status:        TxStatusCompleted,
		Amount:        commission,
		Currency:      adminWallet.Currency,
		BalanceBefore: adminWallet.Balance,
		BalanceAfter:  adminWallet.Balance + commission,
		ReferenceID:   invoice.ID,
		Description:   fmt.Sprintf("Commission for invoice %s", invoice.InvoiceNumber),
		CreatedAt:     now,
		CompletedAt:   &now,
	}

	_, err = tx.Exec(`INSERT INTO transactions (
		id, wallet_id, admin_id, type, status, amount, currency,
		balance_before, balance_after, reference_id, description, created_at, completed_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		transaction.ID, transaction.WalletID, transaction.AdminID, transaction.Type,
		transaction.Status, transaction.Amount, transaction.Currency,
		transaction.BalanceBefore, transaction.BalanceAfter, transaction.ReferenceID,
		transaction.Description, transaction.CreatedAt, transaction.CompletedAt,
	)
	if err != nil {
		return err
	}

	// Update admin wallet
	_, err = tx.Exec(`UPDATE wallets SET 
		balance = balance + ?, total_earned = total_earned + ?, updated_at = ? 
		WHERE id = ?`, commission, commission, now, adminWallet.ID)
	if err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return err
	}

	// Update cache
	adminWallet.Balance += commission
	adminWallet.TotalEarned += commission
	pm.walletCache.Store(adminWallet.ID, adminWallet)

	pm.emitEvent("commission_paid", "", invoice.AdminID, map[string]interface{}{
		"invoice_id": invoice.ID,
		"commission": commission,
	})

	return nil
}

// GetAdminCommissionStats retrieves commission statistics for an admin
func (pm *PaymentManager) GetAdminCommissionStats(adminID string) (*CommissionStats, error) {
	stats := &CommissionStats{
		AdminID: adminID,
	}

	// Total commission earned
	pm.db.QueryRow(`SELECT COALESCE(SUM(amount), 0) FROM transactions 
		WHERE admin_id = ? AND type = ?`, adminID, TxTypeCommission).Scan(&stats.TotalEarned)

	// This month's commission
	firstOfMonth := time.Now().AddDate(0, 0, -time.Now().Day()+1).Truncate(24 * time.Hour)
	pm.db.QueryRow(`SELECT COALESCE(SUM(amount), 0) FROM transactions 
		WHERE admin_id = ? AND type = ? AND created_at >= ?`,
		adminID, TxTypeCommission, firstOfMonth).Scan(&stats.ThisMonth)

	// Total sales count
	pm.db.QueryRow(`SELECT COUNT(*) FROM invoices 
		WHERE admin_id = ? AND status = 'paid'`, adminID).Scan(&stats.TotalSales)

	// This month's sales
	pm.db.QueryRow(`SELECT COUNT(*) FROM invoices 
		WHERE admin_id = ? AND status = 'paid' AND paid_at >= ?`,
		adminID, firstOfMonth).Scan(&stats.ThisMonthSales)

	// Average commission per sale
	if stats.TotalSales > 0 {
		stats.AvgPerSale = stats.TotalEarned / float64(stats.TotalSales)
	}

	// Get current commission rate
	rules, _ := pm.GetCommissionRules(adminID)
	if len(rules) > 0 {
		for _, rule := range rules {
			if stats.TotalSales >= rule.MinSales {
				stats.CurrentRate = rule.Value
				stats.CurrentRateType = rule.Type
				break
			}
		}
	}

	return stats, nil
}

// CommissionStats represents commission statistics
type CommissionStats struct {
	AdminID         string  `json:"admin_id"`
	TotalEarned     float64 `json:"total_earned"`
	ThisMonth       float64 `json:"this_month"`
	TotalSales      int     `json:"total_sales"`
	ThisMonthSales  int     `json:"this_month_sales"`
	AvgPerSale      float64 `json:"avg_per_sale"`
	CurrentRate     float64 `json:"current_rate"`
	CurrentRateType string  `json:"current_rate_type"`
}

// ==================== Subscription Activation ====================

// ActivateSubscriptionFromInvoice activates subscription after payment
func (pm *PaymentManager) ActivateSubscriptionFromInvoice(invoice *Invoice) error {
	for _, item := range invoice.Items {
		if item.Type != "subscription" || item.PlanID == "" {
			continue
		}

		plan, err := pm.GetPlan(item.PlanID)
		if err != nil {
			continue
		}

		// Here you would call UserManager to create or extend user subscription
		// This is a placeholder - actual implementation depends on your user system

		subscriptionData := map[string]interface{}{
			"user_id":          invoice.UserID,
			"plan_id":          plan.ID,
			"plan_name":        plan.Name,
			"duration_days":    plan.DurationDays,
			"traffic_gb":       plan.TrafficGB,
			"device_limit":     plan.DeviceLimit,
			"concurrent_limit": plan.ConcurrentLimit,
			"protocols":        plan.Protocols,
			"nodes":            plan.Nodes,
			"invoice_id":       invoice.ID,
			"admin_id":         invoice.AdminID,
		}

		pm.emitEvent("subscription_activated", invoice.UserID, invoice.AdminID, subscriptionData)
	}

	return nil
}

// ==================== Financial Reports ====================

// FinancialReport represents financial summary
type FinancialReport struct {
	Period          string                     `json:"period"`
	StartDate       time.Time                  `json:"start_date"`
	EndDate         time.Time                  `json:"end_date"`
	TotalRevenue    float64                    `json:"total_revenue"`
	TotalRefunds    float64                    `json:"total_refunds"`
	NetRevenue      float64                    `json:"net_revenue"`
	TotalCommission float64                    `json:"total_commission"`
	InvoiceCount    int                        `json:"invoice_count"`
	PaidCount       int                        `json:"paid_count"`
	RefundCount     int                        `json:"refund_count"`
	AvgOrderValue   float64                    `json:"avg_order_value"`
	Currency        Currency                   `json:"currency"`
	ByGateway       map[PaymentGateway]float64 `json:"by_gateway"`
	ByPlan          map[string]float64         `json:"by_plan"`
	DailyRevenue    []DailyRevenue             `json:"daily_revenue,omitempty"`
}

// DailyRevenue represents daily revenue data
type DailyRevenue struct {
	Date    string  `json:"date"`
	Revenue float64 `json:"revenue"`
	Count   int     `json:"count"`
}

// GenerateFinancialReport generates financial report for a period
func (pm *PaymentManager) GenerateFinancialReport(startDate, endDate time.Time, currency Currency) (*FinancialReport, error) {
	report := &FinancialReport{
		Period:    fmt.Sprintf("%s - %s", startDate.Format("2006-01-02"), endDate.Format("2006-01-02")),
		StartDate: startDate,
		EndDate:   endDate,
		Currency:  currency,
		ByGateway: make(map[PaymentGateway]float64),
		ByPlan:    make(map[string]float64),
	}

	// Total revenue from paid invoices
	pm.db.QueryRow(`SELECT COALESCE(SUM(paid_amount), 0), COUNT(*) FROM invoices 
		WHERE status = 'paid' AND currency = ? AND paid_at BETWEEN ? AND ?`,
		currency, startDate, endDate).Scan(&report.TotalRevenue, &report.PaidCount)

	// Total refunds
	pm.db.QueryRow(`SELECT COALESCE(SUM(ABS(amount)), 0), COUNT(*) FROM transactions 
		WHERE type = 'refund' AND currency = ? AND created_at BETWEEN ? AND ?`,
		currency, startDate, endDate).Scan(&report.TotalRefunds, &report.RefundCount)

	// Total commission paid
	pm.db.QueryRow(`SELECT COALESCE(SUM(amount), 0) FROM transactions 
		WHERE type = 'commission' AND currency = ? AND created_at BETWEEN ? AND ?`,
		currency, startDate, endDate).Scan(&report.TotalCommission)

	// Invoice count
	pm.db.QueryRow(`SELECT COUNT(*) FROM invoices 
		WHERE currency = ? AND created_at BETWEEN ? AND ?`,
		currency, startDate, endDate).Scan(&report.InvoiceCount)

	// Calculate net and average
	report.NetRevenue = report.TotalRevenue - report.TotalRefunds
	if report.PaidCount > 0 {
		report.AvgOrderValue = report.TotalRevenue / float64(report.PaidCount)
	}

	// Revenue by gateway
	rows, _ := pm.db.Query(`SELECT gateway, SUM(paid_amount) FROM invoices 
		WHERE status = 'paid' AND currency = ? AND paid_at BETWEEN ? AND ?
		GROUP BY gateway`, currency, startDate, endDate)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var gateway PaymentGateway
			var amount float64
			rows.Scan(&gateway, &amount)
			report.ByGateway[gateway] = amount
		}
	}

	// Revenue by plan (simplified)
	rows, _ = pm.db.Query(`SELECT items_json, paid_amount FROM invoices 
		WHERE status = 'paid' AND currency = ? AND paid_at BETWEEN ? AND ?`,
		currency, startDate, endDate)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var itemsJSON string
			var amount float64
			rows.Scan(&itemsJSON, &amount)

			var items []InvoiceItem
			json.Unmarshal([]byte(itemsJSON), &items)

			for _, item := range items {
				if item.PlanID != "" {
					report.ByPlan[item.PlanID] += amount
				}
			}
		}
	}

	// Daily revenue
	days := int(endDate.Sub(startDate).Hours() / 24)
	if days <= 90 { // Only for periods up to 90 days
		rows, _ := pm.db.Query(`SELECT DATE(paid_at), SUM(paid_amount), COUNT(*) FROM invoices 
			WHERE status = 'paid' AND currency = ? AND paid_at BETWEEN ? AND ?
			GROUP BY DATE(paid_at) ORDER BY DATE(paid_at)`, currency, startDate, endDate)
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var dr DailyRevenue
				rows.Scan(&dr.Date, &dr.Revenue, &dr.Count)
				report.DailyRevenue = append(report.DailyRevenue, dr)
			}
		}
	}

	return report, nil
}

// GetTopSellingPlans returns top selling plans
func (pm *PaymentManager) GetTopSellingPlans(limit int, startDate, endDate time.Time) ([]map[string]interface{}, error) {
	var results []map[string]interface{}

	rows, err := pm.db.Query(`SELECT items_json, paid_amount FROM invoices 
		WHERE status = 'paid' AND paid_at BETWEEN ? AND ?`, startDate, endDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	planStats := make(map[string]struct {
		count   int
		revenue float64
	})

	for rows.Next() {
		var itemsJSON string
		var amount float64
		rows.Scan(&itemsJSON, &amount)

		var items []InvoiceItem
		json.Unmarshal([]byte(itemsJSON), &items)

		for _, item := range items {
			if item.PlanID != "" {
				stats := planStats[item.PlanID]
				stats.count++
				stats.revenue += amount
				planStats[item.PlanID] = stats
			}
		}
	}

	// Sort by count
	type planStat struct {
		id      string
		count   int
		revenue float64
	}

	var sorted []planStat
	for id, stats := range planStats {
		sorted = append(sorted, planStat{id, stats.count, stats.revenue})
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})

	if limit > len(sorted) {
		limit = len(sorted)
	}

	for i := 0; i < limit; i++ {
		plan, err := pm.GetPlan(sorted[i].id)
		planName := sorted[i].id
		if err == nil {
			planName = plan.Name
		}

		results = append(results, map[string]interface{}{
			"plan_id":   sorted[i].id,
			"plan_name": planName,
			"count":     sorted[i].count,
			"revenue":   sorted[i].revenue,
		})
	}

	return results, nil
}

// Core/payment.go
// MXUI VPN Panel - Payment & Financial System
// Part 3: Payment Gateways, Webhooks, API Handlers, Notifications

// ==================== Gateway Handlers ====================

// BaseGatewayHandler provides common gateway functionality
type BaseGatewayHandler struct {
	config PaymentGatewayConfig
}

func (h *BaseGatewayHandler) Name() string {
	return h.config.Name
}

func (h *BaseGatewayHandler) SupportedCurrencies() []Currency {
	return h.config.Currencies
}

// ==================== Zarinpal Gateway ====================

// ZarinpalHandler handles Zarinpal payments
type ZarinpalHandler struct {
	BaseGatewayHandler
	merchantID string
	sandbox    bool
}

// ZarinpalRequest represents Zarinpal API request
type ZarinpalRequest struct {
	MerchantID  string `json:"merchant_id"`
	Amount      int    `json:"amount"`
	CallbackURL string `json:"callback_url"`
	Description string `json:"description"`
	Mobile      string `json:"mobile,omitempty"`
	Email       string `json:"email,omitempty"`
}

// ZarinpalResponse represents Zarinpal API response
type ZarinpalResponse struct {
	Data struct {
		Code      int    `json:"code"`
		Message   string `json:"message"`
		Authority string `json:"authority"`
		FeeType   string `json:"fee_type"`
		Fee       int    `json:"fee"`
	} `json:"data"`
	Errors []interface{} `json:"errors"`
}

// ZarinpalVerifyRequest for verification
type ZarinpalVerifyRequest struct {
	MerchantID string `json:"merchant_id"`
	Amount     int    `json:"amount"`
	Authority  string `json:"authority"`
}

// ZarinpalVerifyResponse for verification response
type ZarinpalVerifyResponse struct {
	Data struct {
		Code     int    `json:"code"`
		Message  string `json:"message"`
		CardHash string `json:"card_hash"`
		CardPan  string `json:"card_pan"`
		RefID    int64  `json:"ref_id"`
		FeeType  string `json:"fee_type"`
		Fee      int    `json:"fee"`
	} `json:"data"`
	Errors []interface{} `json:"errors"`
}

// NewZarinpalHandler creates new Zarinpal handler
func NewZarinpalHandler(config PaymentGatewayConfig) *ZarinpalHandler {
	merchantID, _ := config.Config["merchant_id"].(string)
	sandbox, _ := config.Config["sandbox"].(bool)

	return &ZarinpalHandler{
		BaseGatewayHandler: BaseGatewayHandler{config: config},
		merchantID:         merchantID,
		sandbox:            sandbox,
	}
}

func (h *ZarinpalHandler) getBaseURL() string {
	if h.sandbox {
		return "https://sandbox.zarinpal.com/pg/v4/payment"
	}
	return "https://api.zarinpal.com/pg/v4/payment"
}

func (h *ZarinpalHandler) getPaymentURL() string {
	if h.sandbox {
		return "https://sandbox.zarinpal.com/pg/StartPay/"
	}
	return "https://www.zarinpal.com/pg/StartPay/"
}

// CreatePayment creates a Zarinpal payment
func (h *ZarinpalHandler) CreatePayment(ctx context.Context, invoice *Invoice) (*PaymentSession, error) {
	// Convert to Rial (Zarinpal uses Rial)
	amount := int(invoice.Total)
	if invoice.Currency == CurrencyIRR {
		// Already in Rial
	} else {
		// Convert to IRR - this is simplified
		amount = int(invoice.Total * 10) // Toman to Rial
	}

	reqBody := ZarinpalRequest{
		MerchantID:  h.merchantID,
		Amount:      amount,
		CallbackURL: h.config.CallbackURL + "?invoice_id=" + invoice.ID,
		Description: fmt.Sprintf("Payment for invoice %s", invoice.InvoiceNumber),
	}

	jsonBody, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, "POST", h.getBaseURL()+"/request.json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("zarinpal request failed: %w", err)
	}
	defer resp.Body.Close()

	var result ZarinpalResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if result.Data.Code != 100 {
		return nil, fmt.Errorf("zarinpal error: %s", result.Data.Message)
	}

	return &PaymentSession{
		InvoiceID:  invoice.ID,
		UserID:     invoice.UserID,
		Gateway:    GatewayZarinpal,
		Amount:     invoice.Total,
		Currency:   invoice.Currency,
		Status:     "pending",
		PaymentURL: h.getPaymentURL() + result.Data.Authority,
		GatewayData: map[string]interface{}{
			"authority": result.Data.Authority,
			"amount":    amount,
		},
	}, nil
}

// VerifyPayment verifies Zarinpal payment
func (h *ZarinpalHandler) VerifyPayment(ctx context.Context, session *PaymentSession, data map[string]string) (bool, error) {
	authority := data["Authority"]
	status := data["Status"]

	if status != "OK" {
		return false, errors.New("payment was not successful")
	}

	amount, _ := session.GatewayData["amount"].(float64)

	reqBody := ZarinpalVerifyRequest{
		MerchantID: h.merchantID,
		Amount:     int(amount),
		Authority:  authority,
	}

	jsonBody, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, "POST", h.getBaseURL()+"/verify.json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result ZarinpalVerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	if result.Data.Code != 100 && result.Data.Code != 101 {
		return false, fmt.Errorf("verification failed: %s", result.Data.Message)
	}

	// Update session with RefID
	session.GatewayData["ref_id"] = result.Data.RefID
	session.GatewayData["card_pan"] = result.Data.CardPan

	return true, nil
}

// RefundPayment refunds a Zarinpal payment (not fully supported by Zarinpal)
func (h *ZarinpalHandler) RefundPayment(ctx context.Context, transaction *Transaction) error {
	return errors.New("zarinpal does not support automatic refunds")
}

// GetStatus gets payment status
func (h *ZarinpalHandler) GetStatus(ctx context.Context, session *PaymentSession) (string, error) {
	return session.Status, nil
}

// ParseWebhook parses Zarinpal webhook (callback)
func (h *ZarinpalHandler) ParseWebhook(r *http.Request) (map[string]interface{}, error) {
	return map[string]interface{}{
		"Authority": r.URL.Query().Get("Authority"),
		"Status":    r.URL.Query().Get("Status"),
	}, nil
}

// ==================== Stripe Gateway ====================

// StripeHandler handles Stripe payments
type StripeHandler struct {
	BaseGatewayHandler
	secretKey     string
	webhookSecret string
}

// NewStripeHandler creates new Stripe handler
func NewStripeHandler(config PaymentGatewayConfig) *StripeHandler {
	secretKey, _ := config.Config["secret_key"].(string)
	webhookSecret, _ := config.Config["webhook_secret"].(string)

	return &StripeHandler{
		BaseGatewayHandler: BaseGatewayHandler{config: config},
		secretKey:          secretKey,
		webhookSecret:      webhookSecret,
	}
}

// CreatePayment creates a Stripe payment session
func (h *StripeHandler) CreatePayment(ctx context.Context, invoice *Invoice) (*PaymentSession, error) {
	// Stripe amount is in cents
	amount := int64(invoice.Total * 100)

	// Build line items
	lineItems := make([]map[string]interface{}, 0)
	for _, item := range invoice.Items {
		lineItems = append(lineItems, map[string]interface{}{
			"price_data": map[string]interface{}{
				"currency": strings.ToLower(string(invoice.Currency)),
				"product_data": map[string]interface{}{
					"name":        item.Name,
					"description": item.Description,
				},
				"unit_amount": int64(item.UnitPrice * 100),
			},
			"quantity": item.Quantity,
		})
	}

	reqBody := map[string]interface{}{
		"mode":                "payment",
		"success_url":         h.config.CallbackURL + "?session_id={CHECKOUT_SESSION_ID}&status=success",
		"cancel_url":          h.config.CallbackURL + "?session_id={CHECKOUT_SESSION_ID}&status=cancel",
		"line_items":          lineItems,
		"client_reference_id": invoice.ID,
		"customer_email":      "", // Add if available
		"metadata": map[string]string{
			"invoice_id":     invoice.ID,
			"invoice_number": invoice.InvoiceNumber,
		},
	}

	jsonBody, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.stripe.com/v1/checkout/sessions", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+h.secretKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stripe request failed: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if errMsg, ok := result["error"].(map[string]interface{}); ok {
		return nil, fmt.Errorf("stripe error: %v", errMsg["message"])
	}

	sessionID, _ := result["id"].(string)
	paymentURL, _ := result["url"].(string)

	return &PaymentSession{
		InvoiceID:  invoice.ID,
		UserID:     invoice.UserID,
		Gateway:    GatewayStripe,
		Amount:     invoice.Total,
		Currency:   invoice.Currency,
		Status:     "pending",
		PaymentURL: paymentURL,
		GatewayData: map[string]interface{}{
			"session_id": sessionID,
			"amount":     amount,
		},
	}, nil
}

// VerifyPayment verifies Stripe payment
func (h *StripeHandler) VerifyPayment(ctx context.Context, session *PaymentSession, data map[string]string) (bool, error) {
	sessionID := data["session_id"]
	status := data["status"]

	if status == "cancel" {
		return false, errors.New("payment was cancelled")
	}

	// Retrieve session from Stripe
	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://api.stripe.com/v1/checkout/sessions/"+sessionID, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", "Bearer "+h.secretKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	paymentStatus, _ := result["payment_status"].(string)
	if paymentStatus != "paid" {
		return false, errors.New("payment not completed")
	}

	// Get payment intent for transaction ID
	paymentIntent, _ := result["payment_intent"].(string)
	session.GatewayData["payment_intent"] = paymentIntent

	return true, nil
}

// RefundPayment refunds a Stripe payment
func (h *StripeHandler) RefundPayment(ctx context.Context, transaction *Transaction) error {
	paymentIntent, ok := transaction.Meta["payment_intent"].(string)
	if !ok {
		return errors.New("payment intent not found")
	}

	reqBody := map[string]interface{}{
		"payment_intent": paymentIntent,
	}

	jsonBody, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.stripe.com/v1/refunds", bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+h.secretKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if errMsg, ok := result["error"].(map[string]interface{}); ok {
		return fmt.Errorf("refund failed: %v", errMsg["message"])
	}

	return nil
}

// GetStatus gets Stripe payment status
func (h *StripeHandler) GetStatus(ctx context.Context, session *PaymentSession) (string, error) {
	sessionID, _ := session.GatewayData["session_id"].(string)

	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://api.stripe.com/v1/checkout/sessions/"+sessionID, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+h.secretKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	status, _ := result["payment_status"].(string)
	return status, nil
}

// ParseWebhook parses Stripe webhook
func (h *StripeHandler) ParseWebhook(r *http.Request) (map[string]interface{}, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	// Verify webhook signature
	signature := r.Header.Get("Stripe-Signature")
	if h.webhookSecret != "" && signature != "" {
		// Simple signature verification - in production use stripe-go library
		if !h.verifyWebhookSignature(body, signature) {
			return nil, errors.New("invalid webhook signature")
		}
	}

	var event map[string]interface{}
	if err := json.Unmarshal(body, &event); err != nil {
		return nil, err
	}

	return event, nil
}

func (h *StripeHandler) verifyWebhookSignature(payload []byte, signature string) bool {
	// Simplified - in production use proper signature verification
	parts := strings.Split(signature, ",")
	var timestamp, sig string

	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			switch kv[0] {
			case "t":
				timestamp = kv[1]
			case "v1":
				sig = kv[1]
			}
		}
	}

	signedPayload := timestamp + "." + string(payload)
	expectedSig := hmacSHA256String(signedPayload, h.webhookSecret)

	return hmac.Equal([]byte(sig), []byte(expectedSig))
}

func hmacSHA256String(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// ==================== NowPayments (Crypto) Gateway ====================

// NowPaymentsHandler handles cryptocurrency payments
type NowPaymentsHandler struct {
	BaseGatewayHandler
	apiKey    string
	ipnSecret string
}

// NewNowPaymentsHandler creates new NowPayments handler
func NewNowPaymentsHandler(config PaymentGatewayConfig) *NowPaymentsHandler {
	apiKey, _ := config.Config["api_key"].(string)
	ipnSecret, _ := config.Config["ipn_secret"].(string)

	return &NowPaymentsHandler{
		BaseGatewayHandler: BaseGatewayHandler{config: config},
		apiKey:             apiKey,
		ipnSecret:          ipnSecret,
	}
}

// CreatePayment creates a NowPayments invoice
func (h *NowPaymentsHandler) CreatePayment(ctx context.Context, invoice *Invoice) (*PaymentSession, error) {
	// Convert to USD if not already
	amount := invoice.Total
	currency := invoice.Currency

	if currency != CurrencyUSD {
		// NowPayments prefers USD
		// In production, convert properly
	}

	reqBody := map[string]interface{}{
		"price_amount":      amount,
		"price_currency":    strings.ToLower(string(currency)),
		"order_id":          invoice.ID,
		"order_description": fmt.Sprintf("Invoice %s", invoice.InvoiceNumber),
		"ipn_callback_url":  h.config.WebhookURL,
		"success_url":       h.config.CallbackURL + "?status=success&invoice_id=" + invoice.ID,
		"cancel_url":        h.config.CallbackURL + "?status=cancel&invoice_id=" + invoice.ID,
	}

	jsonBody, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.nowpayments.io/v1/invoice", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("x-api-key", h.apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nowpayments request failed: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if errMsg, ok := result["message"].(string); ok && result["id"] == nil {
		return nil, fmt.Errorf("nowpayments error: %s", errMsg)
	}

	invoiceID, _ := result["id"].(string)
	invoiceURL, _ := result["invoice_url"].(string)

	return &PaymentSession{
		InvoiceID:  invoice.ID,
		UserID:     invoice.UserID,
		Gateway:    GatewayNowPayments,
		Amount:     invoice.Total,
		Currency:   invoice.Currency,
		Status:     "pending",
		PaymentURL: invoiceURL,
		GatewayData: map[string]interface{}{
			"nowpayments_id": invoiceID,
			"amount":         amount,
		},
	}, nil
}

// VerifyPayment verifies NowPayments payment (usually via IPN)
func (h *NowPaymentsHandler) VerifyPayment(ctx context.Context, session *PaymentSession, data map[string]string) (bool, error) {
	paymentID := data["payment_id"]

	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://api.nowpayments.io/v1/payment/"+paymentID, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("x-api-key", h.apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	status, _ := result["payment_status"].(string)

	// Confirmed statuses
	confirmedStatuses := map[string]bool{
		"finished":       true,
		"confirmed":      true,
		"sending":        true,
		"partially_paid": true,
	}

	if !confirmedStatuses[status] {
		return false, fmt.Errorf("payment status: %s", status)
	}

	session.GatewayData["payment_id"] = paymentID
	session.GatewayData["payment_status"] = status

	return true, nil
}

// RefundPayment - NowPayments doesn't support automatic refunds
func (h *NowPaymentsHandler) RefundPayment(ctx context.Context, transaction *Transaction) error {
	return errors.New("crypto payments cannot be automatically refunded")
}

// GetStatus gets NowPayments payment status
func (h *NowPaymentsHandler) GetStatus(ctx context.Context, session *PaymentSession) (string, error) {
	nowpaymentsID, _ := session.GatewayData["nowpayments_id"].(string)

	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://api.nowpayments.io/v1/invoice/"+nowpaymentsID, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("x-api-key", h.apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	status, _ := result["payment_status"].(string)
	return status, nil
}

// ParseWebhook parses NowPayments IPN
func (h *NowPaymentsHandler) ParseWebhook(r *http.Request) (map[string]interface{}, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	// Verify IPN signature
	signature := r.Header.Get("x-nowpayments-sig")
	if h.ipnSecret != "" && signature != "" {
		// Sort and hash for verification
		var data map[string]interface{}
		json.Unmarshal(body, &data)

		// Verify signature (simplified)
		expectedSig := hmacSHA512(string(body), h.ipnSecret)
		if signature != expectedSig {
			return nil, errors.New("invalid IPN signature")
		}
	}

	var result map[string]interface{}
	json.Unmarshal(body, &result)

	return result, nil
}

func hmacSHA512(data, secret string) string {
	h := hmac.New(sha512.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// ==================== Card-to-Card Gateway ====================

// CardToCardHandler handles card-to-card payments (manual verification)
type CardToCardHandler struct {
	BaseGatewayHandler
	cardNumber   string
	cardHolder   string
	bankName     string
	instructions string
}

// NewCardToCardHandler creates new card-to-card handler
func NewCardToCardHandler(config PaymentGatewayConfig) *CardToCardHandler {
	cardNumber, _ := config.Config["card_number"].(string)
	cardHolder, _ := config.Config["card_holder"].(string)
	bankName, _ := config.Config["bank_name"].(string)
	instructions, _ := config.Config["instructions"].(string)

	return &CardToCardHandler{
		BaseGatewayHandler: BaseGatewayHandler{config: config},
		cardNumber:         cardNumber,
		cardHolder:         cardHolder,
		bankName:           bankName,
		instructions:       instructions,
	}
}

// CreatePayment creates card-to-card payment info
func (h *CardToCardHandler) CreatePayment(ctx context.Context, invoice *Invoice) (*PaymentSession, error) {
	// Generate unique payment code
	paymentCode := fmt.Sprintf("%d", time.Now().UnixNano()%1000000)

	paymentInfo := map[string]interface{}{
		"card_number":  h.cardNumber,
		"card_holder":  h.cardHolder,
		"bank_name":    h.bankName,
		"amount":       invoice.Total,
		"currency":     invoice.Currency,
		"payment_code": paymentCode,
		"instructions": h.instructions,
		"invoice_id":   invoice.ID,
	}

	return &PaymentSession{
		InvoiceID:   invoice.ID,
		UserID:      invoice.UserID,
		Gateway:     GatewayCard,
		Amount:      invoice.Total,
		Currency:    invoice.Currency,
		Status:      "awaiting_transfer",
		PaymentURL:  "", // No URL, show card info in app
		GatewayData: paymentInfo,
	}, nil
}

// VerifyPayment - requires manual admin verification
func (h *CardToCardHandler) VerifyPayment(ctx context.Context, session *PaymentSession, data map[string]string) (bool, error) {
	// This should be verified manually by admin
	// data should contain tracking number or receipt image reference

	trackingNumber := data["tracking_number"]
	if trackingNumber == "" {
		return false, errors.New("tracking number required")
	}

	session.GatewayData["tracking_number"] = trackingNumber
	session.GatewayData["verified_at"] = time.Now().Format(time.RFC3339)

	// In real scenario, this would require admin approval
	// For now, we mark it as pending verification
	session.Status = "pending_verification"

	return false, errors.New("payment requires admin verification")
}

// RefundPayment - manual refund
func (h *CardToCardHandler) RefundPayment(ctx context.Context, transaction *Transaction) error {
	return errors.New("card-to-card refunds must be processed manually")
}

// GetStatus returns current status
func (h *CardToCardHandler) GetStatus(ctx context.Context, session *PaymentSession) (string, error) {
	return session.Status, nil
}

// ParseWebhook - not applicable for card-to-card
func (h *CardToCardHandler) ParseWebhook(r *http.Request) (map[string]interface{}, error) {
	return nil, errors.New("card-to-card does not support webhooks")
}

// ==================== Manual Gateway ====================

// ManualHandler handles manual/offline payments
type ManualHandler struct {
	BaseGatewayHandler
	instructions string
}

// NewManualHandler creates new manual handler
func NewManualHandler(config PaymentGatewayConfig) *ManualHandler {
	instructions, _ := config.Config["instructions"].(string)

	return &ManualHandler{
		BaseGatewayHandler: BaseGatewayHandler{config: config},
		instructions:       instructions,
	}
}

// CreatePayment creates manual payment request
func (h *ManualHandler) CreatePayment(ctx context.Context, invoice *Invoice) (*PaymentSession, error) {
	return &PaymentSession{
		InvoiceID:  invoice.ID,
		UserID:     invoice.UserID,
		Gateway:    GatewayManual,
		Amount:     invoice.Total,
		Currency:   invoice.Currency,
		Status:     "pending",
		PaymentURL: "",
		GatewayData: map[string]interface{}{
			"instructions": h.instructions,
			"invoice_id":   invoice.ID,
		},
	}, nil
}

// VerifyPayment - admin verifies manually
func (h *ManualHandler) VerifyPayment(ctx context.Context, session *PaymentSession, data map[string]string) (bool, error) {
	adminVerified := data["admin_verified"]
	if adminVerified != "true" {
		return false, errors.New("requires admin verification")
	}
	return true, nil
}

// RefundPayment - manual
func (h *ManualHandler) RefundPayment(ctx context.Context, transaction *Transaction) error {
	return errors.New("manual refund required")
}

// GetStatus returns status
func (h *ManualHandler) GetStatus(ctx context.Context, session *PaymentSession) (string, error) {
	return session.Status, nil
}

// ParseWebhook - not applicable
func (h *ManualHandler) ParseWebhook(r *http.Request) (map[string]interface{}, error) {
	return nil, errors.New("manual payments do not support webhooks")
}

// ==================== IDPay Gateway ====================

// IDPayHandler handles IDPay payments (Iranian gateway)
type IDPayHandler struct {
	BaseGatewayHandler
	apiKey  string
	sandbox bool
}

// NewIDPayHandler creates new IDPay handler
func NewIDPayHandler(config PaymentGatewayConfig) *IDPayHandler {
	apiKey, _ := config.Config["api_key"].(string)
	sandbox, _ := config.Config["sandbox"].(bool)

	return &IDPayHandler{
		BaseGatewayHandler: BaseGatewayHandler{config: config},
		apiKey:             apiKey,
		sandbox:            sandbox,
	}
}

func (h *IDPayHandler) getBaseURL() string {
	if h.sandbox {
		return "https://api.idpay.ir/v1.1/payment"
	}
	return "https://api.idpay.ir/v1.1/payment"
}

// CreatePayment creates IDPay payment
func (h *IDPayHandler) CreatePayment(ctx context.Context, invoice *Invoice) (*PaymentSession, error) {
	amount := int(invoice.Total)
	if invoice.Currency == CurrencyIRR {
		amount = int(invoice.Total / 10) // Rial to Toman
	}

	reqBody := map[string]interface{}{
		"order_id": invoice.ID,
		"amount":   amount,
		"callback": h.config.CallbackURL,
		"desc":     fmt.Sprintf("Ù¾Ø±Ø¯Ø§Ø®Øª ÙØ§Ú©ØªÙˆØ± %s", invoice.InvoiceNumber),
	}

	jsonBody, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, "POST", h.getBaseURL(), bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-API-KEY", h.apiKey)
	req.Header.Set("Content-Type", "application/json")
	if h.sandbox {
		req.Header.Set("X-SANDBOX", "1")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if errCode, ok := result["error_code"].(float64); ok && errCode != 0 {
		errMsg, _ := result["error_message"].(string)
		return nil, fmt.Errorf("idpay error: %s", errMsg)
	}

	id, _ := result["id"].(string)
	link, _ := result["link"].(string)

	return &PaymentSession{
		InvoiceID:  invoice.ID,
		UserID:     invoice.UserID,
		Gateway:    GatewayIdpay,
		Amount:     invoice.Total,
		Currency:   invoice.Currency,
		Status:     "pending",
		PaymentURL: link,
		GatewayData: map[string]interface{}{
			"idpay_id": id,
			"amount":   amount,
		},
	}, nil
}

// VerifyPayment verifies IDPay payment
func (h *IDPayHandler) VerifyPayment(ctx context.Context, session *PaymentSession, data map[string]string) (bool, error) {
	status := data["status"]
	id := data["id"]
	orderId := data["order_id"]

	if status != "10" {
		return false, errors.New("payment not successful")
	}

	amount, _ := session.GatewayData["amount"].(float64)

	reqBody := map[string]interface{}{
		"id":       id,
		"order_id": orderId,
	}

	jsonBody, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, "POST", h.getBaseURL()+"/verify", bytes.NewBuffer(jsonBody))
	if err != nil {
		return false, err
	}

	req.Header.Set("X-API-KEY", h.apiKey)
	req.Header.Set("Content-Type", "application/json")
	if h.sandbox {
		req.Header.Set("X-SANDBOX", "1")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if errCode, ok := result["error_code"].(float64); ok && errCode != 0 {
		errMsg, _ := result["error_message"].(string)
		return false, fmt.Errorf("verification failed: %s", errMsg)
	}

	verifyAmount, _ := result["amount"].(float64)
	if int(verifyAmount) != int(amount) {
		return false, errors.New("amount mismatch")
	}

	trackID, _ := result["track_id"].(string)
	session.GatewayData["track_id"] = trackID

	return true, nil
}

// RefundPayment - not supported
func (h *IDPayHandler) RefundPayment(ctx context.Context, transaction *Transaction) error {
	return errors.New("idpay refunds must be processed manually")
}

// GetStatus returns status
func (h *IDPayHandler) GetStatus(ctx context.Context, session *PaymentSession) (string, error) {
	return session.Status, nil
}

// ParseWebhook parses IDPay callback
func (h *IDPayHandler) ParseWebhook(r *http.Request) (map[string]interface{}, error) {
	r.ParseForm()
	return map[string]interface{}{
		"id":       r.FormValue("id"),
		"order_id": r.FormValue("order_id"),
		"status":   r.FormValue("status"),
		"track_id": r.FormValue("track_id"),
		"amount":   r.FormValue("amount"),
	}, nil
}

// ==================== Payment Notifications ====================

// PaymentNotifier handles payment notifications
type PaymentNotifier struct {
	db          *sql.DB
	telegramBot *TelegramBot // Reference to bot
	emailSender EmailSender
}

// EmailSender interface for sending emails
type EmailSender interface {
	SendEmail(to, subject, body string) error
}

// NewPaymentNotifier creates new notifier
func NewPaymentNotifier(db *sql.DB, bot *TelegramBot, emailSender EmailSender) *PaymentNotifier {
	return &PaymentNotifier{
		db:          db,
		telegramBot: bot,
		emailSender: emailSender,
	}
}

// NotifyPaymentReceived notifies about received payment
func (pn *PaymentNotifier) NotifyPaymentReceived(invoice *Invoice, transaction *Transaction) {
	// Notify user via Telegram
	if pn.telegramBot != nil {
		userChatID := pn.getUserTelegramChatID(invoice.UserID)
		if userChatID != 0 {
			message := fmt.Sprintf(`âœ… Ù¾Ø±Ø¯Ø§Ø®Øª Ø¨Ø§ Ù…ÙˆÙÙ‚ÛŒØª Ø§Ù†Ø¬Ø§Ù… Ø´Ø¯

ðŸ“‹ Ø´Ù…Ø§Ø±Ù‡ ÙØ§Ú©ØªÙˆØ±: %s
ðŸ’° Ù…Ø¨Ù„Øº: %s
ðŸ“… ØªØ§Ø±ÛŒØ®: %s

Ø§Ø² Ø®Ø±ÛŒØ¯ Ø´Ù…Ø§ Ù…ØªØ´Ú©Ø±ÛŒÙ…!`,
				invoice.InvoiceNumber,
				FormatCurrency(invoice.Total, invoice.Currency),
				time.Now().Format("2006-01-02 15:04"),
			)
			pn.telegramBot.SendMessage(userChatID, message, nil)
		}
	}

	// Notify admin
	pn.notifyAdminNewPayment(invoice)
}

// NotifyPaymentFailed notifies about failed payment
func (pn *PaymentNotifier) NotifyPaymentFailed(invoice *Invoice, reason string) {
	if pn.telegramBot != nil {
		userChatID := pn.getUserTelegramChatID(invoice.UserID)
		if userChatID != 0 {
			message := fmt.Sprintf(`âŒ Ù¾Ø±Ø¯Ø§Ø®Øª Ù†Ø§Ù…ÙˆÙÙ‚

ðŸ“‹ Ø´Ù…Ø§Ø±Ù‡ ÙØ§Ú©ØªÙˆØ±: %s
ðŸ’° Ù…Ø¨Ù„Øº: %s
ðŸ“ Ø¯Ù„ÛŒÙ„: %s

Ù„Ø·ÙØ§Ù‹ Ù…Ø¬Ø¯Ø¯Ø§Ù‹ ØªÙ„Ø§Ø´ Ú©Ù†ÛŒØ¯.`,
				invoice.InvoiceNumber,
				FormatCurrency(invoice.Total, invoice.Currency),
				reason,
			)
			pn.telegramBot.SendMessage(userChatID, message, nil)
		}
	}
}

// NotifySubscriptionActivated notifies about activated subscription
func (pn *PaymentNotifier) NotifySubscriptionActivated(userID string, plan *SubscriptionPlan) {
	if pn.telegramBot != nil {
		userChatID := pn.getUserTelegramChatID(userID)
		if userChatID != 0 {
			message := fmt.Sprintf(`ðŸŽ‰ Ø§Ø´ØªØ±Ø§Ú© Ø´Ù…Ø§ ÙØ¹Ø§Ù„ Ø´Ø¯!

ðŸ“¦ Ù¾Ù„Ù†: %s
â± Ù…Ø¯Øª: %d Ø±ÙˆØ²
ðŸ“Š ØªØ±Ø§ÙÛŒÚ©: %d GB
ðŸ“± Ø¯Ø³ØªÚ¯Ø§Ù‡â€ŒÙ‡Ø§: %d

Ø¨Ø±Ø§ÛŒ Ø¯Ø±ÛŒØ§ÙØª Ù„ÛŒÙ†Ú© Ø§ØªØµØ§Ù„ Ø§Ø² Ù…Ù†ÙˆÛŒ Ø§ØµÙ„ÛŒ Ø§Ø³ØªÙØ§Ø¯Ù‡ Ú©Ù†ÛŒØ¯.`,
				plan.Name,
				plan.DurationDays,
				plan.TrafficGB,
				plan.DeviceLimit,
			)
			pn.telegramBot.SendMessage(userChatID, message, nil)
		}
	}
}

// NotifyRefundProcessed notifies about refund
func (pn *PaymentNotifier) NotifyRefundProcessed(invoice *Invoice, amount float64) {
	if pn.telegramBot != nil {
		userChatID := pn.getUserTelegramChatID(invoice.UserID)
		if userChatID != 0 {
			message := fmt.Sprintf(`ðŸ’¸ Ø¨Ø§Ø²Ù¾Ø±Ø¯Ø§Ø®Øª Ø§Ù†Ø¬Ø§Ù… Ø´Ø¯

ðŸ“‹ Ø´Ù…Ø§Ø±Ù‡ ÙØ§Ú©ØªÙˆØ±: %s
ðŸ’° Ù…Ø¨Ù„Øº Ø¨Ø§Ø²Ú¯Ø´ØªÛŒ: %s

Ù…Ø¨Ù„Øº Ø¨Ù‡ Ú©ÛŒÙ Ù¾ÙˆÙ„ Ø´Ù…Ø§ ÙˆØ§Ø±ÛŒØ² Ø´Ø¯.`,
				invoice.InvoiceNumber,
				FormatCurrency(amount, invoice.Currency),
			)
			pn.telegramBot.SendMessage(userChatID, message, nil)
		}
	}
}

// NotifyInvoiceExpiring notifies about expiring invoice
func (pn *PaymentNotifier) NotifyInvoiceExpiring(invoice *Invoice) {
	if pn.telegramBot != nil {
		userChatID := pn.getUserTelegramChatID(invoice.UserID)
		if userChatID != 0 {
			message := fmt.Sprintf(`â° ÙØ§Ú©ØªÙˆØ± Ø¯Ø± Ø­Ø§Ù„ Ø§Ù†Ù‚Ø¶Ø§

ðŸ“‹ Ø´Ù…Ø§Ø±Ù‡ ÙØ§Ú©ØªÙˆØ±: %s
ðŸ’° Ù…Ø¨Ù„Øº: %s
â± Ù…Ù‡Ù„Øª Ù¾Ø±Ø¯Ø§Ø®Øª: %s

Ù„Ø·ÙØ§Ù‹ Ù‚Ø¨Ù„ Ø§Ø² Ø§Ù†Ù‚Ø¶Ø§ Ù¾Ø±Ø¯Ø§Ø®Øª Ú©Ù†ÛŒØ¯.`,
				invoice.InvoiceNumber,
				FormatCurrency(invoice.Total, invoice.Currency),
				invoice.DueDate.Format("2006-01-02 15:04"),
			)
			pn.telegramBot.SendMessage(userChatID, message, nil)
		}
	}
}

// NotifyCommissionEarned notifies admin about commission
func (pn *PaymentNotifier) NotifyCommissionEarned(adminID string, amount float64, currency Currency) {
	if pn.telegramBot != nil {
		adminChatID := pn.getAdminTelegramChatID(adminID)
		if adminChatID != 0 {
			message := fmt.Sprintf(`ðŸ’° Ú©Ù…ÛŒØ³ÛŒÙˆÙ† Ø¯Ø±ÛŒØ§ÙØª Ø´Ø¯!

Ù…Ø¨Ù„Øº: %s
Ø¨Ù‡ Ú©ÛŒÙ Ù¾ÙˆÙ„ Ø´Ù…Ø§ Ø§Ø¶Ø§ÙÙ‡ Ø´Ø¯.`,
				FormatCurrency(amount, currency),
			)
			pn.telegramBot.SendMessage(adminChatID, message, nil)
		}
	}
}

func (pn *PaymentNotifier) notifyAdminNewPayment(invoice *Invoice) {
	// Get owner admin chat ID
	var ownerChatID int64
	pn.db.QueryRow(`SELECT telegram_chat_id FROM admins WHERE is_owner = 1`).Scan(&ownerChatID)

	if ownerChatID != 0 && pn.telegramBot != nil {
		message := fmt.Sprintf(`ðŸ’³ Ù¾Ø±Ø¯Ø§Ø®Øª Ø¬Ø¯ÛŒØ¯

ðŸ“‹ ÙØ§Ú©ØªÙˆØ±: %s
ðŸ‘¤ Ú©Ø§Ø±Ø¨Ø±: %s
ðŸ’° Ù…Ø¨Ù„Øº: %s
ðŸ“… Ø²Ù…Ø§Ù†: %s`,
			invoice.InvoiceNumber,
			invoice.UserID,
			FormatCurrency(invoice.Total, invoice.Currency),
			time.Now().Format("2006-01-02 15:04:05"),
		)
		pn.telegramBot.SendMessage(ownerChatID, message, nil)
	}
}

func (pn *PaymentNotifier) getUserTelegramChatID(userID string) int64 {
	var chatID int64
	pn.db.QueryRow("SELECT telegram_id FROM users WHERE id = ?", userID).Scan(&chatID)
	return chatID
}

func (pn *PaymentNotifier) getAdminTelegramChatID(adminID string) int64 {
	var chatID int64
	pn.db.QueryRow("SELECT telegram_chat_id FROM admins WHERE id = ?", adminID).Scan(&chatID)
	return chatID
}

// ==================== Payment API Handlers ====================

// PaymentAPIHandler handles payment API requests
type PaymentAPIHandler struct {
	pm       *PaymentManager
	notifier *PaymentNotifier
}

// NewPaymentAPIHandler creates new API handler
func NewPaymentAPIHandler(pm *PaymentManager, notifier *PaymentNotifier) *PaymentAPIHandler {
	return &PaymentAPIHandler{
		pm:       pm,
		notifier: notifier,
	}
}

// HandleGetWallet handles GET /api/wallet
func (h *PaymentAPIHandler) HandleGetWallet(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	wallet, err := h.pm.GetWalletByUser(userID)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusNotFound)
		return
	}

	sendJSON(w, wallet)
}

// HandleGetWalletTransactions handles GET /api/wallet/transactions
func (h *PaymentAPIHandler) HandleGetWalletTransactions(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	wallet, err := h.pm.GetWalletByUser(userID)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusNotFound)
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	txType := TransactionType(r.URL.Query().Get("type"))

	if limit <= 0 {
		limit = 20
	}

	transactions, total, err := h.pm.GetTransactionHistory(wallet.ID, limit, offset, txType)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, map[string]interface{}{
		"transactions": transactions,
		"total":        total,
		"limit":        limit,
		"offset":       offset,
	})
}

// HandleDeposit handles POST /api/wallet/deposit
func (h *PaymentAPIHandler) HandleDeposit(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	var req struct {
		Amount   float64        `json:"amount"`
		Currency Currency       `json:"currency"`
		Gateway  PaymentGateway `json:"gateway"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "invalid request", http.StatusBadRequest)
		return
	}

	if req.Amount <= 0 {
		sendJSONError(w, "invalid amount", http.StatusBadRequest)
		return
	}

	// Create deposit invoice
	item := InvoiceItem{
		Type:      "deposit",
		Name:      "Wallet Deposit",
		Quantity:  1,
		UnitPrice: req.Amount,
	}

	invoice, err := h.pm.CreateInvoice(userID, []InvoiceItem{item}, req.Currency, "")
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create payment session
	ip := getClientIP(r)
	session, err := h.pm.PayInvoice(invoice.ID, req.Gateway, ip)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, map[string]interface{}{
		"invoice": invoice,
		"session": session,
	})
}

// HandleGetPlans handles GET /api/plans
func (h *PaymentAPIHandler) HandleGetPlans(w http.ResponseWriter, r *http.Request) {
	adminID := r.URL.Query().Get("admin_id")

	plans, err := h.pm.GetActivePlans(adminID)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, plans)
}

// HandleCreateInvoice handles POST /api/invoices
func (h *PaymentAPIHandler) HandleCreateInvoice(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	adminID, _ := r.Context().Value("admin_id").(string)

	var req struct {
		PlanID       string   `json:"plan_id"`
		Currency     Currency `json:"currency"`
		DiscountCode string   `json:"discount_code,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "invalid request", http.StatusBadRequest)
		return
	}

	invoice, err := h.pm.CreateInvoiceFromPlan(userID, req.PlanID, req.Currency, adminID)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Apply discount if provided
	if req.DiscountCode != "" {
		invoice, err = h.pm.ApplyDiscountToInvoice(invoice.ID, req.DiscountCode)
		if err != nil {
			// Don't fail, just skip discount
		}
	}

	sendJSON(w, invoice)
}

// HandlePayInvoice handles POST /api/invoices/{id}/pay
func (h *PaymentAPIHandler) HandlePayInvoice(w http.ResponseWriter, r *http.Request) {
	invoiceID := chi.URLParam(r, "id")

	var req struct {
		Gateway PaymentGateway `json:"gateway"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "invalid request", http.StatusBadRequest)
		return
	}

	ip := getClientIP(r)
	session, err := h.pm.PayInvoice(invoiceID, req.Gateway, ip)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	sendJSON(w, session)
}

// HandlePaymentCallback handles payment gateway callbacks
func (h *PaymentAPIHandler) HandlePaymentCallback(w http.ResponseWriter, r *http.Request) {
	gateway := PaymentGateway(chi.URLParam(r, "gateway"))

	handler, ok := h.pm.gatewayHandlers[gateway]
	if !ok {
		sendJSONError(w, "unknown gateway", http.StatusBadRequest)
		return
	}

	// Parse callback data
	callbackData, err := handler.ParseWebhook(r)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get session ID from callback or query
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		if sid, ok := callbackData["session_id"].(string); ok {
			sessionID = sid
		}
	}

	// Convert callback data to string map
	stringData := make(map[string]string)
	for k, v := range callbackData {
		stringData[k] = fmt.Sprintf("%v", v)
	}

	invoice, err := h.pm.VerifyPayment(sessionID, stringData)
	if err != nil {
		// Redirect to failure page
		http.Redirect(w, r, "/payment/failed?error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}

	// Notify
	if h.notifier != nil {
		go h.notifier.NotifyPaymentReceived(invoice, nil)
	}

	// Redirect to success page
	http.Redirect(w, r, "/payment/success?invoice="+invoice.InvoiceNumber, http.StatusFound)
}

// HandleWebhook handles payment gateway webhooks
func (h *PaymentAPIHandler) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	gateway := PaymentGateway(chi.URLParam(r, "gateway"))

	handler, ok := h.pm.gatewayHandlers[gateway]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	data, err := handler.ParseWebhook(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Process based on gateway
	switch gateway {
	case GatewayStripe:
		h.processStripeWebhook(data)
	case GatewayNowPayments:
		h.processNowPaymentsWebhook(data)
	}

	w.WriteHeader(http.StatusOK)
}

func (h *PaymentAPIHandler) processStripeWebhook(data map[string]interface{}) {
	eventType, _ := data["type"].(string)

	switch eventType {
	case "checkout.session.completed":
		// Get session data
		sessionData, _ := data["data"].(map[string]interface{})["object"].(map[string]interface{})
		invoiceID, _ := sessionData["client_reference_id"].(string)

		if invoiceID != "" {
			// Verify and complete payment
			stringData := map[string]string{
				"session_id": sessionData["id"].(string),
				"status":     "success",
			}

			// Find session and verify
			var sessionID string
			h.pm.db.QueryRow("SELECT id FROM payment_sessions WHERE invoice_id = ? AND gateway = ?",
				invoiceID, GatewayStripe).Scan(&sessionID)

			if sessionID != "" {
				h.pm.VerifyPayment(sessionID, stringData)
			}
		}

	case "payment_intent.payment_failed":
		// Handle failure
	}
}

func (h *PaymentAPIHandler) processNowPaymentsWebhook(data map[string]interface{}) {
	paymentStatus, _ := data["payment_status"].(string)
	orderID, _ := data["order_id"].(string)

	if paymentStatus == "finished" || paymentStatus == "confirmed" {
		// Find and verify payment
		var sessionID string
		h.pm.db.QueryRow("SELECT id FROM payment_sessions WHERE invoice_id = ? AND gateway = ?",
			orderID, GatewayNowPayments).Scan(&sessionID)

		if sessionID != "" {
			paymentID, _ := data["payment_id"].(string)
			h.pm.VerifyPayment(sessionID, map[string]string{
				"payment_id": paymentID,
			})
		}
	}
}

// HandleGetInvoices handles GET /api/invoices
func (h *PaymentAPIHandler) HandleGetInvoices(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	status := InvoiceStatus(r.URL.Query().Get("status"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	if limit <= 0 {
		limit = 20
	}

	invoices, total, err := h.pm.GetUserInvoices(userID, status, limit, offset)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, map[string]interface{}{
		"invoices": invoices,
		"total":    total,
	})
}

// HandleGetInvoice handles GET /api/invoices/{id}
func (h *PaymentAPIHandler) HandleGetInvoice(w http.ResponseWriter, r *http.Request) {
	invoiceID := chi.URLParam(r, "id")
	userID := r.Context().Value("user_id").(string)

	invoice, err := h.pm.GetInvoice(invoiceID)
	if err != nil {
		sendJSONError(w, "invoice not found", http.StatusNotFound)
		return
	}

	// Check ownership
	if invoice.UserID != userID {
		sendJSONError(w, "unauthorized", http.StatusForbidden)
		return
	}

	sendJSON(w, invoice)
}

// HandleApplyDiscount handles POST /api/invoices/{id}/discount
func (h *PaymentAPIHandler) HandleApplyDiscount(w http.ResponseWriter, r *http.Request) {
	invoiceID := chi.URLParam(r, "id")

	var req struct {
		Code string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "invalid request", http.StatusBadRequest)
		return
	}

	invoice, err := h.pm.ApplyDiscountToInvoice(invoiceID, req.Code)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	sendJSON(w, invoice)
}

// HandleValidateDiscount handles POST /api/discounts/validate
func (h *PaymentAPIHandler) HandleValidateDiscount(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	var req struct {
		Code   string  `json:"code"`
		Amount float64 `json:"amount"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "invalid request", http.StatusBadRequest)
		return
	}

	discount, err := h.pm.ValidateDiscountCode(req.Code, userID, req.Amount)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	sendJSON(w, map[string]interface{}{
		"valid":    true,
		"discount": discount,
	})
}

// HandleGetGateways handles GET /api/gateways
func (h *PaymentAPIHandler) HandleGetGateways(w http.ResponseWriter, r *http.Request) {
	gateways := make([]map[string]interface{}, 0)

	for _, config := range h.pm.config.Gateways {
		if !config.IsActive {
			continue
		}

		gateways = append(gateways, map[string]interface{}{
			"gateway":    config.Gateway,
			"name":       config.Name,
			"currencies": config.Currencies,
			"min_amount": config.MinAmount,
			"max_amount": config.MaxAmount,
			"fee":        config.Fee,
		})
	}

	sendJSON(w, gateways)
}

// HandleGetCurrencies handles GET /api/currencies
func (h *PaymentAPIHandler) HandleGetCurrencies(w http.ResponseWriter, r *http.Request) {
	currencies := h.pm.GetSupportedCurrencies()
	sendJSON(w, currencies)
}

// HandleGetExchangeRate handles GET /api/currencies/rate
func (h *PaymentAPIHandler) HandleGetExchangeRate(w http.ResponseWriter, r *http.Request) {
	from := Currency(r.URL.Query().Get("from"))
	to := Currency(r.URL.Query().Get("to"))

	rate, err := h.pm.GetExchangeRate(from, to)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	sendJSON(w, map[string]interface{}{
		"from": from,
		"to":   to,
		"rate": rate,
	})
}

// ==================== Admin API Handlers ====================

// HandleAdminGetInvoices handles GET /api/admin/invoices
func (h *PaymentAPIHandler) HandleAdminGetInvoices(w http.ResponseWriter, r *http.Request) {
	filter := InvoiceFilter{
		UserID:    r.URL.Query().Get("user_id"),
		AdminID:   r.URL.Query().Get("admin_id"),
		Status:    InvoiceStatus(r.URL.Query().Get("status")),
		Currency:  Currency(r.URL.Query().Get("currency")),
		Gateway:   PaymentGateway(r.URL.Query().Get("gateway")),
		SortBy:    r.URL.Query().Get("sort_by"),
		SortOrder: r.URL.Query().Get("sort_order"),
	}

	filter.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	filter.Offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
	filter.MinAmount, _ = strconv.ParseFloat(r.URL.Query().Get("min_amount"), 64)
	filter.MaxAmount, _ = strconv.ParseFloat(r.URL.Query().Get("max_amount"), 64)

	if fromDate := r.URL.Query().Get("from_date"); fromDate != "" {
		filter.FromDate, _ = time.Parse("2006-01-02", fromDate)
	}
	if toDate := r.URL.Query().Get("to_date"); toDate != "" {
		filter.ToDate, _ = time.Parse("2006-01-02", toDate)
	}

	invoices, total, err := h.pm.GetAllInvoices(filter)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, map[string]interface{}{
		"invoices": invoices,
		"total":    total,
	})
}

// HandleAdminRefundInvoice handles POST /api/admin/invoices/{id}/refund
func (h *PaymentAPIHandler) HandleAdminRefundInvoice(w http.ResponseWriter, r *http.Request) {
	invoiceID := chi.URLParam(r, "id")
	adminID := r.Context().Value("admin_id").(string)

	var req struct {
		Amount float64 `json:"amount"`
		Reason string  `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "invalid request", http.StatusBadRequest)
		return
	}

	err := h.pm.RefundInvoice(invoiceID, req.Amount, req.Reason, adminID)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	invoice, _ := h.pm.GetInvoice(invoiceID)

	// Notify
	if h.notifier != nil {
		go h.notifier.NotifyRefundProcessed(invoice, req.Amount)
	}

	sendJSON(w, map[string]string{"status": "refunded"})
}

// HandleAdminCreatePlan handles POST /api/admin/plans
func (h *PaymentAPIHandler) HandleAdminCreatePlan(w http.ResponseWriter, r *http.Request) {
	var plan SubscriptionPlan
	if err := json.NewDecoder(r.Body).Decode(&plan); err != nil {
		sendJSONError(w, "invalid request", http.StatusBadRequest)
		return
	}

	if err := h.pm.CreatePlan(&plan); err != nil {
		sendJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	sendJSON(w, plan)
}

// HandleAdminUpdatePlan handles PUT /api/admin/plans/{id}
func (h *PaymentAPIHandler) HandleAdminUpdatePlan(w http.ResponseWriter, r *http.Request) {
	planID := chi.URLParam(r, "id")

	var plan SubscriptionPlan
	if err := json.NewDecoder(r.Body).Decode(&plan); err != nil {
		sendJSONError(w, "invalid request", http.StatusBadRequest)
		return
	}

	plan.ID = planID

	if err := h.pm.UpdatePlan(&plan); err != nil {
		sendJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	sendJSON(w, plan)
}

// HandleAdminDeletePlan handles DELETE /api/admin/plans/{id}
func (h *PaymentAPIHandler) HandleAdminDeletePlan(w http.ResponseWriter, r *http.Request) {
	planID := chi.URLParam(r, "id")

	if err := h.pm.DeletePlan(planID); err != nil {
		sendJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	sendJSON(w, map[string]string{"status": "deleted"})
}

// HandleAdminCreateDiscount handles POST /api/admin/discounts
func (h *PaymentAPIHandler) HandleAdminCreateDiscount(w http.ResponseWriter, r *http.Request) {
	var discount DiscountCode
	if err := json.NewDecoder(r.Body).Decode(&discount); err != nil {
		sendJSONError(w, "invalid request", http.StatusBadRequest)
		return
	}

	if err := h.pm.CreateDiscountCode(&discount); err != nil {
		sendJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	sendJSON(w, discount)
}

// HandleAdminGetDiscounts handles GET /api/admin/discounts
func (h *PaymentAPIHandler) HandleAdminGetDiscounts(w http.ResponseWriter, r *http.Request) {
	activeOnly := r.URL.Query().Get("active_only") == "true"

	discounts, err := h.pm.GetAllDiscountCodes(activeOnly)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, discounts)
}

// HandleAdminGetFinancialReport handles GET /api/admin/reports/financial
func (h *PaymentAPIHandler) HandleAdminGetFinancialReport(w http.ResponseWriter, r *http.Request) {
	currency := Currency(r.URL.Query().Get("currency"))
	if currency == "" {
		currency = h.pm.config.DefaultCurrency
	}

	startDate := time.Now().AddDate(0, -1, 0) // Last month default
	endDate := time.Now()

	if s := r.URL.Query().Get("start_date"); s != "" {
		startDate, _ = time.Parse("2006-01-02", s)
	}
	if e := r.URL.Query().Get("end_date"); e != "" {
		endDate, _ = time.Parse("2006-01-02", e)
	}

	report, err := h.pm.GenerateFinancialReport(startDate, endDate, currency)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, report)
}

// HandleAdminVerifyManualPayment handles POST /api/admin/payments/{session_id}/verify
func (h *PaymentAPIHandler) HandleAdminVerifyManualPayment(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "session_id")

	invoice, err := h.pm.VerifyPayment(sessionID, map[string]string{
		"admin_verified": "true",
	})

	if err != nil {
		sendJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Notify
	if h.notifier != nil {
		go h.notifier.NotifyPaymentReceived(invoice, nil)
	}

	sendJSON(w, invoice)
}

// HandleAdminAdjustWallet handles POST /api/admin/wallets/{id}/adjust
func (h *PaymentAPIHandler) HandleAdminAdjustWallet(w http.ResponseWriter, r *http.Request) {
	walletID := chi.URLParam(r, "id")
	adminID := r.Context().Value("admin_id").(string)

	var req struct {
		Amount float64 `json:"amount"`
		Reason string  `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "invalid request", http.StatusBadRequest)
		return
	}

	transaction, err := h.pm.AdjustBalance(walletID, req.Amount, req.Reason, adminID)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	sendJSON(w, transaction)
}

// HandleAdminGetCommissionStats handles GET /api/admin/commission/stats
func (h *PaymentAPIHandler) HandleAdminGetCommissionStats(w http.ResponseWriter, r *http.Request) {
	adminID := r.URL.Query().Get("admin_id")
	if adminID == "" {
		adminID = r.Context().Value("admin_id").(string)
	}

	stats, err := h.pm.GetAdminCommissionStats(adminID)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSON(w, stats)
}

// ==================== Helper Functions ====================

func sendJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func sendJSONError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// ==================== Payment Routes Registration ====================

// RegisterPaymentRoutes registers all payment API routes
func RegisterPaymentRoutes(r chi.Router, handler *PaymentAPIHandler, authMiddleware func(http.Handler) http.Handler, adminMiddleware func(http.Handler) http.Handler) {
	// Public routes (with user auth)
	r.Route("/api/payment", func(r chi.Router) {
		r.Use(authMiddleware)

		// Wallet
		r.Get("/wallet", handler.HandleGetWallet)
		r.Get("/wallet/transactions", handler.HandleGetWalletTransactions)
		r.Post("/wallet/deposit", handler.HandleDeposit)

		// Plans
		r.Get("/plans", handler.HandleGetPlans)

		// Invoices
		r.Get("/invoices", handler.HandleGetInvoices)
		r.Post("/invoices", handler.HandleCreateInvoice)
		r.Get("/invoices/{id}", handler.HandleGetInvoice)
		r.Post("/invoices/{id}/pay", handler.HandlePayInvoice)
		r.Post("/invoices/{id}/discount", handler.HandleApplyDiscount)

		// Discounts
		r.Post("/discounts/validate", handler.HandleValidateDiscount)

		// Gateways & Currencies
		r.Get("/gateways", handler.HandleGetGateways)
		r.Get("/currencies", handler.HandleGetCurrencies)
		r.Get("/currencies/rate", handler.HandleGetExchangeRate)
	})

	// Payment callbacks (no auth - verified by gateway)
	r.Get("/api/payment/callback/{gateway}", handler.HandlePaymentCallback)
	r.Post("/api/payment/callback/{gateway}", handler.HandlePaymentCallback)
	r.Post("/api/payment/webhook/{gateway}", handler.HandleWebhook)

	// Admin routes
	r.Route("/api/admin/payment", func(r chi.Router) {
		r.Use(adminMiddleware)

		// Invoices
		r.Get("/invoices", handler.HandleAdminGetInvoices)
		r.Post("/invoices/{id}/refund", handler.HandleAdminRefundInvoice)

		// Plans
		r.Get("/plans", func(w http.ResponseWriter, r *http.Request) {
			plans, _ := handler.pm.GetAllPlans()
			sendJSON(w, plans)
		})
		r.Post("/plans", handler.HandleAdminCreatePlan)
		r.Put("/plans/{id}", handler.HandleAdminUpdatePlan)
		r.Delete("/plans/{id}", handler.HandleAdminDeletePlan)

		// Discounts
		r.Get("/discounts", handler.HandleAdminGetDiscounts)
		r.Post("/discounts", handler.HandleAdminCreateDiscount)

		// Wallets
		r.Post("/wallets/{id}/adjust", handler.HandleAdminAdjustWallet)

		// Manual payment verification
		r.Post("/payments/{session_id}/verify", handler.HandleAdminVerifyManualPayment)

		// Reports
		r.Get("/reports/financial", handler.HandleAdminGetFinancialReport)
		r.Get("/reports/top-plans", func(w http.ResponseWriter, r *http.Request) {
			limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
			if limit <= 0 {
				limit = 10
			}
			startDate := time.Now().AddDate(0, -1, 0)
			endDate := time.Now()

			plans, _ := handler.pm.GetTopSellingPlans(limit, startDate, endDate)
			sendJSON(w, plans)
		})

		// Commission
		r.Get("/commission/stats", handler.HandleAdminGetCommissionStats)
	})
}
