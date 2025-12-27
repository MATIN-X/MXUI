// Core/billing/subscription_manager.go
// Subscription Lifecycle Management
// Handles recurring billing, renewals, upgrades, and dunning

package billing

import (
	"database/sql"
	"fmt"
	"time"
)

// ====================================================================================
// SUBSCRIPTION MANAGER
// ====================================================================================

// SubscriptionManager manages subscription lifecycle
type SubscriptionManager struct {
	db *sql.DB
}

// SubscriptionStatus represents subscription states
type SubscriptionStatus string

const (
	SubStatusActive    SubscriptionStatus = "active"
	SubStatusCancelled SubscriptionStatus = "cancelled"
	SubStatusExpired   SubscriptionStatus = "expired"
	SubStatusPastDue   SubscriptionStatus = "past_due"
	SubStatusTrialing  SubscriptionStatus = "trialing"
	SubStatusPaused    SubscriptionStatus = "paused"
)

// UserSubscription represents user subscription
type UserSubscription struct {
	ID             int64
	UserID         int64
	PlanID         int64
	Status         SubscriptionStatus
	CurrentPeriodStart time.Time
	CurrentPeriodEnd   time.Time
	CancelAt       *time.Time
	CancelledAt    *time.Time
	TrialEnd       *time.Time
	StripeSubID    string
	AutoRenew      bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// NewSubscriptionManager creates new subscription manager
func NewSubscriptionManager(db *sql.DB) *SubscriptionManager {
	return &SubscriptionManager{db: db}
}

// ====================================================================================
// SUBSCRIPTION LIFECYCLE
// ====================================================================================

// CreateSubscription creates a new subscription
func (sm *SubscriptionManager) CreateSubscription(userID, planID int64, trialDays int) (*UserSubscription, error) {
	now := time.Now()

	// Get plan details
	var durationDays int
	err := sm.db.QueryRow("SELECT duration_days FROM subscription_plans WHERE id = ?", planID).Scan(&durationDays)
	if err != nil {
		return nil, fmt.Errorf("plan not found: %w", err)
	}

	sub := &UserSubscription{
		UserID:             userID,
		PlanID:             planID,
		Status:             SubStatusActive,
		CurrentPeriodStart: now,
		CurrentPeriodEnd:   now.AddDate(0, 0, durationDays),
		AutoRenew:          true,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	// Add trial if specified
	if trialDays > 0 {
		sub.Status = SubStatusTrialing
		trialEnd := now.AddDate(0, 0, trialDays)
		sub.TrialEnd = &trialEnd
		sub.CurrentPeriodEnd = trialEnd
	}

	// Insert into database
	query := `
		INSERT INTO user_subscriptions
		(user_id, plan_id, status, current_period_start, current_period_end, trial_end, auto_renew, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := sm.db.Exec(query,
		sub.UserID, sub.PlanID, sub.Status,
		sub.CurrentPeriodStart, sub.CurrentPeriodEnd, sub.TrialEnd,
		sub.AutoRenew, sub.CreatedAt, sub.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create subscription: %w", err)
	}

	id, _ := result.LastInsertId()
	sub.ID = id

	// Update user subscription_plan_id
	_, err = sm.db.Exec("UPDATE users SET subscription_plan_id = ?, status = 'active', expiry_date = ? WHERE id = ?",
		planID, sub.CurrentPeriodEnd, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return sub, nil
}

// RenewSubscription renews a subscription for another period
func (sm *SubscriptionManager) RenewSubscription(subscriptionID int64) error {
	// Get subscription
	sub, err := sm.GetSubscription(subscriptionID)
	if err != nil {
		return err
	}

	// Get plan duration
	var durationDays int
	err = sm.db.QueryRow("SELECT duration_days FROM subscription_plans WHERE id = ?", sub.PlanID).Scan(&durationDays)
	if err != nil {
		return fmt.Errorf("plan not found: %w", err)
	}

	// Calculate new period
	newPeriodStart := sub.CurrentPeriodEnd
	newPeriodEnd := newPeriodStart.AddDate(0, 0, durationDays)

	// Update subscription
	query := `
		UPDATE user_subscriptions
		SET current_period_start = ?,
		    current_period_end = ?,
		    status = 'active',
		    updated_at = ?
		WHERE id = ?
	`

	_, err = sm.db.Exec(query, newPeriodStart, newPeriodEnd, time.Now(), subscriptionID)
	if err != nil {
		return fmt.Errorf("failed to renew subscription: %w", err)
	}

	// Update user expiry
	_, err = sm.db.Exec("UPDATE users SET expiry_date = ?, status = 'active' WHERE id = ?",
		newPeriodEnd, sub.UserID)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// CancelSubscription cancels subscription (at period end)
func (sm *SubscriptionManager) CancelSubscription(subscriptionID int64, immediately bool) error {
	sub, err := sm.GetSubscription(subscriptionID)
	if err != nil {
		return err
	}

	now := time.Now()

	if immediately {
		// Cancel immediately
		_, err = sm.db.Exec(`
			UPDATE user_subscriptions
			SET status = 'cancelled',
			    cancelled_at = ?,
			    auto_renew = false,
			    updated_at = ?
			WHERE id = ?
		`, now, now, subscriptionID)

		// Disable user immediately
		_, err = sm.db.Exec("UPDATE users SET status = 'disabled' WHERE id = ?", sub.UserID)
	} else {
		// Cancel at period end
		cancelAt := sub.CurrentPeriodEnd
		_, err = sm.db.Exec(`
			UPDATE user_subscriptions
			SET cancel_at = ?,
			    auto_renew = false,
			    updated_at = ?
			WHERE id = ?
		`, cancelAt, now, subscriptionID)
	}

	return err
}

// UpgradeSubscription upgrades to higher tier plan
func (sm *SubscriptionManager) UpgradeSubscription(subscriptionID, newPlanID int64, prorated bool) error {
	sub, err := sm.GetSubscription(subscriptionID)
	if err != nil {
		return err
	}

	// Get new plan
	var newPrice float64
	var newDuration int
	err = sm.db.QueryRow("SELECT price, duration_days FROM subscription_plans WHERE id = ?", newPlanID).
		Scan(&newPrice, &newDuration)
	if err != nil {
		return fmt.Errorf("new plan not found: %w", err)
	}

	now := time.Now()
	var newPeriodEnd time.Time

	if prorated {
		// Calculate prorated credit and new end date
		remainingDays := int(sub.CurrentPeriodEnd.Sub(now).Hours() / 24)
		newPeriodEnd = now.AddDate(0, 0, remainingDays)
	} else {
		// Start fresh period
		newPeriodEnd = now.AddDate(0, 0, newDuration)
	}

	// Update subscription
	_, err = sm.db.Exec(`
		UPDATE user_subscriptions
		SET plan_id = ?,
		    current_period_start = ?,
		    current_period_end = ?,
		    updated_at = ?
		WHERE id = ?
	`, newPlanID, now, newPeriodEnd, now, subscriptionID)
	if err != nil {
		return fmt.Errorf("failed to upgrade subscription: %w", err)
	}

	// Update user
	_, err = sm.db.Exec("UPDATE users SET subscription_plan_id = ?, expiry_date = ? WHERE id = ?",
		newPlanID, newPeriodEnd, sub.UserID)

	return err
}

// DowngradeSubscription downgrades to lower tier (at period end)
func (sm *SubscriptionManager) DowngradeSubscription(subscriptionID, newPlanID int64) error {
	// Schedule downgrade for end of current period
	// In practice, you'd store this in a pending_changes table
	now := time.Now()

	_, err := sm.db.Exec(`
		INSERT INTO subscription_pending_changes (subscription_id, new_plan_id, change_type, scheduled_at)
		VALUES (?, ?, 'downgrade', ?)
	`, subscriptionID, newPlanID, now)

	return err
}

// ====================================================================================
// GRACE PERIOD & DUNNING
// ====================================================================================

// MarkSubscriptionPastDue marks subscription as past due
func (sm *SubscriptionManager) MarkSubscriptionPastDue(subscriptionID int64) error {
	_, err := sm.db.Exec(`
		UPDATE user_subscriptions
		SET status = 'past_due',
		    updated_at = ?
		WHERE id = ?
	`, time.Now(), subscriptionID)

	return err
}

// ProcessExpiredSubscriptions processes all expired subscriptions
func (sm *SubscriptionManager) ProcessExpiredSubscriptions() error {
	now := time.Now()

	// Get all subscriptions that expired
	rows, err := sm.db.Query(`
		SELECT id, user_id
		FROM user_subscriptions
		WHERE current_period_end < ?
		  AND status = 'active'
		  AND auto_renew = true
	`, now)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var subID, userID int64
		rows.Scan(&subID, &userID)

		// Try to renew
		err := sm.attemptRenewal(subID, userID)
		if err != nil {
			// Renewal failed, mark as past due
			sm.MarkSubscriptionPastDue(subID)

			// Send notification
			// TODO: Send payment failed notification
		}
	}

	// Expire past due subscriptions after grace period (7 days)
	gracePeriod := now.AddDate(0, 0, -7)
	_, err = sm.db.Exec(`
		UPDATE user_subscriptions
		SET status = 'expired'
		WHERE status = 'past_due'
		  AND current_period_end < ?
	`, gracePeriod)

	// Disable users with expired subscriptions
	_, err = sm.db.Exec(`
		UPDATE users
		SET status = 'disabled'
		WHERE id IN (
			SELECT user_id FROM user_subscriptions
			WHERE status = 'expired'
		)
	`)

	return err
}

// attemptRenewal attempts to charge and renew subscription
func (sm *SubscriptionManager) attemptRenewal(subscriptionID, userID int64) error {
	// Get user's payment method
	// Attempt to charge
	// If successful, renew

	// For now, this is a placeholder
	// In production, integrate with Stripe/payment gateway

	return fmt.Errorf("payment method not found")
}

// ====================================================================================
// QUERY FUNCTIONS
// ====================================================================================

// GetSubscription gets subscription by ID
func (sm *SubscriptionManager) GetSubscription(id int64) (*UserSubscription, error) {
	sub := &UserSubscription{}

	query := `
		SELECT id, user_id, plan_id, status,
		       current_period_start, current_period_end,
		       cancel_at, cancelled_at, trial_end,
		       stripe_subscription_id, auto_renew,
		       created_at, updated_at
		FROM user_subscriptions
		WHERE id = ?
	`

	err := sm.db.QueryRow(query, id).Scan(
		&sub.ID, &sub.UserID, &sub.PlanID, &sub.Status,
		&sub.CurrentPeriodStart, &sub.CurrentPeriodEnd,
		&sub.CancelAt, &sub.CancelledAt, &sub.TrialEnd,
		&sub.StripeSubID, &sub.AutoRenew,
		&sub.CreatedAt, &sub.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return sub, nil
}

// GetUserSubscription gets active subscription for user
func (sm *SubscriptionManager) GetUserSubscription(userID int64) (*UserSubscription, error) {
	sub := &UserSubscription{}

	query := `
		SELECT id, user_id, plan_id, status,
		       current_period_start, current_period_end,
		       cancel_at, cancelled_at, trial_end,
		       stripe_subscription_id, auto_renew,
		       created_at, updated_at
		FROM user_subscriptions
		WHERE user_id = ?
		  AND status IN ('active', 'trialing', 'past_due')
		ORDER BY created_at DESC
		LIMIT 1
	`

	err := sm.db.QueryRow(query, userID).Scan(
		&sub.ID, &sub.UserID, &sub.PlanID, &sub.Status,
		&sub.CurrentPeriodStart, &sub.CurrentPeriodEnd,
		&sub.CancelAt, &sub.CancelledAt, &sub.TrialEnd,
		&sub.StripeSubID, &sub.AutoRenew,
		&sub.CreatedAt, &sub.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return sub, nil
}

// GetExpiringSubscriptions gets subscriptions expiring soon
func (sm *SubscriptionManager) GetExpiringSubscriptions(days int) ([]*UserSubscription, error) {
	threshold := time.Now().AddDate(0, 0, days)

	query := `
		SELECT id, user_id, plan_id, status,
		       current_period_start, current_period_end,
		       cancel_at, cancelled_at, trial_end,
		       stripe_subscription_id, auto_renew,
		       created_at, updated_at
		FROM user_subscriptions
		WHERE current_period_end < ?
		  AND current_period_end > ?
		  AND status = 'active'
		ORDER BY current_period_end ASC
	`

	rows, err := sm.db.Query(query, threshold, time.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subscriptions []*UserSubscription
	for rows.Next() {
		sub := &UserSubscription{}
		err := rows.Scan(
			&sub.ID, &sub.UserID, &sub.PlanID, &sub.Status,
			&sub.CurrentPeriodStart, &sub.CurrentPeriodEnd,
			&sub.CancelAt, &sub.CancelledAt, &sub.TrialEnd,
			&sub.StripeSubID, &sub.AutoRenew,
			&sub.CreatedAt, &sub.UpdatedAt,
		)
		if err != nil {
			continue
		}
		subscriptions = append(subscriptions, sub)
	}

	return subscriptions, nil
}
