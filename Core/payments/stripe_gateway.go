// Core/payments/stripe_gateway.go
// Stripe Payment Gateway Integration
// Production-ready Stripe implementation with webhooks

package payments

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/stripe/stripe-go/v76"
	"github.com/stripe/stripe-go/v76/checkout/session"
	"github.com/stripe/stripe-go/v76/customer"
	"github.com/stripe/stripe-go/v76/paymentintent"
	"github.com/stripe/stripe-go/v76/subscription"
	"github.com/stripe/stripe-go/v76/webhook"
)

// ====================================================================================
// STRIPE GATEWAY
// ====================================================================================

// StripeGateway handles Stripe payment processing
type StripeGateway struct {
	apiKey         string
	webhookSecret  string
	successURL     string
	cancelURL      string
	currency       string
}

// StripeConfig holds Stripe configuration
type StripeConfig struct {
	APIKey        string
	WebhookSecret string
	SuccessURL    string
	CancelURL     string
	Currency      string
}

// NewStripeGateway creates a new Stripe gateway
func NewStripeGateway(config *StripeConfig) *StripeGateway {
	stripe.Key = config.APIKey

	return &StripeGateway{
		apiKey:        config.APIKey,
		webhookSecret: config.WebhookSecret,
		successURL:    config.SuccessURL,
		cancelURL:     config.CancelURL,
		currency:      config.Currency,
	}
}

// ====================================================================================
// ONE-TIME PAYMENTS
// ====================================================================================

// CreateCheckoutSession creates a Stripe checkout session for one-time payment
func (sg *StripeGateway) CreateCheckoutSession(amount int64, userEmail, description string, metadata map[string]string) (*stripe.CheckoutSession, error) {
	params := &stripe.CheckoutSessionParams{
		PaymentMethodTypes: stripe.StringSlice([]string{
			"card",
		}),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				PriceData: &stripe.CheckoutSessionLineItemPriceDataParams{
					Currency: stripe.String(sg.currency),
					ProductData: &stripe.CheckoutSessionLineItemPriceDataProductDataParams{
						Name:        stripe.String(description),
						Description: stripe.String(description),
					},
					UnitAmount: stripe.Int64(amount), // Amount in cents
				},
				Quantity: stripe.Int64(1),
			},
		},
		Mode:       stripe.String(string(stripe.CheckoutSessionModePayment)),
		SuccessURL: stripe.String(sg.successURL),
		CancelURL:  stripe.String(sg.cancelURL),
	}

	// Add customer email
	if userEmail != "" {
		params.CustomerEmail = stripe.String(userEmail)
	}

	// Add metadata
	if metadata != nil {
		params.Metadata = metadata
	}

	s, err := session.New(params)
	if err != nil {
		return nil, fmt.Errorf("failed to create checkout session: %w", err)
	}

	return s, nil
}

// ====================================================================================
// RECURRING SUBSCRIPTIONS
// ====================================================================================

// CreateCustomer creates a Stripe customer
func (sg *StripeGateway) CreateCustomer(email, name string, metadata map[string]string) (*stripe.Customer, error) {
	params := &stripe.CustomerParams{
		Email: stripe.String(email),
		Name:  stripe.String(name),
	}

	if metadata != nil {
		params.Metadata = metadata
	}

	c, err := customer.New(params)
	if err != nil {
		return nil, fmt.Errorf("failed to create customer: %w", err)
	}

	return c, nil
}

// CreateSubscription creates a recurring subscription
func (sg *StripeGateway) CreateSubscription(customerID, priceID string, trialDays int64) (*stripe.Subscription, error) {
	params := &stripe.SubscriptionParams{
		Customer: stripe.String(customerID),
		Items: []*stripe.SubscriptionItemsParams{
			{
				Price: stripe.String(priceID),
			},
		},
	}

	// Add trial period if specified
	if trialDays > 0 {
		params.TrialPeriodDays = stripe.Int64(trialDays)
	}

	// Automatically invoice the customer
	params.PaymentBehavior = stripe.String("default_incomplete")
	params.PaymentSettings = &stripe.SubscriptionPaymentSettingsParams{
		SaveDefaultPaymentMethod: stripe.String("on_subscription"),
	}

	sub, err := subscription.New(params)
	if err != nil {
		return nil, fmt.Errorf("failed to create subscription: %w", err)
	}

	return sub, nil
}

// CancelSubscription cancels a subscription
func (sg *StripeGateway) CancelSubscription(subscriptionID string, immediately bool) (*stripe.Subscription, error) {
	params := &stripe.SubscriptionCancelParams{}

	if !immediately {
		// Cancel at period end
		params.CancelAtPeriodEnd = stripe.Bool(true)
	}

	sub, err := subscription.Cancel(subscriptionID, params)
	if err != nil {
		return nil, fmt.Errorf("failed to cancel subscription: %w", err)
	}

	return sub, nil
}

// UpdateSubscription updates a subscription (upgrade/downgrade)
func (sg *StripeGateway) UpdateSubscription(subscriptionID, newPriceID string, prorationBehavior string) (*stripe.Subscription, error) {
	// Get current subscription
	sub, err := subscription.Get(subscriptionID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get subscription: %w", err)
	}

	params := &stripe.SubscriptionParams{
		Items: []*stripe.SubscriptionItemsParams{
			{
				ID:    stripe.String(sub.Items.Data[0].ID),
				Price: stripe.String(newPriceID),
			},
		},
	}

	// Set proration behavior: create_prorations, none, always_invoice
	if prorationBehavior != "" {
		params.ProrationBehavior = stripe.String(prorationBehavior)
	}

	updatedSub, err := subscription.Update(subscriptionID, params)
	if err != nil {
		return nil, fmt.Errorf("failed to update subscription: %w", err)
	}

	return updatedSub, nil
}

// ====================================================================================
// PAYMENT INTENTS (for custom flows)
// ====================================================================================

// CreatePaymentIntent creates a payment intent
func (sg *StripeGateway) CreatePaymentIntent(amount int64, currency string, metadata map[string]string) (*stripe.PaymentIntent, error) {
	params := &stripe.PaymentIntentParams{
		Amount:   stripe.Int64(amount),
		Currency: stripe.String(currency),
	}

	if metadata != nil {
		params.Metadata = metadata
	}

	pi, err := paymentintent.New(params)
	if err != nil {
		return nil, fmt.Errorf("failed to create payment intent: %w", err)
	}

	return pi, nil
}

// ConfirmPaymentIntent confirms a payment intent
func (sg *StripeGateway) ConfirmPaymentIntent(paymentIntentID string) (*stripe.PaymentIntent, error) {
	pi, err := paymentintent.Confirm(paymentIntentID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to confirm payment intent: %w", err)
	}

	return pi, nil
}

// ====================================================================================
// WEBHOOK HANDLING
// ====================================================================================

// WebhookEvent represents a processed webhook event
type WebhookEvent struct {
	Type      string
	ID        string
	Data      interface{}
	CreatedAt time.Time
}

// HandleWebhook processes Stripe webhook events
func (sg *StripeGateway) HandleWebhook(r *http.Request) (*WebhookEvent, error) {
	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	// Verify webhook signature
	event, err := webhook.ConstructEvent(
		body,
		r.Header.Get("Stripe-Signature"),
		sg.webhookSecret,
	)
	if err != nil {
		return nil, fmt.Errorf("webhook signature verification failed: %w", err)
	}

	webhookEvent := &WebhookEvent{
		Type:      event.Type,
		ID:        event.ID,
		CreatedAt: time.Unix(event.Created, 0),
	}

	// Process different event types
	switch event.Type {
	case "checkout.session.completed":
		var session stripe.CheckoutSession
		if err := json.Unmarshal(event.Data.Raw, &session); err != nil {
			return nil, fmt.Errorf("failed to unmarshal session: %w", err)
		}
		webhookEvent.Data = &session

	case "payment_intent.succeeded":
		var paymentIntent stripe.PaymentIntent
		if err := json.Unmarshal(event.Data.Raw, &paymentIntent); err != nil {
			return nil, fmt.Errorf("failed to unmarshal payment intent: %w", err)
		}
		webhookEvent.Data = &paymentIntent

	case "payment_intent.payment_failed":
		var paymentIntent stripe.PaymentIntent
		if err := json.Unmarshal(event.Data.Raw, &paymentIntent); err != nil {
			return nil, fmt.Errorf("failed to unmarshal payment intent: %w", err)
		}
		webhookEvent.Data = &paymentIntent

	case "customer.subscription.created":
		var subscription stripe.Subscription
		if err := json.Unmarshal(event.Data.Raw, &subscription); err != nil {
			return nil, fmt.Errorf("failed to unmarshal subscription: %w", err)
		}
		webhookEvent.Data = &subscription

	case "customer.subscription.updated":
		var subscription stripe.Subscription
		if err := json.Unmarshal(event.Data.Raw, &subscription); err != nil {
			return nil, fmt.Errorf("failed to unmarshal subscription: %w", err)
		}
		webhookEvent.Data = &subscription

	case "customer.subscription.deleted":
		var subscription stripe.Subscription
		if err := json.Unmarshal(event.Data.Raw, &subscription); err != nil {
			return nil, fmt.Errorf("failed to unmarshal subscription: %w", err)
		}
		webhookEvent.Data = &subscription

	case "invoice.paid":
		var invoice stripe.Invoice
		if err := json.Unmarshal(event.Data.Raw, &invoice); err != nil {
			return nil, fmt.Errorf("failed to unmarshal invoice: %w", err)
		}
		webhookEvent.Data = &invoice

	case "invoice.payment_failed":
		var invoice stripe.Invoice
		if err := json.Unmarshal(event.Data.Raw, &invoice); err != nil {
			return nil, fmt.Errorf("failed to unmarshal invoice: %w", err)
		}
		webhookEvent.Data = &invoice

	default:
		// Unknown event type
		webhookEvent.Data = event.Data.Raw
	}

	return webhookEvent, nil
}

// ====================================================================================
// REFUNDS
// ====================================================================================

// CreateRefund creates a refund for a payment
func (sg *StripeGateway) CreateRefund(paymentIntentID string, amount int64, reason string) error {
	params := &stripe.RefundParams{
		PaymentIntent: stripe.String(paymentIntentID),
	}

	// Partial refund if amount specified
	if amount > 0 {
		params.Amount = stripe.Int64(amount)
	}

	// Add refund reason
	if reason != "" {
		params.Reason = stripe.String(reason)
	}

	_, err := stripe.Refund.New(params)
	if err != nil {
		return fmt.Errorf("failed to create refund: %w", err)
	}

	return nil
}

// ====================================================================================
// UTILITY FUNCTIONS
// ====================================================================================

// GetCustomer retrieves customer information
func (sg *StripeGateway) GetCustomer(customerID string) (*stripe.Customer, error) {
	c, err := customer.Get(customerID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get customer: %w", err)
	}

	return c, nil
}

// GetSubscription retrieves subscription information
func (sg *StripeGateway) GetSubscription(subscriptionID string) (*stripe.Subscription, error) {
	sub, err := subscription.Get(subscriptionID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get subscription: %w", err)
	}

	return sub, nil
}

// GetPaymentIntent retrieves payment intent information
func (sg *StripeGateway) GetPaymentIntent(paymentIntentID string) (*stripe.PaymentIntent, error) {
	pi, err := paymentintent.Get(paymentIntentID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get payment intent: %w", err)
	}

	return pi, nil
}
