// Core/notifications.go
// MXUI VPN Panel - Notification System
// Email, SMS, Push Notifications for users and admins

package core

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

// ====================================================================================
// CONSTANTS
// ====================================================================================

const (
	// Notification types
	NotifyTypeEmail    NotificationType = "email"
	NotifyTypeSMS      NotificationType = "sms"
	NotifyTypeTelegram NotificationType = "telegram"
	NotifyTypePush     NotificationType = "push"

	// Notification priorities
	NotifyPriorityLow    = "low"
	NotifyPriorityNormal = "normal"
	NotifyPriorityHigh   = "high"
	NotifyPriorityUrgent = "urgent"

	// Default settings
	DefaultSMTPPort     = 587
	DefaultSMTPTimeout  = 30 * time.Second
	MaxRetries          = 3
	RetryDelay          = 5 * time.Second
	NotificationTimeout = 60 * time.Second
)

// ====================================================================================
// TYPES
// ====================================================================================

type NotificationType string

// NotificationManager manages all notification channels
type EmailNotificationManager struct {
	mu sync.RWMutex

	// Configuration
	config *NotificationConfig

	// Providers
	emailProvider    *EmailProvider
	smsProvider      *SMSProvider
	// telegramProvider removed
	pushProvider     *PushProvider

	// Queue
	queue chan *Notification
	done  chan struct{}

	// Statistics
	stats NotificationStats
}

// NotificationConfig holds notification settings
type NotificationConfig struct {
	// Email settings
	EmailEnabled  bool   `json:"email_enabled"`
	SMTPHost      string `json:"smtp_host"`
	SMTPPort      int    `json:"smtp_port"`
	SMTPUsername  string `json:"smtp_username"`
	SMTPPassword  string `json:"smtp_password"`
	SMTPFromEmail string `json:"smtp_from_email"`
	SMTPFromName  string `json:"smtp_from_name"`
	SMTPTLS       bool   `json:"smtp_tls"`

	// SMS settings
	SMSEnabled    bool   `json:"sms_enabled"`
	SMSProvider   string `json:"sms_provider"` // twilio, nexmo, etc.
	SMSAPIKey     string `json:"sms_api_key"`
	SMSAPISecret  string `json:"sms_api_secret"`
	SMSFrom       string `json:"sms_from"`

	// Push settings
	PushEnabled   bool   `json:"push_enabled"`
	FCMServerKey  string `json:"fcm_server_key"`
	APNSCertPath  string `json:"apns_cert_path"`
	APNSKeyPath   string `json:"apns_key_path"`

	// General
	QueueSize    int  `json:"queue_size"`
	Workers      int  `json:"workers"`
	RetryEnabled bool `json:"retry_enabled"`
}

// Notification represents a notification to send
type Notification struct {
	ID        string           `json:"id"`
	Type      NotificationType `json:"type"`
	To        string           `json:"to"`
	Subject   string           `json:"subject"`
	Body      string           `json:"body"`
	Template  string           `json:"template,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Priority  string           `json:"priority"`
	CreatedAt time.Time        `json:"created_at"`
	Retries   int              `json:"retries"`
}

// NotificationStats holds statistics
type NotificationStats struct {
	TotalSent     int64 `json:"total_sent"`
	TotalFailed   int64 `json:"total_failed"`
	EmailSent     int64 `json:"email_sent"`
	SMSSent       int64 `json:"sms_sent"`
	TelegramSent  int64 `json:"telegram_sent"`
	PushSent      int64 `json:"push_sent"`
}

// ====================================================================================
// EMAIL PROVIDER
// ====================================================================================

// EmailProvider handles email notifications
type EmailProvider struct {
	config     *NotificationConfig
	templates  map[string]*template.Template
	httpClient *http.Client
}

// NewEmailProvider creates a new email provider
func NewEmailProvider(config *NotificationConfig) *EmailProvider {
	return &EmailProvider{
		config:    config,
		templates: make(map[string]*template.Template),
		httpClient: &http.Client{
			Timeout: DefaultSMTPTimeout,
		},
	}
}

// SendEmail sends an email
func (ep *EmailProvider) SendEmail(to, subject, body string) error {
	if !ep.config.EmailEnabled {
		return fmt.Errorf("email notifications disabled")
	}

	// Build email message
	from := fmt.Sprintf("%s <%s>", ep.config.SMTPFromName, ep.config.SMTPFromEmail)

	// Create message
	msg := []byte(
		"From: " + from + "\r\n" +
			"To: " + to + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/html; charset=UTF-8\r\n" +
			"\r\n" +
			body + "\r\n")

	// SMTP authentication
	auth := smtp.PlainAuth("", ep.config.SMTPUsername, ep.config.SMTPPassword, ep.config.SMTPHost)

	// Send email
	addr := fmt.Sprintf("%s:%d", ep.config.SMTPHost, ep.config.SMTPPort)

	// Use TLS if enabled
	if ep.config.SMTPTLS {
		return ep.sendEmailTLS(addr, auth, ep.config.SMTPFromEmail, []string{to}, msg)
	}

	return smtp.SendMail(addr, auth, ep.config.SMTPFromEmail, []string{to}, msg)
}

// sendEmailTLS sends email with explicit TLS
func (ep *EmailProvider) sendEmailTLS(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	// Connect to SMTP server
	conn, err := net.DialTimeout("tcp", addr, DefaultSMTPTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Create SMTP client
	client, err := smtp.NewClient(conn, ep.config.SMTPHost)
	if err != nil {
		return err
	}
	defer client.Close()

	// Start TLS
	tlsConfig := &tls.Config{
		ServerName: ep.config.SMTPHost,
	}
	if err := client.StartTLS(tlsConfig); err != nil {
		return err
	}

	// Authenticate
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return err
		}
	}

	// Set sender
	if err := client.Mail(from); err != nil {
		return err
	}

	// Set recipients
	for _, addr := range to {
		if err := client.Rcpt(addr); err != nil {
			return err
		}
	}

	// Send data
	w, err := client.Data()
	if err != nil {
		return err
	}

	_, err = w.Write(msg)
	if err != nil {
		return err
	}

	err = w.Close()
	if err != nil {
		return err
	}

	return client.Quit()
}

// SendEmailTemplate sends email using template
func (ep *EmailProvider) SendEmailTemplate(to, subject, templateName string, data map[string]interface{}) error {
	tmpl, exists := ep.templates[templateName]
	if !exists {
		return fmt.Errorf("template not found: %s", templateName)
	}

	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return ep.SendEmail(to, subject, body.String())
}

// LoadTemplate loads an email template
func (ep *EmailProvider) LoadTemplate(name, content string) error {
	tmpl, err := template.New(name).Parse(content)
	if err != nil {
		return err
	}

	ep.templates[name] = tmpl
	return nil
}

// ====================================================================================
// SMS PROVIDER
// ====================================================================================

// SMSProvider handles SMS notifications
type SMSProvider struct {
	config     *NotificationConfig
	httpClient *http.Client
}

// NewSMSProvider creates a new SMS provider
func NewSMSProvider(config *NotificationConfig) *SMSProvider {
	return &SMSProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SendSMS sends an SMS
func (sp *SMSProvider) SendSMS(to, message string) error {
	if !sp.config.SMSEnabled {
		return fmt.Errorf("SMS notifications disabled")
	}

	switch strings.ToLower(sp.config.SMSProvider) {
	case "twilio":
		return sp.sendViaTwilio(to, message)
	case "nexmo":
		return sp.sendViaNexmo(to, message)
	default:
		return fmt.Errorf("unsupported SMS provider: %s", sp.config.SMSProvider)
	}
}

// sendViaTwilio sends SMS via Twilio
func (sp *SMSProvider) sendViaTwilio(to, message string) error {
	// Twilio REST API implementation
	// This is a simplified version
	url := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json",
		sp.config.SMSAPIKey)

	data := map[string]string{
		"From": sp.config.SMSFrom,
		"To":   to,
		"Body": message,
	}

	jsonData, _ := json.Marshal(data)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.SetBasicAuth(sp.config.SMSAPIKey, sp.config.SMSAPISecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := sp.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("twilio returned status %d", resp.StatusCode)
	}

	return nil
}

// sendViaNexmo sends SMS via Nexmo
func (sp *SMSProvider) sendViaNexmo(to, message string) error {
	// Nexmo/Vonage API implementation
	url := "https://rest.nexmo.com/sms/json"

	data := map[string]string{
		"api_key":    sp.config.SMSAPIKey,
		"api_secret": sp.config.SMSAPISecret,
		"from":       sp.config.SMSFrom,
		"to":         to,
		"text":       message,
	}

	jsonData, _ := json.Marshal(data)
	resp, err := sp.httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("nexmo returned status %d", resp.StatusCode)
	}

	return nil
}

// ====================================================================================
// PUSH PROVIDER
// ====================================================================================

// PushProvider handles push notifications
type PushProvider struct {
	config     *NotificationConfig
	httpClient *http.Client
}

// NewPushProvider creates a new push provider
func NewPushProvider(config *NotificationConfig) *PushProvider {
	return &PushProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SendPush sends a push notification
func (pp *PushProvider) SendPush(to, title, body string, data map[string]interface{}) error {
	if !pp.config.PushEnabled {
		return fmt.Errorf("push notifications disabled")
	}

	return pp.sendViaFCM(to, title, body, data)
}

// sendViaFCM sends push via Firebase Cloud Messaging
func (pp *PushProvider) sendViaFCM(to, title, body string, data map[string]interface{}) error {
	url := "https://fcm.googleapis.com/fcm/send"

	payload := map[string]interface{}{
		"to": to,
		"notification": map[string]string{
			"title": title,
			"body":  body,
		},
		"data": data,
	}

	jsonData, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "key="+pp.config.FCMServerKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := pp.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("FCM returned status %d", resp.StatusCode)
	}

	return nil
}

// ====================================================================================
// NOTIFICATION MANAGER
// ====================================================================================

// NewEmailNotificationManager creates a new notification manager
func NewEmailNotificationManager(config *NotificationConfig) *EmailNotificationManager {
	if config.QueueSize == 0 {
		config.QueueSize = 1000
	}
	if config.Workers == 0 {
		config.Workers = 5
	}

	enm := &EmailNotificationManager{
		config: config,
		queue:  make(chan *Notification, config.QueueSize),
		done:   make(chan struct{}),
	}

	// Initialize providers
	if config.EmailEnabled {
		enm.emailProvider = NewEmailProvider(config)

		// Load default email templates
		enm.loadDefaultTemplates()
	}

	if config.SMSEnabled {
		enm.smsProvider = NewSMSProvider(config)
	}

	if config.PushEnabled {
		enm.pushProvider = NewPushProvider(config)
	}

	return enm
}

// Start starts the notification workers
func (enm *EmailNotificationManager) Start() {
	for i := 0; i < enm.config.Workers; i++ {
		go enm.worker()
	}

	LogInfo("NOTIFICATIONS", "Notification manager started with %d workers", enm.config.Workers)
}

// Stop stops the notification manager
func (enm *EmailNotificationManager) Stop() {
	close(enm.done)
	LogInfo("NOTIFICATIONS", "Notification manager stopped")
}

// worker processes notifications from queue
func (enm *EmailNotificationManager) worker() {
	for {
		select {
		case notification := <-enm.queue:
			enm.processNotification(notification)
		case <-enm.done:
			return
		}
	}
}

// Send queues a notification
func (enm *EmailNotificationManager) Send(notification *Notification) error {
	if notification.ID == "" {
		notification.ID = generateID()
	}
	notification.CreatedAt = time.Now()

	select {
	case enm.queue <- notification:
		return nil
	default:
		return fmt.Errorf("notification queue full")
	}
}

// processNotification processes a single notification
func (enm *EmailNotificationManager) processNotification(n *Notification) {
	var err error

	switch n.Type {
	case NotifyTypeEmail:
		if n.Template != "" && enm.emailProvider != nil {
			err = enm.emailProvider.SendEmailTemplate(n.To, n.Subject, n.Template, n.Data)
		} else if enm.emailProvider != nil {
			err = enm.emailProvider.SendEmail(n.To, n.Subject, n.Body)
		} else {
			err = fmt.Errorf("email provider not configured")
		}

		if err == nil {
			enm.stats.EmailSent++
		}

	case NotifyTypeSMS:
		if enm.smsProvider != nil {
			err = enm.smsProvider.SendSMS(n.To, n.Body)
			if err == nil {
				enm.stats.SMSSent++
			}
		} else {
			err = fmt.Errorf("SMS provider not configured")
		}

	case NotifyTypePush:
		if enm.pushProvider != nil {
			err = enm.pushProvider.SendPush(n.To, n.Subject, n.Body, n.Data)
			if err == nil {
				enm.stats.PushSent++
			}
		} else {
			err = fmt.Errorf("push provider not configured")
		}

	case NotifyTypeTelegram:
		// Already handled by bot.go TelegramNotifier
		LogInfo("NOTIFICATIONS", "Telegram notification handled by bot")
		enm.stats.TelegramSent++
		return

	default:
		err = fmt.Errorf("unknown notification type: %s", n.Type)
	}

	if err != nil {
		LogError("NOTIFICATIONS", "Failed to send %s to %s: %v", n.Type, n.To, err)
		enm.stats.TotalFailed++

		// Retry if enabled
		if enm.config.RetryEnabled && n.Retries < MaxRetries {
			n.Retries++
			time.Sleep(RetryDelay)
			enm.queue <- n
		}
	} else {
		LogInfo("NOTIFICATIONS", "Sent %s to %s", n.Type, n.To)
		enm.stats.TotalSent++
	}
}

// GetStats returns notification statistics
func (enm *EmailNotificationManager) GetStats() NotificationStats {
	enm.mu.RLock()
	defer enm.mu.RUnlock()
	return enm.stats
}

// loadDefaultTemplates loads default email templates
func (enm *EmailNotificationManager) loadDefaultTemplates() {
	templates := map[string]string{
		"welcome": `
			<h2>Welcome to MXUI VPN Panel!</h2>
			<p>Hello {{.Username}},</p>
			<p>Your account has been successfully created.</p>
			<p>Account Details:</p>
			<ul>
				<li>Email: {{.Email}}</li>
				<li>Expiry Date: {{.ExpiryDate}}</li>
				<li>Traffic Limit: {{.TrafficLimit}} GB</li>
			</ul>
			<p>Thank you for choosing our service!</p>
		`,
		"expiry_warning": `
			<h2>Account Expiry Warning</h2>
			<p>Hello {{.Username}},</p>
			<p>Your account will expire in {{.DaysRemaining}} days.</p>
			<p>Please renew your subscription to avoid service interruption.</p>
		`,
		"traffic_warning": `
			<h2>Traffic Limit Warning</h2>
			<p>Hello {{.Username}},</p>
			<p>You have used {{.UsagePercent}}% of your traffic limit.</p>
			<p>Remaining: {{.RemainingTraffic}} GB</p>
		`,
	}

	for name, content := range templates {
		if err := enm.emailProvider.LoadTemplate(name, content); err != nil {
			LogWarn("NOTIFICATIONS", "Failed to load template %s: %v", name, err)
		}
	}
}

// Helper function to generate notification ID
func generateID() string {
	return fmt.Sprintf("notif_%d", time.Now().UnixNano())
}
