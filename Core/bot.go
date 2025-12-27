// MXUI VPN Panel
// Core/bot.go
// Telegram Bot: Core, Commands, Keyboards, Handlers, Payments, Notifications

package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// CONSTANTS
// ============================================================================

const (
	// Telegram API
	TelegramAPIBase     = "https://api.telegram.org/bot"
	TelegramFileAPIBase = "https://api.telegram.org/file/bot"

	// Update methods
	UpdateMethodPolling = "polling"
	UpdateMethodWebhook = "webhook"

	// Timeouts
	BotPollingTimeout = 60
	BotRequestTimeout = 30 * time.Second

	// Limits
	MaxMessageLength   = 4096
	MaxCaptionLength   = 1024
	MaxCallbackDataLen = 64
	MaxInlineButtons   = 100

	// States
	StateNone           = ""
	StateAwaitingAmount = "awaiting_amount"
	StateAwaitingDays   = "awaiting_days"
	StateAwaitingNote   = "awaiting_note"
	StateAwaitingSearch = "awaiting_search"
	StateAwaitingConfig = "awaiting_config"

	// Callback prefixes
	CallbackUserView      = "user_view:"
	CallbackUserEnable    = "user_enable:"
	CallbackUserDisable   = "user_disable:"
	CallbackUserDelete    = "user_delete:"
	CallbackUserExtend    = "user_extend:"
	CallbackUserReset     = "user_reset:"
	CallbackUserQR        = "user_qr:"
	CallbackUserLink      = "user_link:"
	CallbackPlanSelect    = "plan_select:"
	CallbackPaymentMethod = "payment:"
	CallbackConfirm       = "confirm:"
	CallbackCancel        = "cancel:"
	CallbackPage          = "page:"
	CallbackBack          = "back"
	CallbackClose         = "close"

	// Inline keyboard style
	KeyboardStyleGlass  = "glass"
	KeyboardStyleFlat   = "flat"
	KeyboardStyleInline = "inline"

	// Wallet callbacks
	CallbackWallet       = "wallet:"
	CallbackWalletCharge = "wallet_charge:"
)

// ============================================================================
// BOT MANAGER
// ============================================================================

// TelegramBot represents the Telegram bot
type TelegramBot struct {
	config           TelegramConfig
	token            string
	username         string
	httpClient       *http.Client
	updateOffset     int64
	handlers         map[string]CommandHandler
	callbackHandlers map[string]CallbackHandler
	userStates       map[int64]*UserState
	statesMu         sync.RWMutex
	isRunning        bool
	ctx              context.Context
	cancel           context.CancelFunc
	mu               sync.RWMutex
}

// CommandHandler handles a command
type CommandHandler func(*TelegramBot, *Update) error

// CallbackHandler handles a callback query
type CallbackHandler func(*TelegramBot, *CallbackQuery) error

// UserState represents user's current state in conversation
type UserState struct {
	WalletBalance float64 `json:"wallet_balance"`
	State         string
	KeyboardStyle string `json:"keyboard_style"` // glass, flat
	Data          map[string]interface{}
	UpdatedAt     time.Time
}

// Global bot instance
var Bot *TelegramBot

// InitTelegramBot initializes the Telegram bot
func InitTelegramBot(config TelegramConfig) error {
	if config.BotToken == "" {
		return errors.New("bot token is required")
	}

	ctx, cancel := context.WithCancel(context.Background())

	Bot = &TelegramBot{
		config:           config,
		token:            config.BotToken,
		httpClient:       &http.Client{Timeout: BotRequestTimeout},
		handlers:         make(map[string]CommandHandler),
		callbackHandlers: make(map[string]CallbackHandler),
		userStates:       make(map[int64]*UserState),
		ctx:              ctx,
		cancel:           cancel,
	}

	// Get bot info
	me, err := Bot.GetMe()
	if err != nil {
		return fmt.Errorf("failed to get bot info: %w", err)
	}
	Bot.username = me.Username

	// Register handlers
	Bot.registerHandlers()

	return nil
}

// ============================================================================
// TELEGRAM TYPES
// ============================================================================

// Update represents an incoming update
type Update struct {
	UpdateID      int64          `json:"update_id"`
	Message       *Message       `json:"message,omitempty"`
	EditedMessage *Message       `json:"edited_message,omitempty"`
	CallbackQuery *CallbackQuery `json:"callback_query,omitempty"`
	InlineQuery   *InlineQuery   `json:"inline_query,omitempty"`
}

// Message represents a message
type Message struct {
	MessageID         int64              `json:"message_id"`
	From              *TelegramUser      `json:"from,omitempty"`
	Chat              *Chat              `json:"chat"`
	Date              int64              `json:"date"`
	Text              string             `json:"text,omitempty"`
	Entities          []MessageEntity    `json:"entities,omitempty"`
	ReplyToMessage    *Message           `json:"reply_to_message,omitempty"`
	Photo             []PhotoSize        `json:"photo,omitempty"`
	Document          *Document          `json:"document,omitempty"`
	Caption           string             `json:"caption,omitempty"`
	Contact           *Contact           `json:"contact,omitempty"`
	Location          *Location          `json:"location,omitempty"`
	NewChatMembers    []TelegramUser     `json:"new_chat_members,omitempty"`
	LeftChatMember    *TelegramUser      `json:"left_chat_member,omitempty"`
	SuccessfulPayment *SuccessfulPayment `json:"successful_payment,omitempty"`
}

// TelegramUser represents a Telegram user
type TelegramUser struct {
	ID           int64  `json:"id"`
	IsBot        bool   `json:"is_bot"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name,omitempty"`
	Username     string `json:"username,omitempty"`
	LanguageCode string `json:"language_code,omitempty"`
}

// Chat represents a chat
type Chat struct {
	ID        int64  `json:"id"`
	Type      string `json:"type"` // private, group, supergroup, channel
	Title     string `json:"title,omitempty"`
	Username  string `json:"username,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

// MessageEntity represents a message entity
type MessageEntity struct {
	Type   string        `json:"type"`
	Offset int           `json:"offset"`
	Length int           `json:"length"`
	URL    string        `json:"url,omitempty"`
	User   *TelegramUser `json:"user,omitempty"`
}

// CallbackQuery represents a callback query
type CallbackQuery struct {
	ID              string        `json:"id"`
	From            *TelegramUser `json:"from"`
	Message         *Message      `json:"message,omitempty"`
	InlineMessageID string        `json:"inline_message_id,omitempty"`
	ChatInstance    string        `json:"chat_instance"`
	Data            string        `json:"data,omitempty"`
}

// InlineQuery represents an inline query
type InlineQuery struct {
	ID       string        `json:"id"`
	From     *TelegramUser `json:"from"`
	Query    string        `json:"query"`
	Offset   string        `json:"offset"`
	Location *Location     `json:"location,omitempty"`
}

// PhotoSize represents a photo size
type PhotoSize struct {
	FileID       string `json:"file_id"`
	FileUniqueID string `json:"file_unique_id"`
	Width        int    `json:"width"`
	Height       int    `json:"height"`
	FileSize     int    `json:"file_size,omitempty"`
}

// Document represents a document
type Document struct {
	FileID       string     `json:"file_id"`
	FileUniqueID string     `json:"file_unique_id"`
	Thumbnail    *PhotoSize `json:"thumbnail,omitempty"`
	FileName     string     `json:"file_name,omitempty"`
	MimeType     string     `json:"mime_type,omitempty"`
	FileSize     int64      `json:"file_size,omitempty"`
}

// Contact represents a contact
type Contact struct {
	PhoneNumber string `json:"phone_number"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name,omitempty"`
	UserID      int64  `json:"user_id,omitempty"`
	VCard       string `json:"vcard,omitempty"`
}

// Location represents a location
type Location struct {
	Longitude float64 `json:"longitude"`
	Latitude  float64 `json:"latitude"`
}

// SuccessfulPayment represents a successful payment
type SuccessfulPayment struct {
	Currency                string     `json:"currency"`
	TotalAmount             int        `json:"total_amount"`
	InvoicePayload          string     `json:"invoice_payload"`
	ShippingOptionID        string     `json:"shipping_option_id,omitempty"`
	OrderInfo               *OrderInfo `json:"order_info,omitempty"`
	TelegramPaymentChargeID string     `json:"telegram_payment_charge_id"`
	ProviderPaymentChargeID string     `json:"provider_payment_charge_id"`
}

// OrderInfo represents order information
type OrderInfo struct {
	Name            string           `json:"name,omitempty"`
	PhoneNumber     string           `json:"phone_number,omitempty"`
	Email           string           `json:"email,omitempty"`
	ShippingAddress *ShippingAddress `json:"shipping_address,omitempty"`
}

// ShippingAddress represents a shipping address
type ShippingAddress struct {
	CountryCode string `json:"country_code"`
	State       string `json:"state"`
	City        string `json:"city"`
	StreetLine1 string `json:"street_line1"`
	StreetLine2 string `json:"street_line2"`
	PostCode    string `json:"post_code"`
}

// ============================================================================
// KEYBOARD TYPES
// ============================================================================

// InlineKeyboardMarkup represents an inline keyboard
type InlineKeyboardMarkup struct {
	InlineKeyboard [][]InlineKeyboardButton `json:"inline_keyboard"`
}

// InlineKeyboardButton represents an inline keyboard button
type InlineKeyboardButton struct {
	Text                         string `json:"text"`
	URL                          string `json:"url,omitempty"`
	CallbackData                 string `json:"callback_data,omitempty"`
	SwitchInlineQuery            string `json:"switch_inline_query,omitempty"`
	SwitchInlineQueryCurrentChat string `json:"switch_inline_query_current_chat,omitempty"`
	Pay                          bool   `json:"pay,omitempty"`
}

// ReplyKeyboardMarkup represents a reply keyboard
type ReplyKeyboardMarkup struct {
	Keyboard        [][]KeyboardButton `json:"keyboard"`
	ResizeKeyboard  bool               `json:"resize_keyboard,omitempty"`
	OneTimeKeyboard bool               `json:"one_time_keyboard,omitempty"`
	Selective       bool               `json:"selective,omitempty"`
	IsPersistent    bool               `json:"is_persistent,omitempty"`
}

// KeyboardButton represents a keyboard button
type KeyboardButton struct {
	Text            string `json:"text"`
	RequestContact  bool   `json:"request_contact,omitempty"`
	RequestLocation bool   `json:"request_location,omitempty"`
}

// ReplyKeyboardRemove represents a request to remove reply keyboard
type ReplyKeyboardRemove struct {
	RemoveKeyboard bool `json:"remove_keyboard"`
	Selective      bool `json:"selective,omitempty"`
}

// ============================================================================
// API METHODS
// ============================================================================

// apiRequest makes a request to Telegram API
func (b *TelegramBot) apiRequest(method string, params map[string]interface{}) (json.RawMessage, error) {
	url := fmt.Sprintf("%s%s/%s", TelegramAPIBase, b.token, method)

	body, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result,omitempty"`
		Description string          `json:"description,omitempty"`
		ErrorCode   int             `json:"error_code,omitempty"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	if !result.OK {
		return nil, fmt.Errorf("telegram error %d: %s", result.ErrorCode, result.Description)
	}

	return result.Result, nil
}

// GetMe returns bot information
func (b *TelegramBot) GetMe() (*TelegramUser, error) {
	result, err := b.apiRequest("getMe", nil)
	if err != nil {
		return nil, err
	}

	var user TelegramUser
	if err := json.Unmarshal(result, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

// GetUpdates gets updates using long polling
func (b *TelegramBot) GetUpdates(offset int64, timeout int) ([]Update, error) {
	params := map[string]interface{}{
		"offset":  offset,
		"timeout": timeout,
		"allowed_updates": []string{
			"message", "edited_message", "callback_query", "inline_query",
		},
	}

	result, err := b.apiRequest("getUpdates", params)
	if err != nil {
		return nil, err
	}

	var updates []Update
	if err := json.Unmarshal(result, &updates); err != nil {
		return nil, err
	}

	return updates, nil
}

func (b *TelegramBot) createGlassKeyboard(buttons [][]InlineKeyboardButton) *InlineKeyboardMarkup {
	// Same as inline but UI shows glass style in client
	return &InlineKeyboardMarkup{InlineKeyboard: buttons}
}

// SetWebhook sets the webhook URL
func (b *TelegramBot) SetWebhook(url string) error {
	params := map[string]interface{}{
		"url": url,
		"allowed_updates": []string{
			"message", "edited_message", "callback_query", "inline_query",
		},
	}

	_, err := b.apiRequest("setWebhook", params)
	return err
}

// DeleteWebhook removes the webhook
func (b *TelegramBot) DeleteWebhook() error {
	_, err := b.apiRequest("deleteWebhook", nil)
	return err
}

// SendMessage sends a text message
func (b *TelegramBot) SendMessage(chatID int64, text string, options *SendMessageOptions) (*Message, error) {
	if len(text) > MaxMessageLength {
		text = text[:MaxMessageLength-3] + "..."
	}

	params := map[string]interface{}{
		"chat_id": chatID,
		"text":    text,
	}

	if options != nil {
		if options.ParseMode != "" {
			params["parse_mode"] = options.ParseMode
		}
		if options.ReplyMarkup != nil {
			params["reply_markup"] = options.ReplyMarkup
		}
		if options.ReplyToMessageID > 0 {
			params["reply_to_message_id"] = options.ReplyToMessageID
		}
		if options.DisableWebPagePreview {
			params["disable_web_page_preview"] = true
		}
		if options.DisableNotification {
			params["disable_notification"] = true
		}
	}

	result, err := b.apiRequest("sendMessage", params)
	if err != nil {
		return nil, err
	}

	var msg Message
	if err := json.Unmarshal(result, &msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

// SendMessageOptions represents options for sending a message
type SendMessageOptions struct {
	ParseMode             string      `json:"parse_mode,omitempty"`
	ReplyMarkup           interface{} `json:"reply_markup,omitempty"`
	ReplyToMessageID      int64       `json:"reply_to_message_id,omitempty"`
	DisableWebPagePreview bool        `json:"disable_web_page_preview,omitempty"`
	DisableNotification   bool        `json:"disable_notification,omitempty"`
}

// EditMessageText edits a message's text
func (b *TelegramBot) EditMessageText(chatID int64, messageID int64, text string, options *SendMessageOptions) (*Message, error) {
	params := map[string]interface{}{
		"chat_id":    chatID,
		"message_id": messageID,
		"text":       text,
	}

	if options != nil {
		if options.ParseMode != "" {
			params["parse_mode"] = options.ParseMode
		}
		if options.ReplyMarkup != nil {
			params["reply_markup"] = options.ReplyMarkup
		}
		if options.DisableWebPagePreview {
			params["disable_web_page_preview"] = true
		}
	}

	result, err := b.apiRequest("editMessageText", params)
	if err != nil {
		return nil, err
	}

	var msg Message
	if err := json.Unmarshal(result, &msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

// EditMessageReplyMarkup edits a message's reply markup
func (b *TelegramBot) EditMessageReplyMarkup(chatID int64, messageID int64, markup *InlineKeyboardMarkup) error {
	params := map[string]interface{}{
		"chat_id":      chatID,
		"message_id":   messageID,
		"reply_markup": markup,
	}

	_, err := b.apiRequest("editMessageReplyMarkup", params)
	return err
}

// DeleteMessage deletes a message
func (b *TelegramBot) DeleteMessage(chatID int64, messageID int64) error {
	params := map[string]interface{}{
		"chat_id":    chatID,
		"message_id": messageID,
	}

	_, err := b.apiRequest("deleteMessage", params)
	return err
}

// AnswerCallbackQuery answers a callback query
func (b *TelegramBot) AnswerCallbackQuery(queryID string, text string, showAlert bool) error {
	params := map[string]interface{}{
		"callback_query_id": queryID,
	}

	if text != "" {
		params["text"] = text
		params["show_alert"] = showAlert
	}

	_, err := b.apiRequest("answerCallbackQuery", params)
	return err
}

// SendPhoto sends a photo
func (b *TelegramBot) SendPhoto(chatID int64, photo interface{}, caption string, options *SendMessageOptions) (*Message, error) {
	params := map[string]interface{}{
		"chat_id": chatID,
	}

	switch p := photo.(type) {
	case string:
		params["photo"] = p
	default:
		return nil, errors.New("unsupported photo type")
	}

	if caption != "" {
		if len(caption) > MaxCaptionLength {
			caption = caption[:MaxCaptionLength-3] + "..."
		}
		params["caption"] = caption
	}

	if options != nil {
		if options.ParseMode != "" {
			params["parse_mode"] = options.ParseMode
		}
		if options.ReplyMarkup != nil {
			params["reply_markup"] = options.ReplyMarkup
		}
	}

	result, err := b.apiRequest("sendPhoto", params)
	if err != nil {
		return nil, err
	}

	var msg Message
	if err := json.Unmarshal(result, &msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

// SendDocument sends a document
func (b *TelegramBot) SendDocument(chatID int64, document interface{}, caption string, options *SendMessageOptions) (*Message, error) {
	params := map[string]interface{}{
		"chat_id": chatID,
	}

	switch d := document.(type) {
	case string:
		params["document"] = d
	default:
		return nil, errors.New("unsupported document type")
	}

	if caption != "" {
		params["caption"] = caption
	}

	if options != nil {
		if options.ParseMode != "" {
			params["parse_mode"] = options.ParseMode
		}
		if options.ReplyMarkup != nil {
			params["reply_markup"] = options.ReplyMarkup
		}
	}

	result, err := b.apiRequest("sendDocument", params)
	if err != nil {
		return nil, err
	}

	var msg Message
	if err := json.Unmarshal(result, &msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

// SendInvoice sends an invoice
func (b *TelegramBot) SendInvoice(chatID int64, invoice *TelegramInvoice) (*Message, error) {
	params := map[string]interface{}{
		"chat_id":        chatID,
		"title":          invoice.Title,
		"description":    invoice.Description,
		"payload":        invoice.Payload,
		"provider_token": invoice.ProviderToken,
		"currency":       invoice.Currency,
		"prices":         invoice.Prices,
	}

	if invoice.ReplyMarkup != nil {
		params["reply_markup"] = invoice.ReplyMarkup
	}

	result, err := b.apiRequest("sendInvoice", params)
	if err != nil {
		return nil, err
	}

	var msg Message
	if err := json.Unmarshal(result, &msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

// TelegramInvoice represents a Telegram invoice
type TelegramInvoice struct {
	Title         string                `json:"title"`
	Description   string                `json:"description"`
	Payload       string                `json:"payload"`
	ProviderToken string                `json:"provider_token"`
	Currency      string                `json:"currency"`
	Prices        []LabeledPrice        `json:"prices"`
	ReplyMarkup   *InlineKeyboardMarkup `json:"reply_markup,omitempty"`
}

// LabeledPrice represents a price label
type LabeledPrice struct {
	Label  string `json:"label"`
	Amount int    `json:"amount"` // In smallest units (e.g., cents)
}

// AnswerPreCheckoutQuery answers a pre-checkout query
func (b *TelegramBot) AnswerPreCheckoutQuery(queryID string, ok bool, errorMessage string) error {
	params := map[string]interface{}{
		"pre_checkout_query_id": queryID,
		"ok":                    ok,
	}

	if !ok && errorMessage != "" {
		params["error_message"] = errorMessage
	}

	_, err := b.apiRequest("answerPreCheckoutQuery", params)
	return err
}

// SendChatAction sends a chat action
func (b *TelegramBot) SendChatAction(chatID int64, action string) error {
	params := map[string]interface{}{
		"chat_id": chatID,
		"action":  action,
	}

	_, err := b.apiRequest("sendChatAction", params)
	return err
}

// GetFile gets file info
func (b *TelegramBot) GetFile(fileID string) (*File, error) {
	params := map[string]interface{}{
		"file_id": fileID,
	}

	result, err := b.apiRequest("getFile", params)
	if err != nil {
		return nil, err
	}

	var file File
	if err := json.Unmarshal(result, &file); err != nil {
		return nil, err
	}

	return &file, nil
}

// File represents a file
type File struct {
	FileID       string `json:"file_id"`
	FileUniqueID string `json:"file_unique_id"`
	FileSize     int64  `json:"file_size,omitempty"`
	FilePath     string `json:"file_path,omitempty"`
}

// GetFileURL returns the download URL for a file
func (b *TelegramBot) GetFileURL(filePath string) string {
	return fmt.Sprintf("%s%s/%s", TelegramFileAPIBase, b.token, filePath)
}

// ============================================================================
// BOT LIFECYCLE
// ============================================================================

// Start starts the bot
func (b *TelegramBot) Start() error {
	b.mu.Lock()
	if b.isRunning {
		b.mu.Unlock()
		return nil
	}
	b.isRunning = true
	b.mu.Unlock()

	if b.config.UseWebhook && b.config.WebhookURL != "" {
		return b.SetWebhook(b.config.WebhookURL)
	}

	// Use polling
	go b.pollingLoop()

	return nil
}

// Stop stops the bot
func (b *TelegramBot) Stop() {
	b.mu.Lock()
	b.isRunning = false
	b.mu.Unlock()

	b.cancel()

	if b.config.UseWebhook {
		b.DeleteWebhook()
	}
}

// pollingLoop runs the polling loop
func (b *TelegramBot) pollingLoop() {
	for {
		select {
		case <-b.ctx.Done():
			return
		default:
			updates, err := b.GetUpdates(b.updateOffset, BotPollingTimeout)
			if err != nil {
				time.Sleep(5 * time.Second)
				continue
			}

			for _, update := range updates {
				b.updateOffset = update.UpdateID + 1
				go b.handleUpdate(&update)
			}
		}
	}
}

// HandleWebhook handles a webhook update
func (b *TelegramBot) HandleWebhook(body []byte) error {
	var update Update
	if err := json.Unmarshal(body, &update); err != nil {
		return err
	}

	go b.handleUpdate(&update)
	return nil
}

// handleUpdate processes an update
func (b *TelegramBot) handleUpdate(update *Update) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[Bot] Panic in update handler: %v\n", r)
		}
	}()

	if update.Message != nil {
		b.handleMessage(update)
	} else if update.CallbackQuery != nil {
		b.handleCallbackQuery(update.CallbackQuery)
	} else if update.InlineQuery != nil {
		b.handleInlineQuery(update.InlineQuery)
	}
}

// ============================================================================
// MESSAGE HANDLERS
// ============================================================================

func (b *TelegramBot) handleMessage(update *Update) {
	msg := update.Message
	if msg == nil || msg.From == nil {
		return
	}

	// Check for command
	if msg.Text != "" && strings.HasPrefix(msg.Text, "/") {
		b.handleCommand(update)
		return
	}

	// Check for payment
	if msg.SuccessfulPayment != nil {
		b.handleSuccessfulPayment(msg)
		return
	}

	// Check user state
	state := b.getUserState(msg.From.ID)
	if state != nil && state.State != StateNone {
		b.handleStatefulMessage(update, state)
		return
	}

	// Default message handling
	b.handleDefaultMessage(update)
}

func (b *TelegramBot) handleCommand(update *Update) {
	msg := update.Message
	text := strings.TrimSpace(msg.Text)

	// Parse command
	parts := strings.SplitN(text, " ", 2)
	command := strings.ToLower(parts[0])

	// Remove bot username if present
	if idx := strings.Index(command, "@"); idx != -1 {
		command = command[:idx]
	}

	// Find handler
	handler, ok := b.handlers[command]
	if !ok {
		b.SendMessage(msg.Chat.ID, "âŒ Ø¯Ø³ØªÙˆØ± Ù†Ø§Ù…Ø¹ØªØ¨Ø± Ø§Ø³Øª.\n\nðŸ“‹ Ø¨Ø±Ø§ÛŒ Ù…Ø´Ø§Ù‡Ø¯Ù‡ Ø¯Ø³ØªÙˆØ±Ø§Øª Ø§Ø² /help Ø§Ø³ØªÙØ§Ø¯Ù‡ Ú©Ù†ÛŒØ¯.", nil)
		return
	}

	// Execute handler
	if err := handler(b, update); err != nil {
		fmt.Printf("[Bot] Command error: %v\n", err)
		b.SendMessage(msg.Chat.ID, "âŒ Ø®Ø·Ø§ Ø¯Ø± Ø§Ø¬Ø±Ø§ÛŒ Ø¯Ø³ØªÙˆØ±", nil)
	}
}

func (b *TelegramBot) handleStatefulMessage(update *Update, state *UserState) {
	msg := update.Message
	chatID := msg.Chat.ID
	userID := msg.From.ID

	switch state.State {
	case StateAwaitingAmount:
		amount, err := strconv.ParseInt(msg.Text, 10, 64)
		if err != nil || amount <= 0 {
			b.SendMessage(chatID, "âŒ Ù„Ø·ÙØ§Ù‹ ÛŒÚ© Ø¹Ø¯Ø¯ Ù…Ø¹ØªØ¨Ø± ÙˆØ§Ø±Ø¯ Ú©Ù†ÛŒØ¯:", nil)
			return
		}
		state.Data["amount"] = amount
		b.clearUserState(userID)
		b.processUserCreation(chatID, state.Data)

	case StateAwaitingDays:
		days, err := strconv.Atoi(msg.Text)
		if err != nil || days <= 0 {
			b.SendMessage(chatID, "âŒ Ù„Ø·ÙØ§Ù‹ ÛŒÚ© Ø¹Ø¯Ø¯ Ù…Ø¹ØªØ¨Ø± ÙˆØ§Ø±Ø¯ Ú©Ù†ÛŒØ¯:", nil)
			return
		}
		state.Data["days"] = days
		b.clearUserState(userID)
		b.processExtendUser(chatID, state.Data)

	case StateAwaitingSearch:
		b.clearUserState(userID)
		b.searchUsers(chatID, msg.Text, userID)

	case StateAwaitingNote:
		state.Data["note"] = msg.Text
		b.clearUserState(userID)
		b.processUserUpdate(chatID, state.Data)

	default:
		b.clearUserState(userID)
	}
}

func (b *TelegramBot) handleDefaultMessage(update *Update) {
	msg := update.Message
	chatID := msg.Chat.ID

	// Show main menu
	b.showMainMenu(chatID)
}

// ============================================================================
// CALLBACK HANDLERS
// ============================================================================

func (b *TelegramBot) handleCallbackQuery(query *CallbackQuery) {
	defer b.AnswerCallbackQuery(query.ID, "", false)

	data := query.Data
	chatID := query.Message.Chat.ID
	messageID := query.Message.MessageID
	userID := query.From.ID

	switch {
	case data == CallbackBack:
		b.showMainMenu(chatID)
		b.DeleteMessage(chatID, messageID)

	case data == CallbackClose:
		b.DeleteMessage(chatID, messageID)

	case strings.HasPrefix(data, CallbackUserView):
		id, _ := strconv.ParseInt(strings.TrimPrefix(data, CallbackUserView), 10, 64)
		b.showUserDetails(chatID, messageID, id, userID)

	case strings.HasPrefix(data, CallbackUserEnable):
		id, _ := strconv.ParseInt(strings.TrimPrefix(data, CallbackUserEnable), 10, 64)
		b.enableUser(chatID, messageID, id, userID)

	case strings.HasPrefix(data, CallbackUserDisable):
		id, _ := strconv.ParseInt(strings.TrimPrefix(data, CallbackUserDisable), 10, 64)
		b.disableUser(chatID, messageID, id, userID)

	case strings.HasPrefix(data, CallbackUserDelete):
		id, _ := strconv.ParseInt(strings.TrimPrefix(data, CallbackUserDelete), 10, 64)
		b.deleteUser(chatID, messageID, id, userID)

	case strings.HasPrefix(data, CallbackUserExtend):
		id, _ := strconv.ParseInt(strings.TrimPrefix(data, CallbackUserExtend), 10, 64)
		b.promptExtendUser(chatID, id, userID)

	case strings.HasPrefix(data, CallbackUserReset):
		id, _ := strconv.ParseInt(strings.TrimPrefix(data, CallbackUserReset), 10, 64)
		b.resetUserTraffic(chatID, messageID, id, userID)

	case strings.HasPrefix(data, CallbackUserQR):
		id, _ := strconv.ParseInt(strings.TrimPrefix(data, CallbackUserQR), 10, 64)
		b.sendUserQRCode(chatID, id, userID)

	case strings.HasPrefix(data, CallbackUserLink):
		id, _ := strconv.ParseInt(strings.TrimPrefix(data, CallbackUserLink), 10, 64)
		b.sendUserLink(chatID, id, userID)

	case strings.HasPrefix(data, CallbackPlanSelect):
		planID, _ := strconv.ParseInt(strings.TrimPrefix(data, CallbackPlanSelect), 10, 64)
		b.handlePlanSelection(chatID, messageID, planID, userID)

	case strings.HasPrefix(data, CallbackPage):
		page, _ := strconv.Atoi(strings.TrimPrefix(data, CallbackPage))
		b.showUsersPage(chatID, messageID, page, userID)

	default:
		// Check custom callback handlers
		for prefix, handler := range b.callbackHandlers {
			if strings.HasPrefix(data, prefix) {
				handler(b, query)
				return
			}
		}
	}
}

// ============================================================================
// COMMAND REGISTRATION
// ============================================================================

func (b *TelegramBot) registerHandlers() {
	// Public commands
	b.handlers["/start"] = b.cmdStart
	b.handlers["/help"] = b.cmdHelp
	b.handlers["/status"] = b.cmdStatus
	b.handlers["/plans"] = b.cmdPlans

	// User commands
	b.handlers["/myaccount"] = b.cmdMyAccount
	b.handlers["/support"] = b.cmdSupport

	// Admin commands
	b.handlers["/admin"] = b.cmdAdmin
	b.handlers["/users"] = b.cmdUsers
	b.handlers["/newuser"] = b.cmdNewUser
	b.handlers["/search"] = b.cmdSearch
	b.handlers["/online"] = b.cmdOnline
	b.handlers["/stats"] = b.cmdStats
	b.handlers["/backup"] = b.cmdBackup
	b.handlers["/broadcast"] = b.cmdBroadcast
	b.handlers["/report"] = b.cmdReport
}

// ============================================================================
// COMMAND IMPLEMENTATIONS
// ============================================================================

func (b *TelegramBot) cmdStart(bot *TelegramBot, update *Update) error {
	msg := update.Message
	chatID := msg.Chat.ID
	userID := msg.From.ID

	// Check for deep link
	args := strings.TrimPrefix(msg.Text, "/start")
	args = strings.TrimSpace(args)

	if args != "" {
		// Handle deep link
		return b.handleDeepLink(chatID, userID, args)
	}

	// Check if admin
	admin, _ := Admins.GetAdminByTelegramID(userID)
	if admin != nil {
		return b.showAdminPanel(chatID, admin)
	}

	// Show welcome message
	text := fmt.Sprintf(`
ðŸ‘‹ Ø³Ù„Ø§Ù… %s!

ðŸŒ Ø¨Ù‡ Ø±Ø¨Ø§Øª *MXUI VPN* Ø®ÙˆØ´ Ø¢Ù…Ø¯ÛŒØ¯.

ðŸ“‹ Ø¯Ø³ØªÙˆØ±Ø§Øª Ù…ÙˆØ¬ÙˆØ¯:
/plans - Ù…Ø´Ø§Ù‡Ø¯Ù‡ Ù¾Ù„Ù†â€ŒÙ‡Ø§ Ùˆ Ø®Ø±ÛŒØ¯
/myaccount - Ù…Ø´Ø§Ù‡Ø¯Ù‡ Ø§Ú©Ø§Ù†Øª Ø´Ù…Ø§
/support - Ø§Ø±ØªØ¨Ø§Ø· Ø¨Ø§ Ù¾Ø´ØªÛŒØ¨Ø§Ù†ÛŒ
/help - Ø±Ø§Ù‡Ù†Ù…Ø§

ðŸ’¡ Ø¨Ø±Ø§ÛŒ Ø®Ø±ÛŒØ¯ Ø§Ø´ØªØ±Ø§Ú© Ø§Ø² /plans Ø§Ø³ØªÙØ§Ø¯Ù‡ Ú©Ù†ÛŒØ¯.
`, msg.From.FirstName)

	keyboard := b.getMainMenuKeyboard(false)

	b.SendMessage(chatID, text, &SendMessageOptions{
		ParseMode:   "Markdown",
		ReplyMarkup: keyboard,
	})

	return nil
}

func (b *TelegramBot) cmdHelp(bot *TelegramBot, update *Update) error {
	msg := update.Message
	chatID := msg.Chat.ID

	text := `
ðŸ“š *Ø±Ø§Ù‡Ù†Ù…Ø§ÛŒ Ø±Ø¨Ø§Øª MXUI VPN*

ðŸ”¹ *Ø¯Ø³ØªÙˆØ±Ø§Øª Ú©Ø§Ø±Ø¨Ø±ÛŒ:*
/start - Ø´Ø±ÙˆØ¹ Ù…Ø¬Ø¯Ø¯ Ø±Ø¨Ø§Øª
/plans - Ù…Ø´Ø§Ù‡Ø¯Ù‡ Ù¾Ù„Ù†â€ŒÙ‡Ø§ÛŒ Ø§Ø´ØªØ±Ø§Ú©
/myaccount - Ù…Ø´Ø§Ù‡Ø¯Ù‡ ÙˆØ¶Ø¹ÛŒØª Ø§Ú©Ø§Ù†Øª
/support - Ø§Ø±ØªØ¨Ø§Ø· Ø¨Ø§ Ù¾Ø´ØªÛŒØ¨Ø§Ù†ÛŒ

ðŸ”¹ *Ø¯Ø³ØªÙˆØ±Ø§Øª Ø§Ø¯Ù…ÛŒÙ†:*
/admin - Ù¾Ù†Ù„ Ù…Ø¯ÛŒØ±ÛŒØª
/users - Ù„ÛŒØ³Øª Ú©Ø§Ø±Ø¨Ø±Ø§Ù†
/newuser - Ø§ÛŒØ¬Ø§Ø¯ Ú©Ø§Ø±Ø¨Ø± Ø¬Ø¯ÛŒØ¯
/search - Ø¬Ø³ØªØ¬ÙˆÛŒ Ú©Ø§Ø±Ø¨Ø±
/online - Ú©Ø§Ø±Ø¨Ø±Ø§Ù† Ø¢Ù†Ù„Ø§ÛŒÙ†
/stats - Ø¢Ù…Ø§Ø± Ø³ÛŒØ³ØªÙ…
/backup - Ù¾Ø´ØªÛŒØ¨Ø§Ù†â€ŒÚ¯ÛŒØ±ÛŒ
/broadcast - Ø§Ø±Ø³Ø§Ù„ Ù¾ÛŒØ§Ù… Ù‡Ù…Ú¯Ø§Ù†ÛŒ
/report - Ú¯Ø²Ø§Ø±Ø´ ÙØ±ÙˆØ´

â„¹ï¸ Ø¨Ø±Ø§ÛŒ Ø§Ø·Ù„Ø§Ø¹Ø§Øª Ø¨ÛŒØ´ØªØ± Ø¨Ø§ Ù¾Ø´ØªÛŒØ¨Ø§Ù†ÛŒ ØªÙ…Ø§Ø³ Ø¨Ú¯ÛŒØ±ÛŒØ¯.
`

	b.SendMessage(chatID, text, &SendMessageOptions{ParseMode: "Markdown"})
	return nil
}

func (b *TelegramBot) cmdStatus(bot *TelegramBot, update *Update) error {
	msg := update.Message
	chatID := msg.Chat.ID

	stats, _ := DB.GetSystemStats()

	text := fmt.Sprintf(`
ðŸ“Š *ÙˆØ¶Ø¹ÛŒØª Ø³Ø±ÙˆÛŒØ³*

ðŸ‘¥ Ú©Ù„ Ú©Ø§Ø±Ø¨Ø±Ø§Ù†: %d
âœ… Ú©Ø§Ø±Ø¨Ø±Ø§Ù† ÙØ¹Ø§Ù„: %d
ðŸŸ¢ Ø¢Ù†Ù„Ø§ÛŒÙ†: %d
â° Ù…Ù†Ù‚Ø¶ÛŒ Ø´Ø¯Ù‡: %d

ðŸŒ Ù†ÙˆØ¯Ù‡Ø§:
  â€¢ Ú©Ù„: %d
  â€¢ Ø¢Ù†Ù„Ø§ÛŒÙ†: %d

ðŸ“ˆ ØªØ±Ø§ÙÛŒÚ© Ú©Ù„: %s
`,
		stats.TotalUsers, stats.ActiveUsers, stats.OnlineUsers, stats.ExpiredUsers,
		stats.TotalNodes, stats.OnlineNodes,
		FormatBytes(stats.TotalTraffic))

	b.SendMessage(chatID, text, &SendMessageOptions{ParseMode: "Markdown"})
	return nil
}

func (b *TelegramBot) cmdPlans(bot *TelegramBot, update *Update) error {
	msg := update.Message
	chatID := msg.Chat.ID

	// Get plans from database
	rows, err := DB.db.Query(`
		SELECT id, name, description, price, currency, duration, data_limit
		FROM subscription_plans WHERE is_active = 1 ORDER BY sort_order
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var buttons [][]InlineKeyboardButton
	text := "Plans:\n\n"

	for rows.Next() {
		var plan SubscriptionPlan
		var priceStr, currency string
		var dataLimit int64
		rows.Scan(&plan.ID, &plan.Name, &plan.Description, &priceStr,
			&currency, &plan.DurationDays, &dataLimit)

		text += fmt.Sprintf("ðŸ”¹ *%s*\n", plan.Name)
		text += fmt.Sprintf("   ðŸ’° Ù‚ÛŒÙ…Øª: %.0f %s\n", float64(0), "USD")
		text += fmt.Sprintf("   ðŸ“… Ù…Ø¯Øª: %d Ø±ÙˆØ²\n", plan.DurationDays)
		if plan.TrafficGB > 0 {
			text += fmt.Sprintf("   ðŸ“Š ØªØ±Ø§ÙÛŒÚ©: %s\n", FormatBytes(plan.TrafficGB))
		} else {
			text += "   ðŸ“Š ØªØ±Ø§ÙÛŒÚ©: Ù†Ø§Ù…Ø­Ø¯ÙˆØ¯\n"
		}
		text += "\n"

		buttons = append(buttons, []InlineKeyboardButton{
			{Text: fmt.Sprintf("ðŸ›’ Ø®Ø±ÛŒØ¯ %s", plan.Name), CallbackData: fmt.Sprintf("%s%d", CallbackPlanSelect, plan.ID)},
		})
	}

	buttons = append(buttons, []InlineKeyboardButton{
		{Text: "âŒ Ø¨Ø³ØªÙ†", CallbackData: CallbackClose},
	})

	keyboard := &InlineKeyboardMarkup{InlineKeyboard: buttons}

	b.SendMessage(chatID, text, &SendMessageOptions{
		ParseMode:   "Markdown",
		ReplyMarkup: keyboard,
	})

	return nil
}

func (b *TelegramBot) cmdMyAccount(bot *TelegramBot, update *Update) error {
	msg := update.Message
	chatID := msg.Chat.ID
	_ = msg.From.ID // userID for cmdMyAccount

	// Find user by Telegram ID (you'd need to link accounts)
	// For now, show a message to login
	text := `
ðŸ‘¤ *Ø§Ú©Ø§Ù†Øª Ø´Ù…Ø§*

Ø¨Ø±Ø§ÛŒ Ù…Ø´Ø§Ù‡Ø¯Ù‡ Ø§Ø·Ù„Ø§Ø¹Ø§Øª Ø§Ú©Ø§Ù†ØªØŒ Ù„ÛŒÙ†Ú© Ø§Ø´ØªØ±Ø§Ú© Ø®ÙˆØ¯ Ø±Ø§ Ø§Ø±Ø³Ø§Ù„ Ú©Ù†ÛŒØ¯.

ÛŒØ§ Ø§Ø² Ù„ÛŒÙ†Ú© Ø²ÛŒØ± ÙˆØ§Ø±Ø¯ Ù¾Ù†Ù„ Ø´ÙˆÛŒØ¯:
`

	b.SendMessage(chatID, text, &SendMessageOptions{ParseMode: "Markdown"})
	return nil
}

func (b *TelegramBot) cmdSupport(bot *TelegramBot, update *Update) error {
	msg := update.Message
	chatID := msg.Chat.ID

	text := `
ðŸ“ž *Ù¾Ø´ØªÛŒØ¨Ø§Ù†ÛŒ*

ðŸ• Ø³Ø§Ø¹Ø§Øª Ù¾Ø§Ø³Ø®Ú¯ÙˆÛŒÛŒ: 9 ØµØ¨Ø­ ØªØ§ 12 Ø´Ø¨

ðŸ“± Ø±Ø§Ù‡â€ŒÙ‡Ø§ÛŒ Ø§Ø±ØªØ¨Ø§Ø·ÛŒ:
â€¢ ØªÙ„Ú¯Ø±Ø§Ù…: @MRX_Support
â€¢ Ø§ÛŒÙ…ÛŒÙ„: support@mxui-vpn.com

âš¡ Ù…Ø¹Ù…ÙˆÙ„Ø§Ù‹ Ø¯Ø± Ú©Ù…ØªØ± Ø§Ø² 1 Ø³Ø§Ø¹Øª Ù¾Ø§Ø³Ø® Ù…ÛŒâ€ŒØ¯Ù‡ÛŒÙ….
`

	keyboard := &InlineKeyboardMarkup{
		InlineKeyboard: [][]InlineKeyboardButton{
			{{Text: "ðŸ’¬ Ú†Øª Ø¨Ø§ Ù¾Ø´ØªÛŒØ¨Ø§Ù†ÛŒ", URL: "https://t.me/MRX_Support"}},
			{{Text: "âŒ Ø¨Ø³ØªÙ†", CallbackData: CallbackClose}},
		},
	}

	b.SendMessage(chatID, text, &SendMessageOptions{
		ParseMode:   "Markdown",
		ReplyMarkup: keyboard,
	})

	return nil
}

// ============================================================================
// ADMIN COMMANDS
// ============================================================================

func (b *TelegramBot) cmdAdmin(bot *TelegramBot, update *Update) error {
	msg := update.Message
	chatID := msg.Chat.ID
	userID := msg.From.ID

	admin, err := Admins.GetAdminByTelegramID(userID)
	if err != nil {
		b.SendMessage(chatID, "â›” Ø´Ù…Ø§ Ø¯Ø³ØªØ±Ø³ÛŒ Ø§Ø¯Ù…ÛŒÙ† Ù†Ø¯Ø§Ø±ÛŒØ¯.", nil)
		return nil
	}

	return b.showAdminPanel(chatID, admin)
}

func (b *TelegramBot) showAdminPanel(chatID int64, admin *Admin) error {
	stats, _ := Users.GetUserStatsForAdmin(admin.ID)

	var text string
	if admin.Role == AdminRoleOwner {
		systemStats, _ := DB.GetSystemStats()
		text = fmt.Sprintf(`
ðŸ” *Ù¾Ù†Ù„ Ù…Ø¯ÛŒØ±ÛŒØª*

ðŸ‘‹ Ø³Ù„Ø§Ù… %s (%s)

ðŸ“Š *Ø¢Ù…Ø§Ø± Ú©Ù„ÛŒ:*
ðŸ‘¥ Ú©Ù„ Ú©Ø§Ø±Ø¨Ø±Ø§Ù†: %d
âœ… ÙØ¹Ø§Ù„: %d
ðŸ”´ Ù…Ù†Ù‚Ø¶ÛŒ: %d
ðŸŸ¢ Ø¢Ù†Ù„Ø§ÛŒÙ†: %d

ðŸŒ Ù†ÙˆØ¯Ù‡Ø§: %d/%d Ø¢Ù†Ù„Ø§ÛŒÙ†
ðŸ“ˆ ØªØ±Ø§ÙÛŒÚ© Ú©Ù„: %s
`,
			admin.Username, admin.Role,
			systemStats.TotalUsers, systemStats.ActiveUsers,
			systemStats.ExpiredUsers, systemStats.OnlineUsers,
			systemStats.OnlineNodes, systemStats.TotalNodes,
			FormatBytes(systemStats.TotalTraffic))
	} else {
		text = fmt.Sprintf(`
ðŸ” *Ù¾Ù†Ù„ ÙØ±ÙˆØ´*

ðŸ‘‹ Ø³Ù„Ø§Ù… %s

ðŸ“Š *Ø¢Ù…Ø§Ø± Ø´Ù…Ø§:*
ðŸ‘¥ Ú©Ø§Ø±Ø¨Ø±Ø§Ù† Ø´Ù…Ø§: %d
âœ… ÙØ¹Ø§Ù„: %d
ðŸ”´ Ù…Ù†Ù‚Ø¶ÛŒ: %d
ðŸŸ¢ Ø¢Ù†Ù„Ø§ÛŒÙ†: %d

ðŸ“ˆ ØªØ±Ø§ÙÛŒÚ© Ù…ØµØ±ÙÛŒ: %s / %s
`,
			admin.Username,
			stats.TotalUsers, stats.ActiveUsers,
			stats.ExpiredUsers, stats.OnlineUsers,
			FormatBytes(admin.TrafficUsed), FormatBytes(admin.TrafficLimit))
	}

	keyboard := b.getAdminKeyboard(admin)

	b.SendMessage(chatID, text, &SendMessageOptions{
		ParseMode:   "Markdown",
		ReplyMarkup: keyboard,
	})

	return nil
}

func (b *TelegramBot) cmdUsers(bot *TelegramBot, update *Update) error {
	msg := update.Message
	chatID := msg.Chat.ID
	userID := msg.From.ID

	admin, err := Admins.GetAdminByTelegramID(userID)
	if err != nil {
		b.SendMessage(chatID, "â›” Ø´Ù…Ø§ Ø¯Ø³ØªØ±Ø³ÛŒ Ù†Ø¯Ø§Ø±ÛŒØ¯.", nil)
		return nil
	}

	return b.showUsersPage(chatID, 0, 1, admin.ID)
}

func (b *TelegramBot) showUsersPage(chatID int64, messageID int64, page int, adminID int64) error {
	admin, _ := Admins.GetAdminByID(adminID)
	if admin == nil {
		return nil
	}

	filter := &UserFilter{
		Limit:  10,
		Offset: (page - 1) * 10,
	}

	if admin.Role == AdminRoleReseller {
		filter.AdminID = admin.ID
	}

	result, _ := Users.ListUsers(filter)

	if len(result.Users) == 0 {
		b.SendMessage(chatID, "ðŸ“­ Ú©Ø§Ø±Ø¨Ø±ÛŒ ÛŒØ§ÙØª Ù†Ø´Ø¯.", nil)
		return nil
	}

	text := "ðŸ‘¥ *Ù„ÛŒØ³Øª Ú©Ø§Ø±Ø¨Ø±Ø§Ù†*\n\n"
	var buttons [][]InlineKeyboardButton

	for _, user := range result.Users {
		status := "âœ…"
		switch user.Status {
		case UserStatusExpired:
			status = "ðŸ”´"
		case UserStatusLimited:
			status = "ðŸŸ¡"
		case UserStatusDisabled:
			status = "âš«"
		}

		text += fmt.Sprintf("%s `%s`\n", status, user.Username)

		buttons = append(buttons, []InlineKeyboardButton{
			{Text: user.Username, CallbackData: fmt.Sprintf("%s%d", CallbackUserView, user.ID)},
		})
	}

	// Pagination
	navButtons := []InlineKeyboardButton{}
	if page > 1 {
		navButtons = append(navButtons, InlineKeyboardButton{
			Text: "â—€ï¸ Ù‚Ø¨Ù„ÛŒ", CallbackData: fmt.Sprintf("%s%d", CallbackPage, page-1),
		})
	}
	navButtons = append(navButtons, InlineKeyboardButton{
		Text: fmt.Sprintf("ðŸ“„ %d/%d", page, result.TotalPages), CallbackData: "noop",
	})
	if page < result.TotalPages {
		navButtons = append(navButtons, InlineKeyboardButton{
			Text: "Ø¨Ø¹Ø¯ÛŒ â–¶ï¸", CallbackData: fmt.Sprintf("%s%d", CallbackPage, page+1),
		})
	}

	buttons = append(buttons, navButtons)
	buttons = append(buttons, []InlineKeyboardButton{
		{Text: "ðŸ”™ Ø¨Ø±Ú¯Ø´Øª", CallbackData: CallbackBack},
	})

	keyboard := &InlineKeyboardMarkup{InlineKeyboard: buttons}

	if messageID > 0 {
		b.EditMessageText(chatID, messageID, text, &SendMessageOptions{
			ParseMode:   "Markdown",
			ReplyMarkup: keyboard,
		})
	} else {
		b.SendMessage(chatID, text, &SendMessageOptions{
			ParseMode:   "Markdown",
			ReplyMarkup: keyboard,
		})
	}

	return nil
}

func (b *TelegramBot) cmdNewUser(bot *TelegramBot, update *Update) error {
	msg := update.Message
	chatID := msg.Chat.ID
	userID := msg.From.ID

	admin, err := Admins.GetAdminByTelegramID(userID)
	if err != nil {
		b.SendMessage(chatID, "â›” Ø´Ù…Ø§ Ø¯Ø³ØªØ±Ø³ÛŒ Ù†Ø¯Ø§Ø±ÛŒØ¯.", nil)
		return nil
	}

	// Check reseller limit
	if admin.Role == AdminRoleReseller {
		canCreate, remaining := Admins.CheckResellerUserLimit(admin)
		if !canCreate {
			b.SendMessage(chatID, fmt.Sprintf("â›” Ø´Ù…Ø§ Ø¨Ù‡ Ø­Ø¯Ø§Ú©Ø«Ø± ØªØ¹Ø¯Ø§Ø¯ Ú©Ø§Ø±Ø¨Ø±Ø§Ù† Ø±Ø³ÛŒØ¯Ù‡â€ŒØ§ÛŒØ¯.\nðŸ”¢ Ø¸Ø±ÙÛŒØª Ø¨Ø§Ù‚ÛŒÙ…Ø§Ù†Ø¯Ù‡: %d", remaining), nil)
			return nil
		}
	}

	// Show plan selection
	return b.cmdPlans(bot, update)
}

func (b *TelegramBot) cmdSearch(bot *TelegramBot, update *Update) error {
	msg := update.Message
	chatID := msg.Chat.ID
	userID := msg.From.ID

	admin, err := Admins.GetAdminByTelegramID(userID)
	if err != nil {
		b.SendMessage(chatID, "â›” Ø´Ù…Ø§ Ø¯Ø³ØªØ±Ø³ÛŒ Ù†Ø¯Ø§Ø±ÛŒØ¯.", nil)
		return nil
	}

	// Check if search term is provided
	parts := strings.SplitN(msg.Text, " ", 2)
	if len(parts) > 1 {
		return b.searchUsers(chatID, parts[1], admin.ID)
	}

	// Ask for search term
	b.setUserState(userID, StateAwaitingSearch, nil)
	b.SendMessage(chatID, "ðŸ” Ù†Ø§Ù… Ú©Ø§Ø±Ø¨Ø±ÛŒ ÛŒØ§ Ø§ÛŒÙ…ÛŒÙ„ Ø±Ø§ Ø¨Ø±Ø§ÛŒ Ø¬Ø³ØªØ¬Ùˆ ÙˆØ§Ø±Ø¯ Ú©Ù†ÛŒØ¯:", nil)

	return nil
}

func (b *TelegramBot) searchUsers(chatID int64, query string, adminID int64) error {
	admin, _ := Admins.GetAdminByID(adminID)
	if admin == nil {
		return nil
	}

	filter := &UserFilter{
		Search: query,
		Limit:  20,
	}

	if admin.Role == AdminRoleReseller {
		filter.AdminID = admin.ID
	}

	result, _ := Users.ListUsers(filter)

	if len(result.Users) == 0 {
		b.SendMessage(chatID, "ðŸ“­ Ú©Ø§Ø±Ø¨Ø±ÛŒ Ø¨Ø§ Ø§ÛŒÙ† Ù…Ø´Ø®ØµØ§Øª ÛŒØ§ÙØª Ù†Ø´Ø¯.", nil)
		return nil
	}

	text := fmt.Sprintf("ðŸ” *Ù†ØªØ§ÛŒØ¬ Ø¬Ø³ØªØ¬Ùˆ Ø¨Ø±Ø§ÛŒ:* `%s`\n\n", query)
	var buttons [][]InlineKeyboardButton

	for _, user := range result.Users {
		status := "âœ…"
		switch user.Status {
		case UserStatusExpired:
			status = "ðŸ”´"
		case UserStatusLimited:
			status = "ðŸŸ¡"
		case UserStatusDisabled:
			status = "âš«"
		}

		text += fmt.Sprintf("%s `%s`\n", status, user.Username)

		buttons = append(buttons, []InlineKeyboardButton{
			{Text: user.Username, CallbackData: fmt.Sprintf("%s%d", CallbackUserView, user.ID)},
		})
	}

	buttons = append(buttons, []InlineKeyboardButton{
		{Text: "âŒ Ø¨Ø³ØªÙ†", CallbackData: CallbackClose},
	})

	keyboard := &InlineKeyboardMarkup{InlineKeyboard: buttons}

	b.SendMessage(chatID, text, &SendMessageOptions{
		ParseMode:   "Markdown",
		ReplyMarkup: keyboard,
	})

	return nil
}

func (b *TelegramBot) cmdOnline(bot *TelegramBot, update *Update) error {
	msg := update.Message
	chatID := msg.Chat.ID
	userID := msg.From.ID

	admin, err := Admins.GetAdminByTelegramID(userID)
	if err != nil {
		b.SendMessage(chatID, "â›” Ø´Ù…Ø§ Ø¯Ø³ØªØ±Ø³ÛŒ Ù†Ø¯Ø§Ø±ÛŒØ¯.", nil)
		return nil
	}

	var onlineUsers []*OnlineUser
	if admin.Role == AdminRoleOwner {
		onlineUsers = Users.GetOnlineUsers()
	} else {
		onlineUsers = Users.GetOnlineUsersForAdmin(admin.ID)
	}

	if len(onlineUsers) == 0 {
		b.SendMessage(chatID, "ðŸ“­ Ù‡ÛŒÚ† Ú©Ø§Ø±Ø¨Ø±ÛŒ Ø¢Ù†Ù„Ø§ÛŒÙ† Ù†ÛŒØ³Øª.", nil)
		return nil
	}

	text := fmt.Sprintf("ðŸŸ¢ *Ú©Ø§Ø±Ø¨Ø±Ø§Ù† Ø¢Ù†Ù„Ø§ÛŒÙ† (%d Ù†ÙØ±)*\n\n", len(onlineUsers))

	for i, ou := range onlineUsers {
		if i >= 50 {
			text += fmt.Sprintf("\n... Ùˆ %d Ú©Ø§Ø±Ø¨Ø± Ø¯ÛŒÚ¯Ø±", len(onlineUsers)-50)
			break
		}

		text += fmt.Sprintf("â€¢ `%s` - %s (%s)\n", ou.Username, ou.IP, ou.Protocol)
	}

	b.SendMessage(chatID, text, &SendMessageOptions{ParseMode: "Markdown"})

	return nil
}

func (b *TelegramBot) cmdStats(bot *TelegramBot, update *Update) error {
	msg := update.Message
	chatID := msg.Chat.ID
	userID := msg.From.ID

	admin, err := Admins.GetAdminByTelegramID(userID)
	if err != nil || admin.Role != AdminRoleOwner {
		b.SendMessage(chatID, "â›” Ø´Ù…Ø§ Ø¯Ø³ØªØ±Ø³ÛŒ Ù†Ø¯Ø§Ø±ÛŒØ¯.", nil)
		return nil
	}

	stats, _ := DB.GetSystemStats()
	userStats, _ := Users.GetUserStats()
	nodeStats := Nodes.GetNodeStats()

	text := fmt.Sprintf(`
ðŸ“Š *Ø¢Ù…Ø§Ø± Ú©Ø§Ù…Ù„ Ø³ÛŒØ³ØªÙ…*

ðŸ‘¥ *Ú©Ø§Ø±Ø¨Ø±Ø§Ù†:*
â€¢ Ú©Ù„: %d
â€¢ ÙØ¹Ø§Ù„: %d
â€¢ Ù…Ù†Ù‚Ø¶ÛŒ: %d
â€¢ Ù…Ø­Ø¯ÙˆØ¯ Ø´Ø¯Ù‡: %d
â€¢ Ø¢Ù†Ù„Ø§ÛŒÙ†: %d

ðŸ“ˆ *Ø§Ù…Ø±ÙˆØ²:*
â€¢ Ú©Ø§Ø±Ø¨Ø±Ø§Ù† Ø¬Ø¯ÛŒØ¯: %d
â€¢ Ù…Ù†Ù‚Ø¶ÛŒ Ø´ÙˆÙ†Ø¯Ù‡: %d

ðŸŒ *Ù†ÙˆØ¯Ù‡Ø§:*
â€¢ Ú©Ù„: %d
â€¢ Ø¢Ù†Ù„Ø§ÛŒÙ†: %d
â€¢ Ø¢ÙÙ„Ø§ÛŒÙ†: %d

ðŸ“Š *ØªØ±Ø§ÙÛŒÚ©:*
â€¢ Ú©Ù„: %s
â€¢ Ø¢Ù¾Ù„ÙˆØ¯: %s
â€¢ Ø¯Ø§Ù†Ù„ÙˆØ¯: %s

ðŸ’¾ *Ø³ÛŒØ³ØªÙ…:*
â€¢ Ø¯ÛŒØªØ§Ø¨ÛŒØ³: OK
`,
		stats.TotalUsers, stats.ActiveUsers, userStats.ExpiredUsers,
		userStats.LimitedUsers, stats.OnlineUsers,
		userStats.NewUsersToday, userStats.ExpiringToday,
		nodeStats.TotalNodes, nodeStats.OnlineNodes, nodeStats.OfflineNodes,
		FormatBytes(stats.TotalTraffic), FormatBytes(stats.TotalUpload), FormatBytes(stats.TotalDownload))

	b.SendMessage(chatID, text, &SendMessageOptions{ParseMode: "Markdown"})

	return nil
}

func (b *TelegramBot) cmdBackup(bot *TelegramBot, update *Update) error {
	msg := update.Message
	chatID := msg.Chat.ID
	userID := msg.From.ID

	admin, err := Admins.GetAdminByTelegramID(userID)
	if err != nil || admin.Role != AdminRoleOwner {
		b.SendMessage(chatID, "â›” Ø´Ù…Ø§ Ø¯Ø³ØªØ±Ø³ÛŒ Ù†Ø¯Ø§Ø±ÛŒØ¯.", nil)
		return nil
	}

	b.SendMessage(chatID, "â³ Ø¯Ø± Ø­Ø§Ù„ Ø§ÛŒØ¬Ø§Ø¯ Ø¨Ú©Ø§Ù¾...", nil)

	// Create backup
	backupPath := fmt.Sprintf("./Data/backups/backup_%s.db", time.Now().Format("20060102_150405"))
	if err := DB.BackupDatabase(backupPath); err != nil {
		b.SendMessage(chatID, "âŒ Ø®Ø·Ø§ Ø¯Ø± Ø§ÛŒØ¬Ø§Ø¯ Ø¨Ú©Ø§Ù¾: "+err.Error(), nil)
		return nil
	}

	// Send file
	b.SendDocument(chatID, backupPath, "ðŸ’¾ ÙØ§ÛŒÙ„ Ø¨Ú©Ø§Ù¾ Ø¯ÛŒØªØ§Ø¨ÛŒØ³", nil)

	return nil
}

func (b *TelegramBot) cmdBroadcast(bot *TelegramBot, update *Update) error {
	msg := update.Message
	chatID := msg.Chat.ID
	userID := msg.From.ID

	admin, err := Admins.GetAdminByTelegramID(userID)
	if err != nil || admin.Role != AdminRoleOwner {
		b.SendMessage(chatID, "â›” Ø´Ù…Ø§ Ø¯Ø³ØªØ±Ø³ÛŒ Ù†Ø¯Ø§Ø±ÛŒØ¯.", nil)
		return nil
	}

	parts := strings.SplitN(msg.Text, " ", 2)
	if len(parts) < 2 {
		b.SendMessage(chatID, "ðŸ“¢ Ø§Ø³ØªÙØ§Ø¯Ù‡:\n/broadcast [Ù¾ÛŒØ§Ù…]\n\nÙ…Ø«Ø§Ù„:\n/broadcast Ø³Ø±ÙˆØ±Ù‡Ø§ Ø¢Ù¾Ø¯ÛŒØª Ø´Ø¯Ù†Ø¯!", nil)
		return nil
	}

	broadcastText := parts[1]

	// Send to all admin chat IDs
	sent := 0
	for _, adminChatID := range b.config.AdminChatIDs {
		_, err := b.SendMessage(adminChatID, "ðŸ“¢ *Ù¾ÛŒØ§Ù… Ù‡Ù…Ú¯Ø§Ù†ÛŒ:*\n\n"+broadcastText, &SendMessageOptions{ParseMode: "Markdown"})
		if err == nil {
			sent++
		}
	}

	b.SendMessage(chatID, fmt.Sprintf("âœ… Ù¾ÛŒØ§Ù… Ø¨Ù‡ %d Ù†ÙØ± Ø§Ø±Ø³Ø§Ù„ Ø´Ø¯.", sent), nil)

	return nil
}

func (b *TelegramBot) cmdReport(bot *TelegramBot, update *Update) error {
	msg := update.Message
	chatID := msg.Chat.ID
	userID := msg.From.ID

	admin, err := Admins.GetAdminByTelegramID(userID)
	if err != nil {
		b.SendMessage(chatID, "â›” Ø´Ù…Ø§ Ø¯Ø³ØªØ±Ø³ÛŒ Ù†Ø¯Ø§Ø±ÛŒØ¯.", nil)
		return nil
	}

	stats, _ := Users.GetUserStatsForAdmin(admin.ID)

	text := fmt.Sprintf(`
ðŸ“Š *Ú¯Ø²Ø§Ø±Ø´ ÙØ±ÙˆØ´*

ðŸ‘¤ Ø§Ø¯Ù…ÛŒÙ†: %s
ðŸ“… ØªØ§Ø±ÛŒØ®: %s

ðŸ‘¥ *Ú©Ø§Ø±Ø¨Ø±Ø§Ù†:*
â€¢ Ú©Ù„: %d
â€¢ ÙØ¹Ø§Ù„: %d
â€¢ Ù…Ù†Ù‚Ø¶ÛŒ: %d
â€¢ Ø¢Ù†Ù„Ø§ÛŒÙ†: %d

ðŸ“ˆ *ØªØ±Ø§ÙÛŒÚ© Ù…ØµØ±ÙÛŒ:*
â€¢ Ú©Ù„: %s

ðŸ’° *Ú©Ø§Ø±Ø¨Ø±Ø§Ù† Ø¬Ø¯ÛŒØ¯:*
â€¢ Ø§Ù…Ø±ÙˆØ²: %d
â€¢ Ø§ÛŒÙ† Ù‡ÙØªÙ‡: %d
`,
		admin.Username, time.Now().Format("2006-01-02"),
		stats.TotalUsers, stats.ActiveUsers, stats.ExpiredUsers, stats.OnlineUsers,
		FormatBytes(stats.TotalTraffic),
		stats.NewUsersToday, stats.NewUsersWeek)

	b.SendMessage(chatID, text, &SendMessageOptions{ParseMode: "Markdown"})

	return nil
}

// ============================================================================
// USER ACTIONS
// ============================================================================

func (b *TelegramBot) showUserDetails(chatID int64, messageID int64, userID int64, adminID int64) {
	admin, _ := Admins.GetAdminByID(adminID)
	if admin == nil {
		return
	}

	user, err := Users.GetUserByID(userID)
	if err != nil {
		b.AnswerCallbackQuery("", "Ú©Ø§Ø±Ø¨Ø± ÛŒØ§ÙØª Ù†Ø´Ø¯", true)
		return
	}

	// Check permission
	if admin.Role == AdminRoleReseller && user.CreatedByAdminID != admin.ID {
		b.AnswerCallbackQuery("", "Ø´Ù…Ø§ Ø¨Ù‡ Ø§ÛŒÙ† Ú©Ø§Ø±Ø¨Ø± Ø¯Ø³ØªØ±Ø³ÛŒ Ù†Ø¯Ø§Ø±ÛŒØ¯", true)
		return
	}

	status := "âœ… ÙØ¹Ø§Ù„"
	switch user.Status {
	case UserStatusExpired:
		status = "ðŸ”´ Ù…Ù†Ù‚Ø¶ÛŒ"
	case UserStatusLimited:
		status = "ðŸŸ¡ Ù…Ø­Ø¯ÙˆØ¯"
	case UserStatusDisabled:
		status = "âš« ØºÛŒØ±ÙØ¹Ø§Ù„"
	case UserStatusOnHold:
		status = "â¸ Ø¯Ø± Ø§Ù†ØªØ¸Ø§Ø±"
	}

	remaining := "Ù†Ø§Ù…Ø­Ø¯ÙˆØ¯"
	if user.ExpiryTime != nil {
		days := GetRemainingDays(user.ExpiryTime)
		if days < 0 {
			remaining = "Ù…Ù†Ù‚Ø¶ÛŒ Ø´Ø¯Ù‡"
		} else {
			remaining = fmt.Sprintf("%d Ø±ÙˆØ²", days)
		}
	}

	traffic := "Ù†Ø§Ù…Ø­Ø¯ÙˆØ¯"
	if user.DataLimit > 0 {
		traffic = fmt.Sprintf("%s / %s (%.1f%%)",
			FormatBytes(user.DataUsed), FormatBytes(user.DataLimit),
			float64(user.DataUsed)/float64(user.DataLimit)*100)
	} else {
		traffic = FormatBytes(user.DataUsed)
	}

	text := fmt.Sprintf(`
ðŸ‘¤ *Ø§Ø·Ù„Ø§Ø¹Ø§Øª Ú©Ø§Ø±Ø¨Ø±*

ðŸ”– Ù†Ø§Ù… Ú©Ø§Ø±Ø¨Ø±ÛŒ: `+"`%s`"+`
ðŸ“Š ÙˆØ¶Ø¹ÛŒØª: %s
ðŸ“… Ø²Ù…Ø§Ù† Ø¨Ø§Ù‚ÛŒÙ…Ø§Ù†Ø¯Ù‡: %s
ðŸ“ˆ ØªØ±Ø§ÙÛŒÚ©: %s

ðŸ“± Ù…Ø­Ø¯ÙˆØ¯ÛŒØª Ø¯Ø³ØªÚ¯Ø§Ù‡: %d
ðŸŒ Ù…Ø­Ø¯ÙˆØ¯ÛŒØª IP: %d

â± Ø¢Ø®Ø±ÛŒÙ† Ø§ØªØµØ§Ù„: %s
ðŸŒ Ø¢Ø®Ø±ÛŒÙ† IP: %s
`,
		user.Username, status, remaining, traffic,
		user.DeviceLimit, user.IPLimit,
		func() string {
			if user.LastOnline != nil {
				return user.LastOnline.Format("2006-01-02 15:04")
			}
			return "Ù‡Ø±Ú¯Ø²"
		}(),
		func() string {
			if user.LastIP != "" {
				return user.LastIP
			}
			return "-"
		}())

	buttons := [][]InlineKeyboardButton{
		{
			{Text: "ðŸ“± QR Code", CallbackData: fmt.Sprintf("%s%d", CallbackUserQR, user.ID)},
			{Text: "ðŸ”— Ù„ÛŒÙ†Ú©", CallbackData: fmt.Sprintf("%s%d", CallbackUserLink, user.ID)},
		},
		{
			{Text: "â™»ï¸ Ø±ÛŒØ³Øª ØªØ±Ø§ÙÛŒÚ©", CallbackData: fmt.Sprintf("%s%d", CallbackUserReset, user.ID)},
			{Text: "ðŸ“… ØªÙ…Ø¯ÛŒØ¯", CallbackData: fmt.Sprintf("%s%d", CallbackUserExtend, user.ID)},
		},
	}

	if user.Status == UserStatusActive || user.Status == UserStatusExpired {
		buttons = append(buttons, []InlineKeyboardButton{
			{Text: "â¸ ØºÛŒØ±ÙØ¹Ø§Ù„", CallbackData: fmt.Sprintf("%s%d", CallbackUserDisable, user.ID)},
		})
	} else {
		buttons = append(buttons, []InlineKeyboardButton{
			{Text: "â–¶ï¸ ÙØ¹Ø§Ù„", CallbackData: fmt.Sprintf("%s%d", CallbackUserEnable, user.ID)},
		})
	}

	buttons = append(buttons, []InlineKeyboardButton{
		{Text: "ðŸ—‘ Ø­Ø°Ù", CallbackData: fmt.Sprintf("%s%d", CallbackUserDelete, user.ID)},
	})

	buttons = append(buttons, []InlineKeyboardButton{
		{Text: "ðŸ”™ Ø¨Ø±Ú¯Ø´Øª", CallbackData: CallbackBack},
	})

	keyboard := &InlineKeyboardMarkup{InlineKeyboard: buttons}

	b.EditMessageText(chatID, messageID, text, &SendMessageOptions{
		ParseMode:   "Markdown",
		ReplyMarkup: keyboard,
	})
}

func (b *TelegramBot) enableUser(chatID int64, messageID int64, userID int64, adminID int64) {
	admin, _ := Admins.GetAdminByID(adminID)
	if !b.checkUserPermission(admin, userID) {
		return
	}

	if err := Users.EnableUser(userID); err != nil {
		b.AnswerCallbackQuery("", "Ø®Ø·Ø§ Ø¯Ø± ÙØ¹Ø§Ù„â€ŒØ³Ø§Ø²ÛŒ", true)
		return
	}

	b.showUserDetails(chatID, messageID, userID, adminID)
	b.AnswerCallbackQuery("", "âœ… Ú©Ø§Ø±Ø¨Ø± ÙØ¹Ø§Ù„ Ø´Ø¯", false)
}

func (b *TelegramBot) disableUser(chatID int64, messageID int64, userID int64, adminID int64) {
	admin, _ := Admins.GetAdminByID(adminID)
	if !b.checkUserPermission(admin, userID) {
		return
	}

	if err := Users.DisableUser(userID); err != nil {
		b.AnswerCallbackQuery("", "Ø®Ø·Ø§ Ø¯Ø± ØºÛŒØ±ÙØ¹Ø§Ù„â€ŒØ³Ø§Ø²ÛŒ", true)
		return
	}

	b.showUserDetails(chatID, messageID, userID, adminID)
	b.AnswerCallbackQuery("", "â¸ Ú©Ø§Ø±Ø¨Ø± ØºÛŒØ±ÙØ¹Ø§Ù„ Ø´Ø¯", false)
}

func (b *TelegramBot) deleteUser(chatID int64, messageID int64, userID int64, adminID int64) {
	admin, _ := Admins.GetAdminByID(adminID)
	if !b.checkUserPermission(admin, userID) {
		return
	}

	user, _ := Users.GetUserByID(userID)
	if user == nil {
		return
	}

	// Confirm deletion
	text := fmt.Sprintf("âš ï¸ Ø¢ÛŒØ§ Ø§Ø² Ø­Ø°Ù Ú©Ø§Ø±Ø¨Ø± `%s` Ù…Ø·Ù…Ø¦Ù† Ù‡Ø³ØªÛŒØ¯ØŸ\n\nØ§ÛŒÙ† Ø¹Ù…Ù„ Ù‚Ø§Ø¨Ù„ Ø¨Ø§Ø²Ú¯Ø´Øª Ù†ÛŒØ³Øª!", user.Username)

	keyboard := &InlineKeyboardMarkup{
		InlineKeyboard: [][]InlineKeyboardButton{
			{
				{Text: "âœ… Ø¨Ù„Ù‡ØŒ Ø­Ø°Ù Ú©Ù†", CallbackData: fmt.Sprintf("%s%d", CallbackConfirm, userID)},
				{Text: "âŒ Ø®ÛŒØ±", CallbackData: CallbackBack},
			},
		},
	}

	b.EditMessageText(chatID, messageID, text, &SendMessageOptions{
		ParseMode:   "Markdown",
		ReplyMarkup: keyboard,
	})
}

func (b *TelegramBot) resetUserTraffic(chatID int64, messageID int64, userID int64, adminID int64) {
	admin, _ := Admins.GetAdminByID(adminID)
	if !b.checkUserPermission(admin, userID) {
		return
	}

	if err := Users.ResetUserTraffic(userID); err != nil {
		b.AnswerCallbackQuery("", "Ø®Ø·Ø§ Ø¯Ø± Ø±ÛŒØ³Øª ØªØ±Ø§ÙÛŒÚ©", true)
		return
	}

	b.showUserDetails(chatID, messageID, userID, adminID)
	b.AnswerCallbackQuery("", "â™»ï¸ ØªØ±Ø§ÙÛŒÚ© Ø±ÛŒØ³Øª Ø´Ø¯", false)
}

func (b *TelegramBot) promptExtendUser(chatID int64, userID int64, adminID int64) {
	b.setUserState(adminID, StateAwaitingDays, map[string]interface{}{
		"user_id": userID,
	})

	b.SendMessage(chatID, "ðŸ“… Ú†Ù†Ø¯ Ø±ÙˆØ² Ù…ÛŒâ€ŒØ®ÙˆØ§Ù‡ÛŒØ¯ ØªÙ…Ø¯ÛŒØ¯ Ú©Ù†ÛŒØ¯ØŸ\n\nØ¹Ø¯Ø¯ Ø±Ø§ ÙˆØ§Ø±Ø¯ Ú©Ù†ÛŒØ¯:", nil)
}

func (b *TelegramBot) processExtendUser(chatID int64, data map[string]interface{}) {
	userID, _ := data["user_id"].(int64)
	days, _ := data["days"].(int)

	if err := Users.ExtendSubscription(userID, days, 0); err != nil {
		b.SendMessage(chatID, "âŒ Ø®Ø·Ø§ Ø¯Ø± ØªÙ…Ø¯ÛŒØ¯: "+err.Error(), nil)
		return
	}

	b.SendMessage(chatID, fmt.Sprintf("âœ… Ø§Ø´ØªØ±Ø§Ú© Ú©Ø§Ø±Ø¨Ø± %d Ø±ÙˆØ² ØªÙ…Ø¯ÛŒØ¯ Ø´Ø¯.", days), nil)
}

func (b *TelegramBot) sendUserQRCode(chatID int64, userID int64, adminID int64) {
	admin, _ := Admins.GetAdminByID(adminID)
	if !b.checkUserPermission(admin, userID) {
		return
	}

	user, _ := Users.GetUserByID(userID)
	if user == nil {
		return
	}

	// Generate QR code URL (would need QR generation)
	subURL := fmt.Sprintf("https://example.com/sub/%s", user.SubscriptionURL)

	text := fmt.Sprintf("ðŸ“± *QR Code Ø¨Ø±Ø§ÛŒ* `%s`\n\nðŸ”— Ù„ÛŒÙ†Ú© Ø§Ø´ØªØ±Ø§Ú©:\n`%s`", user.Username, subURL)

	b.SendMessage(chatID, text, &SendMessageOptions{ParseMode: "Markdown"})
}

func (b *TelegramBot) sendUserLink(chatID int64, userID int64, adminID int64) {
	admin, _ := Admins.GetAdminByID(adminID)
	if !b.checkUserPermission(admin, userID) {
		return
	}

	user, _ := Users.GetUserByID(userID)
	if user == nil {
		return
	}

	subURL := fmt.Sprintf("https://example.com/sub/%s", user.SubscriptionURL)

	text := fmt.Sprintf(`
ðŸ”— *Ù„ÛŒÙ†Ú© Ø§Ø´ØªØ±Ø§Ú©*

ðŸ‘¤ Ú©Ø§Ø±Ø¨Ø±: `+"`%s`"+`

ðŸ“‹ Ù„ÛŒÙ†Ú©:
`+"`%s`"+`

ðŸ’¡ Ø§ÛŒÙ† Ù„ÛŒÙ†Ú© Ø±Ø§ Ø¯Ø± Ø§Ù¾Ù„ÛŒÚ©ÛŒØ´Ù† VPN Ø®ÙˆØ¯ ÙˆØ§Ø±Ø¯ Ú©Ù†ÛŒØ¯.
`, user.Username, subURL)

	b.SendMessage(chatID, text, &SendMessageOptions{ParseMode: "Markdown"})
}

func (b *TelegramBot) handlePlanSelection(chatID int64, messageID int64, planID int64, userID int64) {
	admin, _ := Admins.GetAdminByTelegramID(userID)
	if admin == nil {
		b.AnswerCallbackQuery("", "Ù„Ø·ÙØ§Ù‹ Ø§Ø¨ØªØ¯Ø§ Ø§Ø¯Ù…ÛŒÙ† Ø´ÙˆÛŒØ¯", true)
		return
	}

	// Get plan
	var plan SubscriptionPlan
	err := DB.db.QueryRow(`
		SELECT id, name, price, currency, duration, data_limit, device_limit
		FROM subscription_plans WHERE id = ?
	`, planID).Scan(&plan.ID, &plan.Name, nil, nil,
		&plan.DurationDays, &plan.TrafficGB, &plan.DeviceLimit)

	if err != nil {
		b.AnswerCallbackQuery("", "Ù¾Ù„Ù† ÛŒØ§ÙØª Ù†Ø´Ø¯", true)
		return
	}

	// Create user with random username
	username := fmt.Sprintf("user_%d", time.Now().UnixNano()%100000)

	req := &CreateUserRequest{
		Username:         username,
		ExpiryDays:       plan.DurationDays,
		DataLimit:        plan.TrafficGB,
		DeviceLimit:      plan.DeviceLimit,
		CreatedByAdminID: admin.ID,
	}

	user, err := Users.CreateUser(req)
	if err != nil {
		b.AnswerCallbackQuery("", "Ø®Ø·Ø§ Ø¯Ø± Ø§ÛŒØ¬Ø§Ø¯ Ú©Ø§Ø±Ø¨Ø±: "+err.Error(), true)
		return
	}

	// Sync to inbounds
	if Protocols != nil {
		Protocols.SyncUsersToInbounds()
	}

	subURL := fmt.Sprintf("https://example.com/sub/%s", user.SubscriptionURL)

	text := fmt.Sprintf(`
âœ… *Ú©Ø§Ø±Ø¨Ø± Ø¨Ø§ Ù…ÙˆÙÙ‚ÛŒØª Ø§ÛŒØ¬Ø§Ø¯ Ø´Ø¯*

ðŸ“‹ Ù¾Ù„Ù†: %s
ðŸ‘¤ Ù†Ø§Ù… Ú©Ø§Ø±Ø¨Ø±ÛŒ: `+"`%s`"+`
ðŸ“… Ù…Ø¯Øª: %d Ø±ÙˆØ²
ðŸ“Š ØªØ±Ø§ÙÛŒÚ©: %s

ðŸ”— Ù„ÛŒÙ†Ú© Ø§Ø´ØªØ±Ø§Ú©:
`+"`%s`"+`

ðŸ’¡ Ø§ÛŒÙ† Ù„ÛŒÙ†Ú© Ø±Ø§ Ø¨Ø±Ø§ÛŒ Ú©Ø§Ø±Ø¨Ø± Ø§Ø±Ø³Ø§Ù„ Ú©Ù†ÛŒØ¯.
`,
		plan.Name, user.Username, plan.DurationDays,
		func() string {
			if plan.TrafficGB > 0 {
				return FormatBytes(plan.TrafficGB)
			}
			return "Ù†Ø§Ù…Ø­Ø¯ÙˆØ¯"
		}(), subURL)

	b.EditMessageText(chatID, messageID, text, &SendMessageOptions{
		ParseMode: "Markdown",
		ReplyMarkup: &InlineKeyboardMarkup{
			InlineKeyboard: [][]InlineKeyboardButton{
				{
					{Text: "ðŸ“± QR Code", CallbackData: fmt.Sprintf("%s%d", CallbackUserQR, user.ID)},
					{Text: "ðŸ‘¤ Ù…Ø´Ø§Ù‡Ø¯Ù‡", CallbackData: fmt.Sprintf("%s%d", CallbackUserView, user.ID)},
				},
				{{Text: "ðŸ”™ Ø¨Ø±Ú¯Ø´Øª", CallbackData: CallbackBack}},
			},
		},
	})
}

// ============================================================================
// PAYMENT HANDLERS
// ============================================================================

func (b *TelegramBot) handleSuccessfulPayment(msg *Message) {
	payment := msg.SuccessfulPayment
	chatID := msg.Chat.ID

	// Parse payload
	var payload map[string]interface{}
	json.Unmarshal([]byte(payment.InvoicePayload), &payload)

	_, _ = payload["plan_id"].(float64)
	_ = msg.From.ID

	// Create subscription
	// Implementation would create user and link to telegram ID

	text := fmt.Sprintf(`
âœ… *Ù¾Ø±Ø¯Ø§Ø®Øª Ù…ÙˆÙÙ‚*

ðŸ’° Ù…Ø¨Ù„Øº: %.2f %s
ðŸ“‹ Ú©Ø¯ Ù¾ÛŒÚ¯ÛŒØ±ÛŒ: %s

Ø§Ø´ØªØ±Ø§Ú© Ø´Ù…Ø§ ÙØ¹Ø§Ù„ Ø´Ø¯!
`,
		float64(payment.TotalAmount)/100, payment.Currency,
		payment.TelegramPaymentChargeID)

	b.SendMessage(chatID, text, &SendMessageOptions{ParseMode: "Markdown"})
}

// ============================================================================
// INLINE QUERY HANDLERS
// ============================================================================

func (b *TelegramBot) handleInlineQuery(query *InlineQuery) {
	// Implement inline query handling for user search
}

// ============================================================================
// DEEP LINK HANDLERS
// ============================================================================

func (b *TelegramBot) handleDeepLink(chatID int64, userID int64, args string) error {
	// Handle deep links like /start sub_xxxxx
	if strings.HasPrefix(args, "sub_") {
		subToken := strings.TrimPrefix(args, "sub_")
		return b.handleSubscriptionDeepLink(chatID, userID, subToken)
	}

	return nil
}

func (b *TelegramBot) handleSubscriptionDeepLink(chatID int64, userID int64, token string) error {
	user, err := Users.GetUserBySubscriptionURL(token)
	if err != nil {
		b.SendMessage(chatID, "âŒ Ø§Ø´ØªØ±Ø§Ú© Ù†Ø§Ù…Ø¹ØªØ¨Ø± Ø§Ø³Øª.", nil)
		return nil
	}

	info, _ := Users.GetSubscriptionInfo(user.ID)

	text := fmt.Sprintf(`
ðŸ“Š *ÙˆØ¶Ø¹ÛŒØª Ø§Ø´ØªØ±Ø§Ú© Ø´Ù…Ø§*

ðŸ‘¤ Ù†Ø§Ù… Ú©Ø§Ø±Ø¨Ø±ÛŒ: `+"`%s`"+`
ðŸ“Š ÙˆØ¶Ø¹ÛŒØª: %s
ðŸ“… Ø±ÙˆØ² Ø¨Ø§Ù‚ÛŒÙ…Ø§Ù†Ø¯Ù‡: %v
ðŸ“ˆ ØªØ±Ø§ÙÛŒÚ© Ù…ØµØ±ÙÛŒ: %s
`,
		user.Username, user.Status,
		info["days_remaining"], FormatBytes(user.DataUsed))

	keyboard := &InlineKeyboardMarkup{
		InlineKeyboard: [][]InlineKeyboardButton{
			{{Text: "ðŸ”— Ø¯Ø±ÛŒØ§ÙØª Ù„ÛŒÙ†Ú© Ø§ØªØµØ§Ù„", CallbackData: fmt.Sprintf("%s%d", CallbackUserLink, user.ID)}},
			{{Text: "ðŸ“ž Ù¾Ø´ØªÛŒØ¨Ø§Ù†ÛŒ", URL: "https://t.me/MRX_Support"}},
		},
	}

	b.SendMessage(chatID, text, &SendMessageOptions{
		ParseMode:   "Markdown",
		ReplyMarkup: keyboard,
	})

	return nil
}

// ============================================================================
// NOTIFICATIONS
// ============================================================================

// SendNotification sends a notification to admins
func (b *TelegramBot) SendNotification(title, message string) {
	text := fmt.Sprintf("ðŸ”” *%s*\n\n%s", title, message)

	for _, chatID := range b.config.AdminChatIDs {
		b.SendMessage(chatID, text, &SendMessageOptions{ParseMode: "Markdown"})
	}
}

// NotifyUserExpiring notifies about expiring users
func (b *TelegramBot) NotifyUserExpiring(user *User, daysRemaining int) {
	text := fmt.Sprintf(`
âš ï¸ *Ù‡Ø´Ø¯Ø§Ø± Ø§Ù†Ù‚Ø¶Ø§*

Ú©Ø§Ø±Ø¨Ø± `+"`%s`"+` ØªØ§ %d Ø±ÙˆØ² Ø¯ÛŒÚ¯Ø± Ù…Ù†Ù‚Ø¶ÛŒ Ù…ÛŒâ€ŒØ´ÙˆØ¯.
`, user.Username, daysRemaining)

	for _, chatID := range b.config.AdminChatIDs {
		b.SendMessage(chatID, text, &SendMessageOptions{ParseMode: "Markdown"})
	}
}

// NotifyUserExpired notifies about expired users
func (b *TelegramBot) NotifyUserExpired(user *User) {
	text := fmt.Sprintf(`
ðŸ”´ *Ø§Ø´ØªØ±Ø§Ú© Ù…Ù†Ù‚Ø¶ÛŒ Ø´Ø¯*

Ú©Ø§Ø±Ø¨Ø± `+"`%s`"+` Ù…Ù†Ù‚Ø¶ÛŒ Ø´Ø¯.
`, user.Username)

	for _, chatID := range b.config.AdminChatIDs {
		b.SendMessage(chatID, text, &SendMessageOptions{ParseMode: "Markdown"})
	}
}

// NotifyTrafficLimit notifies about traffic limit
func (b *TelegramBot) NotifyTrafficLimit(user *User) {
	text := fmt.Sprintf(`
ðŸŸ¡ *ØªØ±Ø§ÙÛŒÚ© ØªÙ…Ø§Ù… Ø´Ø¯*

Ú©Ø§Ø±Ø¨Ø± `+"`%s`"+` Ø¨Ù‡ Ø­Ø¯ ØªØ±Ø§ÙÛŒÚ© Ø±Ø³ÛŒØ¯.
Ù…ØµØ±Ù: %s / %s
`, user.Username, FormatBytes(user.DataUsed), FormatBytes(user.DataLimit))

	for _, chatID := range b.config.AdminChatIDs {
		b.SendMessage(chatID, text, &SendMessageOptions{ParseMode: "Markdown"})
	}
}

// NotifyNodeDown notifies about node going down
func (b *TelegramBot) NotifyNodeDown(node *Node, err error) {
	text := fmt.Sprintf(`
ðŸ”´ *Ù†ÙˆØ¯ Ø¢ÙÙ„Ø§ÛŒÙ† Ø´Ø¯*

ðŸŒ Ù†ÙˆØ¯: %s
ðŸ“ Ø¢Ø¯Ø±Ø³: %s
âŒ Ø®Ø·Ø§: %s
â° Ø²Ù…Ø§Ù†: %s
`, node.Name, node.Address, err.Error(), time.Now().Format("15:04:05"))

	for _, chatID := range b.config.AdminChatIDs {
		b.SendMessage(chatID, text, &SendMessageOptions{ParseMode: "Markdown"})
	}
}

// NotifyNewUser notifies about new user creation
func (b *TelegramBot) NotifyNewUser(user *User, admin *Admin) {
	text := fmt.Sprintf(`
âœ… *Ú©Ø§Ø±Ø¨Ø± Ø¬Ø¯ÛŒØ¯*

ðŸ‘¤ Ù†Ø§Ù… Ú©Ø§Ø±Ø¨Ø±ÛŒ: `+"`%s`"+`
ðŸ‘” ØªÙˆØ³Ø·: %s
ðŸ“… Ù…Ø¯Øª: %v Ø±ÙˆØ²
ðŸ“Š ØªØ±Ø§ÙÛŒÚ©: %s
`,
		user.Username, admin.Username,
		GetRemainingDays(user.ExpiryTime),
		func() string {
			if user.DataLimit > 0 {
				return FormatBytes(user.DataLimit)
			}
			return "Ù†Ø§Ù…Ø­Ø¯ÙˆØ¯"
		}())

	for _, chatID := range b.config.AdminChatIDs {
		b.SendMessage(chatID, text, &SendMessageOptions{ParseMode: "Markdown"})
	}
}

// ============================================================================
// KEYBOARDS
// ============================================================================

func (b *TelegramBot) getMainMenuKeyboard(isAdmin bool) *ReplyKeyboardMarkup {
	keyboard := &ReplyKeyboardMarkup{
		ResizeKeyboard: true,
		IsPersistent:   true,
	}

	if isAdmin {
		keyboard.Keyboard = [][]KeyboardButton{
			{{Text: "ðŸ‘¥ Ú©Ø§Ø±Ø¨Ø±Ø§Ù†"}, {Text: "âž• Ú©Ø§Ø±Ø¨Ø± Ø¬Ø¯ÛŒØ¯"}},
			{{Text: "ðŸ“Š Ø¢Ù…Ø§Ø±"}, {Text: "ðŸŸ¢ Ø¢Ù†Ù„Ø§ÛŒÙ†â€ŒÙ‡Ø§"}},
			{{Text: "âš™ï¸ ØªÙ†Ø¸ÛŒÙ…Ø§Øª"}, {Text: "ðŸ’¾ Ø¨Ú©Ø§Ù¾"}},
		}
	} else {
		keyboard.Keyboard = [][]KeyboardButton{
			{{Text: "ðŸ“‹ Ù¾Ù„Ù†â€ŒÙ‡Ø§"}, {Text: "ðŸ‘¤ Ø§Ú©Ø§Ù†Øª Ù…Ù†"}},
			{{Text: "ðŸ“ž Ù¾Ø´ØªÛŒØ¨Ø§Ù†ÛŒ"}, {Text: "â“ Ø±Ø§Ù‡Ù†Ù…Ø§"}},
		}
	}

	return keyboard
}

func (b *TelegramBot) getAdminKeyboard(admin *Admin) *InlineKeyboardMarkup {
	buttons := [][]InlineKeyboardButton{
		{
			{Text: "ðŸ‘¥ Ú©Ø§Ø±Ø¨Ø±Ø§Ù†", CallbackData: "menu_users"},
			{Text: "âž• Ú©Ø§Ø±Ø¨Ø± Ø¬Ø¯ÛŒØ¯", CallbackData: "menu_newuser"},
		},
		{
			{Text: "ðŸŸ¢ Ø¢Ù†Ù„Ø§ÛŒÙ†", CallbackData: "menu_online"},
			{Text: "ðŸ” Ø¬Ø³ØªØ¬Ùˆ", CallbackData: "menu_search"},
		},
		{
			{Text: "ðŸ“Š Ú¯Ø²Ø§Ø±Ø´", CallbackData: "menu_report"},
			{Text: "ðŸ“ˆ Ø¢Ù…Ø§Ø±", CallbackData: "menu_stats"},
		},
	}

	if admin.Role == AdminRoleOwner {
		buttons = append(buttons, []InlineKeyboardButton{
			{Text: "ðŸŒ Ù†ÙˆØ¯Ù‡Ø§", CallbackData: "menu_nodes"},
			{Text: "âš™ï¸ ØªÙ†Ø¸ÛŒÙ…Ø§Øª", CallbackData: "menu_settings"},
		})
		buttons = append(buttons, []InlineKeyboardButton{
			{Text: "ðŸ’¾ Ø¨Ú©Ø§Ù¾", CallbackData: "menu_backup"},
			{Text: "ðŸ“¢ Ø§Ø·Ù„Ø§Ø¹â€ŒØ±Ø³Ø§Ù†ÛŒ", CallbackData: "menu_broadcast"},
		})
	}

	return &InlineKeyboardMarkup{InlineKeyboard: buttons}
}

// ============================================================================
// STATE MANAGEMENT
// ============================================================================

func (b *TelegramBot) setUserState(userID int64, state string, data map[string]interface{}) {
	b.statesMu.Lock()
	defer b.statesMu.Unlock()

	b.userStates[userID] = &UserState{
		State:     state,
		Data:      data,
		UpdatedAt: time.Now(),
	}
}

func (b *TelegramBot) getUserState(userID int64) *UserState {
	b.statesMu.RLock()
	defer b.statesMu.RUnlock()

	return b.userStates[userID]
}

func (b *TelegramBot) clearUserState(userID int64) {
	b.statesMu.Lock()
	defer b.statesMu.Unlock()

	delete(b.userStates, userID)
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func (b *TelegramBot) checkUserPermission(admin *Admin, userID int64) bool {
	if admin == nil {
		return false
	}

	if admin.Role == AdminRoleOwner {
		return true
	}

	user, err := Users.GetUserByID(userID)
	if err != nil {
		return false
	}

	return user.CreatedByAdminID == admin.ID
}

func (b *TelegramBot) showMainMenu(chatID int64) {
	text := `
ðŸ  *Ù…Ù†ÙˆÛŒ Ø§ØµÙ„ÛŒ*

Ù„Ø·ÙØ§Ù‹ ÛŒÚ©ÛŒ Ø§Ø² Ú¯Ø²ÛŒÙ†Ù‡â€ŒÙ‡Ø§ Ø±Ø§ Ø§Ù†ØªØ®Ø§Ø¨ Ú©Ù†ÛŒØ¯:
`

	keyboard := b.getMainMenuKeyboard(false)

	b.SendMessage(chatID, text, &SendMessageOptions{
		ParseMode:   "Markdown",
		ReplyMarkup: keyboard,
	})
}

func (b *TelegramBot) processUserCreation(chatID int64, data map[string]interface{}) {
	// Create user based on collected data
	// Implementation would be similar to handlePlanSelection
}

func (b *TelegramBot) processUserUpdate(chatID int64, data map[string]interface{}) {
	// Update user with collected data
}

// IsAdmin checks if a Telegram user is an admin
func (b *TelegramBot) IsAdmin(telegramID int64) bool {
	admin, err := Admins.GetAdminByTelegramID(telegramID)
	return err == nil && admin != nil
}

// GetBotUsername returns the bot username
func (b *TelegramBot) GetBotUsername() string {
	return b.username
}

// CreateGlassButton creates inline button with glass style
func CreateGlassButton(text, data string) InlineKeyboardButton {
	return InlineKeyboardButton{
		Text:         "✨ " + text,
		CallbackData: data,
	}
}
