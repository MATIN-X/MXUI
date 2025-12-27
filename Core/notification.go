package core

import (
	"fmt"
	"time"
)

// NotificationManager manages notifications
type NotificationManager struct {
	bot *TelegramBot
}

// Global notification manager instance
var Notifications *NotificationManager

// NewNotificationManager creates notification manager
func NewNotificationManager(bot *TelegramBot) *NotificationManager {
	nm := &NotificationManager{bot: bot}
	Notifications = nm
	return nm
}

// SendNotification sends a notification
func (nm *NotificationManager) SendNotification(userID int64, message string) error {
	if nm.bot == nil {
		return nil
	}
	user, _ := Users.GetUserByID(userID)
	if user != nil && user.TelegramID > 0 {
		nm.bot.SendMessage(user.TelegramID, message, nil)
	}
	return nil
}

// Send sends a notification with type and data (for compatibility)
func (nm *NotificationManager) Send(notifType string, data map[string]interface{}, channels ...string) error {
	message := fmt.Sprintf("[%s] %v", notifType, data)
	return nm.SendToAdmins(message)
}

// SendToAdmins sends notification to all admin Telegram IDs
func (nm *NotificationManager) SendToAdmins(message string) error {
	if nm.bot == nil {
		return nil
	}
	// Get admin chat IDs from config
	for _, adminID := range nm.bot.config.AdminChatIDs {
		nm.bot.SendMessage(adminID, message, nil)
	}
	return nil
}

type NotificationService struct {
	bot *TelegramBot
}

func (ns *NotificationService) SendToUser(userID int64, message string) error {
	user, _ := Users.GetUserByID(userID)
	if user != nil && user.TelegramID > 0 {
		_, err := ns.bot.SendMessage(user.TelegramID, message, nil)
		return err
	}
	return nil
}

func (ns *NotificationService) SendToAllUsers(message string) error {
	users, _ := Users.ListUsers(&UserFilter{Status: UserStatusActive})
	for _, user := range users.Users {
		ns.SendToUser(user.ID, message)
	}
	return nil
}

func (ns *NotificationService) SendExpiryWarning(user *User, daysLeft int) {
	msg := fmt.Sprintf("⚠️ اشتراک شما %d روز دیگر منقضی می‌شود", daysLeft)
	ns.SendToUser(user.ID, msg)
}

// ============================================================================
// GLOBAL NOTIFICATION HELPER FUNCTIONS
// ============================================================================

// NotifyUserExpiringS sends user expiring notification
func NotifyUserExpiring(username string, days int, expiryDate time.Time) {
	if Notifications == nil {
		return
	}
	msg := fmt.Sprintf("⚠️ *هشدار انقضا*\n\n👤 کاربر: `%s`\n⏰ روزهای باقیمانده: *%d*\n📅 تاریخ انقضا: %s",
		username, days, expiryDate.Format("2006-01-02"))
	Notifications.SendToAdmins(msg)
}

// NotifyUserExpiredd sends user expired notification
func NotifyUserExpiredd(username string, expiryDate time.Time) {
	if Notifications == nil {
		return
	}
	msg := fmt.Sprintf("❌ *اشتراک منقضی شد*\n\n👤 کاربر: `%s`\n📅 تاریخ انقضا: %s",
		username, expiryDate.Format("2006-01-02"))
	Notifications.SendToAdmins(msg)
}

// NotifyTrafficLimit sends traffic limit notification
func NotifyTrafficLimit(username string, usedTraffic, totalTraffic int64) {
	if Notifications == nil {
		return
	}
	msg := fmt.Sprintf("📊 *محدودیت ترافیک*\n\n👤 کاربر: `%s`\n📥 مصرف: %s\n📊 سقف: %s",
		username, formatBytesHelper(usedTraffic), formatBytesHelper(totalTraffic))
	Notifications.SendToAdmins(msg)
}

// NotifyPaymentSuccess sends payment success notification
func NotifyPaymentSuccess(username, amount, description string) {
	if Notifications == nil {
		return
	}
	msg := fmt.Sprintf("💰 *پرداخت جدید*\n\n👤 کاربر: `%s`\n💵 مبلغ: *%s*\n📝 توضیحات: %s",
		username, amount, description)
	Notifications.SendToAdmins(msg)
}

// NotifyPaymentFailure sends payment failure notification
func NotifyPaymentFailure(username, amount, reason string) {
	if Notifications == nil {
		return
	}
	msg := fmt.Sprintf("❌ *پرداخت ناموفق*\n\n👤 کاربر: `%s`\n💵 مبلغ: *%s*\n❗ دلیل: %s",
		username, amount, reason)
	Notifications.SendToAdmins(msg)
}

// NotifyNodeDown sends node offline notification
func NotifyNodeDown(nodeName, ip string) {
	if Notifications == nil {
		return
	}
	msg := fmt.Sprintf("🔴 *سرور آفلاین*\n\n🖥️ نام: `%s`\n🌐 IP: `%s`\n⏰ زمان: %s",
		nodeName, ip, time.Now().Format("2006-01-02 15:04:05"))
	Notifications.SendToAdmins(msg)
}

// NotifyNodeUp sends node online notification
func NotifyNodeUp(nodeName, ip string) {
	if Notifications == nil {
		return
	}
	msg := fmt.Sprintf("🟢 *سرور آنلاین*\n\n🖥️ نام: `%s`\n🌐 IP: `%s`\n⏰ زمان: %s",
		nodeName, ip, time.Now().Format("2006-01-02 15:04:05"))
	Notifications.SendToAdmins(msg)
}

// NotifyBruteForceAttack sends brute force detection notification
func NotifyBruteForceAttack(ip string, attempts int, location string) {
	if Notifications == nil {
		return
	}
	msg := fmt.Sprintf("🚨 *حمله Brute Force*\n\n🌐 IP: `%s`\n🔢 تلاش‌ها: *%d*\n🌍 موقعیت: %s\n⏰ زمان: %s",
		ip, attempts, location, time.Now().Format("2006-01-02 15:04:05"))
	Notifications.SendToAdmins(msg)
}

// NotifyBackupDone sends backup completed notification
func NotifyBackupDone(fileName, size string) {
	if Notifications == nil {
		return
	}
	msg := fmt.Sprintf("✅ *پشتیبان‌گیری موفق*\n\n📦 نام فایل: `%s`\n📏 سایز: *%s*\n⏰ زمان: %s",
		fileName, size, time.Now().Format("2006-01-02 15:04:05"))
	Notifications.SendToAdmins(msg)
}

// NotifyAbnormalTrafficAlert sends abnormal traffic notification
func NotifyAbnormalTrafficAlert(username, traffic, description string) {
	if Notifications == nil {
		return
	}
	msg := fmt.Sprintf("📈 *ترافیک غیرعادی*\n\n👤 کاربر: `%s`\n📊 ترافیک: *%s*\n📝 توضیحات: %s",
		username, traffic, description)
	Notifications.SendToAdmins(msg)
}

// formatBytesHelper formats bytes to human readable
func formatBytesHelper(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
