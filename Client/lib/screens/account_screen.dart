// MX-UI VPN Client
// screens/account_screen.dart - Account Management Screen

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:url_launcher/url_launcher.dart';
import '../core/theme.dart';
import '../core/constants.dart';
import '../providers/app_provider.dart';
import '../providers/account_provider.dart';
import '../widgets/glass_card.dart';

class AccountScreen extends StatelessWidget {
  const AccountScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final isDark = context.watch<AppProvider>().isDarkMode;
    final appProvider = context.watch<AppProvider>();
    final accountProvider = context.watch<AccountProvider>();
    final account = accountProvider.activeAccount;

    return SafeArea(
      child: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(20, 20, 20, 100),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header
            Text(
              'حساب کاربری',
              style: TextStyle(
                color: isDark ? Colors.white : Colors.black87,
                fontSize: 28,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 24),

            // Active Account Card
            if (account != null) ...[
              _ActiveAccountCard(
                account: account,
                isDark: isDark,
                onRefresh: () => accountProvider.refreshAccount(),
              ),
              const SizedBox(height: 16),
            ],

            // Account List
            _AccountsSection(
              accounts: accountProvider.accounts,
              activeAccount: account,
              isDark: isDark,
              onAccountSelected: accountProvider.setActiveAccount,
              onAccountRemoved: accountProvider.removeAccount,
              onAddAccount: () => _showAddAccountDialog(context),
            ),

            const SizedBox(height: 24),

            // Theme Toggle
            _SettingsCard(
              title: 'تم اپلیکیشن',
              subtitle: isDark ? 'تم تیره' : 'تم روشن',
              icon: isDark ? Icons.dark_mode_rounded : Icons.light_mode_rounded,
              iconColor: isDark ? Colors.amber : Colors.orange,
              isDark: isDark,
              trailing: Switch(
                value: isDark,
                onChanged: (_) => appProvider.toggleTheme(),
                activeColor: AppColors.primary,
              ),
            ),

            const SizedBox(height: 16),

            // Telegram Support
            _SettingsCard(
              title: 'پشتیبانی تلگرام',
              subtitle: 'تماس با ادمین',
              icon: Icons.telegram,
              iconColor: const Color(0xFF0088CC),
              isDark: isDark,
              onTap: () => _openTelegram(context),
            ),

            const SizedBox(height: 16),

            // Subscription URL
            if (account != null)
              _SettingsCard(
                title: 'لینک سابسکریپشن',
                subtitle: 'کپی لینک اشتراک',
                icon: Icons.link_rounded,
                iconColor: AppColors.secondary,
                isDark: isDark,
                onTap: () => _copySubscriptionUrl(context, account.subscriptionUrl),
              ),

            const SizedBox(height: 32),

            // Logout Button
            if (account != null)
              Center(
                child: TextButton.icon(
                  onPressed: () => _showLogoutDialog(context),
                  icon: const Icon(Icons.logout_rounded, color: AppColors.error),
                  label: const Text(
                    'خروج از اکانت',
                    style: TextStyle(color: AppColors.error),
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }

  void _showAddAccountDialog(BuildContext context) {
    final controller = TextEditingController();
    final isDark = Theme.of(context).brightness == Brightness.dark;

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: isDark ? AppColors.darkCard : AppColors.lightCard,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(AppConstants.radiusLarge),
        ),
        title: Text(
          'افزودن اکانت',
          style: TextStyle(color: isDark ? Colors.white : Colors.black87),
        ),
        content: TextField(
          controller: controller,
          decoration: InputDecoration(
            hintText: 'لینک سابسکریپشن',
            hintStyle: TextStyle(
              color: isDark ? Colors.white38 : Colors.black38,
            ),
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
            ),
          ),
          style: TextStyle(color: isDark ? Colors.white : Colors.black87),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('انصراف'),
          ),
          ElevatedButton(
            onPressed: () async {
              if (controller.text.isNotEmpty) {
                Navigator.pop(context);
                final provider = Provider.of<AccountProvider>(
                  context,
                  listen: false,
                );
                await provider.addSubscription(controller.text);
              }
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.primary,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
              ),
            ),
            child: const Text('افزودن'),
          ),
        ],
      ),
    );
  }

  void _openTelegram(BuildContext context) async {
    const telegramUrl = 'https://t.me/MX_UI_Support';
    if (await canLaunchUrl(Uri.parse(telegramUrl))) {
      await launchUrl(Uri.parse(telegramUrl), mode: LaunchMode.externalApplication);
    }
  }

  void _copySubscriptionUrl(BuildContext context, String url) {
    Clipboard.setData(ClipboardData(text: url));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: const Text('لینک کپی شد'),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
        ),
      ),
    );
  }

  void _showLogoutDialog(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: isDark ? AppColors.darkCard : AppColors.lightCard,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(AppConstants.radiusLarge),
        ),
        title: Text(
          'خروج از اکانت',
          style: TextStyle(color: isDark ? Colors.white : Colors.black87),
        ),
        content: Text(
          'آیا مطمئن هستید که می‌خواهید از اکانت خارج شوید؟',
          style: TextStyle(color: isDark ? Colors.white70 : Colors.black54),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('انصراف'),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(context);
              Provider.of<AppProvider>(context, listen: false).logout();
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.error,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
              ),
            ),
            child: const Text('خروج'),
          ),
        ],
      ),
    );
  }
}

class _ActiveAccountCard extends StatelessWidget {
  final dynamic account;
  final bool isDark;
  final VoidCallback onRefresh;

  const _ActiveAccountCard({
    required this.account,
    required this.isDark,
    required this.onRefresh,
  });

  String _formatBytes(int bytes) {
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }

  @override
  Widget build(BuildContext context) {
    final usedPercent = account.dataLimit > 0
        ? (account.dataUsed / account.dataLimit * 100).clamp(0, 100)
        : 0.0;

    return GradientGlassCard(
      gradientColors: [
        AppColors.primary.withOpacity(0.3),
        AppColors.secondary.withOpacity(0.2),
      ],
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 56,
                height: 56,
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [AppColors.primary, AppColors.secondary],
                  ),
                  borderRadius: BorderRadius.circular(16),
                ),
                child: const Icon(
                  Icons.person_rounded,
                  color: Colors.white,
                  size: 32,
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      account.name ?? 'اکانت من',
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 20,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    if (account.username != null)
                      Text(
                        account.username,
                        style: const TextStyle(
                          color: Colors.white70,
                          fontSize: 14,
                        ),
                      ),
                  ],
                ),
              ),
              IconButton(
                onPressed: onRefresh,
                icon: const Icon(
                  Icons.refresh_rounded,
                  color: Colors.white70,
                ),
              ),
            ],
          ),
          const SizedBox(height: 24),

          // Stats Grid
          Row(
            children: [
              _StatItem(
                icon: Icons.arrow_upward_rounded,
                label: 'آپلود',
                value: _formatBytes(account.uploadUsed),
              ),
              const SizedBox(width: 16),
              _StatItem(
                icon: Icons.arrow_downward_rounded,
                label: 'دانلود',
                value: _formatBytes(account.downloadUsed),
              ),
              const SizedBox(width: 16),
              _StatItem(
                icon: Icons.calendar_today_rounded,
                label: 'انقضا',
                value: account.expiryTime != null
                    ? '${account.expiryTime.difference(DateTime.now()).inDays} روز'
                    : '∞',
              ),
            ],
          ),

          const SizedBox(height: 20),

          // Usage Bar
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  const Text(
                    'مصرف کل',
                    style: TextStyle(color: Colors.white70, fontSize: 12),
                  ),
                  Text(
                    '${usedPercent.toStringAsFixed(1)}%',
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 12,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              ClipRRect(
                borderRadius: BorderRadius.circular(4),
                child: LinearProgressIndicator(
                  value: usedPercent / 100,
                  backgroundColor: Colors.white.withOpacity(0.2),
                  valueColor: const AlwaysStoppedAnimation<Color>(Colors.white),
                  minHeight: 8,
                ),
              ),
              const SizedBox(height: 4),
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    _formatBytes(account.dataUsed),
                    style: const TextStyle(color: Colors.white60, fontSize: 11),
                  ),
                  Text(
                    account.dataLimit > 0 ? _formatBytes(account.dataLimit) : 'نامحدود',
                    style: const TextStyle(color: Colors.white60, fontSize: 11),
                  ),
                ],
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _StatItem extends StatelessWidget {
  final IconData icon;
  final String label;
  final String value;

  const _StatItem({
    required this.icon,
    required this.label,
    required this.value,
  });

  @override
  Widget build(BuildContext context) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: Colors.white.withOpacity(0.1),
          borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
        ),
        child: Column(
          children: [
            Icon(icon, color: Colors.white70, size: 20),
            const SizedBox(height: 8),
            Text(
              value,
              style: const TextStyle(
                color: Colors.white,
                fontSize: 14,
                fontWeight: FontWeight.bold,
              ),
            ),
            Text(
              label,
              style: const TextStyle(
                color: Colors.white60,
                fontSize: 11,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _AccountsSection extends StatelessWidget {
  final List accounts;
  final dynamic activeAccount;
  final bool isDark;
  final Function(dynamic) onAccountSelected;
  final Function(dynamic) onAccountRemoved;
  final VoidCallback onAddAccount;

  const _AccountsSection({
    required this.accounts,
    required this.activeAccount,
    required this.isDark,
    required this.onAccountSelected,
    required this.onAccountRemoved,
    required this.onAddAccount,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(
              'اکانت‌ها',
              style: TextStyle(
                color: isDark ? Colors.white70 : Colors.black54,
                fontSize: 14,
                fontWeight: FontWeight.w500,
              ),
            ),
            TextButton.icon(
              onPressed: onAddAccount,
              icon: const Icon(Icons.add_rounded, size: 20),
              label: const Text('افزودن'),
              style: TextButton.styleFrom(
                foregroundColor: AppColors.primary,
              ),
            ),
          ],
        ),
        const SizedBox(height: 8),
        ...accounts.map((account) => _AccountListItem(
              account: account,
              isActive: account.id == activeAccount?.id,
              isDark: isDark,
              onTap: () => onAccountSelected(account),
              onRemove: () => onAccountRemoved(account),
            )),
        if (accounts.isEmpty)
          GlassCard(
            isDark: isDark,
            child: Center(
              child: Column(
                children: [
                  Icon(
                    Icons.account_circle_outlined,
                    color: isDark ? Colors.white38 : Colors.black26,
                    size: 48,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'هیچ اکانتی وجود ندارد',
                    style: TextStyle(
                      color: isDark ? Colors.white54 : Colors.black45,
                    ),
                  ),
                ],
              ),
            ),
          ),
      ],
    );
  }
}

class _AccountListItem extends StatelessWidget {
  final dynamic account;
  final bool isActive;
  final bool isDark;
  final VoidCallback onTap;
  final VoidCallback onRemove;

  const _AccountListItem({
    required this.account,
    required this.isActive,
    required this.isDark,
    required this.onTap,
    required this.onRemove,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      child: Material(
        color: isActive
            ? AppColors.primary.withOpacity(0.15)
            : (isDark
                ? Colors.white.withOpacity(0.08)
                : Colors.black.withOpacity(0.05)),
        borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Row(
              children: [
                Container(
                  width: 40,
                  height: 40,
                  decoration: BoxDecoration(
                    color: isActive
                        ? AppColors.primary.withOpacity(0.2)
                        : (isDark
                            ? Colors.white.withOpacity(0.1)
                            : Colors.black.withOpacity(0.1)),
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: Icon(
                    Icons.person_rounded,
                    color: isActive
                        ? AppColors.primary
                        : (isDark ? Colors.white54 : Colors.black45),
                    size: 22,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        account.name ?? 'اکانت',
                        style: TextStyle(
                          color: isDark ? Colors.white : Colors.black87,
                          fontWeight:
                              isActive ? FontWeight.w600 : FontWeight.normal,
                        ),
                      ),
                      Text(
                        '${account.servers.length} سرور',
                        style: TextStyle(
                          color: isDark ? Colors.white54 : Colors.black45,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                ),
                if (isActive)
                  Icon(Icons.check_circle_rounded, color: AppColors.primary),
                IconButton(
                  onPressed: onRemove,
                  icon: Icon(
                    Icons.delete_outline_rounded,
                    color: isDark ? Colors.white38 : Colors.black26,
                    size: 20,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _SettingsCard extends StatelessWidget {
  final String title;
  final String subtitle;
  final IconData icon;
  final Color iconColor;
  final bool isDark;
  final Widget? trailing;
  final VoidCallback? onTap;

  const _SettingsCard({
    required this.title,
    required this.subtitle,
    required this.icon,
    required this.iconColor,
    required this.isDark,
    this.trailing,
    this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GlassCard(
      isDark: isDark,
      padding: const EdgeInsets.all(12),
      onTap: onTap,
      child: Row(
        children: [
          Container(
            width: 40,
            height: 40,
            decoration: BoxDecoration(
              color: iconColor.withOpacity(0.2),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Icon(icon, color: iconColor, size: 22),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: TextStyle(
                    color: isDark ? Colors.white : Colors.black87,
                    fontSize: 14,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                Text(
                  subtitle,
                  style: TextStyle(
                    color: isDark ? Colors.white54 : Colors.black45,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
          if (trailing != null) trailing!,
          if (onTap != null && trailing == null)
            Icon(
              Icons.chevron_left_rounded,
              color: isDark ? Colors.white38 : Colors.black26,
            ),
        ],
      ),
    );
  }
}
