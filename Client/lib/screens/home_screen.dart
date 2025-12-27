// MX-UI VPN Client
// screens/home_screen.dart - Home Screen with Connect Button

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../core/theme.dart';
import '../core/constants.dart';
import '../providers/app_provider.dart';
import '../providers/vpn_provider.dart';
import '../providers/account_provider.dart';
import '../widgets/connect_button.dart';
import '../widgets/warp_toggle.dart';
import '../widgets/connection_mode_selector.dart';
import '../widgets/traffic_stats.dart';
import '../widgets/glass_card.dart';

class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final isDark = context.watch<AppProvider>().isDarkMode;
    final vpn = context.watch<VpnProvider>();
    final account = context.watch<AccountProvider>();

    return SafeArea(
      child: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(20, 20, 20, 100),
        child: Column(
          children: [
            // Header with account info
            _AccountInfoCard(
              account: account.activeAccount,
              isDark: isDark,
            ),

            const SizedBox(height: 24),

            // Server selection
            if (account.activeAccount?.servers.isNotEmpty == true)
              _ServerSelector(
                servers: account.activeAccount!.servers,
                selectedServer: vpn.selectedServer,
                onServerSelected: vpn.selectServer,
                isDark: isDark,
              ),

            const SizedBox(height: 32),

            // Connect Button
            ConnectButton(
              isConnected: vpn.isConnected,
              isConnecting: vpn.isConnecting,
              onTap: vpn.toggleConnection,
            ),

            const SizedBox(height: 24),

            // Connection Status
            _ConnectionStatus(
              status: vpn.status,
              serverName: vpn.selectedServer?.name ?? 'نامشخص',
              isDark: isDark,
            ),

            const SizedBox(height: 24),

            // Traffic Stats (when connected)
            if (vpn.isConnected)
              TrafficStatsWidget(
                stats: vpn.trafficStats,
                isDark: isDark,
              ),

            const SizedBox(height: 24),

            // WARP Toggle
            WarpToggle(
              isEnabled: vpn.warpEnabled,
              isConnected: vpn.warpConnected,
              onToggle: vpn.toggleWarp,
              isDark: isDark,
            ),

            const SizedBox(height: 24),

            // Connection Modes
            ConnectionModeSelector(
              selectedMode: vpn.connectionMode,
              onModeSelected: vpn.setConnectionMode,
              isDark: isDark,
            ),
          ],
        ),
      ),
    );
  }
}

class _AccountInfoCard extends StatelessWidget {
  final dynamic account;
  final bool isDark;

  const _AccountInfoCard({
    required this.account,
    required this.isDark,
  });

  String _formatBytes(int bytes) {
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }

  @override
  Widget build(BuildContext context) {
    if (account == null) {
      return GlassCard(
        isDark: isDark,
        child: Row(
          children: [
            Icon(
              Icons.warning_rounded,
              color: AppColors.warning,
              size: 24,
            ),
            const SizedBox(width: 12),
            Text(
              'اکانتی انتخاب نشده',
              style: TextStyle(
                color: isDark ? Colors.white70 : Colors.black54,
              ),
            ),
          ],
        ),
      );
    }

    final usedPercent = account.dataLimit > 0
        ? (account.dataUsed / account.dataLimit * 100).clamp(0, 100)
        : 0.0;

    return GlassCard(
      isDark: isDark,
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 40,
                height: 40,
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [AppColors.primary, AppColors.secondary],
                  ),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: const Icon(
                  Icons.person_rounded,
                  color: Colors.white,
                  size: 24,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      account.name ?? 'اکانت من',
                      style: TextStyle(
                        color: isDark ? Colors.white : Colors.black87,
                        fontSize: 16,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    if (account.expiryTime != null)
                      Text(
                        'انقضا: ${_formatExpiry(account.expiryTime)}',
                        style: TextStyle(
                          color: isDark ? Colors.white54 : Colors.black45,
                          fontSize: 12,
                        ),
                      ),
                  ],
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: AppColors.success.withOpacity(0.2),
                  borderRadius: BorderRadius.circular(AppConstants.radiusSmall),
                ),
                child: Text(
                  'فعال',
                  style: TextStyle(
                    color: AppColors.success,
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),

          // Data usage progress
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    'مصرف داده',
                    style: TextStyle(
                      color: isDark ? Colors.white54 : Colors.black45,
                      fontSize: 12,
                    ),
                  ),
                  Text(
                    '${_formatBytes(account.dataUsed)} / ${account.dataLimit > 0 ? _formatBytes(account.dataLimit) : '∞'}',
                    style: TextStyle(
                      color: isDark ? Colors.white70 : Colors.black54,
                      fontSize: 12,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              ClipRRect(
                borderRadius: BorderRadius.circular(4),
                child: LinearProgressIndicator(
                  value: usedPercent / 100,
                  backgroundColor: isDark
                      ? Colors.white.withOpacity(0.1)
                      : Colors.black.withOpacity(0.1),
                  valueColor: AlwaysStoppedAnimation<Color>(
                    usedPercent > 80
                        ? AppColors.error
                        : usedPercent > 50
                            ? AppColors.warning
                            : AppColors.success,
                  ),
                  minHeight: 6,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  String _formatExpiry(DateTime date) {
    final now = DateTime.now();
    final diff = date.difference(now);

    if (diff.isNegative) return 'منقضی شده';
    if (diff.inDays > 30) return '${diff.inDays} روز';
    if (diff.inDays > 0) return '${diff.inDays} روز باقی‌مانده';
    if (diff.inHours > 0) return '${diff.inHours} ساعت';
    return '${diff.inMinutes} دقیقه';
  }
}

class _ServerSelector extends StatelessWidget {
  final List servers;
  final dynamic selectedServer;
  final Function(dynamic) onServerSelected;
  final bool isDark;

  const _ServerSelector({
    required this.servers,
    required this.selectedServer,
    required this.onServerSelected,
    required this.isDark,
  });

  @override
  Widget build(BuildContext context) {
    return GlassCard(
      isDark: isDark,
      padding: const EdgeInsets.all(12),
      onTap: () => _showServerPicker(context),
      child: Row(
        children: [
          Container(
            width: 40,
            height: 40,
            decoration: BoxDecoration(
              color: AppColors.primary.withOpacity(0.2),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Icon(
              Icons.dns_rounded,
              color: AppColors.primary,
              size: 22,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  selectedServer?.name ?? 'انتخاب سرور',
                  style: TextStyle(
                    color: isDark ? Colors.white : Colors.black87,
                    fontSize: 14,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                Text(
                  selectedServer != null
                      ? '${selectedServer.protocol.toUpperCase()} - ${selectedServer.address}'
                      : '${servers.length} سرور موجود',
                  style: TextStyle(
                    color: isDark ? Colors.white54 : Colors.black45,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
          Icon(
            Icons.chevron_left_rounded,
            color: isDark ? Colors.white54 : Colors.black45,
          ),
        ],
      ),
    );
  }

  void _showServerPicker(BuildContext context) {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      builder: (context) => _ServerPickerSheet(
        servers: servers,
        selectedServer: selectedServer,
        onServerSelected: onServerSelected,
        isDark: isDark,
      ),
    );
  }
}

class _ServerPickerSheet extends StatelessWidget {
  final List servers;
  final dynamic selectedServer;
  final Function(dynamic) onServerSelected;
  final bool isDark;

  const _ServerPickerSheet({
    required this.servers,
    required this.selectedServer,
    required this.onServerSelected,
    required this.isDark,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        color: isDark ? AppColors.darkCard : AppColors.lightCard,
        borderRadius: const BorderRadius.vertical(
          top: Radius.circular(AppConstants.radiusXLarge),
        ),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            margin: const EdgeInsets.only(top: 12),
            width: 40,
            height: 4,
            decoration: BoxDecoration(
              color: isDark ? Colors.white24 : Colors.black12,
              borderRadius: BorderRadius.circular(2),
            ),
          ),
          Padding(
            padding: const EdgeInsets.all(20),
            child: Row(
              children: [
                Text(
                  'انتخاب سرور',
                  style: TextStyle(
                    color: isDark ? Colors.white : Colors.black87,
                    fontSize: 18,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const Spacer(),
                Text(
                  '${servers.length} سرور',
                  style: TextStyle(
                    color: isDark ? Colors.white54 : Colors.black45,
                    fontSize: 14,
                  ),
                ),
              ],
            ),
          ),
          Flexible(
            child: ListView.builder(
              shrinkWrap: true,
              itemCount: servers.length,
              itemBuilder: (context, index) {
                final server = servers[index];
                final isSelected = server.id == selectedServer?.id;

                return ListTile(
                  onTap: () {
                    onServerSelected(server);
                    Navigator.pop(context);
                  },
                  leading: Container(
                    width: 40,
                    height: 40,
                    decoration: BoxDecoration(
                      color: isSelected
                          ? AppColors.primary.withOpacity(0.2)
                          : (isDark
                              ? Colors.white.withOpacity(0.1)
                              : Colors.black.withOpacity(0.05)),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: Icon(
                      Icons.public_rounded,
                      color: isSelected
                          ? AppColors.primary
                          : (isDark ? Colors.white54 : Colors.black45),
                    ),
                  ),
                  title: Text(
                    server.name,
                    style: TextStyle(
                      color: isDark ? Colors.white : Colors.black87,
                      fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
                    ),
                  ),
                  subtitle: Text(
                    '${server.protocol.toUpperCase()} • ${server.transport}',
                    style: TextStyle(
                      color: isDark ? Colors.white54 : Colors.black45,
                      fontSize: 12,
                    ),
                  ),
                  trailing: isSelected
                      ? Icon(Icons.check_circle_rounded, color: AppColors.primary)
                      : null,
                );
              },
            ),
          ),
          const SizedBox(height: 20),
        ],
      ),
    );
  }
}

class _ConnectionStatus extends StatelessWidget {
  final String status;
  final String serverName;
  final bool isDark;

  const _ConnectionStatus({
    required this.status,
    required this.serverName,
    required this.isDark,
  });

  @override
  Widget build(BuildContext context) {
    String statusText;
    Color statusColor;
    IconData statusIcon;

    switch (status) {
      case VpnStatus.connected:
        statusText = 'متصل به $serverName';
        statusColor = AppColors.success;
        statusIcon = Icons.check_circle_rounded;
        break;
      case VpnStatus.connecting:
        statusText = 'در حال اتصال...';
        statusColor = AppColors.warning;
        statusIcon = Icons.sync_rounded;
        break;
      case VpnStatus.disconnecting:
        statusText = 'در حال قطع...';
        statusColor = AppColors.warning;
        statusIcon = Icons.sync_rounded;
        break;
      case VpnStatus.error:
        statusText = 'خطا در اتصال';
        statusColor = AppColors.error;
        statusIcon = Icons.error_rounded;
        break;
      default:
        statusText = 'قطع شده';
        statusColor = isDark ? Colors.white54 : Colors.black45;
        statusIcon = Icons.circle_outlined;
    }

    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Icon(statusIcon, color: statusColor, size: 20),
        const SizedBox(width: 8),
        Text(
          statusText,
          style: TextStyle(
            color: statusColor,
            fontSize: 14,
            fontWeight: FontWeight.w500,
          ),
        ),
      ],
    );
  }
}
