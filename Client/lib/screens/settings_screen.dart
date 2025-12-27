// MX-UI VPN Client
// screens/settings_screen.dart - Settings Screen (Hiddify/V2rayNG Style)

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../core/theme.dart';
import '../core/constants.dart';
import '../providers/app_provider.dart';
import '../providers/settings_provider.dart';
import '../providers/vpn_provider.dart';
import '../widgets/glass_card.dart';
import '../widgets/connection_mode_selector.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final isDark = context.watch<AppProvider>().isDarkMode;
    final settings = context.watch<SettingsProvider>();
    final vpn = context.watch<VpnProvider>();

    return SafeArea(
      child: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(20, 20, 20, 100),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header
            Text(
              'تنظیمات',
              style: TextStyle(
                color: isDark ? Colors.white : Colors.black87,
                fontSize: 28,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 24),

            // Connection Mode Section
            _SectionHeader(title: 'حالت اتصال', isDark: isDark),
            ConnectionModeGrid(
              selectedMode: vpn.connectionMode,
              onModeSelected: vpn.setConnectionMode,
              isDark: isDark,
            ),

            const SizedBox(height: 24),

            // Network Settings
            _SectionHeader(title: 'تنظیمات شبکه', isDark: isDark),

            _SettingToggle(
              title: 'IPv6',
              subtitle: 'فعال‌سازی پشتیبانی IPv6',
              icon: Icons.language_rounded,
              value: settings.ipv6Enabled,
              onChanged: settings.toggleIPv6,
              isDark: isDark,
            ),

            _SettingToggle(
              title: 'UDP',
              subtitle: 'فعال‌سازی ترافیک UDP',
              icon: Icons.swap_vert_rounded,
              value: settings.udpEnabled,
              onChanged: settings.toggleUDP,
              isDark: isDark,
            ),

            _SettingToggle(
              title: 'TLS Verification',
              subtitle: 'اعتبارسنجی گواهی TLS',
              icon: Icons.verified_user_rounded,
              value: settings.tlsVerification,
              onChanged: settings.toggleTLSVerification,
              isDark: isDark,
            ),

            const SizedBox(height: 24),

            // DNS Settings
            _SectionHeader(title: 'تنظیمات DNS', isDark: isDark),

            _SettingOption(
              title: 'DNS',
              subtitle: settings.dnsMode,
              icon: Icons.dns_rounded,
              isDark: isDark,
              onTap: () => _showDNSPicker(context, settings),
            ),

            _SettingToggle(
              title: 'مسدودسازی تبلیغات',
              subtitle: 'استفاده از DNS مسدودکننده تبلیغات',
              icon: Icons.block_rounded,
              value: settings.adBlockEnabled,
              onChanged: settings.toggleAdBlock,
              isDark: isDark,
            ),

            const SizedBox(height: 24),

            // Routing Settings
            _SectionHeader(title: 'تنظیمات مسیریابی', isDark: isDark),

            _SettingOption(
              title: 'حالت مسیریابی',
              subtitle: settings.routingMode,
              icon: Icons.route_rounded,
              isDark: isDark,
              onTap: () => _showRoutingPicker(context, settings),
            ),

            _SettingToggle(
              title: 'Bypass LAN',
              subtitle: 'مستثنی کردن شبکه محلی',
              icon: Icons.lan_rounded,
              value: settings.bypassLan,
              onChanged: settings.toggleBypassLan,
              isDark: isDark,
            ),

            _SettingToggle(
              title: 'Bypass Iran',
              subtitle: 'مستثنی کردن سایت‌های ایرانی',
              icon: Icons.flag_rounded,
              value: settings.bypassIran,
              onChanged: settings.toggleBypassIran,
              isDark: isDark,
            ),

            const SizedBox(height: 24),

            // WARP Settings
            _SectionHeader(title: 'تنظیمات WARP', isDark: isDark),

            _SettingToggle(
              title: 'WARP+',
              subtitle: 'استفاده از لایسنس WARP+',
              icon: Icons.shield_rounded,
              iconColor: AppColors.warpOrange,
              value: settings.warpPlusEnabled,
              onChanged: settings.toggleWarpPlus,
              isDark: isDark,
            ),

            if (settings.warpPlusEnabled)
              _SettingInput(
                title: 'لایسنس WARP+',
                value: settings.warpLicense ?? '',
                hint: 'وارد کردن لایسنس',
                icon: Icons.key_rounded,
                isDark: isDark,
                onSaved: settings.setWarpLicense,
              ),

            const SizedBox(height: 24),

            // Fragment Settings
            _SectionHeader(title: 'تنظیمات Fragment', isDark: isDark),

            _SettingToggle(
              title: 'Fragment',
              subtitle: 'تقسیم پکت‌های TLS برای عبور از فیلترینگ',
              icon: Icons.splitscreen_rounded,
              value: settings.fragmentEnabled,
              onChanged: settings.toggleFragment,
              isDark: isDark,
            ),

            if (settings.fragmentEnabled) ...[
              _SettingSlider(
                title: 'اندازه Fragment',
                value: settings.fragmentSize.toDouble(),
                min: 10,
                max: 500,
                unit: 'bytes',
                isDark: isDark,
                onChanged: (v) => settings.setFragmentSize(v.toInt()),
              ),
              _SettingSlider(
                title: 'تاخیر Fragment',
                value: settings.fragmentDelay.toDouble(),
                min: 0,
                max: 100,
                unit: 'ms',
                isDark: isDark,
                onChanged: (v) => settings.setFragmentDelay(v.toInt()),
              ),
            ],

            const SizedBox(height: 24),

            // AI Smart Settings
            _SectionHeader(title: 'هوش مصنوعی', isDark: isDark),

            _SettingToggle(
              title: 'پیکربندی هوشمند AI',
              subtitle: 'تنظیم خودکار بر اساس شرایط شبکه',
              icon: Icons.auto_awesome_rounded,
              iconColor: AppColors.aiPurple,
              value: settings.aiSmartConfig,
              onChanged: settings.toggleAISmartConfig,
              isDark: isDark,
            ),

            _SettingOption(
              title: 'ChatGPT API',
              subtitle: settings.chatGptApiKey != null ? 'پیکربندی شده' : 'پیکربندی نشده',
              icon: Icons.smart_toy_rounded,
              iconColor: AppColors.aiPurple,
              isDark: isDark,
              onTap: () => _showChatGPTApiDialog(context, settings),
            ),

            const SizedBox(height: 24),

            // Advanced Settings
            _SectionHeader(title: 'تنظیمات پیشرفته', isDark: isDark),

            _SettingOption(
              title: 'Mux',
              subtitle: settings.muxEnabled ? 'فعال (${settings.muxConcurrency} اتصال)' : 'غیرفعال',
              icon: Icons.merge_rounded,
              isDark: isDark,
              onTap: () => _showMuxSettings(context, settings),
            ),

            _SettingOption(
              title: 'پورت محلی',
              subtitle: 'SOCKS: ${settings.socksPort} | HTTP: ${settings.httpPort}',
              icon: Icons.settings_ethernet_rounded,
              isDark: isDark,
              onTap: () => _showPortSettings(context, settings),
            ),

            _SettingToggle(
              title: 'حالت اشکال‌زدایی',
              subtitle: 'نمایش لاگ‌های دقیق',
              icon: Icons.bug_report_rounded,
              value: settings.debugMode,
              onChanged: settings.toggleDebugMode,
              isDark: isDark,
            ),

            const SizedBox(height: 24),

            // App Info
            _SectionHeader(title: 'درباره', isDark: isDark),

            _SettingOption(
              title: 'نسخه',
              subtitle: '1.0.0',
              icon: Icons.info_outline_rounded,
              isDark: isDark,
              showArrow: false,
            ),

            _SettingOption(
              title: 'هسته sing-box',
              subtitle: '1.8.0',
              icon: Icons.memory_rounded,
              isDark: isDark,
              showArrow: false,
            ),

            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }

  void _showDNSPicker(BuildContext context, SettingsProvider settings) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final options = ['سیستم', 'Cloudflare', 'Google', 'AdGuard', 'سفارشی'];

    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      builder: (context) => _PickerSheet(
        title: 'انتخاب DNS',
        options: options,
        selectedOption: settings.dnsMode,
        onSelected: settings.setDNSMode,
        isDark: isDark,
      ),
    );
  }

  void _showRoutingPicker(BuildContext context, SettingsProvider settings) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final options = ['Global', 'Bypass Iran', 'Bypass LAN', 'GeoIP'];

    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      builder: (context) => _PickerSheet(
        title: 'حالت مسیریابی',
        options: options,
        selectedOption: settings.routingMode,
        onSelected: settings.setRoutingMode,
        isDark: isDark,
      ),
    );
  }

  void _showChatGPTApiDialog(BuildContext context, SettingsProvider settings) {
    final controller = TextEditingController(text: settings.chatGptApiKey ?? '');
    final isDark = Theme.of(context).brightness == Brightness.dark;

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: isDark ? AppColors.darkCard : AppColors.lightCard,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(AppConstants.radiusLarge),
        ),
        title: Text(
          'ChatGPT API Key',
          style: TextStyle(color: isDark ? Colors.white : Colors.black87),
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              'برای پیکربندی هوشمند خودکار، کلید API ChatGPT خود را وارد کنید.',
              style: TextStyle(
                color: isDark ? Colors.white70 : Colors.black54,
                fontSize: 13,
              ),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: controller,
              decoration: InputDecoration(
                hintText: 'sk-...',
                hintStyle: TextStyle(
                  color: isDark ? Colors.white38 : Colors.black38,
                ),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
                ),
              ),
              style: TextStyle(color: isDark ? Colors.white : Colors.black87),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('انصراف'),
          ),
          ElevatedButton(
            onPressed: () {
              settings.setChatGptApiKey(
                controller.text.isNotEmpty ? controller.text : null,
              );
              Navigator.pop(context);
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.primary,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
              ),
            ),
            child: const Text('ذخیره'),
          ),
        ],
      ),
    );
  }

  void _showMuxSettings(BuildContext context, SettingsProvider settings) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      builder: (context) => StatefulBuilder(
        builder: (context, setState) => Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: isDark ? AppColors.darkCard : AppColors.lightCard,
            borderRadius: const BorderRadius.vertical(
              top: Radius.circular(AppConstants.radiusXLarge),
            ),
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Center(
                child: Container(
                  width: 40,
                  height: 4,
                  decoration: BoxDecoration(
                    color: isDark ? Colors.white24 : Colors.black12,
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
              ),
              const SizedBox(height: 20),
              Text(
                'تنظیمات Mux',
                style: TextStyle(
                  color: isDark ? Colors.white : Colors.black87,
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 20),
              SwitchListTile(
                title: Text(
                  'فعال‌سازی Mux',
                  style: TextStyle(color: isDark ? Colors.white : Colors.black87),
                ),
                value: settings.muxEnabled,
                onChanged: (v) {
                  settings.toggleMux(v);
                  setState(() {});
                },
                activeColor: AppColors.primary,
              ),
              if (settings.muxEnabled) ...[
                const SizedBox(height: 16),
                Text(
                  'تعداد اتصال همزمان: ${settings.muxConcurrency}',
                  style: TextStyle(
                    color: isDark ? Colors.white70 : Colors.black54,
                  ),
                ),
                Slider(
                  value: settings.muxConcurrency.toDouble(),
                  min: 1,
                  max: 16,
                  divisions: 15,
                  onChanged: (v) {
                    settings.setMuxConcurrency(v.toInt());
                    setState(() {});
                  },
                  activeColor: AppColors.primary,
                ),
              ],
              const SizedBox(height: 20),
            ],
          ),
        ),
      ),
    );
  }

  void _showPortSettings(BuildContext context, SettingsProvider settings) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final socksController = TextEditingController(text: settings.socksPort.toString());
    final httpController = TextEditingController(text: settings.httpPort.toString());

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: isDark ? AppColors.darkCard : AppColors.lightCard,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(AppConstants.radiusLarge),
        ),
        title: Text(
          'تنظیمات پورت',
          style: TextStyle(color: isDark ? Colors.white : Colors.black87),
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: socksController,
              keyboardType: TextInputType.number,
              decoration: InputDecoration(
                labelText: 'پورت SOCKS',
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
                ),
              ),
              style: TextStyle(color: isDark ? Colors.white : Colors.black87),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: httpController,
              keyboardType: TextInputType.number,
              decoration: InputDecoration(
                labelText: 'پورت HTTP',
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
                ),
              ),
              style: TextStyle(color: isDark ? Colors.white : Colors.black87),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('انصراف'),
          ),
          ElevatedButton(
            onPressed: () {
              final socks = int.tryParse(socksController.text) ?? 10808;
              final http = int.tryParse(httpController.text) ?? 10809;
              settings.setPorts(socks, http);
              Navigator.pop(context);
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.primary,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
              ),
            ),
            child: const Text('ذخیره'),
          ),
        ],
      ),
    );
  }
}

class _SectionHeader extends StatelessWidget {
  final String title;
  final bool isDark;

  const _SectionHeader({required this.title, required this.isDark});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Text(
        title,
        style: TextStyle(
          color: AppColors.primary,
          fontSize: 14,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }
}

class _SettingToggle extends StatelessWidget {
  final String title;
  final String subtitle;
  final IconData icon;
  final Color? iconColor;
  final bool value;
  final Function(bool) onChanged;
  final bool isDark;

  const _SettingToggle({
    required this.title,
    required this.subtitle,
    required this.icon,
    this.iconColor,
    required this.value,
    required this.onChanged,
    required this.isDark,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: isDark
            ? Colors.white.withOpacity(0.08)
            : Colors.black.withOpacity(0.05),
        borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
      ),
      child: Row(
        children: [
          Container(
            width: 36,
            height: 36,
            decoration: BoxDecoration(
              color: (iconColor ?? AppColors.primary).withOpacity(0.2),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(
              icon,
              color: iconColor ?? AppColors.primary,
              size: 20,
            ),
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
                    fontSize: 11,
                  ),
                ),
              ],
            ),
          ),
          Switch(
            value: value,
            onChanged: onChanged,
            activeColor: iconColor ?? AppColors.primary,
          ),
        ],
      ),
    );
  }
}

class _SettingOption extends StatelessWidget {
  final String title;
  final String subtitle;
  final IconData icon;
  final Color? iconColor;
  final bool isDark;
  final VoidCallback? onTap;
  final bool showArrow;

  const _SettingOption({
    required this.title,
    required this.subtitle,
    required this.icon,
    this.iconColor,
    required this.isDark,
    this.onTap,
    this.showArrow = true,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      child: Material(
        color: isDark
            ? Colors.white.withOpacity(0.08)
            : Colors.black.withOpacity(0.05),
        borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
            child: Row(
              children: [
                Container(
                  width: 36,
                  height: 36,
                  decoration: BoxDecoration(
                    color: (iconColor ?? AppColors.primary).withOpacity(0.2),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Icon(
                    icon,
                    color: iconColor ?? AppColors.primary,
                    size: 20,
                  ),
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
                          fontSize: 11,
                        ),
                      ),
                    ],
                  ),
                ),
                if (showArrow)
                  Icon(
                    Icons.chevron_left_rounded,
                    color: isDark ? Colors.white38 : Colors.black26,
                  ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _SettingSlider extends StatelessWidget {
  final String title;
  final double value;
  final double min;
  final double max;
  final String unit;
  final bool isDark;
  final Function(double) onChanged;

  const _SettingSlider({
    required this.title,
    required this.value,
    required this.min,
    required this.max,
    required this.unit,
    required this.isDark,
    required this.onChanged,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: isDark
            ? Colors.white.withOpacity(0.08)
            : Colors.black.withOpacity(0.05),
        borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                title,
                style: TextStyle(
                  color: isDark ? Colors.white : Colors.black87,
                  fontSize: 14,
                ),
              ),
              Text(
                '${value.toInt()} $unit',
                style: TextStyle(
                  color: AppColors.primary,
                  fontSize: 14,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
          Slider(
            value: value,
            min: min,
            max: max,
            onChanged: onChanged,
            activeColor: AppColors.primary,
            inactiveColor: isDark
                ? Colors.white.withOpacity(0.2)
                : Colors.black.withOpacity(0.1),
          ),
        ],
      ),
    );
  }
}

class _SettingInput extends StatelessWidget {
  final String title;
  final String value;
  final String hint;
  final IconData icon;
  final bool isDark;
  final Function(String) onSaved;

  const _SettingInput({
    required this.title,
    required this.value,
    required this.hint,
    required this.icon,
    required this.isDark,
    required this.onSaved,
  });

  @override
  Widget build(BuildContext context) {
    final controller = TextEditingController(text: value);

    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: isDark
            ? Colors.white.withOpacity(0.08)
            : Colors.black.withOpacity(0.05),
        borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
      ),
      child: Row(
        children: [
          Expanded(
            child: TextField(
              controller: controller,
              decoration: InputDecoration(
                hintText: hint,
                hintStyle: TextStyle(
                  color: isDark ? Colors.white38 : Colors.black38,
                ),
                border: InputBorder.none,
                prefixIcon: Icon(
                  icon,
                  color: isDark ? Colors.white54 : Colors.black45,
                  size: 20,
                ),
              ),
              style: TextStyle(
                color: isDark ? Colors.white : Colors.black87,
                fontSize: 14,
              ),
              onSubmitted: onSaved,
            ),
          ),
          IconButton(
            onPressed: () => onSaved(controller.text),
            icon: Icon(
              Icons.check_rounded,
              color: AppColors.primary,
            ),
          ),
        ],
      ),
    );
  }
}

class _PickerSheet extends StatelessWidget {
  final String title;
  final List<String> options;
  final String selectedOption;
  final Function(String) onSelected;
  final bool isDark;

  const _PickerSheet({
    required this.title,
    required this.options,
    required this.selectedOption,
    required this.onSelected,
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
            child: Text(
              title,
              style: TextStyle(
                color: isDark ? Colors.white : Colors.black87,
                fontSize: 18,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
          ...options.map((option) => ListTile(
                onTap: () {
                  onSelected(option);
                  Navigator.pop(context);
                },
                title: Text(
                  option,
                  style: TextStyle(
                    color: isDark ? Colors.white : Colors.black87,
                    fontWeight: option == selectedOption
                        ? FontWeight.w600
                        : FontWeight.normal,
                  ),
                ),
                trailing: option == selectedOption
                    ? Icon(Icons.check_rounded, color: AppColors.primary)
                    : null,
              )),
          const SizedBox(height: 20),
        ],
      ),
    );
  }
}
