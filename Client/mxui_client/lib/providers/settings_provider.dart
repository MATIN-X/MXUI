import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:hive_flutter/hive_flutter.dart';

// Settings State
class SettingsState {
  final ThemeMode themeMode;
  final String language;
  final bool autoConnect;
  final bool killSwitch;
  final bool splitTunneling;
  final String dnsMode;
  final String customDns;
  final bool showNotifications;
  final bool startOnBoot;
  final String protocol;
  final bool enableLogs;
  final List<String> excludedApps;

  const SettingsState({
    this.themeMode = ThemeMode.system,
    this.language = 'en',
    this.autoConnect = false,
    this.killSwitch = false,
    this.splitTunneling = false,
    this.dnsMode = 'system',
    this.customDns = '',
    this.showNotifications = true,
    this.startOnBoot = false,
    this.protocol = 'auto',
    this.enableLogs = false,
    this.excludedApps = const [],
  });

  SettingsState copyWith({
    ThemeMode? themeMode,
    String? language,
    bool? autoConnect,
    bool? killSwitch,
    bool? splitTunneling,
    String? dnsMode,
    String? customDns,
    bool? showNotifications,
    bool? startOnBoot,
    String? protocol,
    bool? enableLogs,
    List<String>? excludedApps,
  }) {
    return SettingsState(
      themeMode: themeMode ?? this.themeMode,
      language: language ?? this.language,
      autoConnect: autoConnect ?? this.autoConnect,
      killSwitch: killSwitch ?? this.killSwitch,
      splitTunneling: splitTunneling ?? this.splitTunneling,
      dnsMode: dnsMode ?? this.dnsMode,
      customDns: customDns ?? this.customDns,
      showNotifications: showNotifications ?? this.showNotifications,
      startOnBoot: startOnBoot ?? this.startOnBoot,
      protocol: protocol ?? this.protocol,
      enableLogs: enableLogs ?? this.enableLogs,
      excludedApps: excludedApps ?? this.excludedApps,
    );
  }

  Map<String, dynamic> toJson() => {
    'themeMode': themeMode.index,
    'language': language,
    'autoConnect': autoConnect,
    'killSwitch': killSwitch,
    'splitTunneling': splitTunneling,
    'dnsMode': dnsMode,
    'customDns': customDns,
    'showNotifications': showNotifications,
    'startOnBoot': startOnBoot,
    'protocol': protocol,
    'enableLogs': enableLogs,
    'excludedApps': excludedApps,
  };

  factory SettingsState.fromJson(Map<String, dynamic> json) {
    return SettingsState(
      themeMode: ThemeMode.values[json['themeMode'] ?? 0],
      language: json['language'] ?? 'en',
      autoConnect: json['autoConnect'] ?? false,
      killSwitch: json['killSwitch'] ?? false,
      splitTunneling: json['splitTunneling'] ?? false,
      dnsMode: json['dnsMode'] ?? 'system',
      customDns: json['customDns'] ?? '',
      showNotifications: json['showNotifications'] ?? true,
      startOnBoot: json['startOnBoot'] ?? false,
      protocol: json['protocol'] ?? 'auto',
      enableLogs: json['enableLogs'] ?? false,
      excludedApps: List<String>.from(json['excludedApps'] ?? []),
    );
  }
}

class SettingsNotifier extends StateNotifier<SettingsState> {
  static const _boxName = 'settings';
  Box? _box;

  SettingsNotifier() : super(const SettingsState()) {
    _loadSettings();
  }

  Future<void> _loadSettings() async {
    _box = await Hive.openBox(_boxName);
    final data = _box?.get('settings');
    if (data != null) {
      state = SettingsState.fromJson(Map<String, dynamic>.from(data));
    }
  }

  Future<void> _saveSettings() async {
    await _box?.put('settings', state.toJson());
  }

  void setThemeMode(ThemeMode mode) {
    state = state.copyWith(themeMode: mode);
    _saveSettings();
  }

  void setLanguage(String language) {
    state = state.copyWith(language: language);
    _saveSettings();
  }

  void setAutoConnect(bool value) {
    state = state.copyWith(autoConnect: value);
    _saveSettings();
  }

  void setKillSwitch(bool value) {
    state = state.copyWith(killSwitch: value);
    _saveSettings();
  }

  void setSplitTunneling(bool value) {
    state = state.copyWith(splitTunneling: value);
    _saveSettings();
  }

  void setDnsMode(String mode) {
    state = state.copyWith(dnsMode: mode);
    _saveSettings();
  }

  void setCustomDns(String dns) {
    state = state.copyWith(customDns: dns);
    _saveSettings();
  }

  void setShowNotifications(bool value) {
    state = state.copyWith(showNotifications: value);
    _saveSettings();
  }

  void setStartOnBoot(bool value) {
    state = state.copyWith(startOnBoot: value);
    _saveSettings();
  }

  void setProtocol(String protocol) {
    state = state.copyWith(protocol: protocol);
    _saveSettings();
  }

  void setEnableLogs(bool value) {
    state = state.copyWith(enableLogs: value);
    _saveSettings();
  }

  void addExcludedApp(String packageName) {
    if (!state.excludedApps.contains(packageName)) {
      state = state.copyWith(
        excludedApps: [...state.excludedApps, packageName],
      );
      _saveSettings();
    }
  }

  void removeExcludedApp(String packageName) {
    state = state.copyWith(
      excludedApps: state.excludedApps.where((p) => p != packageName).toList(),
    );
    _saveSettings();
  }

  Future<void> resetSettings() async {
    state = const SettingsState();
    await _saveSettings();
  }
}

// Providers
final settingsProvider = StateNotifierProvider<SettingsNotifier, SettingsState>((ref) {
  return SettingsNotifier();
});

// Convenience providers
final themeModeProvider = Provider<ThemeMode>((ref) {
  return ref.watch(settingsProvider).themeMode;
});

final languageProvider = Provider<String>((ref) {
  return ref.watch(settingsProvider).language;
});

final autoConnectProvider = Provider<bool>((ref) {
  return ref.watch(settingsProvider).autoConnect;
});

final killSwitchProvider = Provider<bool>((ref) {
  return ref.watch(settingsProvider).killSwitch;
});

final protocolProvider = Provider<String>((ref) {
  return ref.watch(settingsProvider).protocol;
});

// Available languages
final supportedLanguages = {
  'en': 'English',
  'fa': 'فارسی',
  'ru': 'Русский',
  'zh': '中文',
  'ar': 'العربية',
  'tr': 'Türkçe',
};

// Available protocols
final supportedProtocols = {
  'auto': 'Auto',
  'vmess': 'VMess',
  'vless': 'VLESS',
  'trojan': 'Trojan',
  'shadowsocks': 'Shadowsocks',
  'hysteria': 'Hysteria',
  'hysteria2': 'Hysteria2',
  'tuic': 'TUIC',
  'wireguard': 'WireGuard',
};

// Available DNS modes
final dnsModesMap = {
  'system': 'System DNS',
  'cloudflare': 'Cloudflare (1.1.1.1)',
  'google': 'Google (8.8.8.8)',
  'quad9': 'Quad9 (9.9.9.9)',
  'doh_cloudflare': 'DoH - Cloudflare',
  'doh_google': 'DoH - Google',
  'custom': 'Custom',
};
