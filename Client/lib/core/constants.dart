// MXUI VPN Client
// core/constants.dart - Application Constants

class AppConstants {
  static const String appName = 'MXUI VPN';
  static const String appVersion = '1.0.0';

  // API
  static const Duration connectionTimeout = Duration(seconds: 30);
  static const Duration receiveTimeout = Duration(seconds: 30);

  // Storage Keys
  static const String keyThemeMode = 'theme_mode';
  static const String keyLocale = 'locale';
  static const String keyActiveAccount = 'active_account';
  static const String keyAccounts = 'accounts';
  static const String keyWarpEnabled = 'warp_enabled';
  static const String keyWarpConfig = 'warp_config';
  static const String keyConnectionMode = 'connection_mode';
  static const String keyRoutingRules = 'routing_rules';
  static const String keyDnsConfig = 'dns_config';
  static const String keyFragmentEnabled = 'fragment_enabled';
  static const String keyFragmentConfig = 'fragment_config';
  static const String keyTlsConfig = 'tls_config';
  static const String keyBlockAds = 'block_ads';
  static const String keyIpv6Enabled = 'ipv6_enabled';
  static const String keyDirectApps = 'direct_apps';
  static const String keyProxyApps = 'proxy_apps';

  // Connection Modes
  static const String modeAuto = 'auto';
  static const String modeGame = 'game';
  static const String modeAI = 'ai';
  static const String modeDownload = 'download';
  static const String modeSocial = 'social';
  static const String modeTrade = 'trade';

  // Animation Durations
  static const Duration animFast = Duration(milliseconds: 200);
  static const Duration animNormal = Duration(milliseconds: 300);
  static const Duration animSlow = Duration(milliseconds: 500);

  // Border Radius
  static const double radiusSmall = 8.0;
  static const double radiusMedium = 12.0;
  static const double radiusLarge = 16.0;
  static const double radiusXLarge = 24.0;
  static const double radiusRound = 100.0;

  // Padding
  static const double paddingSmall = 8.0;
  static const double paddingMedium = 16.0;
  static const double paddingLarge = 24.0;
  static const double paddingXLarge = 32.0;
}

class VpnStatus {
  static const String disconnected = 'disconnected';
  static const String connecting = 'connecting';
  static const String connected = 'connected';
  static const String disconnecting = 'disconnecting';
  static const String error = 'error';
}

class ConnectionMode {
  final String id;
  final String name;
  final String nameFa;
  final String icon;
  final String description;
  final Map<String, dynamic> config;

  const ConnectionMode({
    required this.id,
    required this.name,
    required this.nameFa,
    required this.icon,
    required this.description,
    required this.config,
  });

  static const List<ConnectionMode> modes = [
    ConnectionMode(
      id: 'auto',
      name: 'Auto',
      nameFa: 'خودکار',
      icon: '🔄',
      description: 'Automatically select best config',
      config: {'strategy': 'latency', 'fallback': true},
    ),
    ConnectionMode(
      id: 'game',
      name: 'Game Mode',
      nameFa: 'گیم مود',
      icon: '🎮',
      description: 'Low latency for gaming',
      config: {'strategy': 'latency', 'mtu': 1400, 'udp': true},
    ),
    ConnectionMode(
      id: 'ai',
      name: 'AI Mode',
      nameFa: 'هوش مصنوعی',
      icon: '🤖',
      description: 'Optimized for ChatGPT, Gemini',
      config: {'strategy': 'speed', 'domains': ['openai.com', 'google.com']},
    ),
    ConnectionMode(
      id: 'download',
      name: 'Download',
      nameFa: 'دانلود',
      icon: '⬇️',
      description: 'Maximum speed for downloads',
      config: {'strategy': 'speed', 'mtu': 1500, 'buffer': 'large'},
    ),
    ConnectionMode(
      id: 'social',
      name: 'Social Media',
      nameFa: 'شبکه اجتماعی',
      icon: '📱',
      description: 'Instagram, Telegram, Twitter',
      config: {'strategy': 'balanced', 'domains': ['instagram.com', 'telegram.org', 'twitter.com']},
    ),
    ConnectionMode(
      id: 'trade',
      name: 'Trading',
      nameFa: 'ترید',
      icon: '📈',
      description: 'Stable connection for trading',
      config: {'strategy': 'stability', 'keepalive': 10, 'reconnect': true},
    ),
  ];
}
