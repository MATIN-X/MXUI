class AppConfig {
  static const String appName = 'MXUI';
  static const String appVersion = '1.0.0';
  static const String apiBaseUrl = 'https://api.mxui.io'; // Default, user can change
  
  // Proxy protocols
  static const List<String> supportedProtocols = [
    'VMess',
    'VLESS',
    'Trojan',
    'Shadowsocks',
    'Hysteria2',
    'TUIC',
    'WireGuard',
  ];
  
  // App settings
  static const int connectionTimeout = 30000; // ms
  static const int maxRetries = 3;
  static const bool enableLogs = true;
}
