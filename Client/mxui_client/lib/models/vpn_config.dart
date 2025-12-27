class VpnConfig {
  final String id;
  final String name;
  final String protocol;
  final String server;
  final int port;
  final Map<String, dynamic> settings;
  final bool isConnected;
  final DateTime? lastConnected;
  final int? ping; // ms

  VpnConfig({
    required this.id,
    required this.name,
    required this.protocol,
    required this.server,
    required this.port,
    required this.settings,
    this.isConnected = false,
    this.lastConnected,
    this.ping,
  });

  String get displayServer {
    return '$server:$port';
  }

  String get statusText {
    if (isConnected) return 'Connected';
    if (lastConnected != null) return 'Last: ${_formatDate(lastConnected!)}';
    return 'Never connected';
  }

  String _formatDate(DateTime date) {
    final now = DateTime.now();
    final diff = now.difference(date);
    
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    if (diff.inDays < 7) return '${diff.inDays}d ago';
    return '${date.day}/${date.month}/${date.year}';
  }

  factory VpnConfig.fromJson(Map<String, dynamic> json) {
    return VpnConfig(
      id: json['id'] ?? '',
      name: json['name'] ?? 'Unknown',
      protocol: json['protocol'] ?? 'VMess',
      server: json['server'] ?? '',
      port: json['port'] ?? 0,
      settings: Map<String, dynamic>.from(json['settings'] ?? {}),
      isConnected: json['is_connected'] ?? false,
      lastConnected: json['last_connected'] != null 
          ? DateTime.parse(json['last_connected']) 
          : null,
      ping: json['ping'],
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'name': name,
      'protocol': protocol,
      'server': server,
      'port': port,
      'settings': settings,
      'is_connected': isConnected,
      'last_connected': lastConnected?.toIso8601String(),
      'ping': ping,
    };
  }

  VpnConfig copyWith({
    String? id,
    String? name,
    String? protocol,
    String? server,
    int? port,
    Map<String, dynamic>? settings,
    bool? isConnected,
    DateTime? lastConnected,
    int? ping,
  }) {
    return VpnConfig(
      id: id ?? this.id,
      name: name ?? this.name,
      protocol: protocol ?? this.protocol,
      server: server ?? this.server,
      port: port ?? this.port,
      settings: settings ?? this.settings,
      isConnected: isConnected ?? this.isConnected,
      lastConnected: lastConnected ?? this.lastConnected,
      ping: ping ?? this.ping,
    );
  }
}
