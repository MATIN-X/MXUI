// MX-UI VPN Client
// models/account.dart - Account Model

class Account {
  final String id;
  final String subscriptionUrl;
  final String? name;
  final String? username;
  final String? email;
  final String status;
  final int dataLimit;
  final int dataUsed;
  final int uploadUsed;
  final int downloadUsed;
  final DateTime? expiryTime;
  final int deviceLimit;
  final int onlineDevices;
  final int maxDevices;
  final List<ServerConfig> servers;
  final DateTime createdAt;
  final DateTime? lastSync;

  Account({
    required this.id,
    required this.subscriptionUrl,
    this.name,
    this.username,
    this.email,
    this.status = 'active',
    this.dataLimit = 0,
    this.dataUsed = 0,
    this.uploadUsed = 0,
    this.downloadUsed = 0,
    this.expiryTime,
    this.deviceLimit = 0,
    this.onlineDevices = 0,
    this.maxDevices = 0,
    this.servers = const [],
    required this.createdAt,
    this.lastSync,
  });

  // Computed properties
  double get usagePercent => dataLimit > 0 ? (dataUsed / dataLimit) * 100 : 0;
  int get remainingData => dataLimit - dataUsed;
  int get remainingDays {
    if (expiryTime == null) return -1;
    final diff = expiryTime!.difference(DateTime.now());
    return diff.inDays;
  }

  bool get isActive => status == 'active';
  bool get isExpired => status == 'expired' || (expiryTime != null && expiryTime!.isBefore(DateTime.now()));
  bool get isLimited => status == 'limited' || (dataLimit > 0 && dataUsed >= dataLimit);

  factory Account.fromJson(Map<String, dynamic> json) {
    return Account(
      id: json['id']?.toString() ?? '',
      subscriptionUrl: json['subscription_url'] ?? '',
      name: json['name'],
      username: json['username'],
      email: json['email'],
      status: json['status'] ?? 'active',
      dataLimit: json['data_limit'] ?? 0,
      dataUsed: json['data_used'] ?? 0,
      uploadUsed: json['upload_used'] ?? 0,
      downloadUsed: json['download_used'] ?? 0,
      expiryTime: json['expiry_time'] != null ? DateTime.parse(json['expiry_time']) : null,
      deviceLimit: json['device_limit'] ?? 0,
      onlineDevices: json['online_devices'] ?? 0,
      maxDevices: json['max_devices'] ?? json['device_limit'] ?? 0,
      servers: (json['servers'] as List<dynamic>?)
              ?.map((s) => ServerConfig.fromJson(s))
              .toList() ?? [],
      createdAt: json['created_at'] != null ? DateTime.parse(json['created_at']) : DateTime.now(),
      lastSync: json['last_sync'] != null ? DateTime.parse(json['last_sync']) : null,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'subscription_url': subscriptionUrl,
      'name': name,
      'username': username,
      'email': email,
      'status': status,
      'data_limit': dataLimit,
      'data_used': dataUsed,
      'upload_used': uploadUsed,
      'download_used': downloadUsed,
      'expiry_time': expiryTime?.toIso8601String(),
      'device_limit': deviceLimit,
      'online_devices': onlineDevices,
      'max_devices': maxDevices,
      'servers': servers.map((s) => s.toJson()).toList(),
      'created_at': createdAt.toIso8601String(),
      'last_sync': lastSync?.toIso8601String(),
    };
  }

  Account copyWith({
    String? id,
    String? subscriptionUrl,
    String? name,
    String? username,
    String? email,
    String? status,
    int? dataLimit,
    int? dataUsed,
    int? uploadUsed,
    int? downloadUsed,
    DateTime? expiryTime,
    int? deviceLimit,
    int? onlineDevices,
    int? maxDevices,
    List<ServerConfig>? servers,
    DateTime? createdAt,
    DateTime? lastSync,
  }) {
    return Account(
      id: id ?? this.id,
      subscriptionUrl: subscriptionUrl ?? this.subscriptionUrl,
      name: name ?? this.name,
      username: username ?? this.username,
      email: email ?? this.email,
      status: status ?? this.status,
      dataLimit: dataLimit ?? this.dataLimit,
      dataUsed: dataUsed ?? this.dataUsed,
      uploadUsed: uploadUsed ?? this.uploadUsed,
      downloadUsed: downloadUsed ?? this.downloadUsed,
      expiryTime: expiryTime ?? this.expiryTime,
      deviceLimit: deviceLimit ?? this.deviceLimit,
      onlineDevices: onlineDevices ?? this.onlineDevices,
      maxDevices: maxDevices ?? this.maxDevices,
      servers: servers ?? this.servers,
      createdAt: createdAt ?? this.createdAt,
      lastSync: lastSync ?? this.lastSync,
    );
  }
}

class ServerConfig {
  final String id;
  final String name;
  final String address;
  final int port;
  final String protocol;
  final String transport;
  final String security;
  final int latency;
  final bool isAvailable;
  final Map<String, dynamic> settings;

  ServerConfig({
    required this.id,
    required this.name,
    required this.address,
    required this.port,
    this.protocol = 'vless',
    this.transport = 'tcp',
    this.security = 'tls',
    this.latency = 0,
    this.isAvailable = true,
    this.settings = const {},
  });

  factory ServerConfig.fromJson(Map<String, dynamic> json) {
    return ServerConfig(
      id: json['id']?.toString() ?? '',
      name: json['name'] ?? json['remark'] ?? 'Server',
      address: json['address'] ?? json['add'] ?? '',
      port: json['port'] ?? 443,
      protocol: json['protocol'] ?? json['type'] ?? 'vless',
      transport: json['transport'] ?? json['net'] ?? 'tcp',
      security: json['security'] ?? json['tls'] ?? 'tls',
      latency: json['latency'] ?? 0,
      isAvailable: json['is_available'] ?? true,
      settings: json['settings'] ?? {},
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'name': name,
      'address': address,
      'port': port,
      'protocol': protocol,
      'transport': transport,
      'security': security,
      'latency': latency,
      'is_available': isAvailable,
      'settings': settings,
    };
  }

  String get flag {
    // Return emoji flag based on server location/name
    if (name.toLowerCase().contains('germany') || name.toLowerCase().contains('de')) return '🇩🇪';
    if (name.toLowerCase().contains('netherlands') || name.toLowerCase().contains('nl')) return '🇳🇱';
    if (name.toLowerCase().contains('france') || name.toLowerCase().contains('fr')) return '🇫🇷';
    if (name.toLowerCase().contains('uk') || name.toLowerCase().contains('united kingdom')) return '🇬🇧';
    if (name.toLowerCase().contains('us') || name.toLowerCase().contains('united states')) return '🇺🇸';
    if (name.toLowerCase().contains('japan') || name.toLowerCase().contains('jp')) return '🇯🇵';
    if (name.toLowerCase().contains('singapore') || name.toLowerCase().contains('sg')) return '🇸🇬';
    if (name.toLowerCase().contains('turkey') || name.toLowerCase().contains('tr')) return '🇹🇷';
    return '🌐';
  }
}

class TrafficStats {
  final int upload;
  final int download;
  final int uploadSpeed;
  final int downloadSpeed;
  final Duration connectionTime;

  TrafficStats({
    this.upload = 0,
    this.download = 0,
    this.uploadSpeed = 0,
    this.downloadSpeed = 0,
    this.connectionTime = Duration.zero,
  });

  int get total => upload + download;
  int get totalSpeed => uploadSpeed + downloadSpeed;
}
