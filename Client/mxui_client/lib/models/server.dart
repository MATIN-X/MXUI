class Server {
  final String id;
  final String name;
  final String address;
  final int port;
  final String protocol;
  final String location;
  final String? countryCode;
  final int? ping;
  final bool isOnline;
  final double? load;
  final Map<String, dynamic>? settings;

  const Server({
    required this.id,
    required this.name,
    required this.address,
    required this.port,
    required this.protocol,
    required this.location,
    this.countryCode,
    this.ping,
    this.isOnline = true,
    this.load,
    this.settings,
  });

  Server copyWith({
    String? id,
    String? name,
    String? address,
    int? port,
    String? protocol,
    String? location,
    String? countryCode,
    int? ping,
    bool? isOnline,
    double? load,
    Map<String, dynamic>? settings,
  }) {
    return Server(
      id: id ?? this.id,
      name: name ?? this.name,
      address: address ?? this.address,
      port: port ?? this.port,
      protocol: protocol ?? this.protocol,
      location: location ?? this.location,
      countryCode: countryCode ?? this.countryCode,
      ping: ping ?? this.ping,
      isOnline: isOnline ?? this.isOnline,
      load: load ?? this.load,
      settings: settings ?? this.settings,
    );
  }

  factory Server.fromJson(Map<String, dynamic> json) {
    return Server(
      id: json['id'] ?? '',
      name: json['name'] ?? '',
      address: json['address'] ?? json['host'] ?? '',
      port: json['port'] ?? 443,
      protocol: json['protocol'] ?? 'vmess',
      location: json['location'] ?? json['country'] ?? 'Unknown',
      countryCode: json['countryCode'] ?? json['country_code'],
      ping: json['ping'],
      isOnline: json['isOnline'] ?? json['online'] ?? true,
      load: json['load']?.toDouble(),
      settings: json['settings'],
    );
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'name': name,
    'address': address,
    'port': port,
    'protocol': protocol,
    'location': location,
    'countryCode': countryCode,
    'ping': ping,
    'isOnline': isOnline,
    'load': load,
    'settings': settings,
  };

  String get displayPing => ping != null ? '${ping}ms' : '—';
  
  String get countryEmoji {
    final code = countryCode?.toUpperCase();
    if (code == null || code.length != 2) return '🌍';
    
    final flagOffset = 0x1F1E6;
    final asciiOffset = 0x41;
    
    final firstChar = code.codeUnitAt(0) - asciiOffset + flagOffset;
    final secondChar = code.codeUnitAt(1) - asciiOffset + flagOffset;
    
    return String.fromCharCodes([firstChar, secondChar]);
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Server && runtimeType == other.runtimeType && id == other.id;

  @override
  int get hashCode => id.hashCode;
}
