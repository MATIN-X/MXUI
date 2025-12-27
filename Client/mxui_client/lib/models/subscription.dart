class Subscription {
  final String id;
  final String name;
  final String url;
  final String protocol;
  final int totalTraffic; // bytes
  final int usedTraffic; // bytes
  final DateTime? expiryDate;
  final bool isActive;
  final DateTime createdAt;
  final DateTime updatedAt;

  Subscription({
    required this.id,
    required this.name,
    required this.url,
    required this.protocol,
    required this.totalTraffic,
    required this.usedTraffic,
    this.expiryDate,
    required this.isActive,
    required this.createdAt,
    required this.updatedAt,
  });

  double get trafficUsagePercent {
    if (totalTraffic == 0) return 0;
    return (usedTraffic / totalTraffic) * 100;
  }

  int get remainingTraffic => totalTraffic - usedTraffic;

  bool get isExpired {
    if (expiryDate == null) return false;
    return DateTime.now().isAfter(expiryDate!);
  }

  int? get daysRemaining {
    if (expiryDate == null) return null;
    return expiryDate!.difference(DateTime.now()).inDays;
  }

  factory Subscription.fromJson(Map<String, dynamic> json) {
    return Subscription(
      id: json['id'] ?? '',
      name: json['name'] ?? 'Unknown',
      url: json['url'] ?? '',
      protocol: json['protocol'] ?? 'VMess',
      totalTraffic: json['total_traffic'] ?? 0,
      usedTraffic: json['used_traffic'] ?? 0,
      expiryDate: json['expiry_date'] != null 
          ? DateTime.parse(json['expiry_date']) 
          : null,
      isActive: json['is_active'] ?? false,
      createdAt: DateTime.parse(json['created_at'] ?? DateTime.now().toIso8601String()),
      updatedAt: DateTime.parse(json['updated_at'] ?? DateTime.now().toIso8601String()),
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'name': name,
      'url': url,
      'protocol': protocol,
      'total_traffic': totalTraffic,
      'used_traffic': usedTraffic,
      'expiry_date': expiryDate?.toIso8601String(),
      'is_active': isActive,
      'created_at': createdAt.toIso8601String(),
      'updated_at': updatedAt.toIso8601String(),
    };
  }

  Subscription copyWith({
    String? id,
    String? name,
    String? url,
    String? protocol,
    int? totalTraffic,
    int? usedTraffic,
    DateTime? expiryDate,
    bool? isActive,
    DateTime? createdAt,
    DateTime? updatedAt,
  }) {
    return Subscription(
      id: id ?? this.id,
      name: name ?? this.name,
      url: url ?? this.url,
      protocol: protocol ?? this.protocol,
      totalTraffic: totalTraffic ?? this.totalTraffic,
      usedTraffic: usedTraffic ?? this.usedTraffic,
      expiryDate: expiryDate ?? this.expiryDate,
      isActive: isActive ?? this.isActive,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
    );
  }
}
