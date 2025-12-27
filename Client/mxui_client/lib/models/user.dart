class User {
  final String id;
  final String username;
  final String? email;
  final String? avatar;
  final DateTime createdAt;
  final DateTime? expiresAt;
  final int trafficLimit;
  final int trafficUsed;
  final bool isActive;
  final String? subscriptionUrl;
  final Map<String, dynamic>? metadata;

  const User({
    required this.id,
    required this.username,
    this.email,
    this.avatar,
    required this.createdAt,
    this.expiresAt,
    this.trafficLimit = 0,
    this.trafficUsed = 0,
    this.isActive = true,
    this.subscriptionUrl,
    this.metadata,
  });

  factory User.fromJson(Map<String, dynamic> json) {
    return User(
      id: json['id']?.toString() ?? '',
      username: json['username'] ?? json['name'] ?? '',
      email: json['email'],
      avatar: json['avatar'],
      createdAt: json['createdAt'] != null
          ? DateTime.parse(json['createdAt'])
          : DateTime.now(),
      expiresAt: json['expiresAt'] != null
          ? DateTime.parse(json['expiresAt'])
          : null,
      trafficLimit: json['trafficLimit'] ?? json['data_limit'] ?? 0,
      trafficUsed: json['trafficUsed'] ?? json['used_traffic'] ?? 0,
      isActive: json['isActive'] ?? json['status'] == 'active',
      subscriptionUrl: json['subscriptionUrl'] ?? json['subscription_url'],
      metadata: json['metadata'],
    );
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'username': username,
    'email': email,
    'avatar': avatar,
    'createdAt': createdAt.toIso8601String(),
    'expiresAt': expiresAt?.toIso8601String(),
    'trafficLimit': trafficLimit,
    'trafficUsed': trafficUsed,
    'isActive': isActive,
    'subscriptionUrl': subscriptionUrl,
    'metadata': metadata,
  };

  double get trafficUsagePercentage {
    if (trafficLimit == 0) return 0;
    return (trafficUsed / trafficLimit * 100).clamp(0, 100);
  }

  int get trafficRemaining => (trafficLimit - trafficUsed).clamp(0, trafficLimit);

  bool get isExpired {
    if (expiresAt == null) return false;
    return DateTime.now().isAfter(expiresAt!);
  }

  Duration? get timeRemaining {
    if (expiresAt == null) return null;
    final diff = expiresAt!.difference(DateTime.now());
    return diff.isNegative ? Duration.zero : diff;
  }

  String get displayTrafficUsed => _formatBytes(trafficUsed);
  String get displayTrafficLimit => _formatBytes(trafficLimit);
  String get displayTrafficRemaining => _formatBytes(trafficRemaining);

  static String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }

  User copyWith({
    String? id,
    String? username,
    String? email,
    String? avatar,
    DateTime? createdAt,
    DateTime? expiresAt,
    int? trafficLimit,
    int? trafficUsed,
    bool? isActive,
    String? subscriptionUrl,
    Map<String, dynamic>? metadata,
  }) {
    return User(
      id: id ?? this.id,
      username: username ?? this.username,
      email: email ?? this.email,
      avatar: avatar ?? this.avatar,
      createdAt: createdAt ?? this.createdAt,
      expiresAt: expiresAt ?? this.expiresAt,
      trafficLimit: trafficLimit ?? this.trafficLimit,
      trafficUsed: trafficUsed ?? this.trafficUsed,
      isActive: isActive ?? this.isActive,
      subscriptionUrl: subscriptionUrl ?? this.subscriptionUrl,
      metadata: metadata ?? this.metadata,
    );
  }
}
