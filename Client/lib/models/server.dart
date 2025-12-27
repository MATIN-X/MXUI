class Server {
  final String id;
  final String name;
  final String address;
  final int port;
  final String protocol;
  final String country;
  final String flag;
  final int latency;
  final bool isOnline;

  Server({
    required this.id,
    required this.name,
    required this.address,
    required this.port,
    this.protocol = 'vmess',
    this.country = '',
    this.flag = '',
    this.latency = 0,
    this.isOnline = true,
  });

  factory Server.fromJson(Map<String, dynamic> json) {
    return Server(
      id: json['id'] ?? '',
      name: json['name'] ?? '',
      address: json['address'] ?? '',
      port: json['port'] ?? 443,
      protocol: json['protocol'] ?? 'vmess',
      country: json['country'] ?? '',
      flag: json['flag'] ?? '',
      latency: json['latency'] ?? 0,
      isOnline: json['is_online'] ?? true,
    );
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'name': name,
    'address': address,
    'port': port,
    'protocol': protocol,
    'country': country,
    'flag': flag,
    'latency': latency,
    'is_online': isOnline,
  };
}
