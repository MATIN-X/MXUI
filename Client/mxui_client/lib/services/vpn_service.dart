import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import '../models/server.dart';
import '../models/subscription.dart';
import '../models/vpn_config.dart';

enum VpnStatus { disconnected, connecting, connected, disconnecting }

/// Traffic statistics returned from VPN connection
class TrafficStats {
  final int downloadBytes;
  final int uploadBytes;
  final double currentSpeed;

  const TrafficStats({
    this.downloadBytes = 0,
    this.uploadBytes = 0,
    this.currentSpeed = 0,
  });
}

class VpnService extends ChangeNotifier {
  static const platform = MethodChannel('com.mxui.vpn/native');

  VpnStatus _status = VpnStatus.disconnected;
  VpnConfig? _currentConfig;
  int _uploadSpeed = 0; // bytes/s
  int _downloadSpeed = 0; // bytes/s
  int _totalUploaded = 0; // bytes
  int _totalDownloaded = 0; // bytes
  Duration _connectionDuration = Duration.zero;

  // Mock data for servers and subscriptions
  List<Server> _servers = [];
  List<Subscription> _subscriptions = [];

  VpnStatus get status => _status;
  VpnConfig? get currentConfig => _currentConfig;
  int get uploadSpeed => _uploadSpeed;
  int get downloadSpeed => _downloadSpeed;
  int get totalUploaded => _totalUploaded;
  int get totalDownloaded => _totalDownloaded;
  Duration get connectionDuration => _connectionDuration;

  bool get isConnected => _status == VpnStatus.connected;
  bool get isConnecting => _status == VpnStatus.connecting;
  bool get isDisconnecting => _status == VpnStatus.disconnecting;

  /// Connect to a VPN server
  Future<void> connect(Server server) async {
    if (_status == VpnStatus.connected || _status == VpnStatus.connecting) {
      throw Exception('Already connected or connecting');
    }

    _status = VpnStatus.connecting;
    notifyListeners();

    try {
      // Prepare VPN permission
      final bool prepared = await platform.invokeMethod('prepareVpn');

      if (!prepared) {
        throw Exception('VPN permission not granted');
      }

      // Build VPN config
      final config = {
        'server': server.address,
        'port': server.port,
        'protocol': server.protocol,
        'settings': server.settings,
      };

      // Start VPN
      await platform.invokeMethod('startVpn', {'config': config.toString()});

      _status = VpnStatus.connected;
      _startStats();
      notifyListeners();
    } catch (e) {
      _status = VpnStatus.disconnected;
      _currentConfig = null;
      notifyListeners();
      rethrow;
    }
  }

  /// Disconnect from VPN
  Future<void> disconnect() async {
    if (_status != VpnStatus.connected) {
      throw Exception('Not connected');
    }

    _status = VpnStatus.disconnecting;
    notifyListeners();

    try {
      // Stop VPN service
      await platform.invokeMethod('stopVpn');

      _status = VpnStatus.disconnected;
      _currentConfig = null;
      _stopStats();
      notifyListeners();
    } catch (e) {
      _status = VpnStatus.connected;
      notifyListeners();
      rethrow;
    }
  }

  /// Get all servers
  Future<List<Server>> getServers() async {
    // Return mock servers if empty
    if (_servers.isEmpty) {
      _servers = [
        Server(
          id: '1',
          name: 'Auto Select',
          address: 'auto.example.com',
          port: 443,
          protocol: 'auto',
          location: 'Best Available',
          countryCode: null,
          ping: null,
        ),
        Server(
          id: '2',
          name: 'Germany #1',
          address: 'de1.example.com',
          port: 443,
          protocol: 'vless',
          location: 'Frankfurt',
          countryCode: 'DE',
          ping: 45,
        ),
        Server(
          id: '3',
          name: 'Netherlands #1',
          address: 'nl1.example.com',
          port: 443,
          protocol: 'vmess',
          location: 'Amsterdam',
          countryCode: 'NL',
          ping: 52,
        ),
        Server(
          id: '4',
          name: 'USA #1',
          address: 'us1.example.com',
          port: 443,
          protocol: 'trojan',
          location: 'New York',
          countryCode: 'US',
          ping: 120,
        ),
      ];
    }
    return _servers;
  }

  /// Get all subscriptions
  Future<List<Subscription>> getSubscriptions() async {
    return _subscriptions;
  }

  /// Add a subscription
  Future<Subscription> addSubscription(String url, String name) async {
    final now = DateTime.now();
    final subscription = Subscription(
      id: now.millisecondsSinceEpoch.toString(),
      name: name,
      url: url,
      protocol: 'VMess',
      totalTraffic: 0,
      usedTraffic: 0,
      isActive: true,
      createdAt: now,
      updatedAt: now,
    );
    _subscriptions.add(subscription);
    notifyListeners();
    return subscription;
  }

  /// Remove a subscription
  Future<void> removeSubscription(String id) async {
    _subscriptions.removeWhere((s) => s.id == id);
    notifyListeners();
  }

  /// Update a subscription (fetch new servers)
  Future<void> updateSubscription(String id) async {
    // TODO: Implement actual subscription update
    await Future.delayed(const Duration(seconds: 1));
  }

  /// Ping a server
  Future<int> pingServer(Server server) async {
    // Simulate ping
    await Future.delayed(const Duration(milliseconds: 100));
    return (50 + DateTime.now().millisecond % 150);
  }

  /// Get traffic stats
  Future<TrafficStats> getStats() async {
    return TrafficStats(
      downloadBytes: _totalDownloaded,
      uploadBytes: _totalUploaded,
      currentSpeed: _downloadSpeed.toDouble(),
    );
  }

  void _startStats() {
    // TODO: Implement actual stats monitoring
    _totalUploaded = 0;
    _totalDownloaded = 0;
    _connectionDuration = Duration.zero;
  }

  void _stopStats() {
    _uploadSpeed = 0;
    _downloadSpeed = 0;
    _totalUploaded = 0;
    _totalDownloaded = 0;
    _connectionDuration = Duration.zero;
  }

  String formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(2)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(2)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }

  String formatSpeed(int bytesPerSecond) {
    return '${formatBytes(bytesPerSecond)}/s';
  }
}
