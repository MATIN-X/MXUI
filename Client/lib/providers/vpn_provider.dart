// MX-UI VPN Client
// providers/vpn_provider.dart - VPN Connection State Provider

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:hive/hive.dart';
import '../core/constants.dart';
import '../models/account.dart';

class VpnProvider extends ChangeNotifier {
  String _status = VpnStatus.disconnected;
  ServerConfig? _selectedServer;
  String _connectionMode = AppConstants.modeAuto;
  bool _warpEnabled = false;
  bool _warpConnected = false;
  TrafficStats _trafficStats = TrafficStats();
  DateTime? _connectedAt;
  Timer? _statsTimer;

  // Getters
  String get status => _status;
  ServerConfig? get selectedServer => _selectedServer;
  String get connectionMode => _connectionMode;
  bool get warpEnabled => _warpEnabled;
  bool get warpConnected => _warpConnected;
  TrafficStats get trafficStats => _trafficStats;
  DateTime? get connectedAt => _connectedAt;

  bool get isConnected => _status == VpnStatus.connected;
  bool get isConnecting => _status == VpnStatus.connecting;
  bool get isDisconnected => _status == VpnStatus.disconnected;

  Duration get connectionDuration {
    if (_connectedAt == null) return Duration.zero;
    return DateTime.now().difference(_connectedAt!);
  }

  VpnProvider() {
    _loadSettings();
  }

  Future<void> _loadSettings() async {
    final box = Hive.box('settings');
    _warpEnabled = box.get(AppConstants.keyWarpEnabled, defaultValue: false);
    _connectionMode = box.get(AppConstants.keyConnectionMode, defaultValue: AppConstants.modeAuto);
    notifyListeners();
  }

  // Connection Methods
  Future<void> connect() async {
    if (_status == VpnStatus.connected || _status == VpnStatus.connecting) return;

    _status = VpnStatus.connecting;
    notifyListeners();

    try {
      // TODO: Implement actual VPN connection using sing-box
      // This is a simulation
      await Future.delayed(const Duration(seconds: 2));

      // If WARP is enabled, connect through WARP
      if (_warpEnabled) {
        await _connectWarp();
      }

      _status = VpnStatus.connected;
      _connectedAt = DateTime.now();
      _startStatsTimer();
    } catch (e) {
      _status = VpnStatus.error;
    }

    notifyListeners();
  }

  Future<void> disconnect() async {
    if (_status == VpnStatus.disconnected || _status == VpnStatus.disconnecting) return;

    _status = VpnStatus.disconnecting;
    notifyListeners();

    try {
      _stopStatsTimer();

      // Disconnect WARP first if connected
      if (_warpConnected) {
        await _disconnectWarp();
      }

      // TODO: Implement actual VPN disconnection
      await Future.delayed(const Duration(milliseconds: 500));

      _status = VpnStatus.disconnected;
      _connectedAt = null;
      _trafficStats = TrafficStats();
    } catch (e) {
      _status = VpnStatus.error;
    }

    notifyListeners();
  }

  Future<void> toggleConnection() async {
    if (isConnected || isConnecting) {
      await disconnect();
    } else {
      await connect();
    }
  }

  // Server Selection
  void selectServer(ServerConfig server) {
    _selectedServer = server;
    notifyListeners();
  }

  // Connection Mode
  void setConnectionMode(String mode) {
    _connectionMode = mode;
    final box = Hive.box('settings');
    box.put(AppConstants.keyConnectionMode, mode);
    notifyListeners();
  }

  // WARP Methods
  Future<void> toggleWarp() async {
    _warpEnabled = !_warpEnabled;
    final box = Hive.box('settings');
    box.put(AppConstants.keyWarpEnabled, _warpEnabled);

    // If currently connected, need to reconnect with/without WARP
    if (isConnected) {
      if (_warpEnabled && !_warpConnected) {
        await _connectWarp();
      } else if (!_warpEnabled && _warpConnected) {
        await _disconnectWarp();
      }
    }

    notifyListeners();
  }

  Future<void> _connectWarp() async {
    // TODO: Implement WARP connection
    // User > Connected Server > WARP > End Server
    await Future.delayed(const Duration(milliseconds: 500));
    _warpConnected = true;
    notifyListeners();
  }

  Future<void> _disconnectWarp() async {
    // TODO: Implement WARP disconnection
    await Future.delayed(const Duration(milliseconds: 300));
    _warpConnected = false;
    notifyListeners();
  }

  // Stats Timer
  void _startStatsTimer() {
    _statsTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      _updateStats();
    });
  }

  void _stopStatsTimer() {
    _statsTimer?.cancel();
    _statsTimer = null;
  }

  void _updateStats() {
    // TODO: Get real stats from VPN core
    // This is a simulation
    final random = DateTime.now().millisecondsSinceEpoch % 1000;
    _trafficStats = TrafficStats(
      upload: _trafficStats.upload + random * 100,
      download: _trafficStats.download + random * 300,
      uploadSpeed: random * 50,
      downloadSpeed: random * 150,
      connectionTime: connectionDuration,
    );
    notifyListeners();
  }

  @override
  void dispose() {
    _stopStatsTimer();
    super.dispose();
  }
}
