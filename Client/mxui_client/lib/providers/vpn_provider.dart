import 'dart:async';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../models/server.dart';
import '../models/subscription.dart';
import '../services/vpn_service.dart';

// VPN Connection State
enum VpnStatus {
  disconnected,
  connecting,
  connected,
  disconnecting,
  error,
}

class VpnState {
  final VpnStatus status;
  final Server? currentServer;
  final String? error;
  final int downloadBytes;
  final int uploadBytes;
  final Duration connectionDuration;
  final double currentSpeed;
  final List<Server> servers;
  final List<Subscription> subscriptions;
  final bool isAutoConnect;

  const VpnState({
    this.status = VpnStatus.disconnected,
    this.currentServer,
    this.error,
    this.downloadBytes = 0,
    this.uploadBytes = 0,
    this.connectionDuration = Duration.zero,
    this.currentSpeed = 0,
    this.servers = const [],
    this.subscriptions = const [],
    this.isAutoConnect = false,
  });

  VpnState copyWith({
    VpnStatus? status,
    Server? currentServer,
    String? error,
    int? downloadBytes,
    int? uploadBytes,
    Duration? connectionDuration,
    double? currentSpeed,
    List<Server>? servers,
    List<Subscription>? subscriptions,
    bool? isAutoConnect,
  }) {
    return VpnState(
      status: status ?? this.status,
      currentServer: currentServer ?? this.currentServer,
      error: error,
      downloadBytes: downloadBytes ?? this.downloadBytes,
      uploadBytes: uploadBytes ?? this.uploadBytes,
      connectionDuration: connectionDuration ?? this.connectionDuration,
      currentSpeed: currentSpeed ?? this.currentSpeed,
      servers: servers ?? this.servers,
      subscriptions: subscriptions ?? this.subscriptions,
      isAutoConnect: isAutoConnect ?? this.isAutoConnect,
    );
  }

  bool get isConnected => status == VpnStatus.connected;
  bool get isConnecting => status == VpnStatus.connecting;
  bool get isDisconnecting => status == VpnStatus.disconnecting;
}

class VpnNotifier extends StateNotifier<VpnState> {
  final VpnService _vpnService;
  Timer? _statsTimer;
  DateTime? _connectionStartTime;

  VpnNotifier(this._vpnService) : super(const VpnState()) {
    _loadServers();
    _loadSubscriptions();
  }

  Future<void> _loadServers() async {
    try {
      final servers = await _vpnService.getServers();
      state = state.copyWith(servers: servers);
    } catch (e) {
      state = state.copyWith(error: e.toString());
    }
  }

  Future<void> _loadSubscriptions() async {
    try {
      final subscriptions = await _vpnService.getSubscriptions();
      state = state.copyWith(subscriptions: subscriptions);
    } catch (e) {
      state = state.copyWith(error: e.toString());
    }
  }

  Future<void> connect({Server? server}) async {
    if (state.status == VpnStatus.connecting || 
        state.status == VpnStatus.connected) return;

    final targetServer = server ?? state.currentServer ?? _selectBestServer();
    if (targetServer == null) {
      state = state.copyWith(
        status: VpnStatus.error,
        error: 'No server available',
      );
      return;
    }

    state = state.copyWith(
      status: VpnStatus.connecting,
      currentServer: targetServer,
      error: null,
    );

    try {
      await _vpnService.connect(targetServer);
      _connectionStartTime = DateTime.now();
      _startStatsTimer();
      
      state = state.copyWith(
        status: VpnStatus.connected,
        downloadBytes: 0,
        uploadBytes: 0,
        connectionDuration: Duration.zero,
      );
    } catch (e) {
      state = state.copyWith(
        status: VpnStatus.error,
        error: e.toString(),
      );
    }
  }

  Future<void> disconnect() async {
    if (state.status != VpnStatus.connected) return;

    state = state.copyWith(status: VpnStatus.disconnecting);

    try {
      await _vpnService.disconnect();
      _stopStatsTimer();
      _connectionStartTime = null;
      
      state = state.copyWith(
        status: VpnStatus.disconnected,
        downloadBytes: 0,
        uploadBytes: 0,
        connectionDuration: Duration.zero,
        currentSpeed: 0,
      );
    } catch (e) {
      state = state.copyWith(
        status: VpnStatus.error,
        error: e.toString(),
      );
    }
  }

  void selectServer(Server server) {
    state = state.copyWith(currentServer: server);
  }

  Server? _selectBestServer() {
    if (state.servers.isEmpty) return null;
    // Select server with lowest ping
    return state.servers.reduce((a, b) => 
      (a.ping ?? 999) < (b.ping ?? 999) ? a : b);
  }

  void _startStatsTimer() {
    _statsTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      _updateStats();
    });
  }

  void _stopStatsTimer() {
    _statsTimer?.cancel();
    _statsTimer = null;
  }

  Future<void> _updateStats() async {
    if (state.status != VpnStatus.connected || _connectionStartTime == null) return;

    try {
      final stats = await _vpnService.getStats();
      final duration = DateTime.now().difference(_connectionStartTime!);
      
      state = state.copyWith(
        downloadBytes: stats.downloadBytes,
        uploadBytes: stats.uploadBytes,
        connectionDuration: duration,
        currentSpeed: stats.currentSpeed,
      );
    } catch (e) {
      // Ignore stats update errors
    }
  }

  Future<void> refreshServers() async {
    await _loadServers();
  }

  Future<void> addSubscription(String url, String name) async {
    try {
      final subscription = await _vpnService.addSubscription(url, name);
      state = state.copyWith(
        subscriptions: [...state.subscriptions, subscription],
      );
      await _loadServers();
    } catch (e) {
      state = state.copyWith(error: e.toString());
      rethrow;
    }
  }

  Future<void> removeSubscription(String id) async {
    try {
      await _vpnService.removeSubscription(id);
      state = state.copyWith(
        subscriptions: state.subscriptions.where((s) => s.id != id).toList(),
      );
      await _loadServers();
    } catch (e) {
      state = state.copyWith(error: e.toString());
      rethrow;
    }
  }

  Future<void> updateSubscription(String id) async {
    try {
      await _vpnService.updateSubscription(id);
      await _loadServers();
    } catch (e) {
      state = state.copyWith(error: e.toString());
      rethrow;
    }
  }

  Future<void> pingAllServers() async {
    final updatedServers = await Future.wait(
      state.servers.map((server) async {
        final ping = await _vpnService.pingServer(server);
        return server.copyWith(ping: ping);
      }),
    );
    state = state.copyWith(servers: updatedServers);
  }

  void setAutoConnect(bool value) {
    state = state.copyWith(isAutoConnect: value);
    // TODO: Save to preferences
  }

  @override
  void dispose() {
    _stopStatsTimer();
    super.dispose();
  }
}

// Provider
final vpnServiceProvider = Provider<VpnService>((ref) {
  return VpnService();
});

final vpnProvider = StateNotifierProvider<VpnNotifier, VpnState>((ref) {
  final vpnService = ref.watch(vpnServiceProvider);
  return VpnNotifier(vpnService);
});

// Convenience providers
final vpnStatusProvider = Provider<VpnStatus>((ref) {
  return ref.watch(vpnProvider).status;
});

final currentServerProvider = Provider<Server?>((ref) {
  return ref.watch(vpnProvider).currentServer;
});

final serversProvider = Provider<List<Server>>((ref) {
  return ref.watch(vpnProvider).servers;
});

final subscriptionsProvider = Provider<List<Subscription>>((ref) {
  return ref.watch(vpnProvider).subscriptions;
});

final connectionStatsProvider = Provider<({int download, int upload, Duration duration, double speed})>((ref) {
  final state = ref.watch(vpnProvider);
  return (
    download: state.downloadBytes,
    upload: state.uploadBytes,
    duration: state.connectionDuration,
    speed: state.currentSpeed,
  );
});
