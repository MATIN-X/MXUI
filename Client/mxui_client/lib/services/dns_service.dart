import 'dart:io';
import 'package:flutter/services.dart';
import 'logger_service.dart';
import 'storage_service.dart';

enum DnsMode {
  system,
  cloudflare,
  google,
  quad9,
  adguard,
  custom,
}

class DnsServer {
  final String name;
  final String primary;
  final String secondary;
  final String? dohUrl;
  final String? dotHost;

  const DnsServer({
    required this.name,
    required this.primary,
    required this.secondary,
    this.dohUrl,
    this.dotHost,
  });
}

class DnsService {
  static final DnsService _instance = DnsService._internal();
  factory DnsService() => _instance;
  DnsService._internal();

  static const platform = MethodChannel('com.mxui.vpn/dns');

  static const Map<DnsMode, DnsServer> predefinedServers = {
    DnsMode.system: DnsServer(
      name: 'System DNS',
      primary: '',
      secondary: '',
    ),
    DnsMode.cloudflare: DnsServer(
      name: 'Cloudflare',
      primary: '1.1.1.1',
      secondary: '1.0.0.1',
      dohUrl: 'https://cloudflare-dns.com/dns-query',
      dotHost: 'cloudflare-dns.com',
    ),
    DnsMode.google: DnsServer(
      name: 'Google',
      primary: '8.8.8.8',
      secondary: '8.8.4.4',
      dohUrl: 'https://dns.google/dns-query',
      dotHost: 'dns.google',
    ),
    DnsMode.quad9: DnsServer(
      name: 'Quad9',
      primary: '9.9.9.9',
      secondary: '149.112.112.112',
      dohUrl: 'https://dns.quad9.net/dns-query',
      dotHost: 'dns.quad9.net',
    ),
    DnsMode.adguard: DnsServer(
      name: 'AdGuard',
      primary: '94.140.14.14',
      secondary: '94.140.15.15',
      dohUrl: 'https://dns.adguard.com/dns-query',
      dotHost: 'dns.adguard.com',
    ),
  };

  DnsMode _currentMode = DnsMode.system;
  List<String> _customServers = [];

  DnsMode get currentMode => _currentMode;
  List<String> get customServers => _customServers;

  DnsServer get currentServer {
    if (_currentMode == DnsMode.custom) {
      return DnsServer(
        name: 'Custom DNS',
        primary: _customServers.isNotEmpty ? _customServers[0] : '1.1.1.1',
        secondary: _customServers.length > 1 ? _customServers[1] : '8.8.8.8',
      );
    }
    return predefinedServers[_currentMode]!;
  }

  Future<void> initialize() async {
    try {
      final modeStr = storage.getDnsMode();
      _currentMode = DnsMode.values.firstWhere(
        (e) => e.name == modeStr,
        orElse: () => DnsMode.system,
      );
      _customServers = storage.getCustomDns();
      logger.info('DNS', 'DNS service initialized with mode: ${_currentMode.name}');
    } catch (e) {
      logger.error('DNS', 'Failed to initialize DNS service', e);
    }
  }

  Future<void> setMode(DnsMode mode) async {
    _currentMode = mode;
    await storage.setDnsMode(mode.name);
    logger.info('DNS', 'DNS mode changed to: ${mode.name}');

    if (_currentMode != DnsMode.custom) {
      await _applyDns(predefinedServers[mode]!);
    }
  }

  Future<void> setCustomServers(List<String> servers) async {
    if (servers.isEmpty) {
      logger.warning('DNS', 'Cannot set empty DNS server list');
      return;
    }

    // Validate IP addresses
    for (final server in servers) {
      if (!_isValidIp(server) && !_isValidDomain(server)) {
        logger.warning('DNS', 'Invalid DNS server: $server');
        return;
      }
    }

    _customServers = servers;
    await storage.setCustomDns(servers);
    _currentMode = DnsMode.custom;
    await storage.setDnsMode(DnsMode.custom.name);

    await _applyDns(currentServer);
    logger.info('DNS', 'Custom DNS set: ${servers.join(", ")}');
  }

  Future<void> _applyDns(DnsServer server) async {
    if (server.primary.isEmpty) {
      // System DNS, nothing to apply
      return;
    }

    try {
      await platform.invokeMethod('setDns', {
        'primary': server.primary,
        'secondary': server.secondary,
        'dohUrl': server.dohUrl,
        'dotHost': server.dotHost,
      });
      logger.info('DNS', 'Applied DNS: ${server.name}');
    } catch (e) {
      logger.error('DNS', 'Failed to apply DNS', e);
    }
  }

  Future<String?> resolve(String domain) async {
    try {
      final addresses = await InternetAddress.lookup(domain);
      if (addresses.isNotEmpty) {
        return addresses.first.address;
      }
    } catch (e) {
      logger.error('DNS', 'Failed to resolve $domain', e);
    }
    return null;
  }

  Future<int> testDns(DnsServer server) async {
    final stopwatch = Stopwatch()..start();
    try {
      // Test resolution with the DNS server
      final result = await platform.invokeMethod<int>('testDns', {
        'server': server.primary,
        'testDomain': 'google.com',
      });
      stopwatch.stop();
      return result ?? stopwatch.elapsedMilliseconds;
    } catch (e) {
      // Fallback to simple ping test
      stopwatch.stop();
      final addresses = await InternetAddress.lookup('google.com');
      return addresses.isNotEmpty ? stopwatch.elapsedMilliseconds : 9999;
    }
  }

  Future<Map<DnsMode, int>> testAllDns() async {
    final results = <DnsMode, int>{};

    for (final entry in predefinedServers.entries) {
      if (entry.key == DnsMode.system || entry.key == DnsMode.custom) continue;

      try {
        results[entry.key] = await testDns(entry.value);
        logger.debug('DNS', '${entry.value.name}: ${results[entry.key]}ms');
      } catch (e) {
        results[entry.key] = 9999;
      }
    }

    return results;
  }

  bool _isValidIp(String ip) {
    try {
      final parts = ip.split('.');
      if (parts.length != 4) return false;
      for (final part in parts) {
        final num = int.tryParse(part);
        if (num == null || num < 0 || num > 255) return false;
      }
      return true;
    } catch (e) {
      return false;
    }
  }

  bool _isValidDomain(String domain) {
    final regex = RegExp(
      r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$',
    );
    return regex.hasMatch(domain);
  }

  String getDnsDescription(DnsMode mode) {
    switch (mode) {
      case DnsMode.system:
        return 'Use system default DNS';
      case DnsMode.cloudflare:
        return 'Fast and privacy-focused (1.1.1.1)';
      case DnsMode.google:
        return 'Google Public DNS (8.8.8.8)';
      case DnsMode.quad9:
        return 'Security focused with malware blocking';
      case DnsMode.adguard:
        return 'Blocks ads and trackers';
      case DnsMode.custom:
        return 'Your custom DNS servers';
    }
  }
}

// Global DNS service instance
final dnsService = DnsService();
