// MXUI VPN Client
// providers/settings_provider.dart - Settings State Provider

import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:hive/hive.dart';
import '../core/constants.dart';

class SettingsProvider extends ChangeNotifier {
  // Routing
  bool _routeAll = true;
  List<String> _proxyDomains = [];
  List<String> _directDomains = [];
  List<String> _blockedDomains = [];
  List<String> _directApps = [];
  List<String> _proxyApps = [];

  // DNS
  String _dnsMode = 'auto';
  String _remoteDns = 'https://1.1.1.1/dns-query';
  String _directDns = '223.5.5.5';
  bool _dnsRouting = true;

  // WARP
  bool _warpEnabled = false;
  String _warpMode = 'proxy'; // proxy, warp_only
  String _warpLicense = '';
  Map<String, dynamic>? _warpConfig;

  // TLS & Fragment
  bool _tlsEnabled = true;
  String _tlsFingerprint = 'chrome';
  bool _fragmentEnabled = false;
  String _fragmentMode = 'tlshello';
  int _fragmentLength = 100;
  int _fragmentInterval = 50;

  // Network
  bool _ipv6Enabled = false;
  bool _blockAds = true;
  bool _blockMalware = true;
  int _mtu = 1500;
  bool _sniffing = true;

  // Connection
  int _connectionTimeout = 5000;
  bool _autoReconnect = true;
  int _testUrl = 0; // 0: Google, 1: Cloudflare
  bool _bypassLAN = true;

  // UI
  bool _showNotification = true;
  bool _showSpeed = true;
  bool _vibrate = true;
  bool _batterySaver = false;

  // Getters
  bool get routeAll => _routeAll;
  List<String> get proxyDomains => _proxyDomains;
  List<String> get directDomains => _directDomains;
  List<String> get blockedDomains => _blockedDomains;
  List<String> get directApps => _directApps;
  List<String> get proxyApps => _proxyApps;

  String get dnsMode => _dnsMode;
  String get remoteDns => _remoteDns;
  String get directDns => _directDns;
  bool get dnsRouting => _dnsRouting;

  bool get warpEnabled => _warpEnabled;
  String get warpMode => _warpMode;
  String get warpLicense => _warpLicense;
  Map<String, dynamic>? get warpConfig => _warpConfig;

  bool get tlsEnabled => _tlsEnabled;
  String get tlsFingerprint => _tlsFingerprint;
  bool get fragmentEnabled => _fragmentEnabled;
  String get fragmentMode => _fragmentMode;
  int get fragmentLength => _fragmentLength;
  int get fragmentInterval => _fragmentInterval;

  bool get ipv6Enabled => _ipv6Enabled;
  bool get blockAds => _blockAds;
  bool get blockMalware => _blockMalware;
  int get mtu => _mtu;
  bool get sniffing => _sniffing;

  int get connectionTimeout => _connectionTimeout;
  bool get autoReconnect => _autoReconnect;
  int get testUrl => _testUrl;
  bool get bypassLAN => _bypassLAN;

  bool get showNotification => _showNotification;
  bool get showSpeed => _showSpeed;
  bool get vibrate => _vibrate;
  bool get batterySaver => _batterySaver;

  SettingsProvider() {
    _loadSettings();
  }

  Future<void> _loadSettings() async {
    final box = Hive.box('settings');

    // Routing
    _routeAll = box.get('route_all', defaultValue: true);
    _proxyDomains = _loadList(box, 'proxy_domains');
    _directDomains = _loadList(box, 'direct_domains');
    _blockedDomains = _loadList(box, 'blocked_domains');
    _directApps = _loadList(box, 'direct_apps');
    _proxyApps = _loadList(box, 'proxy_apps');

    // DNS
    _dnsMode = box.get('dns_mode', defaultValue: 'auto');
    _remoteDns = box.get('remote_dns', defaultValue: 'https://1.1.1.1/dns-query');
    _directDns = box.get('direct_dns', defaultValue: '223.5.5.5');
    _dnsRouting = box.get('dns_routing', defaultValue: true);

    // WARP
    _warpEnabled = box.get(AppConstants.keyWarpEnabled, defaultValue: false);
    _warpMode = box.get('warp_mode', defaultValue: 'proxy');
    _warpLicense = box.get('warp_license', defaultValue: '');
    final warpConfigStr = box.get(AppConstants.keyWarpConfig);
    if (warpConfigStr != null) {
      _warpConfig = jsonDecode(warpConfigStr);
    }

    // TLS & Fragment
    _tlsEnabled = box.get('tls_enabled', defaultValue: true);
    _tlsFingerprint = box.get('tls_fingerprint', defaultValue: 'chrome');
    _fragmentEnabled = box.get(AppConstants.keyFragmentEnabled, defaultValue: false);
    _fragmentMode = box.get('fragment_mode', defaultValue: 'tlshello');
    _fragmentLength = box.get('fragment_length', defaultValue: 100);
    _fragmentInterval = box.get('fragment_interval', defaultValue: 50);

    // Network
    _ipv6Enabled = box.get(AppConstants.keyIpv6Enabled, defaultValue: false);
    _blockAds = box.get(AppConstants.keyBlockAds, defaultValue: true);
    _blockMalware = box.get('block_malware', defaultValue: true);
    _mtu = box.get('mtu', defaultValue: 1500);
    _sniffing = box.get('sniffing', defaultValue: true);

    // Connection
    _connectionTimeout = box.get('connection_timeout', defaultValue: 5000);
    _autoReconnect = box.get('auto_reconnect', defaultValue: true);
    _testUrl = box.get('test_url', defaultValue: 0);
    _bypassLAN = box.get('bypass_lan', defaultValue: true);

    // UI
    _showNotification = box.get('show_notification', defaultValue: true);
    _showSpeed = box.get('show_speed', defaultValue: true);
    _vibrate = box.get('vibrate', defaultValue: true);
    _batterySaver = box.get('battery_saver', defaultValue: false);

    notifyListeners();
  }

  List<String> _loadList(Box box, String key) {
    final str = box.get(key);
    if (str == null) return [];
    try {
      return List<String>.from(jsonDecode(str));
    } catch (e) {
      return [];
    }
  }

  Future<void> _saveList(String key, List<String> list) async {
    final box = Hive.box('settings');
    await box.put(key, jsonEncode(list));
  }

  // Routing Setters
  void setRouteAll(bool value) {
    _routeAll = value;
    Hive.box('settings').put('route_all', value);
    notifyListeners();
  }

  void addProxyDomain(String domain) {
    if (!_proxyDomains.contains(domain)) {
      _proxyDomains.add(domain);
      _saveList('proxy_domains', _proxyDomains);
      notifyListeners();
    }
  }

  void removeProxyDomain(String domain) {
    _proxyDomains.remove(domain);
    _saveList('proxy_domains', _proxyDomains);
    notifyListeners();
  }

  void addDirectDomain(String domain) {
    if (!_directDomains.contains(domain)) {
      _directDomains.add(domain);
      _saveList('direct_domains', _directDomains);
      notifyListeners();
    }
  }

  void removeDirectDomain(String domain) {
    _directDomains.remove(domain);
    _saveList('direct_domains', _directDomains);
    notifyListeners();
  }

  void addBlockedDomain(String domain) {
    if (!_blockedDomains.contains(domain)) {
      _blockedDomains.add(domain);
      _saveList('blocked_domains', _blockedDomains);
      notifyListeners();
    }
  }

  void removeBlockedDomain(String domain) {
    _blockedDomains.remove(domain);
    _saveList('blocked_domains', _blockedDomains);
    notifyListeners();
  }

  // DNS Setters
  void setDnsMode(String mode) {
    _dnsMode = mode;
    Hive.box('settings').put('dns_mode', mode);
    notifyListeners();
  }

  void setRemoteDns(String dns) {
    _remoteDns = dns;
    Hive.box('settings').put('remote_dns', dns);
    notifyListeners();
  }

  void setDirectDns(String dns) {
    _directDns = dns;
    Hive.box('settings').put('direct_dns', dns);
    notifyListeners();
  }

  void setDnsRouting(bool value) {
    _dnsRouting = value;
    Hive.box('settings').put('dns_routing', value);
    notifyListeners();
  }

  // WARP Setters
  void setWarpEnabled(bool value) {
    _warpEnabled = value;
    Hive.box('settings').put(AppConstants.keyWarpEnabled, value);
    notifyListeners();
  }

  void setWarpMode(String mode) {
    _warpMode = mode;
    Hive.box('settings').put('warp_mode', mode);
    notifyListeners();
  }

  void setWarpLicense(String license) {
    _warpLicense = license;
    Hive.box('settings').put('warp_license', license);
    notifyListeners();
  }

  void setWarpConfig(Map<String, dynamic> config) {
    _warpConfig = config;
    Hive.box('settings').put(AppConstants.keyWarpConfig, jsonEncode(config));
    notifyListeners();
  }

  // Fragment Setters
  void setFragmentEnabled(bool value) {
    _fragmentEnabled = value;
    Hive.box('settings').put(AppConstants.keyFragmentEnabled, value);
    notifyListeners();
  }

  void setFragmentMode(String mode) {
    _fragmentMode = mode;
    Hive.box('settings').put('fragment_mode', mode);
    notifyListeners();
  }

  void setFragmentLength(int length) {
    _fragmentLength = length;
    Hive.box('settings').put('fragment_length', length);
    notifyListeners();
  }

  void setFragmentInterval(int interval) {
    _fragmentInterval = interval;
    Hive.box('settings').put('fragment_interval', interval);
    notifyListeners();
  }

  // Network Setters
  void setIpv6Enabled(bool value) {
    _ipv6Enabled = value;
    Hive.box('settings').put(AppConstants.keyIpv6Enabled, value);
    notifyListeners();
  }

  void setBlockAds(bool value) {
    _blockAds = value;
    Hive.box('settings').put(AppConstants.keyBlockAds, value);
    notifyListeners();
  }

  void setBlockMalware(bool value) {
    _blockMalware = value;
    Hive.box('settings').put('block_malware', value);
    notifyListeners();
  }

  void setMtu(int value) {
    _mtu = value;
    Hive.box('settings').put('mtu', value);
    notifyListeners();
  }

  void setSniffing(bool value) {
    _sniffing = value;
    Hive.box('settings').put('sniffing', value);
    notifyListeners();
  }

  // Connection Setters
  void setConnectionTimeout(int value) {
    _connectionTimeout = value;
    Hive.box('settings').put('connection_timeout', value);
    notifyListeners();
  }

  void setAutoReconnect(bool value) {
    _autoReconnect = value;
    Hive.box('settings').put('auto_reconnect', value);
    notifyListeners();
  }

  void setBypassLAN(bool value) {
    _bypassLAN = value;
    Hive.box('settings').put('bypass_lan', value);
    notifyListeners();
  }

  // UI Setters
  void setShowNotification(bool value) {
    _showNotification = value;
    Hive.box('settings').put('show_notification', value);
    notifyListeners();
  }

  void setShowSpeed(bool value) {
    _showSpeed = value;
    Hive.box('settings').put('show_speed', value);
    notifyListeners();
  }

  void setVibrate(bool value) {
    _vibrate = value;
    Hive.box('settings').put('vibrate', value);
    notifyListeners();
  }

  void setBatterySaver(bool value) {
    _batterySaver = value;
    Hive.box('settings').put('battery_saver', value);
    notifyListeners();
  }

  // Reset to defaults
  Future<void> resetToDefaults() async {
    final box = Hive.box('settings');
    await box.clear();
    await _loadSettings();
  }
}
