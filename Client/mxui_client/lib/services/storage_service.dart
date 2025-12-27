import 'dart:convert';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../models/server.dart';
import '../models/subscription.dart';
import 'logger_service.dart';

class StorageService {
  static final StorageService _instance = StorageService._internal();
  factory StorageService() => _instance;
  StorageService._internal();

  static const _secureStorage = FlutterSecureStorage(
    aOptions: AndroidOptions(
      encryptedSharedPreferences: true,
    ),
    iOptions: IOSOptions(
      accessibility: KeychainAccessibility.first_unlock_this_device,
    ),
  );

  SharedPreferences? _prefs;
  Box? _settingsBox;
  Box? _serversBox;
  Box? _subscriptionsBox;

  bool _isInitialized = false;

  Future<void> initialize() async {
    if (_isInitialized) return;

    try {
      _prefs = await SharedPreferences.getInstance();

      await Hive.initFlutter();
      _settingsBox = await Hive.openBox('settings');
      _serversBox = await Hive.openBox('servers');
      _subscriptionsBox = await Hive.openBox('subscriptions');

      _isInitialized = true;
      logger.info('Storage', 'Storage service initialized');
    } catch (e) {
      logger.error('Storage', 'Failed to initialize storage', e);
      rethrow;
    }
  }

  // ============================================================================
  // SECURE STORAGE (for sensitive data like tokens)
  // ============================================================================

  Future<void> saveToken(String token) async {
    await _secureStorage.write(key: 'auth_token', value: token);
    logger.debug('Storage', 'Token saved securely');
  }

  Future<String?> getToken() async {
    return await _secureStorage.read(key: 'auth_token');
  }

  Future<void> deleteToken() async {
    await _secureStorage.delete(key: 'auth_token');
    logger.debug('Storage', 'Token deleted');
  }

  Future<void> saveCredentials(String username, String password) async {
    await _secureStorage.write(key: 'username', value: username);
    await _secureStorage.write(key: 'password', value: password);
    logger.debug('Storage', 'Credentials saved');
  }

  Future<Map<String, String>?> getCredentials() async {
    final username = await _secureStorage.read(key: 'username');
    final password = await _secureStorage.read(key: 'password');

    if (username != null && password != null) {
      return {'username': username, 'password': password};
    }
    return null;
  }

  Future<void> clearCredentials() async {
    await _secureStorage.delete(key: 'username');
    await _secureStorage.delete(key: 'password');
    await _secureStorage.delete(key: 'auth_token');
    logger.debug('Storage', 'All credentials cleared');
  }

  // ============================================================================
  // SETTINGS (non-sensitive preferences)
  // ============================================================================

  Future<void> setSetting<T>(String key, T value) async {
    await _settingsBox?.put(key, value);
  }

  T? getSetting<T>(String key, {T? defaultValue}) {
    return _settingsBox?.get(key, defaultValue: defaultValue) as T?;
  }

  // Theme
  Future<void> setThemeMode(String mode) async {
    await setSetting('themeMode', mode);
  }

  String getThemeMode() {
    return getSetting('themeMode', defaultValue: 'system') ?? 'system';
  }

  // Language
  Future<void> setLanguage(String langCode) async {
    await setSetting('language', langCode);
  }

  String getLanguage() {
    return getSetting('language', defaultValue: 'en') ?? 'en';
  }

  // VPN Settings
  Future<void> setAutoConnect(bool enabled) async {
    await setSetting('autoConnect', enabled);
  }

  bool getAutoConnect() {
    return getSetting('autoConnect', defaultValue: false) ?? false;
  }

  Future<void> setKillSwitch(bool enabled) async {
    await setSetting('killSwitch', enabled);
  }

  bool getKillSwitch() {
    return getSetting('killSwitch', defaultValue: false) ?? false;
  }

  Future<void> setSplitTunneling(bool enabled) async {
    await setSetting('splitTunneling', enabled);
  }

  bool getSplitTunneling() {
    return getSetting('splitTunneling', defaultValue: false) ?? false;
  }

  // DNS Settings
  Future<void> setDnsMode(String mode) async {
    await setSetting('dnsMode', mode);
  }

  String getDnsMode() {
    return getSetting('dnsMode', defaultValue: 'system') ?? 'system';
  }

  Future<void> setCustomDns(List<String> servers) async {
    await setSetting('customDns', servers);
  }

  List<String> getCustomDns() {
    final dns = getSetting<List<dynamic>>('customDns');
    return dns?.cast<String>() ?? ['1.1.1.1', '8.8.8.8'];
  }

  // Last connected server
  Future<void> setLastServerId(String? serverId) async {
    await setSetting('lastServerId', serverId);
  }

  String? getLastServerId() {
    return getSetting('lastServerId');
  }

  // API Base URL
  Future<void> setApiBaseUrl(String url) async {
    await setSetting('apiBaseUrl', url);
  }

  String? getApiBaseUrl() {
    return getSetting('apiBaseUrl');
  }

  // ============================================================================
  // SERVERS CACHE
  // ============================================================================

  Future<void> saveServers(List<Server> servers) async {
    try {
      final jsonList = servers.map((s) => s.toJson()).toList();
      await _serversBox?.put('cachedServers', jsonEncode(jsonList));
      await _serversBox?.put('serversCacheTime', DateTime.now().toIso8601String());
      logger.debug('Storage', 'Saved ${servers.length} servers to cache');
    } catch (e) {
      logger.error('Storage', 'Failed to save servers', e);
    }
  }

  List<Server>? getCachedServers() {
    try {
      final json = _serversBox?.get('cachedServers') as String?;
      if (json == null) return null;

      final List<dynamic> jsonList = jsonDecode(json);
      return jsonList.map((j) => Server.fromJson(j)).toList();
    } catch (e) {
      logger.error('Storage', 'Failed to load cached servers', e);
      return null;
    }
  }

  DateTime? getServersCacheTime() {
    final timeStr = _serversBox?.get('serversCacheTime') as String?;
    if (timeStr == null) return null;
    return DateTime.tryParse(timeStr);
  }

  bool isServersCacheValid({Duration maxAge = const Duration(hours: 1)}) {
    final cacheTime = getServersCacheTime();
    if (cacheTime == null) return false;
    return DateTime.now().difference(cacheTime) < maxAge;
  }

  // ============================================================================
  // SUBSCRIPTIONS
  // ============================================================================

  Future<void> saveSubscriptions(List<Subscription> subscriptions) async {
    try {
      final jsonList = subscriptions.map((s) => s.toJson()).toList();
      await _subscriptionsBox?.put('subscriptions', jsonEncode(jsonList));
      logger.debug('Storage', 'Saved ${subscriptions.length} subscriptions');
    } catch (e) {
      logger.error('Storage', 'Failed to save subscriptions', e);
    }
  }

  List<Subscription>? getSubscriptions() {
    try {
      final json = _subscriptionsBox?.get('subscriptions') as String?;
      if (json == null) return null;

      final List<dynamic> jsonList = jsonDecode(json);
      return jsonList.map((j) => Subscription.fromJson(j)).toList();
    } catch (e) {
      logger.error('Storage', 'Failed to load subscriptions', e);
      return null;
    }
  }

  Future<void> addSubscription(Subscription subscription) async {
    final subscriptions = getSubscriptions() ?? [];
    subscriptions.add(subscription);
    await saveSubscriptions(subscriptions);
  }

  Future<void> removeSubscription(String id) async {
    final subscriptions = getSubscriptions() ?? [];
    subscriptions.removeWhere((s) => s.id == id);
    await saveSubscriptions(subscriptions);
  }

  // ============================================================================
  // USAGE STATS
  // ============================================================================

  Future<void> updateTotalTraffic(int downloaded, int uploaded) async {
    final totalDownload = _prefs?.getInt('totalDownload') ?? 0;
    final totalUpload = _prefs?.getInt('totalUpload') ?? 0;

    await _prefs?.setInt('totalDownload', totalDownload + downloaded);
    await _prefs?.setInt('totalUpload', totalUpload + uploaded);
  }

  Map<String, int> getTotalTraffic() {
    return {
      'download': _prefs?.getInt('totalDownload') ?? 0,
      'upload': _prefs?.getInt('totalUpload') ?? 0,
    };
  }

  Future<void> updateConnectionTime(Duration duration) async {
    final totalSeconds = _prefs?.getInt('totalConnectionSeconds') ?? 0;
    await _prefs?.setInt('totalConnectionSeconds', totalSeconds + duration.inSeconds);
  }

  Duration getTotalConnectionTime() {
    final seconds = _prefs?.getInt('totalConnectionSeconds') ?? 0;
    return Duration(seconds: seconds);
  }

  // ============================================================================
  // CLEANUP
  // ============================================================================

  Future<void> clearAllData() async {
    await clearCredentials();
    await _settingsBox?.clear();
    await _serversBox?.clear();
    await _subscriptionsBox?.clear();
    await _prefs?.clear();
    logger.info('Storage', 'All data cleared');
  }

  Future<void> clearCache() async {
    await _serversBox?.clear();
    logger.info('Storage', 'Cache cleared');
  }
}

// Global storage instance
final storage = StorageService();
