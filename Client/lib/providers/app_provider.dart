// MX-UI VPN Client
// providers/app_provider.dart - Application State Provider

import 'package:flutter/material.dart';
import 'package:hive/hive.dart';
import '../core/constants.dart';

class AppProvider extends ChangeNotifier {
  bool _isLoading = true;
  bool _hasSubscription = false;
  ThemeMode _themeMode = ThemeMode.dark;
  Locale _locale = const Locale('fa', 'IR');

  // Getters
  bool get isLoading => _isLoading;
  bool get hasSubscription => _hasSubscription;
  ThemeMode get themeMode => _themeMode;
  Locale get locale => _locale;
  bool get isDarkMode => _themeMode == ThemeMode.dark;

  AppProvider() {
    _initialize();
  }

  Future<void> _initialize() async {
    await _loadSettings();
    await _checkSubscription();
    _isLoading = false;
    notifyListeners();
  }

  Future<void> _loadSettings() async {
    final box = Hive.box('settings');

    // Load theme
    final themeStr = box.get(AppConstants.keyThemeMode, defaultValue: 'dark');
    _themeMode = themeStr == 'light' ? ThemeMode.light : ThemeMode.dark;

    // Load locale
    final localeStr = box.get(AppConstants.keyLocale, defaultValue: 'fa_IR');
    final parts = localeStr.split('_');
    _locale = Locale(parts[0], parts.length > 1 ? parts[1] : '');
  }

  Future<void> _checkSubscription() async {
    final accountsBox = Hive.box('accounts');
    final activeAccount = accountsBox.get(AppConstants.keyActiveAccount);
    _hasSubscription = activeAccount != null;
  }

  // Theme Methods
  void setThemeMode(ThemeMode mode) {
    _themeMode = mode;
    final box = Hive.box('settings');
    box.put(AppConstants.keyThemeMode, mode == ThemeMode.light ? 'light' : 'dark');
    notifyListeners();
  }

  void toggleTheme() {
    setThemeMode(_themeMode == ThemeMode.dark ? ThemeMode.light : ThemeMode.dark);
  }

  // Locale Methods
  void setLocale(Locale locale) {
    _locale = locale;
    final box = Hive.box('settings');
    box.put(AppConstants.keyLocale, '${locale.languageCode}_${locale.countryCode}');
    notifyListeners();
  }

  // Subscription Methods
  void setHasSubscription(bool value) {
    _hasSubscription = value;
    notifyListeners();
  }

  Future<void> logout() async {
    final accountsBox = Hive.box('accounts');
    await accountsBox.delete(AppConstants.keyActiveAccount);
    _hasSubscription = false;
    notifyListeners();
  }
}
