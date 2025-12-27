// MXUI VPN Client
// providers/account_provider.dart - Account State Provider

import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:hive/hive.dart';
import '../core/constants.dart';
import '../models/account.dart';
import '../services/api_service.dart';

class AccountProvider extends ChangeNotifier {
  List<Account> _accounts = [];
  Account? _activeAccount;
  bool _isLoading = false;
  String? _error;

  // Getters
  List<Account> get accounts => _accounts;
  Account? get activeAccount => _activeAccount;
  bool get isLoading => _isLoading;
  String? get error => _error;
  bool get hasAccounts => _accounts.isNotEmpty;

  AccountProvider() {
    _loadAccounts();
  }

  Future<void> _loadAccounts() async {
    final box = Hive.box('accounts');
    final accountsJson = box.get(AppConstants.keyAccounts);

    if (accountsJson != null) {
      try {
        final List<dynamic> decoded = jsonDecode(accountsJson);
        _accounts = decoded.map((e) => Account.fromJson(e)).toList();
      } catch (e) {
        _accounts = [];
      }
    }

    final activeId = box.get(AppConstants.keyActiveAccount);
    if (activeId != null && _accounts.isNotEmpty) {
      _activeAccount = _accounts.firstWhere(
        (a) => a.id == activeId,
        orElse: () => _accounts.first,
      );
    }

    notifyListeners();
  }

  Future<void> _saveAccounts() async {
    final box = Hive.box('accounts');
    final accountsJson = jsonEncode(_accounts.map((a) => a.toJson()).toList());
    await box.put(AppConstants.keyAccounts, accountsJson);
    if (_activeAccount != null) {
      await box.put(AppConstants.keyActiveAccount, _activeAccount!.id);
    }
  }

  // Add subscription from URL
  Future<bool> addSubscription(String url) async {
    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      // Fetch subscription info
      final account = await ApiService.fetchSubscription(url);

      // Check if already exists
      final existingIndex = _accounts.indexWhere((a) => a.subscriptionUrl == url);
      if (existingIndex >= 0) {
        _accounts[existingIndex] = account;
      } else {
        _accounts.add(account);
      }

      // Set as active
      _activeAccount = account;
      await _saveAccounts();

      _isLoading = false;
      notifyListeners();
      return true;
    } catch (e) {
      _error = e.toString();
      _isLoading = false;
      notifyListeners();
      return false;
    }
  }

  // Switch active account
  void setActiveAccount(Account account) {
    _activeAccount = account;
    final box = Hive.box('accounts');
    box.put(AppConstants.keyActiveAccount, account.id);
    notifyListeners();
  }

  // Refresh account info
  Future<void> refreshAccount([Account? account]) async {
    account ??= _activeAccount;
    if (account == null) return;

    _isLoading = true;
    notifyListeners();

    try {
      final updated = await ApiService.fetchSubscription(account.subscriptionUrl);
      final index = _accounts.indexWhere((a) => a.id == account!.id);
      if (index >= 0) {
        _accounts[index] = updated;
        if (_activeAccount?.id == account.id) {
          _activeAccount = updated;
        }
        await _saveAccounts();
      }
    } catch (e) {
      _error = e.toString();
    }

    _isLoading = false;
    notifyListeners();
  }

  // Remove account
  Future<void> removeAccount(Account account) async {
    _accounts.removeWhere((a) => a.id == account.id);

    if (_activeAccount?.id == account.id) {
      _activeAccount = _accounts.isNotEmpty ? _accounts.first : null;
    }

    await _saveAccounts();
    notifyListeners();
  }

  // Rename account
  Future<void> renameAccount(Account account, String name) async {
    final index = _accounts.indexWhere((a) => a.id == account.id);
    if (index >= 0) {
      _accounts[index] = account.copyWith(name: name);
      if (_activeAccount?.id == account.id) {
        _activeAccount = _accounts[index];
      }
      await _saveAccounts();
      notifyListeners();
    }
  }

  // Clear error
  void clearError() {
    _error = null;
    notifyListeners();
  }
}
