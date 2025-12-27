import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../services/api_service.dart';
import '../services/storage_service.dart';
import '../services/logger_service.dart';

final apiServiceProvider = Provider<ApiService>((ref) {
  return ApiService();
});

final authStateProvider = StateNotifierProvider<AuthNotifier, AuthState>((ref) {
  return AuthNotifier(ref.read(apiServiceProvider));
});

enum AuthStatus { initial, loading, authenticated, unauthenticated, error }

class AuthState {
  final AuthStatus status;
  final String? token;
  final String? username;
  final String? error;
  final bool rememberMe;

  AuthState({
    required this.status,
    this.token,
    this.username,
    this.error,
    this.rememberMe = false,
  });

  factory AuthState.initial() {
    return AuthState(status: AuthStatus.initial);
  }

  AuthState copyWith({
    AuthStatus? status,
    String? token,
    String? username,
    String? error,
    bool? rememberMe,
  }) {
    return AuthState(
      status: status ?? this.status,
      token: token ?? this.token,
      username: username ?? this.username,
      error: error,
      rememberMe: rememberMe ?? this.rememberMe,
    );
  }

  bool get isAuthenticated => status == AuthStatus.authenticated;
  bool get isLoading => status == AuthStatus.loading;
}

class AuthNotifier extends StateNotifier<AuthState> {
  final ApiService _apiService;

  AuthNotifier(this._apiService) : super(AuthState.initial()) {
    _initAuth();
  }

  Future<void> _initAuth() async {
    await checkAuth();
  }

  Future<void> login(String username, String password, {bool rememberMe = false}) async {
    state = state.copyWith(status: AuthStatus.loading, error: null);
    logger.info('Auth', 'Attempting login for user: $username');

    try {
      final result = await _apiService.login(username, password);
      final token = result['token'] as String?;

      if (token != null) {
        // Save token securely
        await storage.saveToken(token);

        // Save credentials if remember me is enabled
        if (rememberMe) {
          await storage.saveCredentials(username, password);
        }

        state = state.copyWith(
          status: AuthStatus.authenticated,
          token: token,
          username: username,
          rememberMe: rememberMe,
        );

        logger.info('Auth', 'Login successful for user: $username');
      } else {
        throw Exception('No token received');
      }
    } catch (e) {
      logger.error('Auth', 'Login failed', e);
      state = state.copyWith(
        status: AuthStatus.error,
        error: _parseError(e.toString()),
      );
    }
  }

  Future<void> logout() async {
    logger.info('Auth', 'Logging out user: ${state.username}');

    try {
      await _apiService.logout();
    } catch (e) {
      logger.warning('Auth', 'Logout API call failed', e);
    }

    // Clear stored credentials and token
    await storage.clearCredentials();

    state = AuthState.initial().copyWith(status: AuthStatus.unauthenticated);
    logger.info('Auth', 'Logout completed');
  }

  Future<void> checkAuth() async {
    logger.debug('Auth', 'Checking authentication status');

    try {
      // Check for saved token
      final token = await storage.getToken();

      if (token != null && token.isNotEmpty) {
        // Validate token with API
        _apiService.setToken(token);

        try {
          final user = await _apiService.getCurrentUser();
          state = state.copyWith(
            status: AuthStatus.authenticated,
            token: token,
            username: user['username'],
          );
          logger.info('Auth', 'Session restored for user: ${user['username']}');
          return;
        } catch (e) {
          // Token invalid, try auto-login with saved credentials
          logger.debug('Auth', 'Token validation failed, trying saved credentials');
          await _tryAutoLogin();
          return;
        }
      }

      // Try auto-login with saved credentials
      await _tryAutoLogin();
    } catch (e) {
      logger.error('Auth', 'Auth check failed', e);
      state = state.copyWith(status: AuthStatus.unauthenticated);
    }
  }

  Future<void> _tryAutoLogin() async {
    final credentials = await storage.getCredentials();

    if (credentials != null) {
      logger.debug('Auth', 'Found saved credentials, attempting auto-login');
      try {
        await login(
          credentials['username']!,
          credentials['password']!,
          rememberMe: true,
        );
        return;
      } catch (e) {
        logger.warning('Auth', 'Auto-login failed', e);
      }
    }

    state = state.copyWith(status: AuthStatus.unauthenticated);
  }

  Future<void> refreshToken() async {
    if (state.token == null) return;

    try {
      final newToken = await _apiService.refreshToken();
      await storage.saveToken(newToken);
      state = state.copyWith(token: newToken);
      logger.debug('Auth', 'Token refreshed');
    } catch (e) {
      logger.error('Auth', 'Token refresh failed', e);
      // Force re-authentication
      await checkAuth();
    }
  }

  String _parseError(String error) {
    if (error.contains('401') || error.contains('unauthorized')) {
      return 'Invalid username or password';
    }
    if (error.contains('network') || error.contains('connection')) {
      return 'Network error. Please check your connection';
    }
    if (error.contains('timeout')) {
      return 'Connection timeout. Please try again';
    }
    return 'Login failed. Please try again';
  }
}
