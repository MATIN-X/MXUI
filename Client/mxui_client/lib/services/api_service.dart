import 'dart:convert';
import 'package:http/http.dart' as http;
import '../config/app_config.dart';
import '../models/subscription.dart';
import '../models/vpn_config.dart';

class ApiService {
  final String baseUrl;
  String? _token;

  ApiService({String? baseUrl}) : baseUrl = baseUrl ?? AppConfig.apiBaseUrl;

  void setToken(String token) {
    _token = token;
  }

  void clearToken() {
    _token = null;
  }

  Map<String, String> get _headers {
    final headers = {
      'Content-Type': 'application/json',
    };
    if (_token != null) {
      headers['Authorization'] = 'Bearer $_token';
    }
    return headers;
  }

  // Auth
  Future<Map<String, dynamic>> login(String username, String password) async {
    final response = await http.post(
      Uri.parse('$baseUrl/api/auth/login'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'username': username, 'password': password}),
    );

    if (response.statusCode == 200) {
      final data = jsonDecode(response.body);
      if (data['token'] != null) {
        setToken(data['token']);
      }
      return data;
    } else {
      throw Exception('Login failed: ${response.body}');
    }
  }

  Future<void> logout() async {
    clearToken();
  }

  // Subscriptions
  Future<List<Subscription>> getSubscriptions() async {
    final response = await http.get(
      Uri.parse('$baseUrl/api/subscriptions'),
      headers: _headers,
    );

    if (response.statusCode == 200) {
      final List<dynamic> data = jsonDecode(response.body);
      return data.map((json) => Subscription.fromJson(json)).toList();
    } else {
      throw Exception('Failed to load subscriptions: ${response.body}');
    }
  }

  Future<Subscription> createSubscription(Map<String, dynamic> data) async {
    final response = await http.post(
      Uri.parse('$baseUrl/api/subscriptions'),
      headers: _headers,
      body: jsonEncode(data),
    );

    if (response.statusCode == 201) {
      return Subscription.fromJson(jsonDecode(response.body));
    } else {
      throw Exception('Failed to create subscription: ${response.body}');
    }
  }

  Future<void> deleteSubscription(String id) async {
    final response = await http.delete(
      Uri.parse('$baseUrl/api/subscriptions/$id'),
      headers: _headers,
    );

    if (response.statusCode != 200) {
      throw Exception('Failed to delete subscription: ${response.body}');
    }
  }

  // VPN Configs
  Future<List<VpnConfig>> getConfigs(String subscriptionId) async {
    final response = await http.get(
      Uri.parse('$baseUrl/api/subscriptions/$subscriptionId/configs'),
      headers: _headers,
    );

    if (response.statusCode == 200) {
      final List<dynamic> data = jsonDecode(response.body);
      return data.map((json) => VpnConfig.fromJson(json)).toList();
    } else {
      throw Exception('Failed to load configs: ${response.body}');
    }
  }

  Future<Map<String, dynamic>> testConfig(String configId) async {
    final response = await http.post(
      Uri.parse('$baseUrl/api/configs/$configId/test'),
      headers: _headers,
    );

    if (response.statusCode == 200) {
      return jsonDecode(response.body);
    } else {
      throw Exception('Failed to test config: ${response.body}');
    }
  }

  // User
  Future<dynamic> getCurrentUser() async {
    final response = await http.get(
      Uri.parse('$baseUrl/api/user/me'),
      headers: _headers,
    );

    if (response.statusCode == 200) {
      return jsonDecode(response.body);
    } else {
      throw Exception('Failed to get current user: ${response.body}');
    }
  }

  Future<String> refreshToken() async {
    final response = await http.post(
      Uri.parse('$baseUrl/api/auth/refresh'),
      headers: _headers,
    );

    if (response.statusCode == 200) {
      final data = jsonDecode(response.body);
      final newToken = data['token'] as String;
      setToken(newToken);
      return newToken;
    } else {
      throw Exception('Failed to refresh token: ${response.body}');
    }
  }

  // Stats
  Future<Map<String, dynamic>> getStats() async {
    final response = await http.get(
      Uri.parse('$baseUrl/api/stats'),
      headers: _headers,
    );

    if (response.statusCode == 200) {
      return jsonDecode(response.body);
    } else {
      throw Exception('Failed to load stats: ${response.body}');
    }
  }

  // Import subscription URL
  Future<Subscription> importSubscription(String url) async {
    final response = await http.post(
      Uri.parse('$baseUrl/api/subscriptions/import'),
      headers: _headers,
      body: jsonEncode({'url': url}),
    );

    if (response.statusCode == 201) {
      return Subscription.fromJson(jsonDecode(response.body));
    } else {
      throw Exception('Failed to import subscription: ${response.body}');
    }
  }
}
