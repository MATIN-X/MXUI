import 'dart:async';
import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:hive/hive.dart';
import '../config/app_config.dart';
import 'logger_service.dart';

/// Service for handling push notifications from MXUI Panel
class NotificationService {
  static final NotificationService _instance = NotificationService._internal();
  factory NotificationService() => _instance;
  NotificationService._internal();

  final _notificationsController = StreamController<MXUINotification>.broadcast();
  Stream<MXUINotification> get notificationStream => _notificationsController.stream;

  Timer? _pollingTimer;
  String? _baseUrl;
  String? _token;
  int _lastNotificationId = 0;

  /// Initialize the notification service
  Future<void> initialize() async {
    try {
      final box = Hive.box('settings');
      _lastNotificationId = box.get('lastNotificationId', defaultValue: 0);
      logger.info('NotificationService', 'Initialized with lastId: $_lastNotificationId');
    } catch (e) {
      logger.error('NotificationService', 'Failed to initialize: $e');
    }
  }

  /// Configure the service with server URL and authentication
  void configure({required String baseUrl, required String token}) {
    _baseUrl = baseUrl;
    _token = token;
  }

  /// Start polling for new notifications
  void startPolling({Duration interval = const Duration(minutes: 5)}) {
    stopPolling();
    _pollingTimer = Timer.periodic(interval, (_) => fetchNotifications());
    // Initial fetch
    fetchNotifications();
    logger.info('NotificationService', 'Started polling every ${interval.inMinutes} minutes');
  }

  /// Stop polling for notifications
  void stopPolling() {
    _pollingTimer?.cancel();
    _pollingTimer = null;
  }

  /// Fetch new notifications from the server
  Future<List<MXUINotification>> fetchNotifications() async {
    if (_baseUrl == null || _token == null) {
      logger.warning('NotificationService', 'Not configured, skipping fetch');
      return [];
    }

    try {
      final response = await http.get(
        Uri.parse('$_baseUrl/api/v1/client/notifications?since=$_lastNotificationId'),
        headers: {
          'Authorization': 'Bearer $_token',
          'Content-Type': 'application/json',
        },
      ).timeout(const Duration(seconds: 30));

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        final List<dynamic> notificationsJson = data['notifications'] ?? [];

        final notifications = notificationsJson
            .map((json) => MXUINotification.fromJson(json))
            .toList();

        for (final notification in notifications) {
          _notificationsController.add(notification);
          if (notification.id > _lastNotificationId) {
            _lastNotificationId = notification.id;
          }
        }

        // Save last notification ID
        final box = Hive.box('settings');
        await box.put('lastNotificationId', _lastNotificationId);

        logger.info('NotificationService', 'Fetched ${notifications.length} notifications');
        return notifications;
      } else if (response.statusCode == 401) {
        logger.warning('NotificationService', 'Unauthorized, token may be expired');
        return [];
      } else {
        logger.error('NotificationService', 'Failed to fetch: ${response.statusCode}');
        return [];
      }
    } catch (e) {
      logger.error('NotificationService', 'Error fetching notifications: $e');
      return [];
    }
  }

  /// Mark a notification as read
  Future<bool> markAsRead(int notificationId) async {
    if (_baseUrl == null || _token == null) return false;

    try {
      final response = await http.post(
        Uri.parse('$_baseUrl/api/v1/client/notifications/$notificationId/read'),
        headers: {
          'Authorization': 'Bearer $_token',
          'Content-Type': 'application/json',
        },
      );

      return response.statusCode == 200;
    } catch (e) {
      logger.error('NotificationService', 'Error marking as read: $e');
      return false;
    }
  }

  /// Get all stored notifications
  Future<List<MXUINotification>> getStoredNotifications() async {
    try {
      final box = await Hive.openBox('notifications');
      final stored = box.values.toList();
      return stored.map((json) => MXUINotification.fromJson(Map<String, dynamic>.from(json))).toList();
    } catch (e) {
      logger.error('NotificationService', 'Error getting stored: $e');
      return [];
    }
  }

  /// Clear all stored notifications
  Future<void> clearNotifications() async {
    try {
      final box = await Hive.openBox('notifications');
      await box.clear();
    } catch (e) {
      logger.error('NotificationService', 'Error clearing: $e');
    }
  }

  void dispose() {
    stopPolling();
    _notificationsController.close();
  }
}

/// Model for MXUI Panel notifications
class MXUINotification {
  final int id;
  final String title;
  final String message;
  final String type; // info, warning, alert, promo
  final DateTime createdAt;
  final bool isRead;
  final Map<String, dynamic>? extra;

  MXUINotification({
    required this.id,
    required this.title,
    required this.message,
    required this.type,
    required this.createdAt,
    this.isRead = false,
    this.extra,
  });

  factory MXUINotification.fromJson(Map<String, dynamic> json) {
    return MXUINotification(
      id: json['id'] ?? 0,
      title: json['title'] ?? '',
      message: json['message'] ?? '',
      type: json['type'] ?? 'info',
      createdAt: DateTime.tryParse(json['created_at'] ?? '') ?? DateTime.now(),
      isRead: json['is_read'] ?? false,
      extra: json['extra'],
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'title': title,
      'message': message,
      'type': type,
      'created_at': createdAt.toIso8601String(),
      'is_read': isRead,
      'extra': extra,
    };
  }
}

// Global instance
final notificationService = NotificationService();
