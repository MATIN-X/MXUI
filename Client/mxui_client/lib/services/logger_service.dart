import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';
import 'package:intl/intl.dart';

enum LogLevel { debug, info, warning, error }

class LogEntry {
  final DateTime timestamp;
  final LogLevel level;
  final String tag;
  final String message;
  final Object? error;
  final StackTrace? stackTrace;

  LogEntry({
    required this.timestamp,
    required this.level,
    required this.tag,
    required this.message,
    this.error,
    this.stackTrace,
  });

  String get formattedTime => DateFormat('HH:mm:ss.SSS').format(timestamp);

  String get levelIcon {
    switch (level) {
      case LogLevel.debug:
        return 'D';
      case LogLevel.info:
        return 'I';
      case LogLevel.warning:
        return 'W';
      case LogLevel.error:
        return 'E';
    }
  }

  @override
  String toString() {
    final buffer = StringBuffer();
    buffer.write('[$formattedTime][$levelIcon][$tag] $message');
    if (error != null) {
      buffer.write('\nError: $error');
    }
    if (stackTrace != null) {
      buffer.write('\nStack trace:\n$stackTrace');
    }
    return buffer.toString();
  }
}

class LoggerService {
  static final LoggerService _instance = LoggerService._internal();
  factory LoggerService() => _instance;
  LoggerService._internal();

  final List<LogEntry> _logs = [];
  final int _maxLogs = 1000;
  File? _logFile;
  bool _isInitialized = false;

  List<LogEntry> get logs => List.unmodifiable(_logs);
  List<LogEntry> get recentLogs => _logs.take(100).toList();

  Future<void> initialize() async {
    if (_isInitialized) return;

    try {
      final directory = await getApplicationDocumentsDirectory();
      final logDir = Directory('${directory.path}/logs');
      if (!await logDir.exists()) {
        await logDir.create(recursive: true);
      }

      final dateStr = DateFormat('yyyy-MM-dd').format(DateTime.now());
      _logFile = File('${logDir.path}/mxui_$dateStr.log');
      _isInitialized = true;

      info('Logger', 'Logger initialized');
    } catch (e) {
      debugPrint('Failed to initialize logger: $e');
    }
  }

  void _log(LogLevel level, String tag, String message, [Object? error, StackTrace? stackTrace]) {
    final entry = LogEntry(
      timestamp: DateTime.now(),
      level: level,
      tag: tag,
      message: message,
      error: error,
      stackTrace: stackTrace,
    );

    _logs.insert(0, entry);
    if (_logs.length > _maxLogs) {
      _logs.removeLast();
    }

    if (kDebugMode) {
      debugPrint(entry.toString());
    }

    _writeToFile(entry);
  }

  Future<void> _writeToFile(LogEntry entry) async {
    if (_logFile == null) return;

    try {
      await _logFile!.writeAsString(
        '${entry.toString()}\n',
        mode: FileMode.append,
      );
    } catch (e) {
      // Silently fail file writes
    }
  }

  void debug(String tag, String message) {
    if (kDebugMode) {
      _log(LogLevel.debug, tag, message);
    }
  }

  void info(String tag, String message) {
    _log(LogLevel.info, tag, message);
  }

  void warning(String tag, String message, [Object? error]) {
    _log(LogLevel.warning, tag, message, error);
  }

  void error(String tag, String message, [Object? error, StackTrace? stackTrace]) {
    _log(LogLevel.error, tag, message, error, stackTrace);
  }

  List<LogEntry> getLogsByLevel(LogLevel level) {
    return _logs.where((log) => log.level == level).toList();
  }

  List<LogEntry> getLogsByTag(String tag) {
    return _logs.where((log) => log.tag == tag).toList();
  }

  List<LogEntry> searchLogs(String query) {
    final lowerQuery = query.toLowerCase();
    return _logs.where((log) =>
      log.message.toLowerCase().contains(lowerQuery) ||
      log.tag.toLowerCase().contains(lowerQuery)
    ).toList();
  }

  void clearLogs() {
    _logs.clear();
  }

  Future<String?> exportLogs() async {
    if (_logs.isEmpty) return null;

    try {
      final directory = await getApplicationDocumentsDirectory();
      final exportFile = File(
        '${directory.path}/mxui_logs_export_${DateTime.now().millisecondsSinceEpoch}.txt'
      );

      final buffer = StringBuffer();
      buffer.writeln('MX-UI Client Logs Export');
      buffer.writeln('Generated: ${DateTime.now().toIso8601String()}');
      buffer.writeln('Total entries: ${_logs.length}');
      buffer.writeln('=' * 50);
      buffer.writeln();

      for (final log in _logs.reversed) {
        buffer.writeln(log.toString());
        buffer.writeln();
      }

      await exportFile.writeAsString(buffer.toString());
      return exportFile.path;
    } catch (e) {
      error('Logger', 'Failed to export logs', e);
      return null;
    }
  }

  Future<void> cleanOldLogs({int daysToKeep = 7}) async {
    try {
      final directory = await getApplicationDocumentsDirectory();
      final logDir = Directory('${directory.path}/logs');

      if (!await logDir.exists()) return;

      final cutoffDate = DateTime.now().subtract(Duration(days: daysToKeep));

      await for (final file in logDir.list()) {
        if (file is File) {
          final stat = await file.stat();
          if (stat.modified.isBefore(cutoffDate)) {
            await file.delete();
            debug('Logger', 'Deleted old log file: ${file.path}');
          }
        }
      }
    } catch (e) {
      warning('Logger', 'Failed to clean old logs', e);
    }
  }
}

// Global logger instance
final logger = LoggerService();

// Convenience extension for VPN-specific logging
extension VpnLogging on LoggerService {
  void vpnConnecting(String server) {
    info('VPN', 'Connecting to $server...');
  }

  void vpnConnected(String server, int latency) {
    info('VPN', 'Connected to $server (${latency}ms)');
  }

  void vpnDisconnected(String reason) {
    info('VPN', 'Disconnected: $reason');
  }

  void vpnError(String message, [Object? error]) {
    this.error('VPN', message, error);
  }

  void networkChange(String type) {
    info('Network', 'Network changed to: $type');
  }

  void configParsed(String protocol, int serverCount) {
    debug('Config', 'Parsed $serverCount servers ($protocol)');
  }
}
