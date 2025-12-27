// MX-UI VPN Client
// services/api_service.dart - API Service

import 'dart:convert';
import 'package:dio/dio.dart';
import '../models/account.dart';
import '../core/constants.dart';

class ApiService {
  static final Dio _dio = Dio(
    BaseOptions(
      connectTimeout: AppConstants.connectionTimeout,
      receiveTimeout: AppConstants.receiveTimeout,
      headers: {
        'User-Agent': 'MX-UI-Client/1.0',
      },
    ),
  );

  // Fetch subscription info
  static Future<Account> fetchSubscription(String url) async {
    try {
      final response = await _dio.get(url);

      // Parse subscription response
      // Supports multiple formats: JSON, base64, raw links
      final data = response.data;
      final headers = response.headers;

      // Extract account info from headers
      String? userInfo = headers.value('subscription-userinfo');
      int upload = 0, download = 0, total = 0, expire = 0;

      if (userInfo != null) {
        final parts = userInfo.split(';');
        for (var part in parts) {
          final kv = part.trim().split('=');
          if (kv.length == 2) {
            switch (kv[0].trim()) {
              case 'upload':
                upload = int.tryParse(kv[1].trim()) ?? 0;
                break;
              case 'download':
                download = int.tryParse(kv[1].trim()) ?? 0;
                break;
              case 'total':
                total = int.tryParse(kv[1].trim()) ?? 0;
                break;
              case 'expire':
                expire = int.tryParse(kv[1].trim()) ?? 0;
                break;
            }
          }
        }
      }

      // Parse configs
      List<ServerConfig> servers = [];

      if (data is String) {
        // Try base64 decode
        String configData = data;
        try {
          configData = utf8.decode(base64.decode(data));
        } catch (e) {
          // Not base64, use as-is
        }

        // Parse config lines
        final lines = configData.split('\n').where((l) => l.trim().isNotEmpty);
        for (var line in lines) {
          final server = _parseConfigLine(line);
          if (server != null) {
            servers.add(server);
          }
        }
      } else if (data is Map) {
        // JSON format
        if (data['outbounds'] != null) {
          for (var outbound in data['outbounds']) {
            servers.add(ServerConfig.fromJson(outbound));
          }
        }
      }

      // Generate account ID from URL
      final accountId = url.hashCode.abs().toString();

      return Account(
        id: accountId,
        subscriptionUrl: url,
        name: headers.value('profile-title') ?? 'My Account',
        username: headers.value('profile-username'),
        status: 'active',
        dataLimit: total,
        dataUsed: upload + download,
        uploadUsed: upload,
        downloadUsed: download,
        expiryTime: expire > 0 ? DateTime.fromMillisecondsSinceEpoch(expire * 1000) : null,
        servers: servers,
        createdAt: DateTime.now(),
        lastSync: DateTime.now(),
      );
    } catch (e) {
      throw Exception('Failed to fetch subscription: $e');
    }
  }

  static ServerConfig? _parseConfigLine(String line) {
    try {
      if (line.startsWith('vmess://')) {
        return _parseVmess(line);
      } else if (line.startsWith('vless://')) {
        return _parseVless(line);
      } else if (line.startsWith('trojan://')) {
        return _parseTrojan(line);
      } else if (line.startsWith('ss://')) {
        return _parseShadowsocks(line);
      } else if (line.startsWith('hysteria2://') || line.startsWith('hy2://')) {
        return _parseHysteria2(line);
      }
    } catch (e) {
      // Invalid config line
    }
    return null;
  }

  static ServerConfig _parseVmess(String link) {
    final base64Part = link.substring(8);
    final jsonStr = utf8.decode(base64.decode(base64Part));
    final json = jsonDecode(jsonStr);

    return ServerConfig(
      id: json['id'] ?? '',
      name: json['ps'] ?? 'VMess',
      address: json['add'] ?? '',
      port: int.tryParse(json['port']?.toString() ?? '443') ?? 443,
      protocol: 'vmess',
      transport: json['net'] ?? 'tcp',
      security: json['tls'] ?? 'none',
      settings: {
        'uuid': json['id'],
        'alterId': json['aid'] ?? 0,
        'host': json['host'],
        'path': json['path'],
        'sni': json['sni'],
      },
    );
  }

  static ServerConfig _parseVless(String link) {
    final uri = Uri.parse(link);
    final params = uri.queryParameters;

    return ServerConfig(
      id: uri.userInfo,
      name: Uri.decodeComponent(uri.fragment.isNotEmpty ? uri.fragment : 'VLESS'),
      address: uri.host,
      port: uri.port,
      protocol: 'vless',
      transport: params['type'] ?? 'tcp',
      security: params['security'] ?? 'tls',
      settings: {
        'uuid': uri.userInfo,
        'flow': params['flow'],
        'sni': params['sni'],
        'fp': params['fp'],
        'pbk': params['pbk'],
        'sid': params['sid'],
        'path': params['path'],
        'host': params['host'],
      },
    );
  }

  static ServerConfig _parseTrojan(String link) {
    final uri = Uri.parse(link);
    final params = uri.queryParameters;

    return ServerConfig(
      id: uri.userInfo,
      name: Uri.decodeComponent(uri.fragment.isNotEmpty ? uri.fragment : 'Trojan'),
      address: uri.host,
      port: uri.port,
      protocol: 'trojan',
      transport: params['type'] ?? 'tcp',
      security: 'tls',
      settings: {
        'password': uri.userInfo,
        'sni': params['sni'],
        'fp': params['fp'],
        'path': params['path'],
      },
    );
  }

  static ServerConfig _parseShadowsocks(String link) {
    // ss://base64@host:port#name
    final uri = Uri.parse(link);
    String method = '', password = '';

    try {
      final decoded = utf8.decode(base64.decode(uri.userInfo));
      final parts = decoded.split(':');
      if (parts.length == 2) {
        method = parts[0];
        password = parts[1];
      }
    } catch (e) {
      // Try direct parse
      final parts = uri.userInfo.split(':');
      if (parts.length == 2) {
        method = parts[0];
        password = parts[1];
      }
    }

    return ServerConfig(
      id: password.hashCode.abs().toString(),
      name: Uri.decodeComponent(uri.fragment.isNotEmpty ? uri.fragment : 'Shadowsocks'),
      address: uri.host,
      port: uri.port,
      protocol: 'shadowsocks',
      transport: 'tcp',
      security: 'none',
      settings: {
        'method': method,
        'password': password,
      },
    );
  }

  static ServerConfig _parseHysteria2(String link) {
    final uri = Uri.parse(link.replaceFirst('hy2://', 'https://').replaceFirst('hysteria2://', 'https://'));
    final params = uri.queryParameters;

    return ServerConfig(
      id: uri.userInfo,
      name: Uri.decodeComponent(uri.fragment.isNotEmpty ? uri.fragment : 'Hysteria2'),
      address: uri.host,
      port: uri.port,
      protocol: 'hysteria2',
      transport: 'udp',
      security: 'tls',
      settings: {
        'password': uri.userInfo,
        'sni': params['sni'],
        'obfs': params['obfs'],
        'obfs-password': params['obfs-password'],
      },
    );
  }

  // Test server latency
  static Future<int> testLatency(ServerConfig server) async {
    try {
      final stopwatch = Stopwatch()..start();
      await _dio.head(
        'https://${server.address}:${server.port}',
        options: Options(
          receiveTimeout: const Duration(seconds: 5),
        ),
      );
      stopwatch.stop();
      return stopwatch.elapsedMilliseconds;
    } catch (e) {
      return -1;
    }
  }

  // Register WARP
  static Future<Map<String, dynamic>> registerWarp(String? license) async {
    // WARP registration logic
    // This would interact with Cloudflare WARP API
    try {
      // Simulated WARP config
      return {
        'private_key': 'generated_private_key',
        'public_key': 'cloudflare_public_key',
        'endpoint': '162.159.192.1:2408',
        'address_ipv4': '172.16.0.2/32',
        'address_ipv6': '2606:4700:110:8a36:df92:102a:9602:fa18/128',
        'reserved': [0, 0, 0],
        'license': license,
      };
    } catch (e) {
      throw Exception('Failed to register WARP: $e');
    }
  }
}
