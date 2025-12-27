import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:hive_flutter/hive_flutter.dart';

import 'config/app_config.dart';
import 'config/theme.dart';
import 'screens/splash_screen.dart';
import 'screens/home_screen.dart';
import 'screens/login_screen.dart';
import 'screens/servers_screen.dart';
import 'screens/settings_screen.dart';
import 'screens/subscription_screen.dart';
import 'screens/qr_scanner_screen.dart';
import 'services/storage_service.dart';
import 'services/logger_service.dart';
import 'services/dns_service.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Initialize services
  await _initializeServices();

  // Set preferred orientations
  await SystemChrome.setPreferredOrientations([
    DeviceOrientation.portraitUp,
    DeviceOrientation.portraitDown,
  ]);

  // Set system UI style
  SystemChrome.setSystemUIOverlayStyle(
    const SystemUiOverlayStyle(
      statusBarColor: Colors.transparent,
      statusBarIconBrightness: Brightness.dark,
    ),
  );

  runApp(const ProviderScope(child: MXUIApp()));
}

Future<void> _initializeServices() async {
  // Initialize logger first
  await logger.initialize();
  logger.info('App', 'Starting MXUI Client v${AppConfig.appVersion}');

  // Initialize Hive for local storage
  await Hive.initFlutter();
  await Hive.openBox('settings');
  await Hive.openBox('servers');
  await Hive.openBox('subscriptions');

  // Initialize storage service
  await storage.initialize();

  // Initialize DNS service
  await dnsService.initialize();

  // Clean old logs
  await logger.cleanOldLogs();

  logger.info('App', 'All services initialized');
}

class MXUIApp extends ConsumerWidget {
  const MXUIApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final themeMode = ref.watch(themeModeProvider);
    
    return MaterialApp(
      title: AppConfig.appName,
      debugShowCheckedModeBanner: false,
      
      // Theme
      theme: AppTheme.lightTheme,
      darkTheme: AppTheme.darkTheme,
      themeMode: themeMode,
      
      // Routes
      initialRoute: '/',
      routes: {
        '/': (context) => const SplashScreen(),
        '/login': (context) => const LoginScreen(),
        '/home': (context) => const HomeScreen(),
        '/servers': (context) => const ServersScreen(),
        '/subscription': (context) => const SubscriptionScreen(),
        '/settings': (context) => const SettingsScreen(),
        '/qr-scanner': (context) => const QRScannerScreen(),
      },
    );
  }
}

// Theme mode provider
final themeModeProvider = StateNotifierProvider<ThemeModeNotifier, ThemeMode>((ref) {
  return ThemeModeNotifier();
});

class ThemeModeNotifier extends StateNotifier<ThemeMode> {
  ThemeModeNotifier() : super(ThemeMode.system) {
    _loadTheme();
  }
  
  Future<void> _loadTheme() async {
    final box = Hive.box('settings');
    final savedTheme = box.get('themeMode', defaultValue: 'system');
    state = ThemeMode.values.firstWhere(
      (e) => e.name == savedTheme,
      orElse: () => ThemeMode.system,
    );
  }
  
  Future<void> setTheme(ThemeMode mode) async {
    final box = Hive.box('settings');
    await box.put('themeMode', mode.name);
    state = mode;
  }
}
