import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../config/app_config.dart';
import '../config/theme.dart';
import '../providers/auth_provider.dart';
import '../widgets/glass_card.dart';
import 'login_screen.dart';

class SettingsScreen extends ConsumerWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final authState = ref.watch(authStateProvider);

    return CustomScrollView(
      slivers: [
        const SliverAppBar(
          floating: true,
          backgroundColor: Colors.transparent,
          title: Text('Settings'),
        ),
        SliverPadding(
          padding: const EdgeInsets.all(16),
          sliver: SliverList(
            delegate: SliverChildListDelegate([
              // Account
              GlassCard(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Account',
                      style: TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 16),
                    ListTile(
                      leading: const Icon(Icons.person_outline),
                      title: Text(authState.username ?? 'Guest'),
                      subtitle: const Text('Username'),
                      contentPadding: EdgeInsets.zero,
                    ),
                    const Divider(),
                    ListTile(
                      leading: const Icon(Icons.logout, color: AppTheme.errorColor),
                      title: const Text(
                        'Logout',
                        style: TextStyle(color: AppTheme.errorColor),
                      ),
                      contentPadding: EdgeInsets.zero,
                      onTap: () async {
                        await ref.read(authStateProvider.notifier).logout();
                        if (context.mounted) {
                          Navigator.of(context).pushReplacement(
                            MaterialPageRoute(builder: (_) => const LoginScreen()),
                          );
                        }
                      },
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              
              // Connection
              GlassCard(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Connection',
                      style: TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 16),
                    ListTile(
                      leading: const Icon(Icons.dns_outlined),
                      title: const Text('DNS Server'),
                      subtitle: const Text('1.1.1.1'),
                      contentPadding: EdgeInsets.zero,
                      onTap: () {
                        // TODO: Implement DNS settings
                      },
                    ),
                    const Divider(),
                    ListTile(
                      leading: const Icon(Icons.speed_outlined),
                      title: const Text('Connection Timeout'),
                      subtitle: Text('${AppConfig.connectionTimeout ~/ 1000}s'),
                      contentPadding: EdgeInsets.zero,
                      onTap: () {
                        // TODO: Implement timeout settings
                      },
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              
              // Advanced
              GlassCard(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Advanced',
                      style: TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 16),
                    SwitchListTile(
                      secondary: const Icon(Icons.bug_report_outlined),
                      title: const Text('Enable Logs'),
                      value: AppConfig.enableLogs,
                      contentPadding: EdgeInsets.zero,
                      onChanged: (value) {
                        // TODO: Implement log toggle
                      },
                    ),
                    const Divider(),
                    ListTile(
                      leading: const Icon(Icons.delete_outline, color: AppTheme.errorColor),
                      title: const Text(
                        'Clear Cache',
                        style: TextStyle(color: AppTheme.errorColor),
                      ),
                      contentPadding: EdgeInsets.zero,
                      onTap: () {
                        // TODO: Implement clear cache
                      },
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              
              // About
              GlassCard(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'About',
                      style: TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 16),
                    ListTile(
                      leading: const Icon(Icons.info_outline),
                      title: const Text('Version'),
                      subtitle: Text(AppConfig.appVersion),
                      contentPadding: EdgeInsets.zero,
                    ),
                    const Divider(),
                    ListTile(
                      leading: const Icon(Icons.description_outlined),
                      title: const Text('Licenses'),
                      contentPadding: EdgeInsets.zero,
                      onTap: () {
                        showLicensePage(context: context);
                      },
                    ),
                  ],
                ),
              ),
            ]),
          ),
        ),
      ],
    );
  }
}
