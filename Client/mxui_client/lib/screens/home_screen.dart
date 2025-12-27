import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../widgets/connection_button.dart';
import '../widgets/server_card.dart';
import '../widgets/stats_card.dart';

class HomeScreen extends ConsumerStatefulWidget {
  const HomeScreen({super.key});

  @override
  ConsumerState<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends ConsumerState<HomeScreen> {
  int _currentIndex = 0;
  bool _isConnected = false;
  String _selectedServer = 'Auto Select';
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: IndexedStack(
          index: _currentIndex,
          children: [
            _buildHomePage(),
            _buildServersPage(),
            _buildSettingsPage(),
          ],
        ),
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _currentIndex,
        onDestinationSelected: (index) {
          setState(() => _currentIndex = index);
        },
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.home_outlined),
            selectedIcon: Icon(Icons.home),
            label: 'Home',
          ),
          NavigationDestination(
            icon: Icon(Icons.dns_outlined),
            selectedIcon: Icon(Icons.dns),
            label: 'Servers',
          ),
          NavigationDestination(
            icon: Icon(Icons.settings_outlined),
            selectedIcon: Icon(Icons.settings),
            label: 'Settings',
          ),
        ],
      ),
    );
  }

  Widget _buildHomePage() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'MXUI',
                    style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  Text(
                    _isConnected ? 'Connected' : 'Not Connected',
                    style: TextStyle(
                      color: _isConnected ? Colors.green : Colors.grey,
                    ),
                  ),
                ],
              ),
              IconButton(
                onPressed: () => Navigator.pushNamed(context, '/subscription'),
                icon: const Icon(Icons.add_circle_outline),
                tooltip: 'Add Subscription',
              ),
            ],
          ),
          
          const SizedBox(height: 40),
          
          // Connection Button
          Center(
            child: ConnectionButton(
              isConnected: _isConnected,
              onPressed: () {
                setState(() => _isConnected = !_isConnected);
              },
            ),
          ),
          
          const SizedBox(height: 40),
          
          // Current Server Card
          GestureDetector(
            onTap: () => setState(() => _currentIndex = 1),
            child: Card(
              child: ListTile(
                leading: Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.primary.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Icon(
                    Icons.public,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                ),
                title: Text(_selectedServer),
                subtitle: const Text('Tap to change server'),
                trailing: const Icon(Icons.chevron_right),
              ),
            ),
          ),
          
          const SizedBox(height: 24),
          
          // Stats
          if (_isConnected) ...[
            Text(
              'Connection Stats',
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                fontWeight: FontWeight.w600,
              ),
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: StatsCard(
                    icon: Icons.arrow_downward,
                    label: 'Download',
                    value: '125.4 MB',
                    color: Colors.green,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: StatsCard(
                    icon: Icons.arrow_upward,
                    label: 'Upload',
                    value: '45.2 MB',
                    color: Colors.blue,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: StatsCard(
                    icon: Icons.timer,
                    label: 'Duration',
                    value: '01:24:35',
                    color: Colors.orange,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: StatsCard(
                    icon: Icons.speed,
                    label: 'Speed',
                    value: '24.5 Mbps',
                    color: Colors.purple,
                  ),
                ),
              ],
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildServersPage() {
    return const ServersPageContent();
  }

  Widget _buildSettingsPage() {
    return const SettingsPageContent();
  }
}

class ServersPageContent extends StatelessWidget {
  const ServersPageContent({super.key});

  @override
  Widget build(BuildContext context) {
    final servers = [
      {'name': 'Auto Select', 'location': 'Best Available', 'ping': '—'},
      {'name': 'Germany #1', 'location': 'Frankfurt', 'ping': '45ms'},
      {'name': 'Netherlands #1', 'location': 'Amsterdam', 'ping': '52ms'},
      {'name': 'USA #1', 'location': 'New York', 'ping': '120ms'},
      {'name': 'Japan #1', 'location': 'Tokyo', 'ping': '180ms'},
    ];

    return Scaffold(
      appBar: AppBar(
        title: const Text('Servers'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: () {},
            tooltip: 'Refresh',
          ),
          IconButton(
            icon: const Icon(Icons.qr_code_scanner),
            onPressed: () => Navigator.pushNamed(context, '/qr-scanner'),
            tooltip: 'Scan QR',
          ),
        ],
      ),
      body: ListView.builder(
        padding: const EdgeInsets.all(16),
        itemCount: servers.length,
        itemBuilder: (context, index) {
          final server = servers[index];
          return ServerCard(
            name: server['name']!,
            location: server['location']!,
            ping: server['ping']!,
            isSelected: index == 0,
            onTap: () {},
          );
        },
      ),
    );
  }
}

class SettingsPageContent extends StatelessWidget {
  const SettingsPageContent({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _buildSection(
            context,
            'General',
            [
              _buildSettingsTile(
                Icons.language,
                'Language',
                'English',
                onTap: () {},
              ),
              _buildSettingsTile(
                Icons.dark_mode,
                'Theme',
                'System',
                onTap: () {},
              ),
            ],
          ),
          const SizedBox(height: 16),
          _buildSection(
            context,
            'VPN',
            [
              _buildSwitchTile(
                Icons.play_arrow,
                'Auto Connect',
                'Connect on app start',
                true,
                (value) {},
              ),
              _buildSwitchTile(
                Icons.block,
                'Kill Switch',
                'Block internet if VPN disconnects',
                false,
                (value) {},
              ),
              _buildSettingsTile(
                Icons.dns,
                'DNS',
                'System DNS',
                onTap: () {},
              ),
            ],
          ),
          const SizedBox(height: 16),
          _buildSection(
            context,
            'Subscription',
            [
              _buildSettingsTile(
                Icons.link,
                'Manage Subscriptions',
                '',
                onTap: () => Navigator.pushNamed(context, '/subscription'),
              ),
              _buildSettingsTile(
                Icons.qr_code,
                'Scan QR Code',
                '',
                onTap: () => Navigator.pushNamed(context, '/qr-scanner'),
              ),
            ],
          ),
          const SizedBox(height: 16),
          _buildSection(
            context,
            'About',
            [
              _buildSettingsTile(
                Icons.info,
                'Version',
                '1.0.0',
                onTap: () {},
              ),
              _buildSettingsTile(
                Icons.policy,
                'Privacy Policy',
                '',
                onTap: () {},
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildSection(BuildContext context, String title, List<Widget> children) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 8),
          child: Text(
            title,
            style: Theme.of(context).textTheme.titleSmall?.copyWith(
              color: Theme.of(context).colorScheme.primary,
              fontWeight: FontWeight.w600,
            ),
          ),
        ),
        Card(
          child: Column(children: children),
        ),
      ],
    );
  }

  Widget _buildSettingsTile(
    IconData icon,
    String title,
    String subtitle, {
    VoidCallback? onTap,
  }) {
    return ListTile(
      leading: Icon(icon),
      title: Text(title),
      subtitle: subtitle.isNotEmpty ? Text(subtitle) : null,
      trailing: const Icon(Icons.chevron_right),
      onTap: onTap,
    );
  }

  Widget _buildSwitchTile(
    IconData icon,
    String title,
    String subtitle,
    bool value,
    ValueChanged<bool> onChanged,
  ) {
    return SwitchListTile(
      secondary: Icon(icon),
      title: Text(title),
      subtitle: Text(subtitle),
      value: value,
      onChanged: onChanged,
    );
  }
}
