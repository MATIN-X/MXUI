import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../models/server.dart';
import '../providers/vpn_provider.dart';
import '../widgets/server_card.dart';

class ServersScreen extends ConsumerStatefulWidget {
  const ServersScreen({super.key});

  @override
  ConsumerState<ServersScreen> createState() => _ServersScreenState();
}

class _ServersScreenState extends ConsumerState<ServersScreen> {
  List<Server> _servers = [];
  bool _isLoading = true;
  String? _selectedServerId;
  bool _isPinging = false;

  @override
  void initState() {
    super.initState();
    _loadServers();
  }

  Future<void> _loadServers() async {
    setState(() => _isLoading = true);
    try {
      final vpnService = ref.read(vpnServiceProvider);
      final servers = await vpnService.getServers();
      setState(() {
        _servers = servers;
        _isLoading = false;
      });
    } catch (e) {
      setState(() => _isLoading = false);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error loading servers: $e')),
        );
      }
    }
  }

  Future<void> _pingAllServers() async {
    if (_isPinging) return;
    setState(() => _isPinging = true);

    try {
      final vpnService = ref.read(vpnServiceProvider);
      final updatedServers = <Server>[];

      for (final server in _servers) {
        final ping = await vpnService.pingServer(server);
        updatedServers.add(server.copyWith(ping: ping));
      }

      updatedServers.sort((a, b) {
        if (a.ping == null) return 1;
        if (b.ping == null) return -1;
        return a.ping!.compareTo(b.ping!);
      });

      setState(() {
        _servers = updatedServers;
        _isPinging = false;
      });
    } catch (e) {
      setState(() => _isPinging = false);
    }
  }

  void _selectServer(Server server) {
    setState(() => _selectedServerId = server.id);
    Navigator.pop(context, server);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Select Server'),
        actions: [
          if (_isPinging)
            const Padding(
              padding: EdgeInsets.all(16),
              child: SizedBox(
                width: 20,
                height: 20,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
            )
          else
            IconButton(
              icon: const Icon(Icons.speed),
              onPressed: _pingAllServers,
              tooltip: 'Test All',
            ),
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _loadServers,
            tooltip: 'Refresh',
          ),
          IconButton(
            icon: const Icon(Icons.qr_code_scanner),
            onPressed: () => Navigator.pushNamed(context, '/qr-scanner'),
            tooltip: 'Scan QR',
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : _servers.isEmpty
              ? _buildEmptyState()
              : _buildServerList(),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.dns_outlined,
            size: 64,
            color: Theme.of(context).colorScheme.outline,
          ),
          const SizedBox(height: 16),
          Text(
            'No servers available',
            style: Theme.of(context).textTheme.titleMedium,
          ),
          const SizedBox(height: 8),
          Text(
            'Add a subscription to get servers',
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
              color: Theme.of(context).colorScheme.outline,
            ),
          ),
          const SizedBox(height: 24),
          FilledButton.icon(
            onPressed: () => Navigator.pushNamed(context, '/subscription'),
            icon: const Icon(Icons.add),
            label: const Text('Add Subscription'),
          ),
        ],
      ),
    );
  }

  Widget _buildServerList() {
    final groupedServers = _groupServersByLocation(_servers);

    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: groupedServers.length,
      itemBuilder: (context, index) {
        final entry = groupedServers.entries.elementAt(index);
        return _buildLocationGroup(entry.key, entry.value);
      },
    );
  }

  Map<String, List<Server>> _groupServersByLocation(List<Server> servers) {
    final grouped = <String, List<Server>>{};

    // Auto Select first
    final autoServers = servers.where((s) => s.protocol == 'auto').toList();
    if (autoServers.isNotEmpty) {
      grouped['Recommended'] = autoServers;
    }

    // Group rest by country
    for (final server in servers.where((s) => s.protocol != 'auto')) {
      final key = server.countryCode ?? server.location;
      grouped.putIfAbsent(key, () => []).add(server);
    }

    return grouped;
  }

  Widget _buildLocationGroup(String location, List<Server> servers) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 8),
          child: Row(
            children: [
              if (servers.isNotEmpty && servers.first.countryCode != null)
                Text(
                  servers.first.countryEmoji,
                  style: const TextStyle(fontSize: 20),
                ),
              const SizedBox(width: 8),
              Text(
                location,
                style: Theme.of(context).textTheme.titleSmall?.copyWith(
                  fontWeight: FontWeight.w600,
                  color: Theme.of(context).colorScheme.primary,
                ),
              ),
              const SizedBox(width: 8),
              Text(
                '(${servers.length})',
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: Theme.of(context).colorScheme.outline,
                ),
              ),
            ],
          ),
        ),
        ...servers.map((server) => Padding(
          padding: const EdgeInsets.only(bottom: 8),
          child: ServerCard(
            name: server.name,
            location: server.location,
            ping: server.displayPing,
            protocol: server.protocol.toUpperCase(),
            isSelected: server.id == _selectedServerId,
            isOnline: server.isOnline,
            onTap: () => _selectServer(server),
          ),
        )),
        const SizedBox(height: 8),
      ],
    );
  }
}
