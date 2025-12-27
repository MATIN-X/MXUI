import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

class SubscriptionScreen extends ConsumerStatefulWidget {
  const SubscriptionScreen({super.key});

  @override
  ConsumerState<SubscriptionScreen> createState() => _SubscriptionScreenState();
}

class _SubscriptionScreenState extends ConsumerState<SubscriptionScreen> {
  final _urlController = TextEditingController();
  final _nameController = TextEditingController();
  final _formKey = GlobalKey<FormState>();
  bool _isLoading = false;

  final List<Map<String, dynamic>> _subscriptions = [
    {
      'id': '1',
      'name': 'Main Server',
      'url': 'https://example.com/sub/abc123',
      'lastUpdate': DateTime.now().subtract(const Duration(hours: 2)),
      'serverCount': 5,
      'isActive': true,
    },
  ];

  @override
  void dispose() {
    _urlController.dispose();
    _nameController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Subscriptions'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _refreshAllSubscriptions,
            tooltip: 'Refresh All',
          ),
        ],
      ),
      body: Column(
        children: [
          Expanded(
            child: _subscriptions.isEmpty
                ? _buildEmptyState()
                : ListView.builder(
                    padding: const EdgeInsets.all(16),
                    itemCount: _subscriptions.length,
                    itemBuilder: (context, index) {
                      return _buildSubscriptionCard(_subscriptions[index]);
                    },
                  ),
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _showAddSubscriptionDialog,
        icon: const Icon(Icons.add),
        label: const Text('Add'),
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.link_off,
            size: 80,
            color: Theme.of(context).colorScheme.onSurface.withOpacity(0.3),
          ),
          const SizedBox(height: 16),
          Text(
            'No Subscriptions',
            style: Theme.of(context).textTheme.headlineSmall,
          ),
          const SizedBox(height: 8),
          Text(
            'Add a subscription URL or scan QR code',
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
              color: Theme.of(context).colorScheme.onSurface.withOpacity(0.6),
            ),
          ),
          const SizedBox(height: 24),
          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              OutlinedButton.icon(
                onPressed: () => Navigator.pushNamed(context, '/qr-scanner'),
                icon: const Icon(Icons.qr_code_scanner),
                label: const Text('Scan QR'),
              ),
              const SizedBox(width: 16),
              FilledButton.icon(
                onPressed: _showAddSubscriptionDialog,
                icon: const Icon(Icons.add_link),
                label: const Text('Add URL'),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildSubscriptionCard(Map<String, dynamic> subscription) {
    final theme = Theme.of(context);
    final lastUpdate = subscription['lastUpdate'] as DateTime;
    final timeDiff = DateTime.now().difference(lastUpdate);

    String timeAgo;
    if (timeDiff.inMinutes < 60) {
      timeAgo = '${timeDiff.inMinutes} minutes ago';
    } else if (timeDiff.inHours < 24) {
      timeAgo = '${timeDiff.inHours} hours ago';
    } else {
      timeAgo = '${timeDiff.inDays} days ago';
    }

    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: ExpansionTile(
        leading: Container(
          width: 48,
          height: 48,
          decoration: BoxDecoration(
            color: theme.colorScheme.primary.withOpacity(0.1),
            borderRadius: BorderRadius.circular(12),
          ),
          child: Icon(
            Icons.cloud_done,
            color: theme.colorScheme.primary,
          ),
        ),
        title: Text(
          subscription['name'],
          style: const TextStyle(fontWeight: FontWeight.w600),
        ),
        subtitle: Text('${subscription['serverCount']} servers • Updated $timeAgo'),
        trailing: Switch(
          value: subscription['isActive'],
          onChanged: (value) {
            setState(() {
              subscription['isActive'] = value;
            });
          },
        ),
        children: [
          Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // URL Display
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: theme.colorScheme.surfaceContainerHighest,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Row(
                    children: [
                      Expanded(
                        child: Text(
                          subscription['url'],
                          style: theme.textTheme.bodySmall?.copyWith(
                            fontFamily: 'monospace',
                          ),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      IconButton(
                        icon: const Icon(Icons.copy, size: 20),
                        onPressed: () {
                          Clipboard.setData(
                            ClipboardData(text: subscription['url']),
                          );
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(
                              content: Text('URL copied to clipboard'),
                              duration: Duration(seconds: 2),
                            ),
                          );
                        },
                        tooltip: 'Copy URL',
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 16),
                // Action Buttons
                Row(
                  children: [
                    Expanded(
                      child: OutlinedButton.icon(
                        onPressed: () => _updateSubscription(subscription['id']),
                        icon: const Icon(Icons.refresh, size: 18),
                        label: const Text('Update'),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: OutlinedButton.icon(
                        onPressed: () => _editSubscription(subscription),
                        icon: const Icon(Icons.edit, size: 18),
                        label: const Text('Edit'),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: OutlinedButton.icon(
                        onPressed: () => _deleteSubscription(subscription['id']),
                        icon: Icon(Icons.delete, size: 18, color: theme.colorScheme.error),
                        label: Text(
                          'Delete',
                          style: TextStyle(color: theme.colorScheme.error),
                        ),
                        style: OutlinedButton.styleFrom(
                          side: BorderSide(color: theme.colorScheme.error),
                        ),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  void _showAddSubscriptionDialog() {
    _urlController.clear();
    _nameController.clear();

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (context) => Padding(
        padding: EdgeInsets.only(
          bottom: MediaQuery.of(context).viewInsets.bottom,
        ),
        child: Container(
          padding: const EdgeInsets.all(24),
          child: Form(
            key: _formKey,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(
                      'Add Subscription',
                      style: Theme.of(context).textTheme.titleLarge,
                    ),
                    IconButton(
                      icon: const Icon(Icons.close),
                      onPressed: () => Navigator.pop(context),
                    ),
                  ],
                ),
                const SizedBox(height: 24),
                TextFormField(
                  controller: _nameController,
                  decoration: const InputDecoration(
                    labelText: 'Name',
                    hintText: 'My Subscription',
                    prefixIcon: Icon(Icons.label_outline),
                    border: OutlineInputBorder(),
                  ),
                  validator: (value) {
                    if (value == null || value.isEmpty) {
                      return 'Please enter a name';
                    }
                    return null;
                  },
                ),
                const SizedBox(height: 16),
                TextFormField(
                  controller: _urlController,
                  decoration: InputDecoration(
                    labelText: 'Subscription URL',
                    hintText: 'https://...',
                    prefixIcon: const Icon(Icons.link),
                    border: const OutlineInputBorder(),
                    suffixIcon: IconButton(
                      icon: const Icon(Icons.paste),
                      onPressed: () async {
                        final data = await Clipboard.getData('text/plain');
                        if (data?.text != null) {
                          _urlController.text = data!.text!;
                        }
                      },
                      tooltip: 'Paste',
                    ),
                  ),
                  keyboardType: TextInputType.url,
                  validator: (value) {
                    if (value == null || value.isEmpty) {
                      return 'Please enter a URL';
                    }
                    // جایگزین خط 315 و 316
final uri = Uri.tryParse(value);
if (uri == null || !uri.isAbsolute) {
  return 'Please enter a valid URL';
}

                  }
                    return null;
                  },
                ),
                const SizedBox(height: 8),
                TextButton.icon(
                  onPressed: () {
                    Navigator.pop(context);
                    Navigator.pushNamed(context, '/qr-scanner');
                  },
                  icon: const Icon(Icons.qr_code_scanner),
                  label: const Text('Or scan QR code'),
                ),
                const SizedBox(height: 24),
                FilledButton(
                  onPressed: _isLoading ? null : _addSubscription,
                  child: _isLoading
                      ? const SizedBox(
                          height: 20,
                          width: 20,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Text('Add Subscription'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Future<void> _addSubscription() async {
    if (!_formKey.currentState!.validate()) return;

    setState(() => _isLoading = true);

    // Simulate network request
    await Future.delayed(const Duration(seconds: 1));

    setState(() {
      _subscriptions.add({
        'id': DateTime.now().millisecondsSinceEpoch.toString(),
        'name': _nameController.text,
        'url': _urlController.text,
        'lastUpdate': DateTime.now(),
        'serverCount': 0,
        'isActive': true,
      });
      _isLoading = false;
    });

    if (mounted) {
      Navigator.pop(context);
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Subscription added successfully')),
      );
    }
  }

  Future<void> _updateSubscription(String id) async {
    // TODO: Implement subscription update
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Updating subscription...')),
    );
  }

  void _editSubscription(Map<String, dynamic> subscription) {
    _nameController.text = subscription['name'];
    _urlController.text = subscription['url'];
    _showAddSubscriptionDialog();
  }

  void _deleteSubscription(String id) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Delete Subscription'),
        content: const Text('Are you sure you want to delete this subscription?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () {
              setState(() {
                _subscriptions.removeWhere((s) => s['id'] == id);
              });
              Navigator.pop(context);
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Subscription deleted')),
              );
            },
            style: FilledButton.styleFrom(
              backgroundColor: Theme.of(context).colorScheme.error,
            ),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
  }

  void _refreshAllSubscriptions() {
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Refreshing all subscriptions...')),
    );
  }
}
