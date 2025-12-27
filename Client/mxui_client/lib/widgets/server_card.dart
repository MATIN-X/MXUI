import 'package:flutter/material.dart';

class ServerCard extends StatelessWidget {
  final String name;
  final String location;
  final String ping;
  final bool isSelected;
  final VoidCallback? onTap;
  final String? protocol;
  final bool isOnline;

  const ServerCard({
    super.key,
    required this.name,
    required this.location,
    required this.ping,
    this.isSelected = false,
    this.onTap,
    this.protocol,
    this.isOnline = true,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    
    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: isSelected
            ? BorderSide(color: theme.colorScheme.primary, width: 2)
            : BorderSide.none,
      ),
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(12),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            children: [
              // Flag/Icon
              Container(
                width: 48,
                height: 48,
                decoration: BoxDecoration(
                  color: _getLocationColor().withOpacity(0.1),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Center(
                  child: Text(
                    _getCountryEmoji(),
                    style: const TextStyle(fontSize: 24),
                  ),
                ),
              ),
              
              const SizedBox(width: 16),
              
              // Server info
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: Text(
                            name,
                            style: theme.textTheme.titleMedium?.copyWith(
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                        if (isSelected)
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 8,
                              vertical: 2,
                            ),
                            decoration: BoxDecoration(
                              color: theme.colorScheme.primary,
                              borderRadius: BorderRadius.circular(12),
                            ),
                            child: const Text(
                              'Active',
                              style: TextStyle(
                                color: Colors.white,
                                fontSize: 10,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ),
                      ],
                    ),
                    const SizedBox(height: 4),
                    Row(
                      children: [
                        Icon(
                          Icons.location_on,
                          size: 14,
                          color: theme.colorScheme.onSurface.withOpacity(0.6),
                        ),
                        const SizedBox(width: 4),
                        Text(
                          location,
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSurface.withOpacity(0.6),
                          ),
                        ),
                        if (protocol != null) ...[
                          const SizedBox(width: 12),
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 6,
                              vertical: 2,
                            ),
                            decoration: BoxDecoration(
                              color: theme.colorScheme.secondaryContainer,
                              borderRadius: BorderRadius.circular(4),
                            ),
                            child: Text(
                              protocol!,
                              style: TextStyle(
                                fontSize: 10,
                                color: theme.colorScheme.onSecondaryContainer,
                              ),
                            ),
                          ),
                        ],
                      ],
                    ),
                  ],
                ),
              ),
              
              // Ping indicator
              Column(
                crossAxisAlignment: CrossAxisAlignment.end,
                children: [
                  Container(
                    width: 8,
                    height: 8,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: isOnline ? _getPingColor() : Colors.grey,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    ping,
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: _getPingColor(),
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  Color _getLocationColor() {
    final loc = location.toLowerCase();
    if (loc.contains('germany') || loc.contains('frankfurt')) return Colors.amber;
    if (loc.contains('usa') || loc.contains('york')) return Colors.blue;
    if (loc.contains('netherlands') || loc.contains('amsterdam')) return Colors.orange;
    if (loc.contains('japan') || loc.contains('tokyo')) return Colors.red;
    if (loc.contains('uk') || loc.contains('london')) return Colors.indigo;
    return Colors.grey;
  }

  String _getCountryEmoji() {
    final loc = location.toLowerCase();
    if (loc.contains('germany') || loc.contains('frankfurt')) return '🇩🇪';
    if (loc.contains('usa') || loc.contains('york') || loc.contains('america')) return '🇺🇸';
    if (loc.contains('netherlands') || loc.contains('amsterdam')) return '🇳🇱';
    if (loc.contains('japan') || loc.contains('tokyo')) return '🇯🇵';
    if (loc.contains('uk') || loc.contains('london')) return '🇬🇧';
    if (loc.contains('france') || loc.contains('paris')) return '🇫🇷';
    if (loc.contains('canada')) return '🇨🇦';
    if (loc.contains('singapore')) return '🇸🇬';
    if (loc.contains('australia')) return '🇦🇺';
    if (name.toLowerCase().contains('auto')) return '🌐';
    return '🌍';
  }

  Color _getPingColor() {
    if (ping == '—' || ping.isEmpty) return Colors.grey;
    final ms = int.tryParse(ping.replaceAll('ms', '').trim()) ?? 999;
    if (ms < 50) return Colors.green;
    if (ms < 100) return Colors.lightGreen;
    if (ms < 150) return Colors.orange;
    return Colors.red;
  }
}
