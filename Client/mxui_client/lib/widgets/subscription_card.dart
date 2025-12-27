import 'package:flutter/material.dart';
import '../config/theme.dart';
import '../models/subscription.dart';
import '../services/vpn_service.dart';
import 'glass_card.dart';

class SubscriptionCard extends StatelessWidget {
  final Subscription subscription;
  final VoidCallback? onTap;
  final VoidCallback? onDelete;

  const SubscriptionCard({
    super.key,
    required this.subscription,
    this.onTap,
    this.onDelete,
  });

  @override
  Widget build(BuildContext context) {
    final vpnService = VpnService();
    
    return GlassCard(
      onTap: onTap,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      subscription.name,
                      style: const TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 8,
                        vertical: 4,
                      ),
                      decoration: BoxDecoration(
                        color: AppTheme.primaryAccent.withOpacity(0.2),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Text(
                        subscription.protocol,
                        style: const TextStyle(
                          fontSize: 12,
                          color: AppTheme.primaryAccent,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: subscription.isActive
                          ? AppTheme.successColor.withOpacity(0.2)
                          : AppTheme.errorColor.withOpacity(0.2),
                      shape: BoxShape.circle,
                    ),
                    child: Icon(
                      subscription.isActive ? Icons.check : Icons.close,
                      size: 16,
                      color: subscription.isActive
                          ? AppTheme.successColor
                          : AppTheme.errorColor,
                    ),
                  ),
                  if (onDelete != null) ...[
                    const SizedBox(width: 8),
                    IconButton(
                      icon: const Icon(Icons.delete_outline, color: AppTheme.errorColor),
                      onPressed: onDelete,
                    ),
                  ],
                ],
              ),
            ],
          ),
          const SizedBox(height: 16),
          
          // Traffic
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                'Traffic',
                style: TextStyle(
                  color: Colors.white.withOpacity(0.7),
                ),
              ),
              Text(
                '${vpnService.formatBytes(subscription.usedTraffic)} / ${vpnService.formatBytes(subscription.totalTraffic)}',
                style: const TextStyle(fontWeight: FontWeight.w600),
              ),
            ],
          ),
          const SizedBox(height: 8),
          ClipRRect(
            borderRadius: BorderRadius.circular(8),
            child: LinearProgressIndicator(
              value: subscription.trafficUsagePercent / 100,
              minHeight: 8,
              backgroundColor: AppTheme.secondaryGlass,
              valueColor: AlwaysStoppedAnimation<Color>(
                subscription.trafficUsagePercent > 90
                    ? AppTheme.errorColor
                    : subscription.trafficUsagePercent > 70
                        ? AppTheme.warningColor
                        : AppTheme.successColor,
              ),
            ),
          ),
          const SizedBox(height: 16),
          
          // Expiry
          if (subscription.expiryDate != null)
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  'Expires in',
                  style: TextStyle(
                    color: Colors.white.withOpacity(0.7),
                  ),
                ),
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 8,
                    vertical: 4,
                  ),
                  decoration: BoxDecoration(
                    color: subscription.isExpired
                        ? AppTheme.errorColor.withOpacity(0.2)
                        : (subscription.daysRemaining! < 7
                            ? AppTheme.warningColor.withOpacity(0.2)
                            : AppTheme.successColor.withOpacity(0.2)),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Text(
                    subscription.isExpired
                        ? 'Expired'
                        : '${subscription.daysRemaining} days',
                    style: TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w600,
                      color: subscription.isExpired
                          ? AppTheme.errorColor
                          : (subscription.daysRemaining! < 7
                              ? AppTheme.warningColor
                              : AppTheme.successColor),
                    ),
                  ),
                ),
              ],
            ),
        ],
      ),
    );
  }
}
