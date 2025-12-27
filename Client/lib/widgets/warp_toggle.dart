// MXUI VPN Client
// widgets/warp_toggle.dart - WARP Proxy Toggle (Hiddify Style)

import 'package:flutter/material.dart';
import '../core/theme.dart';
import '../core/constants.dart';

class WarpToggle extends StatelessWidget {
  final bool isEnabled;
  final bool isConnected;
  final VoidCallback onToggle;
  final bool isDark;

  const WarpToggle({
    super.key,
    required this.isEnabled,
    required this.isConnected,
    required this.onToggle,
    required this.isDark,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onToggle,
      child: AnimatedContainer(
        duration: AppConstants.animNormal,
        curve: Curves.easeOutCubic,
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        decoration: BoxDecoration(
          gradient: isEnabled
              ? LinearGradient(
                  colors: [
                    AppColors.warpOrange.withOpacity(0.2),
                    AppColors.warpOrange.withOpacity(0.1),
                  ],
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                )
              : null,
          color: isEnabled
              ? null
              : (isDark
                  ? Colors.white.withOpacity(0.08)
                  : Colors.black.withOpacity(0.05)),
          borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
          border: Border.all(
            color: isEnabled
                ? AppColors.warpOrange.withOpacity(0.5)
                : (isDark
                    ? Colors.white.withOpacity(0.1)
                    : Colors.black.withOpacity(0.1)),
            width: 1,
          ),
        ),
        child: Row(
          children: [
            // WARP Icon
            Container(
              width: 40,
              height: 40,
              decoration: BoxDecoration(
                color: isEnabled
                    ? AppColors.warpOrange.withOpacity(0.2)
                    : (isDark
                        ? Colors.white.withOpacity(0.1)
                        : Colors.black.withOpacity(0.1)),
                borderRadius: BorderRadius.circular(AppConstants.radiusSmall),
              ),
              child: Center(
                child: Image.network(
                  'https://1.1.1.1/media/warp-logo.svg',
                  width: 24,
                  height: 24,
                  errorBuilder: (_, __, ___) => Icon(
                    Icons.shield_rounded,
                    color: isEnabled
                        ? AppColors.warpOrange
                        : (isDark ? Colors.white54 : Colors.black38),
                    size: 24,
                  ),
                ),
              ),
            ),
            const SizedBox(width: 12),

            // Text
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'WARP پراکسی',
                    style: TextStyle(
                      color: isEnabled
                          ? AppColors.warpOrange
                          : (isDark ? Colors.white : Colors.black87),
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    isConnected
                        ? 'متصل از طریق Cloudflare'
                        : (isEnabled ? 'فعال - در انتظار اتصال' : 'غیرفعال'),
                    style: TextStyle(
                      color: isDark ? Colors.white54 : Colors.black45,
                      fontSize: 11,
                    ),
                  ),
                ],
              ),
            ),

            // Toggle Switch
            AnimatedContainer(
              duration: AppConstants.animFast,
              width: 50,
              height: 28,
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(14),
                color: isEnabled
                    ? AppColors.warpOrange
                    : (isDark
                        ? Colors.white.withOpacity(0.2)
                        : Colors.black.withOpacity(0.15)),
              ),
              child: Stack(
                children: [
                  AnimatedPositioned(
                    duration: AppConstants.animFast,
                    curve: Curves.easeOutCubic,
                    left: isEnabled ? 24 : 2,
                    top: 2,
                    child: Container(
                      width: 24,
                      height: 24,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        color: Colors.white,
                        boxShadow: [
                          BoxShadow(
                            color: Colors.black.withOpacity(0.2),
                            blurRadius: 4,
                            offset: const Offset(0, 2),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// Compact WARP indicator
class WarpIndicator extends StatelessWidget {
  final bool isEnabled;
  final bool isConnected;

  const WarpIndicator({
    super.key,
    required this.isEnabled,
    required this.isConnected,
  });

  @override
  Widget build(BuildContext context) {
    if (!isEnabled) return const SizedBox.shrink();

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: isConnected
            ? AppColors.warpOrange.withOpacity(0.2)
            : AppColors.warning.withOpacity(0.2),
        borderRadius: BorderRadius.circular(AppConstants.radiusSmall),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            Icons.shield_rounded,
            color: isConnected ? AppColors.warpOrange : AppColors.warning,
            size: 14,
          ),
          const SizedBox(width: 4),
          Text(
            'WARP',
            style: TextStyle(
              color: isConnected ? AppColors.warpOrange : AppColors.warning,
              fontSize: 11,
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ),
    );
  }
}
