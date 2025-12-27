// MXUI VPN Client
// widgets/connection_mode_selector.dart - Connection Mode Selector

import 'package:flutter/material.dart';
import '../core/theme.dart';
import '../core/constants.dart';
import 'glass_card.dart';

class ConnectionModeSelector extends StatelessWidget {
  final String selectedMode;
  final Function(String) onModeSelected;
  final bool isDark;

  const ConnectionModeSelector({
    super.key,
    required this.selectedMode,
    required this.onModeSelected,
    required this.isDark,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 8),
          child: Text(
            'حالت اتصال',
            style: TextStyle(
              color: isDark ? Colors.white70 : Colors.black54,
              fontSize: 14,
              fontWeight: FontWeight.w500,
            ),
          ),
        ),
        SizedBox(
          height: 100,
          child: ListView.builder(
            scrollDirection: Axis.horizontal,
            itemCount: AppConstants.modes.length,
            itemBuilder: (context, index) {
              final mode = AppConstants.modes[index];
              final isSelected = mode.id == selectedMode;

              return _ModeCard(
                mode: mode,
                isSelected: isSelected,
                isDark: isDark,
                onTap: () => onModeSelected(mode.id),
              );
            },
          ),
        ),
      ],
    );
  }
}

class _ModeCard extends StatelessWidget {
  final ConnectionMode mode;
  final bool isSelected;
  final bool isDark;
  final VoidCallback onTap;

  const _ModeCard({
    required this.mode,
    required this.isSelected,
    required this.isDark,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: AnimatedContainer(
        duration: AppConstants.animNormal,
        curve: Curves.easeOutCubic,
        width: 90,
        margin: const EdgeInsets.only(left: 12),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: isSelected
              ? AppColors.primary.withOpacity(0.2)
              : (isDark
                  ? Colors.white.withOpacity(0.08)
                  : Colors.black.withOpacity(0.05)),
          borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
          border: Border.all(
            color: isSelected
                ? AppColors.primary
                : (isDark
                    ? Colors.white.withOpacity(0.1)
                    : Colors.black.withOpacity(0.1)),
            width: isSelected ? 2 : 1,
          ),
        ),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Text(
              mode.icon,
              style: const TextStyle(fontSize: 28),
            ),
            const SizedBox(height: 8),
            Text(
              mode.nameFa,
              style: TextStyle(
                color: isSelected
                    ? AppColors.primary
                    : (isDark ? Colors.white70 : Colors.black54),
                fontSize: 11,
                fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
              ),
              textAlign: TextAlign.center,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
          ],
        ),
      ),
    );
  }
}

// Grid version for settings page
class ConnectionModeGrid extends StatelessWidget {
  final String selectedMode;
  final Function(String) onModeSelected;
  final bool isDark;

  const ConnectionModeGrid({
    super.key,
    required this.selectedMode,
    required this.onModeSelected,
    required this.isDark,
  });

  @override
  Widget build(BuildContext context) {
    return GridView.builder(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 3,
        crossAxisSpacing: 12,
        mainAxisSpacing: 12,
        childAspectRatio: 1.0,
      ),
      itemCount: AppConstants.modes.length,
      itemBuilder: (context, index) {
        final mode = AppConstants.modes[index];
        final isSelected = mode.id == selectedMode;

        return GestureDetector(
          onTap: () => onModeSelected(mode.id),
          child: AnimatedContainer(
            duration: AppConstants.animNormal,
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: isSelected
                  ? AppColors.primary.withOpacity(0.2)
                  : (isDark
                      ? Colors.white.withOpacity(0.08)
                      : Colors.black.withOpacity(0.05)),
              borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
              border: Border.all(
                color: isSelected
                    ? AppColors.primary
                    : (isDark
                        ? Colors.white.withOpacity(0.1)
                        : Colors.black.withOpacity(0.1)),
                width: isSelected ? 2 : 1,
              ),
            ),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Text(mode.icon, style: const TextStyle(fontSize: 32)),
                const SizedBox(height: 8),
                Text(
                  mode.nameFa,
                  style: TextStyle(
                    color: isSelected
                        ? AppColors.primary
                        : (isDark ? Colors.white70 : Colors.black54),
                    fontSize: 12,
                    fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
                  ),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 4),
                Text(
                  mode.description,
                  style: TextStyle(
                    color: isDark ? Colors.white38 : Colors.black38,
                    fontSize: 9,
                  ),
                  textAlign: TextAlign.center,
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}
