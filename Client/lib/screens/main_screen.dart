// MXUI VPN Client
// screens/main_screen.dart - Main Screen with Glass Tab Navigation

import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../core/theme.dart';
import '../core/constants.dart';
import '../providers/app_provider.dart';
import 'home_screen.dart';
import 'account_screen.dart';
import 'settings_screen.dart';

class MainScreen extends StatefulWidget {
  const MainScreen({super.key});

  @override
  State<MainScreen> createState() => _MainScreenState();
}

class _MainScreenState extends State<MainScreen> with SingleTickerProviderStateMixin {
  int _currentIndex = 0;
  late PageController _pageController;
  late AnimationController _tabAnimController;

  final List<_TabItem> _tabs = [
    _TabItem(icon: Icons.home_rounded, label: 'Home', labelFa: 'خانه'),
    _TabItem(icon: Icons.person_rounded, label: 'Account', labelFa: 'حساب'),
    _TabItem(icon: Icons.settings_rounded, label: 'Settings', labelFa: 'تنظیمات'),
  ];

  @override
  void initState() {
    super.initState();
    _pageController = PageController();
    _tabAnimController = AnimationController(
      vsync: this,
      duration: AppConstants.animNormal,
    );
  }

  @override
  void dispose() {
    _pageController.dispose();
    _tabAnimController.dispose();
    super.dispose();
  }

  void _onTabSelected(int index) {
    setState(() => _currentIndex = index);
    _pageController.animateToPage(
      index,
      duration: AppConstants.animNormal,
      curve: Curves.easeOutCubic,
    );
  }

  @override
  Widget build(BuildContext context) {
    final isDark = context.watch<AppProvider>().isDarkMode;

    return Scaffold(
      body: Container(
        decoration: BoxDecoration(
          gradient: isDark ? AppColors.darkBgGradient : null,
          color: isDark ? null : AppColors.lightBg,
        ),
        child: Stack(
          children: [
            // Pages
            PageView(
              controller: _pageController,
              physics: const NeverScrollableScrollPhysics(),
              children: const [
                HomeScreen(),
                AccountScreen(),
                SettingsScreen(),
              ],
            ),

            // Glass Tab Bar (iOS 26 style)
            Positioned(
              left: 24,
              right: 24,
              bottom: 24,
              child: _GlassTabBar(
                tabs: _tabs,
                currentIndex: _currentIndex,
                onTabSelected: _onTabSelected,
                isDark: isDark,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _TabItem {
  final IconData icon;
  final String label;
  final String labelFa;

  _TabItem({required this.icon, required this.label, required this.labelFa});
}

class _GlassTabBar extends StatelessWidget {
  final List<_TabItem> tabs;
  final int currentIndex;
  final Function(int) onTabSelected;
  final bool isDark;

  const _GlassTabBar({
    required this.tabs,
    required this.currentIndex,
    required this.onTabSelected,
    required this.isDark,
  });

  @override
  Widget build(BuildContext context) {
    return ClipRRect(
      borderRadius: BorderRadius.circular(AppConstants.radiusXLarge),
      child: BackdropFilter(
        filter: ImageFilter.blur(sigmaX: 20, sigmaY: 20),
        child: Container(
          height: 72,
          decoration: BoxDecoration(
            color: isDark
                ? Colors.white.withOpacity(0.1)
                : Colors.black.withOpacity(0.05),
            borderRadius: BorderRadius.circular(AppConstants.radiusXLarge),
            border: Border.all(
              color: isDark
                  ? Colors.white.withOpacity(0.2)
                  : Colors.black.withOpacity(0.1),
              width: 1,
            ),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withOpacity(0.1),
                blurRadius: 20,
                offset: const Offset(0, 10),
              ),
            ],
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceEvenly,
            children: tabs.asMap().entries.map((entry) {
              final index = entry.key;
              final tab = entry.value;
              final isSelected = index == currentIndex;

              return _GlassTabItem(
                icon: tab.icon,
                label: tab.labelFa,
                isSelected: isSelected,
                isDark: isDark,
                onTap: () => onTabSelected(index),
              );
            }).toList(),
          ),
        ),
      ),
    );
  }
}

class _GlassTabItem extends StatelessWidget {
  final IconData icon;
  final String label;
  final bool isSelected;
  final bool isDark;
  final VoidCallback onTap;

  const _GlassTabItem({
    required this.icon,
    required this.label,
    required this.isSelected,
    required this.isDark,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      behavior: HitTestBehavior.opaque,
      child: AnimatedContainer(
        duration: AppConstants.animNormal,
        curve: Curves.easeOutCubic,
        padding: EdgeInsets.symmetric(
          horizontal: isSelected ? 20 : 16,
          vertical: 10,
        ),
        decoration: BoxDecoration(
          color: isSelected
              ? AppColors.primary.withOpacity(0.2)
              : Colors.transparent,
          borderRadius: BorderRadius.circular(AppConstants.radiusLarge),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              icon,
              color: isSelected
                  ? AppColors.primary
                  : (isDark ? Colors.white.withOpacity(0.6) : Colors.black.withOpacity(0.5)),
              size: 24,
            ),
            // Animated label slide
            AnimatedSize(
              duration: AppConstants.animNormal,
              curve: Curves.easeOutCubic,
              child: SizedBox(
                width: isSelected ? null : 0,
                child: isSelected
                    ? Padding(
                        padding: const EdgeInsets.only(right: 8),
                        child: Text(
                          label,
                          style: const TextStyle(
                            color: AppColors.primary,
                            fontWeight: FontWeight.w600,
                            fontSize: 14,
                          ),
                        ),
                      )
                    : const SizedBox.shrink(),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
