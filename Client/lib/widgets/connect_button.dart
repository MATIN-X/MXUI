// MXUI VPN Client
// widgets/connect_button.dart - Large Connect Button Widget

import 'dart:math' as math;
import 'package:flutter/material.dart';
import '../core/theme.dart';
import '../core/constants.dart';

class ConnectButton extends StatefulWidget {
  final bool isConnected;
  final bool isConnecting;
  final VoidCallback onTap;

  const ConnectButton({
    super.key,
    required this.isConnected,
    required this.isConnecting,
    required this.onTap,
  });

  @override
  State<ConnectButton> createState() => _ConnectButtonState();
}

class _ConnectButtonState extends State<ConnectButton>
    with TickerProviderStateMixin {
  late AnimationController _pulseController;
  late AnimationController _rotationController;
  late Animation<double> _pulseAnimation;

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1500),
    );
    _rotationController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    );

    _pulseAnimation = Tween<double>(begin: 1.0, end: 1.15).animate(
      CurvedAnimation(parent: _pulseController, curve: Curves.easeInOut),
    );

    _updateAnimations();
  }

  @override
  void didUpdateWidget(ConnectButton oldWidget) {
    super.didUpdateWidget(oldWidget);
    _updateAnimations();
  }

  void _updateAnimations() {
    if (widget.isConnecting) {
      _rotationController.repeat();
      _pulseController.stop();
    } else if (widget.isConnected) {
      _pulseController.repeat(reverse: true);
      _rotationController.stop();
    } else {
      _pulseController.stop();
      _rotationController.stop();
      _pulseController.value = 0;
      _rotationController.value = 0;
    }
  }

  @override
  void dispose() {
    _pulseController.dispose();
    _rotationController.dispose();
    super.dispose();
  }

  Color get _buttonColor {
    if (widget.isConnecting) return AppColors.warning;
    if (widget.isConnected) return AppColors.success;
    return AppColors.primary;
  }

  String get _statusText {
    if (widget.isConnecting) return 'در حال اتصال...';
    if (widget.isConnected) return 'متصل';
    return 'اتصال';
  }

  IconData get _statusIcon {
    if (widget.isConnecting) return Icons.sync_rounded;
    if (widget.isConnected) return Icons.power_settings_new_rounded;
    return Icons.power_settings_new_rounded;
  }

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: widget.isConnecting ? null : widget.onTap,
      child: AnimatedBuilder(
        animation: Listenable.merge([_pulseAnimation, _rotationController]),
        builder: (context, child) {
          return Transform.scale(
            scale: widget.isConnected ? _pulseAnimation.value : 1.0,
            child: Container(
              width: 180,
              height: 180,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                gradient: RadialGradient(
                  colors: [
                    _buttonColor.withOpacity(0.3),
                    _buttonColor.withOpacity(0.1),
                    Colors.transparent,
                  ],
                  stops: const [0.5, 0.7, 1.0],
                ),
              ),
              child: Center(
                child: Container(
                  width: 140,
                  height: 140,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    gradient: LinearGradient(
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                      colors: [
                        _buttonColor,
                        _buttonColor.withOpacity(0.7),
                      ],
                    ),
                    boxShadow: [
                      BoxShadow(
                        color: _buttonColor.withOpacity(0.5),
                        blurRadius: 30,
                        spreadRadius: 5,
                      ),
                    ],
                  ),
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Transform.rotate(
                        angle: widget.isConnecting
                            ? _rotationController.value * 2 * math.pi
                            : 0,
                        child: Icon(
                          _statusIcon,
                          color: Colors.white,
                          size: 48,
                        ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        _statusText,
                        style: const TextStyle(
                          color: Colors.white,
                          fontSize: 14,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          );
        },
      ),
    );
  }
}

// Mini connect button for compact views
class MiniConnectButton extends StatelessWidget {
  final bool isConnected;
  final bool isConnecting;
  final VoidCallback onTap;

  const MiniConnectButton({
    super.key,
    required this.isConnected,
    required this.isConnecting,
    required this.onTap,
  });

  Color get _buttonColor {
    if (isConnecting) return AppColors.warning;
    if (isConnected) return AppColors.success;
    return AppColors.primary;
  }

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: isConnecting ? null : onTap,
      child: Container(
        width: 56,
        height: 56,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          color: _buttonColor,
          boxShadow: [
            BoxShadow(
              color: _buttonColor.withOpacity(0.4),
              blurRadius: 15,
              spreadRadius: 2,
            ),
          ],
        ),
        child: Icon(
          isConnecting
              ? Icons.sync_rounded
              : Icons.power_settings_new_rounded,
          color: Colors.white,
          size: 28,
        ),
      ),
    );
  }
}
