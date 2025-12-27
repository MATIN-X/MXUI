// MXUI VPN Client
// widgets/traffic_stats.dart - Traffic Statistics Widget

import 'package:flutter/material.dart';
import '../core/theme.dart';
import '../core/constants.dart';
import '../models/account.dart';

class TrafficStatsWidget extends StatelessWidget {
  final TrafficStats stats;
  final bool isDark;
  final bool isCompact;

  const TrafficStatsWidget({
    super.key,
    required this.stats,
    required this.isDark,
    this.isCompact = false,
  });

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '${bytes} B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }

  String _formatSpeed(int bytesPerSecond) {
    if (bytesPerSecond < 1024) return '${bytesPerSecond} B/s';
    if (bytesPerSecond < 1024 * 1024) {
      return '${(bytesPerSecond / 1024).toStringAsFixed(1)} KB/s';
    }
    return '${(bytesPerSecond / (1024 * 1024)).toStringAsFixed(1)} MB/s';
  }

  String _formatDuration(Duration duration) {
    final hours = duration.inHours;
    final minutes = duration.inMinutes.remainder(60);
    final seconds = duration.inSeconds.remainder(60);

    if (hours > 0) {
      return '${hours.toString().padLeft(2, '0')}:${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}';
    }
    return '${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}';
  }

  @override
  Widget build(BuildContext context) {
    if (isCompact) {
      return _buildCompactStats();
    }
    return _buildFullStats();
  }

  Widget _buildCompactStats() {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceEvenly,
      children: [
        _StatItem(
          icon: Icons.arrow_upward_rounded,
          value: _formatSpeed(stats.uploadSpeed),
          label: 'آپلود',
          color: AppColors.success,
          isDark: isDark,
          isCompact: true,
        ),
        Container(
          width: 1,
          height: 30,
          color: isDark ? Colors.white12 : Colors.black12,
        ),
        _StatItem(
          icon: Icons.arrow_downward_rounded,
          value: _formatSpeed(stats.downloadSpeed),
          label: 'دانلود',
          color: AppColors.primary,
          isDark: isDark,
          isCompact: true,
        ),
        Container(
          width: 1,
          height: 30,
          color: isDark ? Colors.white12 : Colors.black12,
        ),
        _StatItem(
          icon: Icons.timer_outlined,
          value: _formatDuration(stats.connectionTime),
          label: 'زمان',
          color: AppColors.secondary,
          isDark: isDark,
          isCompact: true,
        ),
      ],
    );
  }

  Widget _buildFullStats() {
    return Column(
      children: [
        Row(
          children: [
            Expanded(
              child: _StatCard(
                icon: Icons.arrow_upward_rounded,
                value: _formatBytes(stats.upload),
                speed: _formatSpeed(stats.uploadSpeed),
                label: 'آپلود',
                color: AppColors.success,
                isDark: isDark,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _StatCard(
                icon: Icons.arrow_downward_rounded,
                value: _formatBytes(stats.download),
                speed: _formatSpeed(stats.downloadSpeed),
                label: 'دانلود',
                color: AppColors.primary,
                isDark: isDark,
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        _TimeCard(
          duration: stats.connectionTime,
          isDark: isDark,
        ),
      ],
    );
  }
}

class _StatItem extends StatelessWidget {
  final IconData icon;
  final String value;
  final String label;
  final Color color;
  final bool isDark;
  final bool isCompact;

  const _StatItem({
    required this.icon,
    required this.value,
    required this.label,
    required this.color,
    required this.isDark,
    this.isCompact = false,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, color: color, size: isCompact ? 16 : 20),
        const SizedBox(height: 4),
        Text(
          value,
          style: TextStyle(
            color: isDark ? Colors.white : Colors.black87,
            fontSize: isCompact ? 12 : 14,
            fontWeight: FontWeight.w600,
          ),
        ),
        Text(
          label,
          style: TextStyle(
            color: isDark ? Colors.white54 : Colors.black45,
            fontSize: isCompact ? 10 : 11,
          ),
        ),
      ],
    );
  }
}

class _StatCard extends StatelessWidget {
  final IconData icon;
  final String value;
  final String speed;
  final String label;
  final Color color;
  final bool isDark;

  const _StatCard({
    required this.icon,
    required this.value,
    required this.speed,
    required this.label,
    required this.color,
    required this.isDark,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: isDark
            ? Colors.white.withOpacity(0.08)
            : Colors.black.withOpacity(0.05),
        borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
        border: Border.all(
          color: isDark
              ? Colors.white.withOpacity(0.1)
              : Colors.black.withOpacity(0.1),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: color.withOpacity(0.2),
                  borderRadius: BorderRadius.circular(AppConstants.radiusSmall),
                ),
                child: Icon(icon, color: color, size: 20),
              ),
              const Spacer(),
              Text(
                speed,
                style: TextStyle(
                  color: color,
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Text(
            value,
            style: TextStyle(
              color: isDark ? Colors.white : Colors.black87,
              fontSize: 18,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            label,
            style: TextStyle(
              color: isDark ? Colors.white54 : Colors.black45,
              fontSize: 12,
            ),
          ),
        ],
      ),
    );
  }
}

class _TimeCard extends StatelessWidget {
  final Duration duration;
  final bool isDark;

  const _TimeCard({
    required this.duration,
    required this.isDark,
  });

  @override
  Widget build(BuildContext context) {
    final hours = duration.inHours;
    final minutes = duration.inMinutes.remainder(60);
    final seconds = duration.inSeconds.remainder(60);

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: isDark
            ? Colors.white.withOpacity(0.08)
            : Colors.black.withOpacity(0.05),
        borderRadius: BorderRadius.circular(AppConstants.radiusMedium),
        border: Border.all(
          color: isDark
              ? Colors.white.withOpacity(0.1)
              : Colors.black.withOpacity(0.1),
        ),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.timer_outlined,
            color: AppColors.secondary,
            size: 24,
          ),
          const SizedBox(width: 12),
          _TimeUnit(value: hours, label: 'ساعت', isDark: isDark),
          _TimeSeparator(isDark: isDark),
          _TimeUnit(value: minutes, label: 'دقیقه', isDark: isDark),
          _TimeSeparator(isDark: isDark),
          _TimeUnit(value: seconds, label: 'ثانیه', isDark: isDark),
        ],
      ),
    );
  }
}

class _TimeUnit extends StatelessWidget {
  final int value;
  final String label;
  final bool isDark;

  const _TimeUnit({
    required this.value,
    required this.label,
    required this.isDark,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Text(
          value.toString().padLeft(2, '0'),
          style: TextStyle(
            color: isDark ? Colors.white : Colors.black87,
            fontSize: 24,
            fontWeight: FontWeight.bold,
            fontFeatures: const [FontFeature.tabularFigures()],
          ),
        ),
        Text(
          label,
          style: TextStyle(
            color: isDark ? Colors.white54 : Colors.black45,
            fontSize: 10,
          ),
        ),
      ],
    );
  }
}

class _TimeSeparator extends StatelessWidget {
  final bool isDark;

  const _TimeSeparator({required this.isDark});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 8),
      child: Text(
        ':',
        style: TextStyle(
          color: isDark ? Colors.white54 : Colors.black45,
          fontSize: 24,
          fontWeight: FontWeight.bold,
        ),
      ),
    );
  }
}
