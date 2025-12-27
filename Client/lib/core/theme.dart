// MX-UI VPN Client
// core/theme.dart - Application Theme

import 'package:flutter/material.dart';

class AppColors {
  // Primary Colors
  static const Color primary = Color(0xFF6366F1);
  static const Color primaryLight = Color(0xFF818CF8);
  static const Color primaryDark = Color(0xFF4F46E5);

  // Accent Colors
  static const Color accent = Color(0xFF22D3EE);
  static const Color accentLight = Color(0xFF67E8F9);

  // Status Colors
  static const Color success = Color(0xFF10B981);
  static const Color warning = Color(0xFFF59E0B);
  static const Color error = Color(0xFFEF4444);
  static const Color info = Color(0xFF3B82F6);

  // Connection Status
  static const Color connected = Color(0xFF10B981);
  static const Color connecting = Color(0xFFF59E0B);
  static const Color disconnected = Color(0xFF6B7280);

  // Dark Theme
  static const Color darkBg = Color(0xFF0F172A);
  static const Color darkCard = Color(0xFF1E293B);
  static const Color darkCardLight = Color(0xFF334155);
  static const Color darkText = Color(0xFFF8FAFC);
  static const Color darkTextSecondary = Color(0xFF94A3B8);

  // Light Theme
  static const Color lightBg = Color(0xFFF8FAFC);
  static const Color lightCard = Color(0xFFFFFFFF);
  static const Color lightCardDark = Color(0xFFF1F5F9);
  static const Color lightText = Color(0xFF0F172A);
  static const Color lightTextSecondary = Color(0xFF64748B);

  // Glass Effect
  static const Color glassLight = Color(0x33FFFFFF);
  static const Color glassDark = Color(0x33000000);

  // Gradients
  static const LinearGradient primaryGradient = LinearGradient(
    colors: [primary, primaryLight],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );

  static const LinearGradient accentGradient = LinearGradient(
    colors: [accent, accentLight],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );

  static const LinearGradient connectedGradient = LinearGradient(
    colors: [Color(0xFF10B981), Color(0xFF059669)],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );

  static const LinearGradient darkBgGradient = LinearGradient(
    colors: [Color(0xFF0F172A), Color(0xFF1E293B)],
    begin: Alignment.topCenter,
    end: Alignment.bottomCenter,
  );
}

class AppTheme {
  static ThemeData get lightTheme {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.light,
      primaryColor: AppColors.primary,
      scaffoldBackgroundColor: AppColors.lightBg,
      fontFamily: 'Vazirmatn',
      colorScheme: const ColorScheme.light(
        primary: AppColors.primary,
        secondary: AppColors.accent,
        background: AppColors.lightBg,
        surface: AppColors.lightCard,
        error: AppColors.error,
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor: Colors.transparent,
        elevation: 0,
        centerTitle: true,
        iconTheme: IconThemeData(color: AppColors.lightText),
        titleTextStyle: TextStyle(
          color: AppColors.lightText,
          fontSize: 18,
          fontWeight: FontWeight.w600,
          fontFamily: 'Vazirmatn',
        ),
      ),
      cardTheme: CardTheme(
        color: AppColors.lightCard,
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
        ),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: AppColors.primary,
          foregroundColor: Colors.white,
          elevation: 0,
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
          textStyle: const TextStyle(
            fontSize: 16,
            fontWeight: FontWeight.w600,
            fontFamily: 'Vazirmatn',
          ),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: AppColors.primary,
          side: const BorderSide(color: AppColors.primary),
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: AppColors.lightCardDark,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide.none,
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide.none,
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: AppColors.primary, width: 2),
        ),
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      ),
      bottomNavigationBarTheme: const BottomNavigationBarThemeData(
        backgroundColor: Colors.transparent,
        elevation: 0,
        selectedItemColor: AppColors.primary,
        unselectedItemColor: AppColors.lightTextSecondary,
      ),
      textTheme: const TextTheme(
        displayLarge: TextStyle(color: AppColors.lightText, fontFamily: 'Vazirmatn'),
        displayMedium: TextStyle(color: AppColors.lightText, fontFamily: 'Vazirmatn'),
        displaySmall: TextStyle(color: AppColors.lightText, fontFamily: 'Vazirmatn'),
        headlineLarge: TextStyle(color: AppColors.lightText, fontFamily: 'Vazirmatn'),
        headlineMedium: TextStyle(color: AppColors.lightText, fontFamily: 'Vazirmatn'),
        headlineSmall: TextStyle(color: AppColors.lightText, fontFamily: 'Vazirmatn'),
        titleLarge: TextStyle(color: AppColors.lightText, fontFamily: 'Vazirmatn'),
        titleMedium: TextStyle(color: AppColors.lightText, fontFamily: 'Vazirmatn'),
        titleSmall: TextStyle(color: AppColors.lightText, fontFamily: 'Vazirmatn'),
        bodyLarge: TextStyle(color: AppColors.lightText, fontFamily: 'Vazirmatn'),
        bodyMedium: TextStyle(color: AppColors.lightText, fontFamily: 'Vazirmatn'),
        bodySmall: TextStyle(color: AppColors.lightTextSecondary, fontFamily: 'Vazirmatn'),
        labelLarge: TextStyle(color: AppColors.lightText, fontFamily: 'Vazirmatn'),
        labelMedium: TextStyle(color: AppColors.lightTextSecondary, fontFamily: 'Vazirmatn'),
        labelSmall: TextStyle(color: AppColors.lightTextSecondary, fontFamily: 'Vazirmatn'),
      ),
    );
  }

  static ThemeData get darkTheme {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      primaryColor: AppColors.primary,
      scaffoldBackgroundColor: AppColors.darkBg,
      fontFamily: 'Vazirmatn',
      colorScheme: const ColorScheme.dark(
        primary: AppColors.primary,
        secondary: AppColors.accent,
        background: AppColors.darkBg,
        surface: AppColors.darkCard,
        error: AppColors.error,
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor: Colors.transparent,
        elevation: 0,
        centerTitle: true,
        iconTheme: IconThemeData(color: AppColors.darkText),
        titleTextStyle: TextStyle(
          color: AppColors.darkText,
          fontSize: 18,
          fontWeight: FontWeight.w600,
          fontFamily: 'Vazirmatn',
        ),
      ),
      cardTheme: CardTheme(
        color: AppColors.darkCard,
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
        ),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: AppColors.primary,
          foregroundColor: Colors.white,
          elevation: 0,
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: AppColors.darkCardLight,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide.none,
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide.none,
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: AppColors.primary, width: 2),
        ),
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      ),
      textTheme: const TextTheme(
        displayLarge: TextStyle(color: AppColors.darkText, fontFamily: 'Vazirmatn'),
        displayMedium: TextStyle(color: AppColors.darkText, fontFamily: 'Vazirmatn'),
        displaySmall: TextStyle(color: AppColors.darkText, fontFamily: 'Vazirmatn'),
        headlineLarge: TextStyle(color: AppColors.darkText, fontFamily: 'Vazirmatn'),
        headlineMedium: TextStyle(color: AppColors.darkText, fontFamily: 'Vazirmatn'),
        headlineSmall: TextStyle(color: AppColors.darkText, fontFamily: 'Vazirmatn'),
        titleLarge: TextStyle(color: AppColors.darkText, fontFamily: 'Vazirmatn'),
        titleMedium: TextStyle(color: AppColors.darkText, fontFamily: 'Vazirmatn'),
        titleSmall: TextStyle(color: AppColors.darkText, fontFamily: 'Vazirmatn'),
        bodyLarge: TextStyle(color: AppColors.darkText, fontFamily: 'Vazirmatn'),
        bodyMedium: TextStyle(color: AppColors.darkText, fontFamily: 'Vazirmatn'),
        bodySmall: TextStyle(color: AppColors.darkTextSecondary, fontFamily: 'Vazirmatn'),
        labelLarge: TextStyle(color: AppColors.darkText, fontFamily: 'Vazirmatn'),
        labelMedium: TextStyle(color: AppColors.darkTextSecondary, fontFamily: 'Vazirmatn'),
        labelSmall: TextStyle(color: AppColors.darkTextSecondary, fontFamily: 'Vazirmatn'),
      ),
    );
  }
}
