import 'package:flutter/material.dart';

class AppLocalizations {
  final Locale locale;
  AppLocalizations(this.locale);

  static AppLocalizations? of(BuildContext context) {
    return Localizations.of<AppLocalizations>(context, AppLocalizations);
  }

  static const LocalizationsDelegate<AppLocalizations> delegate = _AppLocalizationsDelegate();

  static final Map<String, Map<String, String>> _localizedValues = {
    'fa': {
      'appName': 'MXUI',
      'connect': 'اتصال',
      'disconnect': 'قطع',
      'connected': 'متصل',
      'disconnected': 'قطع شده',
      'connecting': 'در حال اتصال',
      'home': 'خانه',
      'account': 'اکانت',
      'settings': 'تنظیمات',
      'subscription': 'اشتراک',
      'addSubscription': 'افزودن اشتراک',
      'scanQR': 'اسکن QR',
      'pasteLink': 'لینک را وارد کنید',
      'server': 'سرور',
      'selectServer': 'انتخاب سرور',
      'traffic': 'ترافیک',
      'upload': 'آپلود',
      'download': 'دانلود',
      'expireDate': 'تاریخ انقضا',
      'remainingTraffic': 'ترافیک باقیمانده',
      'theme': 'تم',
      'language': 'زبان',
      'dark': 'تاریک',
      'light': 'روشن',
      'system': 'سیستم',
      'routing': 'مسیریابی',
      'splitTunneling': 'تونل تقسیم',
      'killSwitch': 'کیل سوییچ',
      'warp': 'وارپ',
      'dns': 'DNS',
      'fragment': 'فرگمنت',
      'tls': 'TLS',
      'support': 'پشتیبانی',
      'about': 'درباره',
      'version': 'نسخه',
      'speedTest': 'تست سرعت',
      'pingTest': 'تست پینگ',
      'latency': 'تاخیر',
      'autoConnect': 'اتصال خودکار',
      'notification': 'اعلان',
      'advancedSettings': 'تنظیمات پیشرفته',
      'ok': 'تایید',
      'cancel': 'لغو',
      'save': 'ذخیره',
      'delete': 'حذف',
      'edit': 'ویرایش',
      'refresh': 'بروزرسانی',
      'copy': 'کپی',
      'share': 'اشتراک گذاری',
      'error': 'خطا',
      'success': 'موفق',
      'warning': 'هشدار',
      'info': 'اطلاعات',
    },
    'en': {
      'appName': 'MXUI',
      'connect': 'Connect',
      'disconnect': 'Disconnect',
      'connected': 'Connected',
      'disconnected': 'Disconnected',
      'connecting': 'Connecting',
      'home': 'Home',
      'account': 'Account',
      'settings': 'Settings',
      'subscription': 'Subscription',
      'addSubscription': 'Add Subscription',
      'scanQR': 'Scan QR',
      'pasteLink': 'Paste Link',
      'server': 'Server',
      'selectServer': 'Select Server',
      'traffic': 'Traffic',
      'upload': 'Upload',
      'download': 'Download',
      'expireDate': 'Expire Date',
      'remainingTraffic': 'Remaining Traffic',
      'theme': 'Theme',
      'language': 'Language',
      'dark': 'Dark',
      'light': 'Light',
      'system': 'System',
      'routing': 'Routing',
      'splitTunneling': 'Split Tunneling',
      'killSwitch': 'Kill Switch',
      'warp': 'WARP',
      'dns': 'DNS',
      'fragment': 'Fragment',
      'tls': 'TLS',
      'support': 'Support',
      'about': 'About',
      'version': 'Version',
      'speedTest': 'Speed Test',
      'pingTest': 'Ping Test',
      'latency': 'Latency',
      'autoConnect': 'Auto Connect',
      'notification': 'Notification',
      'advancedSettings': 'Advanced Settings',
      'ok': 'OK',
      'cancel': 'Cancel',
      'save': 'Save',
      'delete': 'Delete',
      'edit': 'Edit',
      'refresh': 'Refresh',
      'copy': 'Copy',
      'share': 'Share',
      'error': 'Error',
      'success': 'Success',
      'warning': 'Warning',
      'info': 'Info',
    },
  };

  String get(String key) {
    return _localizedValues[locale.languageCode]?[key] ?? key;
  }
}

class _AppLocalizationsDelegate extends LocalizationsDelegate<AppLocalizations> {
  const _AppLocalizationsDelegate();

  @override
  bool isSupported(Locale locale) => ['fa', 'en', 'zh', 'ru'].contains(locale.languageCode);

  @override
  Future<AppLocalizations> load(Locale locale) async => AppLocalizations(locale);

  @override
  bool shouldReload(_AppLocalizationsDelegate old) => false;
}
