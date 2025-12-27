# MX-UI Client (Flutter)

This is the Flutter client scaffold for MX-UI.

## Platforms
- Android
- iOS
- macOS
- Windows
- Linux

## Bootstrap (create platform folders)
From `Client/mxui_client` run:

```bash
flutter create .
flutter pub get
```

This will generate:
- `android/`, `ios/`, `macos/`, `windows/`, `linux/`, `web/`

## Run
```bash
flutter run -d chrome
flutter run -d android
flutter run -d ios
flutter run -d macos
flutter run -d windows
flutter run -d linux
```

## Build
```bash
flutter build apk
flutter build appbundle
flutter build ios
flutter build macos
flutter build windows
flutter build linux
```

## Next steps (when you provide UI/UX requirements)
- Design system (colors/typography/components)
- Auth + server selection + QR import
- Profile management + subscription handling
- Connection engine strategy (platform-specific VPN integration)
