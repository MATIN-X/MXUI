# MXUI Client (Flutter Multi-Platform)

This folder is the scaffold for the MXUI native client app.

## Targets
- Android
- iOS
- macOS
- Windows
- Linux

## Tech
- Flutter (Dart)

## Status
Scaffold only (UI/UX and feature set will be implemented based on your next requirements).

## Local setup
1) Install Flutter SDK (stable channel)
2) From `Client/mxui_client`:

```bash
flutter pub get
flutter run -d chrome     # quick dev
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

## Notes
- The app will talk to the panel API (default `/api/v1`).
- We’ll add theming, animations, and a premium UI layer (Material 3 + custom design system) in the next step.
