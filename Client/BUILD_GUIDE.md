# MX-UI Client Build & Distribution Guide

## Platform Build Instructions

### Android

#### Debug Build
```bash
cd Client/mxui_client
flutter build apk --debug
```

#### Release Build
```bash
# Generate signing key (first time only)
keytool -genkey -v -keystore ~/mxui-release-key.jks \
  -keyalg RSA -keysize 2048 -validity 10000 -alias mxui

# Create android/key.properties
cat > android/key.properties << EOF
storePassword=YOUR_PASSWORD
keyPassword=YOUR_PASSWORD
keyAlias=mxui
storeFile=/path/to/mxui-release-key.jks
EOF

# Build signed APK
flutter build apk --release

# Or build App Bundle for Play Store
flutter build appbundle --release
```

**Output**: `build/app/outputs/flutter-apk/app-release.apk`

---

### iOS

#### Requirements
- macOS with Xcode 15+
- Apple Developer account
- Provisioning profiles

#### Build
```bash
cd Client/mxui_client

# Install pods
cd ios && pod install && cd ..

# Build
flutter build ios --release

# Open in Xcode for signing
open ios/Runner.xcworkspace
```

**Steps in Xcode**:
1. Select Runner → Signing & Capabilities
2. Set Team and Bundle Identifier
3. Archive → Distribute App → App Store Connect

---

### macOS

#### Build
```bash
cd Client/mxui_client
flutter build macos --release
```

**Output**: `build/macos/Build/Products/Release/mxui_client.app`

#### Create DMG
```bash
# Install create-dmg
brew install create-dmg

# Create DMG
create-dmg \
  --volname "MX-UI" \
  --window-pos 200 120 \
  --window-size 600 400 \
  --icon-size 100 \
  --icon "mxui_client.app" 175 120 \
  --hide-extension "mxui_client.app" \
  --app-drop-link 425 120 \
  "MX-UI-macOS.dmg" \
  "build/macos/Build/Products/Release/"
```

---

### Windows

#### Requirements
- Windows 10/11
- Visual Studio 2022 with C++ tools
- Flutter SDK

#### Build
```bash
cd Client/mxui_client
flutter build windows --release
```

**Output**: `build\windows\runner\Release\`

#### Create Installer (Inno Setup)
```bash
# Install Inno Setup
winget install JRSoftware.InnoSetup

# Create installer script
cat > windows/installer.iss << 'EOF'
[Setup]
AppName=MX-UI
AppVersion=1.0.0
DefaultDirName={pf}\MX-UI
DefaultGroupName=MX-UI
OutputDir=.
OutputBaseFilename=MX-UI-Setup
Compression=lzma2
SolidCompression=yes

[Files]
Source: "build\windows\runner\Release\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{group}\MX-UI"; Filename: "{app}\mxui_client.exe"
Name: "{autodesktop}\MX-UI"; Filename: "{app}\mxui_client.exe"
EOF

# Compile
iscc windows/installer.iss
```

---

### Linux

#### Build (Ubuntu/Debian)
```bash
# Install dependencies
sudo apt install clang cmake ninja-build pkg-config \
  libgtk-3-dev liblzma-dev

cd Client/mxui_client
flutter build linux --release
```

**Output**: `build/linux/x64/release/bundle/`

#### Create AppImage
```bash
# Download linuxdeploy
wget https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage
chmod +x linuxdeploy-x86_64.AppImage

# Create AppImage
./linuxdeploy-x86_64.AppImage \
  --appdir AppDir \
  --executable build/linux/x64/release/bundle/mxui_client \
  --desktop-file linux/mxui_client.desktop \
  --icon-file linux/icons/mxui_client.png \
  --output appimage
```

#### Create DEB Package
```bash
# Create package structure
mkdir -p mxui-client_1.0.0_amd64/DEBIAN
mkdir -p mxui-client_1.0.0_amd64/usr/bin
mkdir -p mxui-client_1.0.0_amd64/usr/share/applications
mkdir -p mxui-client_1.0.0_amd64/usr/share/icons/hicolor/512x512/apps

# Copy files
cp -r build/linux/x64/release/bundle/* mxui-client_1.0.0_amd64/usr/bin/
cp linux/mxui_client.desktop mxui-client_1.0.0_amd64/usr/share/applications/
cp linux/icons/mxui_client.png mxui-client_1.0.0_amd64/usr/share/icons/hicolor/512x512/apps/

# Create control file
cat > mxui-client_1.0.0_amd64/DEBIAN/control << EOF
Package: mxui-client
Version: 1.0.0
Section: net
Priority: optional
Architecture: amd64
Maintainer: MX-UI <support@mxui.io>
Description: MX-UI VPN Client
 Multi-platform VPN client for MX-UI panel
EOF

# Build DEB
dpkg-deb --build mxui-client_1.0.0_amd64
```

---

## Distribution Checklist

### Pre-Release
- [ ] Update version in `pubspec.yaml`
- [ ] Update version in platform configs (Android, iOS, etc.)
- [ ] Test on all target platforms
- [ ] Update CHANGELOG
- [ ] Create release notes

### Android
- [ ] Build signed APK/AAB
- [ ] Test on multiple devices (5.0+)
- [ ] Upload to Play Console
- [ ] Submit for review

### iOS
- [ ] Archive and sign
- [ ] Test on TestFlight
- [ ] Submit to App Store
- [ ] Fill App Store metadata

### macOS
- [ ] Notarize app bundle
- [ ] Create signed DMG
- [ ] Upload to Mac App Store (optional)
- [ ] Distribute via GitHub Releases

### Windows
- [ ] Create signed installer
- [ ] Test on Win 10/11
- [ ] Submit to Microsoft Store (optional)
- [ ] Distribute via GitHub Releases

### Linux
- [ ] Create AppImage
- [ ] Create DEB package
- [ ] Create RPM package (optional)
- [ ] Upload to GitHub Releases
- [ ] Submit to Snap Store (optional)

---

## Auto-Update Implementation

### Using Sparkle (macOS)
```yaml
# pubspec.yaml
dependencies:
  sparkle: ^1.0.0
```

### Using Squirrel (Windows)
```yaml
dependencies:
  squirrel_windows: ^1.0.0
```

### Manual Update Check
```dart
// lib/services/update_service.dart
class UpdateService {
  static const String updateUrl = 'https://api.mxui.io/client/updates';
  
  Future<bool> checkForUpdates() async {
    final response = await http.get(Uri.parse(updateUrl));
    // Compare versions and notify user
  }
}
```

---

## CI/CD Pipeline (GitHub Actions)

```yaml
# .github/workflows/build.yml
name: Build Multi-Platform

on:
  push:
    tags:
      - 'v*'

jobs:
  build-android:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: subosito/flutter-action@v2
      - run: flutter pub get
      - run: flutter build apk --release
      - uses: actions/upload-artifact@v3
        with:
          name: android-apk
          path: build/app/outputs/flutter-apk/

  build-ios:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v3
      - uses: subosito/flutter-action@v2
      - run: flutter pub get
      - run: flutter build ios --release --no-codesign

  build-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - uses: subosito/flutter-action@v2
      - run: flutter pub get
      - run: flutter build windows --release

  build-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: subosito/flutter-action@v2
      - run: sudo apt install -y clang cmake ninja-build pkg-config libgtk-3-dev
      - run: flutter pub get
      - run: flutter build linux --release

  build-macos:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v3
      - uses: subosito/flutter-action@v2
      - run: flutter pub get
      - run: flutter build macos --release
```

---

## Download Links Structure

```
https://github.com/your-org/MX-UI/releases/latest/download/
├── mxui-android.apk
├── mxui-ios.ipa
├── mxui-macos.dmg
├── mxui-windows-setup.exe
├── mxui-linux-x86_64.AppImage
└── mxui-linux_amd64.deb
```

Update README.md client download section with actual URLs after first release.
