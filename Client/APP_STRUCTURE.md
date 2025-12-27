# MXUI Native Client App (Flutter)
# iOS 26-Style Glass Morphism Design

## Project Structure

```
Client/
  mxui_client/
    lib/
      main.dart
      screens/
        home_screen.dart
        account_screen.dart
        settings_screen.dart
      widgets/
        glass_button.dart
        glass_card.dart
        connection_button.dart
      services/
        vpn_service.dart
        api_service.dart
      models/
        connection.dart
        user.dart
```

## Features

### 1. Home Tab
- Quick Connect Button (Glass style with glow effect)
- Connection Status (با انیمیشن)
- Connection Modes:
  - Auto (هوشمند)
  - Game (بازی)
  - AI (هوش مصنوعی)
  - Download (دانلود)
  - Social (شبکه‌های اجتماعی)
  - Trading (ترید)
- Traffic Usage Display
- Server Location Display
- Ping & Speed Display

### 2. Account Tab
- Profile Information
- Subscription Details
- Traffic Usage Chart
- Renewal Date
- Payment History
- Referral Code

### 3. Settings Tab
- Protocol Selection
- Auto-Connect
- Kill Switch
- Split Tunneling (انتخاب برنامه‌ها)
- DNS Settings
- WARP Proxy Toggle
- Language Selection
- Theme Selection (Dark/Light)
- About & Version

## Design System

### Colors (iOS 26 Style)
```dart
// Glass Colors
final glassBg = Colors.white.withOpacity(0.08);
final glassBorder = Colors.white.withOpacity(0.18);
final glassBlur = 40.0;

// Primary Gradient
final primaryGradient = LinearGradient(
  colors: [Color(0xFF667eea), Color(0xFF764ba2)],
  begin: Alignment.topLeft,
  end: Alignment.bottomRight,
);

// Status Colors
final connectedGreen = Color(0xFF10b981);
final disconnectedRed = Color(0xFFef4444);
final warningOrange = Color(0xFFf59e0b);
```

### Glass Button Component
```dart
// iOS-style glass morphism button
Widget glassButton({
  required String text,
  required VoidCallback onPressed,
  IconData? icon,
  bool isPrimary = false,
}) {
  return ClipRRect(
    borderRadius: BorderRadius.circular(20),
    child: BackdropFilter(
      filter: ImageFilter.blur(sigmaX: 40, sigmaY: 40),
      child: Container(
        decoration: BoxDecoration(
          gradient: isPrimary ? primaryGradient : null,
          color: isPrimary ? null : glassBg,
          border: Border.all(color: glassBorder),
          borderRadius: BorderRadius.circular(20),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withOpacity(0.1),
              blurRadius: 20,
              offset: Offset(0, 8),
            ),
          ],
        ),
        child: Material(
          color: Colors.transparent,
          child: InkWell(
            onTap: onPressed,
            child: Padding(
              padding: EdgeInsets.symmetric(horizontal: 24, vertical: 16),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (icon != null) Icon(icon, color: Colors.white),
                  if (icon != null) SizedBox(width: 12),
                  Text(
                    text,
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 16,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    ),
  );
}
```

### Connection Button (Main)
```dart
class ConnectionButton extends StatefulWidget {
  @override
  _ConnectionButtonState createState() => _ConnectionButtonState();
}

class _ConnectionButtonState extends State<ConnectionButton> 
    with SingleTickerProviderStateMixin {
  
  late AnimationController _controller;
  bool isConnected = false;
  
  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: Duration(seconds: 2),
    )..repeat();
  }
  
  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: toggleConnection,
      child: Stack(
        alignment: Alignment.center,
        children: [
          // Glow Effect
          if (isConnected)
            AnimatedBuilder(
              animation: _controller,
              builder: (context, child) {
                return Container(
                  width: 200 + (20 * _controller.value),
                  height: 200 + (20 * _controller.value),
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    gradient: RadialGradient(
                      colors: [
                        connectedGreen.withOpacity(0.3 * (1 - _controller.value)),
                        connectedGreen.withOpacity(0),
                      ],
                    ),
                  ),
                );
              },
            ),
          
          // Main Button
          Container(
            width: 180,
            height: 180,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              gradient: isConnected ? 
                LinearGradient(colors: [connectedGreen, connectedGreen.withOpacity(0.7)]) :
                LinearGradient(colors: [glassBg, glassBg]),
              border: Border.all(color: glassBorder, width: 2),
              boxShadow: [
                BoxShadow(
                  color: isConnected ? 
                    connectedGreen.withOpacity(0.5) : 
                    Colors.black.withOpacity(0.2),
                  blurRadius: 30,
                  offset: Offset(0, 10),
                ),
              ],
            ),
            child: Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    isConnected ? Icons.check_circle : Icons.power_settings_new,
                    size: 60,
                    color: Colors.white,
                  ),
                  SizedBox(height: 8),
                  Text(
                    isConnected ? 'متصل' : 'اتصال',
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
  
  void toggleConnection() {
    setState(() {
      isConnected = !isConnected;
    });
    // Call VPN service here
  }
}
```

## Platform Integration

### Android
```kotlin
// VPN Service Integration
class VpnService : VpnService() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val builder = Builder()
        builder.addAddress("10.0.0.2", 24)
        builder.addRoute("0.0.0.0", 0)
        builder.addDnsServer("1.1.1.1")
        builder.setSession("MXUI VPN")
        
        val vpnInterface = builder.establish()
        // Configure VPN...
        
        return START_STICKY
    }
}
```

### iOS
```swift
// Network Extension
import NetworkExtension

class PacketTunnelProvider: NEPacketTunnelProvider {
    override func startTunnel(options: [String : NSObject]?, 
                            completionHandler: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.0.0.1")
        settings.ipv4Settings = NEIPv4Settings(
            addresses: ["10.0.0.2"],
            subnetMasks: ["255.255.255.0"]
        )
        
        setTunnelNetworkSettings(settings) { error in
            completionHandler(error)
        }
    }
}
```

## API Integration

```dart
class ApiService {
  final String baseUrl;
  final String token;
  
  Future<User> getUserInfo() async {
    final response = await http.get(
      Uri.parse('$baseUrl/api/user'),
      headers: {'Authorization': 'Bearer $token'},
    );
    return User.fromJson(jsonDecode(response.body));
  }
  
  Future<List<Server>> getServers() async {
    final response = await http.get(
      Uri.parse('$baseUrl/api/servers'),
      headers: {'Authorization': 'Bearer $token'},
    );
    return (jsonDecode(response.body) as List)
      .map((e) => Server.fromJson(e))
      .toList();
  }
  
  Future<Connection> connect(String serverId) async {
    final response = await http.post(
      Uri.parse('$baseUrl/api/connect'),
      headers: {
        'Authorization': 'Bearer $token',
        'Content-Type': 'application/json',
      },
      body: jsonEncode({'server_id': serverId}),
    );
    return Connection.fromJson(jsonDecode(response.body));
  }
}
```

## Build Instructions

### Android
```bash
cd Client/mxui_client
flutter build apk --release
# Output: build/app/outputs/flutter-apk/app-release.apk
```

### iOS
```bash
cd Client/mxui_client
flutter build ios --release
# Open in Xcode and archive
```

## Dependencies (pubspec.yaml)

```yaml
dependencies:
  flutter:
    sdk: flutter
  http: ^1.1.0
  shared_preferences: ^2.2.2
  provider: ^6.1.1
  fl_chart: ^0.66.0
  flutter_svg: ^2.0.9
  shimmer: ^3.0.0
  connectivity_plus: ^5.0.2
  
  # VPN
  flutter_vpn: ^1.0.0
  
  # UI
  glassmorphism: ^3.0.0
  flutter_animate: ^4.5.0
```

## Screenshots

[Home Screen - Connection Button with Glass Effect]
[Account Screen - Subscription Info with Glass Cards]
[Settings Screen - iOS-style toggles and options]

## Download Links

- **Google Play**: Coming Soon
- **App Store**: Coming Soon
- **APK Direct**: https://github.com/MATIN-X/MXUI/releases
