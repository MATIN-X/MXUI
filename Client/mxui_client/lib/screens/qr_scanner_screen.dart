import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

class QRScannerScreen extends ConsumerStatefulWidget {
  const QRScannerScreen({super.key});

  @override
  ConsumerState<QRScannerScreen> createState() => _QRScannerScreenState();
}

class _QRScannerScreenState extends ConsumerState<QRScannerScreen> {
  MobileScannerController? _controller;
  bool _isFlashOn = false;
  bool _isFrontCamera = false;
  bool _isProcessing = false;
  String? _scannedData;

  @override
  void initState() {
    super.initState();
    _controller = MobileScannerController(
      detectionSpeed: DetectionSpeed.normal,
      facing: CameraFacing.back,
      torchEnabled: false,
    );
  }

  @override
  void dispose() {
    _controller?.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Scan QR Code'),
        actions: [
          IconButton(
            icon: Icon(_isFlashOn ? Icons.flash_on : Icons.flash_off),
            onPressed: _toggleFlash,
            tooltip: 'Toggle Flash',
          ),
          IconButton(
            icon: Icon(_isFrontCamera ? Icons.camera_front : Icons.camera_rear),
            onPressed: _switchCamera,
            tooltip: 'Switch Camera',
          ),
        ],
      ),
      body: Column(
        children: [
          Expanded(
            flex: 3,
            child: Stack(
              alignment: Alignment.center,
              children: [
                // Camera Preview
                MobileScanner(
                  controller: _controller,
                  onDetect: _onDetect,
                ),
                // Scan overlay
                _buildScanOverlay(),
                // Processing indicator
                if (_isProcessing)
                  Container(
                    color: Colors.black54,
                    child: const Center(
                      child: CircularProgressIndicator(),
                    ),
                  ),
              ],
            ),
          ),
          Expanded(
            flex: 1,
            child: Container(
              width: double.infinity,
              padding: const EdgeInsets.all(24),
              color: Theme.of(context).colorScheme.surface,
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  if (_scannedData != null) ...[
                    Text(
                      'QR Code Detected',
                      style: Theme.of(context).textTheme.titleMedium?.copyWith(
                        color: Colors.green,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      _scannedData!.length > 50
                          ? '${_scannedData!.substring(0, 50)}...'
                          : _scannedData!,
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        fontFamily: 'monospace',
                      ),
                      textAlign: TextAlign.center,
                    ),
                  ] else ...[
                    Icon(
                      Icons.qr_code_scanner,
                      size: 48,
                      color: Theme.of(context).colorScheme.primary,
                    ),
                    const SizedBox(height: 12),
                    Text(
                      'Point your camera at a QR code',
                      style: Theme.of(context).textTheme.bodyLarge,
                    ),
                    const SizedBox(height: 4),
                    Text(
                      'Supports subscription URLs and config links',
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: Theme.of(context).colorScheme.onSurface.withOpacity(0.6),
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildScanOverlay() {
    return CustomPaint(
      size: Size.infinite,
      painter: ScanOverlayPainter(
        borderColor: Theme.of(context).colorScheme.primary,
        backgroundColor: Colors.black54,
      ),
    );
  }

  void _toggleFlash() async {
    await _controller?.toggleTorch();
    setState(() => _isFlashOn = !_isFlashOn);
  }

  void _switchCamera() async {
    await _controller?.switchCamera();
    setState(() => _isFrontCamera = !_isFrontCamera);
  }

  void _onDetect(BarcodeCapture capture) {
    if (_isProcessing) return;

    final List<Barcode> barcodes = capture.barcodes;
    if (barcodes.isEmpty) return;

    final barcode = barcodes.first;
    final rawValue = barcode.rawValue;
    
    if (rawValue == null || rawValue.isEmpty) return;

    setState(() {
      _scannedData = rawValue;
      _isProcessing = true;
    });

    _processScannedData(rawValue);
  }

  Future<void> _processScannedData(String data) async {
    // Pause scanning
    _controller?.stop();

    try {
      // Check if it's a valid subscription URL or config
      if (_isValidSubscriptionUrl(data)) {
        await _showConfirmationDialog(data);
      } else if (_isValidConfig(data)) {
        await _showConfirmationDialog(data, isConfig: true);
      } else {
        _showInvalidQRDialog();
      }
    } finally {
      setState(() => _isProcessing = false);
      _controller?.start();
    }
  }

  bool _isValidSubscriptionUrl(String data) {
    return data.startsWith('http://') || 
           data.startsWith('https://') ||
           data.startsWith('sub://');
  }

  bool _isValidConfig(String data) {
    return data.startsWith('vmess://') ||
           data.startsWith('vless://') ||
           data.startsWith('trojan://') ||
           data.startsWith('ss://') ||
           data.startsWith('ssr://') ||
           data.startsWith('hysteria://') ||
           data.startsWith('hysteria2://') ||
           data.startsWith('tuic://') ||
           data.startsWith('wireguard://');
  }

  Future<void> _showConfirmationDialog(String data, {bool isConfig = false}) async {
    final result = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(isConfig ? 'Import Config' : 'Add Subscription'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(isConfig
                ? 'Do you want to import this configuration?'
                : 'Do you want to add this subscription?'),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Text(
                data.length > 100 ? '${data.substring(0, 100)}...' : data,
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 12,
                ),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Add'),
          ),
        ],
      ),
    );

    if (result == true && mounted) {
      // TODO: Implement actual import logic
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(isConfig
              ? 'Configuration imported successfully'
              : 'Subscription added successfully'),
        ),
      );
      Navigator.pop(context, data);
    }
  }

  void _showInvalidQRDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Invalid QR Code'),
        content: const Text(
          'This QR code does not contain a valid subscription URL or configuration.',
        ),
        actions: [
          FilledButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('OK'),
          ),
        ],
      ),
    );

    setState(() => _scannedData = null);
  }
}

class ScanOverlayPainter extends CustomPainter {
  final Color borderColor;
  final Color backgroundColor;

  ScanOverlayPainter({
    required this.borderColor,
    required this.backgroundColor,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final double scanAreaSize = size.width * 0.7;
    final double left = (size.width - scanAreaSize) / 2;
    final double top = (size.height - scanAreaSize) / 2;
    final Rect scanArea = Rect.fromLTWH(left, top, scanAreaSize, scanAreaSize);

    // Draw semi-transparent background
    final backgroundPaint = Paint()..color = backgroundColor;
    
    // Top rectangle
    canvas.drawRect(
      Rect.fromLTWH(0, 0, size.width, top),
      backgroundPaint,
    );
    // Bottom rectangle
    canvas.drawRect(
      Rect.fromLTWH(0, top + scanAreaSize, size.width, size.height - top - scanAreaSize),
      backgroundPaint,
    );
    // Left rectangle
    canvas.drawRect(
      Rect.fromLTWH(0, top, left, scanAreaSize),
      backgroundPaint,
    );
    // Right rectangle
    canvas.drawRect(
      Rect.fromLTWH(left + scanAreaSize, top, size.width - left - scanAreaSize, scanAreaSize),
      backgroundPaint,
    );

    // Draw corner borders
    final borderPaint = Paint()
      ..color = borderColor
      ..style = PaintingStyle.stroke
      ..strokeWidth = 4
      ..strokeCap = StrokeCap.round;

    const double cornerLength = 30;

    // Top-left corner
    canvas.drawLine(
      Offset(scanArea.left, scanArea.top + cornerLength),
      Offset(scanArea.left, scanArea.top),
      borderPaint,
    );
    canvas.drawLine(
      Offset(scanArea.left, scanArea.top),
      Offset(scanArea.left + cornerLength, scanArea.top),
      borderPaint,
    );

    // Top-right corner
    canvas.drawLine(
      Offset(scanArea.right - cornerLength, scanArea.top),
      Offset(scanArea.right, scanArea.top),
      borderPaint,
    );
    canvas.drawLine(
      Offset(scanArea.right, scanArea.top),
      Offset(scanArea.right, scanArea.top + cornerLength),
      borderPaint,
    );

    // Bottom-left corner
    canvas.drawLine(
      Offset(scanArea.left, scanArea.bottom - cornerLength),
      Offset(scanArea.left, scanArea.bottom),
      borderPaint,
    );
    canvas.drawLine(
      Offset(scanArea.left, scanArea.bottom),
      Offset(scanArea.left + cornerLength, scanArea.bottom),
      borderPaint,
    );

    // Bottom-right corner
    canvas.drawLine(
      Offset(scanArea.right - cornerLength, scanArea.bottom),
      Offset(scanArea.right, scanArea.bottom),
      borderPaint,
    );
    canvas.drawLine(
      Offset(scanArea.right, scanArea.bottom),
      Offset(scanArea.right, scanArea.bottom - cornerLength),
      borderPaint,
    );
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}
