# Fonts

## Vazirmatn Font (Persian)

Download from: https://github.com/rastikerdar/vazirmatn/releases

Required files:
- Vazirmatn-Regular.ttf
- Vazirmatn-Bold.ttf
- Vazirmatn-Medium.ttf (optional)
- Vazirmatn-Light.ttf (optional)

Place the TTF files in this directory.

## Alternative:

You can use Google Fonts package instead:
```yaml
dependencies:
  google_fonts: ^6.1.0
```

Then use in code:
```dart
import 'package:google_fonts/google_fonts.dart';

TextTheme textTheme = GoogleFonts.vazirmatnTextTheme();
```
