# Flutter
-keep class io.flutter.** { *; }
-keep class io.flutter.embedding.** { *; }

# Keep native methods
-keepclassmembers class * {
    native <methods>;
}

# Sing-box
-keep class go.** { *; }
-keep class libcore.** { *; }
