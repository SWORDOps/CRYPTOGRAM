# CRYPTOGRAM Build Guide - Quick Start

## Prerequisites

### For Desktop (PC) Build
- **Linux/macOS/WSL**
- Git, CMake 3.16+, GCC/Clang
- 8GB+ RAM, 20GB+ disk space

### For Android Build
- **Java 11+**
- Android SDK (auto-detected from `~/Android/Sdk`)
- Android NDK 25+ (optional, auto-detected)
- 10GB+ disk space

---

## Desktop/PC Build (Linux/macOS)

### Basic Build
```bash
cd ~/CRYPTOGRAM
./build_all.sh
```

### Build Options
```bash
# Verbose output
./build_all.sh --verbose

# Force clean rebuild
./build_all.sh --force

# Resume interrupted build
./build_all.sh --resume

# Custom install location
./build_all.sh --prefix=/opt/cryptogram

# Parallel jobs (default: auto-detected cores)
./build_all.sh -j8
```

### What Gets Built
1. ✓ System requirements check
2. ✓ Git repository validation
3. ✓ Compiler detection (GCC/Clang)
4. ✓ Git submodules (recursive)
5. ✓ Build environment setup
6. ✓ Ada URL Parser
7. ✓ Protocol Buffers
8. ✓ CMake configuration
9. ✓ CRYPTOGRAM Desktop build

**Build Time**: 20-60 minutes (first build)
**Output**: `~/CRYPTOGRAM/build_release/bin/Telegram`

---

## Android Build (APK/AAB)

### Basic Build
```bash
cd ~/CRYPTOGRAM
./build_android.sh
```

### Build Options
```bash
# Debug APK (default)
./build_android.sh

# Release APK/AAB with signing
./build_android.sh --release \
  --keystore=release.jks \
  --keystore-pass=your_password

# Force rebuild
./build_android.sh --force

# Verbose output
./build_android.sh --verbose
```



```bash
# Option 1: Hardcoded IP (highest priority)

# Option 2: mDNS auto-discovery (default)

# Option 3: Custom mDNS service

```

### What Gets Built
1. ✓ System requirements check
2. ✓ Git submodules (recursive)
3. ✓ Android SDK validation
4. ✓ Android NDK validation
6. ✓ Gradle dependencies
7. ✓ Android APK/AAB compilation
8. ✓ Build artifact verification

**Build Time**: 10-30 minutes (first build)
**Output**: `android/build/outputs/apk/debug/*.apk` (or `bundle/release/*.aab`)

---

## Environment Variables

### Desktop Build
```bash
export CRYPTOGRAM_ROOT=~/CRYPTOGRAM     # Project root
export INSTALL_PREFIX=/usr/local        # Install location
export VERBOSE=1                        # Enable verbose
export FORCE=1                          # Force rebuild
```

### Android Build
```bash
export ANDROID_SDK_ROOT=~/Android/Sdk   # SDK location
export ANDROID_NDK_VERSION=25.2.9519653 # NDK version
export KEYSTORE_PATH=/path/to/key.jks  # Release keystore
export KEYSTORE_PASSWORD=secret         # Keystore password
```

---

## Build Both Desktop & Android

```bash
# Build desktop first
./build_all.sh

# Then build Android
./build_android.sh

```

---

## Troubleshooting

### Desktop Build Issues

**Missing dependencies**:
```bash
# Ubuntu/Debian
sudo apt-get install build-essential cmake git libssl-dev

# Fedora/RHEL
sudo dnf install gcc-c++ cmake git openssl-devel

# macOS
xcode-select --install
brew install cmake
```

**Submodule errors**:
```bash
git submodule update --init --recursive --force
```

**Build fails - check logs**:
```bash
cat /tmp/cryptogram_builds_$USER/build_*.log
cat /tmp/cryptogram_builds_$USER/errors_*.log
```

### Android Build Issues

**SDK not found**:
```bash
export ANDROID_SDK_ROOT=~/Android/Sdk
# Or install via Android Studio
```

**Gradle errors**:
```bash
cd android
./gradlew clean
./gradlew --refresh-dependencies
```

```bash
# Use hardcoded IP instead of auto-discovery

```

---

## Quick Reference

| Task | Command |
|------|---------|
| **Desktop debug build** | `./build_all.sh` |
| **Desktop with verbose** | `./build_all.sh --verbose` |
| **Android debug APK** | `./build_android.sh` |
| **Android release AAB** | `./build_android.sh --release --keystore=key.jks --keystore-pass=pass` |
| **Force rebuild both** | `./build_all.sh --force && ./build_android.sh --force` |
| **Check build logs** | `cat /tmp/cryptogram_*/build_*.log` |
| **View help** | `./build_all.sh --help` or `./build_android.sh --help` |

---

## Advanced: CI/CD Pipeline

```bash
#!/bin/bash
# Example CI/CD script

# Build desktop
./build_all.sh --verbose || exit 1

# Build Android release
export KEYSTORE_PATH=/secure/release.jks
export KEYSTORE_PASSWORD=${CI_KEYSTORE_PASSWORD}
./build_android.sh --release || exit 1

# Archive artifacts
tar -czf cryptogram-desktop.tar.gz build_release/bin/
cp android/build/outputs/bundle/release/*.aab cryptogram-release.aab
```

---

## Git Submodules

Both build scripts automatically handle recursive submodules with:
- `git submodule update --init --recursive`
- Broken submodule detection
- Automatic verification

No manual submodule management needed!

---

## Need Help?

- **Desktop build help**: `./build_all.sh --help`
- **Android build help**: `./build_android.sh --help`
- **Build logs**: `/tmp/cryptogram_builds_$USER/` or `/tmp/cryptogram_android_$USER/`
- **Test scripts**: `./test_build_fixes.sh`

---

**Last Updated**: 2025-11-18
**Script Versions**: build_all.sh v3.1, build_android.sh v1.0
