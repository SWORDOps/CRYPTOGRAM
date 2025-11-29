# CRYPTOGRAM Build Guide

Quick reference for building CRYPTOGRAM on different platforms.

## Build Scripts Overview

| Script | Purpose | Platform | Output |
|--------|---------|----------|--------|
| `build_linux.sh` | Desktop build | Linux/macOS | Qt/C++ binary |
| `build_apk.sh` | Android build | Any (with Android SDK) | APK file |
| `build_all.sh` | Comprehensive desktop | Linux/macOS | Full build with deps |
| `build_everything.sh` | Interactive menu | Any | Multiple targets |

---

## 🐧 Linux Desktop Build

Build CRYPTOGRAM desktop application for Linux.

### Quick Start
```bash
./build_linux.sh
```

### Advanced Options
```bash
# Custom build type
BUILD_TYPE=Debug ./build_linux.sh

# Custom build directory
BUILD_DIR=/tmp/cryptogram_build ./build_linux.sh

# Use specific number of jobs
JOBS=8 ./build_linux.sh
```

### Output
- Binary: `build_release/bin/Telegram`
- Build time: ~30-45 minutes (first build)

### Requirements
- Automatically installed by script:
  - Qt6 development packages
  - C++ compiler (gcc/clang)
  - CMake, Ninja
  - All dependencies (OpenAL, LZ4, FFmpeg, etc.)

---

## 📱 Android APK Build

Build CRYPTOGRAM/SWORDCOMM Android APK.

### Quick Start
```bash
# Auto-detect project location
./build_apk.sh

# Specify project path
./build_apk.sh /path/to/android/project
```

### Build Variants
```bash
# Debug build (default)
./build_apk.sh

# Release build (requires signing)
BUILD_VARIANT=release ./build_apk.sh

# Clean build
CLEAN_BUILD=1 ./build_apk.sh

# Different flavor
FLAVOR=gms BUILD_VARIANT=release ./build_apk.sh
```

### Release Signing
```bash
export CI_KEYSTORE_PATH=/path/to/keystore.jks
export CI_KEYSTORE_PASSWORD=your_password
export CI_KEYSTORE_ALIAS=your_alias
BUILD_VARIANT=release ./build_apk.sh
```

### Output
- Debug APK: `app/build/outputs/apk/foss/debug/`
- Release APK: `app/build/outputs/apk/foss/release/`
- Build time: ~5-15 minutes

### Requirements
- Java JDK 17+
- Android SDK
- Gradle (wrapper included in project)

---

## 🔧 Full Build (Recommended for First Time)

Use the comprehensive build script for first-time setup:

```bash
./build_all.sh
```

Features:
- ✅ Auto-installs all dependencies
- ✅ Configures compilers
- ✅ Builds third-party libraries
- ✅ Handles git submodules
- ✅ Resume support (`--resume`)
- ✅ Force rebuild (`--force`)

---

## 📋 Common Tasks

### Clean Build
```bash
# Desktop
rm -rf build_release && ./build_linux.sh

# Android
CLEAN_BUILD=1 ./build_apk.sh
```

### Install APK on Device
```bash
# Find APK
find . -name "*.apk" -mmin -60

# Install
adb install -r app/build/outputs/apk/foss/debug/app-foss-debug.apk
```

### Run Desktop Binary
```bash
# Direct
./build_release/bin/Telegram

# With TSM integration
source .tsm_cryptogram_env.sh
python -m Telegram.lib_tsm.mock_server.server &
./build_release/bin/Telegram
```

---

## 🐛 Troubleshooting

### Linux Build Issues

**Missing dependencies:**
```bash
# Script auto-installs, but if manual install needed:
sudo apt-get install qt6-base-dev libssl-dev cmake ninja-build \
    libopenal-dev liblz4-dev libavcodec-dev
```

**CMake errors:**
```bash
# Clean and retry
rm -rf build_release
./build_all.sh --force
```

### Android Build Issues

**ANDROID_HOME not set:**
```bash
export ANDROID_HOME=$HOME/Android/Sdk
export PATH=$PATH:$ANDROID_HOME/tools:$ANDROID_HOME/platform-tools
```

**Gradle daemon issues:**
```bash
./gradlew --stop
CLEAN_BUILD=1 ./build_apk.sh
```

**Java version mismatch:**
```bash
# Install Java 17
sudo apt-get install openjdk-17-jdk

# Set as default
sudo update-alternatives --config java
```

---

## 📚 Build Logs

All scripts save detailed logs:

```bash
# Linux builds
ls -lh /tmp/cryptogram_builds_root/linux_build_*.log

# Android builds
ls -lh /tmp/cryptogram_builds_root/apk_build_*.log

# View latest
tail -f /tmp/cryptogram_builds_root/*_build_*.log | tail -100
```

---

## 🚀 CI/CD Integration

### GitHub Actions Example

```yaml
jobs:
  build-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          submodules: recursive
      - name: Build Desktop
        run: ./build_linux.sh

  build-android:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Java
        uses: actions/setup-java@v3
        with:
          java-version: '17'
      - name: Build APK
        run: ./build_apk.sh
```

---

## 📞 Support

- **Issues:** Check build logs first
- **Documentation:** See README.md
- **Community:** GitHub Issues

---

*Last updated: 2025-11-29*
