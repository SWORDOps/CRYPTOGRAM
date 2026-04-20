# CRYPTOGRAM Build Guide

Quick reference for building CRYPTOGRAM on different platforms.

Desktop/Linux claim gate and build-state source of truth:
`docs/status/DESKTOP_BUILD_ALIGNMENT.md`.

## Build Scripts Overview

| Script | Role | Platform | Output |
|--------|------|----------|--------|
| `build_linux.sh` | **Canonical desktop entrypoint** | Linux/macOS | Qt/C++ binary |
| `build_all.sh` | Desktop orchestrator/wrapper used by `build_linux.sh` | Linux/macOS | Full desktop build flow |
| `build_apk.sh` | Android build | Any (with Android SDK) | APK file |
| `build_everything.sh` | Interactive multi-target wrapper | Any | Multiple targets |

---

## 🐧 Linux Desktop Build (Canonical)

Build CRYPTOGRAM desktop application for Linux.

Important for this repo snapshot:
- The desktop source tree expects a populated top-level `cmake` git submodule.
- Required helper files include `cmake/version.cmake` and `cmake/validate_special_target.cmake`.
- If those files are missing, desktop configure cannot start.
- The current pinned `cmake` submodule revision may be unavailable upstream, so `git submodule update --init --recursive cmake` can still fail even on a healthy machine.

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
- A fetchable top-level `cmake` submodule revision

### Current Desktop Limitation

If `build_linux.sh` stops with a missing `cmake/version.cmake` or `cmake/validate_special_target.cmake` error, the checkout is missing the root helper submodule contents. The intended recovery command is:

```bash
git submodule update --init --recursive cmake
```

If that command fails to fetch the pinned commit, the desktop tree cannot currently be configured from this snapshot alone.

---

## 📱 Android APK Build

Build CRYPTOGRAM/CRYPTOGRAM Android Android APK.

Important for this repo snapshot:
- This repository does not currently contain a self-contained Android Gradle project.
- `build_apk.sh` builds against an external Android Gradle checkout that you provide.
- A valid external project root must contain `gradlew` plus Gradle build files such as `build.gradle`, `build.gradle.kts`, `settings.gradle`, `settings.gradle.kts`, or `app/build.gradle`.
- Autodiscovery in `build_apk.sh` is best-effort only; pass the external project path explicitly when possible.

### Quick Start
```bash
# Preferred: pass the external Android project explicitly
./build_apk.sh /path/to/android/gradle/project

# Or via environment variable
ANDROID_PROJECT_PATH=/path/to/android/gradle/project ./build_apk.sh
```

### Build Variants
```bash
# Debug build (default)
./build_apk.sh /path/to/android/gradle/project

# Release build (requires signing)
BUILD_VARIANT=release ./build_apk.sh /path/to/android/gradle/project

# Clean build
CLEAN_BUILD=1 ./build_apk.sh /path/to/android/gradle/project

# Different flavor
FLAVOR=gms BUILD_VARIANT=release ./build_apk.sh /path/to/android/gradle/project
```

Avoid relying on `BUILD_VARIANT=release ./build_apk.sh` without a path unless you know one of the script's fallback search locations already contains the correct external Android checkout.

### Release Signing
```bash
export CI_KEYSTORE_PATH=/path/to/keystore.jks
export CI_KEYSTORE_PASSWORD=your_password
export CI_KEYSTORE_ALIAS=your_alias
BUILD_VARIANT=release ./build_apk.sh /path/to/android/gradle/project
```

### Output
- Typical debug APK: `<external-project>/app/build/outputs/apk/foss/debug/`
- Typical release APK: `<external-project>/app/build/outputs/apk/foss/release/`
- Some Android bases may instead emit under `build/outputs/apk/` or `TMessagesProj/build/outputs/apk/`
- Build time: ~5-15 minutes

### Requirements
- Java JDK 17+
- Android SDK
- An external Android Gradle project with `gradlew`

### Current Repository Limitation

The CRYPTOGRAM repository contains Android source modifications under `TMessagesProj/`, but it does not ship the full Gradle Android base in this snapshot. That means:

- `./build_apk.sh` cannot succeed on this repo alone
- you must point it at an external Android project checkout
- the script will fail fast if that external path is missing `gradlew` or Gradle build files

---

## 🔧 Full Build Wrapper

Use the comprehensive wrapper when you want the extended orchestration:

```bash
./build_all.sh
```

Notes:
- ✅ Auto-installs all dependencies
- ✅ Configures compilers
- ✅ Builds third-party libraries
- ✅ Handles git submodules
- ✅ Resume support (`--resume`)
- ✅ Force rebuild (`--force`)
- It is not the canonical desktop entrypoint for docs. Use `./build_linux.sh` for standard Linux instructions.

---

## 📋 Common Tasks

### Clean Build
```bash
# Desktop
rm -rf build_release && ./build_linux.sh

# Android
CLEAN_BUILD=1 ./build_apk.sh /path/to/android/gradle/project
```

### Install APK on Device
```bash
# Find APK
find /path/to/android/gradle/project -name "*.apk" -mmin -60

# Install
adb install -r /path/to/android/gradle/project/app/build/outputs/apk/foss/debug/app-foss-debug.apk
```

### Run Desktop Binary
```bash
# Direct
./build_release/bin/Telegram

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
cd /path/to/android/gradle/project
./gradlew --stop
CLEAN_BUILD=1 /media/john/NVME_STORAGE10/CRYPTOGRAM/build_apk.sh /path/to/android/gradle/project
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

`build_all.sh` may use a user-specific log directory such as `/tmp/cryptogram_builds_$USER/` or `$HOME/.cache/cryptogram_builds/` if `/tmp/cryptogram_builds_root/` is not the active location for that script.

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
      - name: Checkout Android base
        uses: actions/checkout@v3
        with:
          repository: your-org/your-android-base
          path: android-base
      - name: Build APK
        run: ./build_apk.sh "$GITHUB_WORKSPACE/android-base"
```

---

## 📞 Support

- **Issues:** Check build logs first
- **Documentation:** See README.md
- **Community:** GitHub Issues

---

*Last updated: 2025-11-29*
