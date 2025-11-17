# SWORD Dual Project Setup Guide

Complete setup and build guide for both **CRYPTOGRAM** (Desktop) and **SWORDCOMM** (Android).

## Quick Start (All-in-One)

```bash
# Setup both projects at once
/home/user/CRYPTOGRAM/setup-all.sh

# Source the environment
source /tmp/sword_build_env.sh
```

---

## Project Locations

| Project | Type | Location | Build Tool |
|---------|------|----------|-----------|
| **CRYPTOGRAM** | Desktop (C++/Qt) | `/home/user/CRYPTOGRAM` | CMake |
| **SWORDCOMM** | Android (Kotlin) | `~/Documents/SWORDCOMM` | Gradle |

---

## Setup Scripts

### 1. Unified Setup (Both Projects)

```bash
# Setup both CRYPTOGRAM and SWORDCOMM
/home/user/CRYPTOGRAM/setup-all.sh

# Setup only CRYPTOGRAM
/home/user/CRYPTOGRAM/setup-all.sh --desktop

# Setup only SWORDCOMM
/home/user/CRYPTOGRAM/setup-all.sh --android

# Use GCC 15 for desktop
/home/user/CRYPTOGRAM/setup-all.sh --all --gcc15
```

### 2. Individual Setup Scripts

#### CRYPTOGRAM Desktop

```bash
cd /home/user/CRYPTOGRAM

# Automated setup (GCC 14)
./setup.sh

# With GCC 15
./setup.sh --gcc15

# Debug configuration
./setup.sh --debug

# Build immediately after setup
./setup.sh --build --gcc14
```

#### SWORDCOMM Android

```bash
cd ~/Documents/SWORDCOMM

# Verify Java 17 is installed
java -version

# Build debug APK
./gradlew assembleDebug

# Build release APK
./gradlew assembleRelease

# Install on connected device
./gradlew installDebug
```

---

## Build Commands

### CRYPTOGRAM Desktop

```bash
cd /home/user/CRYPTOGRAM

# Build release (optimized)
./build.sh

# Build debug (with symbols)
./build.sh --debug

# Verbose output
./build.sh --verbose

# Custom parallel jobs
./build.sh --jobs 4

# Run the application
./build_release/bin/Telegram
```

### SWORDCOMM Android

```bash
cd ~/Documents/SWORDCOMM

# Load environment (if using setup-all.sh)
source /tmp/sword_build_env.sh

# Build debug APK
./gradlew assembleDebug
# Output: app/build/outputs/apk/debug/app-debug.apk

# Build release APK
./gradlew assembleRelease
# Output: app/build/outputs/apk/release/app-release.apk

# Build and install on device
./gradlew installDebug

# Run tests
./gradlew test

# Check gradle dependencies
./gradlew dependencies
```

---

## Full Workflow

### Setup Everything

```bash
# 1. Run unified setup
/home/user/CRYPTOGRAM/setup-all.sh --all

# 2. Load environment
source /tmp/sword_build_env.sh

# 3. Verify installations
gcc-14 --version
java -version
cmake --version
```

### Build Both Projects

#### Build CRYPTOGRAM

```bash
cd /home/user/CRYPTOGRAM

# Configure and build
./setup.sh --gcc14 --build

# Or separately
./setup.sh
./build.sh

# Run
./build_release/bin/Telegram
```

#### Build SWORDCOMM

```bash
cd ~/Documents/SWORDCOMM

# Set Java path
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

# Build APK
./gradlew assembleDebug

# Install to device
./gradlew installDebug
```

---

## Dependencies Installed

### CRYPTOGRAM Requirements

**Build Tools:**
- GCC 14/15
- CMake 3.25+
- Git
- pkg-config

**Qt6 Libraries:**
- qt6-base-dev
- qt6-tools-dev
- qt6-image-formats-plugins
- qt6-declarative-dev

**System Libraries:**
- libssl-dev (OpenSSL)
- libopenal-dev (Audio)
- libpulse-dev (PulseAudio)
- libx11-dev, libxrandr-dev (X11)
- libxcb-* (XCB)
- libfontconfig1-dev, libfreetype6-dev

**Python (for TSM):**
- python3-dev
- python3-pip
- grpcio, cryptography, pyyaml, requests, sqlalchemy

**Optimization:**
- ccache (build caching)
- ninja-build (parallel compilation)

### SWORDCOMM Requirements

**Java:**
- openjdk-17-jdk (required for Gradle 8.11+)
- openjdk-17-jdk-headless

**Build Tools:**
- gradle
- git
- curl, wget, unzip

**Android SDK (optional, if using local SDK):**
- android-sdk
- android-sdk-build-tools
- android-sdk-platform-tools
- android-sdk-platforms

---

## Troubleshooting

### CRYPTOGRAM Issues

#### Qt6 Not Found
```bash
# Verify installation
dpkg -l | grep qt6-base

# Reinstall
sudo apt-get install qt6-base-dev qt6-base-private-dev

# Or specify path in CMake
cmake -DCMAKE_PREFIX_PATH=/usr/lib/x86_64-linux-gnu/cmake/Qt6 ..
```

#### GCC Not Found
```bash
# Check available versions
ls /usr/bin/gcc-*

# Install specific version
sudo apt-get install gcc-14 g++-14

# Or use default
export CC=gcc CXX=g++
```

#### Out of Memory During Build
```bash
# Reduce parallel jobs
./build.sh --jobs 2

# Or limit with make
cd build_release
make -j2
```

### SWORDCOMM Issues

#### Java 17 Not Found
```bash
# Install Java 17
sudo apt-get install openjdk-17-jdk openjdk-17-jdk-headless

# Verify
java -version
javac -version

# Set JAVA_HOME
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
```

#### Gradle Daemon Issues
```bash
# Kill daemon
cd ~/Documents/SWORDCOMM
./gradlew --stop

# Retry build
./gradlew assembleDebug
```

#### Build Cache Issues
```bash
# Clean build
./gradlew clean assembleDebug

# Full clean
rm -rf .gradle build app/build
./gradlew assembleDebug
```

#### Missing Android SDK
```bash
# Check SDK location
echo $ANDROID_HOME

# Gradle can auto-install, or set:
export ANDROID_HOME=$HOME/Android/Sdk

# Install SDK if needed
# Visit: https://developer.android.com/studio/command-line/sdkmanager
```

---

## Environment Variables

### Desktop (CRYPTOGRAM)

```bash
# GCC configuration
export CC=gcc-14
export CXX=g++-14
export CFLAGS="-march=native -O3"
export CXXFLAGS="-march=native -O3"

# Build location
export CRYPTOGRAM_BUILD_DIR="/home/user/CRYPTOGRAM/build_release"

# Optional: Telegram API (for full functionality)
export TDESKTOP_API_ID=YOUR_API_ID
export TDESKTOP_API_HASH=YOUR_API_HASH
```

### Android (SWORDCOMM)

```bash
# Java configuration
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

# Android SDK (if using local SDK)
export ANDROID_HOME=$HOME/Android/Sdk
export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools

# Gradle options (optional)
export GRADLE_OPTS="-Xmx4g"  # Increase heap if low memory
```

### Persistent Environment

Save to `~/.bashrc`:

```bash
# SWORD Projects Environment
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export ANDROID_HOME=$HOME/Android/Sdk
export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools

# Desktop
export CC=gcc-14
export CXX=g++-14
```

Then reload:
```bash
source ~/.bashrc
```

---

## Performance Tips

### CRYPTOGRAM Desktop

1. **Use ccache** for faster rebuilds
   ```bash
   sudo apt-get install ccache
   export CC="ccache gcc-14"
   export CXX="ccache g++-14"
   ```

2. **Use all CPU cores**
   ```bash
   ./build.sh --jobs $(nproc)
   ```

3. **Enable LTO** (Link-Time Optimization)
   ```bash
   export CFLAGS="-march=native -O3 -flto"
   export CXXFLAGS="-march=native -O3 -flto"
   ```

### SWORDCOMM Android

1. **Enable gradle build cache**
   ```bash
   ./gradlew assembleDebug --build-cache
   ```

2. **Increase Gradle heap** (if low memory)
   ```bash
   export GRADLE_OPTS="-Xmx2g"
   ```

3. **Parallel gradle workers**
   ```bash
   ./gradlew assembleDebug --max-workers=4
   ```

---

## Verification Checklist

```bash
# Desktop
[ ] CMake installed: cmake --version
[ ] GCC 14/15 installed: gcc-14 --version or gcc-15 --version
[ ] Qt6 installed: dpkg -l | grep qt6-base
[ ] Python deps: python3 -m pip list | grep grpcio
[ ] CRYPTOGRAM builds: cd /home/user/CRYPTOGRAM && ./build.sh

# Android
[ ] Java 17 installed: java -version
[ ] Gradle works: cd ~/Documents/SWORDCOMM && ./gradlew --version
[ ] Gradle builds: ./gradlew assembleDebug
[ ] (Optional) Device connected: adb devices
```

---

## Project Structure

### CRYPTOGRAM
```
/home/user/CRYPTOGRAM/
├── setup.sh              # Single-project setup
├── setup-all.sh          # Dual-project setup
├── build.sh              # Build wrapper
├── Telegram/
│   ├── CMakeLists.txt
│   ├── lib_tsm/          # TSM submodule (added)
│   ├── SourceFiles/
│   └── ...
├── cmake/
├── docs/
└── build_release/        # Build artifacts (created)
```

### SWORDCOMM
```
~/Documents/SWORDCOMM/
├── build.gradle.kts
├── gradlew              # Gradle wrapper
├── app/
│   ├── build/
│   └── src/
└── ...
```

---

## Next Steps

1. **Run setup**: `/home/user/CRYPTOGRAM/setup-all.sh`
2. **Load environment**: `source /tmp/sword_build_env.sh`
3. **Build desktop**: `cd /home/user/CRYPTOGRAM && ./build.sh`
4. **Build Android**: `cd ~/Documents/SWORDCOMM && ./gradlew assembleDebug`
5. **Deploy**: Run APK on device or run desktop binary

---

## Support

For issues or questions:

- **CRYPTOGRAM**: See `QUICK_START.md` and `SETUP_GUIDE.md`
- **Build Logs**: Check `build_release/cmake_build.log` or gradle output
- **Detailed Setup**: This guide (`DUAL_PROJECT_SETUP.md`)

Last Updated: November 2024
