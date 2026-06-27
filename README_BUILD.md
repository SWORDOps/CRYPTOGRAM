# 🚀 CRYPTOGRAM Build System

Canonical Linux desktop build command: `./build_linux.sh`  
Desktop claim/status source of truth: `docs/status/DESKTOP_BUILD_ALIGNMENT.md`


---

## ⚡ Quick Start (Choose One)

### Build CRYPTOGRAM Desktop ONLY (canonical)
```bash
./build_linux.sh
```
**Time:** 35-90 minutes | **Output:** Linux desktop app

### Build CRYPTOGRAM Android Android ONLY
```bash
./build_android.sh /path/to/swordcomm
```
**Time:** 15-20 minutes | **Output:** Android APK/AAB

### Build BOTH (Interactive Menu)
```bash
./build_everything.sh
```
**Time:** 60-95 minutes | **Output:** Both apps with master log

---

## 📊 Build System Overview

```
┌──────────────────────────────────────────────────────────┐
├──────────────────────────────────────────────────────────┤
│                                                          │
│  build_all.sh ─────────────┐                            │
│  (CRYPTOGRAM Desktop)      │                            │
│  • Ada library builder     │  ┌─ build_everything.sh  │
│  • Protobuf compiler       ├─┤  (Master Coordinator)   │
│  • CMake configuration     │  │  • Interactive menu    │
│  • C++/Qt compilation      │  │  • Handles both builds │
│                            │  │  • Master logging      │
│  build_android.sh ─────────┘  │                       │
│  (CRYPTOGRAM Android Android)           │                       │
│  • Gradle configuration        │                       │
│  • Kotlin/Java compilation  └─ Runs both in sequence   │
│  • APK/AAB packaging                                   │
│  • Optional signing                                    │
│                                                        │
│  ✓ Python gRPC server ready                           │
│  ✓ Secure YubiKey support                             │
│  ✓ Environment setup provided                         │
└──────────────────────────────────────────────────────────┘
```

---

## 🎯 What's Included

### Build Scripts (In Root)
```
✓ build_linux.sh        - canonical desktop entrypoint
✓ build_all.sh          - desktop orchestrator/wrapper
✓ build_android.sh      - CRYPTOGRAM Android Android builder
✓ build_everything.sh   - Master orchestrator (menu-driven)
```

### Documentation
```
✓ BUILD_SYSTEM.md       - Complete reference guide
✓ BUILD_INSTRUCTIONS.md - Step-by-step guide
✓ BUILD_STATUS.md       - Technical analysis
✓ SETUP_GUIDE.md        - Configuration guide
✓ This file (README_BUILD.md)
```

```
✓ Python environment configured
✓ gRPC server ready (port 50051)
✓ Secure config with YubiKey
✓ Environment setup script
```

---

## 📈 Build Timeline

### CRYPTOGRAM Only
| Step | Time | Notes |
|------|------|-------|
| Ada library | ~1 min | Very fast |
| Protobuf | ~15 min | Large C++ lib |
| CMake config | ~3 min | Dependency check |
| CRYPTOGRAM build | ~30-60 min | **Main step** |
| Verification | ~1 min | Checks executable |
| **Total** | **50-80 min** | Depends on CPU cores |

### CRYPTOGRAM Android Only
| Step | Time | Notes |
|------|------|-------|
| Setup | ~2 min | Config check |
| Gradle build | ~10-15 min | APK/AAB compile |
| Sign | ~1 min | Release only |
| Verify | ~1 min | Artifact check |
| **Total** | **15-20 min** | Much faster |

### Both Together
```
CRYPTOGRAM (50-80 min) + CRYPTOGRAM Android (15-20 min)
        = 65-100 minutes (sequential)
        or 50-80 minutes (if optimized)
```

---

## 🔧 System Requirements

### Minimum
```
RAM:        4GB available
Disk:       4GB free
CPU:        4 cores (2+ cores per job)
Internet:   Required (for cloning deps)
```

### Recommended
```
RAM:        16GB+ free (compilation is memory-intensive)
Disk:       10GB free
CPU:        8+ cores
SSD:        Yes (much faster)
```

> **⚠️ OOM Prevention**: Each `cc1plus` process can consume 1-3GB RAM. With 16 cores, the build can spawn 48+ concurrent processes. If you have less than 16GB free RAM, limit parallelism:
> ```bash
> JOBS=4 ./build_linux.sh
> # Or with direct CMake:
> cmake --build build_test --parallel 4
> ```

### For CRYPTOGRAM Only
```
OS:         Linux (Ubuntu 24.04+)
Compiler:   GCC 13+ (auto-detected)
CMake:      3.20+
Git:        Any version
```

### For CRYPTOGRAM Android Only
```
OS:         Linux/macOS/Windows
Java:       JDK 11+
Gradle:     7.0+ (bundled)
Docker:     Optional (for isolated builds)
```

---

## 🎮 How to Use

### Method 1: Interactive Menu (Recommended)
```bash
# Start the master orchestrator
./build_everything.sh

# Choose from menu:
# 1) CRYPTOGRAM Desktop only
# 2) CRYPTOGRAM Android Android only
# 3) Both CRYPTOGRAM and CRYPTOGRAM Android
# 4) Skip builds (verify only)

# Follow prompts for Android signing (optional)
```

### Method 2: Direct Script
```bash
# Build CRYPTOGRAM alone (canonical)
./build_linux.sh

# Optional wrapper/orchestrator
./build_all.sh

# Build CRYPTOGRAM Android alone
./build_android.sh /path/to/swordcomm

# Build with signing (Android)
export CI_KEYSTORE_PATH="/path/to/keystore.jks"
export CI_KEYSTORE_PASSWORD="password"
export CI_KEYSTORE_ALIAS="key_alias"
./build_android.sh /path/to/swordcomm
```

### Method 3: Script Chaining
```bash
# Run multiple scripts in sequence
./build_all.sh && ./build_android.sh /path/to/swordcomm
```

---

## 📍 Finding Outputs

### CRYPTOGRAM Desktop
```
Location:  <CRYPTOGRAM_ROOT>/build_release/bin/Telegram
Size:      100-200MB
Type:      Linux ELF executable
Run:       ./build_release/bin/Telegram
```

### CRYPTOGRAM Android Android (Debug)
```
Location:  /path/to/swordcomm/build/outputs/apk/debug/app-debug.apk
Size:      30-60MB
Type:      Android APK
Install:   adb install app-debug.apk
```

### CRYPTOGRAM Android Android (Release)
```
Location:  /path/to/swordcomm/build/outputs/bundle/release/app-release.aab
Size:      30-80MB
Type:      Android App Bundle
Upload:    Google Play Console
```

### Build Logs
```
CRYPTOGRAM: /tmp/cryptogram_build_YYYYMMDD_HHMMSS.log
CRYPTOGRAM Android:  /tmp/swordcomm_build_YYYYMMDD_HHMMSS.log
Both:       /tmp/cryptogram_swordcomm_build_YYYYMMDD_HHMMSS.log
```

---


### Start Both Together
```bash
cd <CRYPTOGRAM_ROOT>

./build_release/bin/Telegram
```

### Verify Integration
```bash
# Check environment
echo $CRYPTOGRAM_ROOT

# Test gRPC connection
python -c "import grpc; print('gRPC available')"
```

---

## 🛠️ Troubleshooting

### CRYPTOGRAM Build Fails
```bash
# Check logs
tail -100 /tmp/cryptogram_build_*.log

# Most common: Missing dependencies
# Solution: Run setup script first

# Or install manually
sudo apt-get install cmake build-essential git python3-dev
```

### CRYPTOGRAM Android Build Fails
```bash
# Check logs
tail -100 /tmp/swordcomm_build_*.log

# Most common: Java not found
# Solution: Install JDK
sudo apt-get install default-jdk

# Gradle cache issue
rm -rf ~/.gradle/
./build_android.sh /path/to/swordcomm
```

### Disk Space Issues
```bash
# Check available space
df -h /

# Clean up old builds
rm -rf /tmp/ada /tmp/protobuf /tmp/cryptogram*

# Or make space on disk and retry
```

### Signing Problems (Android)
```bash
# Verify keystore exists and password is correct
keytool -list -v -keystore /path/to/keystore.jks

# Get correct alias name
keytool -list -keystore /path/to/keystore.jks

# Then set environment variables correctly
export CI_KEYSTORE_PATH="/path/to/keystore.jks"
export CI_KEYSTORE_PASSWORD="correct_password"
export CI_KEYSTORE_ALIAS="correct_alias"
```

---

## 📊 Monitoring Builds

### Watch Progress
```bash
# From another terminal, follow the log
tail -f /tmp/cryptogram_build_*.log

# Or use grep to see just key events
tail -f /tmp/cryptogram_build_*.log | grep "✓\|✗\|error"
```

### Check System Resources
```bash
# Monitor CPU, memory, disk
watch -n 1 'ps aux | grep cmake; free -h; df -h'

# Or use htop
htop

# Or use iostat
iostat -x 1
```

---

## ✅ Post-Build Verification

### CRYPTOGRAM
```bash
# Check executable exists
ls -lah <CRYPTOGRAM_ROOT>/build_release/bin/Telegram

# Verify it's actually an executable
file ./build_release/bin/Telegram

# Check dependencies
ldd ./build_release/bin/Telegram

# Run it (requires X11/display)
./build_release/bin/Telegram --help
```

### CRYPTOGRAM Android
```bash
# Check APK exists
ls -lah build/outputs/apk/debug/app-debug.apk

# Verify it's a valid APK
file build/outputs/apk/debug/app-debug.apk

# Check APK contents
unzip -t build/outputs/apk/debug/app-debug.apk

# Install on device
adb install -r build/outputs/apk/debug/app-debug.apk
```

---

## 🔐 Security Best Practices

### For Signing
```bash
# Store keystore in secure location
chmod 600 /path/to/keystore.jks

# Never commit to version control
# Use environment variables (not hardcoded)
# Back up keystore in secure location
```

### For Credentials
```bash
# Use environment variables only
export CI_KEYSTORE_PASSWORD="secure_password"

# Not in scripts or config files
# Not in version control history
# Not in environment file history
```

---

## 📚 Documentation Guide

| Document | Purpose | Read When |
|----------|---------|-----------|
| **This file** | Overview & quick start | First time, orientation |
| **BUILD_SYSTEM.md** | Complete reference | Detailed questions |
| **BUILD_INSTRUCTIONS.md** | Step-by-step guide | Running for first time |
| **BUILD_STATUS.md** | Technical details | Debugging issues |
| **SETUP_GUIDE.md** | Configuration | Setting up environment |

---

## 🎉 Success Checklist

- [ ] Downloaded repository
- [ ] Ran `./build_everything.sh` (or specific script)
- [ ] Build completed without errors
- [ ] Checked `/tmp/*build*.log` for success message
- [ ] Located output files (Telegram binary or APK)
- [ ] Verified executables with `file` command
- [ ] Ran CRYPTOGRAM or installed CRYPTOGRAM Android APK
- [ ] Confirmed both CRYPTOGRAM and CRYPTOGRAM Android work

---

## 🚀 Next Steps

1. **Run a build:** Choose your method above and start building
2. **Monitor progress:** Check logs with `tail -f`
3. **Verify results:** Check artifacts in expected locations
5. **Deploy:** Follow platform-specific deployment guides

---

## 📞 Getting Help

### Check Logs First
```bash
# View build log
less /tmp/cryptogram_build_*.log
less /tmp/swordcomm_build_*.log

# Search for errors
grep -i error /tmp/*build*.log

# Get last 50 lines
tail -50 /tmp/*build*.log
```

### System Information
```bash
# What system are we on?
uname -a
lsb_release -a

# Available resources?
free -h
df -h
nproc

# Required tools?
which cmake git java gradle
```

### Common Solutions
```bash
# Update package manager
sudo apt-get update

# Install build tools
sudo apt-get install build-essential

# Install Java
sudo apt-get install default-jdk

# Install CMake
sudo apt-get install cmake
```

---

## 📝 Version Information

- **CRYPTOGRAM Android:** Android with dual-backend support
- **Build System:** Version 1.0 (Comprehensive dual-platform)

---

## 🎯 Final Notes

- All builds save detailed logs - check them if something fails
- Each script is independent - can run separately or together
- Real-time output shows exactly what's happening
- System resource checking prevents out-of-memory failures
- Comprehensive error detection stops build on problems

**Ready to build? Start with:**
```bash
./build_everything.sh
```

---

*Happy building! 🚀*
