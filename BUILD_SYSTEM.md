
**Build CRYPTOGRAM Desktop + CRYPTOGRAM Android Android with automated scripts**

---

## 📋 Quick Start

### Build Everything at Once
```bash
cd <CRYPTOGRAM_ROOT>
./build_everything.sh
```

### Build Only CRYPTOGRAM Desktop
```bash
./build_all.sh
```

### Build Only CRYPTOGRAM Android Android
```bash
./build_android.sh /path/to/swordcomm
```

---

## 🎯 Available Scripts

### 1. `build_all.sh` - CRYPTOGRAM Desktop Builder

```bash
./build_all.sh
```

**What it does:**
- ✅ Builds Ada URL parser library
- ✅ Builds Protobuf library
- ✅ Configures CRYPTOGRAM with CMake
- ✅ Compiles CRYPTOGRAM desktop
- ✅ Verifies executable

**Duration:** 35-90 minutes (depending on CPU)

**Output:**
- Executable: `build_release/bin/Telegram`
- Log: `/tmp/cryptogram_build_YYYYMMDD_HHMMSS.log`

**Features:**
- Real-time verbose output
- Full error detection
- System resource checking
- Detailed timing information
- Clear next steps

---

### 2. `build_android.sh` - CRYPTOGRAM Android Android Builder
**Builds the Kotlin/Gradle Android application**

```bash
./build_android.sh /path/to/swordcomm
```

**What it does:**
- ✅ Cleans previous builds
- ✅ Configures Gradle project
- ✅ Builds Debug APK or Release AAB
- ✅ Signs release builds (with credentials)
- ✅ Verifies artifacts

**Duration:** 5-20 minutes

**Output:**
- Debug APK: `build/outputs/apk/debug/app-debug.apk`
- Release AAB: `build/outputs/bundle/release/app-release.aab`
- Log: `/tmp/swordcomm_build_YYYYMMDD_HHMMSS.log`

**Signing (Optional):**

For release builds, set environment variables before running:
```bash
export CI_KEYSTORE_PATH="/path/to/keystore.jks"
export CI_KEYSTORE_PASSWORD="your_password"
export CI_KEYSTORE_ALIAS="key_alias"
export CI_MAPS_API_KEY="optional_api_key"

./build_android.sh /path/to/swordcomm
```

Or provide interactively when prompted.

---

### 3. `build_everything.sh` - Master Orchestrator
**Build both CRYPTOGRAM and CRYPTOGRAM Android together**

```bash
./build_everything.sh
```

**What it does:**
- ✅ Interactive menu to select builds
- ✅ Can build one project or both
- ✅ Auto-detects CRYPTOGRAM Android location
- ✅ Handles signing configuration
- ✅ Generates master build log

**Duration:** 40-110 minutes (depending on choices)

**Menu Options:**
```
1) CRYPTOGRAM Desktop (C++/Qt) only
2) CRYPTOGRAM Android Android (Kotlin/Gradle) only
3) Both CRYPTOGRAM and CRYPTOGRAM Android
4) Skip builds (just verify setup)
```

**Master Log:** `/tmp/cryptogram_swordcomm_build_YYYYMMDD_HHMMSS.log`

---

## 🔧 System Requirements

### For CRYPTOGRAM Desktop
```
OS:          Linux (Ubuntu 24.04+ recommended)
Compiler:    GCC 13+ (auto-detected)
Memory:      4GB+ available
Disk space:  ~2GB for build
CMake:       3.20+
Git:         Any recent version
```

### For CRYPTOGRAM Android Android
```
OS:          Linux, macOS, Windows
Java:        JDK 11+ (for Gradle)
Android SDK: API 28+
Gradle:      7.0+ (bundled in project)
Docker:      Optional (for isolated builds)
Memory:      4GB+ available
Disk space:  ~2GB for build
```

### For Both
```
Total disk:  ~4GB available
Total memory: 8GB+ recommended
Network:     Required (clones dependencies)
```

---

## 📊 Build Flow

### CRYPTOGRAM Desktop Build
```
1. Clone & build Ada library                    (~1 min)
2. Clone & build Protobuf library               (~15 min)
3. Configure CRYPTOGRAM with CMake              (~3 min)
4. Compile CRYPTOGRAM desktop                   (~30-60 min)
5. Verify executable                            (~1 min)
                                                 ─────────
                                    Total:       ~50-80 min
```

### CRYPTOGRAM Android Android Build
```
1. Clean previous builds                        (~1 min)
2. Configure Gradle project                     (~2 min)
3. Build APK/AAB                                (~10-15 min)
4. Sign (release only)                          (~1 min)
5. Verify artifacts                             (~1 min)
                                                 ─────────
                                    Total:       ~15-20 min
```

### Combined Build (Both)
```
CRYPTOGRAM (50-80 min) + CRYPTOGRAM Android (15-20 min) + overlap (~5 min)
                                                 ─────────
                                    Total:       ~60-95 min
```

---

## 🚀 Running the Result

### CRYPTOGRAM Alone
```bash
<CRYPTOGRAM_ROOT>/build_release/bin/Telegram
```

### CRYPTOGRAM Android on Device/Emulator
```bash
# Install debug APK
adb install build/outputs/apk/debug/app-debug.apk

# Or launch from Android Studio
```

### CRYPTOGRAM Android to Play Store
```bash
# Upload the AAB from build_android.sh output to Google Play Console
```

```bash
cd <CRYPTOGRAM_ROOT>


./build_release/bin/Telegram
```

---

## 📝 Environment Variables

### For CRYPTOGRAM Build
```bash
CRYPTOGRAM_ROOT      # Override CRYPTOGRAM location (default: <CRYPTOGRAM_ROOT>)
```

### For CRYPTOGRAM Android Build
```bash
CI_KEYSTORE_PATH     # Path to keystore.jks for signing
CI_KEYSTORE_PASSWORD # Keystore password
CI_KEYSTORE_ALIAS    # Key alias in keystore
CI_MAPS_API_KEY      # Optional Google Maps API key
```

### Example
```bash
export CI_KEYSTORE_PATH="/home/john/my-release-key.jks"
export CI_KEYSTORE_PASSWORD="secure_password"
export CI_KEYSTORE_ALIAS="my-app-key"
export CI_MAPS_API_KEY="AIzaSyD..."

./build_android.sh /path/to/swordcomm
```

---

## 🔍 Monitoring Builds

### Watch Build in Real-Time (from another terminal)
```bash
# Follow CRYPTOGRAM build
tail -f /tmp/cryptogram_build_*.log

# Follow CRYPTOGRAM Android build
tail -f /tmp/swordcomm_build_*.log

# Follow combined build
tail -f /tmp/cryptogram_swordcomm_build_*.log
```

### Check Progress
```bash
# List active build processes
ps aux | grep "cmake\|gradle"

# Monitor system resources
top
# or
htop
```

---

## ❌ Troubleshooting

### Build Fails with "Missing Command"
```bash
# Check if required tools are available
which cmake git gcc g++

# For Android: check JDK
java -version

# Install missing tools
apt-get install cmake git build-essential default-jdk gradle
```

### Disk Space Full
```bash
# Check available space
df -h

# Clean build artifacts
rm -rf /tmp/ada /tmp/protobuf
./build_all.sh  # Will re-clone if needed
```

### Out of Memory
```bash
# Reduce parallel jobs
CMAKE_JOBS=4 ./build_all.sh

# Or modify build scripts
# Edit build_all.sh, change: $(nproc) to a smaller number
```

### Signing Credentials Wrong
```bash
# Use correct paths
ls -la /path/to/keystore.jks  # Verify it exists

# Test keystore
keytool -list -v -keystore /path/to/keystore.jks

# Get correct alias
keytool -list -keystore /path/to/keystore.jks
```

### CMake Finds Wrong Ada/Protobuf
```bash
# Clear CMake cache and try again
rm -rf <CRYPTOGRAM_ROOT>/build_release/CMakeCache.txt
rm -rf <CRYPTOGRAM_ROOT>/build_release/CMakeFiles
./build_all.sh
```

---

## 📦 Build Artifacts

### CRYPTOGRAM Desktop
```
<CRYPTOGRAM_ROOT>/
├── build_release/
│   ├── bin/Telegram           ← Main executable
│   ├── CMakeCache.txt
│   └── ... (intermediate build files)
```

### CRYPTOGRAM Android Android
```
/path/to/swordcomm/
├── build/
│   ├── outputs/apk/debug/app-debug.apk          ← Debug APK
│   └── outputs/bundle/release/app-release.aab   ← Release AAB
└── gradle.properties
```

---



### Automatic Setup
```bash
# 2. gRPC server configuration
# 3. Secure config with YubiKey support
# 4. Integration scripts generation
```

### Manual Setup
```bash
# Source environment


# In another terminal, run CRYPTOGRAM
./build_release/bin/Telegram
```

---

## 📋 Build Script Comparison

| Feature | build_all.sh | build_android.sh | build_everything.sh |
|---------|------------|-----------------|-------------------|
| Builds CRYPTOGRAM | ✓ | - | ✓ |
| Builds CRYPTOGRAM Android | - | ✓ | ✓ |
| Real-time output | ✓ | ✓ | ✓ |
| Auto-detection | ✓ | ✓ | ✓ |
| Signing support | - | ✓ | ✓ |
| Menu selection | - | - | ✓ |
| Master log | - | - | ✓ |
| Error recovery | ✓ | ✓ | ✓ |

---

## 📞 Getting Help

### Build Logs
All builds save detailed logs:
```bash
# View recent logs
ls -lart /tmp/*build*.log

# View specific log
less +F /tmp/cryptogram_build_20251117_170109.log

# Last 100 lines of log
tail -100 /tmp/cryptogram_build_20251117_170109.log
```

### Debug Output
```bash
# Run with full output visible
./build_all.sh 2>&1 | tee build_debug.log

# Check specific error
grep -i "error" /tmp/cryptogram_build_*.log
```

### Common Issues

**Issue:** CMake can't find dependencies
```bash
# Solution: Ensure /usr/local/lib is in library path
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
./build_all.sh
```

**Issue:** Java not found for Android build
```bash
# Solution: Install JDK
apt-get install default-jdk

# Or set Java path
export JAVA_HOME=/usr/lib/jvm/default-java
./build_android.sh
```

**Issue:** Gradle can't download dependencies
```bash
# Solution: Check internet connection
ping github.com

# Or manually run gradle
cd /path/to/swordcomm
./gradlew assembleDebug
```

---

## 🔗 Resources

- **CRYPTOGRAM:** https://github.com/SWORDOps/CRYPTOGRAM
- **CRYPTOGRAM Android:** https://github.com/SWORDOps/CRYPTOGRAM Android
- **Build Docs:** See `BUILD_INSTRUCTIONS.md` for detailed steps

---

## ✅ Verification Checklist

After build completes:

### CRYPTOGRAM
- [ ] Executable exists at `build_release/bin/Telegram`
- [ ] File size > 50MB (typical: 100-200MB)
- [ ] File is executable (`ls -lah` shows `x`)
- [ ] Can run: `./build_release/bin/Telegram` (may need display)

### CRYPTOGRAM Android
- [ ] APK/AAB exists in build/outputs/
- [ ] File size > 10MB (typical: 30-80MB)
- [ ] Can install on device: `adb install app-debug.apk`
- [ ] Signed correctly (release builds)

---

## 📈 Performance Tuning

### Faster Builds
```bash
# Use more CPU cores (default: auto-detect)
NUM_JOBS=16 ./build_all.sh

# Use SSD instead of HDD
# Use faster CPU cores (avoid low-power cores)
# Close other applications to free RAM
```

### Smaller Artifacts
```bash
# Strip debug symbols (in build_all.sh)
strip build_release/bin/Telegram

# Compress APK
# (Gradle does this automatically)
```

---

## 🔐 Security Notes

### Signing Keys
- Store keystore.jks in **secure location**
- **Never** commit to version control
- Use **strong passwords**
- **Back up** keystore file

### Credentials
- **Never** hardcode passwords in scripts
- Use **environment variables**
- Use **CI/CD secrets** for automated builds

### Binary Verification
```bash
# Verify CRYPTOGRAM binary
file ./build_release/bin/Telegram
ldd ./build_release/bin/Telegram  # Check dependencies

# Verify APK integrity
jarsigner -verify -verbose app-debug.apk
```

---

## 📖 Next Steps

1. **Run a build:** `./build_everything.sh`
2. **Check logs:** `tail -f /tmp/*build*.log`
3. **Run results:** See "Running the Result" section above
5. **Deploy:** Follow platform-specific deployment guides

---

*For more detailed information, see individual build scripts and documentation files.*
