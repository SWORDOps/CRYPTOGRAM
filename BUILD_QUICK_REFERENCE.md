# Build System Quick Reference

Quick reference for the CRYPTOGRAM build system v3.1.

---

## Quick Start

```bash
# Standard build (recommended)
./build_all.sh

# Custom installation prefix
./build_all.sh --prefix=$HOME/.local

# Resume interrupted build
./build_all.sh --resume

# Force clean rebuild
./build_all.sh --force

# Parallel build with 8 jobs
./build_all.sh -j8
```

---

## Common Issues & Solutions

### Issue: Permission Denied Errors

**Symptom:**
```
./build_all.sh: line 101: /tmp/cryptogram_builds/build_*.log: Permission denied
```

**Solution:**
The script now uses user-specific log directories. If you still see this:
```bash
export LOG_DIR=$HOME/.cache/cryptogram_builds
./build_all.sh
```

### Issue: Submodule Errors

**Symptom:**
```
```

**Solution:**
```bash
# Option 1: Use fix script
./fix_submodules.sh

# Option 2: Manual fix
./build_all.sh
```

See [SUBMODULE_FIX.md](./SUBMODULE_FIX.md) for detailed troubleshooting.

### Issue: Protobuf Verification Failed

**Symptom:**
```
Protobuf installation verification FAILED
```

**What it means:**
Protobuf libraries were not found after installation.

**Solution:**
```bash
# Check if Protobuf is in system paths
find /usr -name 'libprotobuf.so*' 2>/dev/null

# If not found, install system Protobuf
sudo apt-get install libprotobuf-dev  # Debian/Ubuntu
sudo dnf install protobuf-devel       # Fedora/RHEL

# Or use user prefix
./build_all.sh --prefix=$HOME/.local
```

### Issue: Build Interrupted

**Symptom:**
Build stopped due to Ctrl+C, power loss, or error.

**Solution:**
```bash
# Resume from where it stopped
./build_all.sh --resume

# Start fresh if resume doesn't work
./build_all.sh --force
```

### Issue: Insufficient Memory

**Symptom:**
```
Insufficient memory: 1GB (minimum 2GB required)
```

**Solution:**
- Close other applications to free memory
- Reduce parallel jobs: `./build_all.sh -j1`
- Add swap space (Linux):
  ```bash
  sudo fallocate -l 2G /swapfile
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  ```

---

## Command-Line Options

```
./build_all.sh [OPTIONS]

Options:
  -h, --help          Show help message
  -v, --version       Show script version
  --prefix=PATH       Installation prefix (default: /usr/local)
  -j, --jobs=N        Parallel jobs (default: auto-detected)
  --force             Force rebuild all components
  --resume            Resume from previous build
  --dry-run           Preview without executing
  --verbose           Enable verbose output
  -q, --quiet         Quiet mode
```

---

## Environment Variables

```bash
# Custom log directory
export LOG_DIR=/path/to/logs

# Installation prefix
export INSTALL_PREFIX=/usr/local

# Compiler override
export CC=gcc-12
export CXX=g++-12

# Compiler flags
export CFLAGS="-O3 -march=native"
export CXXFLAGS="-O3 -march=native"

# Parallel jobs
export JOBS=8

# Verbosity
export VERBOSE=1

# Force rebuild
export FORCE=1
```

---

## Log Files

Logs are saved to: `/tmp/cryptogram_builds_${USER}/` (or `$HOME/.cache/cryptogram_builds`)

```
build_*.log          Main build log with all output
errors_*.log         Error messages only
state_*.json         Build state for resume
summary_*.txt        Build summary with metrics
```

**View logs:**
```bash
# Main log
tail -f /tmp/cryptogram_builds_${USER}/build_*.log

# Errors only
cat /tmp/cryptogram_builds_${USER}/errors_*.log

# Build summary
cat /tmp/cryptogram_builds_${USER}/summary_*.txt
```

---

## Build Steps (9 total)

1. **System Requirements Check** - OS, memory, CPU, disk
2. **Tool Dependencies Check** - git, cmake, make, gcc, g++
3. **Permission Check** - Source directory, install prefix
4. **Git Submodules Check** - Initialize and update submodules
5. **Compiler Configuration** - Detect and configure C/C++ compilers
6. **Building Ada URL Parser** - Clone, build, install Ada library
7. **Building Protocol Buffers** - Clone, build, install Protobuf
8. **Configuring CRYPTOGRAM** - CMake configuration
9. **Building CRYPTOGRAM Desktop** - Compile main application

---

## System Requirements

**Minimum:**
- OS: Linux (Ubuntu 20.04+, Fedora 35+, etc.)
- Memory: 2GB RAM
- Disk: 5GB free space
- CPU: 2 cores
- Tools: git, cmake 3.16+, gcc/g++ or clang

**Recommended:**
- Memory: 4GB+ RAM
- Disk: 10GB+ free space
- CPU: 4+ cores
- Compiler: gcc-11+ or clang-12+

---

## Testing

```bash
# Run test suite
./test_build_fixes.sh

# Expected output
All tests passed! (X/12)

# Tests verify:
  1. User-specific log directories
  2. Log directory writability
  3. Log file creation
  4. Protobuf verification logic
  5. User isolation
  6. Verification messages
  7. Diagnostic output
  8. Unbound variable protection
  9. Enhanced logging system
  10. Build state management
  11. System validation
  12. Enhanced error handling
```

---

## Troubleshooting

### Build Fails at Step X

1. **Check logs:**
   ```bash
   tail -100 /tmp/cryptogram_builds_${USER}/build_*.log
   ```

2. **Check error log:**
   ```bash
   cat /tmp/cryptogram_builds_${USER}/errors_*.log
   ```

3. **Resume with verbose mode:**
   ```bash
   ./build_all.sh --resume --verbose
   ```

### Missing Dependencies

```bash
# Debian/Ubuntu
sudo apt-get install git cmake build-essential \
  qtbase5-dev qtwayland5 libqt5svg5-dev \
  libprotobuf-dev protobuf-compiler

# Fedora/RHEL
sudo dnf install git cmake gcc gcc-c++ \
  qt5-qtbase-devel qt5-qtwayland qt5-qtsvg-devel \
  protobuf-devel

# Verify installation
git --version
cmake --version
gcc --version
```

### Clean Everything and Start Over

```bash
# Remove all build artifacts
rm -rf build_release/
rm -rf /tmp/cryptogram_builds_${USER}/

# Remove installed libraries (if using user prefix)
rm -rf $HOME/.local/lib/libada*
rm -rf $HOME/.local/lib/libprotobuf*

# Clean submodules
git submodule deinit -f --all

# Start fresh
./build_all.sh --force
```

---

## Advanced Usage

### Custom Build Configuration

```bash
# Minimal build (single job, quiet)
./build_all.sh -j1 --quiet

# Development build with verbose output
./build_all.sh --verbose --prefix=$HOME/dev/cryptogram

# Production build with optimizations
export CFLAGS="-O3 -march=native -DNDEBUG"
export CXXFLAGS="-O3 -march=native -DNDEBUG"
./build_all.sh --force -j$(nproc)
```

### CI/CD Integration

```bash
# Non-interactive build for CI
export NONINTERACTIVE=1
./build_all.sh --prefix=/opt/cryptogram -j4

# Check exit code
if [ $? -eq 0 ]; then
  echo "Build successful"
else
  echo "Build failed"
  cat /tmp/cryptogram_builds_${USER}/errors_*.log
  exit 1
fi
```

---

## Help Resources

- **Build Script Help:** `./build_all.sh --help`
- **PR Summary:** [PR_SUMMARY.md](./PR_SUMMARY.md)
- **Submodule Guide:** [SUBMODULE_FIX.md](./SUBMODULE_FIX.md)
- **Changelog:** [CHANGELOG_BUILD_IMPROVEMENTS.md](./CHANGELOG_BUILD_IMPROVEMENTS.md)
- **Test Suite:** `./test_build_fixes.sh`

---

## Version Information

**Build System Version:** 3.1.0
**Branch:** claude/build-ada-protobuf-01Tpe3rvKAkdWnRVGPd3uLET
**Date:** November 18, 2025

**Check version:**
```bash
./build_all.sh --version
```

---

## Quick Diagnostic Commands

```bash
# System check
uname -a
free -h
df -h $HOME
nproc

# Tool versions
git --version
cmake --version
gcc --version
g++ --version

# Submodule status
git submodule status --recursive

# Build state (if exists)
cat /tmp/cryptogram_builds_${USER}/state_*.json

# Last build summary
cat /tmp/cryptogram_builds_${USER}/summary_*.txt
```

---

**Last Updated:** November 18, 2025
**Maintained By:** SWORDIntel/CRYPTOGRAM Team
