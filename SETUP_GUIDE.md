# CRYPTOGRAM Setup & Build Guide


## Quick Start (Automated)

The easiest way to set up and build CRYPTOGRAM:

```bash
cd /home/user/CRYPTOGRAM

# Step 1: Run setup (installs all dependencies)
./setup.sh

# Step 2: Build the project
./build.sh

# Step 3: Run
./build_release/bin/Telegram
```

## Detailed Setup Instructions

### Prerequisites

- **Debian 6.17+** or Ubuntu 20.04+
- **GCC 14** or **GCC 15** installed
- **sudo** access (for installing packages)
- **~10-15 GB** free disk space
- **4+ GB** RAM (8+ GB recommended)
- **Multi-core processor** (build uses all cores)

### Step 1: Initial Setup

Run the automated setup script:

```bash
./setup.sh [OPTIONS]
```

**Options:**
- `--gcc14` - Use GCC 14 (default)
- `--gcc15` - Use GCC 15
- `--debug` - Configure for Debug build
- `--release` - Configure for Release (default)
- `--build` - Build immediately after configuration
- `--jobs N` - Use N parallel jobs

**Examples:**

```bash
# Interactive setup (default)
./setup.sh

# Full setup with GCC 15 and immediate build
./setup.sh --gcc15 --build

# Setup for debugging
./setup.sh --debug

# Custom parallel jobs
./setup.sh --build --jobs 8
```

### What the Setup Script Does

1. **Checks System Compatibility**
   - Verifies Debian/Ubuntu system
   - Checks GCC version availability

2. **Installs Dependencies**
   - Core build tools: gcc, cmake, git
   - Qt6 development libraries
   - System libraries (OpenSSL, OpenAL, X11, etc.)
   - Python 3 development headers
   - Build acceleration tools (ccache, ninja)

   - grpcio - gRPC framework
   - cryptography - Encryption libraries
   - pyyaml - Configuration files
   - sqlalchemy - Database ORM
   - requests - HTTP client
   - protobuf - Protocol buffers

4. **Configures Build Environment**
   - Sets up GCC alternatives
   - Configures CMake
   - Creates `.env.sh` for environment persistence

### Step 2: Configure CMake

The setup script automatically configures CMake. To manually reconfigure:

```bash
cd /home/user/CRYPTOGRAM
mkdir -p build_release
cd build_release

cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER=gcc-14 \
      -DCMAKE_CXX_COMPILER=g++-14 \
      -DCMAKE_PREFIX_PATH=/usr/lib/x86_64-linux-gnu/cmake/Qt6 \
      ..
```

### Step 3: Build

After setup, build with:

```bash
./build.sh [OPTIONS]
```

**Build Options:**
- `--release` - Release build (default, optimized)
- `--debug` - Debug build (with symbols for debugging)
- `--clean` - Clean build directory before building
- `--verbose` - Show detailed build output
- `--jobs N` - Use N parallel jobs

**Examples:**

```bash
# Standard release build
./build.sh

# Debug build with verbose output
./build.sh --debug --verbose

# Clean and rebuild
./build.sh --clean

# Fast build with many jobs
./build.sh --jobs 16
```

Or build manually:

```bash
cd build_release
make -j$(nproc)
```

### Step 4: Run CRYPTOGRAM

After successful build:

```bash
# From build_release directory
./bin/Telegram

# Or use full path
/home/user/CRYPTOGRAM/build_release/bin/Telegram
```

## Telegram API Configuration (Optional)

To enable full Telegram functionality:

1. **Get API Credentials**
   - Visit: https://my.telegram.org/apps
   - Create a new application
   - Copy your `API_ID` and `API_HASH`

2. **Set Environment Variables**
   ```bash
   export TDESKTOP_API_ID=YOUR_API_ID
   export TDESKTOP_API_HASH=YOUR_API_HASH
   ```

3. **Reconfigure CMake**
   ```bash
   cd build_release
   cmake -DTDESKTOP_API_ID=$TDESKTOP_API_ID \
         -DTDESKTOP_API_HASH=$TDESKTOP_API_HASH \
         ..
   ```

## Using Different GCC Versions

### Switch Between GCC 14 and GCC 15

```bash
# Use GCC 15
./setup.sh --gcc15 --build

# Or manually set alternatives
sudo update-alternatives --config gcc
sudo update-alternatives --config g++
```

### Set Environment Variables Directly

```bash
export CC=gcc-14
export CXX=g++-14
export CFLAGS="-march=native -O3"
export CXXFLAGS="-march=native -O3"
```

## Advanced Build Options

### Debug Build with Symbols

```bash
./setup.sh --debug
./build.sh --debug
```

### Profile-Guided Optimization

```bash
./setup.sh --gcc14 --build
# Additional optimization flags can be added to CFLAGS
```

### Static Linking (Advanced)

```bash
cmake -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=OFF \
      ..
```

## Troubleshooting

### Qt6 Not Found

```bash
# Verify Qt6 installation
dpkg -l | grep qt6-base

# If missing, reinstall
sudo apt-get install qt6-base-dev qt6-base-private-dev

# Provide explicit path
cmake -DCMAKE_PREFIX_PATH=/usr/lib/x86_64-linux-gnu/cmake/Qt6 ..
```

### GCC Version Not Found

```bash
# List available GCC versions
ls /usr/bin/gcc-*

# Install specific version
sudo apt-get install gcc-14 g++-14

# If not available, use default
export CC=gcc
export CXX=g++
```

### Build Fails with Memory Issues

Reduce parallel jobs:

```bash
./build.sh --jobs 2
```

Or set environment variable:

```bash
export MAKEFLAGS=-j2
./build.sh
```

### Missing Libraries at Runtime

```bash
# Check for missing dependencies
ldd ./build_release/bin/Telegram | grep "not found"

# Install missing packages
sudo apt-get install <package>-dev
```

### Python Dependencies Issues

```bash
# Reinstall Python dependencies
python3 -m pip install --upgrade --force-reinstall \
  grpcio cryptography pyyaml requests sqlalchemy

# Or use virtual environment
python3 -m venv venv
source venv/bin/activate
pip install grpcio cryptography pyyaml requests sqlalchemy
```

## Performance Optimization

### Compiler Flags

The setup script uses:
```bash
CFLAGS="-march=native -O3"
CXXFLAGS="-march=native -O3"
```

For more aggressive optimization:
```bash
export CFLAGS="-march=native -O3 -flto"
export CXXFLAGS="-march=native -O3 -flto"
```

### Build Caching

Enable ccache for faster rebuilds:

```bash
sudo apt-get install ccache
export CC="ccache gcc-14"
export CXX="ccache g++-14"
```

### Parallel Jobs

Use all CPU cores:
```bash
./build.sh --jobs $(nproc)
```

Or limit to avoid system hang:
```bash
./build.sh --jobs $(($(nproc) - 1))
```

## Environment Persistence

The setup script creates `.env.sh` which can be sourced for consistent environment:

```bash
source .env.sh
./build.sh
```

To modify environment:
```bash
export CMAKE_BUILD_TYPE=Debug
export CFLAGS="-march=native -g -O0"
./build.sh --debug
```

## Development Workflow

### Make Changes and Rebuild

```bash
# Edit source files...
cd build_release
make -j$(nproc)
```

### Clean Rebuild

```bash
./build.sh --clean --release
```

### Debug Build

```bash
./setup.sh --debug
./build.sh --debug --verbose
```



- **Hardware Security**: YubiKey 5 Series support
- **Session Management**: Multi-account switching
- **Post-Quantum Cryptography**: ML-KEM, ML-DSA support
- **Mobile Sync**: iOS/Android integration
- **gRPC API**: Remote session control


```bash

```

## Docker Build (Alternative)

If native compilation fails, use Docker:

```bash
./docker/build.sh --linux --release
```

This handles all dependencies automatically.

## System Requirements Summary

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU Cores | 2 | 4+ |
| RAM | 4 GB | 8+ GB |
| Disk Space | 10 GB | 20 GB |
| GCC | 14 | 15 |
| CMake | 3.25 | 3.28+ |
| Qt | 6.0 | 6.2+ |

## Additional Resources

- **CRYPTOGRAM Documentation**: See `docs/` directory
- **Build System**: See `CMakeLists.txt` and `Telegram/cmake/`
- **GitHub Repository**: https://github.com/SWORDOps/CRYPTOGRAM

## Getting Help

If you encounter issues:

1. Check the `cmake_configure.log` in build directory
2. Review `cmake_build.log` for build errors
3. Verify all dependencies are installed
4. Try reducing `--jobs` parameter
5. Use `--verbose` flag for detailed output

---

**Last Updated**: November 2024
**Tested on**: Debian 6.17, GCC 14, GCC 15
