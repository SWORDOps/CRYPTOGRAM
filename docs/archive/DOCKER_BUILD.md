# CRYPTOGRAM Docker Multi-Platform Build System

Complete Docker-based build infrastructure for building CRYPTOGRAM on Linux, Windows, and iOS (experimental).

---

## 📋 Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Platform Support](#platform-support)
- [Requirements](#requirements)
- [Building](#building)
- [CI/CD Integration](#cicd-integration)
- [Troubleshooting](#troubleshooting)
- [Advanced Usage](#advanced-usage)

---

## 🎯 Overview

This Docker build system provides:

- **✅ Fully supported**: Linux (x86_64) native builds
- **⚠️ Experimental**: Windows (x86_64) cross-compilation from Linux
- **❌ Stretch goal**: iOS builds (requires significant additional setup)
- **🚀 Automated**: GitHub Actions CI/CD pipeline
- **📦 Reproducible**: Consistent builds across environments
- **⚡ Cached**: Fast rebuilds with ccache integration

---

## 🚀 Quick Start

### Prerequisites

Install Docker:
```bash
# Ubuntu/Debian
sudo apt-get install docker.io docker-compose

# macOS
brew install docker docker-compose

# Or download from: https://docs.docker.com/get-docker/
```

### Build for Linux (Recommended)

```bash
cd docker
./build.sh --linux --release
```

Binary output: `out/CRYPTOGRAM-linux-x64`

### Build All Platforms

```bash
cd docker
./build.sh --all --release
```

---

## 🖥️ Platform Support

### Linux (✅ Fully Supported)

**Status**: Production-ready
**Build method**: Native Docker build
**Dependencies**: All included in Docker image

**Supported distributions**:
- Ubuntu 20.04+
- Debian 11+
- Fedora 35+
- Arch Linux (latest)
- Any Linux with glibc 2.31+

**Build time**: ~20-30 minutes (first build), ~5-10 minutes (cached)
**Artifacts**: Single statically-linked binary

#### Linux Build Details

The Linux build uses:
- **Base**: Ubuntu 22.04 LTS
- **Compiler**: Clang 14 with LLD linker
- **Qt**: Qt 5.15 from Ubuntu repositories
- **Libraries**: All dependencies statically linked
- **Output**: `CRYPTOGRAM-linux-x64` (single executable)

#### Linux-Specific Features

- X11 screen saver integration (idle detection)
- PulseAudio and ALSA support
- Wayland support via QtWayland
- Native system tray integration
- DBus notification support

### Windows (⚠️ Experimental)

**Status**: Experimental / Cross-compile
**Build method**: MinGW cross-compilation from Linux
**Dependencies**: Requires Qt for MinGW (not included)

**Challenges**:
- Qt for Windows (MinGW) must be provided separately
- Some Windows-specific features may not work
- Cross-compilation complexity
- Limited testing

**Recommended alternative**: Use native Windows build (see [Native Windows Build](#native-windows-build))

#### Windows Cross-Compile Setup

If you want to attempt Windows cross-compilation:

1. **Download Qt for MinGW**:
   ```bash
   # Download from: https://www.qt.io/download-open-source
   # Extract to: /path/to/qt-mingw
   ```

2. **Mount Qt volume**:
   ```bash
   docker run --rm \
     -v $(pwd):/build/CRYPTOGRAM:ro \
     -v /path/to/qt-mingw:/opt/qt-mingw:ro \
     -v $(pwd)/out:/output \
     cryptogram-windows:latest --release
   ```

3. **Known limitations**:
   - Windows-specific libraries may be missing
   - Code signing not supported
   - Installer creation not supported

#### Native Windows Build

**Recommended approach** for production Windows builds:

Use GitHub Actions with Windows runner (see `.github/workflows/docker-build.yml`):

```yaml
build-windows-native:
  runs-on: windows-latest
  steps:
    - uses: actions/checkout@v4
    - uses: jurplel/install-qt-action@v3
      with:
        version: '6.5.0'
        arch: 'win64_msvc2019_64'
    - uses: ilammy/msvc-dev-cmd@v1
    - run: |
        mkdir build && cd build
        cmake .. -G "Visual Studio 17 2022" -A x64
        cmake --build . --config Release
```

Or build on actual Windows machine:

```powershell
# Install Visual Studio 2022
# Install Qt 6.5+
# Install CMake

mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### iOS (❌ Stretch Goal - Not Recommended)

**Status**: Not supported / Extremely difficult
**Build method**: Would require OSXCross + iOS SDK (not included)
**Dependencies**: macOS SDK, Xcode, Apple Developer account

**Why iOS builds are problematic**:

1. **Legal issues**:
   - Apple EULA restricts macOS to Apple hardware
   - Cannot legally redistribute macOS SDK or Xcode
   - Violates Apple's licensing terms

2. **Technical issues**:
   - Requires macOS SDK (cannot be included)
   - Requires Xcode (cannot be included)
   - Code signing requires Apple Developer account ($99/year)
   - iOS Simulator requires actual macOS
   - Telegram Desktop is Qt-based (not iOS-native)

3. **Architectural issues**:
   - Telegram Desktop: Qt/C++ (Desktop platforms)
   - Telegram iOS: Swift/Objective-C (Separate codebase)
   - These are **incompatible** - cannot directly port

**Recommended alternatives**:

1. **Use Telegram iOS source code**:
   - Official: https://github.com/TelegramMessenger/Telegram-iOS
   - Native Swift/Objective-C implementation
   - Properly maintained and supported

2. **Build on macOS natively**:
   - Install Xcode from App Store
   - Use `xcodebuild` for building
   - Proper code signing and provisioning

3. **Use GitHub Actions with macOS runner**:
   ```yaml
   build-ios:
     runs-on: macos-latest
     steps:
       - uses: actions/checkout@v4
       - run: xcodebuild build ...
   ```

4. **Fork Telegram-iOS for CRYPTOGRAM features**:
   - Port Double Ratchet to Swift
   - Implement Monero mining (if allowed by Apple - unlikely)
   - Submit to App Store (will face review challenges)

**Bottom line**: Don't use Docker for iOS builds. Use native macOS + Xcode.

---

## 📦 Requirements

### System Requirements

- **Docker**: Version 20.10+ (with BuildKit support)
- **Disk space**: ~10GB for build artifacts and caches
- **RAM**: 4GB minimum, 8GB recommended
- **CPU**: Multi-core recommended for faster builds

### For Development

```bash
# Check Docker version
docker --version  # Should be 20.10+

# Check Docker is running
docker ps

# Check disk space
df -h
```

---

## 🔨 Building

### Using the Universal Build Script

The `docker/build.sh` script handles everything:

```bash
cd docker

# Build for Linux
./build.sh --linux

# Build for Windows (cross-compile - experimental)
./build.sh --windows

# Build for all platforms
./build.sh --all

# Build in debug mode
./build.sh --linux --debug

# Use 16 parallel jobs
./build.sh --linux --jobs 16

# Show help
./build.sh --help
```

### Using Docker Directly

#### Linux Build

```bash
# Build Docker image
docker build -t cryptogram-linux:latest docker/linux/

# Run build
docker run --rm \
  -v $(pwd):/build/CRYPTOGRAM:ro \
  -v $(pwd)/out:/output \
  -v cryptogram-ccache:/build/.ccache \
  cryptogram-linux:latest --release

# Binary output: out/CRYPTOGRAM-linux-x64
```

#### Windows Build

```bash
# Build Docker image
docker build -t cryptogram-windows:latest docker/windows/

# Run build (will likely fail without Qt)
docker run --rm \
  -v $(pwd):/build/CRYPTOGRAM:ro \
  -v $(pwd)/out:/output \
  cryptogram-windows:latest --release
```

### Using Docker Compose

```bash
cd docker

# Build all images
docker-compose build

# Build Linux
docker-compose run --rm linux

# Build Windows
docker-compose run --rm windows

# Build everything
docker-compose up
```

### Build Options

| Option | Description |
|--------|-------------|
| `--release` | Release build (optimized, no debug symbols) |
| `--debug` | Debug build (with debug symbols, not optimized) |
| `--relwithdebinfo` | Release with debug info |
| `--jobs N` | Use N parallel compilation jobs |
| `--clean` | Clean build directory before building |

---

## 🤖 CI/CD Integration

### GitHub Actions

The included GitHub Actions workflow (`.github/workflows/docker-build.yml`) automatically builds CRYPTOGRAM on every push and pull request.

**Features**:
- ✅ Builds Linux (Docker)
- ✅ Builds Windows (native Windows runner)
- ✅ Caches Docker layers for faster builds
- ✅ Uploads build artifacts
- ✅ Creates releases on tags

**Triggers**:
- Push to `main`, `master`, `develop`, or `claude/*` branches
- Pull requests to `main`, `master`, or `develop`
- Tags starting with `v*` (creates GitHub release)
- Manual workflow dispatch

**Artifacts**:
- `cryptogram-linux-x64` - Linux binary
- `cryptogram-windows-x64-native` - Windows binary (from native build)

#### Manual Trigger

From GitHub web interface:
1. Go to "Actions" tab
2. Select "Docker Multi-Platform Build"
3. Click "Run workflow"
4. Choose platform (linux, windows, all)

#### Creating a Release

```bash
# Tag a release
git tag v1.0.0
git push origin v1.0.0

# GitHub Actions will automatically:
# - Build for all platforms
# - Create GitHub release
# - Upload binaries
```

### GitLab CI

Example `.gitlab-ci.yml`:

```yaml
stages:
  - build

build-linux:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  script:
    - cd docker
    - docker build -t cryptogram-linux linux/
    - docker run --rm -v $CI_PROJECT_DIR:/build/CRYPTOGRAM:ro -v $CI_PROJECT_DIR/out:/output cryptogram-linux --release
  artifacts:
    paths:
      - out/CRYPTOGRAM-linux-x64
    expire_in: 1 week
```

### Jenkins

Example `Jenkinsfile`:

```groovy
pipeline {
    agent any
    stages {
        stage('Build Linux') {
            steps {
                sh 'cd docker && ./build.sh --linux --release'
            }
        }
        stage('Archive') {
            steps {
                archiveArtifacts artifacts: 'out/*', fingerprint: true
            }
        }
    }
}
```

---

## 🐛 Troubleshooting

### Common Issues

#### "Docker daemon not running"

**Solution**:
```bash
# Start Docker
sudo systemctl start docker  # Linux
open -a Docker  # macOS

# Verify
docker ps
```

#### "Permission denied" when running Docker

**Solution**:
```bash
# Add user to docker group (Linux)
sudo usermod -aG docker $USER
newgrp docker

# Or run with sudo
sudo docker ...
```

#### "No space left on device"

**Solution**:
```bash
# Clean up Docker
docker system prune -a
docker volume prune

# Remove old images
docker image prune -a

# Check disk space
df -h
```

#### "CMake configuration failed"

**Causes**:
- Missing dependencies in Docker image
- Source code issues
- CMakeLists.txt errors

**Solution**:
```bash
# Check Docker logs
docker logs <container_id>

# Run interactively for debugging
docker run -it --entrypoint /bin/bash cryptogram-linux
```

#### "Build fails with Qt errors" (Windows)

**Cause**: Qt for MinGW not provided

**Solution**: Either provide Qt for MinGW or use native Windows build (recommended)

#### "ccache fills up disk"

**Solution**:
```bash
# Set ccache size limit
docker run --rm -it cryptogram-linux /bin/bash
ccache -M 5G  # Set max 5GB

# Or clean ccache
docker volume rm cryptogram-ccache-linux
```

### Getting More Information

```bash
# View Docker logs
docker logs <container_id>

# Run container interactively
docker run -it --entrypoint /bin/bash cryptogram-linux:latest

# Inside container, manually run build
cd /build/CRYPTOGRAM
mkdir build && cd build
cmake ..
cmake --build . --verbose
```

### Performance Issues

**Problem**: Slow builds

**Solutions**:
1. Use more parallel jobs: `--jobs $(nproc)`
2. Enable BuildKit: `export DOCKER_BUILDKIT=1`
3. Use SSD for Docker storage
4. Increase Docker memory/CPU limits
5. Use ccache volumes for faster rebuilds

**Problem**: Docker using too much disk space

**Solution**:
```bash
# Check Docker disk usage
docker system df

# Clean up
docker system prune -a
docker builder prune
```

---

## 🚀 Advanced Usage

### Custom Build Configuration

#### Build with Custom API Keys

```bash
docker run --rm \
  -v $(pwd):/build/CRYPTOGRAM:ro \
  -v $(pwd)/out:/output \
  -e TDESKTOP_API_ID=your_api_id \
  -e TDESKTOP_API_HASH=your_api_hash \
  cryptogram-linux:latest --release
```

#### Build Specific Target

```bash
# Inside container
docker run -it --entrypoint /bin/bash cryptogram-linux:latest

# Manual build
cd /build/CRYPTOGRAM
mkdir build && cd build
cmake ..
cmake --build . --target CRYPTOGRAM
```

### Multi-Stage Builds

For smaller images, use multi-stage builds:

```dockerfile
# Build stage
FROM ubuntu:22.04 AS builder
# ... build dependencies and build ...

# Runtime stage
FROM ubuntu:22.04
COPY --from=builder /build/CRYPTOGRAM/build/CRYPTOGRAM /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/CRYPTOGRAM"]
```

### Cross-Architecture Builds

Build for ARM64:

```bash
# Set up QEMU for cross-arch builds
docker run --privileged --rm tonistiigi/binfmt --install all

# Build for ARM64
docker buildx build --platform linux/arm64 -t cryptogram-linux-arm64 docker/linux/

# Or build multi-arch
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t cryptogram-linux:latest \
  docker/linux/
```

### Custom Build Scripts

Create your own build script:

```bash
#!/bin/bash
# custom-build.sh

docker build -t my-cryptogram docker/linux/

docker run --rm \
  -v $(pwd):/build/CRYPTOGRAM:ro \
  -v $(pwd)/out:/output \
  -e CMAKE_FLAGS="-DCUSTOM_OPTION=ON" \
  my-cryptogram:latest --release
```

### Development Workflow

For development, mount source as read-write:

```bash
docker run --rm -it \
  -v $(pwd):/build/CRYPTOGRAM \
  --entrypoint /bin/bash \
  cryptogram-linux:latest

# Inside container, edit and rebuild
cd /build/CRYPTOGRAM
mkdir build && cd build
cmake .. && cmake --build .
```

### Debugging Failed Builds

```bash
# Keep container after failure
docker run -it \
  -v $(pwd):/build/CRYPTOGRAM:ro \
  --entrypoint /bin/bash \
  cryptogram-linux:latest

# Inside container
cd /build/CRYPTOGRAM
mkdir build && cd build
cmake .. --trace  # Verbose CMake
cmake --build . --verbose  # Verbose build
```

---

## 📊 Build Matrix

| Platform | Method | Docker | Status | Recommended |
|----------|--------|--------|--------|-------------|
| Linux x64 | Native | ✅ Yes | ✅ Production | ✅ Yes |
| Linux ARM64 | Cross | ✅ Yes | ⚠️ Experimental | ⚠️ Maybe |
| Windows x64 | Cross-compile | ✅ Yes | ⚠️ Experimental | ❌ No |
| Windows x64 | Native | ❌ No | ✅ Production | ✅ Yes |
| macOS x64 | Native | ❌ No | ✅ Production | ✅ Yes (on macOS) |
| macOS ARM64 | Native | ❌ No | ✅ Production | ✅ Yes (on macOS) |
| iOS | OSXCross | ⚠️ Partial | ❌ Not working | ❌ No |

---

## 📚 Additional Resources

- **Docker Documentation**: https://docs.docker.com/
- **Telegram Desktop Build Instructions**: https://github.com/telegramdesktop/tdesktop/blob/dev/docs/building-cmake.md
- **CMake Documentation**: https://cmake.org/documentation/
- **GitHub Actions**: https://docs.github.com/en/actions

---

## 🤝 Contributing

To improve the Docker build system:

1. Test builds on your platform
2. Report issues with detailed logs
3. Submit PRs for improvements
4. Update documentation

---

## 📄 License

Same as CRYPTOGRAM - see main repository LICENSE file.

---

## 📞 Support

For build issues:
1. Check this documentation
2. Check [Troubleshooting](#troubleshooting) section
3. Review Docker logs
4. Open GitHub issue with logs

---

**Happy Building! 🚀**
