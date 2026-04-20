#!/bin/bash

################################################################################
# CRYPTOGRAM Bootstrap Setup Script
# For Debian Linux with gcc-14/gcc-15 support
#
# This script:
# - Installs all required dependencies
# - Configures the build environment
# - Sets up CMake configuration
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build_release"
GCC_VERSION=14
CMAKE_BUILD_TYPE="Release"
ENABLE_BUILD=0
JOBS=$(nproc)

# Functions
print_header() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC} $1"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
}

print_info() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_step() {
    echo -e "${BLUE}→${NC} $1"
}

# Parse arguments
show_help() {
    cat << EOF
CRYPTOGRAM Setup Bootstrap Script

Usage: $0 [OPTIONS]

Options:
  --gcc14              Use GCC 14 (default)
  --gcc15              Use GCC 15
  --debug              Configure for Debug build
  --release            Configure for Release build (default)
  --build              Build after configuration
  --jobs N             Use N parallel jobs (default: auto-detect = $JOBS)
  --help               Show this help message

Examples:
  # Install dependencies and configure (interactive)
  $0

  # Full setup with GCC 15 and immediate build
  $0 --gcc15 --build

  # Configure for debugging
  $0 --debug

  # Build with custom parallel jobs
  $0 --build --jobs 8
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --gcc14)
            GCC_VERSION=14
            shift
            ;;
        --gcc15)
            GCC_VERSION=15
            shift
            ;;
        --debug)
            CMAKE_BUILD_TYPE="Debug"
            shift
            ;;
        --release)
            CMAKE_BUILD_TYPE="Release"
            shift
            ;;
        --build)
            ENABLE_BUILD=1
            shift
            ;;
        --jobs)
            JOBS=$2
            shift 2
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Main script
print_header "CRYPTOGRAM Bootstrap Setup (Debian/Linux)"

# Check system
print_step "Checking system compatibility..."
if ! grep -qi "debian\|ubuntu" /etc/os-release; then
    print_warning "This script is optimized for Debian/Ubuntu. Some steps may differ on your system."
fi

# Check GCC availability
print_step "Checking GCC $GCC_VERSION availability..."
if ! command -v gcc-$GCC_VERSION &> /dev/null; then
    print_error "GCC $GCC_VERSION not found"
    print_info "Available GCC versions:"
    ls /usr/bin/gcc-* 2>/dev/null | grep -o 'gcc-[0-9]*' | sort -u || echo "None found"
    exit 1
fi
print_info "GCC $GCC_VERSION found: $(gcc-$GCC_VERSION --version | head -1)"

# Check CMake
print_step "Checking CMake..."
if ! command -v cmake &> /dev/null; then
    print_error "CMake not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y cmake
else
    print_info "CMake $(cmake --version | head -1 | awk '{print $NF}')"
fi

# Install system dependencies
print_step "Installing system dependencies..."
print_info "Updating package cache..."
sudo apt-get update > /dev/null 2>&1

# Core build tools
PACKAGES=(
    "build-essential"
    "cmake"
    "git"
    "pkg-config"
    "curl"
    "wget"
)

# Qt6 dependencies
PACKAGES+=(
    "qt6-base-dev"
    "qt6-base-private-dev"
    "qt6-tools-dev"
    "qt6-tools-dev-tools"
    "qt6-image-formats-plugins"
    "qt6-l10n-tools"
    "qt6-declarative-dev"
)

# System libraries
PACKAGES+=(
    "libssl-dev"
    "libopenal-dev"
    "libpulse-dev"
    "libxcb-icccm4-dev"
    "libxcb-image0-dev"
    "libxcb-keysyms1-dev"
    "libxcb-randr0-dev"
    "libxcb-render-util0-dev"
    "libxcb-shape0-dev"
    "libxcb-xfixes0-dev"
    "libxcb-xinerama0-dev"
    "libxcb-xkb-dev"
    "libxkbcommon-dev"
    "libxkbcommon-x11-dev"
    "libfontconfig1-dev"
    "libfreetype6-dev"
    "libharfbuzz-dev"
    "libglib2.0-dev"
    "libdbus-1-dev"
    "libx11-dev"
    "libxrandr-dev"
    "libxi-dev"
)

# Development tools
PACKAGES+=(
    "python3-dev"
    "python3-pip"
    "python3-distutils"
    "yasm"
    "nasm"
)

# Optional but useful
PACKAGES+=(
    "ccache"
    "ninja-build"
)

print_info "Installing ${#PACKAGES[@]} packages..."
for pkg in "${PACKAGES[@]}"; do
    if ! dpkg -l | grep -q "^ii  $pkg"; then
        print_step "Installing $pkg..."
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" > /dev/null 2>&1 || print_warning "Failed to install $pkg (non-critical)"
    else
        print_info "$pkg already installed"
    fi
done

PYTHON_PACKAGES=(
    "grpcio"
    "grpcio-tools"
    "cryptography"
    "pyyaml"
    "requests"
    "sqlalchemy"
    "protobuf"
)

for pkg in "${PYTHON_PACKAGES[@]}"; do
    print_step "Installing Python package: $pkg..."
    python3 -m pip install --upgrade "$pkg" 2>/dev/null || print_warning "Failed to install $pkg (non-critical)"
done

# Set up GCC environment
print_step "Configuring GCC $GCC_VERSION..."
export CC="gcc-$GCC_VERSION"
export CXX="g++-$GCC_VERSION"
export CFLAGS="-march=native -O3"
export CXXFLAGS="-march=native -O3"

print_info "CC: $CC"
print_info "CXX: $CXX"
print_info "CFLAGS: $CFLAGS"
print_info "CXXFLAGS: $CXXFLAGS"

# Update CMake alternatives (if needed)
print_step "Setting up compiler alternatives..."
if ! update-alternatives --list gcc &>/dev/null || [[ $(update-alternatives --list gcc | grep $GCC_VERSION) ]]; then
    sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-$GCC_VERSION 100 \
                             --slave /usr/bin/g++ g++ /usr/bin/g++-$GCC_VERSION \
                             --slave /usr/bin/cc cc /usr/bin/gcc-$GCC_VERSION \
                             --slave /usr/bin/c++ c++ /usr/bin/g++-$GCC_VERSION 2>/dev/null || true
    print_info "GCC alternatives updated"
fi

# Create build directory
print_step "Setting up build directory..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
print_info "Build directory: $BUILD_DIR"

# Configure CMake
print_step "Configuring CMake (${CMAKE_BUILD_TYPE})..."

# Detect Qt6 path
QT6_PATH=""
if [ -d "/usr/lib/x86_64-linux-gnu/cmake/Qt6" ]; then
    QT6_PATH="/usr/lib/x86_64-linux-gnu/cmake/Qt6"
elif [ -d "/usr/lib/cmake/Qt6" ]; then
    QT6_PATH="/usr/lib/cmake/Qt6"
fi

CMAKE_ARGS=(
    "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
    "-DCMAKE_C_COMPILER=${CC}"
    "-DCMAKE_CXX_COMPILER=${CXX}"
    "-DCMAKE_C_FLAGS=${CFLAGS}"
    "-DCMAKE_CXX_FLAGS=${CXXFLAGS}"
    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
)

# Add Qt6 path if found
if [ -n "$QT6_PATH" ]; then
    CMAKE_ARGS+=("-DCMAKE_PREFIX_PATH=${QT6_PATH}")
    print_info "Qt6 found at: $QT6_PATH"
fi

# Add Telegram API configuration
if [ -z "$TDESKTOP_API_ID" ] || [ -z "$TDESKTOP_API_HASH" ]; then
    print_warning "Telegram API credentials not set"
    print_info "To use the full application, set:"
    print_info "  export TDESKTOP_API_ID=<your-api-id>"
    print_info "  export TDESKTOP_API_HASH=<your-api-hash>"
    print_info "Get them from: https://my.telegram.org/apps"
else
    CMAKE_ARGS+=("-DTDESKTOP_API_ID=${TDESKTOP_API_ID}")
    CMAKE_ARGS+=("-DTDESKTOP_API_HASH=${TDESKTOP_API_HASH}")
    print_info "Using Telegram API credentials"
fi

# Additional CMake options
CMAKE_ARGS+=(
    "-DDESKTOP_APP_DISABLE_AUTOUPDATE=ON"
    "-DDESKTOP_APP_DISABLE_CRASH_REPORTS=ON"
)

# Run CMake
print_info "Running CMake configure..."
cmake "${CMAKE_ARGS[@]}" "$PROJECT_ROOT" 2>&1 | tee cmake_configure.log

if [ ${PIPESTATUS[0]} -ne 0 ]; then
    print_error "CMake configuration failed!"
    print_info "Check cmake_configure.log for details"
    exit 1
fi

print_info "CMake configuration completed successfully"

# Build if requested
if [ $ENABLE_BUILD -eq 1 ]; then
    print_step "Building CRYPTOGRAM..."
    print_info "Using $JOBS parallel jobs"

    if cmake --build . --config "$CMAKE_BUILD_TYPE" --parallel "$JOBS" 2>&1 | tee cmake_build.log; then
        print_info "Build completed successfully!"
        EXECUTABLE="./bin/Telegram"
        if [ -f "$EXECUTABLE" ]; then
            print_info "Executable: $EXECUTABLE"
            print_info "Run with: $EXECUTABLE"
        fi
    else
        print_error "Build failed!"
        print_info "Check cmake_build.log for details"
        exit 1
    fi
else
    print_info "Configuration complete!"
    echo ""
    print_step "Next steps:"
    echo "  1. Review CMake output above for any issues"
    echo "  2. Build with:"
    echo "     cd $BUILD_DIR"
    echo "     cmake --build . --config $CMAKE_BUILD_TYPE --parallel $JOBS"
    echo ""
    echo "  Or use make:"
    echo "     cd $BUILD_DIR"
    echo "     make -j$JOBS"
    echo ""
fi

echo ""
print_header "Setup Complete!"
print_info "Environment:"
print_info "  GCC: $GCC_VERSION"
print_info "  Build Type: $CMAKE_BUILD_TYPE"
print_info "  Build Dir: $BUILD_DIR"
print_info "  Parallel Jobs: $JOBS"

# Create environment setup file for future use
cat > "$PROJECT_ROOT/.env.sh" << EOF
#!/bin/bash
# CRYPTOGRAM Build Environment
export CC="gcc-$GCC_VERSION"
export CXX="g++-$GCC_VERSION"
export CFLAGS="-march=native -O3"
export CXXFLAGS="-march=native -O3"
export CMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}"
export BUILD_DIR="$BUILD_DIR"
EOF
chmod +x "$PROJECT_ROOT/.env.sh"
print_info "Environment saved to: .env.sh"

echo ""
echo "  python3 -m venv venv"
echo "  source venv/bin/activate"
echo "  pip install -r requirements.txt"
echo ""
