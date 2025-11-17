#!/bin/bash

################################################################################
# SWORD Projects Bootstrap Setup Script
# Handles both CRYPTOGRAM (Desktop) and SWORDCOMM (Android)
#
# This script sets up the complete development environment for:
# - CRYPTOGRAM: C++/Qt desktop application with TSM integration
# - SWORDCOMM: Android application using Gradle/Kotlin
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
DESKTOP_PROJECT="/home/user/CRYPTOGRAM"
ANDROID_PROJECT="$HOME/Documents/SWORDCOMM"
GCC_VERSION=14
SETUP_DESKTOP=0
SETUP_ANDROID=0
SETUP_ALL=0
VERBOSE=0

# Functions
print_header() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC} $1"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
}

print_section() {
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
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

show_help() {
    cat << EOF
SWORD Projects Bootstrap Setup

Unified setup for CRYPTOGRAM (Desktop) and SWORDCOMM (Android)

Usage: $0 [OPTIONS]

Options:
  --desktop            Setup CRYPTOGRAM (C++/Qt desktop)
  --android            Setup SWORDCOMM (Android/Gradle)
  --all                Setup both projects (default)
  --gcc14              Use GCC 14 for desktop build
  --gcc15              Use GCC 15 for desktop build
  --verbose            Show detailed output
  --help               Show this help message

Examples:
  # Setup both projects
  $0

  # Desktop only
  $0 --desktop

  # Android only
  $0 --android

  # Both with GCC 15
  $0 --all --gcc15 --verbose
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --desktop)
            SETUP_DESKTOP=1
            shift
            ;;
        --android)
            SETUP_ANDROID=1
            shift
            ;;
        --all)
            SETUP_ALL=1
            shift
            ;;
        --gcc14)
            GCC_VERSION=14
            shift
            ;;
        --gcc15)
            GCC_VERSION=15
            shift
            ;;
        --verbose)
            VERBOSE=1
            shift
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

# Default to all if none specified
if [ $SETUP_DESKTOP -eq 0 ] && [ $SETUP_ANDROID -eq 0 ] && [ $SETUP_ALL -eq 0 ]; then
    SETUP_ALL=1
fi

if [ $SETUP_ALL -eq 1 ]; then
    SETUP_DESKTOP=1
    SETUP_ANDROID=1
fi

# Main script
print_header "SWORD Projects Bootstrap Setup"

echo "System Information:"
echo "  OS: $(lsb_release -d | cut -f2)"
echo "  Kernel: $(uname -r)"
echo "  CPU: $(nproc) cores"
echo ""

# Check system
print_step "Checking system compatibility..."
if ! grep -qi "debian\|ubuntu" /etc/os-release; then
    print_warning "This script is optimized for Debian/Ubuntu"
fi

# Update package cache
print_step "Updating package cache..."
sudo apt-get update > /dev/null 2>&1
print_info "Package cache updated"

# ============================================================================
# DESKTOP SETUP (CRYPTOGRAM)
# ============================================================================

if [ $SETUP_DESKTOP -eq 1 ]; then
    print_section "CRYPTOGRAM Desktop Setup (C++/Qt with TSM)"

    # Check GCC
    print_step "Checking GCC $GCC_VERSION..."
    if ! command -v gcc-$GCC_VERSION &> /dev/null; then
        print_warning "GCC $GCC_VERSION not found, installing..."
        sudo apt-get install -y gcc-$GCC_VERSION g++-$GCC_VERSION > /dev/null 2>&1
    fi
    print_info "GCC $GCC_VERSION: $(gcc-$GCC_VERSION --version | head -1)"

    # Check CMake
    print_step "Checking CMake..."
    if ! command -v cmake &> /dev/null; then
        print_step "Installing CMake..."
        sudo apt-get install -y cmake > /dev/null 2>&1
    fi
    print_info "CMake: $(cmake --version | head -1 | awk '{print $NF}')"

    # Install desktop dependencies
    print_step "Installing desktop dependencies..."
    DESKTOP_PACKAGES=(
        "build-essential" "git" "pkg-config"
        "qt6-base-dev" "qt6-base-private-dev" "qt6-tools-dev" "qt6-tools-dev-tools"
        "qt6-image-formats-plugins" "qt6-l10n-tools" "qt6-declarative-dev"
        "libssl-dev" "libopenal-dev" "libpulse-dev"
        "libxcb-icccm4-dev" "libxcb-image0-dev" "libxcb-keysyms1-dev"
        "libxcb-randr0-dev" "libxcb-render-util0-dev" "libxcb-shape0-dev"
        "libxcb-xfixes0-dev" "libxcb-xinerama0-dev" "libxcb-xkb-dev"
        "libxkbcommon-dev" "libxkbcommon-x11-dev"
        "libfontconfig1-dev" "libfreetype6-dev" "libharfbuzz-dev"
        "libglib2.0-dev" "libdbus-1-dev" "libx11-dev"
        "libxrandr-dev" "libxi-dev"
        "python3-dev" "python3-pip" "python3-distutils"
        "yasm" "nasm" "ccache" "ninja-build"
    )

    for pkg in "${DESKTOP_PACKAGES[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg"; then
            if [ $VERBOSE -eq 1 ]; then
                print_step "Installing $pkg..."
            fi
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" > /dev/null 2>&1 || true
        fi
    done
    print_info "Desktop dependencies installed"

    # Install Python dependencies for TSM
    print_step "Installing Python dependencies (TSM)..."
    PYTHON_PACKAGES=("grpcio" "grpcio-tools" "cryptography" "pyyaml" "requests" "sqlalchemy" "protobuf")
    for pkg in "${PYTHON_PACKAGES[@]}"; do
        python3 -m pip install --quiet --upgrade "$pkg" 2>/dev/null || true
    done
    print_info "Python dependencies installed"

    # Create/verify CRYPTOGRAM build
    if [ -d "$DESKTOP_PROJECT" ]; then
        print_step "Setting up CRYPTOGRAM build..."
        mkdir -p "$DESKTOP_PROJECT/build_release"
        cd "$DESKTOP_PROJECT/build_release"

        # Check if already configured
        if [ ! -f "CMakeCache.txt" ]; then
            print_step "Configuring CMake for CRYPTOGRAM..."
            cmake -DCMAKE_BUILD_TYPE=Release \
                  -DCMAKE_C_COMPILER=gcc-$GCC_VERSION \
                  -DCMAKE_CXX_COMPILER=g++-$GCC_VERSION \
                  -DDESKTOP_APP_DISABLE_AUTOUPDATE=ON \
                  -DDESKTOP_APP_DISABLE_CRASH_REPORTS=ON \
                  .. > /dev/null 2>&1 || print_warning "CMake configuration had issues (may need Qt6)"
            print_info "CMake configured"
        else
            print_info "CRYPTOGRAM already configured"
        fi
    else
        print_warning "CRYPTOGRAM directory not found at $DESKTOP_PROJECT"
    fi

    echo ""
fi

# ============================================================================
# ANDROID SETUP (SWORDCOMM)
# ============================================================================

if [ $SETUP_ANDROID -eq 1 ]; then
    print_section "SWORDCOMM Android Setup (Gradle/Kotlin)"

    # Install Java 17 (required for Gradle 8.11+)
    print_step "Checking Java 17..."
    if ! command -v java &> /dev/null || ! java -version 2>&1 | grep -q "17"; then
        print_step "Installing OpenJDK 17..."
        sudo apt-get install -y openjdk-17-jdk openjdk-17-jdk-headless > /dev/null 2>&1
        print_info "Java 17 installed"
    else
        print_info "Java 17 found: $(java -version 2>&1 | head -1)"
    fi

    # Install Android SDK essentials
    print_step "Installing Android build tools..."
    ANDROID_PACKAGES=(
        "android-sdk"
        "android-sdk-build-tools"
        "android-sdk-platform-tools"
        "android-sdk-platforms"
    )
    for pkg in "${ANDROID_PACKAGES[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg"; then
            if [ $VERBOSE -eq 1 ]; then
                print_step "Installing $pkg..."
            fi
            sudo apt-get install -y "$pkg" > /dev/null 2>&1 || print_warning "$pkg not found in repos (optional)"
        fi
    done

    # Install additional Android build requirements
    print_step "Installing Android build requirements..."
    ANDROID_REQ=(
        "git"
        "curl"
        "wget"
        "unzip"
        "gradle"
    )
    for pkg in "${ANDROID_REQ[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg"; then
            sudo apt-get install -y "$pkg" > /dev/null 2>&1 || true
        fi
    done
    print_info "Android build tools installed"

    # Setup SWORDCOMM
    if [ -d "$ANDROID_PROJECT" ]; then
        print_step "Verifying SWORDCOMM project..."
        cd "$ANDROID_PROJECT"

        # Check if it's a Gradle project
        if [ -f "build.gradle.kts" ] || [ -f "build.gradle" ]; then
            print_info "SWORDCOMM Gradle project verified"

            # Set up gradle wrapper
            if [ ! -f "gradlew" ]; then
                print_step "Setting up Gradle wrapper..."
                gradle wrapper --gradle-version 8.11.1 2>/dev/null || print_warning "Could not setup wrapper"
            fi
        else
            print_warning "SWORDCOMM: Not a Gradle project or invalid structure"
        fi
    else
        print_warning "SWORDCOMM directory not found at $ANDROID_PROJECT"
    fi

    echo ""
fi

# ============================================================================
# ENVIRONMENT CONFIGURATION
# ============================================================================

print_section "Environment Configuration"

# Create unified environment script
ENV_SCRIPT="/tmp/sword_build_env.sh"
cat > "$ENV_SCRIPT" << 'EOF'
#!/bin/bash
# SWORD Projects Build Environment

# Desktop (CRYPTOGRAM)
export CC=gcc-14
export CXX=g++-14
export CFLAGS="-march=native -O3"
export CXXFLAGS="-march=native -O3"
export CRYPTOGRAM_BUILD_DIR="/home/user/CRYPTOGRAM/build_release"

# Android (SWORDCOMM)
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export ANDROID_HOME=${ANDROID_HOME:-$HOME/Android/Sdk}
export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools

echo "SWORD Build Environment Loaded:"
echo "  Desktop Compiler: $CC / $CXX"
echo "  Java Home: $JAVA_HOME"
echo "  Android SDK: $ANDROID_HOME"
EOF

chmod +x "$ENV_SCRIPT"
print_info "Environment script created: $ENV_SCRIPT"

# ============================================================================
# BUILD INSTRUCTIONS
# ============================================================================

print_section "Build Instructions"

echo ""
echo -e "${CYAN}CRYPTOGRAM (Desktop)${NC}"
echo "  Setup (if needed):     cd $DESKTOP_PROJECT && ./setup.sh"
echo "  Build:                 cd $DESKTOP_PROJECT && ./build.sh"
echo "  Run:                   $DESKTOP_PROJECT/build_release/bin/Telegram"
echo ""

echo -e "${CYAN}SWORDCOMM (Android)${NC}"
echo "  Setup environment:     source $ENV_SCRIPT"
echo "  Build Debug APK:       cd $ANDROID_PROJECT && ./gradlew assembleDebug"
echo "  Build Release APK:     cd $ANDROID_PROJECT && ./gradlew assembleRelease"
echo "  Install on device:     cd $ANDROID_PROJECT && ./gradlew installDebug"
echo ""

# ============================================================================
# FINAL SUMMARY
# ============================================================================

print_header "Setup Complete!"

echo ""
echo "Projects Setup:"
[ $SETUP_DESKTOP -eq 1 ] && echo "  ✓ CRYPTOGRAM Desktop (C++/Qt)" || echo "  ○ CRYPTOGRAM Desktop"
[ $SETUP_ANDROID -eq 1 ] && echo "  ✓ SWORDCOMM Android (Gradle)" || echo "  ○ SWORDCOMM Android"
echo ""

echo "Next Steps:"
echo "  1. Load environment: source $ENV_SCRIPT"
echo "  2. Build projects using instructions above"
echo "  3. For detailed help: see QUICK_START.md (Desktop) or docs (Android)"
echo ""

echo "For issues:"
echo "  - Desktop: Check build_release/cmake_build.log"
echo "  - Android: Check gradle output"
echo ""
