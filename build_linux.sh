#!/bin/bash

################################################################################
# CRYPTOGRAM Desktop Build Script (Linux/macOS)
# Focused build script for CRYPTOGRAM Qt/C++ Desktop application
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRYPTOGRAM_ROOT="${CRYPTOGRAM_ROOT:-$SCRIPT_DIR}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
BUILD_DIR="${BUILD_DIR:-$CRYPTOGRAM_ROOT/build_${BUILD_TYPE,,}}"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
JOBS="${JOBS:-$(nproc)}"
LOG_DIR="/tmp/cryptogram_builds_root"
BUILD_DATE=$(date +%Y%m%d_%H%M%S)
BUILD_LOG="$LOG_DIR/linux_build_$BUILD_DATE.log"

# Create log directory
mkdir -p "$LOG_DIR"

# Functions
print_header() {
    echo -e "${MAGENTA}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${NC} $1"
    echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════════╝${NC}"
}

print_section() {
    echo -e "\n${CYAN}┌────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} $1"
    echo -e "${CYAN}└────────────────────────────────────────────────────────────────┘${NC}"
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

print_progress() {
    echo -e "${BLUE}→${NC} $1"
}

fail() {
    print_error "$1"
    echo ""
    echo "Build failed after $(($(date +%s) - START_TIME))s"
    echo "Log: $BUILD_LOG"
    exit 1
}

################################################################################
# MAIN BUILD
################################################################################

{
START_TIME=$(date +%s)

clear
print_header "CRYPTOGRAM Desktop Build (Linux)"

echo "Configuration:"
echo "  Build type: $BUILD_TYPE"
echo "  Source:     $CRYPTOGRAM_ROOT"
echo "  Build dir:  $BUILD_DIR"
echo "  Jobs:       $JOBS"
echo "  Log:        $BUILD_LOG"
echo ""

# Verify we're in the right directory
if [ ! -f "$CRYPTOGRAM_ROOT/CMakeLists.txt" ]; then
    fail "CRYPTOGRAM source not found at: $CRYPTOGRAM_ROOT"
fi

print_section "Pre-Build Checks"

# Check for build script
if [ -f "$CRYPTOGRAM_ROOT/build_all.sh" ]; then
    print_info "Using comprehensive build script: build_all.sh"
    echo ""

    # Export environment variables for build_all.sh
    export CRYPTOGRAM_ROOT
    export BUILD_TYPE
    export BUILD_DIR
    export JOBS

    # Run the comprehensive build script
    print_progress "Starting build..."
    echo ""

    if ! bash "$CRYPTOGRAM_ROOT/build_all.sh" "$@"; then
        fail "CRYPTOGRAM build failed"
    fi
else
    print_warning "build_all.sh not found, using fallback CMake build"
    echo ""

    print_section "CMake Configuration"

    # Create build directory
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    # Configure with CMake
    print_progress "Configuring CMake..."
    if ! cmake \
        -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
        -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
        -DDESKTOP_APP_DISABLE_AUTOUPDATE=ON \
        -DDESKTOP_APP_DISABLE_CRASH_REPORTS=ON \
        "$CRYPTOGRAM_ROOT"; then
        fail "CMake configuration failed"
    fi

    print_section "Building"

    # Build
    print_progress "Building with $JOBS jobs..."
    if ! cmake --build . --parallel "$JOBS"; then
        fail "Build failed"
    fi

    print_info "Build complete"
fi

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

print_header "✓ BUILD SUCCESSFUL"

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "BUILD SUMMARY"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "Build time: $((DURATION / 60))m $((DURATION % 60))s"
echo "Build type: $BUILD_TYPE"
echo ""
echo "Binary location:"
if [ -f "$BUILD_DIR/bin/Telegram" ]; then
    echo "  $BUILD_DIR/bin/Telegram"
elif [ -f "$BUILD_DIR/Telegram" ]; then
    echo "  $BUILD_DIR/Telegram"
else
    echo "  (Check $BUILD_DIR for binaries)"
fi
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "NEXT STEPS"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "Run CRYPTOGRAM:"
echo "  $BUILD_DIR/bin/Telegram"
echo ""
echo "Or with TSM integration:"
echo "  1. source .tsm_cryptogram_env.sh"
echo "  2. python -m Telegram.lib_tsm.mock_server.server &"
echo "  3. $BUILD_DIR/bin/Telegram"
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo ""

} 2>&1 | tee "$BUILD_LOG"

print_info "Build log saved to: $BUILD_LOG"
echo ""
