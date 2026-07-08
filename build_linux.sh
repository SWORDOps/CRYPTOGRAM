#!/bin/bash

################################################################################
# CRYPTOGRAM Desktop Build Script (Linux/macOS)
# Focused build script for CRYPTOGRAM Qt/C++ Desktop application
################################################################################

set -Eeuo pipefail

# Colors
if [ -t 1 ] && [ "${TERM:-}" != "dumb" ] && [ -z "${NO_COLOR:-}" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    MAGENTA='\033[0;35m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    MAGENTA=''
    NC=''
fi

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

desktop_cmake_helpers_ready() {
    [ -f "$CRYPTOGRAM_ROOT/cmake/CMakeLists.txt" ] && \
    [ -f "$CRYPTOGRAM_ROOT/cmake/version.cmake" ] && \
    [ -f "$CRYPTOGRAM_ROOT/cmake/validate_special_target.cmake" ] && \
    [ -f "$CRYPTOGRAM_ROOT/cmake/options.cmake" ] && \
    [ -f "$CRYPTOGRAM_ROOT/cmake/external/qt/package.cmake" ]
}

print_cmake_submodule_diagnostics() {
    local cmake_dir="$CRYPTOGRAM_ROOT/cmake"

    echo "Expected root CMake helper files include:"
    echo "  $cmake_dir/CMakeLists.txt"
    echo "  $cmake_dir/version.cmake"
    echo "  $cmake_dir/validate_special_target.cmake"
    echo "  $cmake_dir/options.cmake"
    echo "  $cmake_dir/external/qt/package.cmake"
    echo ""

    if [ -d "$cmake_dir/.git" ] || [ -f "$cmake_dir/.git" ]; then
        echo "Detected git metadata under $cmake_dir."
        if git -C "$CRYPTOGRAM_ROOT" submodule status -- cmake >/dev/null 2>&1; then
            echo "Current submodule status:"
            git -C "$CRYPTOGRAM_ROOT" submodule status -- cmake 2>/dev/null || true
            echo ""
        fi

        if git -C "$cmake_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
            local deleted_count
            deleted_count="$(git -C "$cmake_dir" status --porcelain 2>/dev/null | awk '$1 ~ /^D/ { count++ } END { print count + 0 }')"
            if [ "$deleted_count" -gt 0 ]; then
                echo "The cmake submodule worktree exists in git metadata but files are deleted in the working tree."
                echo "This checkout cannot configure until that worktree is repopulated."
                echo ""
            fi
        fi
    fi
}

require_desktop_cmake_helpers() {
    if desktop_cmake_helpers_ready; then
        return 0
    fi

    echo ""
    print_error "Desktop build prerequisites are incomplete"
    print_cmake_submodule_diagnostics
    echo "This checkout expects a populated top-level 'cmake' git submodule."
    echo "Minimal next repair:"
    echo "  git -C \"$CRYPTOGRAM_ROOT/cmake\" status --short"
    echo "  git -C \"$CRYPTOGRAM_ROOT\" submodule update --init --recursive cmake"
    echo ""
    echo "If the submodule still points at deleted files locally, repopulate that worktree before retrying the build."
    echo "If the superproject continues to require an unfetchable cmake gitlink revision, the desktop tree cannot be reproduced from this snapshot alone."
    echo ""
    fail "Desktop CMake helper submodule is missing or incomplete"
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

if [ -t 1 ] && [ -n "${TERM:-}" ] && command -v clear >/dev/null 2>&1; then
    clear || true
fi
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
require_desktop_cmake_helpers

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
    
    CMAKE_ARGS=(
        -DCMAKE_BUILD_TYPE="$BUILD_TYPE"
        -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX"
        -DDESKTOP_APP_DISABLE_AUTOUPDATE=ON
        -DDESKTOP_APP_DISABLE_CRASH_REPORTS=ON
    )
    
    if [ -n "${TDESKTOP_API_ID:-}" ] && [ -n "${TDESKTOP_API_HASH:-}" ]; then
        CMAKE_ARGS+=("-DTDESKTOP_API_ID=${TDESKTOP_API_ID}" "-DTDESKTOP_API_HASH=${TDESKTOP_API_HASH}")
    fi
    
    if ! cmake "${CMAKE_ARGS[@]}" "$CRYPTOGRAM_ROOT"; then
        fail "CMake configuration failed"
    fi

    print_section "Building"

    # Build
    print_progress "Building with $JOBS jobs..."
    if ! cmake --build . --target Telegram --parallel "$JOBS"; then
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
echo "═══════════════════════════════════════════════════════════════════"
echo ""

} 2>&1 | tee "$BUILD_LOG"

print_info "Build log saved to: $BUILD_LOG"
echo ""
