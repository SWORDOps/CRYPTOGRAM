#!/bin/bash

################################################################################
# CRYPTOGRAM Build Script
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
CMAKE_BUILD_TYPE="Release"
JOBS=$(nproc)
VERBOSE=0
CLEAN_BUILD=0

print_info() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_step() {
    echo -e "${BLUE}→${NC} $1"
}

desktop_cmake_helpers_ready() {
    [ -f "$PROJECT_ROOT/cmake/version.cmake" ] && \
    [ -f "$PROJECT_ROOT/cmake/validate_special_target.cmake" ]
}

require_desktop_cmake_helpers() {
    if desktop_cmake_helpers_ready; then
        return 0
    fi

    print_error "Desktop CMake helper submodule is missing or incomplete"
    echo ""
    echo "Missing files:"
    echo "  $PROJECT_ROOT/cmake/version.cmake"
    echo "  $PROJECT_ROOT/cmake/validate_special_target.cmake"
    echo ""
    echo "Try:"
    echo "  git -C \"$PROJECT_ROOT\" submodule update --init --recursive cmake"
    echo ""
    echo "If that still fails, the pinned cmake submodule revision is currently unavailable."
    exit 1
}

show_help() {
    cat << EOF
CRYPTOGRAM Build Script

Usage: $0 [OPTIONS]

Options:
  --debug              Build in Debug mode
  --release            Build in Release mode (default)
  --clean              Clean build directory before building
  --verbose            Show build details
  --jobs N             Use N parallel jobs (default: $JOBS)
  --help               Show this help message

Examples:
  # Standard build
  $0

  # Debug build with verbose output
  $0 --debug --verbose

  # Clean and rebuild
  $0 --clean --release

  # Use custom parallel jobs
  $0 --jobs 16
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            CMAKE_BUILD_TYPE="Debug"
            shift
            ;;
        --release)
            CMAKE_BUILD_TYPE="Release"
            shift
            ;;
        --clean)
            CLEAN_BUILD=1
            shift
            ;;
        --verbose)
            VERBOSE=1
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

# Load environment if available
if [ -f "$PROJECT_ROOT/.env.sh" ]; then
    print_step "Loading environment from .env.sh..."
    source "$PROJECT_ROOT/.env.sh"
    print_info "Environment loaded"
fi

require_desktop_cmake_helpers

# Check if build directory exists and is configured
if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
    print_error "Build directory not configured. Run ./setup.sh first"
    exit 1
fi

# Clean if requested
if [ $CLEAN_BUILD -eq 1 ]; then
    print_step "Cleaning build directory..."
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    print_info "Build directory cleaned"

    # Re-run CMake
    print_step "Reconfiguring CMake..."
    cmake -DCMAKE_BUILD_TYPE="$CMAKE_BUILD_TYPE" "$PROJECT_ROOT"
fi

# Navigate to build directory
cd "$BUILD_DIR"

# Build
print_step "Building CRYPTOGRAM (${CMAKE_BUILD_TYPE})..."
print_info "Using $JOBS parallel jobs"

BUILD_CMD="cmake --build . --config $CMAKE_BUILD_TYPE --parallel $JOBS"
if [ $VERBOSE -eq 1 ]; then
    BUILD_CMD="$BUILD_CMD --verbose"
fi

if $BUILD_CMD; then
    print_info "Build completed successfully!"

    # Show executable location
    if [ -f "bin/Telegram" ]; then
        print_info "Executable: $(readlink -f bin/Telegram)"
        echo ""
        echo "Run with:"
        echo "  ./bin/Telegram"
        echo ""
    elif [ -f "Telegram/Telegram" ]; then
        print_info "Executable: $(readlink -f Telegram/Telegram)"
        echo ""
        echo "Run with:"
        echo "  ./Telegram/Telegram"
        echo ""
    fi
else
    print_error "Build failed!"
    echo "For more details, check the build output above"
    exit 1
fi
