#!/bin/bash

################################################################################
# TSM + CRYPTOGRAM - Complete Automated Build Script
# Builds everything: ada, protobuf, CMake config, and CRYPTOGRAM desktop
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Logging
LOG_FILE="/tmp/cryptogram_build_$(date +%Y%m%d_%H%M%S).log"

# Functions
print_header() {
    echo -e "${MAGENTA}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${NC} $1"
    echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════════╝${NC}"
}

print_step() {
    echo -e "\n${CYAN}┌────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} STEP $1: $2"
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
    echo "Build log saved to: $LOG_FILE"
    exit 1
}

get_time() {
    date +"%Y-%m-%d %H:%M:%S"
}

################################################################################
# START
################################################################################

clear
print_header "TSM + CRYPTOGRAM Complete Build"

echo "Start time: $(get_time)"
echo "Log file: $LOG_FILE"
echo ""
echo "This script will:"
echo "  1. Build and install Ada URL parser library"
echo "  2. Build and install Protobuf library"
echo "  3. Configure CRYPTOGRAM with CMake"
echo "  4. Compile CRYPTOGRAM desktop application"
echo ""
echo "Estimated time: 35-90 minutes (depending on CPU)"
echo ""
read -p "Press ENTER to start, or Ctrl+C to cancel..."

{

################################################################################
# STEP 1: Build Ada
################################################################################

print_step "1" "Building Ada URL Parser"

print_progress "Cloning Ada repository..."
rm -rf /tmp/ada 2>/dev/null || true
git clone https://github.com/ada-url/ada.git /tmp/ada > /dev/null 2>&1
print_info "Repository cloned"

print_progress "Configuring Ada build..."
cd /tmp/ada
mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release > /dev/null 2>&1
print_info "CMake configured"

print_progress "Compiling Ada..."
START_ADA=$(date +%s)
cmake --build . --config Release > /dev/null 2>&1
END_ADA=$(date +%s)
ELAPSED_ADA=$((END_ADA - START_ADA))
print_info "Ada compiled in $ELAPSED_ADA seconds"

print_progress "Installing Ada..."
cmake --install . --prefix /usr/local > /dev/null 2>&1
print_info "Ada installed to /usr/local"

# Verify
if [ -f /usr/local/lib/libada.a ] && [ -f /usr/local/lib/cmake/ada/ada-config.cmake ]; then
    print_info "Ada verification PASSED"
else
    fail "Ada installation verification FAILED"
fi

echo ""

################################################################################
# STEP 2: Build Protobuf
################################################################################

print_step "2" "Building Protobuf Library"

print_progress "Cloning Protobuf repository..."
rm -rf /tmp/protobuf 2>/dev/null || true
git clone --depth 1 https://github.com/protocolbuffers/protobuf.git /tmp/protobuf > /dev/null 2>&1
print_info "Repository cloned"

print_progress "Configuring Protobuf build..."
cd /tmp/protobuf
mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF > /dev/null 2>&1
print_info "CMake configured"

print_progress "Compiling Protobuf (this may take 10+ minutes)..."
START_PROTOBUF=$(date +%s)
cmake --build . --config Release > /dev/null 2>&1
END_PROTOBUF=$(date +%s)
ELAPSED_PROTOBUF=$((END_PROTOBUF - START_PROTOBUF))
print_info "Protobuf compiled in $ELAPSED_PROTOBUF seconds"

print_progress "Installing Protobuf..."
cmake --install . --prefix /usr/local > /dev/null 2>&1
print_info "Protobuf installed to /usr/local"

# Verify
if [ -f /usr/local/lib/libprotobuf.so ] && [ -f /usr/local/lib/cmake/protobuf/protobufConfig.cmake ]; then
    print_info "Protobuf verification PASSED"
else
    fail "Protobuf installation verification FAILED"
fi

echo ""

################################################################################
# STEP 3: Prepare CRYPTOGRAM Build Directory
################################################################################

print_step "3" "Preparing CRYPTOGRAM Build Directory"

CRYPTOGRAM_ROOT="/home/user/CRYPTOGRAM"
BUILD_DIR="$CRYPTOGRAM_ROOT/build_release"

if [ ! -d "$CRYPTOGRAM_ROOT" ]; then
    fail "CRYPTOGRAM directory not found at $CRYPTOGRAM_ROOT"
fi

print_progress "Creating build directory..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
print_info "Build directory ready: $BUILD_DIR"

print_progress "Cleaning old build files..."
rm -f CMakeCache.txt
rm -rf CMakeFiles
print_info "Build directory cleaned"

echo ""

################################################################################
# STEP 4: CMake Configuration
################################################################################

print_step "4" "Configuring CRYPTOGRAM with CMake"

export CC=/usr/bin/gcc-13
export CXX=/usr/bin/g++-13

print_progress "Running CMake configuration..."
print_progress "Compiler: GCC-13 (C and C++)"
print_progress "Build type: Release"
print_progress "Auto-update: DISABLED"
print_progress "Crash reports: DISABLED"
echo ""

START_CMAKE=$(date +%s)

if cmake -DCMAKE_BUILD_TYPE=Release \
         -DDESKTOP_APP_DISABLE_AUTOUPDATE=ON \
         -DDESKTOP_APP_DISABLE_CRASH_REPORTS=ON \
         "$CRYPTOGRAM_ROOT" > /dev/null 2>&1; then
    END_CMAKE=$(date +%s)
    ELAPSED_CMAKE=$((END_CMAKE - START_CMAKE))
    print_info "CMake configuration successful ($ELAPSED_CMAKE seconds)"
else
    print_error "CMake configuration FAILED"
    echo ""
    echo "Running CMake again with verbose output for debugging..."
    cmake -DCMAKE_BUILD_TYPE=Release \
           -DDESKTOP_APP_DISABLE_AUTOUPDATE=ON \
           -DDESKTOP_APP_DISABLE_CRASH_REPORTS=ON \
           "$CRYPTOGRAM_ROOT" 2>&1 | tail -50
    fail "See errors above"
fi

echo ""

################################################################################
# STEP 5: Build CRYPTOGRAM Desktop
################################################################################

print_step "5" "Compiling CRYPTOGRAM Desktop Application"

NUM_JOBS=$(nproc)
print_progress "CPU cores detected: $NUM_JOBS"
print_progress "Building with $NUM_JOBS parallel jobs..."
echo ""
echo "Note: This is the longest step (20-60 minutes)"
echo "You can monitor progress by watching the output below"
echo ""
echo "────────────────────────────────────────────────────────────────"

START_BUILD=$(date +%s)

if cmake --build . --config Release --parallel "$NUM_JOBS"; then
    END_BUILD=$(date +%s)
    ELAPSED_BUILD=$((END_BUILD - START_BUILD))
    BUILD_MINUTES=$((ELAPSED_BUILD / 60))
    BUILD_SECONDS=$((ELAPSED_BUILD % 60))

    echo "────────────────────────────────────────────────────────────────"
    echo ""
    print_info "CRYPTOGRAM build completed in ${BUILD_MINUTES}m ${BUILD_SECONDS}s"
else
    echo "────────────────────────────────────────────────────────────────"
    echo ""
    print_error "CRYPTOGRAM build FAILED"
    fail "Check the output above for details"
fi

echo ""

################################################################################
# STEP 6: Verification
################################################################################

print_step "6" "Verifying Build"

EXEC_PATH="$BUILD_DIR/bin/Telegram"
if [ -f "$EXEC_PATH" ]; then
    SIZE=$(du -h "$EXEC_PATH" | cut -f1)
    print_info "Executable found: $EXEC_PATH ($SIZE)"
else
    # Try alternate location
    EXEC_PATH=$(find "$BUILD_DIR" -name "Telegram" -type f -executable 2>/dev/null | head -1)
    if [ -z "$EXEC_PATH" ]; then
        fail "CRYPTOGRAM executable not found"
    else
        SIZE=$(du -h "$EXEC_PATH" | cut -f1)
        print_info "Executable found at: $EXEC_PATH ($SIZE)"
    fi
fi

echo ""

################################################################################
# FINAL SUMMARY
################################################################################

TOTAL_START=$((START_ADA))
TOTAL_END=$(date +%s)
TOTAL_ELAPSED=$((TOTAL_END - TOTAL_START))
TOTAL_MINUTES=$((TOTAL_ELAPSED / 60))
TOTAL_SECONDS=$((TOTAL_ELAPSED % 60))

print_header "BUILD COMPLETE!"

echo ""
echo "Build Summary:"
echo "  Ada build:          $ELAPSED_ADA seconds"
echo "  Protobuf build:     $ELAPSED_PROTOBUF seconds"
echo "  CMake config:       $ELAPSED_CMAKE seconds"
echo "  CRYPTOGRAM build:   ${BUILD_MINUTES}m ${BUILD_SECONDS}s"
echo "  ────────────────────────────────"
echo "  Total time:         ${TOTAL_MINUTES}m ${TOTAL_SECONDS}s"
echo ""

echo "Build artifacts:"
echo "  Executable:         $EXEC_PATH"
echo "  Build directory:    $BUILD_DIR"
echo "  Log file:           $LOG_FILE"
echo ""

echo "Next steps:"
echo ""
echo "1. To run CRYPTOGRAM alone:"
echo "   $EXEC_PATH"
echo ""
echo "2. To run CRYPTOGRAM with TSM integration:"
echo "   cd $CRYPTOGRAM_ROOT"
echo "   source .tsm_cryptogram_env.sh"
echo "   Telegram/lib_tsm/mock_server/server.py &"
echo "   $EXEC_PATH"
echo ""
echo "3. To verify TSM backend:"
echo "   source $CRYPTOGRAM_ROOT/.tsm_cryptogram_env.sh"
echo "   cd $CRYPTOGRAM_ROOT/Telegram/lib_tsm"
echo "   python -m mock_server.server"
echo ""

echo "End time: $(get_time)"
echo ""

} 2>&1 | tee "$LOG_FILE"

echo ""
echo "Build log saved to: $LOG_FILE"
echo ""
