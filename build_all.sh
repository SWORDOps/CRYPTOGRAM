#!/bin/bash

################################################################################
# TSM + CRYPTOGRAM - Complete Automated Build Script (VERBOSE)
# Builds everything: ada, protobuf, CMake config, and CRYPTOGRAM desktop
# WITH FULL LOGGING AND REAL-TIME OUTPUT
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
BUILD_DATE=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/tmp/cryptogram_build_$BUILD_DATE.log"
BUILD_ROOT="/home/user/CRYPTOGRAM"

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
    print_error "Build failed! Check log at: $LOG_FILE"
    echo ""
    echo "Last 50 lines of log:"
    echo "════════════════════════════════════════════════════════════════"
    tail -50 "$LOG_FILE"
    echo "════════════════════════════════════════════════════════════════"
    exit 1
}

get_time() {
    date +"%Y-%m-%d %H:%M:%S"
}

################################################################################
# START
################################################################################

clear
print_header "TSM + CRYPTOGRAM Complete Build (VERBOSE MODE)"

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
echo "ALL OUTPUT IS LOGGED TO:"
echo "  $LOG_FILE"
echo ""
read -p "Press ENTER to start, or Ctrl+C to cancel..."

{

echo "════════════════════════════════════════════════════════════════"
echo "BUILD LOG - Started: $(get_time)"
echo "Log file: $LOG_FILE"
echo "════════════════════════════════════════════════════════════════"
echo ""

################################################################################
# STEP 1: Build Ada
################################################################################

print_step "1" "Building Ada URL Parser"

print_progress "Cloning Ada repository..."
rm -rf /tmp/ada 2>/dev/null || true
if git clone https://github.com/ada-url/ada.git /tmp/ada 2>&1; then
    print_info "Repository cloned successfully"
else
    fail "Failed to clone Ada repository"
fi

print_progress "Configuring Ada build..."
cd /tmp/ada
mkdir -p build
cd build
if cmake .. -DCMAKE_BUILD_TYPE=Release 2>&1; then
    print_info "CMake configured successfully"
else
    fail "CMake configuration failed for Ada"
fi

print_progress "Compiling Ada (this should be fast)..."
START_ADA=$(date +%s)
if cmake --build . --config Release 2>&1; then
    END_ADA=$(date +%s)
    ELAPSED_ADA=$((END_ADA - START_ADA))
    print_info "Ada compiled in $ELAPSED_ADA seconds"
else
    fail "Ada build failed"
fi

print_progress "Installing Ada..."
if cmake --install . --prefix /usr/local 2>&1; then
    print_info "Ada installed to /usr/local"
else
    fail "Ada installation failed"
fi

# Verify
echo ""
print_progress "Verifying Ada installation..."
if [ -f /usr/local/lib/libada.a ]; then
    print_info "✓ Ada library file found"
else
    fail "Ada library file NOT found at /usr/local/lib/libada.a"
fi

if [ -f /usr/local/lib/cmake/ada/ada-config.cmake ]; then
    print_info "✓ Ada CMake config found"
else
    fail "Ada CMake config NOT found at /usr/local/lib/cmake/ada/ada-config.cmake"
fi

if [ -d /usr/local/include/ada ]; then
    FILE_COUNT=$(ls -1 /usr/local/include/ada | wc -l)
    print_info "✓ Ada header files found ($FILE_COUNT files)"
else
    fail "Ada header directory NOT found at /usr/local/include/ada"
fi

echo ""

################################################################################
# STEP 2: Build Protobuf
################################################################################

print_step "2" "Building Protobuf Library"

print_progress "Cloning Protobuf repository..."
rm -rf /tmp/protobuf 2>/dev/null || true
if git clone --depth 1 https://github.com/protocolbuffers/protobuf.git /tmp/protobuf 2>&1; then
    print_info "Repository cloned successfully"
else
    fail "Failed to clone Protobuf repository"
fi

print_progress "Configuring Protobuf build..."
cd /tmp/protobuf
mkdir -p build
cd build
if cmake .. -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF 2>&1; then
    print_info "CMake configured successfully"
else
    fail "CMake configuration failed for Protobuf"
fi

print_progress "Compiling Protobuf (this will take 10-15 minutes)..."
print_progress "This is a large library, grab a coffee! ☕"
START_PROTOBUF=$(date +%s)
if cmake --build . --config Release 2>&1; then
    END_PROTOBUF=$(date +%s)
    ELAPSED_PROTOBUF=$((END_PROTOBUF - START_PROTOBUF))
    MIN=$((ELAPSED_PROTOBUF / 60))
    SEC=$((ELAPSED_PROTOBUF % 60))
    print_info "Protobuf compiled in ${MIN}m ${SEC}s"
else
    fail "Protobuf build failed"
fi

print_progress "Installing Protobuf..."
if cmake --install . --prefix /usr/local 2>&1; then
    print_info "Protobuf installation command completed"
else
    fail "Protobuf installation failed"
fi

# Verify - MORE THOROUGH
echo ""
print_progress "Verifying Protobuf installation (thorough check)..."
echo "Checking /usr/local/lib/ for protobuf..."
ls -lah /usr/local/lib/libprotobuf* 2>&1 | head -20

if [ -f /usr/local/lib/libprotobuf.so ] || [ -f /usr/local/lib/libprotobuf.a ]; then
    print_info "✓ Protobuf library found"
else
    print_warning "Protobuf library not in expected location, checking alternatives..."
    PROTO_LIB=$(find /usr/local -name "libprotobuf.so*" -o -name "libprotobuf.a*" 2>/dev/null | head -1)
    if [ -n "$PROTO_LIB" ]; then
        print_info "✓ Protobuf library found at: $PROTO_LIB"
    else
        print_warning "⚠ Protobuf library not found anywhere - will check CMake config"
    fi
fi

if [ -f /usr/local/lib/cmake/protobuf/protobufConfig.cmake ]; then
    print_info "✓ Protobuf CMake config found"
else
    print_warning "⚠ Protobuf CMake config not found, checking alternatives..."
    PROTO_CMAKE=$(find /usr/local -name "protobufConfig.cmake" -o -name "protobuf-config.cmake" 2>/dev/null | head -1)
    if [ -n "$PROTO_CMAKE" ]; then
        print_info "✓ Protobuf CMake config found at: $PROTO_CMAKE"
    else
        print_warning "⚠ Protobuf CMake config not found - CMake may fail, but continuing..."
    fi
fi

if [ -d /usr/local/include/google/protobuf ]; then
    FILE_COUNT=$(find /usr/local/include/google/protobuf -type f | wc -l)
    print_info "✓ Protobuf header files found ($FILE_COUNT files)"
else
    print_warning "⚠ Protobuf headers not found"
fi

echo ""

################################################################################
# STEP 3: Prepare CRYPTOGRAM Build Directory
################################################################################

print_step "3" "Preparing CRYPTOGRAM Build Directory"

BUILD_DIR="$BUILD_ROOT/build_release"

if [ ! -d "$BUILD_ROOT" ]; then
    fail "CRYPTOGRAM directory not found at $BUILD_ROOT"
fi
print_info "CRYPTOGRAM root found: $BUILD_ROOT"

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

print_progress "Compiler information:"
echo "  CC:  $(which gcc-13) ($(gcc-13 --version 2>&1 | head -1))"
echo "  CXX: $(which g++-13) ($(g++-13 --version 2>&1 | head -1))"
echo ""

print_progress "CMake configuration parameters:"
echo "  -DCMAKE_BUILD_TYPE=Release"
echo "  -DDESKTOP_APP_DISABLE_AUTOUPDATE=ON"
echo "  -DDESKTOP_APP_DISABLE_CRASH_REPORTS=ON"
echo ""

print_progress "Running CMake configuration..."
print_warning "This may take 2-3 minutes..."
echo ""

START_CMAKE=$(date +%s)

if cmake -DCMAKE_BUILD_TYPE=Release \
         -DDESKTOP_APP_DISABLE_AUTOUPDATE=ON \
         -DDESKTOP_APP_DISABLE_CRASH_REPORTS=ON \
         "$BUILD_ROOT" 2>&1; then
    END_CMAKE=$(date +%s)
    ELAPSED_CMAKE=$((END_CMAKE - START_CMAKE))
    print_info "CMake configuration successful ($ELAPSED_CMAKE seconds)"
else
    print_error "CMake configuration FAILED"
    echo ""
    fail "CMake setup failed - see log for details"
fi

echo ""

################################################################################
# STEP 5: Build CRYPTOGRAM Desktop
################################################################################

print_step "5" "Compiling CRYPTOGRAM Desktop Application"

NUM_JOBS=$(nproc)
print_progress "System information:"
echo "  CPU cores: $NUM_JOBS"
echo "  Available memory: $(free -h | grep Mem | awk '{print $2}')"
echo ""

print_progress "Starting build with $NUM_JOBS parallel jobs..."
print_warning "This is the longest step (20-60 minutes)"
echo ""
echo "Build output will appear below:"
echo "════════════════════════════════════════════════════════════════"

START_BUILD=$(date +%s)

if cmake --build . --config Release --parallel "$NUM_JOBS" 2>&1; then
    END_BUILD=$(date +%s)
    ELAPSED_BUILD=$((END_BUILD - START_BUILD))
    BUILD_MINUTES=$((ELAPSED_BUILD / 60))
    BUILD_SECONDS=$((ELAPSED_BUILD % 60))

    echo "════════════════════════════════════════════════════════════════"
    echo ""
    print_info "CRYPTOGRAM build completed in ${BUILD_MINUTES}m ${BUILD_SECONDS}s"
else
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    print_error "CRYPTOGRAM build FAILED"
    fail "Build failed - see log above for details"
fi

echo ""

################################################################################
# STEP 6: Verification
################################################################################

print_step "6" "Verifying Build"

print_progress "Checking for executable..."
EXEC_PATH="$BUILD_DIR/bin/Telegram"
if [ -f "$EXEC_PATH" ]; then
    SIZE=$(du -h "$EXEC_PATH" | cut -f1)
    FILESIZE=$(ls -lh "$EXEC_PATH" | awk '{print $5}')
    print_info "Executable found: $EXEC_PATH"
    print_info "Size: $FILESIZE"
else
    print_warning "Primary location not found, searching..."
    EXEC_PATH=$(find "$BUILD_DIR" -name "Telegram" -type f -executable 2>/dev/null | head -1)
    if [ -z "$EXEC_PATH" ]; then
        fail "CRYPTOGRAM executable not found anywhere in build directory"
    else
        SIZE=$(du -h "$EXEC_PATH" | cut -f1)
        FILESIZE=$(ls -lh "$EXEC_PATH" | awk '{print $5}')
        print_info "Executable found at: $EXEC_PATH"
        print_info "Size: $FILESIZE"
    fi
fi

# Verify it's actually executable
if [ -x "$EXEC_PATH" ]; then
    print_info "✓ File is executable"
else
    fail "File exists but is not executable"
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

print_header "✓ BUILD COMPLETE!"

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "BUILD SUMMARY"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "Build timing:"
echo "  Ada library:        ${ELAPSED_ADA}s"
printf "  Protobuf library:   %dm %ds\n" $((ELAPSED_PROTOBUF / 60)) $((ELAPSED_PROTOBUF % 60))
echo "  CMake config:       ${ELAPSED_CMAKE}s"
printf "  CRYPTOGRAM build:   %dm %ds\n" "$BUILD_MINUTES" "$BUILD_SECONDS"
echo "  ──────────────────────────────"
printf "  Total time:         %dm %ds\n" "$TOTAL_MINUTES" "$TOTAL_SECONDS"
echo ""

echo "Build artifacts:"
echo "  Executable:   $EXEC_PATH"
echo "  Build dir:    $BUILD_DIR"
echo "  Build log:    $LOG_FILE"
echo ""

echo "═══════════════════════════════════════════════════════════════════"
echo "NEXT STEPS"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

echo "1. Run CRYPTOGRAM alone:"
echo "   $EXEC_PATH"
echo ""

echo "2. Run CRYPTOGRAM with TSM integration:"
echo "   cd $BUILD_ROOT"
echo "   source .tsm_cryptogram_env.sh"
echo "   python -m Telegram.lib_tsm.mock_server.server &"
echo "   $EXEC_PATH"
echo ""

echo "3. Verify TSM backend (in separate terminal):"
echo "   cd $BUILD_ROOT"
echo "   source .tsm_cryptogram_env.sh"
echo "   python -m Telegram.lib_tsm.mock_server.server"
echo ""

echo "═══════════════════════════════════════════════════════════════════"
echo "End time: $(get_time)"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

} 2>&1 | tee "$LOG_FILE"

echo ""
echo "✓ Complete build log saved to: $LOG_FILE"
echo ""
echo "To view the full log anytime:"
echo "  less +F $LOG_FILE"
echo ""
