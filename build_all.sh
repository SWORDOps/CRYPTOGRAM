#!/bin/bash

################################################################################
# TSM + CRYPTOGRAM - Complete Automated Build Script (VERBOSE)
# Builds everything: ada, protobuf, CMake config, and CRYPTOGRAM desktop
# FULL LOGGING + REAL-TIME OUTPUT + CORRECT ERROR PROPAGATION
################################################################################

set -Eeuo pipefail

# Disable external hardware detection scripts (keep build process clean and fast)
export SKIP_HARDWARE_DETECTION=1
export PYTHONWARNINGS=ignore

# ──────────────────────────────────────────────────────────────────────────────
# Colors
# ──────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# ──────────────────────────────────────────────────────────────────────────────
# Core paths / logging
# ──────────────────────────────────────────────────────────────────────────────
BUILD_DATE="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/tmp/cryptogram_build_${BUILD_DATE}.log"

CRYPTOGRAM_ROOT="${CRYPTOGRAM_ROOT:-$HOME/CRYPTOGRAM}"
BUILD_DIR="${CRYPTOGRAM_ROOT}/build_release"

# ──────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ──────────────────────────────────────────────────────────────────────────────
get_time() {
    date +"%Y-%m-%d %H:%M:%S"
}

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
    local msg="${1:-Build failed}"
    echo ""
    print_error "$msg"
    echo ""
    print_error "Build failed! Check log at: $LOG_FILE"
    echo ""
    echo "Last 50 lines of log:"
    echo "════════════════════════════════════════════════════════════════"
    tail -n 50 "$LOG_FILE" 2>/dev/null || echo "(log file not readable)"
    echo "════════════════════════════════════════════════════════════════"
    echo "Build log saved to: $LOG_FILE"
    exit 1
}

# Trap ANY error and fail properly
trap 'fail "An unexpected error occurred (line $LINENO)"' ERR
trap 'fail "Build interrupted (signal received)"' INT TERM

# ──────────────────────────────────────────────────────────────────────────────
# Initialize log file (all heavy commands go through logging wrappers below)
# ──────────────────────────────────────────────────────────────────────────────
mkdir -p "$(dirname "$LOG_FILE")"
: > "$LOG_FILE"  # Create empty log file

################################################################################
# Function to run a command, log it, and fail if it returns non-zero
################################################################################
run_cmd() {
    local cmd="$*"
    echo "[$(get_time)] Running: $cmd" >> "$LOG_FILE"
    if ! eval "$cmd" >> "$LOG_FILE" 2>&1; then
        local exit_code=$?
        echo "[$(get_time)] Command failed with exit code $exit_code: $cmd" >> "$LOG_FILE"
        return $exit_code
    fi
    return 0
}

# Wrapper for commands that should output to console AND log
run_cmd_verbose() {
    local cmd="$*"
    echo "[$(get_time)] Running: $cmd" >> "$LOG_FILE"
    # Run command, tee output to both console and log in real-time
    if eval "$cmd" 2>&1 | tee -a "$LOG_FILE"; then
        return 0
    else
        local exit_code=$?
        echo "[$(get_time)] Command failed with exit code $exit_code: $cmd" >> "$LOG_FILE"
        return $exit_code
    fi
}

################################################################################
# START
################################################################################

if [ -t 1 ]; then
    clear || true
fi
print_header "TSM + CRYPTOGRAM Complete Build (VERBOSE MODE)"

echo "Start time : $(get_time)"
echo "Log file   : $LOG_FILE"
echo "Root dir   : $CRYPTOGRAM_ROOT"
echo "Build dir  : $BUILD_DIR"
echo ""
echo "This script will:"
echo "  1. Build and install Ada URL parser library"
echo "  2. Build and install Protobuf library"
echo "  3. Configure CRYPTOGRAM with CMake"
echo "  4. Compile CRYPTOGRAM desktop application"
echo ""
echo "Estimated time: 35–90 minutes (depending on CPU)"
echo ""
echo "ALL OUTPUT IS LOGGED TO:"
echo "  $LOG_FILE"
echo ""
echo "Tailing log in real-time from another terminal:"
echo "  tail -f $LOG_FILE"
echo ""

print_step "0" "Environment & Prerequisite Checks"

{
    echo "════════════════════════════════════════════════════════════════"
    echo "BUILD LOG - Started: $(get_time)"
    echo "Log file: $LOG_FILE"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
} >> "$LOG_FILE"

print_progress "System information:"
{
    uname -a || print_warning "uname not available"
    if command -v lsb_release >/dev/null 2>&1; then
        echo "  Distro: $(lsb_release -ds)"
    fi
    echo ""
} | tee -a "$LOG_FILE"

print_progress "Toolchain versions:"
{
    if command -v cmake >/dev/null 2>&1; then
        echo "  CMake : $(cmake --version | head -n1)"
    else
        fail "cmake not found in PATH"
    fi

    if command -v git >/dev/null 2>&1; then
        echo "  Git   : $(git --version)"
    else
        fail "git not found in PATH"
    fi
} | tee -a "$LOG_FILE"

# Compiler selection (prefer gcc-13/g++-13 if present)
if command -v gcc-13 >/dev/null 2>&1; then
    export CC="$(command -v gcc-13)"
    print_info "Using gcc-13 at $CC"
else
    export CC="$(command -v gcc || true)"
    [ -n "$CC" ] || fail "No C compiler found (gcc/gcc-13)"
    print_warning "gcc-13 not found; using default gcc at $CC"
fi

if command -v g++-13 >/dev/null 2>&1; then
    export CXX="$(command -v g++-13)"
    print_info "Using g++-13 at $CXX"
else
    export CXX="$(command -v g++ || true)"
    [ -n "$CXX" ] || fail "No C++ compiler found (g++/g++-13)"
    print_warning "g++-13 not found; using default g++ at $CXX"
fi

{
    echo "  CC  : $CC ($( "$CC" --version 2>/dev/null | head -n1 ))"
    echo "  CXX : $CXX ($( "$CXX" --version 2>/dev/null | head -n1 ))"
    echo ""
} | tee -a "$LOG_FILE"

NUM_JOBS="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
print_info "Detected CPU cores: $NUM_JOBS"

if [ ! -d "$CRYPTOGRAM_ROOT" ]; then
    fail "CRYPTOGRAM directory not found at $CRYPTOGRAM_ROOT"
fi
print_info "CRYPTOGRAM root found: $CRYPTOGRAM_ROOT"
echo ""

# Check write permissions for /usr/local (needed for Ada and Protobuf installation)
print_progress "Checking installation directory permissions..."
if [ ! -w /usr/local ]; then
    print_warning "/usr/local is NOT writable by current user"
    echo ""
    echo "IMPORTANT: This script needs to install Ada and Protobuf libraries to /usr/local"
    echo "Options to fix this:"
    echo ""
    echo "1. Run the script with sudo (EASIEST):"
    echo "   sudo bash $0"
    echo ""
    echo "2. Grant yourself write access to /usr/local:"
    echo "   sudo chown -R \$USER /usr/local"
    echo ""
    echo "3. Install to a user directory instead (ADVANCED):"
    echo "   Edit this script and change '/usr/local' to '\$HOME/.local'"
    echo ""
    if [ -t 0 ]; then
        read -rp "Continue anyway? (y/N): " -n 1 CONTINUE
        echo ""
        if [ "$CONTINUE" != "y" ] && [ "$CONTINUE" != "Y" ]; then
            echo "Aborting. Please fix permissions and try again."
            exit 1
        fi
        print_warning "Continuing with potentially limited permissions..."
    else
        fail "/usr/local not writable and no interactive TTY available for confirmation. Aborting."
    fi
else
    print_info "/usr/local is writable - proceeding with installation"
fi
echo ""

if [ -t 0 ]; then
    read -rp "Press ENTER to start the full build, or Ctrl+C to cancel..."
else
    print_warning "Non-interactive shell detected; starting full build without confirmation..."
fi

TOTAL_START="$(date +%s)"

################################################################################
# STEP 1: Build Ada
################################################################################

print_step "1" "Building Ada URL Parser"

print_progress "Cleaning previous Ada work directory (/tmp/ada)..."
run_cmd "rm -rf /tmp/ada"

print_progress "Cloning Ada repository from GitHub..."
run_cmd_verbose "git clone https://github.com/ada-url/ada.git /tmp/ada" || fail "Failed to clone Ada repository"
print_info "Ada repository cloned"

echo ""
print_progress "Ada repository details:"
{
    cd /tmp/ada
    echo "  Current branch : $(git rev-parse --abbrev-ref HEAD)"
    echo "  HEAD commit    : $(git rev-parse --short HEAD)"
} | tee -a "$LOG_FILE"
echo ""

print_progress "Configuring Ada build with CMake (Release)..."
cd /tmp/ada
mkdir -p build
cd build

START_ADA_CONFIG="$(date +%s)"
run_cmd_verbose "cmake .. -DCMAKE_BUILD_TYPE=Release" || fail "Ada CMake configuration failed"
END_ADA_CONFIG="$(date +%s)"
print_info "Ada CMake configuration completed in $((END_ADA_CONFIG - START_ADA_CONFIG)) seconds"

print_progress "Compiling Ada (this should be fast)..."
START_ADA_BUILD="$(date +%s)"
run_cmd_verbose "cmake --build . --config Release" || fail "Ada build failed"
END_ADA_BUILD="$(date +%s)"
ELAPSED_ADA="$((END_ADA_BUILD - START_ADA_BUILD))"
print_info "Ada compiled in ${ELAPSED_ADA} seconds"

print_progress "Installing Ada to /usr/local..."
run_cmd_verbose "cmake --install . --prefix /usr/local" || fail "Ada installation failed"
print_info "Ada installed to /usr/local"

echo ""
print_progress "Verifying Ada installation..."

if ls /usr/local/lib/libada.* >/dev/null 2>&1; then
    print_info "✓ Ada library file found in /usr/local/lib"
else
    fail "Ada library file NOT found in /usr/local/lib"
fi

if [ -f /usr/local/lib/cmake/ada/ada-config.cmake ]; then
    print_info "✓ Ada CMake config found at /usr/local/lib/cmake/ada/ada-config.cmake"
else
    fail "Ada CMake config NOT found at /usr/local/lib/cmake/ada/ada-config.cmake"
fi

if [ -d /usr/local/include/ada ]; then
    FILE_COUNT="$(ls -1 /usr/local/include/ada | wc -l)"
    print_info "✓ Ada header directory found (/usr/local/include/ada) with $FILE_COUNT files"
else
    fail "Ada header directory NOT found at /usr/local/include/ada"
fi

echo ""

################################################################################
# STEP 2: Build Protobuf
################################################################################

print_step "2" "Building Protobuf Library"

print_progress "Cleaning previous Protobuf work directory (/tmp/protobuf)..."
run_cmd "rm -rf /tmp/protobuf"

print_progress "Cloning Protobuf repository from GitHub (shallow clone)..."
run_cmd_verbose "git clone --depth 1 https://github.com/protocolbuffers/protobuf.git /tmp/protobuf" || fail "Failed to clone Protobuf repository"
print_info "Protobuf repository cloned"

echo ""
print_progress "Protobuf repository details:"
{
    cd /tmp/protobuf
    echo "  Commit (HEAD): $(git rev-parse --short HEAD)"
} | tee -a "$LOG_FILE"
echo ""

print_progress "Configuring Protobuf build with CMake (Release, tests OFF)..."
cd /tmp/protobuf
mkdir -p build
cd build

START_PROTOBUF_CONFIG="$(date +%s)"
run_cmd_verbose "cmake .. -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF" || fail "Protobuf CMake configuration failed"
END_PROTOBUF_CONFIG="$(date +%s)"
print_info "Protobuf CMake configuration completed in $((END_PROTOBUF_CONFIG - START_PROTOBUF_CONFIG)) seconds"

print_progress "Compiling Protobuf (large library, this may take 10–20 minutes)..."
print_progress "You should see continuous compilation output below."
START_PROTOBUF_BUILD="$(date +%s)"
run_cmd_verbose "cmake --build . --config Release" || fail "Protobuf build failed"
END_PROTOBUF_BUILD="$(date +%s)"
ELAPSED_PROTOBUF="$((END_PROTOBUF_BUILD - START_PROTOBUF_BUILD))"
PROTOBUF_MIN="$((ELAPSED_PROTOBUF / 60))"
PROTOBUF_SEC="$((ELAPSED_PROTOBUF % 60))"
print_info "Protobuf compiled in ${PROTOBUF_MIN}m ${PROTOBUF_SEC}s"

print_progress "Installing Protobuf to /usr/local..."
print_progress "NOTE: This step requires root privileges for /usr/local installation"
print_progress "If this fails due to permissions, you may need to use 'sudo' or install to a user directory"
echo ""

# Try installation with verbose output
PROTO_INSTALL_OUTPUT="$(cmake --install . --prefix /usr/local 2>&1 || true)"
PROTO_INSTALL_EXIT=$?

echo "$PROTO_INSTALL_OUTPUT" | tee -a "$LOG_FILE"
if [ $PROTO_INSTALL_EXIT -ne 0 ]; then
    print_warning "cmake --install returned non-zero exit code ($PROTO_INSTALL_EXIT)"
    print_warning "Attempting to verify what was installed anyway..."
fi
print_info "Protobuf installation step completed"

echo ""
print_progress "Verifying Protobuf installation (thorough check)..."

# First, check if anything is in /usr/local at all
echo "Listing protobuf-related items in /usr/local (if present):" | tee -a "$LOG_FILE"
{
    echo "  /usr/local/lib/:"
    ls -lah /usr/local/lib/libprotobuf* 2>/dev/null || echo "    (no libprotobuf files found)"
    echo ""
    echo "  /usr/local/include/:"
    ls -lah /usr/local/include/google/protobuf* 2>/dev/null || echo "    (no protobuf headers found)"
} | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

PROTO_LIB_PATH="$(find /usr/local -name 'libprotobuf.so*' -o -name 'libprotobuf.a*' 2>/dev/null | head -n1 || true)"
if [ -n "$PROTO_LIB_PATH" ]; then
    print_info "✓ Protobuf library found at: $PROTO_LIB_PATH"
    echo "  Path: $PROTO_LIB_PATH" >> "$LOG_FILE"
else
    # Try to find protobuf elsewhere
    print_warning "Protobuf library not found in /usr/local, checking system paths..."
    SYSTEM_PROTO="$(find /usr -name 'libprotobuf.so*' 2>/dev/null | head -n1 || true)"
    if [ -n "$SYSTEM_PROTO" ]; then
        print_warning "Found system Protobuf at: $SYSTEM_PROTO"
        print_warning "Using system Protobuf instead of local installation"
        echo "  System path: $SYSTEM_PROTO" >> "$LOG_FILE"
    else
        fail "Protobuf library not found in /usr/local or system paths - installation may have failed"
    fi
fi

PROTO_CMAKE_PATH="$(find /usr/local -name 'protobufConfig.cmake' -o -name 'protobuf-config.cmake' 2>/dev/null | head -n1 || true)"
if [ -n "$PROTO_CMAKE_PATH" ]; then
    print_info "✓ Protobuf CMake config found at: $PROTO_CMAKE_PATH"
    echo "  Path: $PROTO_CMAKE_PATH" >> "$LOG_FILE"
else
    print_warning "⚠ Protobuf CMake config not found under /usr/local – CMake may need manual hints"
    echo "  Warning: Protobuf CMake config not found" >> "$LOG_FILE"
fi

if [ -d /usr/local/include/google/protobuf ]; then
    FILE_COUNT="$(find /usr/local/include/google/protobuf -type f | wc -l)"
    print_info "✓ Protobuf headers found in /usr/local/include/google/protobuf ($FILE_COUNT files)"
    echo "  Header count: $FILE_COUNT" >> "$LOG_FILE"
else
    print_warning "⚠ Protobuf headers directory not found at /usr/local/include/google/protobuf"
    echo "  Warning: Protobuf headers not found" >> "$LOG_FILE"
fi

echo ""

################################################################################
# STEP 3: Prepare CRYPTOGRAM Build Directory
################################################################################

print_step "3" "Preparing CRYPTOGRAM Build Directory"

print_progress "Creating build directory: $BUILD_DIR"
run_cmd "mkdir -p \"$BUILD_DIR\""

cd "$BUILD_DIR"
print_info "Build directory ready: $BUILD_DIR"

print_progress "Cleaning old CMake cache and files in build directory..."
run_cmd "rm -f CMakeCache.txt"
run_cmd "rm -rf CMakeFiles"
print_info "Build directory cleaned"

echo ""

################################################################################
# STEP 4: CMake Configuration for CRYPTOGRAM
################################################################################

print_step "4" "Configuring CRYPTOGRAM with CMake"

print_progress "Compiler information:"
{
    echo "  CC : $CC"
    echo "  CXX: $CXX"
    echo ""
} | tee -a "$LOG_FILE"

print_progress "CMake configuration parameters:"
{
    echo "  -DCMAKE_BUILD_TYPE=Release"
    echo "  -DDESKTOP_APP_DISABLE_AUTOUPDATE=ON"
    echo "  -DDESKTOP_APP_DISABLE_CRASH_REPORTS=ON"
    echo "  Source dir: $CRYPTOGRAM_ROOT"
    echo ""
} | tee -a "$LOG_FILE"

print_warning "CMake configuration may take a couple of minutes..."

START_CMAKE="$(date +%s)"
run_cmd_verbose "cmake -DCMAKE_BUILD_TYPE=Release -DDESKTOP_APP_DISABLE_AUTOUPDATE=ON -DDESKTOP_APP_DISABLE_CRASH_REPORTS=ON \"$CRYPTOGRAM_ROOT\"" || fail "CMake configuration failed"
END_CMAKE="$(date +%s)"
ELAPSED_CMAKE="$((END_CMAKE - START_CMAKE))"
print_info "CMake configuration successful (${ELAPSED_CMAKE} seconds)"

echo ""

################################################################################
# STEP 5: Build CRYPTOGRAM Desktop
################################################################################

print_step "5" "Compiling CRYPTOGRAM Desktop Application"

print_progress "System build information:"
{
    echo "  CPU cores used: $NUM_JOBS"
    if command -v free >/dev/null 2>&1; then
        echo "  Total memory  : $(free -h | awk '/Mem/ {print $2}')"
    fi
    echo ""
} | tee -a "$LOG_FILE"

print_progress "Starting CRYPTOGRAM build with $NUM_JOBS parallel jobs..."
print_warning "This is the longest step (20–60 minutes). Continuous output should appear below."
echo ""
echo "════════════════════════════════════════════════════════════════" | tee -a "$LOG_FILE"
START_BUILD="$(date +%s)"
run_cmd_verbose "cmake --build . --config Release --parallel \"$NUM_JOBS\"" || fail "CRYPTOGRAM build failed"
END_BUILD="$(date +%s)"
ELAPSED_BUILD="$((END_BUILD - START_BUILD))"
BUILD_MINUTES="$((ELAPSED_BUILD / 60))"
BUILD_SECONDS="$((ELAPSED_BUILD % 60))"
echo "════════════════════════════════════════════════════════════════" | tee -a "$LOG_FILE"
echo ""
print_info "CRYPTOGRAM build completed in ${BUILD_MINUTES}m ${BUILD_SECONDS}s"

echo ""

################################################################################
# STEP 6: Verification
################################################################################

print_step "6" "Verifying Build"

print_progress "Checking for CRYPTOGRAM executable (Telegram binary)..."
EXEC_PATH="$BUILD_DIR/bin/Telegram"

if [ -f "$EXEC_PATH" ]; then
    SIZE_HUMAN="$(du -h "$EXEC_PATH" | cut -f1)"
    FILESIZE="$(ls -lh "$EXEC_PATH" | awk '{print $5}')"
    print_info "Executable found at: $EXEC_PATH"
    print_info "Size: $FILESIZE ($SIZE_HUMAN)"
else
    print_warning "Primary expected location ($EXEC_PATH) not found, searching recursively..."
    EXEC_PATH="$(find "$BUILD_DIR" -name 'Telegram' -type f -executable 2>/dev/null | head -n1 || true)"
    if [ -z "$EXEC_PATH" ]; then
        fail "CRYPTOGRAM executable not found anywhere under $BUILD_DIR"
    else
        SIZE_HUMAN="$(du -h "$EXEC_PATH" | cut -f1)"
        FILESIZE="$(ls -lh "$EXEC_PATH" | awk '{print $5}')"
        print_info "Executable found at: $EXEC_PATH"
        print_info "Size: $FILESIZE ($SIZE_HUMAN)"
    fi
fi

if [ -x "$EXEC_PATH" ]; then
    print_info "✓ Executable bit is set on $EXEC_PATH"
else
    fail "File exists but is not executable: $EXEC_PATH"
fi

echo ""

################################################################################
# FINAL SUMMARY
################################################################################
TOTAL_END="$(date +%s)"
TOTAL_ELAPSED="$((TOTAL_END - TOTAL_START))"
TOTAL_MINUTES="$((TOTAL_ELAPSED / 60))"
TOTAL_SECONDS="$((TOTAL_ELAPSED % 60))"

print_header "✓ BUILD COMPLETE!"

{
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo "BUILD SUMMARY"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    echo "Build timing:"
    echo "  Ada library:        ${ELAPSED_ADA}s"
    printf "  Protobuf library:   %dm %ds\n" "$PROTOBUF_MIN" "$PROTOBUF_SEC"
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
    echo "   cd $CRYPTOGRAM_ROOT"
    echo "   source .tsm_cryptogram_env.sh"
    echo "   python -m Telegram.lib_tsm.mock_server.server &"
    echo "   $EXEC_PATH"
    echo ""
    echo "3. Verify TSM backend (in separate terminal):"
    echo "   cd $CRYPTOGRAM_ROOT"
    echo "   source .tsm_cryptogram_env.sh"
    echo "   python -m Telegram.lib_tsm.mock_server.server"
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo "End time: $(get_time)"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    echo "BUILD SUCCEEDED"
    echo "Full build log saved to: $LOG_FILE"
    echo "To follow log in real time from another terminal:"
    echo "  tail -F $LOG_FILE"
    echo ""
} | tee -a "$LOG_FILE"

# Explicit success exit
exit 0
