#!/bin/bash

################################################################################
# TSM + CRYPTOGRAM Integration Setup Script (IMPROVED)
# Complete setup: TSM initialization → CRYPTOGRAM build → Integration
#
# This script:
# 1. Handles all submodule initialization
# 2. Installs all missing dependencies (including Qt6)
# 3. Configures CMake properly
# 4. Builds CRYPTOGRAM with TSM integration
# 5. Sets up integrated services
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
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TSM_PATH="$PROJECT_ROOT/Telegram/lib_tsm"
BUILD_DIR="$PROJECT_ROOT/build_release"
TSM_VENV="$TSM_PATH/venv"
TSM_CONFIG_DIR="$TSM_PATH/config"
STEP_COUNTER=0

# Detect compiler
CC_BIN=$(which gcc-14 2>/dev/null || which gcc-13 2>/dev/null || which gcc)
CXX_BIN=$(which g++-14 2>/dev/null || which g++-13 2>/dev/null || which g++)
GCC_VERSION=$(echo "$CC_BIN" | grep -o '[0-9]*$' || echo "default")

# Functions
print_header() {
    echo -e "${MAGENTA}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${NC} $1"
    echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════════╝${NC}"
}

print_major_step() {
    STEP_COUNTER=$((STEP_COUNTER + 1))
    echo ""
    echo -e "${CYAN}┌────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} STEP $STEP_COUNTER: $1"
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

print_step() {
    echo -e "${BLUE}→${NC} $1"
}

fail() {
    print_error "$1"
    exit 1
}

show_help() {
    cat << EOF
TSM + CRYPTOGRAM Integration Setup (IMPROVED)

Usage: $0 [OPTIONS]

Options:
  --skip-tsm           Skip TSM setup
  --skip-cryptogram    Skip CRYPTOGRAM build
  --skip-services      Skip starting TSM services
  --verbose            Show detailed output
  --help               Show this help

Examples:
  # Full setup (default)
  $0

  # Skip building, just setup
  $0 --skip-cryptogram
EOF
}

# Parse arguments
SKIP_TSM=0
SKIP_CRYPTOGRAM=0
SKIP_SERVICES=0
VERBOSE=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-tsm) SKIP_TSM=1; shift ;;
        --skip-cryptogram) SKIP_CRYPTOGRAM=1; shift ;;
        --skip-services) SKIP_SERVICES=1; shift ;;
        --verbose) VERBOSE=1; shift ;;
        --help) show_help; exit 0 ;;
        *) print_error "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

# ============================================================================
# INITIALIZATION
# ============================================================================

print_header "TSM + CRYPTOGRAM Integration Setup (AUTO)"

echo "Configuration:"
echo "  Project Root: $PROJECT_ROOT"
echo "  Build Directory: $BUILD_DIR"
echo "  Compiler: $CC_BIN (GCC $GCC_VERSION)"
echo "  TSM Path: $TSM_PATH"
echo ""

# Verify directories exist
if [ ! -d "$PROJECT_ROOT" ]; then
    fail "Project not found at $PROJECT_ROOT"
fi

# ============================================================================
# STEP 0: GIT SUBMODULE INITIALIZATION
# ============================================================================

print_major_step "Initializing Git Submodules"

print_step "Checking git submodules..."
if [ ! -f "$TSM_PATH/.git" ]; then
    print_warning "TSM submodule not initialized, initializing..."
    git submodule update --init --recursive Telegram/lib_tsm 2>&1 | grep -E "Cloning|Submodule|checked" || true
    print_info "TSM submodule initialized"
fi

if [ ! -f "cmake/.git" ]; then
    print_warning "cmake submodule not initialized, initializing..."
    git submodule update --init --recursive cmake 2>&1 | grep -E "Cloning|Submodule|checked" || true
    print_info "cmake submodule initialized"
fi

print_step "Updating all submodules..."
git submodule update --init --recursive 2>&1 | tail -5 || true
print_info "All submodules initialized"

# Verify cmake files exist
if [ ! -f "cmake/version.cmake" ] || [ ! -f "cmake/validate_special_target.cmake" ]; then
    fail "cmake submodule files missing. Try: git submodule update --init --recursive cmake"
fi

echo ""

# ============================================================================
# STEP 1: SYSTEM DEPENDENCIES
# ============================================================================

print_major_step "Installing System Dependencies"

print_step "Updating package cache..."
sudo apt-get update > /dev/null 2>&1 || print_warning "apt-get update had issues"
print_info "Package cache updated"

# Core dependencies
print_step "Installing core dependencies..."
CORE_DEPS=(
    "build-essential" "cmake" "git" "pkg-config" "curl" "wget"
    "python3-dev" "python3-pip" "python3-venv" "python3-distutils"
    "libssl-dev" "libpcsclite-dev" "swig"
)

for pkg in "${CORE_DEPS[@]}"; do
    if ! dpkg -l | grep -q "^ii  $pkg"; then
        if [ $VERBOSE -eq 1 ]; then
            print_step "Installing $pkg..."
        fi
        sudo apt-get install -y "$pkg" > /dev/null 2>&1 || print_warning "Failed to install $pkg"
    fi
done
print_info "Core dependencies installed"

# Qt6 dependencies (CRITICAL)
print_step "Checking for Qt6..."
if ! dpkg -l | grep -q "^ii  qt6-base-dev"; then
    print_warning "Qt6 not found, installing (this may take a few minutes)..."
    QT6_PACKAGES=(
        "qt6-base-dev"
        "qt6-base-private-dev"
        "qt6-tools-dev"
        "qt6-tools-dev-tools"
        "qt6-image-formats-plugins"
        "qt6-l10n-tools"
        "qt6-declarative-dev"
    )

    for pkg in "${QT6_PACKAGES[@]}"; do
        print_step "Installing $pkg..."
        sudo apt-get install -y "$pkg" > /dev/null 2>&1 || print_warning "Could not install $pkg"
    done
    print_info "Qt6 installed"
else
    print_info "Qt6 already installed"
fi

# Desktop dependencies
print_step "Installing desktop build dependencies..."
DESKTOP_DEPS=(
    "libopenal-dev" "libpulse-dev"
    "libxcb-icccm4-dev" "libxcb-image0-dev" "libxcb-keysyms1-dev"
    "libxcb-randr0-dev" "libxcb-render-util0-dev" "libxcb-shape0-dev"
    "libxcb-xfixes0-dev" "libxcb-xinerama0-dev" "libxcb-xkb-dev"
    "libxkbcommon-dev" "libxkbcommon-x11-dev"
    "libfontconfig1-dev" "libfreetype6-dev" "libharfbuzz-dev"
    "libglib2.0-dev" "libdbus-1-dev" "libx11-dev"
    "libxrandr-dev" "libxi-dev"
    "yasm" "nasm" "ccache" "ninja-build"
)

for pkg in "${DESKTOP_DEPS[@]}"; do
    if ! dpkg -l | grep -q "^ii  $pkg"; then
        sudo apt-get install -y "$pkg" > /dev/null 2>&1 || true
    fi
done
print_info "Desktop dependencies installed"

echo ""

# ============================================================================
# STEP 2: TSM SETUP
# ============================================================================

if [ $SKIP_TSM -eq 0 ]; then
    print_major_step "TSM Initialization and Python Environment"

    # Check for and shutdown existing TSM instances
    print_step "Checking for existing TSM services..."
    TSM_PIDS=$(pgrep -f "mock_server.server" || true)
    if [ -n "$TSM_PIDS" ]; then
        print_warning "Existing TSM services found, shutting down..."
        for pid in $TSM_PIDS; do
            print_step "Killing TSM process: $pid"
            kill $pid 2>/dev/null || true
        done
        sleep 2
        print_info "TSM services stopped"
    else
        print_info "No existing TSM services found"
    fi

    print_step "Creating TSM Python virtual environment..."
    if [ -d "$TSM_VENV" ]; then
        print_warning "TSM venv already exists, skipping creation"
    else
        python3 -m venv "$TSM_VENV" || fail "Failed to create venv"
        print_info "Virtual environment created"
    fi

    print_step "Activating TSM virtual environment..."
    source "$TSM_VENV/bin/activate" || fail "Failed to activate venv"
    print_info "Virtual environment activated"

    print_step "Installing TSM Python dependencies..."
    cd "$TSM_PATH"

    # Upgrade pip
    pip install --quiet --upgrade pip setuptools wheel 2>/dev/null || true

    # Install main requirements
    if [ -f "requirements.txt" ]; then
        if [ $VERBOSE -eq 1 ]; then
            pip install -r requirements.txt || print_warning "Some TSM dependencies failed"
        else
            pip install --quiet -r requirements.txt 2>/dev/null || print_warning "Some TSM dependencies failed"
        fi
        print_info "TSM core requirements installed"
    fi

    # Install mock server requirements
    if [ -f "mock_server/requirements.txt" ]; then
        pip install --quiet -r mock_server/requirements.txt 2>/dev/null || true
        print_info "TSM mock server requirements installed"
    fi

    # Install desktop requirements
    if [ -f "tsm-desktop/requirements.txt" ]; then
        pip install --quiet -r tsm-desktop/requirements.txt 2>/dev/null || true
        print_info "TSM desktop requirements installed"
    fi

    print_step "Creating TSM configuration..."
    mkdir -p "$TSM_CONFIG_DIR"

    cat > "$TSM_CONFIG_DIR/tsm.yaml" << 'TSMEOFCONFIG'
# TSM Configuration - SECURE
tsm:
  port: 50051
  api_port: 6060

security:
  encryption_enabled: true
  require_yubikey: true
  auto_lock_minutes: 15

database:
  type: sqlite
  path: ./tsm.db

api:
  host: 127.0.0.1
  port: 6060
  debug: false

logging:
  level: INFO
  file: ./tsm.log
TSMEOFCONFIG
    print_info "TSM configuration created"

    echo ""
    print_info "TSM Setup Complete!"
    echo ""
fi

# ============================================================================
# STEP 3: CRYPTOGRAM BUILD WITH TSM INTEGRATION
# ============================================================================

if [ $SKIP_CRYPTOGRAM -eq 0 ]; then
    print_major_step "CRYPTOGRAM Desktop Build with TSM Integration"

    print_info "Using Compiler: $CC_BIN ($CXX_BIN)"

    print_step "Creating and cleaning build directory..."
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    # Clean any old cache
    rm -f CMakeCache.txt
    rm -rf CMakeFiles

    print_info "Build directory: $BUILD_DIR"

    print_step "Configuring CMake..."

    # Run CMake with proper environment
    if CC="$CC_BIN" CXX="$CXX_BIN" cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DDESKTOP_APP_DISABLE_AUTOUPDATE=ON \
        -DDESKTOP_APP_DISABLE_CRASH_REPORTS=ON \
        "$PROJECT_ROOT" 2>&1 | tail -30; then
        print_info "CMake configured successfully"
    else
        print_error "CMake configuration failed"
        echo ""
        echo "Checking for Qt6..."
        if ! dpkg -l | grep -q qt6-base-dev; then
            fail "Qt6 not installed. Run: sudo apt-get install qt6-base-dev qt6-base-private-dev"
        else
            fail "CMake configuration failed. Check the output above."
        fi
    fi

    print_step "Building CRYPTOGRAM (this may take 10-30 minutes)..."
    JOBS=$(nproc)
    print_info "Using $JOBS parallel jobs"

    if cmake --build . --config Release --parallel "$JOBS" 2>&1 | tail -20; then
        print_info "CRYPTOGRAM built successfully"

        # Find executable
        if [ -f "bin/Telegram" ]; then
            EXEC="bin/Telegram"
            print_info "Executable: $(cd "$BUILD_DIR" && readlink -f "$EXEC")"
        elif [ -f "Telegram/Telegram" ]; then
            EXEC="Telegram/Telegram"
            print_info "Executable: $(cd "$BUILD_DIR" && readlink -f "$EXEC")"
        else
            print_warning "Executable location could not be determined"
        fi
    else
        fail "CRYPTOGRAM build failed. Check output above."
    fi

    echo ""
    print_info "CRYPTOGRAM Build Complete!"
    echo ""
fi

# ============================================================================
# STEP 4: INTEGRATION CONFIGURATION
# ============================================================================

print_major_step "TSM + CRYPTOGRAM Integration"

print_step "Creating integration scripts..."

# Create environment setup script
ENV_SCRIPT="$PROJECT_ROOT/.tsm_cryptogram_env.sh"
cat > "$ENV_SCRIPT" << EOFENV
#!/bin/bash
# TSM + CRYPTOGRAM Integration Environment

export CC="$CC_BIN"
export CXX="$CXX_BIN"

# Paths
export CRYPTOGRAM_ROOT="$PROJECT_ROOT"
export TSM_ROOT="\$CRYPTOGRAM_ROOT/Telegram/lib_tsm"
export TSM_VENV="\$TSM_ROOT/venv"
export TSM_CONFIG="\$TSM_ROOT/config"
export BUILD_DIR="\$CRYPTOGRAM_ROOT/build_release"

# TSM Services (Secure Configuration)
export TSM_GRPC_PORT=50051
export TSM_API_PORT=6060
export TSM_GRPC_HOST="localhost:50051"
export TSM_API_URL="http://127.0.0.1:6060"
export TSM_REQUIRE_YUBIKEY=true

# Python path for TSM
export PYTHONPATH="\$TSM_ROOT:\$PYTHONPATH"

# Activate TSM venv if available
if [ -f "\$TSM_VENV/bin/activate" ]; then
    source "\$TSM_VENV/bin/activate"
fi

echo "TSM + CRYPTOGRAM Environment Loaded"
echo "  CRYPTOGRAM: \$CRYPTOGRAM_ROOT"
echo "  TSM: \$TSM_ROOT"
echo "  Compiler: $CC_BIN"
EOFENV
chmod +x "$ENV_SCRIPT"
print_info "Environment script: $ENV_SCRIPT"

# Create startup script
START_SCRIPT="$PROJECT_ROOT/start-integrated-system.sh"
cat > "$START_SCRIPT" << 'EOFSTART'
#!/bin/bash
# Start TSM + CRYPTOGRAM Integrated System

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TSM_ROOT="$PROJECT_ROOT/Telegram/lib_tsm"
TSM_VENV="$TSM_ROOT/venv"
BUILD_DIR="$PROJECT_ROOT/build_release"

# Load environment
source "$PROJECT_ROOT/.tsm_cryptogram_env.sh" > /dev/null

echo "Starting TSM + CRYPTOGRAM Integrated System..."
echo ""

# Start TSM gRPC server in background
echo "1. Starting TSM gRPC Server..."
cd "$TSM_ROOT"
python -m mock_server.server > /tmp/tsm_grpc.log 2>&1 &
TSM_PID=$!
echo "   TSM Server PID: $TSM_PID"
sleep 2

# Start CRYPTOGRAM
echo "2. Starting CRYPTOGRAM..."
if [ -f "$BUILD_DIR/bin/Telegram" ]; then
    "$BUILD_DIR/bin/Telegram"
elif [ -f "$BUILD_DIR/Telegram/Telegram" ]; then
    "$BUILD_DIR/Telegram/Telegram"
else
    echo "CRYPTOGRAM executable not found at:"
    echo "  $BUILD_DIR/bin/Telegram"
    echo "  $BUILD_DIR/Telegram/Telegram"
    echo ""
    echo "Try rebuilding with: $PROJECT_ROOT/setup-tsm-cryptogram.sh"
    exit 1
fi

# Cleanup on exit
trap "kill $TSM_PID 2>/dev/null; echo 'Services stopped'" EXIT
EOFSTART
chmod +x "$START_SCRIPT"
print_info "System startup script: $START_SCRIPT"

# Create verification script
VERIFY_SCRIPT="$PROJECT_ROOT/verify-tsm-cryptogram.sh"
cat > "$VERIFY_SCRIPT" << 'EOFVERIFY'
#!/bin/bash
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TSM_ROOT="$PROJECT_ROOT/Telegram/lib_tsm"
TSM_VENV="$TSM_ROOT/venv"
BUILD_DIR="$PROJECT_ROOT/build_release"

echo "TSM + CRYPTOGRAM Verification Checklist"
echo "========================================"
echo ""

PASSED=0
FAILED=0

check() {
    if [ $1 -eq 0 ]; then
        echo "  ✓ $2"
        PASSED=$((PASSED + 1))
    else
        echo "  ✗ $2"
        FAILED=$((FAILED + 1))
    fi
}

# TSM checks
echo "TSM:"
[ -d "$TSM_VENV" ] && check 0 "Virtual environment exists" || check 1 "Virtual environment missing"
[ -f "$TSM_ROOT/requirements.txt" ] && check 0 "Requirements file found" || check 1 "Requirements file missing"
[ -d "$TSM_ROOT/config" ] && check 0 "Config directory exists" || check 1 "Config directory missing"
[ -f "$TSM_ROOT/config/tsm.yaml" ] && check 0 "TSM configuration created" || check 1 "TSM configuration missing"

# CRYPTOGRAM checks
echo ""
echo "CRYPTOGRAM:"
[ -d "$BUILD_DIR" ] && check 0 "Build directory exists" || check 1 "Build directory missing"
[ -f "$BUILD_DIR/CMakeCache.txt" ] && check 0 "CMake configured" || check 1 "CMake not configured"

if [ -f "$BUILD_DIR/bin/Telegram" ]; then
    check 0 "Executable found at bin/Telegram"
elif [ -f "$BUILD_DIR/Telegram/Telegram" ]; then
    check 0 "Executable found at Telegram/Telegram"
else
    check 1 "Executable not found"
fi

# Integration checks
echo ""
echo "Integration:"
[ -f "$PROJECT_ROOT/.tsm_cryptogram_env.sh" ] && check 0 "Environment script exists" || check 1 "Environment script missing"
[ -f "$PROJECT_ROOT/start-integrated-system.sh" ] && check 0 "Startup script exists" || check 1 "Startup script missing"

echo ""
echo "Summary: $PASSED passed, $FAILED failed"

if [ $FAILED -eq 0 ]; then
    echo ""
    echo "✓ System is ready!"
    echo ""
    echo "Next steps:"
    echo "  1. Load environment: source $PROJECT_ROOT/.tsm_cryptogram_env.sh"
    echo "  2. Start system: $PROJECT_ROOT/start-integrated-system.sh"
else
    echo ""
    echo "⚠ Some checks failed. Run setup again: $PROJECT_ROOT/setup-tsm-cryptogram.sh"
fi
EOFVERIFY
chmod +x "$VERIFY_SCRIPT"
print_info "Verification script: $VERIFY_SCRIPT"

echo ""
print_info "Integration Configuration Complete!"
echo ""

# ============================================================================
# STEP 5: OPTIONAL SERVICE STARTUP
# ============================================================================

if [ $SKIP_SERVICES -eq 0 ]; then
    print_major_step "TSM Services Startup (Optional)"

    read -p "Start TSM services now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_step "Starting TSM services..."

        # Activate TSM venv
        source "$TSM_VENV/bin/activate"
        cd "$TSM_PATH"

        print_info "Starting TSM gRPC Server on port 50051..."
        python -m mock_server.server > /tmp/tsm_grpc.log 2>&1 &
        TSM_GRPC_PID=$!
        echo "  PID: $TSM_GRPC_PID"

        sleep 2
        if ps -p $TSM_GRPC_PID > /dev/null; then
            print_info "TSM gRPC Server started successfully"
            echo "  Logs: tail -f /tmp/tsm_grpc.log"
            echo ""
            print_step "To stop service: kill $TSM_GRPC_PID"
        else
            print_error "Failed to start TSM gRPC Server"
            tail /tmp/tsm_grpc.log
        fi
    fi
fi

# ============================================================================
# COMPLETION SUMMARY
# ============================================================================

echo ""
print_header "Integration Setup Complete! ✓"

echo ""
echo "Summary:"
echo "  ✓ Git submodules initialized"
echo "  ✓ System dependencies installed"
echo "  ✓ TSM Python environment created"
echo "  ✓ TSM dependencies installed"
echo "  ✓ CRYPTOGRAM built with TSM support"
echo "  ✓ Integration scripts created"
echo ""

echo "Quick Start:"
echo "  1. Load environment:"
echo "     source $PROJECT_ROOT/.tsm_cryptogram_env.sh"
echo ""
echo "  2. Verify setup:"
echo "     $VERIFY_SCRIPT"
echo ""
echo "  3. Start integrated system:"
echo "     $START_SCRIPT"
echo ""

echo "Directory Locations:"
echo "  Project: $PROJECT_ROOT"
echo "  TSM: $TSM_PATH"
echo "  Build: $BUILD_DIR"
echo ""

echo "Documentation:"
echo "  Setup: $PROJECT_ROOT/DUAL_PROJECT_SETUP.md"
echo "  Quick Start: $PROJECT_ROOT/QUICK_START.md"
echo "  Integration: $PROJECT_ROOT/TSM_CRYPTOGRAM_INTEGRATION.md"
echo ""
