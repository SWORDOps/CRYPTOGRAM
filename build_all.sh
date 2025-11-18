#!/bin/bash

################################################################################
# TSM + CRYPTOGRAM - Ultimate Build Script v3.0 (FINAL)
# Combines best features from all versions for maximum reliability
# FULL LOGGING + REAL-TIME OUTPUT + STATE MANAGEMENT + NON-INTERACTIVE SUPPORT
################################################################################

set -Eeuo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Environment Optimization (from v2 script - prevents unwanted external calls)
# ──────────────────────────────────────────────────────────────────────────────
export SKIP_HARDWARE_DETECTION=1
export PYTHONWARNINGS=ignore
export DEBIAN_FRONTEND=noninteractive
export NONINTERACTIVE=1

# ──────────────────────────────────────────────────────────────────────────────
# Advanced Color Palette
# ──────────────────────────────────────────────────────────────────────────────
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly WHITE='\033[1;37m'
readonly GRAY='\033[0;90m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Unicode symbols
readonly CHECK="✓"
readonly CROSS="✗"
readonly WARN="⚠"
readonly ARROW="→"
readonly INFO="ℹ"

# ──────────────────────────────────────────────────────────────────────────────
# Core Configuration
# ──────────────────────────────────────────────────────────────────────────────
readonly SCRIPT_VERSION="3.0.0"
readonly BUILD_DATE="$(date +%Y%m%d_%H%M%S)"
readonly BUILD_ID="${BUILD_DATE}_$$"

# Detect if running in interactive mode (from v2)
INTERACTIVE_MODE=1
if [ ! -t 0 ] || [ ! -t 1 ]; then
    INTERACTIVE_MODE=0
fi

# Paths
readonly CRYPTOGRAM_ROOT="${CRYPTOGRAM_ROOT:-$HOME/CRYPTOGRAM}"
readonly BUILD_DIR="${CRYPTOGRAM_ROOT}/build_release"
readonly LOG_DIR="${LOG_DIR:-/tmp/cryptogram_builds}"
readonly LOG_FILE="${LOG_DIR}/build_${BUILD_DATE}.log"
readonly ERROR_LOG="${LOG_DIR}/errors_${BUILD_DATE}.log"
readonly STATE_FILE="${LOG_DIR}/state_${BUILD_DATE}.json"
readonly SUMMARY_FILE="${LOG_DIR}/summary_${BUILD_DATE}.txt"

# Build options
readonly DEFAULT_PREFIX="/usr/local"
readonly USER_PREFIX="${HOME}/.local"
INSTALL_PREFIX="${INSTALL_PREFIX:-$DEFAULT_PREFIX}"

# Auto-detect available tools
readonly NUM_CORES="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
readonly TOTAL_MEMORY="$(free -b 2>/dev/null | awk '/^Mem:/{print $2}' || echo 0)"

# Build flags
VERBOSE_MODE="${VERBOSE:-1}"
DRY_RUN="${DRY_RUN:-0}"
FORCE_REBUILD="${FORCE:-0}"
RESUME_BUILD="${RESUME:-0}"
PARALLEL_JOBS="${JOBS:-$NUM_CORES}"

# Component tracking
declare -A BUILD_STATE=(
    ["ada_cloned"]=0
    ["ada_built"]=0
    ["ada_installed"]=0
    ["protobuf_cloned"]=0
    ["protobuf_built"]=0
    ["protobuf_installed"]=0
    ["cryptogram_configured"]=0
    ["cryptogram_built"]=0
)

# Timing tracking
declare -A COMPONENT_TIMES

# ──────────────────────────────────────────────────────────────────────────────
# Initialize Environment
# ──────────────────────────────────────────────────────────────────────────────
initialize() {
    # Create directories
    mkdir -p "$LOG_DIR"
    
    # Initialize logs
    : > "$LOG_FILE"
    : > "$ERROR_LOG"
    
    # Log header
    {
        echo "════════════════════════════════════════════════════════════════"
        echo "BUILD LOG - TSM + CRYPTOGRAM v${SCRIPT_VERSION}"
        echo "Started: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Build ID: $BUILD_ID"
        echo "Interactive: $([ $INTERACTIVE_MODE -eq 1 ] && echo "Yes" || echo "No")"
        echo "════════════════════════════════════════════════════════════════"
        echo ""
    } >> "$LOG_FILE"
}

# ──────────────────────────────────────────────────────────────────────────────
# Utility Functions
# ──────────────────────────────────────────────────────────────────────────────
get_timestamp() {
    date +"%Y-%m-%d %H:%M:%S"
}

format_time() {
    local seconds="$1"
    local minutes=$((seconds / 60))
    local remaining=$((seconds % 60))
    if [ $minutes -gt 0 ]; then
        printf "%dm %ds" "$minutes" "$remaining"
    else
        printf "%ds" "$seconds"
    fi
}

format_size() {
    local size="$1"
    if [[ $size -ge 1073741824 ]]; then
        echo "$((size / 1073741824))GB"
    elif [[ $size -ge 1048576 ]]; then
        echo "$((size / 1048576))MB"
    elif [[ $size -ge 1024 ]]; then
        echo "$((size / 1024))KB"
    else
        echo "${size}B"
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# Logging Functions
# ──────────────────────────────────────────────────────────────────────────────
log() {
    local level="$1"
    shift
    local msg="$*"
    echo "[$(get_timestamp)] [$level] $msg" >> "$LOG_FILE"
    [ "$level" = "ERROR" ] && echo "[$(get_timestamp)] $msg" >> "$ERROR_LOG"
}

print_header() {
    echo -e "${MAGENTA}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${NC} $1"
    echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════════╝${NC}"
    log "INFO" "=== $1 ==="
}

print_step() {
    echo -e "\n${CYAN}┌────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} STEP $1: $2"
    echo -e "${CYAN}└────────────────────────────────────────────────────────────────┘${NC}"
    log "STEP" "$1: $2"
}

print_info() {
    echo -e "${GREEN}${CHECK}${NC} $1"
    log "INFO" "$1"
}

print_warning() {
    echo -e "${YELLOW}${WARN}${NC} $1"
    log "WARN" "$1"
}

print_error() {
    echo -e "${RED}${CROSS}${NC} $1" >&2
    log "ERROR" "$1"
}

print_progress() {
    echo -e "${BLUE}${ARROW}${NC} $1"
    log "PROGRESS" "$1"
}

print_debug() {
    [ $VERBOSE_MODE -eq 1 ] && echo -e "${GRAY}[DEBUG] $1${NC}"
    log "DEBUG" "$1"
}

# ──────────────────────────────────────────────────────────────────────────────
# Command Execution
# ──────────────────────────────────────────────────────────────────────────────
run_cmd() {
    local cmd="$*"
    print_debug "Executing: $cmd"
    echo "[$(get_timestamp)] Running: $cmd" >> "$LOG_FILE"
    
    if [ $DRY_RUN -eq 1 ]; then
        print_info "[DRY RUN] Would execute: $cmd"
        return 0
    fi
    
    if ! eval "$cmd" >> "$LOG_FILE" 2>&1; then
        local exit_code=$?
        echo "[$(get_timestamp)] Command failed with exit code $exit_code: $cmd" >> "$LOG_FILE"
        return $exit_code
    fi
    return 0
}

run_cmd_verbose() {
    local cmd="$*"
    print_debug "Executing (verbose): $cmd"
    echo "[$(get_timestamp)] Running: $cmd" >> "$LOG_FILE"
    
    if [ $DRY_RUN -eq 1 ]; then
        print_info "[DRY RUN] Would execute: $cmd"
        return 0
    fi
    
    if eval "$cmd" 2>&1 | tee -a "$LOG_FILE"; then
        return 0
    else
        local exit_code=$?
        echo "[$(get_timestamp)] Command failed with exit code $exit_code: $cmd" >> "$LOG_FILE"
        return $exit_code
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# State Management
# ──────────────────────────────────────────────────────────────────────────────
save_state() {
    {
        echo "{"
        echo "  \"build_id\": \"$BUILD_ID\","
        echo "  \"timestamp\": \"$(get_timestamp)\","
        echo "  \"state\": {"
        for key in "${!BUILD_STATE[@]}"; do
            echo "    \"$key\": ${BUILD_STATE[$key]},"
        done | sed '$ s/,$//'
        echo "  }"
        echo "}"
    } > "$STATE_FILE"
    print_debug "State saved to $STATE_FILE"
}

load_state() {
    if [ -f "$STATE_FILE" ] && [ $RESUME_BUILD -eq 1 ]; then
        print_info "Loading previous build state..."
        # Simple state restoration (would use jq in production)
        while IFS='=' read -r key value; do
            if [[ -n "$key" ]] && [[ -n "$value" ]]; then
                BUILD_STATE["$key"]="$value"
                print_debug "Restored: $key=$value"
            fi
        done < <(grep -oP '"\K[^"]+(?=":)|(?<=":)\d+' "$STATE_FILE" 2>/dev/null | paste -d= - - 2>/dev/null)
        return 0
    fi
    return 1
}

# ──────────────────────────────────────────────────────────────────────────────
# Error Handling
# ──────────────────────────────────────────────────────────────────────────────
fail() {
    local msg="${1:-Build failed}"
    local line="${2:-$LINENO}"
    
    echo ""
    print_error "$msg (line $line)"
    echo ""
    
    # Save state for resume
    save_state
    
    # Show diagnostic info
    print_error "Build failed! Logs available at:"
    echo "  Main log: $LOG_FILE"
    echo "  Error log: $ERROR_LOG"
    echo "  State file: $STATE_FILE"
    echo ""
    echo "Last 30 lines of log:"
    echo "════════════════════════════════════════════════════════════════"
    tail -n 30 "$LOG_FILE" 2>/dev/null || echo "(log not available)"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    echo "To resume this build: $0 --resume"
    
    exit 1
}

cleanup() {
    local exit_code=$?
    if [ $exit_code -eq 0 ]; then
        generate_summary
        print_info "Build completed successfully!"
    else
        save_state
        print_warning "Build interrupted. State saved for resume."
    fi
    exit $exit_code
}

# Enhanced signal trapping (from v2)
trap 'fail "Unexpected error at line $LINENO"' ERR
trap 'fail "Build interrupted by user"' INT
trap 'fail "Build terminated"' TERM
trap cleanup EXIT

# ──────────────────────────────────────────────────────────────────────────────
# System Checks
# ──────────────────────────────────────────────────────────────────────────────
check_system() {
    print_step "1/8" "System Requirements Check"
    
    # OS Detection
    print_progress "Checking operating system..."
    local os_info="$(uname -a)"
    print_info "System: $os_info"
    log "INFO" "System: $os_info"
    
    # Memory Check
    print_progress "Checking memory..."
    local mem_gb=$((TOTAL_MEMORY / 1073741824))
    print_info "Memory: ${mem_gb}GB available"
    if [ $mem_gb -lt 4 ]; then
        print_warning "Low memory detected. Build may be slow or fail."
    fi
    
    # CPU Check
    print_progress "Checking CPU..."
    print_info "CPU cores: $NUM_CORES"
    print_info "Parallel jobs: $PARALLEL_JOBS"
    
    # Disk Space
    print_progress "Checking disk space..."
    local available_space=$(df "$HOME" | awk 'NR==2 {print $4}')
    local available_gb=$((available_space / 1048576))
    print_info "Available disk: ${available_gb}GB"
    if [ $available_gb -lt 10 ]; then
        print_warning "Low disk space. At least 10GB recommended."
    fi
    
    echo ""
}

check_tools() {
    print_step "2/8" "Tool Dependencies Check"
    
    local missing_tools=()
    
    # Required tools
    local tools=("git" "cmake" "make" "gcc" "g++")
    for tool in "${tools[@]}"; do
        print_progress "Checking for $tool..."
        if command -v "$tool" >/dev/null 2>&1; then
            local version=$($tool --version 2>/dev/null | head -n1 || echo "unknown")
            print_info "$tool found: $version"
        else
            print_error "$tool NOT found"
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        fail "Missing required tools: ${missing_tools[*]}"
    fi
    
    echo ""
}

check_permissions() {
    print_step "3/8" "Permission Check"
    
    print_progress "Checking installation directory permissions..."
    
    if [ ! -d "$CRYPTOGRAM_ROOT" ]; then
        fail "CRYPTOGRAM directory not found at $CRYPTOGRAM_ROOT"
    fi
    
    if [ -w "$INSTALL_PREFIX" ]; then
        print_info "Write access to $INSTALL_PREFIX: OK"
    else
        print_warning "No write access to $INSTALL_PREFIX"
        
        if [ $INTERACTIVE_MODE -eq 1 ]; then
            echo ""
            echo "Options:"
            echo "1. Run with sudo: sudo $0"
            echo "2. Use user prefix: $0 --prefix=$USER_PREFIX"
            echo ""
            read -rp "Continue anyway? (y/N): " -n 1 choice
            echo ""
            if [ "$choice" != "y" ] && [ "$choice" != "Y" ]; then
                echo "Aborting."
                exit 1
            fi
        else
            print_warning "Non-interactive mode: attempting to continue with limited permissions"
            if [ "$INSTALL_PREFIX" = "$DEFAULT_PREFIX" ]; then
                INSTALL_PREFIX="$USER_PREFIX"
                print_info "Switching to user prefix: $INSTALL_PREFIX"
                mkdir -p "$INSTALL_PREFIX"
            fi
        fi
    fi
    
    echo ""
}

configure_compiler() {
    print_step "4/8" "Compiler Configuration"
    
    # Detect best available compiler
    print_progress "Detecting compilers..."
    
    # C Compiler
    for cc in gcc-13 gcc-12 gcc-11 gcc clang; do
        if command -v "$cc" >/dev/null 2>&1; then
            export CC="$(command -v "$cc")"
            break
        fi
    done
    
    # C++ Compiler
    for cxx in g++-13 g++-12 g++-11 g++ clang++; do
        if command -v "$cxx" >/dev/null 2>&1; then
            export CXX="$(command -v "$cxx")"
            break
        fi
    done
    
    [ -z "$CC" ] && fail "No C compiler found"
    [ -z "$CXX" ] && fail "No C++ compiler found"
    
    print_info "C compiler: $CC"
    print_info "C++ compiler: $CXX"
    
    # Set optimization flags
    export CFLAGS="${CFLAGS:--O2 -pipe -march=native}"
    export CXXFLAGS="${CXXFLAGS:--O2 -pipe -march=native}"
    
    print_debug "CFLAGS: $CFLAGS"
    print_debug "CXXFLAGS: $CXXFLAGS"
    
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# Build Functions
# ──────────────────────────────────────────────────────────────────────────────
build_ada() {
    print_step "5/8" "Building Ada URL Parser"
    
    if [ ${BUILD_STATE["ada_installed"]} -eq 1 ] && [ $FORCE_REBUILD -eq 0 ]; then
        print_info "Ada already installed, skipping..."
        return 0
    fi
    
    local ada_dir="/tmp/ada_$$"
    local start_time=$(date +%s)
    
    print_progress "Cloning Ada repository..."
    run_cmd "rm -rf '$ada_dir'"
    run_cmd_verbose "git clone --depth 1 https://github.com/ada-url/ada.git '$ada_dir'" || fail "Failed to clone Ada"
    BUILD_STATE["ada_cloned"]=1
    save_state
    
    print_progress "Configuring Ada..."
    cd "$ada_dir"
    mkdir -p build && cd build
    run_cmd_verbose "cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX='$INSTALL_PREFIX'" || fail "Ada configuration failed"
    
    print_progress "Building Ada..."
    run_cmd_verbose "cmake --build . --config Release -j$PARALLEL_JOBS" || fail "Ada build failed"
    BUILD_STATE["ada_built"]=1
    save_state
    
    print_progress "Installing Ada..."
    run_cmd_verbose "cmake --install . --prefix '$INSTALL_PREFIX'" || fail "Ada installation failed"
    BUILD_STATE["ada_installed"]=1
    save_state
    
    # Verify
    if ls "$INSTALL_PREFIX"/lib/libada.* >/dev/null 2>&1; then
        print_info "Ada installed successfully"
    else
        fail "Ada installation verification failed"
    fi
    
    cd /
    rm -rf "$ada_dir"
    
    local elapsed=$(($(date +%s) - start_time))
    COMPONENT_TIMES["ada"]=$elapsed
    print_info "Ada built in $(format_time $elapsed)"
    
    echo ""
}

build_protobuf() {
    print_step "6/8" "Building Protocol Buffers"
    
    if [ ${BUILD_STATE["protobuf_installed"]} -eq 1 ] && [ $FORCE_REBUILD -eq 0 ]; then
        print_info "Protobuf already installed, skipping..."
        return 0
    fi
    
    local protobuf_dir="/tmp/protobuf_$$"
    local start_time=$(date +%s)
    
    print_progress "Cloning Protobuf repository..."
    run_cmd "rm -rf '$protobuf_dir'"
    run_cmd_verbose "git clone --depth 1 https://github.com/protocolbuffers/protobuf.git '$protobuf_dir'" || fail "Failed to clone Protobuf"
    BUILD_STATE["protobuf_cloned"]=1
    save_state
    
    print_progress "Configuring Protobuf..."
    cd "$protobuf_dir"
    mkdir -p build && cd build
    run_cmd_verbose "cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX='$INSTALL_PREFIX' -Dprotobuf_BUILD_TESTS=OFF" || fail "Protobuf configuration failed"
    
    print_progress "Building Protobuf (this will take 10-20 minutes)..."
    run_cmd_verbose "cmake --build . --config Release -j$PARALLEL_JOBS" || fail "Protobuf build failed"
    BUILD_STATE["protobuf_built"]=1
    save_state
    
    print_progress "Installing Protobuf..."
    run_cmd_verbose "cmake --install . --prefix '$INSTALL_PREFIX'" || fail "Protobuf installation failed"
    BUILD_STATE["protobuf_installed"]=1
    save_state
    
    # Verify
    if ls "$INSTALL_PREFIX"/lib/libprotobuf.* >/dev/null 2>&1; then
        print_info "Protobuf installed successfully"
    else
        # Check system paths as fallback
        if find /usr -name 'libprotobuf.so*' 2>/dev/null | head -n1; then
            print_warning "Using system Protobuf"
        else
            fail "Protobuf installation verification failed"
        fi
    fi
    
    cd /
    rm -rf "$protobuf_dir"
    
    local elapsed=$(($(date +%s) - start_time))
    COMPONENT_TIMES["protobuf"]=$elapsed
    print_info "Protobuf built in $(format_time $elapsed)"
    
    echo ""
}

configure_cryptogram() {
    print_step "7/8" "Configuring CRYPTOGRAM"
    
    if [ ${BUILD_STATE["cryptogram_configured"]} -eq 1 ] && [ $FORCE_REBUILD -eq 0 ]; then
        print_info "CRYPTOGRAM already configured, skipping..."
        return 0
    fi
    
    local start_time=$(date +%s)
    
    print_progress "Creating build directory..."
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    
    if [ $FORCE_REBUILD -eq 1 ]; then
        print_progress "Cleaning previous build..."
        run_cmd "rm -rf CMakeCache.txt CMakeFiles"
    fi
    
    print_progress "Running CMake configuration..."
    run_cmd_verbose "cmake -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH='$INSTALL_PREFIX' \
        -DDESKTOP_APP_DISABLE_AUTOUPDATE=ON \
        -DDESKTOP_APP_DISABLE_CRASH_REPORTS=ON \
        '$CRYPTOGRAM_ROOT'" || fail "CMake configuration failed"
    
    BUILD_STATE["cryptogram_configured"]=1
    save_state
    
    local elapsed=$(($(date +%s) - start_time))
    COMPONENT_TIMES["configure"]=$elapsed
    print_info "Configuration completed in $(format_time $elapsed)"
    
    echo ""
}

build_cryptogram() {
    print_step "8/8" "Building CRYPTOGRAM Desktop"
    
    if [ ${BUILD_STATE["cryptogram_built"]} -eq 1 ] && [ $FORCE_REBUILD -eq 0 ]; then
        print_info "CRYPTOGRAM already built, skipping..."
        return 0
    fi
    
    cd "$BUILD_DIR"
    local start_time=$(date +%s)
    
    print_progress "Starting CRYPTOGRAM build with $PARALLEL_JOBS parallel jobs..."
    print_warning "This will take 20-60 minutes depending on your system"
    echo ""
    
    run_cmd_verbose "cmake --build . --config Release --parallel $PARALLEL_JOBS" || fail "CRYPTOGRAM build failed"
    
    BUILD_STATE["cryptogram_built"]=1
    save_state
    
    local elapsed=$(($(date +%s) - start_time))
    COMPONENT_TIMES["cryptogram"]=$elapsed
    print_info "CRYPTOGRAM built in $(format_time $elapsed)"
    
    # Verify executable
    print_progress "Verifying build..."
    local exec_path="$BUILD_DIR/bin/Telegram"
    if [ ! -f "$exec_path" ]; then
        exec_path=$(find "$BUILD_DIR" -name 'Telegram' -type f -executable 2>/dev/null | head -n1)
    fi
    
    if [ -n "$exec_path" ] && [ -x "$exec_path" ]; then
        local size=$(stat -c%s "$exec_path" 2>/dev/null || stat -f%z "$exec_path" 2>/dev/null || echo 0)
        print_info "Executable found: $exec_path ($(format_size $size))"
        echo "CRYPTOGRAM_EXEC=$exec_path" >> "$SUMMARY_FILE"
    else
        fail "CRYPTOGRAM executable not found"
    fi
    
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# Summary Generation
# ──────────────────────────────────────────────────────────────────────────────
generate_summary() {
    local total_time=0
    for time in "${COMPONENT_TIMES[@]}"; do
        total_time=$((total_time + time))
    done
    
    {
        echo "════════════════════════════════════════════════════════════════"
        echo "                    BUILD SUMMARY"
        echo "════════════════════════════════════════════════════════════════"
        echo ""
        echo "Build ID: $BUILD_ID"
        echo "Date: $(date)"
        echo ""
        echo "Component Build Times:"
        for component in "${!COMPONENT_TIMES[@]}"; do
            printf "  %-20s: %s\n" "$component" "$(format_time ${COMPONENT_TIMES[$component]})"
        done
        echo "  ────────────────────────────"
        printf "  %-20s: %s\n" "Total" "$(format_time $total_time)"
        echo ""
        echo "Build Configuration:"
        echo "  Install prefix: $INSTALL_PREFIX"
        echo "  Parallel jobs: $PARALLEL_JOBS"
        echo "  Compiler: ${CC##*/}"
        echo ""
        echo "Logs:"
        echo "  Main: $LOG_FILE"
        echo "  Errors: $ERROR_LOG"
        echo "  State: $STATE_FILE"
        echo ""
    } | tee -a "$SUMMARY_FILE"
    
    cat "$SUMMARY_FILE"
}

# ──────────────────────────────────────────────────────────────────────────────
# Main Function
# ──────────────────────────────────────────────────────────────────────────────
main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h)
                show_help
                exit 0
                ;;
            --version|-v)
                echo "TSM + CRYPTOGRAM Build Script v$SCRIPT_VERSION"
                exit 0
                ;;
            --prefix=*)
                INSTALL_PREFIX="${1#*=}"
                ;;
            --jobs=*|-j*)
                PARALLEL_JOBS="${1#*=}"
                PARALLEL_JOBS="${PARALLEL_JOBS#-j}"
                ;;
            --force)
                FORCE_REBUILD=1
                ;;
            --resume)
                RESUME_BUILD=1
                ;;
            --dry-run)
                DRY_RUN=1
                ;;
            --verbose)
                VERBOSE_MODE=1
                ;;
            --quiet|-q)
                VERBOSE_MODE=0
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
        shift
    done
    
    # Initialize
    initialize
    
    # Clear screen for interactive mode
    [ $INTERACTIVE_MODE -eq 1 ] && [ -t 1 ] && clear
    
    # Header
    print_header "TSM + CRYPTOGRAM Build Script v$SCRIPT_VERSION"
    
    echo "Configuration:"
    echo "  Root: $CRYPTOGRAM_ROOT"
    echo "  Build: $BUILD_DIR"
    echo "  Prefix: $INSTALL_PREFIX"
    echo "  Jobs: $PARALLEL_JOBS"
    [ $DRY_RUN -eq 1 ] && echo "  Mode: DRY RUN"
    [ $RESUME_BUILD -eq 1 ] && echo "  Mode: RESUME"
    echo ""
    
    # Try to load previous state
    load_state
    
    # Interactive confirmation
    if [ $INTERACTIVE_MODE -eq 1 ] && [ -t 0 ]; then
        read -rp "Press ENTER to start build or Ctrl+C to cancel..."
    else
        print_warning "Non-interactive mode - starting build automatically"
    fi
    
    # Run build steps
    check_system
    check_tools
    check_permissions
    configure_compiler
    build_ada
    build_protobuf
    configure_cryptogram
    build_cryptogram
    
    # Success
    print_header "BUILD SUCCESSFUL!"
    
    # Show summary
    generate_summary
    
    # Get executable path from summary
    if [ -f "$SUMMARY_FILE" ]; then
        EXEC_PATH=$(grep "^CRYPTOGRAM_EXEC=" "$SUMMARY_FILE" | cut -d= -f2)
        if [ -n "$EXEC_PATH" ]; then
            echo ""
            echo "Next steps:"
            echo "1. Run CRYPTOGRAM: $EXEC_PATH"
            echo "2. With TSM: cd $CRYPTOGRAM_ROOT && source .tsm_cryptogram_env.sh && $EXEC_PATH"
            echo ""
        fi
    fi
    
    exit 0
}

# ──────────────────────────────────────────────────────────────────────────────
# Help
# ──────────────────────────────────────────────────────────────────────────────
show_help() {
    cat <<EOF
TSM + CRYPTOGRAM Build Script v$SCRIPT_VERSION

USAGE:
    $0 [OPTIONS]

OPTIONS:
    -h, --help          Show this help
    -v, --version       Show version
    --prefix=PATH       Install prefix (default: $DEFAULT_PREFIX)
    -j, --jobs=N        Parallel jobs (default: auto)
    --force             Force rebuild all components
    --resume            Resume from previous state
    --dry-run           Preview without executing
    --verbose           Enable verbose output
    -q, --quiet         Quiet mode

ENVIRONMENT:
    CRYPTOGRAM_ROOT     Source directory
    CC/CXX              Compiler override
    VERBOSE             Verbosity (0/1)

EXAMPLES:
    # Standard build
    $0

    # User installation
    $0 --prefix=\$HOME/.local

    # Resume interrupted build
    $0 --resume

    # Force rebuild with 8 jobs
    $0 --force -j8

EOF
}

# Entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
