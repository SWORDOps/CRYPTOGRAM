#!/bin/bash

################################################################################
# TSM + CRYPTOGRAM - Ultimate Build Script v3.1 (POLISHED)
# Enhanced with comprehensive error handling, logging, and validation
# FULL LOGGING + REAL-TIME OUTPUT + STATE MANAGEMENT + ROBUST ERROR HANDLING
################################################################################

set -Eeuo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Environment Optimization
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
# shellcheck disable=SC2034
readonly WHITE='\033[1;37m'
readonly GRAY='\033[0;90m'
# shellcheck disable=SC2034
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Unicode symbols
readonly CHECK="✓"
readonly CROSS="✗"
readonly WARN="⚠"
readonly ARROW="→"
# shellcheck disable=SC2034
readonly INFO="ℹ"

# ──────────────────────────────────────────────────────────────────────────────
# Core Configuration
# ──────────────────────────────────────────────────────────────────────────────
readonly SCRIPT_VERSION="3.1.0"
# shellcheck disable=SC2155
readonly BUILD_DATE="$(date +%Y%m%d_%H%M%S)"
readonly BUILD_ID="${BUILD_DATE}_$$"
# shellcheck disable=SC2155
readonly BUILD_START_TIME="$(date +%s)"

# Detect if running in interactive mode
INTERACTIVE_MODE=1
if [ ! -t 0 ] || [ ! -t 1 ]; then
    INTERACTIVE_MODE=0
fi

# ──────────────────────────────────────────────────────────────────────────────
# Paths (derive dynamically, then validate)
# ──────────────────────────────────────────────────────────────────────────────
# Base directory where this script lives
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# CRYPTOGRAM root: allow override via env, otherwise use script directory
CRYPTOGRAM_ROOT="${CRYPTOGRAM_ROOT:-$SCRIPT_DIR}"

# Validate CRYPTOGRAM_ROOT exists
if [ ! -d "${CRYPTOGRAM_ROOT}" ]; then
    echo "ERROR: CRYPTOGRAM_ROOT directory does not exist: ${CRYPTOGRAM_ROOT}"
    echo "Set it explicitly, e.g.:"
    echo "  export CRYPTOGRAM_ROOT=/path/to/CRYPTOGRAM"
    echo "  $0"
    exit 1
fi

readonly CRYPTOGRAM_ROOT
readonly BUILD_DIR="${CRYPTOGRAM_ROOT}/build_release"

# Make log directory user-specific to avoid permission conflicts
LOG_USER="${USER:-$(whoami 2>/dev/null || echo "user${UID}")}"

# Determine writable log directory with fallback
if [ -z "${LOG_DIR:-}" ]; then
    # Try /tmp first (user-specific)
    if mkdir -p "/tmp/cryptogram_builds_${LOG_USER}" 2>/dev/null && \
       [ -w "/tmp/cryptogram_builds_${LOG_USER}" ]; then
        LOG_DIR="/tmp/cryptogram_builds_${LOG_USER}"
    else
        # Fallback to user's cache directory
        LOG_DIR="$HOME/.cache/cryptogram_builds"
        mkdir -p "$LOG_DIR" 2>/dev/null || LOG_DIR="/tmp"
    fi
fi

readonly LOG_DIR
readonly LOG_FILE="${LOG_DIR}/build_${BUILD_DATE}.log"
readonly ERROR_LOG="${LOG_DIR}/errors_${BUILD_DATE}.log"
readonly STATE_FILE="${LOG_DIR}/state_${BUILD_DATE}.json"
readonly SUMMARY_FILE="${LOG_DIR}/summary_${BUILD_DATE}.txt"

# Build options
readonly DEFAULT_PREFIX="/usr/local"
readonly USER_PREFIX="${HOME}/.local"
INSTALL_PREFIX="${INSTALL_PREFIX:-$DEFAULT_PREFIX}"

# Auto-detect available tools
# shellcheck disable=SC2155
readonly NUM_CORES="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
# shellcheck disable=SC2155
readonly TOTAL_MEMORY="$(free -b 2>/dev/null | awk '/^Mem:/{print $2}' || echo 0)"

# Build flags with validation
VERBOSE_MODE="${VERBOSE:-1}"
DRY_RUN="${DRY_RUN:-0}"
FORCE_REBUILD="${FORCE:-0}"
RESUME_BUILD="${RESUME:-0}"
PARALLEL_JOBS="${JOBS:-$NUM_CORES}"

# Validate PARALLEL_JOBS is a number
if ! [[ "$PARALLEL_JOBS" =~ ^[0-9]+$ ]] || [ "$PARALLEL_JOBS" -lt 1 ]; then
    echo "WARNING: Invalid PARALLEL_JOBS value '$PARALLEL_JOBS', using $NUM_CORES"
    PARALLEL_JOBS="$NUM_CORES"
fi

# Component tracking
declare -A BUILD_STATE=(
    ["ada_cloned"]=0
    ["ada_built"]=0
    ["ada_installed"]=0
    ["protobuf_cloned"]=0
    ["protobuf_built"]=0
    ["protobuf_installed"]=0
    ["submodules_initialized"]=0
    ["cryptogram_configured"]=0
    ["cryptogram_built"]=0
)

# Timing tracking
declare -A COMPONENT_TIMES
declare -A STEP_START_TIMES

# ──────────────────────────────────────────────────────────────────────────────
# Git Submodule Management (simple helper – not used in main, kept for future)
# ──────────────────────────────────────────────────────────────────────────────
ensure_submodules() {
    # If this is not a git checkout or there are no submodules, skip.
    if [ ! -d "$CRYPTOGRAM_ROOT/.git" ] || [ ! -f "$CRYPTOGRAM_ROOT/.gitmodules" ]; then
        return 0
    fi

    print_progress "Ensuring git submodules are initialized (recursive)..."

    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "[DRY RUN] Would run: git submodule update --init --recursive"
        return 0
    fi

    (
        cd "$CRYPTOGRAM_ROOT" || exit 1
        git submodule update --init --recursive
    ) || fail "Failed to initialize git submodules"
}

# ──────────────────────────────────────────────────────────────────────────────
# Initialize Environment
# ──────────────────────────────────────────────────────────────────────────────
initialize() {
    # Ensure log directory exists with proper error handling
    if ! mkdir -p "$LOG_DIR" 2>/dev/null; then
        echo "ERROR: Cannot create log directory: $LOG_DIR"
        echo "Please check permissions or set LOG_DIR environment variable to a writable location."
        echo "Attempted fallback locations:"
        echo "  1. /tmp/cryptogram_builds_${LOG_USER}"
        echo "  2. $HOME/.cache/cryptogram_builds"
        echo "  3. /tmp"
        exit 1
    fi

    # Test write permissions
    if ! touch "$LOG_DIR/.write_test" 2>/dev/null; then
        echo "ERROR: Log directory exists but is not writable: $LOG_DIR"
        ls -ld "$LOG_DIR" 2>&1
        exit 1
    fi
    rm -f "$LOG_DIR/.write_test"

    # Initialize log files with error handling
    if ! : > "$LOG_FILE" 2>/dev/null; then
        echo "ERROR: Cannot create log file: $LOG_FILE"
        echo "Log directory: $LOG_DIR"
        ls -ld "$LOG_DIR" 2>&1
        exit 1
    fi

    if ! : > "$ERROR_LOG" 2>/dev/null; then
        echo "ERROR: Cannot create error log: $ERROR_LOG"
        exit 1
    fi

    # Log header with comprehensive information
    {
        echo "════════════════════════════════════════════════════════════════"
        echo "BUILD LOG - TSM + CRYPTOGRAM v${SCRIPT_VERSION}"
        echo "════════════════════════════════════════════════════════════════"
        echo ""
        echo "Build Information:"
        echo "  Started: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Build ID: $BUILD_ID"
        echo "  Script Version: $SCRIPT_VERSION"
        echo "  User: $LOG_USER"
        echo "  PID: $$"
        echo ""
        echo "Directories:"
        echo "  Source: $CRYPTOGRAM_ROOT"
        echo "  Build: $BUILD_DIR"
        echo "  Install Prefix: $INSTALL_PREFIX"
        echo "  Log Directory: $LOG_DIR"
        echo ""
        echo "System Information:"
        echo "  OS: $(uname -s) $(uname -r)"
        echo "  Architecture: $(uname -m)"
        echo "  CPU Cores: $NUM_CORES"
        echo "  Parallel Jobs: $PARALLEL_JOBS"
        echo "  Interactive Mode: $([ "$INTERACTIVE_MODE" -eq 1 ] && echo "Yes" || echo "No")"
        echo ""
        echo "Build Options:"
        echo "  Verbose: $VERBOSE_MODE"
        echo "  Dry Run: $DRY_RUN"
        echo "  Force Rebuild: $FORCE_REBUILD"
        echo "  Resume Build: $RESUME_BUILD"
        echo ""
        echo "════════════════════════════════════════════════════════════════"
        echo ""
    } >> "$LOG_FILE"

    log "INFO" "Build initialization complete"
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
    if [ $minutes -gt 60 ]; then
        local hours=$((minutes / 60))
        minutes=$((minutes % 60))
        printf "%dh %dm %ds" "$hours" "$minutes" "$remaining"
    elif [ $minutes -gt 0 ]; then
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
# Enhanced Logging Functions
# ──────────────────────────────────────────────────────────────────────────────
log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp
    timestamp="$(get_timestamp)"

    # Write to main log
    echo "[${timestamp}] [${level}] ${msg}" >> "$LOG_FILE" 2>/dev/null || true

    # Write errors to error log
    if [ "$level" = "ERROR" ] || [ "$level" = "FATAL" ]; then
        echo "[${timestamp}] ${msg}" >> "$ERROR_LOG" 2>/dev/null || true
    fi
}

print_header() {
    echo -e "${MAGENTA}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${NC} $1"
    echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════════╝${NC}"
    log "INFO" "=== $1 ==="
}

print_step() {
    local step_name="$1: $2"
    STEP_START_TIMES["$1"]="$(date +%s)"

    echo ""
    echo -e "${CYAN}┌────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} STEP ${step_name}"
    echo -e "${CYAN}└────────────────────────────────────────────────────────────────┘${NC}"
    log "STEP" "$step_name"
}

print_step_complete() {
    local step_id="$1"
    if [ -n "${STEP_START_TIMES[$step_id]:-}" ]; then
        local elapsed
        elapsed=$(($(date +%s) - ${STEP_START_TIMES[$step_id]}))
        log "STEP" "$step_id completed in $(format_time "$elapsed")"
    fi
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
    [ "$VERBOSE_MODE" -eq 1 ] && echo -e "${GRAY}[DEBUG] $1${NC}"
    log "DEBUG" "$1"
}

# ──────────────────────────────────────────────────────────────────────────────
# Enhanced Command Execution with Better Error Handling
# ──────────────────────────────────────────────────────────────────────────────
run_cmd() {
    local cmd="$*"
    local cmd_start
    cmd_start="$(date +%s)"

    print_debug "Executing: $cmd"
    log "CMD" "Running: $cmd"

    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "[DRY RUN] Would execute: $cmd"
        return 0
    fi

    if eval "$cmd" >> "$LOG_FILE" 2>&1; then
        local elapsed
        elapsed=$(($(date +%s) - cmd_start))
        log "CMD" "Completed in ${elapsed}s: $cmd"
        return 0
    else
        local exit_code=$?
        local elapsed
        elapsed=$(($(date +%s) - cmd_start))
        log "ERROR" "Command failed (exit $exit_code) after ${elapsed}s: $cmd"
        return "$exit_code"
    fi
}

run_cmd_verbose() {
    local cmd="$*"
    local cmd_start
    cmd_start="$(date +%s)"

    print_debug "Executing (verbose): $cmd"
    log "CMD" "Running (verbose): $cmd"

    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "[DRY RUN] Would execute: $cmd"
        return 0
    fi

    # Use tee to show output and save to log
    if eval "$cmd" 2>&1 | tee -a "$LOG_FILE"; then
        local exit_code=${PIPESTATUS[0]}
        local elapsed
        elapsed=$(($(date +%s) - cmd_start))
        if [ "$exit_code" -eq 0 ]; then
            log "CMD" "Completed in ${elapsed}s: $cmd"
            return 0
        else
            log "ERROR" "Command failed (exit $exit_code) after ${elapsed}s: $cmd"
            return "$exit_code"
        fi
    else
        local exit_code=$?
        local elapsed
        elapsed=$(($(date +%s) - cmd_start))
        log "ERROR" "Command failed (exit $exit_code) after ${elapsed}s: $cmd"
        return "$exit_code"
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# State Management with Validation
# ──────────────────────────────────────────────────────────────────────────────
save_state() {
    local tmp_state="${STATE_FILE}.tmp"

    # Generate JSON with proper escaping
    {
        echo "{"
        echo "  \"build_id\": \"$BUILD_ID\","
        echo "  \"timestamp\": \"$(get_timestamp)\","
        echo "  \"version\": \"$SCRIPT_VERSION\","
        echo "  \"state\": {"
        local first=1
        for key in "${!BUILD_STATE[@]}"; do
            [ $first -eq 0 ] && echo ","
            printf "    \"%s\": %s" "$key" "${BUILD_STATE[$key]}"
            first=0
        done
        echo ""
        echo "  }"
        echo "}"
    } > "$tmp_state"

    # Atomic move
    if mv "$tmp_state" "$STATE_FILE" 2>/dev/null; then
        print_debug "State saved successfully"
        log "STATE" "Build state saved"
    else
        print_warning "Failed to save build state"
        log "WARN" "Failed to save build state to $STATE_FILE"
    fi
}

load_state() {
    if [ -f "$STATE_FILE" ] && [ "$RESUME_BUILD" -eq 1 ]; then
        print_info "Loading previous build state..."
        log "STATE" "Attempting to load state from $STATE_FILE"

        # Simple state restoration
        local loaded=0
        while IFS='=' read -r key value; do
            if [[ -n "$key" ]] && [[ -n "$value" ]] && [[ "$value" =~ ^[01]$ ]]; then
                BUILD_STATE["$key"]="$value"
                print_debug "Restored: $key=$value"
                ((loaded++))
            fi
        done < <(grep -oP '"\K[^"]+(?=":)|(?<=":)\s*\K[01](?=\s*[,}])' "$STATE_FILE" 2>/dev/null | paste -d= - - 2>/dev/null)

        if [ $loaded -gt 0 ]; then
            print_info "Restored $loaded state values"
            log "STATE" "Successfully loaded $loaded state values"
            return 0
        else
            print_warning "Could not load previous state"
            log "WARN" "Failed to parse state file"
        fi
    fi
    return 1
}

# ──────────────────────────────────────────────────────────────────────────────
# Enhanced Error Handling with Context
# ──────────────────────────────────────────────────────────────────────────────
fail() {
    local msg="${1:-Build failed}"
    local line="${2:-$LINENO}"
    local func="${FUNCNAME[1]:-main}"

    echo ""
    print_error "$msg"
    echo ""
    log "FATAL" "$msg (function: $func, line: $line)"

    # Save state for resume
    save_state

    # Calculate total build time
    local total_time
    total_time=$(($(date +%s) - BUILD_START_TIME))

    # Show diagnostic info
    {
        echo ""
        echo "Build failed after $(format_time "$total_time")"
        echo ""
        echo "Error Details:"
        echo "  Message: $msg"
        echo "  Function: $func"
        echo "  Line: $line"
        echo ""
        echo "Logs available at:"
        echo "  Main log: $LOG_FILE"
        echo "  Error log: $ERROR_LOG"
        echo "  State file: $STATE_FILE"
        echo ""
        echo "Last 30 lines of log:"
        echo "════════════════════════════════════════════════════════════════"
    } | tee -a "$ERROR_LOG"

    tail -n 30 "$LOG_FILE" 2>/dev/null || echo "(log not available)"

    echo "════════════════════════════════════════════════════════════════"
    echo ""
    echo "To resume this build: $0 --resume"
    echo "To start fresh: $0 --force"
    echo ""

    exit 1
}

cleanup() {
    local exit_code=$?

    if [ "$exit_code" -eq 0 ]; then
        generate_summary
        local total_time
        total_time=$(($(date +%s) - BUILD_START_TIME))
        print_info "Build completed successfully in $(format_time "$total_time")!"
        log "INFO" "Build completed successfully"
    else
        save_state
        print_warning "Build interrupted with exit code $exit_code"
        log "WARN" "Build interrupted with exit code $exit_code"
    fi

    exit $exit_code
}

# Enhanced signal trapping with better error messages
trap 'fail "Unexpected error at line $LINENO in ${FUNCNAME[0]:-main}" "$LINENO"' ERR
trap 'fail "Build interrupted by user (Ctrl+C)" "$LINENO"' INT
trap 'fail "Build terminated by system" "$LINENO"' TERM
trap cleanup EXIT

# ──────────────────────────────────────────────────────────────────────────────
# System Checks with Enhanced Validation
# ──────────────────────────────────────────────────────────────────────────────
check_system() {
    print_step "1/9" "System Requirements Check"

    # OS Detection with validation
    print_progress "Checking operating system..."
    local os_info
    os_info="$(uname -s) $(uname -r) $(uname -m)"
    print_info "System: $os_info"
    log "SYSTEM" "Operating system: $os_info"

    # Validate supported OS
    case "$(uname -s)" in
        Linux)
            print_debug "Linux system detected"
            ;;
        Darwin)
            print_warning "macOS detected - some features may not work as expected"
            ;;
        *)
            print_warning "Unsupported OS: $(uname -s) - proceeding anyway"
            log "WARN" "Unsupported operating system: $(uname -s)"
            ;;
    esac

    # Memory Check with warnings
    print_progress "Checking memory..."
    local mem_gb=$((TOTAL_MEMORY / 1073741824))
    print_info "Memory: ${mem_gb}GB available"
    log "SYSTEM" "Total memory: ${mem_gb}GB"

    if [ $mem_gb -lt 2 ]; then
        print_error "Insufficient memory: ${mem_gb}GB (minimum 2GB required)"
        fail "Not enough memory to build"
    elif [ $mem_gb -lt 4 ]; then
        print_warning "Low memory: ${mem_gb}GB (4GB+ recommended for optimal performance)"
    fi

    # CPU Check with validation
    print_progress "Checking CPU..."
    print_info "CPU cores: $NUM_CORES"
    print_info "Parallel jobs: $PARALLEL_JOBS"
    log "SYSTEM" "CPU cores: $NUM_CORES, parallel jobs: $PARALLEL_JOBS"

    if [ "$NUM_CORES" -lt 2 ]; then
        print_warning "Single core detected - build will be slow"
    fi

    # Disk Space with critical checks
    print_progress "Checking disk space..."
    local available_space
    available_space=$(df "$HOME" 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)
    local available_gb=$((available_space / 1048576))
    print_info "Available disk: ${available_gb}GB"
    log "SYSTEM" "Available disk space: ${available_gb}GB"

    if [ $available_gb -lt 5 ]; then
        print_error "Insufficient disk space: ${available_gb}GB (minimum 5GB required)"
        fail "Not enough disk space"
    elif [ $available_gb -lt 10 ]; then
        print_warning "Low disk space: ${available_gb}GB (10GB+ recommended)"
    fi

    print_step_complete "1/9"
    echo ""
}

check_tools() {
    print_step "2/9" "Tool Dependencies Check"

    local missing_tools=()
    local tools=("git" "cmake" "make" "gcc" "g++")

    for tool in "${tools[@]}"; do
        print_progress "Checking for $tool..."
        if command -v "$tool" >/dev/null 2>&1; then
            local version
            version=$($tool --version 2>/dev/null | head -n1 || echo "unknown")
            print_info "$tool found: $version"
            log "TOOL" "$tool: $version"
        else
            print_error "$tool NOT found"
            missing_tools+=("$tool")
            log "ERROR" "Required tool not found: $tool"
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo ""
        print_error "Missing required tools: ${missing_tools[*]}"
        echo ""
        echo "Please install missing tools:"
        echo "  Debian/Ubuntu: sudo apt-get install ${missing_tools[*]}"
        echo "  Fedora/RHEL: sudo dnf install ${missing_tools[*]}"
        echo "  macOS: brew install ${missing_tools[*]}"
        echo ""
        fail "Missing required development tools"
    fi

    # Check CMake version
    if command -v cmake >/dev/null 2>&1; then
        local cmake_version
        cmake_version=$(cmake --version | head -n1 | grep -oP '\d+\.\d+\.\d+' || echo "0.0.0")
        local cmake_major
        cmake_major=$(echo "$cmake_version" | cut -d. -f1)
        local cmake_minor
        cmake_minor=$(echo "$cmake_version" | cut -d. -f2)

        if [ "$cmake_major" -lt 3 ] || { [ "$cmake_major" -eq 3 ] && [ "$cmake_minor" -lt 16 ]; }; then
            print_warning "CMake version $cmake_version is old (3.16+ recommended)"
        fi
    fi

    print_step_complete "2/9"
    echo ""
}

check_permissions() {
    print_step "3/9" "Permission Check"

    print_progress "Checking source directory..."

    if [ ! -d "$CRYPTOGRAM_ROOT" ]; then
        print_error "CRYPTOGRAM directory not found: $CRYPTOGRAM_ROOT"
        echo ""
        echo "Please ensure you're in the correct directory or set CRYPTOGRAM_ROOT:"
        echo "  export CRYPTOGRAM_ROOT=/path/to/CRYPTOGRAM"
        echo "  $0"
        echo ""
        fail "Source directory not found"
    fi

    if [ ! -r "$CRYPTOGRAM_ROOT" ]; then
        print_error "Cannot read CRYPTOGRAM directory: $CRYPTOGRAM_ROOT"
        ls -ld "$CRYPTOGRAM_ROOT" 2>&1
        fail "No read access to source directory"
    fi

    print_info "Source directory: $CRYPTOGRAM_ROOT"
    log "PERM" "Source directory validated: $CRYPTOGRAM_ROOT"

    print_progress "Checking installation directory permissions..."

    if [ -w "$INSTALL_PREFIX" ]; then
        print_info "Write access to $INSTALL_PREFIX: OK"
        log "PERM" "Write access confirmed: $INSTALL_PREFIX"
    else
        print_warning "No write access to $INSTALL_PREFIX"
        log "WARN" "No write access to: $INSTALL_PREFIX"

        if [ "$INTERACTIVE_MODE" -eq 1 ]; then
            echo ""
            echo "Options:"
            echo "1. Run with sudo: sudo $0"
            echo "2. Use user prefix: $0 --prefix=$USER_PREFIX"
            echo "3. Cancel and fix permissions"
            echo ""
            read -rp "Continue anyway? (y/N): " -n 1 choice
            echo ""
            if [ "$choice" != "y" ] && [ "$choice" != "Y" ]; then
                log "INFO" "User cancelled due to permission issues"
                echo "Aborting. Please fix permissions or use --prefix option."
                exit 0
            fi
            log "INFO" "User chose to continue despite permission warning"
        else
            print_warning "Non-interactive mode: attempting to continue with limited permissions"
            if [ "$INSTALL_PREFIX" = "$DEFAULT_PREFIX" ]; then
                INSTALL_PREFIX="$USER_PREFIX"
                print_info "Switching to user prefix: $INSTALL_PREFIX"
                mkdir -p "$INSTALL_PREFIX" || fail "Cannot create user prefix directory"
                log "INFO" "Switched to user prefix: $INSTALL_PREFIX"
            fi
        fi
    fi

    print_step_complete "3/9"
    echo ""
}

check_submodules() {
    print_step "4/9" "Git Submodules Check"

    # Work in CRYPTOGRAM_ROOT to avoid CWD surprises
    (
        cd "$CRYPTOGRAM_ROOT" || fail "Cannot change to CRYPTOGRAM_ROOT ($CRYPTOGRAM_ROOT)"

        # Check if we're in a git repository
        if ! git rev-parse --git-dir >/dev/null 2>&1; then
            print_warning "Not in a git repository, skipping submodule check"
            log "SUBMODULE" "Not in git repository, skipping"
            exit 0
        fi

        # Check if there are any submodules configured
        if [ ! -f ".gitmodules" ]; then
            print_info "No submodules configured, skipping"
            log "SUBMODULE" "No .gitmodules file found"
            exit 0
        fi

        print_progress "Checking git submodules..."
        log "SUBMODULE" "Starting submodule initialization"

        # Get list of submodules
        local submodule_count
        submodule_count=$(git config --file .gitmodules --get-regexp path 2>/dev/null | wc -l)
        if [ "$submodule_count" -eq 0 ]; then
            print_info "No submodules found in .gitmodules"
            log "SUBMODULE" "No submodules configured"
            exit 0
        fi

        print_info "Found $submodule_count submodule(s)"
        log "SUBMODULE" "Found $submodule_count submodules"

        # Check for broken submodule directories
        print_progress "Checking for broken submodule directories..."
        local fixed_count=0

        while IFS= read -r submodule_path; do
            if [ -d "$submodule_path" ] && [ ! -d "$submodule_path/.git" ] && [ ! -f "$submodule_path/.git" ]; then
                # Directory exists but is not a git repository (no .git dir or file)
                if [ -z "$(ls -A "$submodule_path" 2>/dev/null)" ]; then
                    # Directory is empty, safe to remove
                    print_warning "Removing empty submodule directory: $submodule_path"
                    log "SUBMODULE" "Removing empty directory: $submodule_path"
                    if rmdir "$submodule_path" 2>/dev/null; then
                        ((fixed_count++))
                        log "SUBMODULE" "Successfully removed: $submodule_path"
                    else
                        print_warning "Failed to remove $submodule_path"
                        log "WARN" "Could not remove directory: $submodule_path"
                    fi
                else
                    # Directory has content but no .git - this is problematic
                    print_error "Submodule directory exists but is not a git repository: $submodule_path"
                    print_error "Directory contains files:"
                    # shellcheck disable=SC2012
                    ls -la "$submodule_path" | head -10 | sed 's/^/  /'
                    echo ""
                    echo "Please manually remove or backup this directory:"
                    echo "  mv $submodule_path ${submodule_path}.backup"
                    echo "  # or"
                    echo "  rm -rf $submodule_path"
                    echo ""
                    log "ERROR" "Broken submodule directory with content: $submodule_path"
                    fail "Broken submodule state detected - manual intervention required"
                fi
            fi
        done < <(git config --file .gitmodules --get-regexp path 2>/dev/null | awk '{print $2}')

        if [ $fixed_count -gt 0 ]; then
            print_info "Fixed $fixed_count broken submodule director(ies)"
            log "SUBMODULE" "Fixed $fixed_count broken directories"
        fi

        if [ "$DRY_RUN" -eq 1 ]; then
            print_info "[DRY RUN] Would run: git submodule init && git submodule update --init --recursive"
            exit 0
        fi

        # Initialize submodules
        print_progress "Initializing git submodules..."
        log "SUBMODULE" "Running git submodule init"

        if ! git submodule init 2>&1 | tee -a "$LOG_FILE"; then
            print_error "Failed to initialize git submodules"
            log "ERROR" "git submodule init failed"
            fail "Failed to initialize git submodules"
        fi
        print_info "Submodules initialized"
        log "SUBMODULE" "Submodules initialized successfully"

        # Update submodules
        print_progress "Updating git submodules (this may take a while)..."
        log "SUBMODULE" "Running git submodule update --init --recursive"

        local update_start
        update_start=$(date +%s)
        if ! git submodule update --init --recursive 2>&1 | tee -a "$LOG_FILE"; then
            print_error "Failed to update git submodules"
            log "ERROR" "git submodule update --init --recursive failed"
            echo ""
            echo "Common solutions:"
            echo "  1. Check network connectivity"
            echo "  2. Ensure you have access to all submodule repositories"
            echo "  3. Verify .gitmodules configuration"
            echo "  4. Try manually: git submodule update --init --recursive --force"
            echo ""
            fail "Failed to update git submodules"
        fi

        local update_time
        update_time=$(($(date +%s) - update_start))
        print_info "Submodules updated successfully in $(format_time "$update_time")"
        log "SUBMODULE" "Submodules updated in $(format_time "$update_time")"

        # Show submodule status for verification
        print_debug "Verifying submodule status..."
        if git submodule status --recursive >> "$LOG_FILE" 2>&1; then
            log "SUBMODULE" "Submodule status verified"
        else
            log "WARN" "Could not verify submodule status"
        fi
    )

    BUILD_STATE["submodules_initialized"]=1
    save_state

    print_step_complete "4/9"
    echo ""
}

configure_compiler() {
    print_step "5/9" "Compiler Configuration"

    # Detect best available compiler
    print_progress "Detecting compilers..."
    log "COMPILER" "Starting compiler detection"

    # C Compiler
    CC=""
    local tried_cc=()
    for cc in gcc-13 gcc-12 gcc-11 gcc clang; do
        tried_cc+=("$cc")
        if command -v "$cc" >/dev/null 2>&1; then
            CC="$(command -v "$cc")"
            print_debug "Found C compiler: $CC"
            break
        fi
    done

    # C++ Compiler
    CXX=""
    local tried_cxx=()
    for cxx in g++-13 g++-12 g++-11 g++ clang++; do
        tried_cxx+=("$cxx")
        if command -v "$cxx" >/dev/null 2>&1; then
            CXX="$(command -v "$cxx")"
            print_debug "Found C++ compiler: $CXX"
            break
        fi
    done

    # Validate compilers were found
    if [ -z "${CC:-}" ]; then
        print_error "No C compiler found"
        echo ""
        echo "Tried: ${tried_cc[*]}"
        echo ""
        echo "Please install a C compiler:"
        echo "  Debian/Ubuntu: sudo apt-get install gcc"
        echo "  Fedora/RHEL: sudo dnf install gcc"
        echo "  macOS: xcode-select --install"
        echo ""
        log "ERROR" "No C compiler found. Tried: ${tried_cc[*]}"
        fail "No C compiler found"
    fi

    if [ -z "${CXX:-}" ]; then
        print_error "No C++ compiler found"
        echo ""
        echo "Tried: ${tried_cxx[*]}"
        echo ""
        echo "Please install a C++ compiler:"
        echo "  Debian/Ubuntu: sudo apt-get install g++"
        echo "  Fedora/RHEL: sudo dnf install gcc-c++"
        echo "  macOS: xcode-select --install"
        echo ""
        log "ERROR" "No C++ compiler found. Tried: ${tried_cxx[*]}"
        fail "No C++ compiler found"
    fi

    export CC
    export CXX

    print_info "C compiler: $CC"
    print_info "C++ compiler: $CXX"
    log "COMPILER" "Selected C compiler: $CC"
    log "COMPILER" "Selected C++ compiler: $CXX"

    # Get compiler versions
    if [ -n "$CC" ]; then
        local cc_version
        cc_version=$($CC --version 2>/dev/null | head -n1 || echo "unknown")
        print_debug "C compiler version: $cc_version"
        log "COMPILER" "C compiler version: $cc_version"
    fi

    if [ -n "$CXX" ]; then
        local cxx_version
        cxx_version=$($CXX --version 2>/dev/null | head -n1 || echo "unknown")
        print_debug "C++ compiler version: $cxx_version"
        log "COMPILER" "C++ compiler version: $cxx_version"
    fi

    # Set optimization flags with validation
    export CFLAGS="${CFLAGS:--O2 -pipe -march=native}"
    export CXXFLAGS="${CXXFLAGS:--O2 -pipe -march=native}"

    print_debug "CFLAGS: $CFLAGS"
    print_debug "CXXFLAGS: $CXXFLAGS"
    log "COMPILER" "CFLAGS: $CFLAGS"
    log "COMPILER" "CXXFLAGS: $CXXFLAGS"

    print_step_complete "5/9"
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# Build Functions with Enhanced Error Handling
# ──────────────────────────────────────────────────────────────────────────────
build_ada() {
    print_step "6/9" "Building Ada URL Parser"

    if [ "${BUILD_STATE["ada_installed"]}" -eq 1 ] && [ "$FORCE_REBUILD" -eq 0 ]; then
        print_info "Ada already installed, skipping..."
        log "BUILD" "Ada already installed, skipping rebuild"
        print_step_complete "6/9"
        echo ""
        return 0
    fi

    local ada_dir="/tmp/ada_$$"
    local start_time
    start_time=$(date +%s)

    log "BUILD" "Starting Ada build"
    log "BUILD" "Ada build directory: $ada_dir"

    print_progress "Cloning Ada repository..."
    run_cmd "rm -rf '$ada_dir'"

    if ! run_cmd_verbose "git clone --depth 1 https://github.com/ada-url/ada.git '$ada_dir'"; then
        print_error "Failed to clone Ada repository"
        echo ""
        echo "Possible issues:"
        echo "  - Network connectivity problems"
        echo "  - Git not configured properly"
        echo "  - GitHub access issues"
        echo ""
        fail "Failed to clone Ada repository"
    fi

    BUILD_STATE["ada_cloned"]=1
    save_state

    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "[DRY RUN] Skipping Ada configure/build/install steps"
        print_step_complete "6/9"
        echo ""
        return 0
    fi

    print_progress "Configuring Ada build..."
    cd "$ada_dir" || fail "Cannot change to Ada directory"
    mkdir -p build || fail "Cannot create Ada build directory"
    cd build || fail "Cannot change to Ada build directory"

    log "BUILD" "Configuring Ada with CMake"
    if ! run_cmd_verbose "cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX='$INSTALL_PREFIX'"; then
        print_error "Ada CMake configuration failed"
        fail "Ada CMake configuration failed"
    fi

    print_progress "Building Ada..."
    log "BUILD" "Building Ada with $PARALLEL_JOBS parallel jobs"

    if ! run_cmd_verbose "cmake --build . --config Release -j$PARALLEL_JOBS"; then
        print_error "Ada build failed"
        echo ""
        echo "Check the log file for detailed error messages:"
        echo "  $LOG_FILE"
        echo ""
        fail "Ada build compilation failed"
    fi

    BUILD_STATE["ada_built"]=1
    save_state

    print_progress "Installing Ada..."
    log "BUILD" "Installing Ada to $INSTALL_PREFIX"

    if ! run_cmd_verbose "cmake --install . --prefix '$INSTALL_PREFIX'"; then
        print_error "Ada installation failed"
        fail "Ada installation failed"
    fi

    # Comprehensive verification
    print_progress "Verifying Ada installation..."
    log "BUILD" "Verifying Ada installation"

    local ada_libs_found=0

    # Check for shared libraries
    if ls "$INSTALL_PREFIX"/lib/libada.so* >/dev/null 2>&1; then
        ada_libs_found=1
        print_debug "Found Ada shared libraries"
    fi

    # Check for static libraries
    if ls "$INSTALL_PREFIX"/lib/libada.a* >/dev/null 2>&1; then
        ada_libs_found=1
        print_debug "Found Ada static libraries"
    fi

    # Check for any libada files
    if ls "$INSTALL_PREFIX"/lib/libada.* >/dev/null 2>&1; then
        ada_libs_found=1
    fi

    if [ $ada_libs_found -eq 1 ]; then
        print_info "Ada verification PASSED"
        print_info "Libraries installed to: $INSTALL_PREFIX/lib"
        log "BUILD" "Ada verification passed"

        # List installed files
        print_debug "Installed Ada files:"
        # shellcheck disable=SC2012
        ls -lh "$INSTALL_PREFIX"/lib/libada.* 2>/dev/null | while read -r line; do
            print_debug "  $line"
        done

        BUILD_STATE["ada_installed"]=1
        save_state
    else
        print_error "Ada installation verification FAILED"
        echo ""
        echo "Diagnostics:"
        echo "  Expected location: $INSTALL_PREFIX/lib/libada.*"
        echo "  Contents of $INSTALL_PREFIX/lib:"
        # shellcheck disable=SC2012
        ls -lA "$INSTALL_PREFIX/lib" 2>&1 | head -20 | sed 's/^/    /'
        echo ""
        log "ERROR" "Ada verification failed - no libraries found"
        fail "Ada installation verification failed - no libraries found"
    fi

    # Cleanup
    cd / || true
    rm -rf "$ada_dir" 2>/dev/null || print_warning "Could not remove temporary Ada directory"

    local elapsed
    elapsed=$(($(date +%s) - start_time))
    COMPONENT_TIMES["ada"]=$elapsed
    print_info "Ada built and installed in $(format_time "$elapsed")"
    log "BUILD" "Ada build completed in $(format_time "$elapsed")"

    print_step_complete "6/9"
    echo ""
}

build_protobuf() {
    print_step "7/9" "Building Protocol Buffers"

    if [ "${BUILD_STATE["protobuf_installed"]}" -eq 1 ] && [ "$FORCE_REBUILD" -eq 0 ]; then
        print_info "Protobuf already installed, skipping..."
        log "BUILD" "Protobuf already installed, skipping rebuild"
        print_step_complete "7/9"
        echo ""
        return 0
    fi

    local protobuf_dir="/tmp/protobuf_$$"
    local start_time
    start_time=$(date +%s)

    log "BUILD" "Starting Protobuf build"
    log "BUILD" "Protobuf build directory: $protobuf_dir"

    print_progress "Cloning Protobuf repository..."
    run_cmd "rm -rf '$protobuf_dir'"

    if ! run_cmd_verbose "git clone --depth 1 https://github.com/protocolbuffers/protobuf.git '$protobuf_dir'"; then
        print_error "Failed to clone Protobuf repository"
        echo ""
        echo "Possible issues:"
        echo "  - Network connectivity problems"
        echo "  - Git not configured properly"
        echo "  - GitHub access issues"
        echo ""
        fail "Failed to clone Protobuf repository"
    fi

    BUILD_STATE["protobuf_cloned"]=1
    save_state

    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "[DRY RUN] Skipping Protobuf configure/build/install steps"
        print_step_complete "7/9"
        echo ""
        return 0
    fi

    print_progress "Configuring Protobuf build..."
    cd "$protobuf_dir" || fail "Cannot change to Protobuf directory"
    mkdir -p build || fail "Cannot create Protobuf build directory"
    cd build || fail "Cannot change to Protobuf build directory"

    log "BUILD" "Configuring Protobuf with CMake"
    if ! run_cmd_verbose "cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX='$INSTALL_PREFIX' -Dprotobuf_BUILD_TESTS=OFF"; then
        print_error "Protobuf CMake configuration failed"
        fail "Protobuf CMake configuration failed"
    fi

    print_progress "Building Protobuf (this may take 10-20 minutes)..."
    print_info "This is the longest build step - please be patient"
    log "BUILD" "Building Protobuf with $PARALLEL_JOBS parallel jobs"

    if ! run_cmd_verbose "cmake --build . --config Release -j$PARALLEL_JOBS"; then
        print_error "Protobuf build failed"
        echo ""
        echo "Protobuf build can fail due to:"
        echo "  - Insufficient memory (requires 4GB+ RAM)"
        echo "  - Compilation errors"
        echo "  - Disk space issues"
        echo ""
        echo "Check the log file for detailed error messages:"
        echo "  $LOG_FILE"
        echo ""
        fail "Protobuf build compilation failed"
    fi

    BUILD_STATE["protobuf_built"]=1
    save_state

    print_progress "Installing Protobuf..."
    log "BUILD" "Installing Protobuf to $INSTALL_PREFIX"

    if ! run_cmd_verbose "cmake --install . --prefix '$INSTALL_PREFIX'"; then
        print_warning "Protobuf installation command had errors"
        log "WARN" "Protobuf installation command returned non-zero"
    fi
    print_info "Protobuf installation command completed"

    # Comprehensive verification
    echo ""
    print_progress "Verifying Protobuf installation..."
    log "BUILD" "Verifying Protobuf installation"

    # Show what was installed (debug mode)
    if [ "$VERBOSE_MODE" -eq 1 ]; then
        print_debug "Checking $INSTALL_PREFIX/lib for Protobuf libraries..."
        if ls -lh "$INSTALL_PREFIX"/lib/libprotobuf*.* 2>/dev/null; then
            print_debug "Files listed above"
        else
            print_debug "No files found in $INSTALL_PREFIX/lib"
        fi
    fi

    # Check if libraries exist
    local protobuf_found=0

    # Check for shared libraries
    if ls "$INSTALL_PREFIX"/lib/libprotobuf.so* >/dev/null 2>&1; then
        protobuf_found=1
        print_debug "Found Protobuf shared libraries"
    fi

    # Check for static libraries
    if ls "$INSTALL_PREFIX"/lib/libprotobuf.a* >/dev/null 2>&1; then
        protobuf_found=1
        print_debug "Found Protobuf static libraries"
    fi

    # Check for any libprotobuf files
    if ls "$INSTALL_PREFIX"/lib/libprotobuf.* >/dev/null 2>&1; then
        protobuf_found=1
    fi

    if [ $protobuf_found -eq 1 ]; then
        print_info "Protobuf verification PASSED"
        print_info "Libraries installed to: $INSTALL_PREFIX/lib"
        log "BUILD" "Protobuf verification passed"

        # Check for protoc compiler
        if command -v protoc >/dev/null 2>&1; then
            local protoc_version
            protoc_version=$(protoc --version 2>/dev/null || echo "unknown")
            print_debug "Protocol buffer compiler: $protoc_version"
            log "BUILD" "protoc version: $protoc_version"
        fi

        BUILD_STATE["protobuf_installed"]=1
        save_state
    else
        # Check system paths as fallback
        print_warning "Protobuf libraries not found in $INSTALL_PREFIX/lib"
        log "WARN" "Protobuf not found in install prefix, checking system paths"

        SYSTEM_PROTO=$(find /usr -name 'libprotobuf.so*' -o -name 'libprotobuf.a' 2>/dev/null | head -n1)
        if [ -n "$SYSTEM_PROTO" ]; then
            print_warning "Found system Protobuf at: $SYSTEM_PROTO"
            print_warning "Using system Protobuf instead of locally built version"
            log "WARN" "Using system Protobuf: $SYSTEM_PROTO"
            BUILD_STATE["protobuf_installed"]=1
            save_state
        else
            print_error "Protobuf installation verification FAILED"
            echo ""
            echo "Diagnostics:"
            echo "  Expected location: $INSTALL_PREFIX/lib/libprotobuf.*"
            echo "  Permissions on $INSTALL_PREFIX/lib:"
            # shellcheck disable=SC2012
            ls -ld "$INSTALL_PREFIX/lib" 2>&1 | sed 's/^/    /'
            echo "  Contents of $INSTALL_PREFIX/lib (first 20 files):"
            # shellcheck disable=SC2012
            ls -lA "$INSTALL_PREFIX/lib" 2>&1 | head -20 | sed 's/^/    /'
            echo ""
            echo "Possible solutions:"
            echo "  1. Check if installation completed without errors above"
            echo "  2. Verify write permissions to $INSTALL_PREFIX"
            echo "  3. Try installing to user directory: $0 --prefix=$USER_PREFIX"
            echo ""
            log "ERROR" "Protobuf verification failed - no libraries found"
            fail "Protobuf installation verification failed - no libraries found"
        fi
    fi

    # Cleanup
    cd / || true
    rm -rf "$protobuf_dir" 2>/dev/null || print_warning "Could not remove temporary Protobuf directory"

    local elapsed
    elapsed=$(($(date +%s) - start_time))
    COMPONENT_TIMES["protobuf"]=$elapsed
    print_info "Protobuf built and installed in $(format_time "$elapsed")"
    log "BUILD" "Protobuf build completed in $(format_time "$elapsed")"

    print_step_complete "7/9"
    echo ""
}

configure_cryptogram() {
    print_step "8/9" "Configuring CRYPTOGRAM"

    if [ "${BUILD_STATE["cryptogram_configured"]}" -eq 1 ] && [ "$FORCE_REBUILD" -eq 0 ]; then
        print_info "CRYPTOGRAM already configured, skipping..."
        log "BUILD" "CRYPTOGRAM already configured, skipping"
        print_step_complete "8/9"
        echo ""
        return 0
    fi

    local start_time
    start_time=$(date +%s)

    log "BUILD" "Starting CRYPTOGRAM configuration"
    log "BUILD" "Build directory: $BUILD_DIR"

    print_progress "Creating build directory..."
    if ! mkdir -p "$BUILD_DIR" 2>/dev/null; then
        print_error "Cannot create build directory: $BUILD_DIR"
        fail "Cannot create build directory"
    fi

    cd "$BUILD_DIR" || fail "Cannot change to build directory"

    if [ "$FORCE_REBUILD" -eq 1 ]; then
        print_progress "Cleaning previous build (forced rebuild)..."
        run_cmd "rm -rf CMakeCache.txt CMakeFiles"
        log "BUILD" "Cleaned previous CMake cache"
    fi

    print_progress "Running CMake configuration..."
    log "BUILD" "Running CMake with Release configuration"

    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "[DRY RUN] Would run CMake configuration for CRYPTOGRAM"
    else
        if ! run_cmd_verbose "cmake -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH='$INSTALL_PREFIX' \
        -DDESKTOP_APP_DISABLE_AUTOUPDATE=ON \
        -DDESKTOP_APP_DISABLE_CRASH_REPORTS=ON \
        '$CRYPTOGRAM_ROOT'"; then
            print_error "CMake configuration failed"
            echo ""
            echo "Common issues:"
            echo "  - Missing dependencies (Qt, etc.)"
            echo "  - Ada or Protobuf not found"
            echo "  - CMake version too old"
            echo ""
            echo "Check the log file for detailed error messages:"
            echo "  $LOG_FILE"
            echo ""
            fail "CMake configuration failed"
        fi
    fi

    BUILD_STATE["cryptogram_configured"]=1
    save_state

    local elapsed
    elapsed=$(($(date +%s) - start_time))
    COMPONENT_TIMES["configure"]=$elapsed
    print_info "Configuration completed in $(format_time "$elapsed")"
    log "BUILD" "Configuration completed in $(format_time "$elapsed")"

    print_step_complete "8/9"
    echo ""
}

build_cryptogram() {
    print_step "9/9" "Building CRYPTOGRAM Desktop"

    if [ "${BUILD_STATE["cryptogram_built"]}" -eq 1 ] && [ "$FORCE_REBUILD" -eq 0 ]; then
        print_info "CRYPTOGRAM already built, skipping..."
        log "BUILD" "CRYPTOGRAM already built, skipping"
        print_step_complete "9/9"
        echo ""
        return 0
    fi

    if [ ! -d "$BUILD_DIR" ]; then
        print_error "Build directory does not exist: $BUILD_DIR"
        fail "Build directory not found - run configure first"
    fi

    cd "$BUILD_DIR" || fail "Cannot change to build directory"
    local start_time
    start_time=$(date +%s)

    log "BUILD" "Starting CRYPTOGRAM compilation"

    print_progress "Starting CRYPTOGRAM build with $PARALLEL_JOBS parallel jobs..."
    print_warning "This will take 20-60 minutes depending on your system"
    print_info "Progress will be shown in real-time below"
    echo ""

    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "[DRY RUN] Would run CRYPTOGRAM build"
    else
        if ! run_cmd_verbose "cmake --build . --config Release --parallel $PARALLEL_JOBS"; then
            print_error "CRYPTOGRAM build failed"
            echo ""
            echo "Common issues:"
            echo "  - Compilation errors"
            echo "  - Missing dependencies"
            echo "  - Insufficient memory"
            echo "  - Disk space issues"
            echo ""
            echo "Check the log file for detailed error messages:"
            echo "  $LOG_FILE"
            echo ""
            fail "CRYPTOGRAM build compilation failed"
        fi

        BUILD_STATE["cryptogram_built"]=1
        save_state
    fi

    local elapsed
    elapsed=$(($(date +%s) - start_time))
    COMPONENT_TIMES["cryptogram"]=$elapsed
    print_info "CRYPTOGRAM built in $(format_time "$elapsed")"
    log "BUILD" "CRYPTOGRAM build completed in $(format_time "$elapsed")"

    # Verify executable
    print_progress "Verifying build output..."
    log "BUILD" "Verifying executable"

    local exec_path="$BUILD_DIR/bin/Telegram"
    if [ ! -f "$exec_path" ]; then
        print_debug "Executable not in expected location, searching..."
        exec_path=$(find "$BUILD_DIR" -name 'Telegram' -type f -executable 2>/dev/null | head -n1)
    fi

    if [ -n "$exec_path" ] && [ -x "$exec_path" ]; then
        local size
        size=$(stat -c%s "$exec_path" 2>/dev/null || stat -f%z "$exec_path" 2>/dev/null || echo 0)
        print_info "Executable found: $exec_path ($(format_size "$size"))"
        log "BUILD" "Executable verified: $exec_path ($(format_size "$size"))"
        echo "CRYPTOGRAM_EXEC=$exec_path" >> "$SUMMARY_FILE"
    else
        print_error "CRYPTOGRAM executable not found"
        echo ""
        echo "Expected locations:"
        echo "  $BUILD_DIR/bin/Telegram"
        echo "  $BUILD_DIR/Telegram"
        echo ""
        echo "Searching for executable..."
        find "$BUILD_DIR" -name 'Telegram' -type f 2>/dev/null | head -5
        echo ""
        log "ERROR" "Executable not found after build"
        fail "CRYPTOGRAM executable not found after build"
    fi

    print_step_complete "9/9"
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# Summary Generation with Enhanced Metrics
# ──────────────────────────────────────────────────────────────────────────────
generate_summary() {
    local total_time
    total_time=$(($(date +%s) - BUILD_START_TIME))
    local component_time=0

    for time in "${COMPONENT_TIMES[@]}"; do
        component_time=$((component_time + time))
    done

    {
        echo "════════════════════════════════════════════════════════════════"
        echo "                    BUILD SUMMARY"
        echo "════════════════════════════════════════════════════════════════"
        echo ""
        echo "Build Information:"
        echo "  Build ID: $BUILD_ID"
        echo "  Completed: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Total Time: $(format_time "$total_time")"
        echo "  Script Version: $SCRIPT_VERSION"
        echo ""
        echo "Component Build Times:"
        for component in ada protobuf configure cryptogram; do
            if [ -n "${COMPONENT_TIMES[$component]:-}" ]; then
                printf "  %-20s: %s\n" "$component" "$(format_time "${COMPONENT_TIMES[$component]}")"
            fi
        done
        echo "  ────────────────────────────────────────────"
        printf "  %-20s: %s\n" "Total (components)" "$(format_time "$component_time")"
        printf "  %-20s: %s\n" "Total (wall clock)" "$(format_time "$total_time")"
        local overhead=$((total_time - component_time))
        if [ $overhead -gt 0 ]; then
            printf "  %-20s: %s\n" "Overhead" "$(format_time "$overhead")"
        fi
        echo ""
        echo "Build Configuration:"
        echo "  Source: $CRYPTOGRAM_ROOT"
        echo "  Build Directory: $BUILD_DIR"
        echo "  Install Prefix: $INSTALL_PREFIX"
        echo "  Parallel Jobs: $PARALLEL_JOBS"
        echo "  Compiler: ${CC##*/} / ${CXX##*/}"
        echo ""
        echo "System Information:"
        echo "  OS: $(uname -s) $(uname -r)"
        echo "  Architecture: $(uname -m)"
        echo "  CPU Cores: $NUM_CORES"
        echo ""
        echo "Logs and State:"
        echo "  Main Log: $LOG_FILE"
        echo "  Error Log: $ERROR_LOG"
        echo "  State File: $STATE_FILE"
        echo ""
        echo "════════════════════════════════════════════════════════════════"
    } | tee -a "$SUMMARY_FILE"

    cat "$SUMMARY_FILE"
    log "SUMMARY" "Build summary generated"
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
                # Validate is number
                if ! [[ "$PARALLEL_JOBS" =~ ^[0-9]+$ ]]; then
                    echo "ERROR: Invalid jobs value: $PARALLEL_JOBS"
                    exit 1
                fi
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
    [ "$INTERACTIVE_MODE" -eq 1 ] && [ -t 1 ] && clear || true

    # Header
    print_header "TSM + CRYPTOGRAM Build Script v$SCRIPT_VERSION"

    echo "Configuration:"
    echo "  Root: $CRYPTOGRAM_ROOT"
    echo "  Build: $BUILD_DIR"
    echo "  Prefix: $INSTALL_PREFIX"
    echo "  Jobs: $PARALLEL_JOBS"
    [ "$DRY_RUN" -eq 1 ] && echo "  Mode: DRY RUN"
    [ "$RESUME_BUILD" -eq 1 ] && echo "  Mode: RESUME"
    [ "$FORCE_REBUILD" -eq 1 ] && echo "  Mode: FORCE REBUILD"
    echo ""

    # Try to load previous state
    if load_state; then
        echo "Resuming from previous build state"
        echo ""
    fi

    # Interactive confirmation
    if [ "$INTERACTIVE_MODE" -eq 1 ] && [ -t 0 ]; then
        read -rp "Press ENTER to start build or Ctrl+C to cancel..."
        log "INFO" "User confirmed build start"
    else
        print_warning "Non-interactive mode - starting build automatically in 3 seconds..."
        sleep 3
        log "INFO" "Build started in non-interactive mode"
    fi

    # Run build steps
    check_system
    check_tools
    check_permissions
    check_submodules
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
        EXEC_PATH=$(grep "^CRYPTOGRAM_EXEC=" "$SUMMARY_FILE" 2>/dev/null | cut -d= -f2)
        if [ -n "$EXEC_PATH" ]; then
            echo ""
            echo "Next steps:"
            echo "1. Run CRYPTOGRAM: $EXEC_PATH"
            echo "2. With TSM: cd $CRYPTOGRAM_ROOT && source .tsm_cryptogram_env.sh && $EXEC_PATH"
            echo ""
        fi
    fi

    log "INFO" "Build completed successfully"
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
    -j, --jobs=N        Parallel jobs (default: auto-detected = $NUM_CORES)
    --force             Force rebuild all components
    --resume            Resume from previous state
    --dry-run           Preview without executing
    --verbose           Enable verbose output
    -q, --quiet         Quiet mode

ENVIRONMENT:
    CRYPTOGRAM_ROOT     Source directory (default: directory containing this script: $SCRIPT_DIR)
    LOG_DIR             Log directory (default: auto-detected)
    INSTALL_PREFIX      Installation prefix
    CC/CXX              Compiler override
    CFLAGS/CXXFLAGS     Compiler flags override
    VERBOSE             Verbosity (0/1)
    JOBS                Parallel jobs

EXAMPLES:
    # Standard build
    $0

    # User installation
    $0 --prefix=\$HOME/.local

    # Resume interrupted build
    $0 --resume

    # Force rebuild with 8 jobs
    $0 --force -j8

    # Dry run to see what would happen
    $0 --dry-run

LOGS:
    Logs are saved to: $LOG_DIR/
    - build_*.log      Main build log
    - errors_*.log     Error messages only
    - state_*.json     Build state for resume
    - summary_*.txt    Build summary

EOF
}

# Entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
