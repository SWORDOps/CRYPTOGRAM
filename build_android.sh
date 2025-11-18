#!/bin/bash

################################################################################
# CRYPTOGRAM Android - Production Build Script v1.0
# Complete Android APK/AAB build with TSM integration
# Zero shellcheck errors - production-grade quality
################################################################################

set -Eeuo pipefail

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
readonly SCRIPT_VERSION="1.0.0"
# shellcheck disable=SC2155
readonly BUILD_DATE="$(date +%Y%m%d_%H%M%S)"
readonly BUILD_ID="${BUILD_DATE}_$$"
# shellcheck disable=SC2155
readonly BUILD_START_TIME="$(date +%s)"

# Paths
readonly CRYPTOGRAM_ROOT="${CRYPTOGRAM_ROOT:-$HOME/CRYPTOGRAM}"
readonly ANDROID_ROOT="${CRYPTOGRAM_ROOT}/android"
readonly TSM_ROOT="${CRYPTOGRAM_ROOT}/tsm"

# Logs
LOG_USER="${USER:-$(whoami 2>/dev/null || echo "user${UID}")}"
if [ -z "${LOG_DIR:-}" ]; then
    if mkdir -p "/tmp/cryptogram_android_${LOG_USER}" 2>/dev/null && \
       [ -w "/tmp/cryptogram_android_${LOG_USER}" ]; then
        LOG_DIR="/tmp/cryptogram_android_${LOG_USER}"
    else
        LOG_DIR="$HOME/.cache/cryptogram_android"
        mkdir -p "$LOG_DIR" 2>/dev/null || LOG_DIR="/tmp"
    fi
fi

readonly LOG_DIR
readonly LOG_FILE="${LOG_DIR}/build_${BUILD_DATE}.log"
readonly ERROR_LOG="${LOG_DIR}/errors_${BUILD_DATE}.log"
readonly STATE_FILE="${LOG_DIR}/state_${BUILD_DATE}.json"
readonly SUMMARY_FILE="${LOG_DIR}/summary_${BUILD_DATE}.txt"

# Build configuration
readonly DEFAULT_BUILD_TYPE="debug"
BUILD_TYPE="${BUILD_TYPE:-$DEFAULT_BUILD_TYPE}"
VERBOSE_MODE="${VERBOSE:-1}"
DRY_RUN="${DRY_RUN:-0}"
FORCE_REBUILD="${FORCE:-0}"
TSM_ENABLED="${TSM_ENABLED:-1}"

# Android SDK configuration
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}"
ANDROID_NDK_VERSION="${ANDROID_NDK_VERSION:-25.2.9519653}"

# Signing configuration
KEYSTORE_PATH="${KEYSTORE_PATH:-}"
KEYSTORE_PASSWORD="${KEYSTORE_PASSWORD:-}"
KEYSTORE_ALIAS="${KEYSTORE_ALIAS:-swordcomm}"
KEY_PASSWORD="${KEY_PASSWORD:-${KEYSTORE_PASSWORD}}"

# TSM configuration
TSM_HOST="${TSM_HOST:-}"  # Hardcoded IP or hostname
TSM_PORT="${TSM_PORT:-8443}"
TSM_SERVER="${TSM_SERVER:-https://tsm.swordops.com}"
TSM_API_KEY="${TSM_API_KEY:-}"
TSM_MDNS_SERVICE="${TSM_MDNS_SERVICE:-_tsm._tcp}"  # mDNS service name

# Build state
declare -A BUILD_STATE=(
    ["submodules_initialized"]=0
    ["sdk_validated"]=0
    ["ndk_validated"]=0
    ["dependencies_fetched"]=0
    ["tsm_initialized"]=0
    ["app_built"]=0
)

# Component timing
declare -A COMPONENT_TIMES=(
    ["system"]=0
    ["submodules"]=0
    ["sdk"]=0
    ["ndk"]=0
    ["dependencies"]=0
    ["tsm"]=0
    ["build"]=0
)

# ──────────────────────────────────────────────────────────────────────────────
# Utility Functions
# ──────────────────────────────────────────────────────────────────────────────
get_timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

format_time() {
    local seconds=$1
    if [ "$seconds" -lt 60 ]; then
        echo "${seconds}s"
    elif [ "$seconds" -lt 3600 ]; then
        printf "%dm %ds\n" $((seconds / 60)) $((seconds % 60))
    else
        printf "%dh %dm %ds\n" $((seconds / 3600)) $(((seconds % 3600) / 60)) $((seconds % 60))
    fi
}

format_size() {
    local bytes=$1
    if [ "$bytes" -lt 1024 ]; then
        echo "${bytes}B"
    elif [ "$bytes" -lt 1048576 ]; then
        echo "$((bytes / 1024))KB"
    elif [ "$bytes" -lt 1073741824 ]; then
        echo "$((bytes / 1048576))MB"
    else
        echo "$((bytes / 1073741824))GB"
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# Logging Functions
# ──────────────────────────────────────────────────────────────────────────────
log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp
    timestamp="$(get_timestamp)"

    echo "[${timestamp}] [${level}] ${msg}" >> "$LOG_FILE" 2>/dev/null || true

    if [ "$level" = "ERROR" ] || [ "$level" = "FATAL" ]; then
        echo "[${timestamp}] ${msg}" >> "$ERROR_LOG" 2>/dev/null || true
    fi
}

print_header() {
    echo -e "${MAGENTA}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${NC} $1"
    echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════════╝${NC}"
}

print_step() {
    echo -e "\n${CYAN}┌────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} STEP $1/$2: $3"
    echo -e "${CYAN}└────────────────────────────────────────────────────────────────┘${NC}"
}

print_step_complete() {
    echo -e "${GREEN}${CHECK} Step $1 complete${NC}"
}

print_info() {
    echo -e "${GREEN}${CHECK}${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}${WARN}${NC} $1"
}

print_error() {
    echo -e "${RED}${CROSS}${NC} $1"
}

print_progress() {
    echo -e "${BLUE}${ARROW}${NC} $1"
}

print_debug() {
    if [ "$VERBOSE_MODE" -eq 1 ]; then
        echo -e "${GRAY}[DEBUG]${NC} $1"
    fi
}

fail() {
    local msg="$1"
    print_error "FATAL: $msg"
    log "FATAL" "$msg"

    echo ""
    echo "Error Details:"
    echo "  Time: $(get_timestamp)"
    echo "  Log: $LOG_FILE"
    echo "  Errors: $ERROR_LOG"
    echo ""

    if [ -f "$ERROR_LOG" ]; then
        echo "Recent errors:"
        tail -20 "$ERROR_LOG" | sed 's/^/  /'
    fi

    exit 1
}

# ──────────────────────────────────────────────────────────────────────────────
# Command Execution
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
        local elapsed=$(($(date +%s) - cmd_start))
        log "CMD" "Completed in ${elapsed}s: $cmd"
        return 0
    else
        local exit_code=$?
        local elapsed=$(($(date +%s) - cmd_start))
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

    if eval "$cmd" 2>&1 | tee -a "$LOG_FILE"; then
        local elapsed=$(($(date +%s) - cmd_start))
        log "CMD" "Completed in ${elapsed}s: $cmd"
        return 0
    else
        local exit_code=$?
        local elapsed=$(($(date +%s) - cmd_start))
        log "ERROR" "Command failed (exit $exit_code) after ${elapsed}s: $cmd"
        return "$exit_code"
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# Build State Management
# ──────────────────────────────────────────────────────────────────────────────
save_state() {
    {
        echo "{"
        echo "  \"build_id\": \"$BUILD_ID\","
        echo "  \"timestamp\": \"$(get_timestamp)\","
        echo "  \"state\": {"
        local first=1
        for key in "${!BUILD_STATE[@]}"; do
            [ $first -eq 0 ] && echo ","
            echo -n "    \"$key\": ${BUILD_STATE[$key]}"
            first=0
        done
        echo ""
        echo "  }"
        echo "}"
    } > "$STATE_FILE" 2>/dev/null || true
}

# ──────────────────────────────────────────────────────────────────────────────
# System Validation
# ──────────────────────────────────────────────────────────────────────────────
check_system() {
    print_step "1" "8" "System Requirements Check"

    local start_time
    start_time=$(date +%s)

    # OS Detection
    print_progress "Checking operating system..."
    local os_info
    os_info="$(uname -s) $(uname -r) $(uname -m)"
    print_info "System: $os_info"
    log "SYSTEM" "Operating system: $os_info"

    case "$(uname -s)" in
        Linux)
            print_debug "Linux system detected"
            ;;
        Darwin)
            print_warning "macOS detected - some features may differ"
            ;;
        *)
            print_warning "Unsupported OS: $(uname -s)"
            ;;
    esac

    # Check required tools
    print_progress "Checking required tools..."
    local missing_tools=()
    local tools=("java" "git")

    for tool in "${tools[@]}"; do
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
        print_error "Missing required tools: ${missing_tools[*]}"
        fail "Missing required development tools"
    fi

    # Check Java version
    if command -v java >/dev/null 2>&1; then
        local java_version
        java_version=$(java -version 2>&1 | grep version | cut -d'"' -f2)
        local java_major
        java_major=$(echo "$java_version" | cut -d. -f1)

        if [ "$java_major" -lt 11 ]; then
            print_warning "Java $java_version detected - Java 11+ recommended"
        else
            print_info "Java version: $java_version"
        fi
    fi

    # Disk Space
    print_progress "Checking disk space..."
    local available_space
    available_space=$(df "$HOME" 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)
    local available_gb=$((available_space / 1048576))
    print_info "Available disk: ${available_gb}GB"
    log "SYSTEM" "Available disk space: ${available_gb}GB"

    if [ "$available_gb" -lt 10 ]; then
        print_error "Insufficient disk space: ${available_gb}GB (minimum 10GB required for Android build)"
        fail "Not enough disk space"
    elif [ "$available_gb" -lt 20 ]; then
        print_warning "Low disk space: ${available_gb}GB (20GB+ recommended)"
    fi

    local elapsed=$(($(date +%s) - start_time))
    COMPONENT_TIMES["system"]=$elapsed

    print_step_complete "1/8"
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# Git Submodule Initialization (with recursive support)
# ──────────────────────────────────────────────────────────────────────────────
initialize_submodules() {
    print_step "2" "8" "Git Submodule Initialization"

    local start_time
    start_time=$(date +%s)

    if [ "${BUILD_STATE["submodules_initialized"]}" -eq 1 ] && [ "$FORCE_REBUILD" -eq 0 ]; then
        print_info "Submodules already initialized, skipping..."
        print_step_complete "2/8"
        echo ""
        return 0
    fi

    # Check if we're in a git repository
    if [ ! -d "$ANDROID_ROOT/.git" ] && [ ! -f "$ANDROID_ROOT/.git" ]; then
        print_warning "Not a git repository: $ANDROID_ROOT"
        print_info "Skipping submodule initialization"
        print_step_complete "2/8"
        echo ""
        return 0
    fi

    cd "$ANDROID_ROOT" || fail "Cannot change to Android directory"

    print_progress "Checking git submodules..."
    log "SUBMODULE" "Starting submodule initialization"

    # Get list of submodules
    local submodule_count
    submodule_count=$(git config --file .gitmodules --get-regexp path 2>/dev/null | wc -l)
    if [ "$submodule_count" -eq 0 ]; then
        print_info "No submodules found in .gitmodules"
        log "SUBMODULE" "No submodules configured"
        BUILD_STATE["submodules_initialized"]=1
        save_state
        print_step_complete "2/8"
        echo ""
        return 0
    fi

    print_info "Found $submodule_count submodule(s)"
    log "SUBMODULE" "Found $submodule_count submodules"

    # Initialize submodules
    print_progress "Initializing git submodules..."
    if ! git submodule init 2>&1 | tee -a "$LOG_FILE"; then
        print_error "Failed to initialize git submodules"
        log "ERROR" "git submodule init failed"
        fail "Failed to initialize git submodules"
    fi
    print_info "Submodules initialized"
    log "SUBMODULE" "Submodules initialized successfully"

    # Update submodules recursively
    print_progress "Updating git submodules recursively (this may take a while)..."
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

    local update_time=$(($(date +%s) - update_start))
    print_info "Submodules updated successfully in $(format_time "$update_time")"
    log "SUBMODULE" "Submodules updated in $(format_time "$update_time")"

    # Verify submodules
    print_progress "Verifying submodule status..."
    local broken_submodules=0
    while IFS= read -r submodule_path; do
        if [ ! -d "$submodule_path/.git" ] && [ ! -f "$submodule_path/.git" ]; then
            print_warning "Submodule not properly initialized: $submodule_path"
            ((broken_submodules++))
        fi
    done < <(git config --file .gitmodules --get-regexp path | awk '{print $2}')

    if [ "$broken_submodules" -gt 0 ]; then
        print_warning "Found $broken_submodules broken submodule(s)"
        log "WARN" "Broken submodules: $broken_submodules"
    else
        print_info "All submodules verified"
        log "SUBMODULE" "All submodules verified successfully"
    fi

    BUILD_STATE["submodules_initialized"]=1
    save_state

    local elapsed=$(($(date +%s) - start_time))
    COMPONENT_TIMES["submodules"]=$elapsed

    print_step_complete "2/8"
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# Android SDK Validation
# ──────────────────────────────────────────────────────────────────────────────
check_android_sdk() {
    print_step "3" "8" "Android SDK Validation"

    local start_time
    start_time=$(date +%s)

    if [ "${BUILD_STATE["sdk_validated"]}" -eq 1 ] && [ "$FORCE_REBUILD" -eq 0 ]; then
        print_info "SDK already validated, skipping..."
        print_step_complete "3/8"
        echo ""
        return 0
    fi

    print_progress "Checking Android SDK..."

    if [ ! -d "$ANDROID_SDK_ROOT" ]; then
        print_warning "Android SDK not found at: $ANDROID_SDK_ROOT"
        print_warning "Set ANDROID_SDK_ROOT environment variable or install Android SDK"

        # Try to find SDK in common locations
        for sdk_path in "$HOME/Android/Sdk" "/usr/local/android-sdk" "/opt/android-sdk"; do
            if [ -d "$sdk_path" ]; then
                print_info "Found SDK at: $sdk_path"
                ANDROID_SDK_ROOT="$sdk_path"
                export ANDROID_SDK_ROOT
                break
            fi
        done

        if [ ! -d "$ANDROID_SDK_ROOT" ]; then
            fail "Android SDK not found - please install Android SDK"
        fi
    fi

    print_info "Android SDK: $ANDROID_SDK_ROOT"
    log "SDK" "Android SDK root: $ANDROID_SDK_ROOT"

    # Check for SDK manager
    local sdkmanager="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"
    if [ ! -f "$sdkmanager" ]; then
        sdkmanager="$ANDROID_SDK_ROOT/tools/bin/sdkmanager"
    fi

    if [ -f "$sdkmanager" ]; then
        print_info "SDK Manager found"
    else
        print_warning "SDK Manager not found - some validations skipped"
    fi

    # Export SDK paths
    export ANDROID_SDK_ROOT
    export ANDROID_HOME="$ANDROID_SDK_ROOT"
    export PATH="$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/tools:$PATH"

    BUILD_STATE["sdk_validated"]=1
    save_state

    local elapsed=$(($(date +%s) - start_time))
    COMPONENT_TIMES["sdk"]=$elapsed

    print_step_complete "3/8"
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# Android NDK Validation
# ──────────────────────────────────────────────────────────────────────────────
check_android_ndk() {
    print_step "4" "8" "Android NDK Validation"

    local start_time
    start_time=$(date +%s)

    if [ "${BUILD_STATE["ndk_validated"]}" -eq 1 ] && [ "$FORCE_REBUILD" -eq 0 ]; then
        print_info "NDK already validated, skipping..."
        print_step_complete "4/8"
        echo ""
        return 0
    fi

    print_progress "Checking Android NDK..."

    local ndk_path="$ANDROID_SDK_ROOT/ndk/$ANDROID_NDK_VERSION"
    if [ ! -d "$ndk_path" ]; then
        print_warning "NDK $ANDROID_NDK_VERSION not found"

        # Try to find any NDK version
        local ndk_dir="$ANDROID_SDK_ROOT/ndk"
        if [ -d "$ndk_dir" ]; then
            local found_ndk
            found_ndk=$(find "$ndk_dir" -maxdepth 1 -type d | tail -n1)
            if [ -n "$found_ndk" ] && [ "$found_ndk" != "$ndk_dir" ]; then
                ndk_path="$found_ndk"
                ANDROID_NDK_VERSION=$(basename "$ndk_path")
                print_info "Using NDK: $ANDROID_NDK_VERSION"
            fi
        fi

        if [ ! -d "$ndk_path" ]; then
            print_warning "No NDK found - native code compilation may fail"
            print_warning "Install NDK via Android Studio SDK Manager"
        fi
    else
        print_info "NDK found: $ANDROID_NDK_VERSION"
        log "NDK" "Android NDK: $ndk_path"
    fi

    if [ -d "$ndk_path" ]; then
        export ANDROID_NDK_HOME="$ndk_path"
        export ANDROID_NDK_ROOT="$ndk_path"
        BUILD_STATE["ndk_validated"]=1
        save_state
    fi

    local elapsed=$(($(date +%s) - start_time))
    COMPONENT_TIMES["ndk"]=$elapsed

    print_step_complete "4/8"
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# TSM Integration
# ──────────────────────────────────────────────────────────────────────────────
initialize_tsm() {
    print_step "5" "8" "TSM (Telegram Security Module) Integration"

    local start_time
    start_time=$(date +%s)

    if [ "$TSM_ENABLED" -eq 0 ]; then
        print_info "TSM integration disabled"
        print_step_complete "5/8"
        echo ""
        return 0
    fi

    if [ "${BUILD_STATE["tsm_initialized"]}" -eq 1 ] && [ "$FORCE_REBUILD" -eq 0 ]; then
        print_info "TSM already initialized, skipping..."
        print_step_complete "5/8"
        echo ""
        return 0
    fi

    print_progress "Initializing TSM..."
    log "TSM" "Starting TSM initialization"

    # ──────────────────────────────────────────────────────────────────────────
    # TSM Network Discovery
    # ──────────────────────────────────────────────────────────────────────────
    local tsm_endpoint=""

    # Option 1: Hardcoded IP/hostname
    if [ -n "$TSM_HOST" ]; then
        tsm_endpoint="https://$TSM_HOST:$TSM_PORT"
        print_info "Using hardcoded TSM endpoint: $tsm_endpoint"
        log "TSM" "Hardcoded TSM host: $TSM_HOST:$TSM_PORT"
    else
        # Option 2: mDNS auto-discovery
        print_progress "Attempting TSM auto-discovery via mDNS..."
        log "TSM" "Starting mDNS discovery for service: $TSM_MDNS_SERVICE"

        local discovered_host=""
        local discovered_port=""

        # Try avahi-browse (Linux)
        if command -v avahi-browse >/dev/null 2>&1; then
            print_debug "Using avahi-browse for mDNS discovery"
            local avahi_output
            avahi_output=$(timeout 5 avahi-browse -t -p -r "$TSM_MDNS_SERVICE" 2>/dev/null | grep "^=" | head -n1)

            if [ -n "$avahi_output" ]; then
                # Parse avahi output: =;eth0;IPv4;TSM Server;_tsm._tcp;local;hostname;192.168.1.100;8443;...
                discovered_host=$(echo "$avahi_output" | cut -d';' -f8)
                discovered_port=$(echo "$avahi_output" | cut -d';' -f9)

                if [ -n "$discovered_host" ]; then
                    print_info "Discovered TSM via mDNS: $discovered_host:$discovered_port"
                    log "TSM" "mDNS discovered: $discovered_host:$discovered_port"
                fi
            fi
        fi

        # Try dns-sd (macOS/BSD) if avahi didn't work
        if [ -z "$discovered_host" ] && command -v dns-sd >/dev/null 2>&1; then
            print_debug "Using dns-sd for mDNS discovery"
            # dns-sd requires background process, use timeout
            local dns_output
            dns_output=$(timeout 5 dns-sd -L "TSM Server" "$TSM_MDNS_SERVICE" local 2>/dev/null | grep "can be reached at" | head -n1)

            if [ -n "$dns_output" ]; then
                # Parse: hostname.local.:8443 can be reached at 192.168.1.100:8443
                discovered_host=$(echo "$dns_output" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -n1)
                discovered_port=$(echo "$dns_output" | grep -oP ':\d+' | tr -d ':' | head -n1)

                if [ -n "$discovered_host" ]; then
                    print_info "Discovered TSM via mDNS: $discovered_host:$discovered_port"
                    log "TSM" "mDNS discovered: $discovered_host:$discovered_port"
                fi
            fi
        fi

        # Use discovered endpoint or fall back to default
        if [ -n "$discovered_host" ]; then
            discovered_port="${discovered_port:-$TSM_PORT}"
            tsm_endpoint="https://$discovered_host:$discovered_port"
            print_info "Auto-discovered TSM: $tsm_endpoint"
        else
            print_warning "mDNS discovery failed or not available"
            print_info "Using default TSM server: $TSM_SERVER"
            tsm_endpoint="$TSM_SERVER"
        fi
    fi

    # ──────────────────────────────────────────────────────────────────────────
    # TSM Directory Setup
    # ──────────────────────────────────────────────────────────────────────────
    if [ ! -d "$TSM_ROOT" ]; then
        print_warning "TSM directory not found: $TSM_ROOT"
        print_info "Creating TSM directory structure..."

        mkdir -p "$TSM_ROOT"/{lib,include,config}

        if [ ! -d "$TSM_ROOT" ]; then
            print_warning "Could not create TSM directory - TSM disabled"
            TSM_ENABLED=0
            print_step_complete "5/8"
            echo ""
            return 0
        fi
    fi

    print_info "TSM directory: $TSM_ROOT"

    # ──────────────────────────────────────────────────────────────────────────
    # TSM Configuration
    # ──────────────────────────────────────────────────────────────────────────
    local tsm_config="$TSM_ROOT/config/tsm.properties"
    print_info "Creating TSM configuration..."
    cat > "$tsm_config" << EOF
# TSM Configuration
tsm.version=1.0.0
tsm.server=$tsm_endpoint
tsm.enabled=true
tsm.build_date=$(date +%Y%m%d)
tsm.discovery.mdns=$TSM_MDNS_SERVICE
EOF
    print_info "TSM config created: $tsm_config"
    log "TSM" "TSM endpoint configured: $tsm_endpoint"

    # Test TSM connectivity (optional)
    if command -v curl >/dev/null 2>&1; then
        print_progress "Testing TSM connectivity..."
        if timeout 5 curl -k -s -o /dev/null -w "%{http_code}" "$tsm_endpoint/health" 2>/dev/null | grep -q "200\|204"; then
            print_info "TSM server is reachable"
            log "TSM" "TSM connectivity test passed"
        else
            print_warning "TSM server not reachable (may be offline or firewalled)"
            log "TSM" "TSM connectivity test failed (non-critical)"
        fi
    fi

    # Verify TSM API key if provided
    if [ -n "$TSM_API_KEY" ]; then
        print_info "TSM API key configured"
        log "TSM" "TSM API key present"
    else
        print_warning "TSM API key not set (optional)"
    fi

    # Set TSM environment variables for Gradle
    export TSM_ENABLED=true
    export TSM_ROOT="$TSM_ROOT"
    export TSM_SERVER="$tsm_endpoint"
    if [ -n "$TSM_API_KEY" ]; then
        export TSM_API_KEY="$TSM_API_KEY"
    fi

    BUILD_STATE["tsm_initialized"]=1
    save_state

    print_info "TSM integration complete"
    log "TSM" "TSM initialized successfully"

    local elapsed=$(($(date +%s) - start_time))
    COMPONENT_TIMES["tsm"]=$elapsed

    print_step_complete "5/8"
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# Fetch Dependencies
# ──────────────────────────────────────────────────────────────────────────────
fetch_dependencies() {
    print_step "6" "8" "Fetching Dependencies"

    local start_time
    start_time=$(date +%s)

    if [ "${BUILD_STATE["dependencies_fetched"]}" -eq 1 ] && [ "$FORCE_REBUILD" -eq 0 ]; then
        print_info "Dependencies already fetched, skipping..."
        print_step_complete "6/8"
        echo ""
        return 0
    fi

    if [ ! -d "$ANDROID_ROOT" ]; then
        print_error "Android project not found at: $ANDROID_ROOT"
        fail "Android project directory not found"
    fi

    cd "$ANDROID_ROOT" || fail "Cannot change to Android directory"

    # Check for Gradle wrapper
    if [ ! -f "gradlew" ]; then
        print_error "Gradle wrapper not found"
        fail "gradlew not found in $ANDROID_ROOT"
    fi

    # Make gradlew executable
    chmod +x gradlew

    print_progress "Running Gradle dependency fetch..."
    print_warning "This may take several minutes on first run..."

    if run_cmd_verbose "./gradlew --refresh-dependencies dependencies"; then
        print_info "Dependencies fetched successfully"
        log "GRADLE" "Dependencies fetched"
        BUILD_STATE["dependencies_fetched"]=1
        save_state
    else
        fail "Failed to fetch dependencies"
    fi

    local elapsed=$(($(date +%s) - start_time))
    COMPONENT_TIMES["dependencies"]=$elapsed

    print_step_complete "6/8"
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# Build Android App
# ──────────────────────────────────────────────────────────────────────────────
build_android_app() {
    print_step "7" "8" "Building Android Application"

    local start_time
    start_time=$(date +%s)

    if [ ! -d "$ANDROID_ROOT" ]; then
        fail "Android project not found at: $ANDROID_ROOT"
    fi

    cd "$ANDROID_ROOT" || fail "Cannot change to Android directory"

    # Determine build task based on build type
    local gradle_task
    local output_type
    case "${BUILD_TYPE,,}" in
        release)
            if [ -n "$KEYSTORE_PATH" ] && [ -f "$KEYSTORE_PATH" ]; then
                gradle_task="bundleRelease"
                output_type="AAB (Android App Bundle)"
                print_info "Building RELEASE with signing"
            else
                print_warning "No keystore found - building unsigned release"
                gradle_task="assembleRelease"
                output_type="Unsigned APK"
            fi
            ;;
        debug|*)
            gradle_task="assembleDebug"
            output_type="Debug APK"
            BUILD_TYPE="debug"
            ;;
    esac

    print_progress "Build type: ${BUILD_TYPE}"
    print_progress "Gradle task: $gradle_task"
    print_progress "Output: $output_type"
    print_warning "Build may take 10-30 minutes depending on system..."
    echo ""

    # Set signing properties if available
    local gradle_args=""
    if [ -n "$KEYSTORE_PATH" ] && [ -f "$KEYSTORE_PATH" ]; then
        gradle_args="-Pandroid.injected.signing.store.file=$KEYSTORE_PATH"
        gradle_args="$gradle_args -Pandroid.injected.signing.store.password=$KEYSTORE_PASSWORD"
        gradle_args="$gradle_args -Pandroid.injected.signing.key.alias=$KEYSTORE_ALIAS"
        gradle_args="$gradle_args -Pandroid.injected.signing.key.password=$KEY_PASSWORD"
    fi

    # Add TSM properties
    if [ "$TSM_ENABLED" -eq 1 ]; then
        gradle_args="$gradle_args -Ptsm.enabled=true"
        gradle_args="$gradle_args -Ptsm.root=$TSM_ROOT"
    fi

    # Clean build directory if force rebuild
    if [ "$FORCE_REBUILD" -eq 1 ]; then
        print_progress "Cleaning build directory..."
        run_cmd "./gradlew clean"
    fi

    # Run build
    print_progress "Starting build..."
    # shellcheck disable=SC2086
    if run_cmd_verbose "./gradlew $gradle_task $gradle_args"; then
        print_info "Build completed successfully"
        log "BUILD" "Android app built successfully"
        BUILD_STATE["app_built"]=1
        save_state
    else
        fail "Android build failed"
    fi

    local elapsed=$(($(date +%s) - start_time))
    COMPONENT_TIMES["build"]=$elapsed

    print_step_complete "7/8"
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# Locate and Verify Build Artifacts
# ──────────────────────────────────────────────────────────────────────────────
verify_artifacts() {
    print_step "8" "8" "Locating Build Artifacts"

    if [ ! -d "$ANDROID_ROOT" ]; then
        fail "Android project not found"
    fi

    cd "$ANDROID_ROOT" || fail "Cannot change to Android directory"

    print_progress "Searching for build outputs..."

    local artifact_path=""
    local artifact_type=""

    # Search for artifacts based on build type
    case "${BUILD_TYPE,,}" in
        release)
            # Look for AAB first
            artifact_path=$(find . -name "*-release.aab" -o -name "*.aab" 2>/dev/null | grep -v unaligned | head -n1)
            if [ -n "$artifact_path" ]; then
                artifact_type="AAB"
            else
                # Fall back to APK
                artifact_path=$(find . -name "*-release.apk" 2>/dev/null | grep -v unaligned | head -n1)
                if [ -n "$artifact_path" ]; then
                    artifact_type="Release APK"
                fi
            fi
            ;;
        debug|*)
            artifact_path=$(find . -name "*-debug.apk" 2>/dev/null | grep -v unaligned | head -n1)
            if [ -n "$artifact_path" ]; then
                artifact_type="Debug APK"
            fi
            ;;
    esac

    if [ -z "$artifact_path" ] || [ ! -f "$artifact_path" ]; then
        print_error "Build artifact not found"
        echo ""
        echo "Searched for:"
        case "${BUILD_TYPE,,}" in
            release)
                echo "  *-release.aab"
                echo "  *-release.apk"
                ;;
            *)
                echo "  *-debug.apk"
                ;;
        esac
        fail "Build artifacts not found"
    fi

    # Get artifact info
    local size
    size=$(stat -c%s "$artifact_path" 2>/dev/null || stat -f%z "$artifact_path" 2>/dev/null || echo 0)
    local size_formatted
    size_formatted=$(format_size "$size")

    print_info "Artifact found: $artifact_path"
    print_info "Type: $artifact_type"
    print_info "Size: $size_formatted"

    log "ARTIFACT" "Build artifact: $artifact_path ($size_formatted)"

    # Save artifact info to summary
    {
        echo "CRYPTOGRAM Android Build - $BUILD_TYPE"
        echo "========================================"
        echo ""
        echo "Artifact: $artifact_path"
        echo "Type: $artifact_type"
        echo "Size: $size_formatted"
        echo "Build Date: $(get_timestamp)"
        echo ""
    } > "$SUMMARY_FILE"

    print_step_complete "8/8"
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# Build Summary
# ──────────────────────────────────────────────────────────────────────────────
show_summary() {
    local total_time=$(($(date +%s) - BUILD_START_TIME))

    print_header "✓ BUILD COMPLETE!"

    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo "BUILD SUMMARY"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    echo "Script Version: $SCRIPT_VERSION"
    echo "Build ID: $BUILD_ID"
    echo "Build Type: $BUILD_TYPE"
    echo "TSM Enabled: $([ "$TSM_ENABLED" -eq 1 ] && echo "Yes" || echo "No")"
    echo ""
    echo "Timings:"
    printf "  %-20s: %s\n" "Total Time" "$(format_time "$total_time")"

    for component in system submodules sdk ndk tsm dependencies build; do
        if [ -n "${COMPONENT_TIMES[$component]:-}" ] && [ "${COMPONENT_TIMES[$component]}" -gt 0 ]; then
            printf "  %-20s: %s\n" "$component" "$(format_time "${COMPONENT_TIMES[$component]}")"
        fi
    done

    echo ""
    echo "Logs:"
    echo "  Build log: $LOG_FILE"
    echo "  Error log: $ERROR_LOG"
    echo "  Summary: $SUMMARY_FILE"
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""

    if [ -f "$SUMMARY_FILE" ]; then
        cat "$SUMMARY_FILE"
    fi

    echo "═══════════════════════════════════════════════════════════════════"
    echo "Completed: $(get_timestamp)"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# Error Handler
# ──────────────────────────────────────────────────────────────────────────────
error_handler() {
    local line_no=$1
    local bash_lineno=$2
    local exit_code=$3

    echo ""
    print_error "Build failed at line $line_no with exit code $exit_code"
    log "FATAL" "Script failed at line $line_no (bash line: $bash_lineno) with exit code $exit_code"

    echo ""
    echo "Error context:"
    if [ -f "$ERROR_LOG" ]; then
        echo "Recent errors from $ERROR_LOG:"
        tail -20 "$ERROR_LOG" | sed 's/^/  /'
    fi

    echo ""
    echo "Full log: $LOG_FILE"
    echo ""

    exit "$exit_code"
}

trap 'error_handler ${LINENO} ${BASH_LINENO[0]} $?' ERR

# ──────────────────────────────────────────────────────────────────────────────
# Argument Parsing
# ──────────────────────────────────────────────────────────────────────────────
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --release)
                BUILD_TYPE="release"
                ;;
            --debug)
                BUILD_TYPE="debug"
                ;;
            --force|-f)
                FORCE_REBUILD=1
                ;;
            --verbose|-v)
                VERBOSE_MODE=1
                ;;
            --dry-run)
                DRY_RUN=1
                ;;
            --no-tsm)
                TSM_ENABLED=0
                ;;
            --keystore=*)
                KEYSTORE_PATH="${1#*=}"
                ;;
            --keystore-pass=*)
                KEYSTORE_PASSWORD="${1#*=}"
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
        shift
    done
}

show_help() {
    cat << EOF
CRYPTOGRAM Android Build Script v$SCRIPT_VERSION

Usage: $0 [OPTIONS]

Options:
  --release              Build release APK/AAB
  --debug                Build debug APK (default)
  --force, -f            Force rebuild (clean first)
  --verbose, -v          Enable verbose output
  --dry-run              Show what would be done
  --no-tsm               Disable TSM integration
  --keystore=PATH        Path to keystore file
  --keystore-pass=PASS   Keystore password
  --help, -h             Show this help message

Environment Variables:
  ANDROID_SDK_ROOT       Android SDK location
  ANDROID_NDK_VERSION    NDK version to use
  TSM_ENABLED            Enable/disable TSM (1/0)
  TSM_HOST               Hardcoded TSM IP/hostname (overrides auto-discovery)
  TSM_PORT               TSM port (default: 8443)
  TSM_SERVER             TSM server URL (fallback if discovery fails)
  TSM_MDNS_SERVICE       mDNS service name (default: _tsm._tcp)
  TSM_API_KEY            TSM API key
  KEYSTORE_PATH          Path to release keystore
  KEYSTORE_PASSWORD      Keystore password
  KEYSTORE_ALIAS         Key alias (default: swordcomm)

TSM Network Discovery:
  The build script will discover TSM in the following order:
  1. Hardcoded IP/hostname (TSM_HOST environment variable)
  2. mDNS auto-discovery on local network (avahi/dns-sd)
  3. Fallback to TSM_SERVER URL

Examples:
  $0                                    # Build debug APK with TSM auto-discovery
  $0 --release                          # Build release (unsigned)
  $0 --release --keystore=release.jks --keystore-pass=secret
  TSM_HOST=192.168.1.100 $0             # Use hardcoded TSM IP
  TSM_MDNS_SERVICE=_cryptogram._tcp $0  # Custom mDNS service name

EOF
}

# ──────────────────────────────────────────────────────────────────────────────
# Main Execution
# ──────────────────────────────────────────────────────────────────────────────
main() {
    # Parse arguments
    parse_args "$@"

    # Create log directory
    mkdir -p "$LOG_DIR" 2>/dev/null || true

    # Initialize logs
    echo "CRYPTOGRAM Android Build Started: $(get_timestamp)" > "$LOG_FILE"
    echo "CRYPTOGRAM Android Build Errors" > "$ERROR_LOG"

    # Clear screen and show header
    clear
    print_header "CRYPTOGRAM Android Build System v$SCRIPT_VERSION"

    echo ""
    echo "Configuration:"
    echo "  Project Root: $CRYPTOGRAM_ROOT"
    echo "  Android Root: $ANDROID_ROOT"
    echo "  TSM Root: $TSM_ROOT"
    echo "  Build Type: $BUILD_TYPE"
    echo "  TSM Enabled: $([ "$TSM_ENABLED" -eq 1 ] && echo "Yes" || echo "No")"
    echo "  Log File: $LOG_FILE"
    echo ""

    # Execute build steps
    check_system
    initialize_submodules
    check_android_sdk
    check_android_ndk
    initialize_tsm
    fetch_dependencies
    build_android_app
    verify_artifacts
    show_summary

    print_info "Build completed successfully!"
    log "SUCCESS" "Build completed successfully"
}

# Start main execution
main "$@"
