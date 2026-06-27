#!/bin/bash

################################################################################
# CRYPTOGRAM Android - Production Build Script v1.0
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
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Paths
readonly CRYPTOGRAM_ROOT="${CRYPTOGRAM_ROOT:-$SCRIPT_DIR}"
readonly ANDROID_ROOT="${ANDROID_ROOT:-${CRYPTOGRAM_ROOT}/telegram-android}"

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

# Android SDK configuration
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}"
ANDROID_NDK_VERSION="${ANDROID_NDK_VERSION:-25.2.9519653}"

# Signing configuration
KEYSTORE_PATH="${KEYSTORE_PATH:-}"
KEYSTORE_PASSWORD="${KEYSTORE_PASSWORD:-}"
KEYSTORE_ALIAS="${KEYSTORE_ALIAS:-cryptogram}"
KEY_PASSWORD="${KEY_PASSWORD:-${KEYSTORE_PASSWORD}}"


# Build state
declare -A BUILD_STATE=(
    ["submodules_initialized"]=0
    ["sdk_validated"]=0
    ["ndk_validated"]=0
    ["dependencies_fetched"]=0
    ["app_built"]=0
)

# Component timing
declare -A COMPONENT_TIMES=(
    ["system"]=0
    ["submodules"]=0
    ["sdk"]=0
    ["ndk"]=0
    ["dependencies"]=0
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

    if [ "${available_gb}" -lt 5 ]; then
        print_error "Insufficient disk space: ${available_gb}GB (minimum 5GB required for Android build)"
        fail "Not enough disk space"
    elif [ "${available_gb}" -lt 10 ]; then
        print_warning "Low disk space: ${available_gb}GB (10GB+ recommended)"
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
# CRYPTOGRAM Android Overlay Validation
# ──────────────────────────────────────────────────────────────────────────────
check_cryptogram_android_overlay() {
    print_step "5" "8" "CRYPTOGRAM Android Overlay Validation"

    local start_time
    start_time=$(date +%s)

    if [ ! -d "$ANDROID_ROOT" ]; then
        fail "Android project not found at: $ANDROID_ROOT"
    fi

    cd "$ANDROID_ROOT" || fail "Cannot change to Android directory"

    local required_files=(
        "TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp"
        "TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/CryptogramNative.java"
        "TMessagesProj/src/main/java/org/telegram/ui/CryptogramSettingsActivity.java"
    )

    local missing=()
    local file
    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            missing+=("$file")
        fi
    done

    if [ "${#missing[@]}" -gt 0 ]; then
        print_error "CRYPTOGRAM Android overlay is not applied to telegram-android"
        echo ""
        echo "Missing overlay markers:"
        printf '  - %s\n' "${missing[@]}"
        echo ""
        echo "This checkout currently contains a restored Telegram Android base,"
        echo "but the CRYPTOGRAM Android modifications still live in the superproject"
        echo "overlay tree and are not applied automatically by this script."
        fail "Apply the CRYPTOGRAM Android overlay before building"
    fi

    print_info "CRYPTOGRAM overlay markers detected"

    local elapsed=$(($(date +%s) - start_time))
    COMPONENT_TIMES["dependencies"]=${COMPONENT_TIMES["dependencies"]:-0}
    log "ANDROID" "CRYPTOGRAM Android overlay markers verified"

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
                gradle_task=":TMessagesProj_App:bundleAfatRelease"
                output_type="AAB (Android App Bundle)"
                print_info "Building RELEASE with signing"
            else
                print_warning "No keystore found - building unsigned release"
                gradle_task=":TMessagesProj_App:assembleAfatRelease"
                output_type="Unsigned APK"
            fi
            ;;
        debug|*)
            gradle_task=":TMessagesProj_App:assembleAfatDebug"
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
    echo ""
    echo "Timings:"
    printf "  %-20s: %s\n" "Total Time" "$(format_time "$total_time")"
    local component
    for component in system submodules sdk ndk dependencies build; do
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
  --keystore=PATH        Path to keystore file
  --keystore-pass=PASS   Keystore password
  --help, -h             Show this help message

Environment Variables:
  ANDROID_SDK_ROOT       Android SDK location
  ANDROID_NDK_VERSION    NDK version to use
  KEYSTORE_PATH          Path to release keystore
  KEYSTORE_PASSWORD      Keystore password
  KEYSTORE_ALIAS         Key alias (default: cryptogram)

  2. mDNS auto-discovery on local network (avahi/dns-sd)

Examples:
  $0 --release                          # Build release (unsigned)
  $0 --release --keystore=release.jks --keystore-pass=secret

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
    echo "  Build Type: $BUILD_TYPE"
    echo "  Log File: $LOG_FILE"
    echo ""

    # Execute build steps
    check_system
    initialize_submodules
    check_android_sdk
    check_android_ndk
    check_cryptogram_android_overlay
    fetch_dependencies
    build_android_app
    verify_artifacts
    show_summary

    print_info "Build completed successfully!"
    log "SUCCESS" "Build completed successfully"
}

# Start main execution
main "$@"
