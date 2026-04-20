#!/bin/bash

################################################################################
# CRYPTOGRAM Android APK Build Script
# Focused build script for Android APK generation
################################################################################

set -euo pipefail

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
BUILD_DATE=$(date +%Y%m%d_%H%M%S)
LOG_DIR="/tmp/cryptogram_builds_root"
BUILD_LOG="$LOG_DIR/apk_build_$BUILD_DATE.log"

# Create log directory
mkdir -p "$LOG_DIR"

# Build variants
BUILD_VARIANT="${BUILD_VARIANT:-debug}"
FLAVOR="${FLAVOR:-foss}"
ANDROID_PROJECT_PATH="${ANDROID_PROJECT_PATH:-}"

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

fail() {
    print_error "$1"
    echo ""
    echo "Build failed after $(($(date +%s) - START_TIME))s"
    echo "Log: $BUILD_LOG"
    exit 1
}

usage() {
    cat <<EOF
Usage:
  ./build_apk.sh /path/to/android/gradle/project

Environment:
  ANDROID_PROJECT_PATH   Explicit path to an external Android Gradle project
  BUILD_VARIANT          debug | release   (default: debug)
  FLAVOR                 Gradle flavor     (default: foss)
  CLEAN_BUILD            1 to run gradle clean first

Notes:
  - This repository snapshot does not include a self-contained Android Gradle project.
  - You must point this script at an external checkout containing gradlew and build.gradle(.kts).
  - The external project is expected to contain the Android Telegram base that CRYPTOGRAM changes are applied to.
EOF
}

is_gradle_project_root() {
    local path="$1"
    [ -d "$path" ] || return 1

    if [ -f "$path/gradlew" ] && \
       { [ -f "$path/build.gradle" ] || [ -f "$path/build.gradle.kts" ] || \
         [ -f "$path/settings.gradle" ] || [ -f "$path/settings.gradle.kts" ] || \
         [ -f "$path/app/build.gradle" ] || [ -f "$path/app/build.gradle.kts" ]; }; then
        return 0
    fi

    return 1
}

find_android_project() {
    # Try to find Android project directory. This repo does not ship one,
    # so any successful match should be an external Gradle checkout.
    local search_paths=(
        "$1"
        "$ANDROID_PROJECT_PATH"
        "$PWD"
        "$PWD/telegram-android"
        "$HOME/telegram-android"
        "$HOME/Telegram-Android"
        "$HOME/CRYPTOGRAM-android"
        "$HOME/AndroidProjects/telegram-android"
    )

    for path in "${search_paths[@]}"; do
        [ -n "$path" ] || continue
        if is_gradle_project_root "$path"; then
            echo "$path"
            return 0
        fi
    done

    return 1
}

################################################################################
# MAIN BUILD
################################################################################

{
START_TIME=$(date +%s)

if [ -t 1 ] && [ -n "${TERM:-}" ] && command -v clear >/dev/null 2>&1; then
    clear || true
fi
print_header "CRYPTOGRAM Android APK Build"

echo "Configuration:"
echo "  Build variant: $BUILD_VARIANT"
echo "  Flavor:        $FLAVOR"
echo "  Log:           $BUILD_LOG"
echo ""

print_section "Locating Android Project"

# Find Android project
ANDROID_ROOT=""
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    usage
    exit 0
elif [ -n "${1:-}" ]; then
    print_progress "Using provided path: $1"
    ANDROID_ROOT="$1"
elif ANDROID_ROOT=$(find_android_project ""); then
    print_info "Found Android project at: $ANDROID_ROOT"
else
    print_error "Android Gradle project not found"
    echo ""
    echo "This repository snapshot does not contain gradlew or build.gradle files."
    echo "You need to provide an external Android Gradle project path."
    echo ""
    echo "Accepted forms:"
    echo "  • ./build_apk.sh /path/to/android/project"
    echo "  • ANDROID_PROJECT_PATH=/path/to/android/project ./build_apk.sh"
    echo ""
    echo "A valid project root must contain:"
    echo "  • gradlew"
    echo "  • build.gradle(.kts) or settings.gradle(.kts)"
    echo "    and/or app/build.gradle(.kts)"
    echo ""
    echo "Searched locations:"
    echo "  • $PWD"
    echo "  • $PWD/telegram-android"
    echo "  • $HOME/telegram-android"
    echo "  • $HOME/Telegram-Android"
    echo "  • $HOME/CRYPTOGRAM-android"
    echo "  • $HOME/AndroidProjects/telegram-android"
    echo ""
    usage
    fail "No external Android Gradle project was provided or discovered"
fi

# Verify Android project
if [ ! -e "$ANDROID_ROOT" ]; then
    echo ""
    echo "Path checked: $ANDROID_ROOT"
    fail "Provided Android project path does not exist"
elif [ ! -d "$ANDROID_ROOT" ]; then
    echo ""
    echo "Path checked: $ANDROID_ROOT"
    fail "Provided Android project path is not a directory"
fi

cd "$ANDROID_ROOT" || fail "Cannot access: $ANDROID_ROOT"

if ! is_gradle_project_root "$ANDROID_ROOT"; then
    echo ""
    echo "Path checked: $ANDROID_ROOT"
    echo "Missing required Gradle project markers."
    echo "Expected at least:"
    echo "  • gradlew"
    echo "  • build.gradle(.kts) or settings.gradle(.kts)"
    echo "    and/or app/build.gradle(.kts)"
    fail "Not a valid Android Gradle project root"
fi

print_info "Working directory: $ANDROID_ROOT"
echo ""

print_section "Environment Check"

# Check for Gradle wrapper
if [ -f "./gradlew" ]; then
    print_info "Gradle wrapper found"
    GRADLE="./gradlew"
    chmod +x "$GRADLE"
elif command -v gradle >/dev/null 2>&1; then
    print_warning "Using system gradle (wrapper not found)"
    GRADLE="gradle"
else
    fail "Gradle not found. Please install Gradle or add gradlew to the project"
fi

# Check Java/JDK
if command -v java >/dev/null 2>&1; then
    JAVA_VERSION=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2)
    print_info "Java version: $JAVA_VERSION"
else
    print_warning "Java not found in PATH"
    echo ""
    echo "To install Java:"
    echo "  sudo apt-get install openjdk-17-jdk"
    echo ""
fi

# Check Android SDK
if [ -n "${ANDROID_HOME:-}" ]; then
    print_info "Android SDK: $ANDROID_HOME"
elif [ -n "${ANDROID_SDK_ROOT:-}" ]; then
    print_info "Android SDK: $ANDROID_SDK_ROOT"
    export ANDROID_HOME="$ANDROID_SDK_ROOT"
else
    print_warning "ANDROID_HOME not set"
    # Try to find it
    for sdk_path in "$HOME/Android/Sdk" "/opt/android-sdk"; do
        if [ -d "$sdk_path" ]; then
            print_info "Found Android SDK at: $sdk_path"
            export ANDROID_HOME="$sdk_path"
            break
        fi
    done
fi

echo ""

print_section "Build Configuration"

# Determine build task
GRADLE_TASK="assemble${FLAVOR^}${BUILD_VARIANT^}"
print_info "Gradle task: $GRADLE_TASK"
print_info "Using external Android project: $ANDROID_ROOT"

# Check for signing configuration (release builds)
if [ "$BUILD_VARIANT" = "release" ]; then
    echo ""
    print_progress "Release build requires signing configuration"

    if [ -n "${CI_KEYSTORE_PATH:-}" ] && [ -f "$CI_KEYSTORE_PATH" ]; then
        print_info "Using keystore: $CI_KEYSTORE_PATH"
    else
        print_warning "No keystore configured"
        echo ""
        echo "For signed release builds, set environment variables:"
        echo "  export CI_KEYSTORE_PATH=/path/to/keystore.jks"
        echo "  export CI_KEYSTORE_PASSWORD=your_password"
        echo "  export CI_KEYSTORE_ALIAS=your_alias"
        echo ""
        echo "Building unsigned release APK..."
    fi
fi

echo ""

print_section "Building APK"

# Clean previous build (optional)
if [ "${CLEAN_BUILD:-0}" = "1" ]; then
    print_progress "Cleaning previous build..."
    $GRADLE clean || print_warning "Clean failed, continuing..."
fi

# Build APK
print_progress "Running: $GRADLE $GRADLE_TASK"
echo ""

if ! $GRADLE "$GRADLE_TASK" --stacktrace; then
    fail "Gradle build failed"
fi

echo ""
print_info "Build successful"

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

print_header "✓ APK BUILD SUCCESSFUL"

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "BUILD SUMMARY"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "Build time:    $((DURATION / 60))m $((DURATION % 60))s"
echo "Build variant: $FLAVOR-$BUILD_VARIANT"
echo "Project:       $ANDROID_ROOT"
echo ""

# Find and list APK files
print_progress "Locating APK files..."
echo ""

APK_DIRS=(
    "app/build/outputs/apk"
    "build/outputs/apk"
    "TMessagesProj/build/outputs/apk"
)

APK_FOUND=0
for apk_dir in "${APK_DIRS[@]}"; do
    if [ -d "$ANDROID_ROOT/$apk_dir" ]; then
        APKS=$(find "$ANDROID_ROOT/$apk_dir" -name "*.apk" -type f -mmin -60 2>/dev/null || true)
        if [ -n "$APKS" ]; then
            APK_FOUND=1
            echo "APK files:"
            echo "$APKS" | while read -r apk; do
                SIZE=$(du -h "$apk" | cut -f1)
                echo "  • $apk ($SIZE)"
            done
            echo ""
        fi
    fi
done

if [ $APK_FOUND -eq 0 ]; then
    print_warning "No recent APK files found in standard locations"
    echo ""
    echo "Check the Gradle output above for the actual output location."
    echo "This script only scans common APK directories under the external project root."
fi

echo "═══════════════════════════════════════════════════════════════════"
echo "NEXT STEPS"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "Install APK on device:"
echo "  adb install -r <apk-file>"
echo ""
echo "Or copy to device:"
echo "  adb push <apk-file> /sdcard/Download/"
echo ""
echo "Build variants available:"
echo "  • debug   - Debuggable, unsigned"
echo "  • release - Optimized, requires signing"
echo ""
echo "Build different variant:"
echo "  BUILD_VARIANT=release $0 /path/to/android/project"
echo ""
echo "Use an explicit external project:"
echo "  ANDROID_PROJECT_PATH=/path/to/android/project $0"
echo ""
echo "Clean build:"
echo "  CLEAN_BUILD=1 $0 /path/to/android/project"
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo ""

} 2>&1 | tee "$BUILD_LOG"

print_info "Build log saved to: $BUILD_LOG"
echo ""
