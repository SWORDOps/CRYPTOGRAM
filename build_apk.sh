#!/bin/bash

################################################################################
# SWORDCOMM/CRYPTOGRAM Android APK Build Script
# Focused build script for Android APK generation
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
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DATE=$(date +%Y%m%d_%H%M%S)
LOG_DIR="/tmp/cryptogram_builds_root"
BUILD_LOG="$LOG_DIR/apk_build_$BUILD_DATE.log"

# Create log directory
mkdir -p "$LOG_DIR"

# Build variants
BUILD_VARIANT="${BUILD_VARIANT:-debug}"
FLAVOR="${FLAVOR:-foss}"

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

find_android_project() {
    # Try to find Android project directory
    local search_paths=(
        "$1"
        "$SCRIPT_DIR/TMessagesProj"
        "$SCRIPT_DIR"
        "/home/user/SWORDCOMM"
        "/home/user/Documents/SWORDCOMM"
        "$HOME/molly"
        "/molly"
    )

    for path in "${search_paths[@]}"; do
        if [ -d "$path" ] && ([ -f "$path/build.gradle.kts" ] || [ -f "$path/build.gradle" ] || [ -f "$path/app/build.gradle" ]); then
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

clear
print_header "CRYPTOGRAM/SWORDCOMM Android APK Build"

echo "Configuration:"
echo "  Build variant: $BUILD_VARIANT"
echo "  Flavor:        $FLAVOR"
echo "  Log:           $BUILD_LOG"
echo ""

print_section "Locating Android Project"

# Find Android project
ANDROID_ROOT=""
if [ -n "$1" ]; then
    print_progress "Using provided path: $1"
    ANDROID_ROOT="$1"
elif ANDROID_ROOT=$(find_android_project ""); then
    print_info "Found Android project at: $ANDROID_ROOT"
else
    print_error "Android project not found"
    echo ""
    echo "Searched locations:"
    echo "  • $SCRIPT_DIR/TMessagesProj"
    echo "  • /home/user/SWORDCOMM"
    echo "  • /home/user/Documents/SWORDCOMM"
    echo "  • $HOME/molly"
    echo ""
    echo "Usage: $0 [path/to/android/project]"
    echo ""
    fail "Please provide Android project path"
fi

# Verify Android project
cd "$ANDROID_ROOT" || fail "Cannot access: $ANDROID_ROOT"

if [ ! -f "build.gradle" ] && [ ! -f "build.gradle.kts" ] && [ ! -f "app/build.gradle" ]; then
    fail "Not a valid Android/Gradle project: $ANDROID_ROOT"
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
if [ -n "$ANDROID_HOME" ]; then
    print_info "Android SDK: $ANDROID_HOME"
elif [ -n "$ANDROID_SDK_ROOT" ]; then
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

# Check for signing configuration (release builds)
if [ "$BUILD_VARIANT" = "release" ]; then
    echo ""
    print_progress "Release build requires signing configuration"

    if [ -n "$CI_KEYSTORE_PATH" ] && [ -f "$CI_KEYSTORE_PATH" ]; then
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
    echo "Check the Gradle output above for APK location"
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
echo "  BUILD_VARIANT=release $0"
echo ""
echo "Clean build:"
echo "  CLEAN_BUILD=1 $0"
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo ""

} 2>&1 | tee "$BUILD_LOG"

print_info "Build log saved to: $BUILD_LOG"
echo ""
