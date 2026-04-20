#!/bin/bash

################################################################################
# CRYPTOGRAM Complete Build Orchestration
# Builds CRYPTOGRAM Desktop (C++/Qt) and CRYPTOGRAM Android (Gradle/Kotlin)
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
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Logging
BUILD_DATE=$(date +%Y%m%d_%H%M%S)
MASTER_LOG="/tmp/cryptogram_build_$BUILD_DATE.log"

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
    exit 1
}

get_time() {
    date +"%Y-%m-%d %H:%M:%S"
}

show_menu() {
    echo ""
    echo "What would you like to build?"
    echo ""
    echo "  1) CRYPTOGRAM Desktop (C++/Qt) only"
echo "  2) CRYPTOGRAM Android (Gradle/Kotlin) only"
echo "  3) Both CRYPTOGRAM Desktop and Android"
    echo "  4) Skip builds (just verify setup)"
    echo ""
    read -p "Enter choice (1-4): " choice
    echo ""
}

################################################################################
# MAIN
################################################################################

clear
echo "CRYPTOGRAM Desktop + CRYPTOGRAM Android"

echo "Start time: $(get_time)"
echo "Master log: $MASTER_LOG"
echo ""
echo "This script can build:"
echo "  • CRYPTOGRAM Desktop (Linux/macOS)"
echo "  • CRYPTOGRAM Android (requires Android SDK/Gradle)"
echo "  • Both together"
echo ""

# Get user choice
show_menu

case $choice in
    1)
        BUILDS=("CRYPTOGRAM")
        ;;
    2)
        BUILDS=("CRYPTOGRAM_ANDROID")
        ;;
    3)
        BUILDS=("CRYPTOGRAM" "CRYPTOGRAM_ANDROID")
        ;;
    4)
        BUILDS=()
        ;;
    *)
        print_error "Invalid choice"
        exit 1
        ;;
esac

echo "Selected builds: ${BUILDS[@]:-None (verification only)}"
echo ""

{

echo "════════════════════════════════════════════════════════════════"
echo "DUAL BUILD LOG - Started: $(get_time)"
echo "Master log: $MASTER_LOG"
echo "════════════════════════════════════════════════════════════════"
echo ""

CRYPTOGRAM_ROOT="${CRYPTOGRAM_ROOT:-$SCRIPT_DIR}"

################################################################################
# PRE-BUILD VERIFICATION
################################################################################

print_section "Pre-Build Verification"

print_progress "Checking environment..."

# Check CRYPTOGRAM
if [ -d "$CRYPTOGRAM_ROOT" ]; then
    print_info "CRYPTOGRAM found at: $CRYPTOGRAM_ROOT"
else
    print_error "CRYPTOGRAM not found at: $CRYPTOGRAM_ROOT"
fi

# Check for build scripts
if [ -f "$CRYPTOGRAM_ROOT/build_all.sh" ]; then
    print_info "CRYPTOGRAM build script found"
else
    print_warning "CRYPTOGRAM build script not found"
fi

if [ -f "$CRYPTOGRAM_ROOT/build_android.sh" ]; then
    print_info "CRYPTOGRAM Android build script found"
else
    print_warning "CRYPTOGRAM Android build script not found"
fi

# Check system resources
echo ""
print_progress "System resources:"
DISK=$(df -h / | awk 'NR==2 {print $4}')
MEMORY=$(free -h | grep Mem | awk '{print $7}')
CORES=$(nproc)
print_info "Disk available: $DISK"
print_info "Memory available: $MEMORY"
print_info "CPU cores: $CORES"

echo ""

################################################################################
# BUILD PHASE
################################################################################

START_TOTAL=$(date +%s)

for build in "${BUILDS[@]}"; do

    case $build in
        CRYPTOGRAM)
            print_section "Building CRYPTOGRAM Desktop (C++/Qt)"
            echo ""
            print_progress "Starting CRYPTOGRAM build..."
            echo ""

            if [ ! -f "$CRYPTOGRAM_ROOT/build_all.sh" ]; then
                fail "CRYPTOGRAM build script not found"
            fi

            # Run CRYPTOGRAM build
            START_CRYPTO=$(date +%s)

            if bash "$CRYPTOGRAM_ROOT/build_all.sh" 2>&1; then
                END_CRYPTO=$(date +%s)
                CRYPTO_TIME=$((END_CRYPTO - START_CRYPTO))
                print_info "CRYPTOGRAM build successful!"
                echo ""
                echo "Build time: $((CRYPTO_TIME / 60))m $((CRYPTO_TIME % 60))s"
            else
                print_error "CRYPTOGRAM build FAILED"
                fail "See log above for details"
            fi
            ;;

        CRYPTOGRAM_ANDROID)
            print_section "Building CRYPTOGRAM Android (Gradle/Kotlin)"
            echo ""

            # Check for Android project directory
            # Try common locations
            ANDROID_PATHS=(
                "$CRYPTOGRAM_ROOT/telegram-android"
                "$(pwd)/telegram-android"
                "$HOME/telegram-android"
                "$HOME/Telegram-Android"
                "$HOME/CRYPTOGRAM-android"
            )

            ANDROID_ROOT=""
            for path in "${ANDROID_PATHS[@]}"; do
                if [ -d "$path" ] && ([ -f "$path/build.gradle.kts" ] || [ -f "$path/build.gradle" ]); then
                    ANDROID_ROOT="$path"
                    break
                fi
            done

            if [ -z "$ANDROID_ROOT" ]; then
                print_error "CRYPTOGRAM Android directory not found"
                echo ""
                echo "Checked locations:"
                for path in "${ANDROID_PATHS[@]}"; do
                    echo "  • $path"
                done
                echo ""
                print_progress "Please specify CRYPTOGRAM Android path:"
                read -p "Enter Android project path: " ANDROID_ROOT
            fi

            if [ ! -d "$ANDROID_ROOT" ]; then
                fail "CRYPTOGRAM Android project not found at: $ANDROID_ROOT"
            fi

            print_info "CRYPTOGRAM Android found at: $ANDROID_ROOT"
            echo ""
            print_progress "Configure signing (optional):"
            echo ""
            echo "For release builds, provide signing credentials:"
            read -p "Keystore path (leave blank for debug): " KEYSTORE

            if [ -n "$KEYSTORE" ]; then
                read -sp "Keystore password: " KEYSTORE_PASS
                echo ""
                read -p "Keystore alias: " KEYSTORE_ALIAS
                echo ""
                read -p "Maps API key (optional): " MAPS_KEY
                echo ""

                export CI_KEYSTORE_PATH="$KEYSTORE"
                export CI_KEYSTORE_PASSWORD="$KEYSTORE_PASS"
                export CI_KEYSTORE_ALIAS="$KEYSTORE_ALIAS"
                export CI_MAPS_API_KEY="$MAPS_KEY"

                print_info "Release credentials configured"
            else
                print_info "Building debug APK (no signing)"
            fi

            echo ""
            print_progress "Starting Android build..."
            echo ""

            if [ ! -f "$CRYPTOGRAM_ROOT/build_android.sh" ]; then
                fail "Android build script not found"
            fi

            START_ANDROID=$(date +%s)

            if bash "$CRYPTOGRAM_ROOT/build_android.sh" "$ANDROID_ROOT" 2>&1; then
                END_ANDROID=$(date +%s)
                ANDROID_TIME=$((END_ANDROID - START_ANDROID))
                print_info "CRYPTOGRAM Android build successful!"
                echo ""
                echo "Build time: $((ANDROID_TIME / 60))m $((ANDROID_TIME % 60))s"
            else
                print_error "CRYPTOGRAM Android build FAILED"
                fail "See log above for details"
            fi
            ;;
    esac

    echo ""
done

################################################################################
# FINAL SUMMARY
################################################################################

END_TOTAL=$(date +%s)
TOTAL_TIME=$((END_TOTAL - START_TOTAL))

print_header "✓ BUILD CYCLE COMPLETE!"

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "FINAL SUMMARY"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "Builds completed: ${#BUILDS[@]}"
echo "Total build time: $((TOTAL_TIME / 60))m $((TOTAL_TIME % 60))s"
echo ""

if [[ " ${BUILDS[@]} " =~ " CRYPTOGRAM " ]]; then
    echo "CRYPTOGRAM Desktop:"
    echo "  Status: ✓ Complete"
    echo "  Location: $CRYPTOGRAM_ROOT/build_release/bin/Telegram"
    echo ""
fi

if [[ " ${BUILDS[@]} " =~ " CRYPTOGRAM_ANDROID " ]]; then
    echo "CRYPTOGRAM Android:"
    echo "  Status: ✓ Complete"
    echo "  See individual log for artifact location"
    echo ""
fi

echo "═══════════════════════════════════════════════════════════════════"
echo "WHAT'S NEXT"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

if [[ " ${BUILDS[@]} " =~ " CRYPTOGRAM " ]]; then
    echo "CRYPTOGRAM Desktop:"
    echo "  Run: $CRYPTOGRAM_ROOT/build_release/bin/Telegram"
    echo ""
fi

if [[ " ${BUILDS[@]} " =~ " CRYPTOGRAM_ANDROID " ]]; then
    echo "CRYPTOGRAM Android:"
    echo "  Install: adb install build/outputs/apk/debug/app-debug.apk"
    echo "  Or upload AAB to Play Store"
    echo ""
fi

echo "  1. cd $CRYPTOGRAM_ROOT"
echo "  4. ./build_release/bin/Telegram"
echo ""

echo "═══════════════════════════════════════════════════════════════════"
echo "End time: $(get_time)"
echo "Master log: $MASTER_LOG"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

} 2>&1 | tee "$MASTER_LOG"

echo ""
echo "✓ Master build log saved to: $MASTER_LOG"
echo ""
