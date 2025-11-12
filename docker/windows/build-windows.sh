#!/bin/bash
# CRYPTOGRAM Windows Cross-Compile Build Script
# Cross-compiles CRYPTOGRAM for Windows using MinGW

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
BUILD_TYPE="Release"
JOBS=$(nproc)
SOURCE_DIR="/build/CRYPTOGRAM"
BUILD_DIR="/tmp/build-windows"
OUTPUT_DIR="/output"
TOOLCHAIN_FILE="/opt/mingw-w64-toolchain.cmake"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        --release)
            BUILD_TYPE="Release"
            shift
            ;;
        --jobs)
            JOBS="$2"
            shift 2
            ;;
        --clean)
            CLEAN=1
            shift
            ;;
        --help)
            echo "CRYPTOGRAM Windows Cross-Compile Build Script"
            echo ""
            echo "Usage: build-windows.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --debug      Build in Debug mode"
            echo "  --release    Build in Release mode (default)"
            echo "  --jobs N     Use N parallel jobs (default: $(nproc))"
            echo "  --clean      Clean build directory before building"
            echo "  --help       Show this help message"
            echo ""
            echo "NOTE: Cross-compiling Telegram Desktop / CRYPTOGRAM to Windows"
            echo "      is extremely complex due to Qt and Windows library dependencies."
            echo ""
            echo "      For production Windows builds, we recommend:"
            echo "      1. Use GitHub Actions with Windows runners"
            echo "      2. Build on actual Windows machine"
            echo "      3. Use official Telegram Desktop Windows build process"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}CRYPTOGRAM Windows Cross-Compile${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo -e "${YELLOW}WARNING: Windows cross-compilation is experimental${NC}"
echo -e "${YELLOW}For production builds, use native Windows build${NC}"
echo ""
echo "Build Type: ${BUILD_TYPE}"
echo "Jobs: ${JOBS}"
echo "Source: ${SOURCE_DIR}"
echo "Build Dir: ${BUILD_DIR}"
echo "Toolchain: ${TOOLCHAIN_FILE}"
echo ""

# Check if source directory exists
if [ ! -d "${SOURCE_DIR}" ]; then
    echo -e "${RED}ERROR: Source directory not found: ${SOURCE_DIR}${NC}"
    echo "Make sure to mount the source with: -v \$(pwd):/build/CRYPTOGRAM"
    exit 1
fi

# Check for Qt
if [ ! -d "/opt/qt-mingw" ]; then
    echo -e "${YELLOW}WARNING: Qt for MinGW not found at /opt/qt-mingw${NC}"
    echo -e "${YELLOW}Windows build will likely fail without Qt libraries${NC}"
    echo ""
    echo "To provide Qt:"
    echo "  -v /path/to/qt-mingw:/opt/qt-mingw"
    echo ""
fi

cd "${SOURCE_DIR}"

# Clean if requested
if [ -n "${CLEAN}" ]; then
    echo -e "${YELLOW}Cleaning build directory...${NC}"
    rm -rf "${BUILD_DIR}"
fi

# Create build directory
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# Configure with CMake
echo -e "${GREEN}Configuring with CMake for Windows...${NC}"
cmake \
    -G Ninja \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN_FILE}" \
    -DCMAKE_INSTALL_PREFIX="/usr/x86_64-w64-mingw32" \
    -DTDESKTOP_API_ID=611335 \
    -DTDESKTOP_API_HASH=d524b414d21f4d37f08684c1df41ac9c \
    "${SOURCE_DIR}" || {
        echo -e "${RED}CMake configuration failed${NC}"
        echo -e "${YELLOW}This is expected if Qt for Windows is not available${NC}"
        exit 1
    }

# Build
echo -e "${GREEN}Building CRYPTOGRAM for Windows...${NC}"
cmake --build . --parallel "${JOBS}" || {
    echo -e "${RED}Build failed${NC}"
    echo -e "${YELLOW}Windows cross-compilation requires significant setup${NC}"
    exit 1
}

# Check if build succeeded
if [ $? -eq 0 ]; then
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}Build completed successfully!${NC}"
    echo -e "${GREEN}================================${NC}"

    # Find the executable
    BINARY=$(find . -name "CRYPTOGRAM.exe" -o -name "Telegram.exe" -type f | head -1)

    if [ -n "${BINARY}" ]; then
        echo ""
        echo "Binary location: ${BINARY}"
        echo "Size: $(du -h "${BINARY}" | cut -f1)"

        # Copy to output directory
        if [ -d "${OUTPUT_DIR}" ]; then
            echo -e "${YELLOW}Copying binary to output directory...${NC}"
            cp "${BINARY}" "${OUTPUT_DIR}/CRYPTOGRAM-windows-x64.exe"
            echo "Output: ${OUTPUT_DIR}/CRYPTOGRAM-windows-x64.exe"
        fi
    fi

    exit 0
else
    echo -e "${RED}================================${NC}"
    echo -e "${RED}Build failed!${NC}"
    echo -e "${RED}================================${NC}"
    exit 1
fi
