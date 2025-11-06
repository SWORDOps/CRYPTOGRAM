#!/bin/bash
# CRYPTOGRAM Linux Build Script
# Builds CRYPTOGRAM for Linux in Docker environment

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
BUILD_TYPE="Release"
JOBS=$(nproc)
SOURCE_DIR="/build/CRYPTOGRAM"
BUILD_DIR="${SOURCE_DIR}/build-linux"
OUTPUT_DIR="/output"

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
        --relwithdebinfo)
            BUILD_TYPE="RelWithDebInfo"
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
            echo "CRYPTOGRAM Linux Build Script"
            echo ""
            echo "Usage: build-linux.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --debug              Build in Debug mode"
            echo "  --release            Build in Release mode (default)"
            echo "  --relwithdebinfo     Build in RelWithDebInfo mode"
            echo "  --jobs N             Use N parallel jobs (default: $(nproc))"
            echo "  --clean              Clean build directory before building"
            echo "  --help               Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}CRYPTOGRAM Linux Build${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo "Build Type: ${BUILD_TYPE}"
echo "Jobs: ${JOBS}"
echo "Source: ${SOURCE_DIR}"
echo "Build Dir: ${BUILD_DIR}"
echo ""

# Check if source directory exists
if [ ! -d "${SOURCE_DIR}" ]; then
    echo -e "${RED}ERROR: Source directory not found: ${SOURCE_DIR}${NC}"
    echo "Make sure to mount the source with: -v \$(pwd):/build/CRYPTOGRAM"
    exit 1
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
echo -e "${GREEN}Configuring with CMake...${NC}"
cmake \
    -G Ninja \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DCMAKE_INSTALL_PREFIX="/usr" \
    -DCMAKE_C_COMPILER=clang-14 \
    -DCMAKE_CXX_COMPILER=clang++-14 \
    -DCMAKE_LINKER=lld-14 \
    -DCMAKE_C_FLAGS="-fuse-ld=lld" \
    -DCMAKE_CXX_FLAGS="-fuse-ld=lld" \
    -DTDESKTOP_API_ID=611335 \
    -DTDESKTOP_API_HASH=d524b414d21f4d37f08684c1df41ac9c \
    ..

# Build
echo -e "${GREEN}Building CRYPTOGRAM...${NC}"
cmake --build . --parallel "${JOBS}"

# Check if build succeeded
if [ $? -eq 0 ]; then
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}Build completed successfully!${NC}"
    echo -e "${GREEN}================================${NC}"

    # Find the binary
    BINARY=$(find . -name "CRYPTOGRAM" -o -name "Telegram" -type f -executable | head -1)

    if [ -n "${BINARY}" ]; then
        echo ""
        echo "Binary location: ${BINARY}"
        echo "Size: $(du -h "${BINARY}" | cut -f1)"

        # Copy to output directory if it exists
        if [ -d "${OUTPUT_DIR}" ]; then
            echo -e "${YELLOW}Copying binary to output directory...${NC}"
            cp "${BINARY}" "${OUTPUT_DIR}/CRYPTOGRAM-linux-x64"
            chmod +x "${OUTPUT_DIR}/CRYPTOGRAM-linux-x64"
            echo "Output: ${OUTPUT_DIR}/CRYPTOGRAM-linux-x64"
        fi
    else
        echo -e "${YELLOW}Warning: Could not locate binary${NC}"
    fi

    exit 0
else
    echo -e "${RED}================================${NC}"
    echo -e "${RED}Build failed!${NC}"
    echo -e "${RED}================================${NC}"
    exit 1
fi
