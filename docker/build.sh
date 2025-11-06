#!/bin/bash
# CRYPTOGRAM Universal Docker Build Script
# Orchestrates multi-platform builds using Docker

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
OUTPUT_DIR="${PROJECT_ROOT}/out"

# Platform selection
BUILD_LINUX=0
BUILD_WINDOWS=0
BUILD_IOS=0
BUILD_ALL=0
BUILD_MODE="release"
JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 8)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --linux)
            BUILD_LINUX=1
            shift
            ;;
        --windows)
            BUILD_WINDOWS=1
            shift
            ;;
        --ios)
            BUILD_IOS=1
            shift
            ;;
        --all)
            BUILD_ALL=1
            BUILD_LINUX=1
            BUILD_WINDOWS=1
            shift
            ;;
        --debug)
            BUILD_MODE="debug"
            shift
            ;;
        --release)
            BUILD_MODE="release"
            shift
            ;;
        --jobs)
            JOBS="$2"
            shift 2
            ;;
        --help)
            cat << 'EOF'
CRYPTOGRAM Universal Docker Build Script
=========================================

Build CRYPTOGRAM for multiple platforms using Docker.

Usage: ./build.sh [OPTIONS]

Options:
  --linux           Build for Linux (x86_64)
  --windows         Build for Windows (x86_64) [Cross-compile]
  --ios             Build for iOS (experimental, not recommended)
  --all             Build for all supported platforms (Linux + Windows)

  --debug           Build in Debug mode
  --release         Build in Release mode (default)
  --jobs N          Use N parallel jobs (default: auto-detect)

  --help            Show this help message

Examples:
  # Build Linux version
  ./build.sh --linux

  # Build all platforms (Linux + Windows)
  ./build.sh --all --release

  # Build Linux with 16 parallel jobs
  ./build.sh --linux --jobs 16

Output:
  Binaries will be placed in: out/
  - out/CRYPTOGRAM-linux-x64
  - out/CRYPTOGRAM-windows-x64.exe
  - out/CRYPTOGRAM-ios-arm64 (if iOS build succeeds)

Requirements:
  - Docker installed and running
  - Sufficient disk space (~10GB for build artifacts)
  - For Windows: Qt for MinGW (optional, see documentation)
  - For iOS: macOS SDK (not included, see documentation)

Notes:
  - Linux builds are fully supported
  - Windows cross-compilation is experimental
  - iOS builds require significant additional setup (not recommended)
  - For production Windows/iOS builds, use native environments

Documentation:
  See DOCKER_BUILD.md for detailed instructions

EOF
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Show banner
echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                                        ║${NC}"
echo -e "${BLUE}║  ${GREEN}CRYPTOGRAM Multi-Platform Build${BLUE}      ║${NC}"
echo -e "${BLUE}║                                        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo -e "${RED}ERROR: Docker is not installed${NC}"
    echo "Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker daemon is running
if ! docker info &> /dev/null; then
    echo -e "${RED}ERROR: Docker daemon is not running${NC}"
    echo "Please start Docker and try again"
    exit 1
fi

# Default to Linux if no platform specified
if [[ $BUILD_LINUX -eq 0 ]] && [[ $BUILD_WINDOWS -eq 0 ]] && [[ $BUILD_IOS -eq 0 ]] && [[ $BUILD_ALL -eq 0 ]]; then
    echo -e "${YELLOW}No platform specified, defaulting to Linux${NC}"
    BUILD_LINUX=1
fi

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Change to docker directory
cd "${SCRIPT_DIR}"

# Build Docker images first
echo -e "${GREEN}Building Docker images...${NC}"
if [[ $BUILD_LINUX -eq 1 ]] || [[ $BUILD_ALL -eq 1 ]]; then
    echo -e "${BLUE}→ Building Linux image...${NC}"
    docker build -t cryptogram-linux:latest linux/
fi

if [[ $BUILD_WINDOWS -eq 1 ]] || [[ $BUILD_ALL -eq 1 ]]; then
    echo -e "${BLUE}→ Building Windows image...${NC}"
    docker build -t cryptogram-windows:latest windows/
fi

if [[ $BUILD_IOS -eq 1 ]]; then
    echo -e "${BLUE}→ Building iOS image...${NC}"
    docker build -t cryptogram-ios:latest ios/
fi

echo ""
echo -e "${GREEN}Starting builds...${NC}"
echo ""

# Build Linux
if [[ $BUILD_LINUX -eq 1 ]] || [[ $BUILD_ALL -eq 1 ]]; then
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         Building for Linux             ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"

    docker run --rm \
        -v "${PROJECT_ROOT}:/build/CRYPTOGRAM:ro" \
        -v "${OUTPUT_DIR}:/output" \
        -v cryptogram-ccache-linux:/build/.ccache \
        -e JOBS="${JOBS}" \
        cryptogram-linux:latest \
        --"${BUILD_MODE}"

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Linux build completed successfully${NC}"
    else
        echo -e "${RED}✗ Linux build failed${NC}"
        exit 1
    fi
    echo ""
fi

# Build Windows
if [[ $BUILD_WINDOWS -eq 1 ]] || [[ $BUILD_ALL -eq 1 ]]; then
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║        Building for Windows            ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    echo -e "${YELLOW}Note: Windows cross-compilation is experimental${NC}"
    echo ""

    docker run --rm \
        -v "${PROJECT_ROOT}:/build/CRYPTOGRAM:ro" \
        -v "${OUTPUT_DIR}:/output" \
        -v cryptogram-ccache-windows:/build/.ccache \
        -e JOBS="${JOBS}" \
        cryptogram-windows:latest \
        --"${BUILD_MODE}" || {
            echo -e "${YELLOW}Windows build failed (expected without Qt for MinGW)${NC}"
            echo -e "${YELLOW}See DOCKER_BUILD.md for setup instructions${NC}"
        }
    echo ""
fi

# Build iOS
if [[ $BUILD_IOS -eq 1 ]]; then
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          Building for iOS              ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    echo -e "${YELLOW}iOS builds are not supported in Docker${NC}"
    echo -e "${YELLOW}Use native macOS + Xcode for iOS builds${NC}"
    echo ""

    docker run --rm \
        cryptogram-ios:latest \
        --help
    echo ""
fi

# Summary
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║            Build Summary               ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""
echo "Output directory: ${OUTPUT_DIR}"
echo ""

if [ -d "${OUTPUT_DIR}" ]; then
    ls -lh "${OUTPUT_DIR}/"
    echo ""
fi

echo -e "${GREEN}Build process complete!${NC}"
