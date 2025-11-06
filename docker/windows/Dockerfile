# CRYPTOGRAM Windows Cross-Compile Environment
# Ubuntu 22.04 with MinGW for cross-compiling to Windows

FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Build arguments
ARG JOBS=8

# Set working directory
WORKDIR /build

# Install base dependencies and MinGW
RUN apt-get update && apt-get install -y \
    # Build essentials
    build-essential \
    cmake \
    ninja-build \
    git \
    wget \
    curl \
    python3 \
    python3-pip \
    pkg-config \
    # MinGW cross-compiler (64-bit)
    mingw-w64 \
    g++-mingw-w64-x86-64 \
    gcc-mingw-w64-x86-64 \
    binutils-mingw-w64-x86-64 \
    # Wine (for testing Windows binaries on Linux)
    wine64 \
    wine64-tools \
    # Tools
    ccache \
    patchelf \
    zip \
    unzip \
    p7zip-full \
    nsis \
    && rm -rf /var/lib/apt/lists/*

# Set up ccache
ENV PATH="/usr/lib/ccache:${PATH}"
ENV CCACHE_DIR="/build/.ccache"
ENV CCACHE_MAXSIZE="5G"

# Windows cross-compile environment
ENV MINGW_PREFIX="x86_64-w64-mingw32"
ENV CC="${MINGW_PREFIX}-gcc"
ENV CXX="${MINGW_PREFIX}-g++"
ENV AR="${MINGW_PREFIX}-ar"
ENV RANLIB="${MINGW_PREFIX}-ranlib"
ENV WINDRES="${MINGW_PREFIX}-windres"

# Download and install Qt for Windows (MinGW)
# This is complex - typically requires pre-built Qt binaries for MinGW
# Or building Qt from source for Windows target
WORKDIR /opt

# For now, we'll document that Qt for Windows needs to be provided
# via mounted volume or pre-built in the image
RUN echo "Qt for Windows (MinGW) must be provided at /opt/qt-mingw" > /opt/qt-mingw-readme.txt

# CMake toolchain file for cross-compilation
COPY mingw-w64-toolchain.cmake /opt/

# Build script
COPY build-windows.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/build-windows.sh

# Entry point
ENTRYPOINT ["/usr/local/bin/build-windows.sh"]
CMD ["--help"]

# Build artifacts will be in /build/CRYPTOGRAM/build-windows/
# Mount volumes:
# - Source: -v $(pwd):/build/CRYPTOGRAM
# - Qt: -v /path/to/qt-mingw:/opt/qt-mingw
# - Cache: -v cryptogram-ccache:/build/.ccache
# - Output: -v $(pwd)/out:/output

# Example usage:
# docker build -t cryptogram-windows docker/windows/
# docker run --rm -v $(pwd):/build/CRYPTOGRAM -v cryptogram-ccache:/build/.ccache cryptogram-windows --release

# NOTE: Cross-compiling Telegram Desktop / CRYPTOGRAM to Windows is extremely complex
# due to Qt dependencies, Windows-specific libraries, and build system complexity.
#
# Alternative approaches:
# 1. Build on actual Windows in Docker (requires Windows containers)
# 2. Use CI/CD services with Windows runners (GitHub Actions)
# 3. Use Wine + Windows build environment
#
# This Dockerfile provides the foundation for MinGW cross-compilation,
# but full Qt/Telegram build may require significant additional setup.
