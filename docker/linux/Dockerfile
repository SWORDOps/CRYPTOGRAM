# CRYPTOGRAM Linux Build Environment
# Ubuntu 22.04 LTS with all dependencies for building CRYPTOGRAM

FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Build arguments
ARG JOBS=8

# Set working directory
WORKDIR /build

# Install base dependencies
RUN apt-get update && apt-get install -y \
    # Build essentials
    build-essential \
    ninja-build \
    git \
    wget \
    curl \
    python3 \
    python3-pip \
    pkg-config \
    # Qt dependencies
    qtbase5-dev \
    qtbase5-dev-tools \
    qttools5-dev \
    qttools5-dev-tools \
    libqt5svg5-dev \
    libqt5waylandclient5-dev \
    qtwayland5 \
    # Media libraries
    libavcodec-dev \
    libavformat-dev \
    libavutil-dev \
    libswscale-dev \
    libswresample-dev \
    # Audio
    libasound2-dev \
    libpulse-dev \
    libopenal-dev \
    libopus-dev \
    # Graphics
    libgl1-mesa-dev \
    libglu1-mesa-dev \
    libx11-dev \
    libxrandr-dev \
    libxrender-dev \
    libxcomposite-dev \
    libxdamage-dev \
    libxext-dev \
    libxfixes-dev \
    libxkbcommon-dev \
    libxkbcommon-x11-dev \
    # System libraries
    libssl-dev \
    zlib1g-dev \
    liblzma-dev \
    libicu-dev \
    libdbus-1-dev \
    # Network
    libcurl4-openssl-dev \
    # Compression
    libbz2-dev \
    liblz4-dev \
    libzstd-dev \
    # X11 screen saver (for idle detection)
    libxss-dev \
    # Additional tools
    ccache \
    clang-14 \
    lld-14 \
    patchelf \
    && rm -rf /var/lib/apt/lists/*

# Install CMake 3.25+ (Ubuntu 22.04 only has 3.22)
# Using Kitware's official installer
RUN wget -q https://github.com/Kitware/CMake/releases/download/v3.28.1/cmake-3.28.1-linux-x86_64.sh -O /tmp/cmake-install.sh && \
    chmod +x /tmp/cmake-install.sh && \
    /tmp/cmake-install.sh --skip-license --prefix=/usr/local && \
    rm /tmp/cmake-install.sh && \
    cmake --version

# Set up ccache for faster rebuilds
ENV PATH="/usr/lib/ccache:${PATH}"
ENV CCACHE_DIR="/build/.ccache"
ENV CCACHE_MAXSIZE="5G"

# Clone CRYPTOGRAM repository (or use mounted volume)
# Repository will be mounted at /build/CRYPTOGRAM via docker run -v

# Build script
COPY build-linux.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/build-linux.sh

# Entry point
ENTRYPOINT ["/usr/local/bin/build-linux.sh"]
CMD ["--help"]

# Build artifacts will be in /tmp/build-linux/
# Mount volumes:
# - Source: -v $(pwd):/build/CRYPTOGRAM:ro (read-only)
# - Cache: -v cryptogram-ccache:/build/.ccache
# - Output: -v $(pwd)/out:/output

# Example usage:
# docker build -t cryptogram-linux docker/linux/
# docker run --rm -v $(pwd):/build/CRYPTOGRAM:ro -v cryptogram-ccache:/build/.ccache -v $(pwd)/out:/output cryptogram-linux --release
