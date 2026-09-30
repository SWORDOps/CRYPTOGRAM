# CRYPTOGRAM desktop build container (Debian 13 / trixie).
#
# Encodes the verified t420 host recipe: Qt 6.8.2 + OpenSSL 3.5.x from
# trixie, the full xcb/media/glib dev set, and the pinned from-source
# dependency chain (ada, rnnoise PIC, protobuf v21.12, tde2e, tg_owt).
# Debian's ABI-patched abseil breaks tg_owt — tg_owt builds with its own
# bundled abseil via -DCMAKE_DISABLE_FIND_PACKAGE_absl=TRUE.
#
# Build image:
#   docker build -t cryptogram-build:desktop docker/desktop
# Build the project (mount the source tree read-write for the build dir):
#   docker run --rm -v "$PWD":/src -w /src cryptogram-build:desktop \
#     bash -c "cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
#       -DCRYPTOGRAM_BUILD_TESTS=ON -DDESKTOP_APP_DISABLE_AUTOUPDATE=ON \
#       -DDESKTOP_APP_DISABLE_CRASH_REPORTS=ON \
#       -DCRYPTOGRAM_ENABLE_COUNTERINTELLIGENCE=OFF \
#       -DCMAKE_PREFIX_PATH=/usr/local && \
#      cmake --build build --target Telegram -j$(nproc) && \
#      ctest --test-dir build_tests --output-on-failure"
#
# NOTE: submodules must be initialized in the mounted tree
# (git submodule update --init --recursive) BEFORE the container build.

FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build git pkg-config python3 ccache \
    autoconf automake libtool curl ca-certificates unzip xz-utils gperf \
    clang lld \
    qt6-base-dev qt6-base-private-dev qt6-svg-dev qt6-5compat-dev \
    qt6-tools-dev qt6-shadertools-dev qt6-wayland-dev qt6-multimedia-dev \
    qt6-image-formats-plugins \
    libssl-dev liblz4-dev libxxhash-dev zlib1g-dev libminizip-dev \
    librlottie-dev libprotobuf-dev protobuf-compiler libabsl-dev \
    libavcodec-dev libavfilter-dev libavformat-dev libswscale-dev \
    libswresample-dev libavutil-dev libopenh264-dev libvpx-dev libopus-dev \
    libopenal-dev libpipewire-0.3-dev libasound2-dev libpulse-dev \
    libgbm-dev libdrm-dev libegl1-mesa-dev libgl1-mesa-dev \
    libx11-dev libxext-dev libxfixes-dev libxrandr-dev libxcomposite-dev \
    libxdamage-dev libxrender-dev libxtst-dev libxkbcommon-dev \
    libxcb-keysyms1-dev libxcb-record0-dev libxcb-screensaver0-dev \
    libxcb-xfixes0-dev libxcb-damage0-dev libxcb-composite0-dev \
    libxcb-randr0-dev libxcb-shm0-dev libxcb-xinerama0-dev \
    libxcb-xinput-dev libxcb-render-util0-dev libxcb-cursor-dev \
    libxcb-icccm4-dev libxcb-util-dev libxcb-xkb-dev libxcb-shape0-dev \
    libxcb-present-dev libxcb-dri3-dev \
    libglib2.0-dev gobject-introspection libgirepository1.0-dev \
    libhunspell-dev libfmt-dev libavif-dev libjxl-dev libwebp-dev \
    libjpeg-dev libgif-dev libheif-dev \
    libpcsclite-dev libkf6coreaddons-dev \
    catch2 \
    && rm -rf /var/lib/apt/lists/*

# ─── Pinned from-source dependency chain (verified host recipe) ──────────

# ada (URL parser)
RUN git clone --depth 1 https://github.com/ada-url/ada.git /tmp/ada \
    && cmake -S /tmp/ada -B /tmp/ada/build -G Ninja \
       -DADA_TESTING=OFF -DADA_DEVELOPMENT_MODE=OFF \
       -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /tmp/ada/build -j"$(nproc)" \
    && cmake --install /tmp/ada/build \
    && rm -rf /tmp/ada

# rnnoise (static PIC — PIE link fails without -fPIC/--with-pic)
RUN git clone --depth 1 https://github.com/xiph/rnnoise.git /tmp/rnnoise \
    && cd /tmp/rnnoise \
    && ./autogen.sh \
    && ./configure --disable-shared --enable-static --with-pic \
       CFLAGS="-fPIC -O2" \
    && make -j"$(nproc)" && make install \
    && rm -rf /tmp/rnnoise

# protobuf v21.12 (desktop PQ + tde2e expect this generation)
RUN git clone --depth 1 -b v21.12 \
        https://github.com/protocolbuffers/protobuf.git /tmp/protobuf \
    && cmake -S /tmp/protobuf -B /tmp/protobuf/build -G Ninja \
       -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local \
       -Dprotobuf_BUILD_TESTS=OFF -DCMAKE_CXX_STANDARD=17 \
       -Dprotobuf_ABSL_PROVIDER=package \
    && cmake --build /tmp/protobuf/build -j"$(nproc)" \
    && cmake --install /tmp/protobuf/build \
    && rm -rf /tmp/protobuf

# tde2e (TDLib E2E — no Debian package)
RUN git clone --depth 1 https://github.com/tdlib/td.git /tmp/td \
    && cmake -S /tmp/td -B /tmp/td/build -G Ninja \
       -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local \
       -DTD_E2E_ONLY=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    && cmake --build /tmp/td/build -j"$(nproc)" \
    && cmake --install /tmp/td/build \
    && rm -rf /tmp/td

# tg_owt is NOT built here: it is a pinned submodule of the project tree
# (Telegram/tg_owt) and must be built from the mounted source with
# -DCMAKE_DISABLE_FIND_PACKAGE_absl=TRUE so its own bundled abseil is used
# (Debian's ABI-patched abseil breaks it). The project's configure step
# handles it; a prebuilt image variant can add it later if needed.

ENV CMAKE_PREFIX_PATH=/usr/local
WORKDIR /src
