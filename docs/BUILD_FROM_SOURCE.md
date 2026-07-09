# Building CRYPTOGRAM from Source

Building CRYPTOGRAM requires fetching all submodules and compiling its massive dependency tree via the `prepare.py` script before running CMake.

## 1. Clone the Repository
Clone the codebase and all of its submodules recursively:
```bash
git clone --recursive https://github.com/SWORDOps/CRYPTOGRAM.git
cd CRYPTOGRAM
```

## 2. Install Dependencies

### Linux (Ubuntu/Debian)
Install the required tools, Qt6 libraries, and XCB/GIR dependencies:
```bash
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  build-essential git pkg-config \
  qt6-base-dev qt6-base-private-dev qt6-tools-dev qt6-tools-dev-tools \
  qt6-image-formats-plugins qt6-l10n-tools qt6-declarative-dev qt6-multimedia-dev \
  libqt6core5compat6-dev qt6-svg-dev qt6-wayland-dev qtwayland5 \
  libavcodec-dev libavformat-dev libavutil-dev libavfilter-dev libswscale-dev libswresample-dev \
  libjpeg-dev libavif-dev libwebp-dev libopus-dev libvpx-dev \
  libssl-dev libopenal-dev libpulse-dev \
  libxcb-icccm4-dev libxcb-image0-dev libxcb-keysyms1-dev libxcb-record0-dev gobject-introspection libgirepository1.0-dev \
  libxcb-screensaver0-dev libxcb-util-dev libxcb-ewmh-dev \
  libxcb-randr0-dev libxcb-render-util0-dev libxcb-shape0-dev \
  libxcb-sync-dev libxcb-xfixes0-dev libxcb-xkb-dev libxkbcommon-x11-dev libxcb-shm0-dev \
  libxcomposite-dev libxdamage-dev libxrender-dev libxtst-dev libxss-dev libxcursor-dev \
  libasound2-dev libgbm-dev libdrm-dev libepoxy-dev libpipewire-0.3-dev libxkbcommon-x11-dev \
  libgl1-mesa-dev libglib2.0-dev libgtk-3-dev
```

### macOS
Install the required tools via Homebrew. Ensure `HOMEBREW_NO_REQUIRE_TAP_TRUST=1` is set to bypass tap trust issues.
```bash
export HOMEBREW_NO_REQUIRE_TAP_TRUST=1
brew install cmake ninja yasm pkg-config autoconf automake libtool
python3 -m pip install --upgrade pip --break-system-packages
```

## 3. Prepare Third-Party Dependencies
Run the `prepare.py` script to fetch, configure, and compile the massive third-party dependency tree (e.g., FFmpeg, WebRTC, OpenSSL, zlib):
```bash
export QT=6
python3 Telegram/build/prepare/prepare.py
```
*Note: This step may take 10-20 minutes depending on your CPU and network connection.*

## 4. Configure CMake
Once the dependencies are prepared, run the CMake configuration step. 
Use your own API ID and API HASH if necessary, or the default ones provided.
```bash
cmake -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DDESKTOP_APP_USE_PACKAGED=OFF \
  -DTG_OWT_PACKAGED_BUILD=OFF \
  -DTDESKTOP_API_ID=17349 \
  -DTDESKTOP_API_HASH=344583e45741c457fe1862106095a5eb
```

## 5. Compile the Binary
Finally, compile the CRYPTOGRAM binary:
```bash
cmake --build build --config Release --parallel $(nproc)
```

Once compilation completes, the resulting application binary will be located inside the `build/` or `build/bin/` folder.
