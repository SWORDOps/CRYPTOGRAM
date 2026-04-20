# CRYPTOGRAM Build Instructions

## Quick Start

```bash
git clone --recursive https://github.com/SWORDOps/CRYPTOGRAM.git
cd CRYPTOGRAM
git checkout claude/build-ada-protobuf-01Tpe3rvKAkdWnRVGPd3uLET

# Apply required local modifications
./apply-build-patches.sh

# Build
./build_all.sh
```

## Required Local Modifications

After cloning, run `./apply-build-patches.sh` to apply build patches:

- Makes `tde2e` and `tg_owt` libraries optional (cmake submodule)

**Note:** Git will show uncommitted changes in submodules. This is intentional.
See `patches/README.md` for details.

## Building tg_owt Library (Required)

```bash
sudo apt-get install -y libpipewire-0.3-dev libopenh264-dev

mkdir -p ~/Libraries && cd ~/Libraries
git clone https://github.com/desktop-app/tg_owt.git
cd tg_owt
git submodule update --init --recursive
mkdir -p out/Release && cd out/Release
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF ../..
ninja
```

Creates: `~/Libraries/tg_owt/out/Release/libtg_owt.a` (~32MB)

## System Dependencies

```bash
sudo apt-get install -y qt6-base-dev qt6-wayland-dev libqt6svg6-dev \
  libxkbcommon-dev libboost-regex-dev libavcodec-dev libavformat-dev \
  libavutil-dev libavfilter-dev libswscale-dev libswresample-dev \
  libhunspell-dev libpipewire-0.3-dev libopenh264-dev \
  gobject-introspection libgirepository1.0-dev libxcb-record0-dev

# Install all XCB libraries
apt-cache search libxcb | grep -- '-dev' | awk '{print $1}' | xargs sudo apt-get install -y
```

## Build CRYPTOGRAM

```bash
./build_all.sh
```

Build time: 20-40 minutes. Binary will be in `build_release/bin/`

## Troubleshooting

**Submodule fetch errors:** The patches are local-only modifications. Just run `./apply-build-patches.sh` after cloning.

**CMake configuration fails:**
```bash
rm -rf build_release/CMakeCache.txt build_release/CMakeFiles
./build_all.sh --resume
```

**Fresh build:**
```bash
./build_all.sh --force
```
