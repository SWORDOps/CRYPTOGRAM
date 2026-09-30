# AGENT PATH 5 — Reproducible build containers (desktop + Android)

**Scope:** `docker/desktop/`, `docker/android/`, `scripts/interop/build_both.sh`
(container-aware mode), `.github/workflows/*.yml` (container switch — LAST),
`docs/BUILD_CONTAINERS.md`.
**Do NOT touch:** protocol/crypto sources, `Telegram/SourceFiles/**` logic,
`telegram-android/TMessagesProj/src/**` app code. Another session owns
`data_enhanced_privacy.*` / `enhanced_privacy_crypto.*` (in flight).

## Objective

Eliminate the hand-provisioned host dependency that caused today's entire
failure class (gcc SIGBUS from memory-saturated concurrent builds, OpenSSL
version drift, silent library bumps like libheif 1.19→1.23, manual
/usr/local dependency builds). Upstream tdesktop ships Docker build
environments for this reason; the existing `docker/linux/Dockerfile` in this
repo targets Ubuntu 22.04 with the PRE-fork dependency set — obsolete for
us.

Deliverables:
1. `docker/desktop/Dockerfile` — Debian 13 (trixie) base, Qt 6.8.2 + OpenSSL
   3.5.7 from trixie, all system deps from the verified host recipe, plus
   the pinned from-source dependency chain.
2. `docker/android/Dockerfile` — JDK 21 + cmdline-tools + platforms;android-35
   + build-tools;35.0.0 + ndk;27.2.12479018 (the exact ndkVersion from
   `TMessagesProj/build.gradle`).
3. Both images build successfully on the host (Docker 26.1.5 installed;
   podman also available as fallback).
4. A verified in-container build of at least ONE real artifact (host test
   suite for desktop; `compileAfatDebugJavaWithJavac` for Android — the
   full APK/native build is the stretch).
5. CI switch plan documented (`docs/BUILD_CONTAINERS.md`); switching the
   workflows is the final task, only after images prove out.

## The verified host recipe to encode (from the working t420 builds)

### System packages (apt, Debian trixie — matches the verified host set)
- Toolchain: build-essential, cmake, ninja-build, git, pkg-config, python3,
  gperf, autoconf/automake/libtool (rnnoise), ccache (optional), clang
  (optional compiler candidate).
- Qt 6.8.2 dev: qt6-base-dev, qt6-base-private-dev, qt6-svg-dev,
  qt6-5compat-dev, qt6-tools-dev, qt6-shadertools-dev, qt6-wayland-dev,
  qt6-multimedia-dev, qt6-image-formats-plugins.
- Crypto/SSL: libssl-dev (3.5.x from trixie — ML-KEM required by the PQ
  layer; do NOT use an older base).
- Media: libavcodec-dev libavfilter-dev libavformat-dev libswscale-dev
  libswresample-dev libavutil-dev libopenh264-dev libvpx-dev libopus-dev
  libjpeg-dev libgif-dev libwebp-dev libavif-dev libjxl-dev libheif-dev.
- System: libgbm-dev libdrm-dev libegl1-mesa-dev libgl1-mesa-dev
  libx11-dev libxext-dev libxfixes-dev libxrandr-dev libxcomposite-dev
  libxdamage-dev libxrender-dev libxtst-dev libxcb1-dev + the xcb dev family
  (keysyms/record/screensaver/xfixes/damage/composite/randr/shm/xinerama/
  xinput/render-util/cursor/icccm/util/xkb/shape/present/dri3),
  libxkbcommon-dev libasound2-dev libpulse-dev libpipewire-0.3-dev.
- Desktop integration: libglib2.0-dev gobject-introspection
  libgirepository1.0-dev libKF6KCoreAddons? (KF6: kcoreaddons via
  libkf6coreaddons-dev), libdbus-1-dev, minizip (libminizip-dev),
  liblz4-dev libxxhash-dev zlib1g-dev, libhunspell-dev libfmt-dev,
  librlottie-dev libprotobuf-dev protobuf-compiler libabsl-dev,
  libopenal-dev librnnoise? (NOT in trixie — build from source below),
  libpcsclite-dev (CAC/PIV), libheif-dev, ccache.
- Testing: catch2 (3.7.x in trixie ✓), libssl-dev.
- NOTE for full reproducibility later: pin apt to
  snapshot.debian.org (PATH 5 follow-up; document, don't implement first).

### From-source pinned dependencies (build stages in the Dockerfile)
1. ada (ada-url/ada, any recent) → cmake install. (Host recipe: default.)
2. rnnoise (xiph) → autogen/configure --disable-shared --enable-static
   --with-pic CFLAGS="-fPIC -O2" (host hit a PIE relocation error without
   --with-pic — MUST keep).
3. protobuf v21.12: cmake -Dprotobuf_BUILD_TESTS=OFF
   -DCMAKE_CXX_STANDARD=17 -Dprotobuf_ABSL_PROVIDER=package
   (needs libabsl-dev).
4. tde2e: clone tdlib/td, cmake -DTD_E2E_ONLY=ON
   -DCMAKE_POSITION_INDEPENDENT_CODE=ON.
5. tg_owt: the repo's pinned submodule commit (see `Telegram/tg_owt`
   gitlink on main), configure with
   -DTG_OWT_PACKAGED_BUILD=OFF -DENABLE_CRCUTIL=ON
   -DCMAKE_DISABLE_FIND_PACKAGE_absl=TRUE  ← CRITICAL: Debian's ABI-patched
   abseil (inline namespace debian7) breaks tg_owt compilation; this flag
   forces tg_owt's bundled abseil-cpp. Install prefix must match what the
   project configure expects (host used $HOME/.local → in-container use
   /usr/local or a fixed /opt/cryptogram-deps prefix exported as
   CMAKE_PREFIX_PATH).
6. Catch2 v3 (trixie's 3.7.1 package is fine).

### Project configure flags (from the verified host configure)
- -G Ninja -DCMAKE_BUILD_TYPE=Release
- -DCRYPTOGRAM_BUILD_TESTS=ON
- -DDESKTOP_APP_DISABLE_AUTOUPDATE=ON -DDESKTOP_APP_DISABLE_CRASH_REPORTS=ON
- -DCMAKE_PREFIX_PATH=<deps prefix>
- -DCRYPTOGRAM_ENABLE_COUNTERINTELLIGENCE=OFF (default)
- ALL submodules must be initialized in the image or at run time
  (`git submodule update --init --recursive`) — the desktop tree requires
  every ThirdParty entry; the build also expects `ThirdParty/libsignal/src`
  at the repo ROOT sibling path (build quirk, keep the copy step if needed).

### Android image
- FROM eclipse-temurin:21-jdk (JDK 21 verified working with Gradle 8.7 /
  AGP 8.6.1).
- ENV ANDROID_HOME=/opt/android-sdk.
- Install cmdline-tools (commandlinetools-linux-11076708_latest.zip from
  dl.google.com), `yes | sdkmanager --licenses`, then:
  platform-tools, platforms;android-35, build-tools;35.0.0,
  ndk;27.2.12479018 (EXACT ndkVersion from TMessagesProj/build.gradle).
- Workdir /src; entrypoint wraps
  `./gradlew :TMessagesProj_App:assembleAfatDebug --no-daemon`
  with ANDROID_HOME/ANDROID_NDK_HOME/ANDROID_SDK_ROOT set and
  local.properties generated (sdk.dir) at run time.
- Gradle deps: mount a cache volume (~/.gradle, /src/.gradle) so repeated
  container builds don't redownload.

## Tasks

1. Author `docker/desktop/Dockerfile` (multi-stage: deps layer → source
   layer). Keep apt layer BEFORE source copies for cache efficiency.
2. Author `docker/android/Dockerfile`.
3. Author `docker/README-cryptogram.md`: build commands
   (`docker build -t cryptogram-build:desktop docker/desktop` etc.), run
   commands with volume mounts (repo read-only + ccache/ccache dirs),
   known limitations.
4. Build both images on the host; fix until green.
5. In-container verification: desktop → configure + build the Telegram
   target with tests, run the standalone suites (x3dh_fixed,
   quantum_kem, enhanced_privacy, covert_sha384) — all green; android →
   `compileAfatDebugJavaWithJavac` green.
6. `docs/BUILD_CONTAINERS.md`: usage, CI switch plan
   (github-runner → container jobs; sign-off ceremony stays OUTSIDE
   containers — YubiKey PIV/OpenPGP is local-only by design), snapshot
   pinning follow-up, and the libheif-style drift note (images freeze
   distro versions).
7. Only after 1–6 are green: switch `.github/workflows/linux-deb.yml` +
   `android-apk.yml` + `tests.yml` jobs to the containers (or note the
   exact job diffs in the doc if workflow testing needs CI runs).

## Verification gates (report outputs)

1. `docker build` both images: exit 0.
2. In-container: Telegram configure + build + the 4 standalone test suites
   PASS; Android compileAfatDebugJavaWithJavac green.
3. Harnesses on the HOST still PASS (no host-file regressions).
4. Docs exist.

## Guardrails

- Do not switch CI workflows until the images have produced a real binary.
- Do not vendor proprietary bits (Android SDK is license-restricted —
  install at image BUILD time from Google's repo, never redistribute in a
  registry; keep images local or in a private registry only).
- Do not touch protocol/crypto sources or the in-flight agent scopes.
- The desktop binary is built INSIDE the container against container libs —
  the resulting binary targets container glibc; document that runners/users
  need a compatible glibc (or note the snap/AppImage packaging follow-up).

## Report back

Files, image sizes, in-container verification outputs, CI switch plan,
deviations with reasons.
