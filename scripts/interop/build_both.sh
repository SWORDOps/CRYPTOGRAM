#!/usr/bin/env bash
#
# build_both.sh — incremental builds for the live interop verification harness.
#
# Builds BOTH clients that take part in the desktop<->Android E2EE exchange:
#   1. Desktop client  -> build_tests/bin/Telegram (CMake/Ninja, incremental)
#   2. Android client  -> telegram-android/TMessagesProj_App/build/outputs/
#                         apk/afat/debug/app.apk (assembleAfatDebug, incremental)
#
# Incremental by design: a full Android assemble takes ~1h45 cold; this script
# NEVER runs clean tasks. Exits non-zero on the first failing step and prints
# the artifact paths + sizes on success.
#
# Env overrides:
#   ANDROID_HOME          SDK root          (default: $HOME/Android/Sdk)
#   ANDROID_NDK_HOME      NDK root          (default: $ANDROID_HOME/ndk/27.2.12479018)
#   CRYPTOGRAM_DESKTOP_TARGET  cmake target (default: Telegram — the client
#                         binary; the default/all target also builds tests/unit,
#                         whose in-flight targets may be broken by concurrent work)
#   CRYPTOGRAM_BUILD_JOBS      parallel compile jobs (default: nproc; lower it
#                         on memory-saturated shared hosts — cc1plus dies with
#                         SIGBUS "internal compiler error" when swap runs out)
#   CRYPTOGRAM_GRADLE_TASK     gradle task  (default: :TMessagesProj_App:assembleAfatDebug)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/27.2.12479018}"
DESKTOP_BUILD_DIR="$ROOT_DIR/build_tests"
DESKTOP_BIN="$DESKTOP_BUILD_DIR/bin/Telegram"
GRADLE_TASK="${CRYPTOGRAM_GRADLE_TASK:-:TMessagesProj_App:assembleAfatDebug}"
DESKTOP_TARGET="${CRYPTOGRAM_DESKTOP_TARGET:-Telegram}"
JOBS="${CRYPTOGRAM_BUILD_JOBS:-$(nproc)}"
APK="$ROOT_DIR/telegram-android/TMessagesProj_App/build/outputs/apk/afat/debug/app.apk"

log()  { printf '\n=== %s ===\n' "$*"; }
fail() { printf 'BUILD_BOTH: FAILED — %s\n' "$*" >&2; exit 1; }

report_artifact() {
    local path="$1" label="$2"
    if [ ! -f "$path" ]; then
        fail "$label missing after build: $path"
    fi
    printf '%s:\n' "$label"
    printf '  path:   %s\n' "$path"
    printf '  size:   %s\n' "$(du -h "$path" | cut -f1)"
    printf '  sha256: %s\n' "$(sha256sum "$path" | cut -d' ' -f1)"
}

# ---------------------------------------------------------------------------
# Step 1: desktop client (incremental; build_tests uses the Ninja generator)
# ---------------------------------------------------------------------------
log "Step 1/2: desktop client (incremental cmake --build)"

[ -f "$DESKTOP_BUILD_DIR/CMakeCache.txt" ] \
    || fail "desktop build dir not configured (expected $DESKTOP_BUILD_DIR/CMakeCache.txt)"

cmake --build "$DESKTOP_BUILD_DIR" --parallel "$JOBS" --target "$DESKTOP_TARGET"

[ -x "$DESKTOP_BIN" ] || fail "desktop binary not executable after build: $DESKTOP_BIN"

# ---------------------------------------------------------------------------
# Step 2: Android client (incremental assembleDebug; gradle cache is warm)
# ---------------------------------------------------------------------------
log "Step 2/2: Android client (incremental $GRADLE_TASK)"

command -v java >/dev/null 2>&1 || fail "java not found on PATH"

( cd "$ROOT_DIR/telegram-android" && \
  ANDROID_HOME="$ANDROID_HOME" ANDROID_NDK_HOME="$ANDROID_NDK_HOME" \
      ./gradlew "$GRADLE_TASK" --no-daemon )

# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------
log "Artifacts"
report_artifact "$DESKTOP_BIN" "Desktop client binary"
report_artifact "$APK"         "Android debug APK"

printf '\nVerify the APK carries the native interop library:\n'
unzip -l "$APK" | grep -F 'libcryptogram.so' | head -8 \
    || fail "APK does not contain lib/*/libcryptogram.so"

log "build_both.sh OK"
