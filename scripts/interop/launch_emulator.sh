#!/usr/bin/env bash
#
# launch_emulator.sh — boot the interop test AVD, install the APK, launch the app.
#
# Steps:
#   1. Ensure an AVD exists (env CRYPTOGRAM_AVD, default: cryptogram_api35);
#      create it from CRYPTOGRAM_AVD_IMAGE (default: system-images;android-35;
#      google_apis;x86_64) via avdmanager if absent.
#   2. Boot it headless (KVM), wait for sys.boot_completed.
#   3. adb install -r the debug APK.
#   4. Start the launchable activity read from the APK itself (aapt).
#
# GUARDRAIL: the AVD and its snapshots can hold a LOGGED-IN Telegram session.
# State stays under the emulator's own directory (~/.android/avd). Never copy
# AVD state into the repository, never commit it.
#
# Env overrides:
#   CRYPTOGRAM_AVD        AVD name       (default: cryptogram_api35)
#   CRYPTOGRAM_AVD_IMAGE  system image   (default: system-images;android-35;google_apis;x86_64)
#   CRYPTOGRAM_WIPE       =1 -> boot with -wipe-data (destroys the login session!)
#   CRYPTOGRAM_BOOT_WAIT  boot timeout s (default: 600)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
EMU="$ANDROID_HOME/emulator/emulator"
AVDMANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager"
ADB="$ANDROID_HOME/platform-tools/adb"
[ -x "$ADB" ] || ADB="$(command -v adb)"
BUILD_TOOLS="$ANDROID_HOME/build-tools/34.0.0"
[ -x "$BUILD_TOOLS/aapt" ] || BUILD_TOOLS="$ANDROID_HOME/build-tools/35.0.0"
AAPT="$BUILD_TOOLS/aapt"

AVD="${CRYPTOGRAM_AVD:-cryptogram_api35}"
IMAGE="${CRYPTOGRAM_AVD_IMAGE:-system-images;android-35;google_apis;x86_64}"
BOOT_WAIT="${CRYPTOGRAM_BOOT_WAIT:-600}"
APK="$ROOT_DIR/telegram-android/TMessagesProj_App/build/outputs/apk/afat/debug/app.apk"
LOG_DIR="$ROOT_DIR/artifacts/interop-logs"
BOOT_LOG="$LOG_DIR/emulator-boot.log"

log() { printf '\n=== %s ===\n' "$*"; }
fail() { printf 'LAUNCH_EMULATOR: FAILED — %s\n' "$*" >&2; exit 1; }

[ -x "$EMU" ] || fail "emulator binary not found at $EMU (install: sdkmanager 'emulator')"
[ -f "$APK" ] || fail "APK not found: $APK (run scripts/interop/build_both.sh first)"
mkdir -p "$LOG_DIR"

# --- Step 1: AVD present? ---------------------------------------------------
log "Step 1/4: ensure AVD '$AVD' exists"
if "$EMU" -list-avds 2>/dev/null | grep -Fxq "$AVD"; then
    printf 'AVD %s already exists\n' "$AVD"
else
    printf 'Creating AVD %s from %s\n' "$AVD" "$IMAGE"
    echo no | "$AVDMANAGER" create avd -n "$AVD" -k "$IMAGE" -d pixel_5 --force \
        || fail "avdmanager create failed"
fi

# --- Step 2: boot headless ---------------------------------------------------
log "Step 2/4: boot headless (KVM)"
if "$ADB" get-state 2>/dev/null | grep -q device; then
    printf 'A device is already connected via adb; reusing it\n'
else
    WIPE_FLAG=""
    if [ "${CRYPTOGRAM_WIPE:-0}" = "1" ]; then
        WIPE_FLAG="-wipe-data"
        printf 'CRYPTOGRAM_WIPE=1 -> cold boot with -wipe-data (login session will be LOST)\n'
    fi
    nohup "$EMU" -avd "$AVD" $WIPE_FLAG \
        -no-window -no-audio -no-boot-anim -gpu swiftshader_indirect \
        >"$BOOT_LOG" 2>&1 &
    printf 'emulator pid %s; boot log: %s\n' "$!" "$BOOT_LOG"
fi

printf 'Waiting for device (adb wait-for-device)...\n'
"$ADB" wait-for-device

printf 'Polling sys.boot_completed (timeout %ss)...\n' "$BOOT_WAIT"
elapsed=0
until [ "$("$ADB" shell getprop sys.boot_completed 2>/dev/null | tr -d '[:space:]')" = "1" ]; do
    sleep 5
    elapsed=$((elapsed + 5))
    if [ "$elapsed" -ge "$BOOT_WAIT" ]; then
        fail "device did not finish booting within ${BOOT_WAIT}s (see $BOOT_LOG)"
    fi
done
printf 'Boot completed after ~%ss\n' "$elapsed"
"$ADB" devices

# --- Step 3: install ----------------------------------------------------------
log "Step 3/4: install APK"
"$ADB" install -r "$APK"

# --- Step 4: launch -----------------------------------------------------------
log "Step 4/4: launch app"
PKG="$("$AAPT" dump badging "$APK" | sed -n "s/^package: name='\([^']*\)'.*/\1/p" | head -1)"
[ -n "$PKG" ] || fail "could not read package name from $APK"

# The Telegram manifest exposes its launcher via activity-alias entries which
# aapt's launchable-activity heuristic does not report; ask the device to
# resolve the LAUNCHER intent instead, with monkey as the last fallback.
COMPONENT="$("$ADB" shell cmd package resolve-activity --brief \
    -c android.intent.category.LAUNCHER "$PKG" 2>/dev/null | tail -1 | tr -d '[:space:]')"
if [ -n "$COMPONENT" ] && printf '%s' "$COMPONENT" | grep -q '/'; then
    printf 'package=%s component=%s (device-resolved)\n' "$PKG" "$COMPONENT"
    "$ADB" shell am start -n "$COMPONENT"
else
    printf 'package=%s (monkey launcher-intent fallback)\n' "$PKG"
    "$ADB" shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1
fi
sleep 5
PID="$("$ADB" shell "pidof $PKG" 2>/dev/null | tr -d '[:space:]')"
if [ -n "$PID" ]; then
    printf 'App process is running (pid %s)\n' "$PID"
else
    printf 'WARNING: app pid not found — check: adb logcat -d | tail\n' >&2
    exit 1
fi

log "launch_emulator.sh OK (device: $("$ADB" devices | sed -n 2p))"
