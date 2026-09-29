#!/usr/bin/env bash
#
# collect_logs.sh — capture wire-evidence logs for the live interop exchange.
#
# Captures into artifacts/interop-logs/:
#   desktop-log-tail.txt   tail of the desktop debug log (stderr capture or
#                          the newest file under ~/.local/share/Cryptogram)
#   logcat-cryptogram.txt  `adb logcat -d` filtered to the Cryptogram tags:
#                          CryptogramMessageHelper (Java, CryptogramMessageHelper.java)
#                          CryptogramNative      (JNI, CryptogramWrapper.cpp LOG_TAG)
#
# GUARDRAIL: artifacts/ may contain peer ids, phone numbers and session
# metadata. NEVER commit it. The directory is excluded from any git add made
# by the harness agents; treat these files as session data.
#
# Env overrides:
#   CRYPTOGRAM_DESKTOP_LOG  explicit desktop log file (overrides auto-detect)
#   CRYPTOGRAM_LOG_TAIL     tail line count   (default: 2000)
#   ANDROID_HOME / ADB      SDK paths

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
ADB="$ANDROID_HOME/platform-tools/adb"
[ -x "$ADB" ] || ADB="$(command -v adb)"
TAIL_N="${CRYPTOGRAM_LOG_TAIL:-2000}"

CRYPTOGRAM_DATA="$HOME/.local/share/Cryptogram"
LOG_DIR="$ROOT_DIR/artifacts/interop-logs"

log()  { printf '\n=== %s ===\n' "$*"; }

mkdir -p "$LOG_DIR"
printf 'Interop log capture %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$LOG_DIR/README.txt"
printf '%s\n' "GUARDRAIL: NEVER commit artifacts/ — logs may contain peer/phone/session data." >> "$LOG_DIR/README.txt"

# --- Desktop log --------------------------------------------------------------
log "Desktop debug log"
DESKTOP_LOG="${CRYPTOGRAM_DESKTOP_LOG:-}"
if [ -z "$DESKTOP_LOG" ]; then
    # Newest debug log wins: DebugLogs/log_*.txt (written with -debug), else log.txt
    DESKTOP_LOG="$(ls -t "$CRYPTOGRAM_DATA"/DebugLogs/log_*.txt 2>/dev/null | head -1 || true)"
    [ -n "$DESKTOP_LOG" ] || DESKTOP_LOG="$CRYPTOGRAM_DATA/log.txt"
fi
if [ -f "$DESKTOP_LOG" ]; then
    tail -n "$TAIL_N" "$DESKTOP_LOG" > "$LOG_DIR/desktop-log-tail.txt"
    printf 'source: %s\n' "$DESKTOP_LOG"
    printf 'captured %s lines -> %s\n' "$(wc -l < "$LOG_DIR/desktop-log-tail.txt")" \
        "$LOG_DIR/desktop-log-tail.txt"
else
    printf 'WARNING: no desktop log found.\n' | tee "$LOG_DIR/desktop-log-tail.txt"
    printf 'Start the desktop client with -debug and capture stderr, e.g.:\n' \
        | tee -a "$LOG_DIR/desktop-log-tail.txt"
    printf '  ./build_tests/bin/Telegram -platform offscreen -debug 2>&1 | tee desktop-stderr.log\n' \
        | tee -a "$LOG_DIR/desktop-log-tail.txt"
    printf 'then re-run with CRYPTOGRAM_DESKTOP_LOG=desktop-stderr.log\n' \
        | tee -a "$LOG_DIR/desktop-log-tail.txt"
fi

# --- Android logcat -------------------------------------------------------------
log "Android logcat (Cryptogram tags)"
if "$ADB" get-state 2>/dev/null | grep -q device; then
    # -s = silence everything except these tags (all priorities)
    "$ADB" logcat -d -v time -s CryptogramMessageHelper:V CryptogramNative:V \
        > "$LOG_DIR/logcat-cryptogram.txt" || true
    printf 'captured %s lines -> %s\n' "$(wc -l < "$LOG_DIR/logcat-cryptogram.txt")" \
        "$LOG_DIR/logcat-cryptogram.txt"
    if grep -qE 'beginning of|---------' "$LOG_DIR/logcat-cryptogram.txt" \
        && [ "$(grep -cv '^[^-]' "$LOG_DIR/logcat-cryptogram.txt" 2>/dev/null || true)" -gt 0 ]; then
        printf 'Cryptogram tag lines present.\n'
    fi
else
    printf 'WARNING: no adb device attached; logcat not captured.\n' \
        | tee "$LOG_DIR/logcat-cryptogram.txt"
fi

# --- Quick preview ---------------------------------------------------------------
log "Preview of matched Cryptogram lines"
if [ -f "$LOG_DIR/desktop-log-tail.txt" ]; then
    grep -E 'Signal Protocol|CRYPTOGRAM:' "$LOG_DIR/desktop-log-tail.txt" | tail -10 || true
fi
if [ -f "$LOG_DIR/logcat-cryptogram.txt" ]; then
    grep -E 'Encrypted message for user|Decrypted desktop envelope from user|Attached desktop key bundle|CryptogramNative' \
        "$LOG_DIR/logcat-cryptogram.txt" | tail -10 || true
fi

log "collect_logs.sh done — files under $LOG_DIR (never commit)"
