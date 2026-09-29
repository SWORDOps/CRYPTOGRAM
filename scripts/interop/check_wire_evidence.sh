#!/usr/bin/env bash
#
# check_wire_evidence.sh <desktop-log> <logcat-file> [--apk <path>]
#
# Pure grep/sed evidence matrix for the desktop<->Android E2EE live exchange.
# For every step of the wire lifecycle it greps the captured logs for the
# expected POSITIVE evidence line and the known FAILURE lines and prints
# PASS / FAIL / PENDING / OK-ABSENT per row. No magic: the patterns below are
# the literal log strings from
#   Telegram/SourceFiles/data/data_signal_protocol.cpp   (desktop)
#   telegram-android/.../cryptogram/CryptogramMessageHelper.java (Android)
#
# Row states:
#   PASS       positive evidence line found
#   FAIL       a known failure line was found
#   OK-ABSENT  failure-only row: no failure line logged (positive proof still
#              requires the live exchange)
#   PENDING    neither found — step not reached yet. EXPECTED BEFORE THE
#              ONE-TIME HUMAN LOGINS (dry-run state); not a script failure.
#
# Exit code: 0 = no FAIL rows (PENDING allowed), 1 = any FAIL, 2 = usage/IO.
#
# Optional --apk enables the Path 1 (Android ML-KEM parity) gate used by the
# runbook's Scenario D: the APK's libcryptogram.so is scanned for KEM
# markers. PATH1-ABSENT => Scenario D rows are SKIPPED (expected today).

set -euo pipefail

usage() {
    printf 'usage: %s <desktop-log> <logcat-file> [--apk <path>]\n' "$0" >&2
    exit 2
}

[ $# -ge 2 ] || usage
DESKTOP_LOG="$1"; shift
LOGCAT_FILE="$1"; shift
APK=""

while [ $# -gt 0 ]; do
    case "$1" in
        --apk) APK="${2:-}"; shift 2 ;;
        *) usage ;;
    esac
done

[ -r "$DESKTOP_LOG" ] || { printf 'cannot read desktop log: %s\n' "$DESKTOP_LOG" >&2; exit 2; }
[ -r "$LOGCAT_FILE" ] || { printf 'cannot read logcat file: %s\n' "$LOGCAT_FILE" >&2; exit 2; }

# ---------------------------------------------------------------------------
# Path 1 (Android PQ parity) gate — grep the shipped .so for KEM markers.
# ---------------------------------------------------------------------------
PATH1="PATH1-MARKER:UNKNOWN"
if [ -n "$APK" ]; then
    if [ ! -r "$APK" ]; then
        printf 'cannot read apk: %s\n' "$APK" >&2; exit 2
    fi
    if unzip -p "$APK" lib/arm64-v8a/libcryptogram.so 2>/dev/null | strings \
        | grep -Eqi 'ml-kem|mlkem|kyber|kem-1024|pqe1'; then
        PATH1="PATH1-MERGED"
    else
        PATH1="PATH1-ABSENT"
    fi
fi

# ---------------------------------------------------------------------------
# Matrix rows: ID | state-if-positive | POS pattern | NEG pattern | scope
# Patterns are extended regexps over the literal source log strings.
# ---------------------------------------------------------------------------
TOTAL_PASS=0; TOTAL_FAIL=0

row() {
    local id="$1" label="$2" pos="$3" neg="$4" scope="$5"
    local pos_found=0 neg_found=0 state
    if [ -n "$pos" ]; then
        case "$scope" in
            desktop) grep -Eq "$pos" "$DESKTOP_LOG" && pos_found=1 || true ;;
            android) grep -Eq "$pos" "$LOGCAT_FILE" && pos_found=1 || true ;;
        esac
    fi
    if [ -n "$neg" ]; then
        case "$scope" in
            desktop) grep -Eq "$neg" "$DESKTOP_LOG" && neg_found=1 || true ;;
            android) grep -Eq "$neg" "$LOGCAT_FILE" && neg_found=1 || true ;;
        esac
    fi
    if [ "$neg_found" -eq 1 ]; then
        state="FAIL"
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
    elif [ "$pos_found" -eq 1 ]; then
        state="PASS"
        TOTAL_PASS=$((TOTAL_PASS + 1))
    elif [ -z "$pos" ]; then
        state="OK-ABSENT"
    else
        state="PENDING"
    fi
    printf '%-9s %-38s %s\n' "$state" "$id" "$label"
}

printf 'CRYPTOGRAM live-interop wire-evidence matrix\n'
printf 'desktop log : %s\n' "$DESKTOP_LOG"
printf 'logcat file : %s\n' "$LOGCAT_FILE"
printf 'Path 1 gate : %s%s\n' "$PATH1" \
    "${APK:+ (from $(basename "$APK"))}"
printf '%s\n' '---------------------------------------------------------------'

printf '\n[Desktop — data_signal_protocol.cpp via -debug stderr / tdata log]\n'
row "desktop.pq.identity" \
    "PQ KEM identity generated at startup" \
    'Signal Protocol \[PQ\]: generated KEM identity' \
    'QuantumGuard initialization failed' desktop
row "desktop.bundle.verify" \
    "incoming key-bundle signature failures" \
    '' \
    'Incoming key bundle signature verification failed|Key bundle signature verification failed' desktop
row "desktop.session.created" \
    "receiver-side session created for peer" \
    'Receiver-side session created for peer' \
    'Refusing (receiver-side )?session|Could not load signed pre-key' desktop
row "desktop.pq.failures" \
    "PQ wrap/unwrap failure lines" \
    '' \
    '\[PQ\]: (encapsulation failed|unwrap failed|no local KEM identity|peer key import failed)' desktop

printf '\n[Android — logcat tags CryptogramMessageHelper (Java), CryptogramNative (JNI)]\n'
row "android.bundle.attached" \
    "outgoing invisible key bundle attached" \
    'Attached desktop key bundle for user' \
    'Failed to generate desktop-format key bundle' android
row "android.decrypt.desktop" \
    "decrypted a desktop envelope" \
    'Decrypted desktop envelope from user' \
    'Failed to decrypt desktop envelope' android
row "android.encrypt.out" \
    "encrypted an outgoing message" \
    'Encrypted message for user' \
    'Encryption returned null|Failed to encrypt message' android
row "android.bundle.extract" \
    "incoming-bundle extraction failures" \
    '' \
    'Failed to extract incoming key bundles' android
row "android.native.layer" \
    "CryptogramNative JNI log activity" \
    'CryptogramNative' '' android

printf '%s\n' '---------------------------------------------------------------'
printf '%s\n' 'Notes:'
printf '%s\n' '  - PENDING rows are EXPECTED in a dry run: the two one-time account'
printf '%s\n' '    logins have not happened yet, so no wire traffic exists.'
printf '%s\n' '  - desktop.pq.identity PASS + desktop.pq.failures OK-ABSENT is the only'
printf '%s\n' '    PQ send-side evidence the current desktop code can emit: successful'
printf '%s\n' '    quantum wrap is silent (data_signal_protocol.cpp logs failures only).'
printf '%s\n' '  - Scenario D (PQ end-to-end) applies only if the gate says PATH1-MERGED;'
printf '%s\n' '    otherwise those rows are SKIPPED by the runbook, not failures.'
printf '%s\n' '  - android.native.layer is informational: the JNI LOGD/LOGE macros are'
printf '%s\n' '    defined in CryptogramWrapper.cpp but currently unused.'
printf '\nSummary: PASS=%s FAIL=%s (exit %s)\n' \
    "$TOTAL_PASS" "$TOTAL_FAIL" "$([ "$TOTAL_FAIL" -eq 0 ] && echo 0 || echo 1)"

[ "$TOTAL_FAIL" -eq 0 ]
