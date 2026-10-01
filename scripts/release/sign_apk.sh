#!/usr/bin/env bash
# sign_apk.sh — sign a CRYPTOGRAM release APK with the FIPS YubiKey (PIV).
#
# The signing key is non-exportable: it lives in PIV slot 9c (Digital
# Signature) and apksigner reaches it through the Yubico PKCS#11 module.
# Nothing secret ever touches disk.
#
# One-time provisioning (see docs/RELEASE_SIGNING.md):
#   yubico-piv-tool -a generate -k -s 9c -A RSA2048 -o pubkey.pem
#   yubico-piv-tool -a selfsign -k -s 9c -S "/CN=CRYPTOGRAM Release/" \
#       -i pubkey.pem -o cert.pem --valid-days 3650
#   yubico-piv-tool -a import-certificate -s 9c -i cert.pem
#
# Usage:
#   scripts/release/sign_apk.sh <unsigned.apk> [signed.apk]
#
# Environment:
#   YKCS11_MODULE   path to the PKCS#11 module
#                   (default /usr/lib/x86_64-linux-gnu/ykcs11.so)
#   SIGN_PIN        PIV user PIN; if unset the script prompts (never store it)

set -euo pipefail

IN_APK="${1:?usage: sign_apk.sh <unsigned.apk> [signed.apk]}"
OUT_APK="${2:-${IN_APK%.apk}_signed.apk}"
MODULE="${YKCS11_MODULE:-/usr/lib/x86_64-linux-gnu/ykcs11.so}"
ALIAS="${SIGN_ALIAS:-CRYPTOGRAM Release}"

[ -f "$IN_APK" ] || { echo "ERROR: $IN_APK not found" >&2; exit 1; }
[ -f "$MODULE" ] || { echo "ERROR: PKCS#11 module not found: $MODULE
Install: sudo apt install ykcs11  (or libykcs11-1)" >&2; exit 1; }
command -v apksigner >/dev/null || { echo "ERROR: apksigner not found
Install: sudo apt install apksigner  (or use the Android SDK build-tools)" >&2; exit 1; }

# Touch+PIN: confirm the YubiKey is present before asking for the PIN.
if command -v yubico-piv-tool >/dev/null; then
    yubico-piv-tool -a status >/dev/null 2>&1 || {
        echo "ERROR: no YubiKey detected (plug it in)" >&2; exit 1; }
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# SunPKCS11 provider config; PIN is supplied interactively unless provided.
CFG="$WORKDIR/pkcs11.cfg"
{
    echo "library = $MODULE"
    echo "name = YubiKeyPIV"
    echo "slotListIndex = 0"
    if [ -n "${SIGN_PIN:-}" ]; then
        echo "pin = $SIGN_PIN"
    fi
} > "$CFG"

echo "Signing $IN_APK with YubiKey PIV slot 9c ..."
# --ks NONE + --ks-type PKCS11: keystore IS the token; apksigner prompts
# for the PIN if the cfg carries none.
apksigner sign \
    --ks NONE \
    --ks-type PKCS11 \
    --ks-provider-class sun.security.pkcs11.SunPKCS11 \
    --ks-provider-arg "$CFG" \
    --ks-key-alias "$ALIAS" \
    --v1-signing-enabled true \
    --v2-signing-enabled true \
    --out "$OUT_APK" \
    "$IN_APK"

echo "Verifying signature ..."
apksigner verify --print-certs "$OUT_APK"

echo "SHA-256 (signed):"
sha256sum "$OUT_APK"
echo "OK: $OUT_APK"
