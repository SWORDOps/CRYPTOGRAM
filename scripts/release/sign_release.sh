#!/usr/bin/env bash
# sign_release.sh — one-command signing ceremony for a full CRYPTOGRAM
# release: APK (YubiKey PIV slot 9c via ykcs11), .deb (OpenPGP app),
# SHA256SUMS (OpenPGP clear-signed). Keys never leave the tokens.
#
# Usage:
#   scripts/release/sign_release.sh artifacts/cryptogram_1.2.5_afat_release_unsigned.apk \
#                                   artifacts/cryptogram_1.2.5_amd64.deb
#
# Environment:
#   SIGN_PIN        YubiKey PIV PIN (interactive prompt if unset)
#   SIGN_GPG_KEY    OpenPGP signing key fingerprint (default: first secret key)
#   YKCS11_MODULE   ykcs11 module path (default /usr/lib/x86_64-linux-gnu/libykcs11.so)

set -euo pipefail

[ $# -ge 1 ] || { echo "usage: sign_release.sh <unsigned.apk> <package.deb>" >&2; exit 1; }
IN_APK="$1"; IN_DEB="$2"
DIR="$(cd "$(dirname "$0")" && pwd)"

for f in "$IN_APK" "$IN_DEB"; do
    [ -f "$f" ] || { echo "ERROR: $f not found" >&2; exit 1; }
done

command -v apksigner >/dev/null || { echo "ERROR: apksigner not found (Android build-tools)" >&2; exit 1; }
command -v gpg >/dev/null || { echo "ERROR: gpg not found" >&2; exit 1; }
[ -f "${YKCS11_MODULE:-/usr/lib/x86_64-linux-gnu/libykcs11.so}" ] || {
    echo "ERROR: ykcs11 module not found — sudo apt install ykcs11" >&2; exit 1; }

echo "── CRYPTOGRAM release signing ceremony ──────────────────────────"
echo "YubiKey must be plugged in. PIN/touch prompts follow."

# 1. APK — YubiKey PIV slot 9c (see docs/RELEASE_SIGNING.md §1)
"$DIR/sign_apk.sh" "$IN_APK"

# 2. .deb + checksums — OpenPGP app (see docs/RELEASE_SIGNING.md §2)
"$DIR/sign_deb.sh" "$IN_DEB"

SUMS="$(dirname "$IN_DEB")/SHA256SUMS.txt"
if [ -f "$SUMS" ]; then
    gpg --batch --yes --local-user "${SIGN_GPG_KEY:-}" \
        --output "$SUMS.asc" --clear-sign "$SUMS"
    echo "  clear-signed $SUMS.asc"
fi

echo "── Release signing complete ──────────────────────────────────────"
echo "Upload alongside the artifacts:"
echo "  $OUT_APK"
echo "  $IN_DEB.sig"
echo "  $SUMS ( + $SUMS.asc )"
