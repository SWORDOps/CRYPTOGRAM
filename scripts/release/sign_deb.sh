#!/usr/bin/env bash
# sign_deb.sh — detached OpenPGP signature for a CRYPTOGRAM .deb, using the
# OpenPGP smartcard app of the YubiKey (signing subkey on the card; the
# secret material never leaves the token).
#
# One-time provisioning (see docs/RELEASE_SIGNING.md §2): create/move an
# OpenPGP signing subkey onto the YubiKey (keytocard, signature slot).
#
# Usage:
#   scripts/release/sign_deb.sh <package.deb> [more.deb ...]
#
# Environment:
#   SIGN_GPG_KEY    fingerprint of the signing (sub)key; default = first
#                   secret key found (gpg --list-secret-keys)

set -euo pipefail

[ $# -ge 1 ] || { echo "usage: sign_deb.sh <package.deb> [more.deb ...]" >&2; exit 1; }
command -v gpg >/dev/null || { echo "ERROR: gpg not found" >&2; exit 1; }

KEY="${SIGN_GPG_KEY:-}"
if [ -z "$KEY" ]; then
    KEY="$(gpg --list-secret-keys --with-colons 2>/dev/null \
        | awk -F: '/^sec/{print $5; exit}')"
fi
[ -n "$KEY" ] || { echo "ERROR: no secret key found in keyring" >&2; exit 1; }

# Card presence check — fails with a clear message if the YubiKey is absent.
if command -v gpg-card >/dev/null; then
    gpg-card status 2>/dev/null | grep -qi "reader" || {
        echo "ERROR: no OpenPGP card detected (plug in the YubiKey)" >&2; exit 1; }
fi

for pkg in "$@"; do
    [ -f "$pkg" ] || { echo "ERROR: $pkg not found" >&2; exit 1; }
    echo "Signing $pkg with key $KEY ..."
    gpg --batch --yes --local-user "$KEY" \
        --output "$pkg.sig" --detach-sign --armor "$pkg"
    echo "  wrote $pkg.sig"
done

echo "SHA-256 (signed artifacts):"
sha256sum "$@"
echo "Verify later:  gpg --verify <pkg>.sig <pkg>"
