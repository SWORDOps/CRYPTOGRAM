#!/bin/bash
set -e
VERSION=$(grep -oP 'AppVersion \K\S+' Telegram/build/version || echo "1.0.0")
echo "Version: $VERSION"

BINARY=""
for candidate in \
  build_release/bin/Telegram \
  build_Release/bin/Telegram \
  build_release/Telegram \
  build_Release/Telegram \
  build_debug/bin/Telegram \
  build_Debug/bin/Telegram \
  out/Release/Telegram \
  out/Debug/Telegram; do
  if [ -f "$candidate" ]; then
    BINARY="$candidate"
    break
  fi
done

if [ -z "$BINARY" ]; then
  echo "Searching for Telegram binary..."
  BINARY=$(find . -name "Telegram" -type f -executable 2>/dev/null | head -1)
fi

if [ -z "$BINARY" ]; then
  echo "No binary found after build"
  exit 1
fi

ARCH=$(dpkg --print-architecture)
PKGDIR="artifacts/cryptogram_${VERSION}_${ARCH}"

mkdir -p "$PKGDIR/usr/local/bin"
mkdir -p "$PKGDIR/usr/local/share/applications"
mkdir -p "$PKGDIR/usr/local/share/icons/hicolor/256x256/apps"
mkdir -p "$PKGDIR/DEBIAN"

cp "$BINARY" "$PKGDIR/usr/local/bin/cryptogram"
chmod +x "$PKGDIR/usr/local/bin/cryptogram"

cat > "$PKGDIR/usr/local/share/applications/cryptogram.desktop" << 'DESKTOP'
[Desktop Entry]
Name=CRYPTOGRAM
Comment=Military-Grade Secure Messaging Client
Exec=/usr/local/bin/cryptogram
Icon=cryptogram
Type=Application
Categories=Network;InstantMessaging;Security;
Terminal=false
StartupWMClass=CRYPTOGRAM
DESKTOP

cat > "$PKGDIR/DEBIAN/control" << CONTROL
Package: cryptogram
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: CRYPTOGRAM <noreply@cryptogram.dev>
Description: CRYPTOGRAM Secure Messaging Client
 CRYPTOGRAM is a military-grade secure messaging application
 featuring Signal Protocol (Double Ratchet), MLS (RFC 9420),
 voice morphing, surveillance detection, and Tor integration.
Depends: libqt6core6, libqt6gui6, libqt6widgets6, libqt6network6, libssl3, libopenal1, libpulse0
Section: net
Priority: optional
CONTROL

cat > "$PKGDIR/DEBIAN/postinst" << 'POSTINST'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q /usr/local/share/applications
fi
POSTINST
chmod 755 "$PKGDIR/DEBIAN/postinst"

cat > "$PKGDIR/DEBIAN/prerm" << 'PRERM'
#!/bin/sh
set -e
PRERM
chmod 755 "$PKGDIR/DEBIAN/prerm"

cd artifacts
dpkg-deb --build "cryptogram_${VERSION}_${ARCH}"
ls -lh *.deb
