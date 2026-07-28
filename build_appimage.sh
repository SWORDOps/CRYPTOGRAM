#!/bin/bash
set -euo pipefail

APPIMAGE_NAME="${APPIMAGE_NAME:-CRYPTOGRAM-Linux-x86_64.AppImage}"
LINUXDEPLOY="${LINUXDEPLOY:-./linuxdeploy-x86_64.AppImage}"
APPIMAGETOOL="${APPIMAGETOOL:-./appimagetool-x86_64.AppImage}"

export APPIMAGE_EXTRACT_AND_RUN="${APPIMAGE_EXTRACT_AND_RUN:-1}"

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

rm -rf AppDir
mkdir -p AppDir/usr/bin
mkdir -p AppDir/usr/share/applications
mkdir -p AppDir/usr/share/icons/hicolor/256x256/apps

cp "$BINARY" AppDir/usr/bin/cryptogram
chmod +x AppDir/usr/bin/cryptogram

cat > AppDir/AppRun <<'APPRUN'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
export LD_LIBRARY_PATH="$HERE/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export QT_PLUGIN_PATH="$HERE/usr/plugins${QT_PLUGIN_PATH:+:$QT_PLUGIN_PATH}"
exec "$HERE/usr/bin/cryptogram" "$@"
APPRUN
chmod +x AppDir/AppRun

cat > AppDir/usr/share/applications/cryptogram.desktop <<'DESKTOP'
[Desktop Entry]
Name=CRYPTOGRAM
Comment=Military-Grade Secure Messaging Client
Exec=cryptogram
Icon=cryptogram
Type=Application
Categories=Network;InstantMessaging;Security;
Terminal=false
StartupWMClass=CRYPTOGRAM
DESKTOP

cp Telegram/Resources/art/icon256.png AppDir/usr/share/icons/hicolor/256x256/apps/cryptogram.png

if [ ! -x "$LINUXDEPLOY" ]; then
  wget -c "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage" -O "$LINUXDEPLOY"
  chmod +x "$LINUXDEPLOY"
fi

if [ ! -x "$APPIMAGETOOL" ]; then
  wget -c "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage" -O "$APPIMAGETOOL"
  chmod +x "$APPIMAGETOOL"
fi

"$LINUXDEPLOY" --appdir AppDir

QT_PLUGIN_DIR="$(qtpaths6 --plugin-dir)"
mkdir -p AppDir/usr/plugins
for plugin_dir in \
  platforms \
  imageformats \
  iconengines \
  platformthemes \
  wayland-shell-integration \
  wayland-decoration-client \
  wayland-graphics-integration-client; do
  if [ -d "$QT_PLUGIN_DIR/$plugin_dir" ]; then
    cp -a "$QT_PLUGIN_DIR/$plugin_dir" AppDir/usr/plugins/
  fi
done

if [ ! -e AppDir/cryptogram.desktop ]; then
  cp AppDir/usr/share/applications/cryptogram.desktop AppDir/cryptogram.desktop
fi
if [ ! -e AppDir/cryptogram.png ]; then
  cp AppDir/usr/share/icons/hicolor/256x256/apps/cryptogram.png AppDir/cryptogram.png
fi

"$APPIMAGETOOL" -n AppDir "$APPIMAGE_NAME"
"./$APPIMAGE_NAME" --appimage-help >/dev/null
ls -lh "$APPIMAGE_NAME"
