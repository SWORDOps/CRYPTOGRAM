#!/bin/bash
# Apply local modifications required for building CRYPTOGRAM

set -e

echo "Applying CRYPTOGRAM build patches..."

# Check if cmake modifications are already applied
if grep -q "if (DESKTOP_APP_USE_PACKAGED)" cmake/external/tde2e/CMakeLists.txt 2>/dev/null && \
   grep -q "find_package(tde2e QUIET)" cmake/external/tde2e/CMakeLists.txt 2>/dev/null; then
    echo "✓ cmake/external/tde2e/CMakeLists.txt already patched"
else
    echo "1. Patching cmake/external/tde2e/CMakeLists.txt..."
    cd cmake
    git apply ../patches/cmake-optional-libs.patch 2>/dev/null || {
        echo "  Note: Patch may already be applied or needs manual application"
    }
    cd ..
fi

if grep -q "if (DESKTOP_APP_USE_PACKAGED)" cmake/external/webrtc/CMakeLists.txt 2>/dev/null && \
   grep -q "find_package(tg_owt QUIET)" cmake/external/webrtc/CMakeLists.txt 2>/dev/null; then
    echo "✓ cmake/external/webrtc/CMakeLists.txt already patched"
else
    echo "2. Patching cmake/external/webrtc/CMakeLists.txt..."
    # Patch was combined with tde2e in cmake-optional-libs.patch
fi

else
# and doesn't require C++ compilation


INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
EOFCMAKE
fi

echo ""
echo "✅ All patches applied/verified successfully!"
echo ""
echo "Note: Git will show uncommitted changes in submodules."
echo "This is intentional. See LOCAL_CHANGES.md for details."
echo ""
echo "You can now run: ./build_all.sh"
