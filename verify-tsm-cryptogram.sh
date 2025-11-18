#!/bin/bash
# Verify TSM + CRYPTOGRAM Integration

PROJECT_ROOT="/home/user/CRYPTOGRAM"
TSM_ROOT="$PROJECT_ROOT/Telegram/lib_tsm"
TSM_VENV="$TSM_ROOT/venv"
BUILD_DIR="$PROJECT_ROOT/build_release"

echo "TSM + CRYPTOGRAM Verification Checklist"
echo "========================================"
echo ""

# TSM checks
echo "TSM Checks:"
if [ -d "$TSM_VENV" ]; then
    echo "  ✓ TSM virtual environment exists"
else
    echo "  ✗ TSM virtual environment missing"
fi

if [ -f "$TSM_ROOT/requirements.txt" ]; then
    echo "  ✓ TSM requirements file found"
fi

if [ -d "$TSM_ROOT/config" ]; then
    echo "  ✓ TSM config directory exists"
fi

if [ -f "$TSM_ROOT/config/tsm.yaml" ]; then
    echo "  ✓ TSM configuration created"
fi

# CRYPTOGRAM checks
echo ""
echo "CRYPTOGRAM Checks:"
if [ -d "$BUILD_DIR" ]; then
    echo "  ✓ Build directory exists"
else
    echo "  ✗ Build directory missing"
fi

if [ -f "$BUILD_DIR/CMakeCache.txt" ]; then
    echo "  ✓ CMake configured"
fi

if [ -f "$BUILD_DIR/bin/Telegram" ] || [ -f "$BUILD_DIR/Telegram/Telegram" ]; then
    echo "  ✓ CRYPTOGRAM executable found"
    if [ -f "$BUILD_DIR/bin/Telegram" ]; then
        echo "    Location: $BUILD_DIR/bin/Telegram"
    else
        echo "    Location: $BUILD_DIR/Telegram/Telegram"
    fi
else
    echo "  ✗ CRYPTOGRAM executable not found"
fi

# Integration checks
echo ""
echo "Integration Checks:"
if [ -f "$PROJECT_ROOT/.tsm_cryptogram_env.sh" ]; then
    echo "  ✓ Integration environment script exists"
fi

if [ -f "$PROJECT_ROOT/start-integrated-system.sh" ]; then
    echo "  ✓ System startup script exists"
fi

if [ -d "$TSM_ROOT/Telegram/lib_tsm" ]; then
    echo "  ✓ TSM integrated as submodule"
fi

# Python checks
echo ""
echo "Python Environment:"
if [ -f "$TSM_VENV/bin/python" ]; then
    echo "  ✓ Python environment active"
    "$TSM_VENV/bin/python" --version
fi

if [ -f "$TSM_VENV/bin/pip" ]; then
    GRPC_CHECK=$("$TSM_VENV/bin/pip" list 2>/dev/null | grep -i grpc || echo "")
    if [ -n "$GRPC_CHECK" ]; then
        echo "  ✓ gRPC installed"
    fi
fi

echo ""
echo "Next Steps:"
echo "  1. Load environment: source $PROJECT_ROOT/.tsm_cryptogram_env.sh"
echo "  2. Start system: $PROJECT_ROOT/start-integrated-system.sh"
echo "  3. Or manually:"
echo "     - TSM: cd $TSM_ROOT && python -m mock_server.server"
echo "     - CRYPTOGRAM: $BUILD_DIR/bin/Telegram (or Telegram/Telegram)"
