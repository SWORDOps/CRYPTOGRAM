#!/bin/bash
# Start TSM + CRYPTOGRAM Integrated System

PROJECT_ROOT="/home/user/CRYPTOGRAM"
TSM_ROOT="$PROJECT_ROOT/Telegram/lib_tsm"
TSM_VENV="$TSM_ROOT/venv"
BUILD_DIR="$PROJECT_ROOT/build_release"

# Load environment
source "$PROJECT_ROOT/.tsm_cryptogram_env.sh"

echo "Starting TSM + CRYPTOGRAM Integrated System..."
echo ""

# Start TSM gRPC server in background
echo "1. Starting TSM gRPC Server..."
cd "$TSM_ROOT"
python -m mock_server.server &
TSM_PID=$!
echo "   TSM Server PID: $TSM_PID"
sleep 2

# Start TSM API Server in background
echo "2. Starting TSM API Server..."
python -m tsm.api.server &
API_PID=$!
echo "   TSM API Server PID: $API_PID"
sleep 2

# Start CRYPTOGRAM
echo "3. Starting CRYPTOGRAM..."
if [ -f "$BUILD_DIR/bin/Telegram" ]; then
    "$BUILD_DIR/bin/Telegram"
elif [ -f "$BUILD_DIR/Telegram/Telegram" ]; then
    "$BUILD_DIR/Telegram/Telegram"
else
    echo "CRYPTOGRAM executable not found"
    echo "Build with: cd $BUILD_DIR && cmake --build . --config Release"
    exit 1
fi

# Cleanup on exit
trap "kill $TSM_PID $API_PID 2>/dev/null" EXIT
