#!/bin/bash
# TSM + CRYPTOGRAM Integration Environment

# Compiler
export CC=gcc-14
export CXX=g++-14

# Paths
export CRYPTOGRAM_ROOT="/home/user/CRYPTOGRAM"
export TSM_ROOT="$CRYPTOGRAM_ROOT/Telegram/lib_tsm"
export TSM_VENV="$TSM_ROOT/venv"
export TSM_CONFIG="$TSM_ROOT/config"

# TSM Services
export TSM_GRPC_PORT=50051
export TSM_API_PORT=8080
export TSM_GRPC_HOST="localhost:50051"
export TSM_API_URL="http://localhost:8080"

# Python path for TSM
export PYTHONPATH="$TSM_ROOT:$PYTHONPATH"

# Activate TSM venv if available
if [ -f "$TSM_VENV/bin/activate" ]; then
    source "$TSM_VENV/bin/activate"
fi

echo "TSM + CRYPTOGRAM Environment Loaded"
echo "  CRYPTOGRAM: $CRYPTOGRAM_ROOT"
echo "  TSM: $TSM_ROOT"
echo "  TSM gRPC: $TSM_GRPC_HOST"
echo "  TSM API: $TSM_API_URL"
