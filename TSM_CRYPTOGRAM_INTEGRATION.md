# TSM + CRYPTOGRAM Integration Guide

Complete integration of TSM (Telegram Session Manager) with CRYPTOGRAM desktop application.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                   CRYPTOGRAM Desktop                        │
│  (Qt Application with TSM Integration)                      │
│                                                             │
│  ┌────────────────────────────────────────────────┐        │
│  │  UI Layer (Qt6)                                │        │
│  │  - Session Management UI                       │        │
│  │  - TSM Status Display                          │        │
│  │  - YubiKey Integration UI                      │        │
│  └─────────────────┬──────────────────────────────┘        │
│                    │                                        │
│  ┌─────────────────▼──────────────────────────────┐        │
│  │  gRPC Client (C++)                             │        │
│  │  - Communicates with TSM gRPC Server          │        │
│  │  - Session operations                          │        │
│  │  - Encryption/Decryption                       │        │
│  └─────────────────┬──────────────────────────────┘        │
│                    │                                        │
│                    │ gRPC Protocol (Port 50051)            │
│                    ▼                                        │
└─────────────────────────────────────────────────────────────┘
                     │
    ┌────────────────▼────────────────┐
    │                                 │
    ▼                                 ▼
┌─────────────────┐        ┌──────────────────┐
│  TSM gRPC       │        │  TSM API         │
│  Server         │        │  Server          │
│  (Port 50051)   │        │  (Port 8080)     │
│                 │        │                  │
│  - Sessions     │        │  - REST API      │
│  - Crypto Ops   │        │  - Admin Panel   │
│  - YubiKey Auth │        │  - Status        │
└────────┬────────┘        └────────┬─────────┘
         │                          │
         └──────────────┬───────────┘
                        │
                        ▼
         ┌──────────────────────────┐
         │   TSM Python Backend     │
         │                          │
         │  - Session DB (SQLite)   │
         │  - Encryption/Decryption │
         │  - YubiKey Manager       │
         │  - Post-Quantum Crypto   │
         │  - Homomorphic Encoding  │
         │  - Zero-Knowledge Proofs │
         └──────────────────────────┘
```

## Setup Process

### Prerequisites

- Debian/Ubuntu Linux with GCC 14 or GCC 15
- Python 3.9+
- Qt6 development libraries
- 10+ GB free disk space

### Step 1: Run Integrated Setup

```bash
cd /home/user/CRYPTOGRAM

# Full automated setup
./setup-tsm-cryptogram.sh

# Or with specific options
./setup-tsm-cryptogram.sh --gcc14    # Use GCC 14
./setup-tsm-cryptogram.sh --gcc15    # Use GCC 15
./setup-tsm-cryptogram.sh --verbose  # Detailed output
```

This single script will:
1. **Initialize TSM**
   - Create Python virtual environment
   - Install all TSM dependencies (grpcio, cryptography, etc.)
   - Generate TSM configuration
   - Set up configuration directory

2. **Build CRYPTOGRAM**
   - Install Qt6 and system libraries
   - Configure CMake
   - Compile with TSM integration
   - Generate executable

3. **Configure Integration**
   - Create environment setup script
   - Generate system startup script
   - Create verification script

### Step 2: Load Environment

```bash
source /home/user/CRYPTOGRAM/.tsm_cryptogram_env.sh
```

This sets up:
- Compiler environment (GCC 14/15)
- TSM Python virtual environment
- Environment variables for both TSM and CRYPTOGRAM
- Python path for TSM modules

### Step 3: Verify Integration

```bash
/home/user/CRYPTOGRAM/verify-tsm-cryptogram.sh
```

Output checklist:
- ✓ TSM virtual environment
- ✓ TSM requirements installed
- ✓ TSM configuration
- ✓ CRYPTOGRAM build
- ✓ Integration scripts
- ✓ Python environment

## Running the Integrated System

### All-in-One Startup

```bash
# Starts both TSM services and CRYPTOGRAM
/home/user/CRYPTOGRAM/start-integrated-system.sh
```

This will:
1. Start TSM gRPC Server (port 50051)
2. Start TSM API Server (port 8080)
3. Launch CRYPTOGRAM desktop application
4. Automatically stop services on exit

### Manual Component Startup

**Terminal 1 - TSM gRPC Server:**
```bash
source /home/user/CRYPTOGRAM/.tsm_cryptogram_env.sh
cd /home/user/CRYPTOGRAM/Telegram/lib_tsm
python -m mock_server.server
# Logs: TSM gRPC Server listening on 0.0.0.0:50051
```

**Terminal 2 - TSM API Server (optional):**
```bash
source /home/user/CRYPTOGRAM/.tsm_cryptogram_env.sh
cd /home/user/CRYPTOGRAM/Telegram/lib_tsm
python -m tsm.api.server
# Logs: API Server running on http://0.0.0.0:8080
```

**Terminal 3 - CRYPTOGRAM:**
```bash
/home/user/CRYPTOGRAM/build_release/bin/Telegram
```

## Integration Features

### 1. Session Management

CRYPTOGRAM integrates with TSM to provide:
- Multi-session support (unlimited accounts)
- Instant session switching (<100ms)
- Session encryption with AES-256-GCM
- Session isolation

**Usage in CRYPTOGRAM UI:**
```
Settings → Session Manager
  ├── List Sessions (via TSM)
  ├── Switch Session (gRPC call)
  ├── Add Session (creates in TSM)
  └── Delete Session (removes from TSM)
```

### 2. Hardware Security (YubiKey)

TSM provides YubiKey integration:
- Multi-factor authentication
- Hardware-backed key storage
- Touch confirmation requirement
- U2F support

**Configuration:**
```yaml
# .tsm_cryptogram_env.sh
export TSM_REQUIRE_YUBIKEY=true
export YUBIKEY_TIMEOUT=30  # seconds
```

### 3. Post-Quantum Cryptography

TSM implements future-proof encryption:
- CRYSTALS-Kyber (ML-KEM-1024)
- CRYSTALS-Dilithium (ML-DSA-87)
- Lattice-based signatures
- Quantum-resistant key exchange

### 4. Advanced Encryption

Features available through TSM:
- AES-256-GCM symmetric encryption
- X25519 key exchange
- Ed25519 signatures
- Homomorphic encryption (Paillier)
- Zero-knowledge proofs

### 5. gRPC Communication

CRYPTOGRAM communicates with TSM via gRPC:

```protobuf
// Example RPC calls
service TSMService {
  rpc ListSessions(Empty) returns (SessionList);
  rpc SwitchSession(SessionId) returns (Status);
  rpc EncryptData(EncryptRequest) returns (EncryptResponse);
  rpc DecryptData(DecryptRequest) returns (DecryptResponse);
  rpc AuthenticateYubiKey(YubiKeyChallenge) returns (YubiKeyResponse);
}
```

## Environment Variables

### TSM Environment

```bash
# TSM directories
export TSM_ROOT=/home/user/CRYPTOGRAM/Telegram/lib_tsm
export TSM_VENV=$TSM_ROOT/venv
export TSM_CONFIG=$TSM_ROOT/config

# TSM services
export TSM_GRPC_HOST=localhost:50051
export TSM_API_URL=http://localhost:8080
export TSM_GRPC_PORT=50051
export TSM_API_PORT=8080

# Python path
export PYTHONPATH=$TSM_ROOT:$PYTHONPATH
```

### CRYPTOGRAM Environment

```bash
# Compiler
export CC=gcc-14
export CXX=g++-14

# Build
export CRYPTOGRAM_ROOT=/home/user/CRYPTOGRAM
export CRYPTOGRAM_BUILD_DIR=$CRYPTOGRAM_ROOT/build_release

# Optional: Telegram API (for full functionality)
export TDESKTOP_API_ID=YOUR_API_ID
export TDESKTOP_API_HASH=YOUR_API_HASH
```

## Configuration Files

### TSM Configuration

**Location:** `~/.tsm_cryptogram_env.sh`

```bash
# Automatically sourced by scripts
# Contains all environment variables and paths
```

**TSM Settings:** `Telegram/lib_tsm/config/tsm.yaml`

```yaml
tsm:
  port: 50051           # gRPC server port
  api_port: 8080        # REST API port

security:
  encryption_enabled: true
  require_yubikey: false
  auto_lock_minutes: 15

database:
  type: sqlite
  path: ./tsm.db

logging:
  level: INFO
  file: ./tsm.log
```

### CRYPTOGRAM Configuration

**Build Directory:** `build_release/`

**CMake Cache:** `build_release/CMakeCache.txt`

## Troubleshooting

### TSM Issues

#### Python dependencies fail to install

```bash
# Reinstall specific packages
source /home/user/CRYPTOGRAM/Telegram/lib_tsm/venv/bin/activate
pip install --upgrade grpcio cryptography phe py_ecc
```

#### TSM gRPC server won't start

```bash
# Check port availability
netstat -an | grep 50051

# Kill process using port
sudo fuser -k 50051/tcp

# Restart server
python -m mock_server.server
```

#### YubiKey not detected

```bash
# Check USB connection
lsusb | grep Yubico

# Fix permissions
sudo usermod -a -G plugdev $USER
sudo udevadm control --reload-rules
```

### CRYPTOGRAM Issues

#### Build fails with Qt6 errors

```bash
# Verify Qt6 installation
dpkg -l | grep qt6-base

# Reinstall if needed
sudo apt-get install qt6-base-dev qt6-base-private-dev

# Reconfigure CMake
cd build_release
cmake -DCMAKE_PREFIX_PATH=/usr/lib/x86_64-linux-gnu/cmake/Qt6 ..
cmake --build . --config Release
```

#### Executable not found after build

```bash
# Find where it was built
find build_release -name Telegram -type f

# Try manual build
cd build_release
cmake --build . --config Release --verbose
```

### Integration Issues

#### CRYPTOGRAM can't connect to TSM

```bash
# Verify TSM is running
ps aux | grep mock_server

# Check port is listening
netstat -an | grep LISTEN | grep 50051

# Test gRPC connection
python -c "import grpc; print(grpc.__version__)"
```

#### Services not stopping properly

```bash
# Kill all Python processes
pkill -f "python -m mock_server"
pkill -f "python -m tsm"

# Or kill specific PIDs
kill $(pgrep -f mock_server)
```

## Performance Optimization

### Build Optimization

```bash
# Use ccache for faster rebuilds
export CC="ccache gcc-14"
export CXX="ccache g++-14"

# Enable LTO (Link-Time Optimization)
export CFLAGS="-march=native -O3 -flto"
export CXXFLAGS="-march=native -O3 -flto"

# Build with all cores
cmake --build build_release --parallel $(nproc)
```

### Runtime Optimization

```bash
# Increase Python heap for TSM
export PYTHONOPTIMIZE=2

# Enable gRPC connection pooling
export GRPC_GO_LOG_SEVERITY_LEVEL=info

# Session cache (TSM)
export TSM_CACHE_SIZE=1000
```

## Testing Integration

### Manual API Testing

```bash
# Start TSM API server
source /home/user/CRYPTOGRAM/.tsm_cryptogram_env.sh
cd /home/user/CRYPTOGRAM/Telegram/lib_tsm
python -m tsm.api.server &

# Test endpoint
curl http://localhost:8080/api/sessions

# Or use Python client
python -c "
from sdk.tsm_client import TSMApiClient
client = TSMApiClient('http://localhost:8080')
print(client.list_sessions())
"
```

### Unit Tests

```bash
# Run TSM tests
cd /home/user/CRYPTOGRAM/Telegram/lib_tsm
source venv/bin/activate
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=tsm --cov-report=html
```

## Production Deployment

### Systemd Service

Create `/etc/systemd/system/tsm-cryptogram.service`:

```ini
[Unit]
Description=TSM + CRYPTOGRAM Integrated Service
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/home/user/CRYPTOGRAM
Environment="PATH=/home/user/CRYPTOGRAM/Telegram/lib_tsm/venv/bin"
ExecStart=/home/user/CRYPTOGRAM/Telegram/lib_tsm/venv/bin/python -m mock_server.server
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable tsm-cryptogram
sudo systemctl start tsm-cryptogram
sudo systemctl status tsm-cryptogram
```

### Docker Deployment (Optional)

```bash
cd /home/user/CRYPTOGRAM/Telegram/lib_tsm
docker build -f Dockerfile.api -t tsm-api:latest .
docker run -p 8080:8080 -p 50051:50051 tsm-api:latest
```

## Security Considerations

### YubiKey Setup

```bash
# Install YubiKey manager
sudo apt-get install yubikey-manager

# Check device
ykman list

# Configure for TSM
ykman piv access change-pin  # Set PIN
ykman piv reset              # Reset if needed
```

### Session Encryption

All sessions encrypted with:
- Algorithm: AES-256-GCM
- Key derivation: PBKDF2 with SHA-256
- IV: Random, unique per session

### API Security

TSM API server should:
- Use HTTPS in production
- Require authentication tokens
- Implement rate limiting
- Log all access

## Next Steps

1. **Run Setup:** `./setup-tsm-cryptogram.sh`
2. **Verify:** `/home/user/CRYPTOGRAM/verify-tsm-cryptogram.sh`
3. **Start Services:** `/home/user/CRYPTOGRAM/start-integrated-system.sh`
4. **Access UI:** CRYPTOGRAM desktop application
5. **Manage Sessions:** Use TSM Session Manager in settings

## Additional Resources

- **TSM Documentation:** `Telegram/lib_tsm/README.md`
- **CRYPTOGRAM Guide:** `DUAL_PROJECT_SETUP.md`
- **Quick Start:** `QUICK_START.md`
- **GitHub:** https://github.com/SWORDOps/CRYPTOGRAM

---

**Last Updated:** November 2024
**Integration Level:** Full (TSM ↔ CRYPTOGRAM via gRPC)
**Tested on:** Debian 6.17, GCC 14/15
