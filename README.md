## OPSEC VALIDATION NOTE

This document may contain historical implementation claims. Treat all security capabilities as **partial or experimental** unless corroborated by current runtime validation in `docs/status/FINAL_STATUS.md` and `docs/features/android-features.md`.

Desktop Linux claim gate and build-state source of truth:
`docs/status/DESKTOP_BUILD_ALIGNMENT.md`.

# 🔐 CRYPTOGRAM: Advanced OPSEC Messaging

## 🟡 Project Status: Partial/Experimental (Desktop + Android)

CRYPTOGRAM targets two platforms from a single repository:

- **Desktop (Linux)**: Qt-based client with full feature surface.
- **Android**: Telegram-Android fork with native CRYPTOGRAM JNI library (OpenSSL, Signal Protocol, MLS).

Both builds share the same core C++ cryptographic code via the `telegram-android/TMessagesProj/jni/cryptogram/` native layer, with Qt shims (`qt_shims.h`) providing cross-platform compatibility.

The desktop build is currently undergoing final stabilization and linkage.
The Android build uses a native shared library (`libcryptogram.so`) with JNI bridging to Kotlin/Java, providing Double Ratchet and MLS protocol support with persistent key storage. 

### Core Capabilities
- **Signal Protocol (1:1 E2EE)**: X3DH key exchange, Double Ratchet with forward secrecy and post-compromise security, AES-256-GCM authenticated encryption. Key bundles advertised via MTProto init params and zero-width message entities for transparent peer discovery.
- **MLS Protocol (Group E2EE)**: RFC 9420-style group key agreement using TreeKEM. MLS key packages advertised in MTProto init params. Group messages encrypted with `GroupEncryption` singleton; Welcome/Commit messages transported via zero-width message entities. Enables conversations visible only to CRYPTOGRAM users within a shared chat room.
- **Post-Quantum Security**: Native support for NIST-standardized PQC (Kyber/Dilithium) via **QuantumGuard**.
- **Traffic & Linguistic Privacy**: Integrated **Pluggable Transports** (obfs4/meek) and **Stylometry Shield** (AI-rephrasing).
- **Physical OPSEC**: Hardware-based **Kill Switch (Tether)** for USB/Smartcard devices and **Panic Password** for silent secure-erase.
- **Surveillance Countermeasures**: **Universal Threat Detector (UTD)** for AI-powered phishing and signature analysis.
- **Middle Finger Bot**: Fully native, highly integrated auto-response Easter Egg seamlessly embedded into the data session pipeline.

## 🛠 Unified OPSEC Command Center

All advanced security features are configurable via the **CRYPTOGRAM Settings** menu:

| Category | Features |
| --- | --- |
| **Network Anonymity** | Tor, I2P, Snowflake Proxy, I2P Relay, Bridge Config |
| **Surveillance Detection** | AI Threat Detector (UTD), Sensitivity Controls, Diagnostics |
| **Voice Security** | Voice Morphing (AI Anonymization), Acoustic Monitoring |
| **Traffic & Stylometry** | obfs4/meek Transports, AI Writing Style Obfuscation |
| **Location Privacy** | Geographic Randomization, Coordinate Noise, Timezone Masking |
| **E2E Encryption** | Signal Protocol (1:1), MLS Protocol (Group), Key Bundle Transport |
| **QuantumGuard** | PQC Security Levels (1-5), Quantum Threat Assessment |
| **Hardware Failsafes** | Panic Password (Secure Erase), USB/Smartcard Tether |
| **Identity & Trust** | CAC/PIV Smartcard Integration, ZK Authentication |
| **Data Isolation** | IMAP Protection Shield (Protocol-level data masking) |
| **Development** | Monero Mining (CPU controlled), OpenVINO AI Optimization, Middle Finger Bot |

## 🚀 Getting Started (Desktop)

Ensure your environment is loaded and start the gRPC/API services:
```bash
# Start gRPC (50051) and API (8080)
python -m mock_server.server &
```

### 2. Build the Client
Use the canonical Linux entrypoint:
```bash
./build_linux.sh
```

> **⚠️ Memory Tip**: On systems with limited RAM (<16GB free), limit parallel jobs to avoid OOM kills:
> ```bash
JOBS=4 ./build_linux.sh
# Or if building directly with CMake:
cmake --build build_test --parallel 4
> ```

## 📱 Getting Started (Android)

The Android build uses Gradle + CMake (NDK) to produce an APK with the native CRYPTOGRAM library.

```bash
# Full automated build (checks SDK/NDK, submodules, overlays, then Gradle)
./build_android.sh /path/to/telegram-android

# Or build directly with Gradle
cd telegram-android && ./gradlew afatDebug
```

### Android Native Library

The `libcryptogram.so` native library is built from:
- `TMessagesProj/jni/cryptogram/CryptogramWrapper.cpp` — JNI bridge
- `TMessagesProj/jni/cryptogram/data/data_signal_protocol.cpp` — Double Ratchet
- `TMessagesProj/jni/cryptogram/data/data_mls_protocol.cpp` — MLS Protocol
- `TMessagesProj/jni/cryptogram/data/data_group_encryption.cpp` — Group Encryption
- `TMessagesProj/jni/cryptogram/qt_shims.h` — Qt compatibility shims (file I/O, JSON, strings)
- `TMessagesProj/jni/cryptogram/desktop_shims.h` — Desktop type shims (Session, PeerData, etc.)

The shims allow the same C++ crypto code to compile on both desktop (with Qt) and Android (without Qt), using standard C++ and POSIX APIs.

### Android Feature Surface

| Feature | Status |
| --- | --- |
| **Double Ratchet (1:1 E2EE)** | Native, self-test passing, persistent key storage |
| **MLS Protocol (Group E2EE)** | Native, self-test passing |
| **Privacy Controls** | Hide online status, typing indicator, read receipts |
| **Panic Password** | Settings toggle, secure-erase hook |
| **Anti-Forensics** | Settings toggle, secure wipe on trigger |
| **Dead Man's Switch** | Settings toggle, failsafe timer |
| **Media Metadata Stripping** | EXIF/GPS removal from shared media |
| **Traffic Obfuscation** | Settings toggle |
| **DPI Evasion** | Settings toggle (method selection) |
| **QuantumGuard Level** | Settings selection (Levels 1/3/5) |
| **Threat Defense Level** | Settings selection (Standard/Enhanced/Maximum) |
| **Stylometry Shield** | Settings toggle |
| **Universal Threat Detector** | Settings toggle + sensitivity |
| **Voice Morphing** | Settings toggle |
| **Location Privacy** | Settings toggle |
| **Interface Camouflage** | Settings toggle |
| **OPSEC Presets** | Quick-apply preset profiles |
| **Curated Stickers** | UI preference |
| **Feature Status Diagnostics** | Native self-check dialog |

## 🧪 Documentation & Results

- **[Desktop Build Alignment Matrix](docs/status/DESKTOP_BUILD_ALIGNMENT.md)**: Claim gate for Linux build inclusion/runtime wiring.
- **[Desktop Feature Matrix](docs/features/desktop-features.md)**: User-facing desktop feature status aligned with current build state.
- **[Android Feature Matrix](docs/features/android-features.md)**: Android feature surface and native library status.
- **[Integration Test Results](docs/status/DESKTOP_TEST_RESULTS.md)**: verification artifacts; do not treat as blanket production proof.
- **[Final Handoff](HANDOFF.md)**: Architecture summary and active system state.

## ⚖️ License

CRYPTOGRAM is released under the GNU GPL v3.0 with the project-specific OpenSSL exception noted in `LICENSE`.
