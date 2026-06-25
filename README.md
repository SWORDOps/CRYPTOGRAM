## OPSEC VALIDATION NOTE

This document may contain historical implementation claims. Treat all security capabilities as **partial or experimental** unless corroborated by current runtime validation in `docs/status/FINAL_STATUS.md` and `docs/features/android-features.md`.

Desktop Linux claim gate and build-state source of truth:
`docs/status/DESKTOP_BUILD_ALIGNMENT.md`.

# 🔐 CRYPTOGRAM: Advanced OPSEC Messaging

## 🟡 Project Status: Partial/Experimental (Desktop)

The CRYPTOGRAM desktop build contains a broad feature surface, with a mix of fully integrated, partial, and experimental capabilities.
The desktop build is currently undergoing final stabilization and linkage. 

### Core Capabilities
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

## 🧪 Documentation & Results

- **[Desktop Build Alignment Matrix](docs/status/DESKTOP_BUILD_ALIGNMENT.md)**: Claim gate for Linux build inclusion/runtime wiring.
- **[Feature Matrix](docs/features/desktop-features.md)**: User-facing desktop feature status aligned with current build state.
- **[Integration Test Results](docs/status/DESKTOP_TEST_RESULTS.md)**: verification artifacts; do not treat as blanket production proof.
- **[Final Handoff](HANDOFF.md)**: Architecture summary and active system state.

## ⚖️ License

CRYPTOGRAM is released under the GNU GPL v3.0 with the project-specific OpenSSL exception noted in `LICENSE`.
