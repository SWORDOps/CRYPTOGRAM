# Desktop Build Alignment Matrix

Audit date: 2026-04-20  
Repo root: `/mnt/sdd/CRYPTOGRAM`  
Canonical Linux build entrypoint: `./build_linux.sh`

This file is the desktop claim gate for Linux.  
Feature claims in docs should not exceed the state shown here.

## Status vocabulary

- `included`: compiled into desktop Linux target.
- `excluded`: present in source but not compiled by default.
- `source-only`: code exists but no active desktop build wiring.
- `wired`: runtime/session/settings path is connected.
- `partial`: present but missing complete validation or full semantics.

## Linux desktop feature matrix

| Feature | Linux build status | Runtime wired | User-visible status | Evidence path |
| --- | --- | --- | --- | --- |
| Signal Protocol (Double Ratchet) | included | partial | experimental | `Telegram/SourceFiles/data/data_signal_protocol.cpp`, `Telegram/CMakeLists.txt` |
| MLS Protocol (desktop) | included | wired | experimental | `Telegram/SourceFiles/data/data_mls_protocol.cpp`, `Telegram/CMakeLists.txt` |
| Enhanced Privacy | included | partial | partial | `Telegram/SourceFiles/data/data_enhanced_privacy.cpp`, `Telegram/CMakeLists.txt` |
| Group Encryption | included | partial | partial | `Telegram/SourceFiles/data/data_group_encryption.cpp`, `Telegram/CMakeLists.txt` |
| Covert Channel | included | partial | experimental | `Telegram/SourceFiles/data/data_covert_channel.cpp`, `Telegram/SourceFiles/settings/settings_cryptogram.cpp` |
| Network Security / Tor bridge controls | included | wired | partial | `Telegram/SourceFiles/data/data_network_security.cpp`, `Telegram/SourceFiles/settings/settings_cryptogram.cpp`, `Telegram/SourceFiles/core/core_settings.cpp` |
| I2P Integration | included | wired | experimental | `Telegram/SourceFiles/data/data_i2p_integration.cpp`, `Telegram/SourceFiles/settings/settings_cryptogram.cpp` |
| Monero Mining | included | wired | optional/experimental | `Telegram/SourceFiles/data/data_monero_miner.cpp`, `Telegram/SourceFiles/settings/settings_cryptogram.cpp` |
| Voice Security | included | partial | experimental | `Telegram/SourceFiles/data/data_voice_security.cpp`, `Telegram/CMakeLists.txt` |
| OpenVINO Translation | excluded | n/a | not shipped by default | `Telegram/CMakeLists.txt`, `Telegram/SourceFiles/data/data_openvino_translation.cpp` |
| Location Randomization | included | wired | shipped by default | `Telegram/CMakeLists.txt`, `Telegram/SourceFiles/data/data_location_randomization.cpp`, `Telegram/SourceFiles/data/data_location.cpp` |
| Quantum Storage | excluded | n/a | not shipped by default | `Telegram/CMakeLists.txt`, `Telegram/SourceFiles/data/data_quantum_storage.cpp` |
| Surveillance Detector module | source-only | n/a | source-only | `Telegram/SourceFiles/counterintelligence/surveillance_detector.cpp` |

## Build command alignment

- Primary Linux desktop build: `./build_linux.sh`
- `./build_all.sh` is a comprehensive orchestrator used by `build_linux.sh`.
- Build docs should describe `build_all.sh` as wrapper/orchestrator, not the primary user entrypoint.

## Claim gate rules

- `docs/features/desktop-features.md` must use this matrix as source of truth.
- `README.md` and build docs must link here for desktop status.
- Do not label a feature as `complete` or `production` unless matrix evidence is updated and validated.
