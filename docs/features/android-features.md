# CRYPTOGRAM Android Features

This page describes the Android feature surface that is present in the repository today. The Android build now mirrors the desktop settings surface with full OPSEC, encryption, privacy, and threat defense toggles.

## Core Messaging

### 1. Signal Protocol / Double Ratchet
**Status**: Present in code, UI, and native self-tests

The repo contains Double Ratchet classes, native bridge code, settings toggles, and local native self-checks for 1-on-1 encrypted messaging.

- X25519 key exchange
- Ed25519-related protocol code
- AES-256-GCM-related helpers
- Forward-secrecy oriented message flow
- Settings toggle in the CRYPTOGRAM screen
- Native self-test hook exposed through `CryptogramNative`

**Note**: The native layer now exposes local self-tests, but the runtime path should still be treated as an active implementation rather than a finished cryptographic audit result.

### 2. MLS Protocol
**Status**: Partial, with native self-test coverage

MLS-related classes and JNI entry points are present for group encryption flows.

- Group messaging scaffolding
- TreeKEM-oriented data structures
- Settings toggle in the CRYPTOGRAM screen
- Feature status reporting in the UI
- Native self-test hook exposed through `CryptogramNative`

**Note**: Some MLS cryptographic paths still use placeholder logic, so the docs should not claim full end-to-end completion.

### 3. Post-Quantum Cryptography (QuantumGuard)
**Status**: Settings UI present, selection wired

The Android settings screen now exposes QuantumGuard security level selection matching the desktop:

- Level 1 (AES-128 equivalent) — Kyber-512 / Dilithium-2
- Level 3 (AES-256 equivalent) — Kyber-768 / Dilithium-3
- Level 5 (Advanced) — Kyber-1024 / Dilithium-5

Persisted via `SharedConfig.cryptogramQuantumSecurityLevel`.

## Privacy Features

### 4. Enhanced Privacy
**Status**: Present in settings and helper code

The Android tree exposes privacy toggles and supporting helper classes for:

- Hide online status
- Hide typing indicator
- Hide read receipts
- Metadata/privacy helper flows

### 5. Media Metadata Stripping
**Status**: Settings toggle present

- EXIF/GPS metadata spoofing toggle
- Persisted via `SharedConfig.cryptogramMediaMetadataSpoofingEnabled`
- Runtime hook available through `OPSECHelper`

## OPSEC & Security

### 6. Panic Password
**Status**: Settings toggle present, secure-erase hook implemented

- Toggle in CRYPTOGRAM settings screen
- Warning dialog on enable
- `OPSECHelper.triggerPanicWipe()` performs secure file overwrite + deletion
- Persisted via `SharedConfig.cryptogramPanicPasswordEnabled`

### 7. Anti-Forensics
**Status**: Settings toggle present

- Toggle in CRYPTOGRAM settings screen
- `OPSECHelper.secureWipe()` / `secureWipeDirectory()` for evidence destruction
- Persisted via `SharedConfig.cryptogramAntiForensicsEnabled`

### 8. Dead Man's Switch
**Status**: Settings toggle present

- Toggle in CRYPTOGRAM settings screen
- Info dialog on enable (60-minute activity requirement)
- Persisted via `SharedConfig.cryptogramDeadManSwitchEnabled`

### 9. DPI Evasion
**Status**: Settings toggle + method selection

- Enable/disable toggle
- Method selection dialog: HTTPS Mimicry, HTTP Tunneling, DNS Tunneling, Generic Fragmentation, Auto
- Persisted via `SharedConfig.cryptogramDpiEvasionEnabled` and `cryptogramDpiEvasionMethod`

### 10. Traffic Obfuscation
**Status**: Settings toggle present

- Advanced traffic obfuscation toggle
- Persisted via `SharedConfig.cryptogramTrafficObfuscationEnabled`

### 11. Traffic Padding
**Status**: Settings toggle present

- Network traffic padding toggle
- Persisted via `SharedConfig.cryptogramTrafficPaddingEnabled`

### 12. Stylometry Shield
**Status**: Settings toggle + runtime implementation

- Enable/disable toggle
- Mode selection: Rules-only or Model-assisted
- Strength selection: Light, Medium, Heavy
- `OPSECHelper.applyStylometry()` provides rule-based text obfuscation
- Persisted via `SharedConfig.cryptogramStylometryShieldEnabled`, `cryptogramStylometryMode`, `cryptogramStylometryStrength`

### 13. Universal Threat Detector (UTD)
**Status**: Settings toggle + sensitivity

- Enable/disable toggle
- Sensitivity threshold (0-100%)
- Persisted via `SharedConfig.cryptogramUtdEnabled` and `cryptogramUtdThreshold`

### 14. Voice Morphing
**Status**: Settings toggle present

- AI voice anonymization toggle
- Persisted via `SharedConfig.cryptogramVoiceMorphingEnabled`

### 15. Location Privacy
**Status**: Settings toggle + runtime implementation

- Geographic randomization toggle
- `OPSECHelper.randomizeLocation()` adds noise to lat/lon coordinates
- Persisted via `SharedConfig.cryptogramLocationPrivacyEnabled`

### 16. Interface Camouflage
**Status**: Settings toggle present

- UI disguise toggle
- Persisted via `SharedConfig.cryptogramInterfaceCamouflageEnabled`

### 17. Hardware Kill Switch (Tether)
**Status**: Settings toggle present

- USB/Smartcard session tether toggle
- Persisted via `SharedConfig.cryptogramHardwareTetherEnabled`

### 18. IMAP & Protocol Data Protection
**Status**: Settings toggle present

- Protocol synchronization shield toggle
- Protection level: None, Standard, Maximum
- Persisted via `SharedConfig.cryptogramImapProtectionEnabled` and `cryptogramImapProtectionLevel`

### 19. Threat Defense Level
**Status**: Settings selection present

- Standard (Baseline Protection)
- Enhanced (Advanced Obfuscation)
- Maximum (Extreme Countermeasures)
- Persisted via `SharedConfig.cryptogramThreatDefenseLevel`

## OPSEC Presets

### 20. Quick OPSEC Presets
**Status**: Present

Three preset profiles for quick configuration:

- **Standard**: Baseline protection, no aggressive features
- **Enhanced**: Traffic obfuscation, DPI evasion, stylometry, UTD, media stripping
- **Maximum**: All countermeasures including anti-forensics, traffic padding, interface camouflage

Implemented in `CryptogramSettingsActivity.applyPreset()`.

## UI and Settings

### 21. CRYPTOGRAM Settings Screen
**Status**: Present, expanded to full feature parity

The settings activity exposes all toggles matching the desktop settings surface:

- Double Ratchet toggle
- MLS toggle
- Privacy toggles (online status, typing, read receipts)
- Curated stickers toggle
- OPSEC section (18 features)
- OPSEC preset section (3 presets)
- Feature status dialog with native self-check
- Native version/status display

### 22. Visual Indicators
**Status**: Present

The UI includes indicator helpers for encrypted message presentation:

- Lock icon helpers
- Badge helpers for encrypted messages
- Chat status color helpers

## Premium Override

### 23. OPSEC Helper
**Status**: Present

`OPSECHelper.kt` provides:

- Runtime status queries for all OPSEC features
- Secure file wipe (overwrite + delete)
- Secure directory wipe
- Panic wipe trigger
- Stylometry text obfuscation (Light/Medium/Heavy)
- Location coordinate randomization
- Full status report generation
- Feature summary for UI display

## Premium Override

### 24. Premium Features Override
**Status**: Present as a testing hook

The repository includes premium-override toggles and related settings/core references. This should be described as a testing or configuration hook, not as a claim that server-side premium features are available without the upstream service.

## Installation

Android build and installation steps are documented in the platform guides:

```bash
./build_android.sh /path/to/telegram-android
```

Use the current build docs and the status page together, because the docs do not guarantee a clean build or fully tested device runtime.

## Source Code

- `TMessagesProj/jni/cryptogram/` - Native bridge and protocol code
- `TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/` - Java/Kotlin API
  - `CryptogramNative.kt` - Native library interface
  - `DoubleRatchet.kt` - Signal Protocol wrapper
  - `MLSProtocol.kt` - MLS Protocol wrapper
  - `EnhancedPrivacy.kt` - Privacy helper
  - `OPSECHelper.kt` - OPSEC feature implementations
  - `CryptogramMessageHelper.java` - Message encryption/decryption helper
- `TMessagesProj/src/main/java/org/telegram/ui/CryptogramSettingsActivity.java` - Settings screen
- `TMessagesProj/src/main/java/org/telegram/ui/Components/CryptogramIndicator.java` - UI indicators
- `TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java` - Settings persistence

## Feature Parity Matrix (Desktop vs Android)

| Feature | Desktop | Android |
| --- | --- | --- |
| Double Ratchet (1:1 E2EE) | included, partial | Native, self-test passing |
| MLS Protocol (Group E2EE) | included, partial | Native, self-test passing |
| Post-Quantum (QuantumGuard) | included, partial | Settings UI, level selection |
| Privacy Controls | included | Present (3 toggles) |
| Panic Password | included, partial | Toggle + secure-wipe hook |
| Anti-Forensics | included, partial | Toggle + secure-wipe impl |
| Dead Man's Switch | included, partial | Toggle + info dialog |
| Media Metadata Stripping | included, partial | Toggle present |
| Traffic Obfuscation | included, partial | Toggle present |
| Traffic Padding | included, partial | Toggle present |
| DPI Evasion | included, partial | Toggle + method selection |
| Stylometry Shield | included, partial | Toggle + runtime obfuscation |
| Universal Threat Detector | source-only | Toggle + sensitivity |
| Voice Morphing | included, partial | Toggle present |
| Location Privacy | excluded | Toggle + randomization impl |
| Interface Camouflage | included, partial | Toggle present |
| Hardware Tether | included, partial | Toggle present |
| IMAP Protection | included, partial | Toggle + level selection |
| Threat Defense Level | included, partial | Selection (3 levels) |
| OPSEC Presets | included | Present (3 presets) |
| Monero Mining | included, experimental | Not present |
| OpenVINO Translation | excluded | Not present |
| Tor/I2P/Snowflake | included, partial | Not present (network-level) |

## Known Gaps

- Tor/I2P/Snowflake network integration is not present on Android (requires native Tor/I2P libraries).
- Monero mining is not present on Android (desktop-only development feature).
- OpenVINO translation is not present on Android (requires Intel OpenVINO runtime).
- Some JNI-backed features still depend on partial or placeholder cryptographic paths.
- Device-level and end-to-end testing is still limited in this repository snapshot.
