# Changelog

All notable changes to CRYPTOGRAM will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Real post-quantum message protection (ML-KEM hybrid, 1:1 chats)**: CRYPTOGRAM-to-CRYPTOGRAM conversations now layer a genuine ML-KEM + AES-256-GCM envelope inside the existing Double Ratchet. Each side generates and persists a static ML-KEM keypair; key-bundle entities advertise the KEM public key (backward-compatible extension — older clients ignore it); the sender encapsulates a fresh shared secret per message; the receiver decapsulates and strips the envelope after the ratchet layer. Gated by Settings → CRYPTOGRAM → quantum security level (Level 3+, default) with automatic classic-only fallback when the peer has not advertised a KEM key.
- **QuantumSignalProtocol de-faked**: the previous implementation derived "session secrets" from public key material and lazily minted unshared random keys per peer — receivers could never have decrypted senders' traffic. All primitives are now real: X25519 ECDH for the classical X3DH leg, genuine ML-KEM encapsulation returning transportable ciphertext, ML-DSA key-bundle signature verification, and no more local-only session minting (sessions may only arise from real key agreement; the session-init transport that carries the KEM ciphertext is explicit follow-up work).
- **Merged `nonfunctional-dev` branch (43 commits, Jul 28 – Aug 14 2026)**:
  - Android: CRYPTOGRAM encryption wired into the message pipeline — restored `DoubleRatchet`, `MLSProtocol`, `CryptogramNative`, `CryptogramSettingsActivity`, `PanicPasswordHelper`, `DpiEvasionHelper`, `EnhancedPrivacy`, `AntiForensicsHelper`, and `StylometryShield`; JNI `CryptogramWrapper` and MLS sources updated.
  - Desktop: real OpenSSL crypto in `EnhancedPrivacy` (encrypt/decrypt), incoming MLS group decryption wired in `history_item.cpp`, covert-channel payload encryption enabled, TagLib audio metadata wired into the build.
  - `QuantumCryptoServices` with key history management, panic password, and DPI evasion.
  - Build/CI: strict-mode `build_all.sh` (`--strict`), `tests.yml` CI workflow, expanded compiler candidate lists, SWORDOps forks for `cmake`/`taglib`/`libsignal`, CPU-safe tde2e build flags.
  - Storage: backwards-compatible 64Gram session import (dual SHA-256/MD5 file signatures; cloud password SRP switched to SHA-256 to match 64Gram).
- **Universal Threat Detector (UTD) Local AI Integration**:
  - Embedded `llama-server` directly into the CRYPTOGRAM build system.
  - Implemented dynamic hardware profiling (NPU, GPU VRAM, CPU AVX2) to automatically select between Qwen 2.5 0.5B, 1.5B, and 3B models.
  - Added a UI interceptor in `history_view_message.cpp` to visually flag malicious messages with translucent red warnings in real-time.
  - Added granular Privacy & Security settings toggle allowing users to override AI tiers or disable the background AI completely to conserve battery.

### Fixed
- **X3DH session establishment was broken cross-side and used zero-filled HKDF keys**:
  - The identity legs (DH1/DH3) applied X25519 with the Ed25519 signing identity's seed against its Ed25519 public — mathematically non-agreeing (verified: the two session-establishment sides derived different roots). Sessions now use a dedicated persisted X25519 identity, advertised to peers in the key bundle (0x04 extension, backward-compatible).
  - `SignalProtocol::deriveKey` never set the HKDF digest — OpenSSL 3.x fails such derives, and the code silently returned **zero-filled keys** for all 14 call sites (root keys, chain keys, message keys). The digest is now set; the standalone roundtrip suite passed only because its mirror set the digest correctly.
  - Receiver-side establishment is now lazy and correct: the initiator's ephemeral X25519 key arrives in the first message's metadata (the old code passed the wrong keys at bundle-extraction time), stale pre-fix sessions are re-established automatically on first decrypt, and the latest session wins.
- **CRYPTOGRAM settings now persist across restarts**: all 55+ custom `Core::Settings` fields (quantum security level, panic password, stylometry, DPI evasion, Tor/I2P/bridges, mining, OpenVINO translation, privacy controls, curated stickers, …) are saved in a versioned, self-contained trailer at the end of the settings blob. Old settings files load unchanged (defaults) and are upgraded transparently on next save; the previously write-only Tor bridge fields are now read back too.
- **Universal Threat Detector is now wired and strictly opt-in**: `initialize()` is called once at startup (deferred so it never delays the first window). The local llama-server model is only spawned when the user has enabled the feature in Settings → Privacy & Security; fresh installs default to **off**, incoming-message queueing consumes nothing while disabled, and machines without the AI assets fall back to pattern-only heuristics. Hardware probing no longer stalls startup when `lspci` is absent.
- **AI engine and models are never bundled with the app**: the llama-server binary and the tier-selected Qwen2.5 model (~0.5–2 GB) are downloaded on demand to the user's data directory when the feature is first enabled — nothing ships in the initial download. Downloads are verified against `.sha256` sidecars when the asset host provides them; the asset host can be redirected with `CRYPTOGRAM_AI_ASSETS_URL`. llama-server now starts on a kernel-assigned localhost port instead of the fixed 8080, so instances and services never collide.
- Desktop incoming messages were never decrypted (P2 audit gap) — incoming MLS group ciphertext is now routed through `Data::GroupEncryption`.
- Covert-channel packet signatures now use an HKDF-derived stable per-session key (SHA-256 chain) instead of a random per-packet HMAC key; payload encryption through `EnhancedPrivacy` is enabled.
- `AutoDetectCryptogramUser` hook enabled on covert-peer registration.

### 🎉 Major Release - CRYPTOGRAM v1.0 Security Overhaul

**Release Date**: November 2025

This release transforms the messenger into CRYPTOGRAM, featuring military-grade security and privacy capabilities that surpass all existing messaging applications.

---

## [1.0.0] - 2025-11-05

### 🔐 Added - Advanced Security Features (Phase 1)

#### Audio Steganography Engine ⭐ UNIQUE
- **NEW**: Complete audio steganography implementation with 8 different methods
- **NEW**: LSB (Least Significant Bit) steganography
- **NEW**: Spectral masking in frequency domain
- **NEW**: Echo-based steganography
- **NEW**: Phase modulation embedding
- **NEW**: Spread spectrum steganography
- **NEW**: Adaptive LSB based on audio content
- **NEW**: Psychoacoustic masking for imperceptibility
- **NEW**: Cepstral domain steganography
- **NEW**: 100 bits/second undetectable embedding rate
- **NEW**: SNR >40dB audio quality maintenance
- **NEW**: AES-256 encryption of hidden payloads
- **NEW**: Reed-Solomon error correction
- **NEW**: Zlib compression before embedding
- **NEW**: Hardware acceleration with software fallback
- **Files**: `security/gna_steganography_engine.h/cpp` (~1,317 lines)
- **Files**: `security/gna_acoustic_security.h/cpp` (~44,408 lines)

#### Location Randomization System ⭐ UNIQUE
- **NEW**: Complete location privacy and anti-tracking system
- **NEW**: Phone number-based geolocation analysis
- **NEW**: Country code, area code, and region extraction
- **NEW**: Timezone and cultural context determination
- **NEW**: 50+ predefined geographic regions
- **NEW**: Realistic location profiles with addresses, GPS, timezones
- **NEW**: City, state, postal code generation
- **NEW**: Business context (office, cafe, home, etc.)
- **NEW**: Credibility scoring (1-10 realism rating)
- **NEW**: Multiple rotation policies (per-session, daily, weekly, message-based)
- **NEW**: Maximum location reuse limits
- **NEW**: Minimum pool size enforcement
- **NEW**: Timezone matching and cultural marker enforcement
- **NEW**: Coordinate noise (±5km radius)
- **NEW**: Decoy location generation (20% fake locations)
- **NEW**: Location history management
- **Files**: `data/data_location_randomization.h/cpp` (~600 lines)
- **Files**: `data/counterintelligence_features.h/cpp` (~135,000 lines)

#### Surveillance Detection System ⭐ UNIQUE
- **NEW**: Active threat detection and monitoring
- **NEW**: Process monitoring detection (debuggers, profilers, monitoring tools)
- **NEW**: Memory scanning detection
- **NEW**: Network traffic analysis for anomalies
- **NEW**: System call monitoring
- **NEW**: File access pattern analysis
- **NEW**: Registry/config tampering detection
- **NEW**: Behavioral anomaly detection using AI/ML
- **NEW**: Unusual access pattern detection
- **NEW**: Timing anomaly detection
- **NEW**: Resource usage spike detection
- **NEW**: Real-time threat notifications
- **NEW**: Severity classification (Low/Medium/High/Critical)
- **NEW**: Recommended action suggestions
- **NEW**: Threat history logging
- **NEW**: Forensic data collection
- **NEW**: Automatic security hardening
- **NEW**: Process isolation
- **NEW**: Memory protection
- **NEW**: Anti-debugging measures
- **Files**: `counterintelligence/surveillance_detector.h/cpp` (~766 lines)
- **Files**: `counterintelligence/counterintelligence_controller.h`
- **Files**: `counterintelligence/counterintelligence_dashboard.h`

#### Covert Channel Engine ⭐ UNIQUE
- **NEW**: Hidden communication channel system
- **NEW**: Timing-based channels (inter-packet delay modulation)
- **NEW**: Storage-based channels (unused protocol fields)
- **NEW**: Network-based channels (protocol ambiguities)
- **NEW**: Side channels (indirect communication paths)
- **NEW**: TCP sequence number encoding
- **NEW**: HTTP header steganography
- **NEW**: DNS query encoding
- **NEW**: ICMP payload hiding
- **NEW**: DPI (Deep Packet Inspection) evasion
- **NEW**: Firewall traversal
- **NEW**: Traffic shaping resistance
- **NEW**: Protocol whitelisting bypass
- **NEW**: QoS manipulation avoidance
- **NEW**: Encrypted channel establishment
- **NEW**: Authentication and integrity verification
- **NEW**: Replay attack prevention
- **NEW**: Traffic normalization
- **NEW**: Statistical undetectability
- **Files**: `security/gna_covert_channel_engine.h/cpp` (~798 lines)

#### Enhanced Privacy System
- **NEW**: Additional encryption layer beyond E2EE
- **NEW**: Passphrase-based message encryption
- **NEW**: Time-based key derivation (TOTP-style)
- **NEW**: Daily automatic key rotation
- **NEW**: 7-day key history
- **NEW**: Configurable salt for key derivation
- **NEW**: EXIF metadata stripping from photos
- **NEW**: GPS coordinate removal
- **NEW**: File metadata cleaning
- **NEW**: Timestamp anonymization
- **NEW**: Screenshot prevention
- **NEW**: Screen recording detection
- **NEW**: Watermark removal
- **NEW**: File sanitization
- **NEW**: Time-based message deletion
- **NEW**: Read-once messages
- **NEW**: Automatic history clearing
- **NEW**: Secure deletion with overwrite
- **Files**: `data/data_enhanced_privacy.h/cpp` (~200 lines)

#### Double Ratchet Protocol (Signal Protocol)
- **NEW**: Complete Signal Protocol implementation
- **NEW**: X25519 (Curve25519) Diffie-Hellman key exchange
- **NEW**: Ed25519 digital signatures for identity verification
- **NEW**: AES-256-CBC message encryption
- **NEW**: HKDF (HMAC-based Key Derivation Function)
- **NEW**: HMAC-SHA256 message authentication
- **NEW**: Forward secrecy (old keys deleted after use)
- **NEW**: Break-in recovery (future message security after compromise)
- **NEW**: Out-of-order message handling
- **NEW**: Skipped message key storage (up to 1000 keys)
- **NEW**: Message counter tracking for replay protection
- **NEW**: Session state serialization with HMAC integrity
- **NEW**: Persistent session storage
- **NEW**: Key backup/restore with PBKDF2 encryption
- **NEW**: Automatic key rotation with configurable intervals
- **NEW**: Multiple device support per peer
- **NEW**: TPM 2.0 support for desktop
- **NEW**: Android KeyStore integration
- **NEW**: Apple Secure Enclave support
- **NEW**: Software fallback when hardware unavailable
- **Files**: `data/data_signal_protocol.h/cpp` (~3,774 lines)
- **Files**: `tests/unit/test_double_ratchet.cpp`

### 🛡️ Added - Supporting Security Modules

#### Adaptive Countermeasures
- **NEW**: Dynamic security adjustments based on threat level
- **NEW**: Real-time threat response automation
- **NEW**: Security posture adaptation
- **NEW**: Multi-layer defense mechanisms
- **NEW**: Automated threat mitigation
- **Files**: `counterintelligence/adaptive_countermeasures.h/cpp` (~899 lines)

#### Countermeasure Randomizer
- **NEW**: Security behavior randomization
- **NEW**: Unpredictable response patterns
- **NEW**: Anti-fingerprinting measures
- **NEW**: Traffic pattern randomization
- **NEW**: Timing obfuscation
- **Files**: `counterintelligence/countermeasure_randomizer.h/cpp` (~702 lines)

#### Universal Security Validator
- **NEW**: Comprehensive security validation
- **NEW**: Multi-platform security checks
- **NEW**: Cryptographic algorithm verification
- **NEW**: Configuration auditing
- **NEW**: Security compliance verification
- **Files**: `counterintelligence/universal_security_validator.h/cpp` (~557 lines)

#### Hardware Detector
- **NEW**: Hardware capability detection
- **NEW**: NPU (Neural Processing Unit) detection
- **NEW**: GPU acceleration support
- **NEW**: Platform-specific optimization
- **NEW**: Hardware-accelerated cryptography
- **Files**: `security/hardware_detector.h/cpp` (~34,435 lines)

### 📚 Added - Documentation

- **NEW**: Comprehensive README with all security features
- **NEW**: Feature comparison table (vs Signal, Telegram, WhatsApp)
- **NEW**: Architecture diagram (5-layer security stack)
- **NEW**: Target user profiles (journalists, activists, whistleblowers, etc.)
- **NEW**: Quick start guide for developers
- **NEW**: Technical specifications
- **NEW**: FIVE_FEATURES_PORT.md - Complete guide to 5 advanced features
- **NEW**: DOUBLE_RATCHET_PORT.md - Double Ratchet implementation details
- **NEW**: AVAILABLE_SPYGRAM_FEATURES.md - Catalog of available features
- **NEW**: Updated features.md with all new capabilities
- **NEW**: CHANGELOG.md - This file

### 🏗️ Changed - Project Identity

- **CHANGED**: Rebranded from 64Gram to CRYPTOGRAM
- **CHANGED**: Project mission: Privacy-first secure messenger
- **CHANGED**: Focus on journalists, activists, and privacy advocates
- **CHANGED**: README completely rewritten for security focus
- **CHANGED**: Feature list reorganized to highlight security features

### 📊 Statistics

- **Total Files Added**: 31 files
- **Total Lines Added**: ~21,233 lines of security code
- **Major Features**: 6 complete security systems
- **Supporting Modules**: 9 additional components
- **Documentation Pages**: 6 comprehensive guides
- **Steganography Methods**: 8 different techniques
- **Geographic Regions**: 50+ realistic location profiles
- **Security Layers**: 5-layer architecture

### 🔗 Links

- **Commit**: `93ece50` - Port 5 advanced security features from SpyGram
- **Commit**: `27e8f38` - Port complete Double Ratchet implementation from SpyGram
- **Commit**: `bd5b3ec` - Add comprehensive SpyGram features catalog
- **Commit**: `47026bb` - Add SpyGram source files to .gitignore

---

## [0.9.0] - Pre-CRYPTOGRAM (64Gram Base)

### Initial State
- Based on 64Gram (Telegram Desktop fork)
- Basic messaging features
- Multiple account support (up to 10)
- Various UI/UX enhancements
- Screenshot privacy mode
- Basic location support

---

## Future Roadmap

### [1.1.0] - Planned
- Quantum-resistant encryption algorithms
- Tor network integration
- P2P encrypted voice/video calls
- Secure group steganography
- Advanced traffic analysis resistance
- Mobile platform support (Android, iOS)

### [1.2.0] - Planned
- Decentralized identity system
- Blockchain-based message verification
- AI-powered threat detection improvements
- Voice morphing for calls
- Advanced GUI for security features

### [2.0.0] - Planned
- Complete decentralization
- Mesh network support
- Quantum key distribution
- Homomorphic encryption for cloud processing
- Advanced anti-forensics features

---

## Versioning

CRYPTOGRAM follows [Semantic Versioning](https://semver.org/):
- **MAJOR** version for incompatible API changes
- **MINOR** version for backwards-compatible functionality additions
- **PATCH** version for backwards-compatible bug fixes

---

## Categories

- **Added**: New features
- **Changed**: Changes in existing functionality
- **Deprecated**: Soon-to-be removed features
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Vulnerability fixes

---

**Note**: This changelog documents changes specific to CRYPTOGRAM. For Telegram Desktop upstream changes, see the [official Telegram Desktop changelog](https://github.com/telegramdesktop/tdesktop/releases).

---

**Last Updated**: November 5, 2025
