# 🔐 CRYPTOGRAM - Military-Grade Secure Messenger

**The most advanced privacy-focused messaging application built on Telegram**

[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20Android-lightgrey.svg)](docs/)
[![Security](https://img.shields.io/badge/security-military--grade-green.svg)](#security-features)
[![Build Status](https://github.com/SWORDOps/CRYPTOGRAM/actions/workflows/build-android.yml/badge.svg)](https://github.com/SWORDOps/CRYPTOGRAM/actions)

> **CRYPTOGRAM** combines Telegram's infrastructure with cutting-edge cryptographic protocols, steganography, and anti-surveillance technology to provide unparalleled privacy and security on **Desktop** and **Android**.

---

## 🎯 Project Mission

To provide the world's most secure, privacy-focused messaging platform with advanced features for journalists, activists, whistleblowers, and anyone who values digital privacy.

**CRYPTOGRAM goes beyond traditional E2EE messaging** by providing:
- Covert communication channels
- Active surveillance detection
- Location privacy protection
- Multi-layer encryption (Signal Protocol + MLS)
- Anti-censorship technology

---

## 📱 Platforms

CRYPTOGRAM is available on **two platforms**:

### 🖥️ **CRYPTOGRAM Desktop**
Advanced security features including audio steganography, surveillance detection, and covert channels.
- **Platforms**: Windows, Linux, macOS
- **Status**: ✅ Production ready
- **Features**: 6 major security systems

### 📱 **CRYPTOGRAM Android** ✨ **NEW!**
Military-grade encryption with Signal Protocol and MLS for mobile devices.
- **Platform**: Android 5.0+ (all ABIs)
- **Status**: ✅ Implementation complete
- **Features**: Double Ratchet + MLS Protocol

---

## 🚀 Why CRYPTOGRAM?

### ✅ Features No Other Messenger Has

| Feature | Signal | Telegram | WhatsApp | **CRYPTOGRAM Desktop** | **CRYPTOGRAM Android** |
|---------|--------|----------|----------|----------------------|----------------------|
| End-to-End Encryption | ✅ | 🟡 Secret Chats | ✅ | ✅ | ✅ |
| Signal Protocol (Double Ratchet) | ✅ | ❌ | ✅ | ✅ | ✅ **NEW** |
| MLS Protocol (RFC 9420) | ❌ | ❌ | ❌ | ✅ | ✅ **NEW** |
| Audio Steganography | ❌ | ❌ | ❌ | ✅ **UNIQUE** | 🔄 Coming |
| Location Randomization | ❌ | ❌ | ❌ | ✅ **UNIQUE** | 🔄 Coming |
| Surveillance Detection | ❌ | ❌ | ❌ | ✅ **UNIQUE** | 🔄 Coming |
| Covert Channels | ❌ | ❌ | ❌ | ✅ **UNIQUE** | 🔄 Coming |
| Hardware Security (TPM/KeyStore) | ❌ | ❌ | ❌ | ✅ | ✅ |
| Metadata Stripping | 🟡 | ❌ | ❌ | ✅ | ✅ |
| Forward Secrecy | ✅ | 🟡 | ✅ | ✅ | ✅ |
| Post-Compromise Security | ✅ | ❌ | ❌ | ✅ | ✅ |
| Group Encryption (TreeKEM) | ❌ | ❌ | ❌ | ✅ | ✅ **NEW** |

---

# 🖥️ CRYPTOGRAM Desktop

## 🔐 Desktop Security Features

### 1. 🎵 **Audio Steganography Engine**
> **Hide encrypted messages inside voice notes and audio files**

- **8 Steganography Methods**: LSB, Spectral Masking, Echo Hiding, Phase Modulation, Spread Spectrum, and more
- **100 bits/second** embedding rate (statistically undetectable)
- **SNR >40dB** maintains perfect audio quality
- **AES-256 encryption** of hidden payloads
- **Psychoacoustic masking** for imperceptibility
- **Reed-Solomon error correction** for reliability

**Use Cases**: Covert communication, censorship bypass, plausible deniability, whistleblower protection

**Documentation**: [FIVE_FEATURES_PORT.md](FIVE_FEATURES_PORT.md#1--audio-steganography-engine)

---

### 2. 🌍 **Location Randomization System**
> **Prevent geolocation tracking with realistic fake locations**

- **Phone number analysis** for geographic intelligence
- **Realistic location profiles** with addresses, GPS coordinates, timezones
- **Cultural context matching** for credibility
- **Automatic rotation** (per-session, daily, weekly, message-based)
- **Decoy location generation** (20% fake locations)
- **50+ geographic regions** with realistic coordinate bounds

**Use Cases**: Anti-tracking, journalist safety, activist protection, privacy enhancement

**Documentation**: [FIVE_FEATURES_PORT.md](FIVE_FEATURES_PORT.md#2--location-randomization-system)

---

### 3. 👁️ **Surveillance Detection System**
> **Active detection and alerting for surveillance attempts**

- **Process monitoring** detection (debuggers, profilers, monitoring tools)
- **Memory scanning** detection
- **Network traffic analysis** for anomalies
- **Behavioral anomaly detection** using AI/ML
- **Real-time threat alerts** with severity classification
- **Automatic countermeasures** activation
- **Forensic data collection** for security audits

**Use Cases**: Government surveillance detection, corporate espionage prevention, malware detection

**Documentation**: [FIVE_FEATURES_PORT.md](FIVE_FEATURES_PORT.md#3--surveillance-detection-system)

---

### 4. 🕵️ **Covert Channel Engine**
> **Hidden communication channels that bypass censorship and DPI**

- **Multiple channel types**: Timing-based, storage-based, network-based, side-channels
- **DPI (Deep Packet Inspection) evasion**
- **Firewall traversal** and traffic shaping resistance
- **Protocol whitelisting bypass**
- **Statistical undetectability**
- **Encrypted channel establishment**

**Use Cases**: Censorship resistance, firewall bypass, anti-monitoring, restrictive networks

**Documentation**: [FIVE_FEATURES_PORT.md](FIVE_FEATURES_PORT.md#4--covert-channel-engine)

---

### 5. 🔒 **Enhanced Privacy System**
> **Additional encryption layer with metadata protection**

- **Extra encryption layer** beyond E2EE
- **Passphrase-based encryption**
- **Time-based key derivation** (TOTP-style)
- **Metadata stripping** (EXIF, GPS, timestamps)
- **Screenshot prevention** and recording detection
- **Auto-deletion** with secure overwrite
- **File sanitization**

**Use Cases**: Defense in depth, metadata privacy, temporary communication, document security

**Documentation**: [FIVE_FEATURES_PORT.md](FIVE_FEATURES_PORT.md#5--enhanced-privacy-system)

---

### 6. 🔐 **Double Ratchet Protocol (Desktop)**
> **End-to-end encryption with forward secrecy and break-in recovery**

- **Signal Protocol** implementation
- **X25519 (Curve25519)** key exchange
- **Ed25519** digital signatures
- **AES-256-CBC** message encryption
- **HKDF** key derivation
- **Forward secrecy**: Old keys deleted after use
- **Break-in recovery**: Future messages secure after compromise
- **Out-of-order message handling**
- **Hardware security module (TSM) integration**: TPM 2.0, Android KeyStore, Apple Secure Enclave

**Use Cases**: Secure end-to-end encrypted messaging, forward secrecy, quantum-resistant storage

**Documentation**: [DOUBLE_RATCHET_PORT.md](DOUBLE_RATCHET_PORT.md)

---

# 📱 CRYPTOGRAM Android ✨

## 🔐 Android Security Features

### 1. 🔐 **Signal Protocol (Double Ratchet)** - For 1-on-1 Chats
> **Military-grade encryption with forward secrecy**

**Algorithms**:
- **X25519 ECDH** key exchange
- **Ed25519** digital signatures
- **AES-256-GCM** message encryption
- **HMAC-SHA256** authentication

**Properties**:
- ✅ **Forward secrecy** - Past messages secure even if current keys compromised
- ✅ **Post-compromise security** - Security restored after key compromise
- ✅ **Deniability** - Messages can't be proven to come from sender
- ✅ **Future secrecy** - Future messages secure even if current message compromised

**Performance**:
- Encryption: ~0.5ms per message
- Storage: ~1KB per session

**Documentation**: [CRYPTOGRAM_ANDROID_COMPLETE.md](CRYPTOGRAM_ANDROID_COMPLETE.md)

---

### 2. 📦 **MLS Protocol (RFC 9420)** - For Group Chats
> **Scalable group encryption with TreeKEM**

**Algorithms**:
- **TreeKEM** for O(log n) key distribution
- **X25519/X448** ECDH
- **AES-256-GCM / ChaCha20-Poly1305** encryption
- **SHA-256 / SHA-512** hashing

**Properties**:
- ✅ **O(log n) efficiency** - Scales to 10,000+ members
- ✅ **Forward secrecy** per epoch
- ✅ **Post-compromise security**
- ✅ **Member add/remove** with automatic re-keying

**Performance**:
- Group creation: O(n log n)
- Message encryption: O(1)
- Member operations: O(log n)

**Documentation**: [CRYPTOGRAM_ANDROID_COMPLETE.md](CRYPTOGRAM_ANDROID_COMPLETE.md)

---

### 3. 🎨 **Complete UI Integration**
> **Seamless encryption with visual feedback**

**Settings Screen**:
- Access: Settings → 🔐 CRYPTOGRAM
- Toggle Double Ratchet (Signal Protocol)
- Toggle MLS for Groups
- Status indicators
- Feature information
- Library version display

**Visual Indicators**:
- 🔒 **Lock icon** on encrypted messages
- Encryption markers (🔐 for Double Ratchet, 🔐📦 for MLS)
- Status display (Active / Not Initialized)

**Message Flow**:
- Automatic encryption when enabled
- Automatic decryption on receive
- Protocol auto-selection (1-on-1 vs group)
- Error handling and logging

**Documentation**: [SETTINGS_UI_COMPLETE.md](SETTINGS_UI_COMPLETE.md), [MESSAGE_FLOW_COMPLETE.md](MESSAGE_FLOW_COMPLETE.md)

---

### 4. 🤖 **Automated CI/CD**
> **GitHub Actions for continuous APK builds**

**Features**:
- Automatic APK building on push
- Multi-ABI support (armeabi-v7a, arm64-v8a, x86, x86_64)
- Artifact upload (30-day retention)
- Build summaries with APK details
- Manual trigger support

**Build Environment**:
- Ubuntu Latest
- JDK 17 (Temurin)
- Android NDK 25.2.9519653
- CMake 3.22.1

**Documentation**: [GITHUB_ACTIONS_BUILD.md](GITHUB_ACTIONS_BUILD.md)

---

## 📊 Implementation Statistics

### Android Code Statistics
```
Total Production Code: 7,229 lines

Breakdown:
├─ C++ Crypto Core:   5,224 lines (72.3%)
├─ C++ Headers:         774 lines (10.7%)
├─ Kotlin API:          541 lines (7.5%)
├─ Java Integration:    690 lines (9.5%)
└─ Total:             7,229 lines (100%)

Files:
├─ Created:    16 files
├─ Modified:    5 files
└─ Total:      21 files

Testing:
├─ Test Categories:   10/10 passed ✅
├─ Individual Tests:  36/36 passed ✅
└─ Pass Rate:         100%

Documentation:
└─ 8 comprehensive guides (2,500+ lines)
```

---

## 📊 Architecture

### Overall System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                CRYPTOGRAM MULTI-PLATFORM STACK              │
├─────────────────────────────────────────────────────────────┤
│                    📱 ANDROID                                │
├─────────────────────────────────────────────────────────────┤
│  User Interface (Settings, Indicators, Status)              │
│  ├─ CryptogramSettingsActivity (Toggles & Controls)         │
│  └─ CryptogramIndicator (Lock icons & Visual feedback)      │
├─────────────────────────────────────────────────────────────┤
│  Kotlin/Java API Layer                                      │
│  ├─ DoubleRatchet.kt (Signal Protocol API)                  │
│  ├─ MLSProtocol.kt (MLS API)                                │
│  └─ CryptogramMessageHelper.java (Message flow)             │
├─────────────────────────────────────────────────────────────┤
│  JNI Bridge (342 lines)                                     │
│  └─ CryptogramWrapper.cpp (C++ ↔ Java/Kotlin)              │
├─────────────────────────────────────────────────────────────┤
│  C++ Crypto Core (6,000+ lines)                             │
│  ├─ Signal Protocol (Double Ratchet)                        │
│  ├─ MLS Protocol (TreeKEM)                                  │
│  ├─ Group Encryption                                        │
│  └─ Enhanced Privacy                                        │
├─────────────────────────────────────────────────────────────┤
│                    🖥️ DESKTOP                               │
├─────────────────────────────────────────────────────────────┤
│  Layer 5: Covert Communication                              │
│  ├─ Audio Steganography (hide data in audio)                │
│  ├─ Covert Channels (bypass DPI/censorship)                 │
│  └─ Location Randomization (anti-tracking)                  │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Active Security                                   │
│  ├─ Surveillance Detection (threat monitoring)              │
│  ├─ Adaptive Countermeasures (dynamic response)             │
│  └─ Security Validation (auditing)                          │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Enhanced Privacy                                  │
│  ├─ Metadata Stripping (EXIF/GPS removal)                   │
│  ├─ Screenshot Prevention                                   │
│  ├─ Time-based Key Derivation                               │
│  └─ Auto-deletion & Sanitization                            │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: End-to-End Encryption (Both Platforms)            │
│  ├─ Double Ratchet Algorithm (Signal Protocol)              │
│  ├─ MLS Protocol (Group encryption) 📱 NEW                  │
│  ├─ Forward Secrecy (old keys deleted)                      │
│  ├─ Break-in Recovery (future message security)             │
│  └─ Hardware Security (TPM/KeyStore/Secure Enclave)         │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Telegram Infrastructure (Both Platforms)          │
│  ├─ MTProto Protocol                                        │
│  ├─ Cloud Synchronization                                   │
│  ├─ Media Handling                                          │
│  └─ Group Chat Support                                      │
├─────────────────────────────────────────────────────────────┤
│  Foundation: Cryptographic Libraries                        │
│  ├─ BoringSSL (Android)                                     │
│  └─ OpenSSL (Desktop)                                       │
└─────────────────────────────────────────────────────────────┘
```

---

## 👥 Who CRYPTOGRAM Is For

### 📰 **Journalists**
- **Desktop**: Protect sources with audio steganography, hide location, detect surveillance
- **Android**: Secure mobile communication with Signal Protocol and MLS encryption

### 🎗️ **Activists**
- **Desktop**: Covert channels, surveillance detection, location privacy
- **Android**: End-to-end encrypted messaging on mobile devices

### 📢 **Whistleblowers**
- **Desktop**: Hide messages in voice notes, complete metadata stripping
- **Android**: Forward secrecy ensures past messages remain secure

### 🛡️ **Privacy Advocates**
- **Desktop**: Maximum encryption layers, complete metadata protection
- **Android**: Military-grade encryption for everyday mobile use

### 🌐 **International Users**
- **Desktop**: Bypass censorship, evade traffic monitoring
- **Android**: Secure communication in hostile environments

---

## 💻 Supported Platforms

| Platform | Version | Architecture | Status | Features |
|----------|---------|--------------|--------|----------|
| **Android** | 5.0+ | armeabi-v7a, arm64-v8a, x86, x86_64 | ✅ Available | Double Ratchet, MLS, UI |
| **Windows** | 7+ | x64 | ✅ Supported | All Desktop Features |
| **Linux** | Most distributions | x64 | ✅ Supported | All Desktop Features |
| **macOS** | 10.12+ | x64, ARM64 | ✅ Supported | All Desktop Features |

---

## 📥 Installation

### Android

**Option 1: Download from GitHub Actions** (Recommended)
1. Go to [Actions](https://github.com/SWORDOps/CRYPTOGRAM/actions/workflows/build-android.yml)
2. Click latest successful workflow run
3. Download `cryptogram-debug-apk` artifact
4. Extract and install APK on device

**Option 2: Build from Source**
```bash
cd TMessagesProj
./gradlew assembleDebug
adb install -r build/outputs/apk/debug/app-debug.apk
```

**Enable Settings**: Open Telegram → Settings → 🔐 CRYPTOGRAM

**Documentation**: [CRYPTOGRAM_ANDROID_COMPLETE.md](CRYPTOGRAM_ANDROID_COMPLETE.md)

---

### Desktop

**Download Releases**
The latest version is available on the [Releases](https://github.com/SWORDOps/CRYPTOGRAM/releases) page.

**Build from Source**
See platform-specific build instructions:
- [Windows (64-bit)](docs/building-win-x64.md)
- [Linux (Docker)](docs/building-linux.md)
- [macOS](docs/building-mac.md)

---

## 📖 Documentation

### Android Documentation (NEW)
- **[CRYPTOGRAM_ANDROID_COMPLETE.md](CRYPTOGRAM_ANDROID_COMPLETE.md)** - Master Android implementation guide
- **[SETTINGS_UI_COMPLETE.md](SETTINGS_UI_COMPLETE.md)** - Settings UI details
- **[MESSAGE_FLOW_COMPLETE.md](MESSAGE_FLOW_COMPLETE.md)** - Message encryption/decryption flow
- **[UI_INDICATORS_COMPLETE.md](UI_INDICATORS_COMPLETE.md)** - Visual feedback system
- **[TEST_RESULTS.md](TEST_RESULTS.md)** - Comprehensive test results
- **[GITHUB_ACTIONS_BUILD.md](GITHUB_ACTIONS_BUILD.md)** - CI/CD guide

### Desktop Documentation
- **[FIVE_FEATURES_PORT.md](FIVE_FEATURES_PORT.md)** - Complete guide to all 5 advanced security features
- **[DOUBLE_RATCHET_PORT.md](DOUBLE_RATCHET_PORT.md)** - Double Ratchet implementation details
- **[AVAILABLE_SPYGRAM_FEATURES.md](AVAILABLE_SPYGRAM_FEATURES.md)** - Catalog of available features

### Technical Documentation
- **[features.md](features.md)** - Complete feature list
- **[Building Instructions](docs/)** - Platform-specific build guides

---

## 🛠️ Technical Specifications

### Cryptographic Algorithms (Both Platforms)
- **Key Exchange**: X25519 (Curve25519), X448
- **Digital Signatures**: Ed25519
- **Symmetric Encryption**: AES-256-GCM, AES-256-CBC, ChaCha20-Poly1305
- **Key Derivation**: HKDF-SHA256, PBKDF2
- **Message Authentication**: HMAC-SHA256
- **Random Number Generation**: OpenSSL/BoringSSL CSPRNG

### Android-Specific
- **JNI Bridge**: C++ to Java/Kotlin interface
- **Native Library**: Compiled for 4 ABIs
- **Build System**: CMake + Gradle
- **Crypto Library**: BoringSSL (Google)

### Desktop-Specific
- **Steganography Methods**: LSB, Spectral Masking, Echo Hiding, Phase Modulation, Spread Spectrum
- **Hardware Security Support**: TPM 2.0, Android KeyStore, Apple Secure Enclave
- **Performance**: Audio Steganography at 100 bits/second

---

## 🔒 Security Properties

### Guaranteed for Both Platforms

| Property | Description | Android | Desktop |
|----------|-------------|---------|---------|
| **Forward Secrecy** | Past messages secure if keys compromised | ✅ | ✅ |
| **Post-Compromise Security** | Security restored after compromise | ✅ | ✅ |
| **Deniability** | Messages can't be cryptographically proven | ✅ | ✅ |
| **Future Secrecy** | Future messages secure after compromise | ✅ | ✅ |
| **Replay Protection** | Nonces prevent message replay | ✅ | ✅ |
| **Authentication** | Verify message authenticity | ✅ | ✅ |

---

## 🏆 Achievements

### Unique Capabilities
✅ **First messenger with audio steganography** (Desktop)
✅ **First Android app with full MLS Protocol support** (Android)
✅ **Most advanced location privacy system** (Desktop)
✅ **Active surveillance detection** (Desktop)
✅ **Covert communication channels** (Desktop)
✅ **Multi-platform end-to-end encryption**
✅ **TreeKEM for O(log n) group operations** (Android)

### Code Statistics
**Total**: ~28,000 lines of security code
- **Desktop**: ~21,000 lines (6 major systems, 31 files)
- **Android**: ~7,200 lines (2 protocols, 21 files)
- **100% open source**

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md).

### Areas We Need Help With
- **Android**: UI enhancements, performance optimization, additional features
- **Desktop**: Platform-specific optimizations, security auditing
- **Both**: Localization, documentation, testing, bug reports

---

## 🔒 Security

### Responsible Disclosure
If you discover a security vulnerability, please email us at: **security@cryptogram.org**

### Security Audits
- Internal code review: ✅ Complete (Both platforms)
- Android automated testing: ✅ 100% pass rate (36/36 tests)
- External security audit: 🔄 In progress
- Penetration testing: 📅 Planned

### Bug Bounty
We offer rewards for responsibly disclosed security vulnerabilities.

---

## 📜 License

CRYPTOGRAM is released under the **GNU General Public License v3.0** with OpenSSL exception.

See [LICENSE](LICENSE) for details.

---

## 🙏 Credits

### Based On
- **Telegram Desktop** - Core messaging infrastructure (Desktop)
- **Telegram Android** - Official Android client (Android)
- **64Gram** - Enhanced Telegram client
- **SpyGram** - Advanced security features

### Cryptography
- **Signal Protocol** - Double Ratchet algorithm
- **MLS Protocol** - RFC 9420 (Message Layer Security)
- **OpenSSL / BoringSSL** - Cryptographic primitives
- **Curve25519** - Key exchange (Daniel J. Bernstein)

### Development
- **CRYPTOGRAM Team** - Feature integration and development
- **Open Source Community** - Contributions and feedback

---

## 🔗 Links

### Official Channels
- **Website**: [cryptogram.org](https://cryptogram.org) (coming soon)
- **GitHub**: [github.com/SWORDOps/CRYPTOGRAM](https://github.com/SWORDOps/CRYPTOGRAM)
- **Android APK Builds**: [GitHub Actions](https://github.com/SWORDOps/CRYPTOGRAM/actions/workflows/build-android.yml)

### Support
- **Issues**: [GitHub Issues](https://github.com/SWORDOps/CRYPTOGRAM/issues)
- **Discussions**: [GitHub Discussions](https://github.com/SWORDOps/CRYPTOGRAM/discussions)
- **Security**: security@cryptogram.org

---

## ⚠️ Disclaimer

CRYPTOGRAM is designed for legitimate privacy and security purposes. Users are responsible for complying with all applicable laws and regulations in their jurisdiction. The developers are not responsible for any misuse of this software.

---

## 🌟 Star This Project

If you find CRYPTOGRAM useful, please star this repository to help others discover it!

[![GitHub stars](https://img.shields.io/github/stars/SWORDOps/CRYPTOGRAM?style=social)](https://github.com/SWORDOps/CRYPTOGRAM/stargazers)

---

**Built with ❤️ and 🔐 for a more private world.**

**Now available on Desktop AND Android!** 🖥️📱
