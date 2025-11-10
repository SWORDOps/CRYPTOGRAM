# 🔐 CRYPTOGRAM Is WIP not complete and use it at your own peril in this 95% state which im sure will persist at 90%,maybe 80% for weeks.


**Military-grade secure messenger combining Telegram's infrastructure with advanced privacy technology**

[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20Android-lightgrey.svg)](#platforms)
[![Security](https://img.shields.io/badge/security-military--grade-green.svg)](#security)

CRYPTOGRAM goes beyond traditional encrypted messaging with advanced features for journalists, activists, whistleblowers, and anyone who values digital privacy like **that one guy whose account has been banned 150 times**

---

## What Makes CRYPTOGRAM Different?

| Feature | Signal | WhatsApp | Telegram | CRYPTOGRAM |
|---------|--------|----------|----------|------------|
| End-to-End Encryption | ✅ | ✅ | 🟡 Secret Chats Only(lol) | ✅ |
| Post-Quantum Cryptography | ❌ | ❌ | ❌ | ✅ **UNIQUE** |
| AES-256-GCM Encryption | ✅ | ✅ | 🟡 | ✅ |
| Signal Protocol | ✅ | ✅ | ❌ | ✅ |
| MLS Group Encryption | ❌ | ❌ | ❌ | ✅ |
| Hide Messages in Audio | ❌ | ❌ | ❌ | ✅ Desktop |
| Location Randomization | ❌ | ❌ | ❌ | ✅ Desktop |
| Surveillance Detection | ❌ | ❌ | ❌ | ✅ Desktop |
| Hardware Security (TPM/KeyStore) | ❌ | ❌ | ❌ | ✅ |
| Metadata Stripping | 🟡 | ❌ | ❌ | ✅ |
| Hide Online Status | ❌ | ❌ | ❌ | ✅ **UNIQUE** |
| Hide Typing Indicator | ❌ | ❌ | ❌ | ✅ **UNIQUE** |
| Hide Read Receipts | ❌ | ❌ | ❌ | ✅ **UNIQUE** |

---

## 📱 Platforms

### 🖥️ CRYPTOGRAM Desktop
**For Windows, Linux, and macOS**

Advanced privacy features for high-security communication:
- **Post-Quantum Secure** - ML-KEM-1024 + ML-DSA-87 (quantum-resistant encryption)
- **Audio Steganography** - Hide encrypted messages inside voice notes
- **Location Randomization** - Prevent geolocation tracking with realistic fake locations
- **Surveillance Detection** - Detect debuggers, monitoring tools, and suspicious activity
- **Covert Channels** - Bypass censorship and deep packet inspection
- **Enhanced Privacy** - Extra encryption layers and metadata protection
- **Privacy Controls** - Hide online status, typing indicator, and read receipts
- **Double Ratchet + MLS** - Signal Protocol with AES-256-GCM encryption

[📥 Download Desktop](https://github.com/SWORDOps/CRYPTOGRAM/releases) | [📖 Desktop Features](docs/implementation/FIVE_FEATURES_PORT.md)

---

### 📱 CRYPTOGRAM Android
**For Android 5.0+**

Military-grade encryption for mobile messaging:
- **Post-Quantum Secure** - ML-KEM-1024 (Kyber) + ML-DSA-87 (Dilithium)
- **Signal Protocol** - End-to-end encryption with forward secrecy (1-on-1 chats)
- **MLS Protocol** - Scalable group encryption with TreeKEM (group chats)
- **AES-256-GCM** - 256-bit keys derived via HKDF-SHA256
- **Hardware KeyStore** - Secure key storage in Android's hardware security
- **Visual Indicators** - Lock icons show encryption status
- **Privacy Controls** - Hide online status, typing indicator, and read receipts
- **Seamless Integration** - Works automatically with your existing chats

[📥 Download Android APK](https://github.com/SWORDOps/CRYPTOGRAM/actions/workflows/build-android.yml) | [📖 Android Features](docs/implementation/CRYPTOGRAM_ANDROID_COMPLETE.md)

---

## 🚀 Quick Start

### Android Installation

1. Download the latest APK from [GitHub Actions](https://github.com/SWORDOps/CRYPTOGRAM/actions/workflows/build-android.yml)
2. Install on your device
3. Open Telegram → Settings → 🔐 CRYPTOGRAM
4. Enable encryption features

See [Android installation guide](docs/implementation/CRYPTOGRAM_ANDROID_COMPLETE.md#installation) for details.

### Desktop Installation

**Download from [Releases](https://github.com/SWORDOps/CRYPTOGRAM/releases)**

Or build from source:
- [Windows Build Guide](docs/building-win-x64.md)
- [Linux Build Guide](docs/building-linux.md)
- [macOS Build Guide](docs/building-mac.md)

---

## 🎯 Who Is CRYPTOGRAM For?

### 📰 Journalists
Protect sources with covert communication channels and surveillance detection.

### 🎗️ Activists
Bypass censorship and avoid location tracking in hostile environments.

### 📢 Whistleblowers
Hide messages in voice notes with audio steganography and ensure forward secrecy.

### 🛡️ Privacy Advocates
Maximum encryption with metadata protection and hardware-backed security.

### 🌐 Users in Restrictive Countries
Evade deep packet inspection and traffic monitoring with covert channels.

---

## 🔒 Security

CRYPTOGRAM provides multiple layers of security:

**Post-Quantum Cryptography** 🆕
- **ML-KEM-1024** (Kyber) - Quantum-resistant key encapsulation
- **ML-DSA-87** (Dilithium) - Quantum-resistant digital signatures
- **HKDF-SHA256** - Derives 256-bit encryption keys from shared secrets
- **Hybrid Scheme** - Combines post-quantum with classical crypto for maximum security

**Encryption Protocols**
- Signal Protocol (Double Ratchet) for 1-on-1 chats
- MLS Protocol (RFC 9420) for group chats
- X25519 key exchange, AES-256-GCM encryption
- Forward secrecy and post-compromise security

**Privacy Protection**
- Metadata stripping (EXIF, GPS, timestamps)
- Hardware security module integration
- Automatic key deletion after use
- Break-in recovery for future messages

**Desktop Advanced Features**
- Audio steganography (8 methods, statistically undetectable)
- Active surveillance detection
- Location privacy with realistic decoys
- DPI-resistant covert channels

See [technical specifications](docs/implementation/CRYPTOGRAM_ANDROID_COMPLETE.md#cryptographic-algorithms) for details.

### Responsible Disclosure

Found a security issue? Email: **intel@swordintelligence.airforce**

Alternatively just abuse the damn thing like i just know you will.

---

## 📖 Documentation

### Getting Started
- **[Android Guide](docs/implementation/CRYPTOGRAM_ANDROID_COMPLETE.md)** - Complete Android implementation and features
- **[Desktop Features](docs/implementation/FIVE_FEATURES_PORT.md)** - Advanced security features guide
- **[Building Instructions](docs/)** - Platform-specific build guides
- **[Docker Build Guide](DOCKER_BUILD.md)** - Multi-platform Docker builds
- **[GitHub Actions CI/CD](GITHUB_ACTIONS_BUILD.md)** - Automated builds

### Technical Details
- **[Signal Protocol Implementation](docs/implementation/DOUBLE_RATCHET_PORT.md)** - Double Ratchet details
- **[MLS Protocol](docs/implementation/CRYPTOGRAM_ANDROID_COMPLETE.md#mls-protocol)** - Group encryption specification
- **[Message Flow](docs/implementation/MESSAGE_FLOW_COMPLETE.md)** - Encryption/decryption flow
- **[Test Results](docs/status/TEST_RESULTS.md)** - Comprehensive test coverage
- **[Implementation Status](docs/status/FINAL_STATUS.md)** - Current project status

### Feature Documentation
- **[Audio Steganography](docs/implementation/FIVE_FEATURES_PORT.md#1--audio-steganography-engine)** - Hide messages in audio
- **[Location Randomization](docs/implementation/FIVE_FEATURES_PORT.md#2--location-randomization-system)** - Anti-tracking system
- **[Surveillance Detection](docs/implementation/FIVE_FEATURES_PORT.md#3--surveillance-detection-system)** - Threat monitoring
- **[Covert Channels](docs/implementation/FIVE_FEATURES_PORT.md#4--covert-channel-engine)** - Censorship bypass
- **[Enhanced Privacy](docs/implementation/FIVE_FEATURES_PORT.md#5--enhanced-privacy-system)** - Extra protection layers
- **[Privacy Controls](docs/features/)** - Online status, typing indicators, read receipts

---

## 🤝 Contributing

I welcome contributions like seriously someone send help! Areas that are needed:

- **Android**: UI enhancements, performance optimization, new features
- **Desktop**: Platform-specific improvements, security auditing
- **Both**: Localization, documentation, testing, bug reports
- **Mac OSX**: Like....just everything.

See [Contributing Guidelines](CONTRIBUTING.md) to get started.

---

## 📜 License

CRYPTOGRAM is released under the **GNU General Public License v3.0** with OpenSSL exception.

See [LICENSE](LICENSE) for full details.

---

## 🙏 Credits

**Based On**
- Telegram Desktop & Android - Core messaging infrastructure
- 64Gram - Enhanced Telegram client
- SpyGram - Advanced security features

**Cryptography**
- Signal Protocol - Double Ratchet algorithm
- MLS Protocol - RFC 9420 (Message Layer Security)
- OpenSSL / BoringSSL - Cryptographic primitives

**Development**
- CRYPTOGRAM Team - Integration and development
- Open Source Community - Contributions and feedback

---

## 🔗 Links

- **GitHub**: [github.com/SWORDOps/CRYPTOGRAM](https://github.com/SWORDOps/CRYPTOGRAM)
- **Android Builds**: [GitHub Actions](https://github.com/SWORDOps/CRYPTOGRAM/actions/workflows/build-android.yml)
- **Issues**: [GitHub Issues](https://github.com/SWORDOps/CRYPTOGRAM/issues)
- **Discussions**: [GitHub Discussions](https://github.com/SWORDOps/CRYPTOGRAM/discussions)
- **Security**: intel@swordintelligence.airforce

---

## ⚠️ Disclaimer

CRYPTOGRAM is designed for legitimate privacy and security purposes. Users are responsible for complying with all applicable laws and regulations in their jurisdiction(that being said if your jurisidiction forbids encryption they can bite me)

---

## 🌟 Star This Project

If CRYPTOGRAM helps protect your privacy, please star this repository and/or turn up the optional XMR idle cpu usage in options or just straight up give me money like god please

[![GitHub stars](https://img.shields.io/github/stars/SWORDOps/CRYPTOGRAM?style=social)](https://github.com/SWORDOps/CRYPTOGRAM/stargazers)

---

**Built with 🖕 and 🔐 for a more private world and because i warned em to stop banning my account**

**Available on Desktop and Android for now** 🖥️ 📱
