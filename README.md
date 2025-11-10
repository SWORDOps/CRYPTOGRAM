# 🔐 CRYPTOGRAM

**Military-grade secure messenger combining Telegram's infrastructure with advanced cryptography**

[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20Android-lightgrey.svg)](#platforms)
[![Security](https://img.shields.io/badge/security-military--grade-green.svg)](#security)
[![Build Android](https://github.com/SWORDOps/CRYPTOGRAM/workflows/Build%20CRYPTOGRAM%20Android%20APK/badge.svg)](https://github.com/SWORDOps/CRYPTOGRAM/actions)

CRYPTOGRAM provides military-grade encryption and advanced privacy features for journalists, activists, whistleblowers, and anyone who values digital privacy.

---

## 🌟 Key Features

| Feature | Description | Platforms |
|---------|-------------|-----------|
| **End-to-End Encryption** | Signal Protocol + MLS | 🖥️ 📱 |
| **Post-Quantum Security** | ML-KEM-1024 + ML-DSA-87 | 🖥️ 📱 |
| **Audio Steganography** | Hide messages in voice notes | 🖥️ |
| **Location Privacy** | Randomize GPS coordinates | 🖥️ |
| **Surveillance Detection** | Detect monitoring attempts | 🖥️ |
| **Tor/I2P Integration** | Anonymous routing | 🖥️ |
| **Hardware Security** | TPM/KeyStore integration | 🖥️ 📱 |
| **Premium Features** | All Telegram Premium features | 🖥️ 📱 |

🖥️ = Desktop (Windows/Linux/macOS) | 📱 = Android

---

## 🚀 Quick Start

### Android
```bash
# Download latest APK from GitHub Actions
wget https://github.com/SWORDOps/CRYPTOGRAM/actions/workflows/build-android.yml

# Install
adb install cryptogram-debug.apk

# Enable encryption
# Settings → 🔐 CRYPTOGRAM → Enable features
```

### Desktop
```bash
# Download from releases
https://github.com/SWORDOps/CRYPTOGRAM/releases

# Or build from source
git clone https://github.com/SWORDOps/CRYPTOGRAM
cd CRYPTOGRAM
# See docs/setup/ for build instructions
```

---

## 📱 Platforms

### 🖥️ CRYPTOGRAM Desktop
**Windows 10/11, Linux, macOS 10.15+**

Full-featured desktop client with advanced security:

**Core Encryption**:
- Signal Protocol (Double Ratchet)
- MLS Protocol (RFC 9420)
- Post-Quantum Cryptography (ML-KEM-1024, ML-DSA-87)

**Advanced Security**:
- Audio Steganography (8 methods, 40dB SNR)
- Location Randomization (realistic fake GPS)
- Surveillance Detection (debugger/VM/monitoring detection)
- Covert Channels (DPI-resistant communication)
- Enhanced Privacy (metadata stripping)

**Network Privacy**:
- Tor Integration (SOCKS5 + Snowflake bridges)
- I2P Integration (Garlic routing)

**Optional Features**:
- OpenVINO Translation (100+ languages, offline)
- Monero Mining (optional, configurable)

**Premium Override**:
- All Telegram Premium features enabled for testing

[📖 Desktop Features Guide](docs/features/desktop-features.md)

---

### 📱 CRYPTOGRAM Android
**Android 5.0+ (API 21+)**

Mobile security with military-grade encryption:

**Core Encryption**:
- Signal Protocol (X25519, Ed25519, AES-256-GCM)
- MLS Protocol (TreeKEM for groups)
- Post-Quantum (ML-KEM-1024, ML-DSA-87)

**Privacy**:
- Hardware KeyStore integration
- Metadata stripping (EXIF, GPS)
- Visual encryption indicators (lock icons)

**Premium Override**:
- All Telegram Premium features enabled for testing

**Architecture Support**:
- armeabi-v7a, arm64-v8a, x86, x86_64

[📖 Android Features Guide](docs/features/android-features.md) | [📥 Download APK](https://github.com/SWORDOps/CRYPTOGRAM/actions/workflows/build-android.yml)

---

## 🔒 Security

### Cryptographic Primitives

**Symmetric Encryption**:
- AES-256-GCM (authenticated encryption)
- ChaCha20-Poly1305 (alternative cipher)

**Asymmetric Cryptography**:
- X25519 (Diffie-Hellman key exchange)
- Ed25519 (digital signatures)

**Post-Quantum**:
- ML-KEM-1024 (Kyber, NIST approved)
- ML-DSA-87 (Dilithium, NIST approved)

**Hashing & KDF**:
- SHA-256, SHA-512, BLAKE2b
- HKDF-SHA256 (key derivation)

### Security Properties

✅ **Forward Secrecy** - Past messages safe if keys compromised
✅ **Post-Compromise Security** - Future messages safe after compromise
✅ **Deniability** - Cannot prove who sent a message
✅ **Quantum Resistance** - Protected against quantum computers
✅ **Hardware Security** - TPM/KeyStore integration
✅ **Metadata Protection** - GPS, EXIF, timestamp stripping

[📖 Security Overview](docs/features/security-overview.md)

---

## 🎯 Use Cases

### 📰 Journalists
- **Protect Sources**: Audio steganography for covert messages
- **Location Privacy**: Randomize GPS when meeting sources
- **Anti-Surveillance**: Detect monitoring attempts

### 🎗️ Activists
- **Secure Groups**: MLS protocol for encrypted group chats
- **Bypass Censorship**: Tor/I2P integration
- **Privacy Protection**: Location randomization, metadata stripping

### 📢 Whistleblowers
- **Anonymous Communication**: Tor routing + covert channels
- **Plausible Deniability**: Hidden messages in audio
- **Forward Secrecy**: Past messages protected

### 🛡️ Privacy Advocates
- **Maximum Encryption**: All protocols enabled
- **Post-Quantum Security**: Future-proof cryptography
- **Hardware Security**: TPM/KeyStore integration

### 🌐 Users in Restrictive Countries
- **Bypass DPI**: Covert channel engine
- **Traffic Obfuscation**: Protocol mimicry
- **Anonymous Access**: Tor/I2P networks

---

## 📖 Documentation

### Getting Started
- [Android Features](docs/features/android-features.md) - Complete Android feature guide
- [Desktop Features](docs/features/desktop-features.md) - Complete desktop feature guide
- [Security Overview](docs/features/security-overview.md) - Security architecture & threat model

### Building from Source
- [Windows Build Guide](docs/setup/building-win-x64.md)
- [Linux Build Guide](docs/setup/building-linux.md)
- [macOS Build Guide](docs/setup/building-mac.md)
- [API Credentials](docs/setup/api_credentials.md)

### Development
- [CHANGELOG](CHANGELOG.md) - Version history
- [SECURITY](SECURITY_STANDARDS.md) - Security standards
- [GitHub Actions](docs/archive/GITHUB_ACTIONS_BUILD.md) - CI/CD pipeline

### Archived Documentation
See [docs/archive/](docs/archive/) for historical documentation.

---

## 🤝 Contributing

We welcome contributions in:

**Android**:
- UI/UX improvements
- Performance optimization
- New encryption features
- Bug fixes

**Desktop**:
- Platform-specific features
- Security enhancements
- Performance improvements

**Both**:
- Documentation
- Translations
- Testing
- Bug reports

**How to Contribute**:
1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

[📖 Contributing Guidelines](CONTRIBUTING.md) (coming soon)

---

## 📜 License

CRYPTOGRAM is released under the **GNU General Public License v3.0** with OpenSSL exception.

This means:
- ✅ Free to use, modify, distribute
- ✅ Must share source code modifications
- ✅ Must use same GPL license
- ✅ No warranty provided

See [LICENSE](LICENSE) for full details.

---

## 🙏 Credits

**Based On**:
- [Telegram Desktop](https://github.com/telegramdesktop/tdesktop) - Core messaging infrastructure
- [Telegram Android](https://github.com/DrKLO/Telegram) - Android client base
- [64Gram](https://github.com/TDesktop-x64/tdesktop) - Enhanced Telegram client

**Cryptography**:
- [Signal Protocol](https://signal.org/docs/) - Double Ratchet algorithm
- [MLS Protocol](https://messaginglayersecurity.rocks/) - RFC 9420 group encryption
- [BoringSSL](https://boringssl.googlesource.com/boringssl/) - Cryptographic primitives
- [OpenSSL](https://www.openssl.org/) - Additional crypto support

**Post-Quantum**:
- [NIST PQC](https://csrc.nist.gov/projects/post-quantum-cryptography) - ML-KEM, ML-DSA standards

**Development**:
- CRYPTOGRAM Team - Integration and advanced features
- Open Source Community - Contributions and feedback

---

## 🔗 Links

- **GitHub**: [github.com/SWORDOps/CRYPTOGRAM](https://github.com/SWORDOps/CRYPTOGRAM)
- **Releases**: [GitHub Releases](https://github.com/SWORDOps/CRYPTOGRAM/releases)
- **Android Builds**: [GitHub Actions](https://github.com/SWORDOps/CRYPTOGRAM/actions/workflows/build-android.yml)
- **Issues**: [GitHub Issues](https://github.com/SWORDOps/CRYPTOGRAM/issues)
- **Discussions**: [GitHub Discussions](https://github.com/SWORDOps/CRYPTOGRAM/discussions)
- **Security**: security@cryptogram.org

---

## ⚠️ Disclaimer

CRYPTOGRAM is designed for legitimate privacy and security purposes. Users are responsible for complying with all applicable laws and regulations in their jurisdiction.

**Important**:
- Not audited by external security experts yet
- Use at your own risk
- Good for: Journalists, activists, privacy advocates
- Not recommended for: National security secrets (until audited)

---

## 🌟 Star This Project

If CRYPTOGRAM helps protect your privacy, please star this repository!

[![GitHub stars](https://img.shields.io/github/stars/SWORDOps/CRYPTOGRAM?style=social)](https://github.com/SWORDOps/CRYPTOGRAM/stargazers)

---

## 📊 Project Status

| Component | Status | Version |
|-----------|--------|---------|
| Desktop (Windows) | ✅ Stable | 1.0.0 |
| Desktop (Linux) | ✅ Stable | 1.0.0 |
| Desktop (macOS) | ✅ Stable | 1.0.0 |
| Android | ✅ Stable | 1.0.0 |
| Signal Protocol | ✅ Implemented | - |
| MLS Protocol | ✅ Implemented | - |
| Post-Quantum | ✅ Implemented | - |
| Audio Steganography | ✅ Implemented (Desktop) | - |
| Location Privacy | ✅ Implemented (Desktop) | - |
| Surveillance Detection | ✅ Implemented (Desktop) | - |
| Tor/I2P | ✅ Implemented (Desktop) | - |
| Premium Override | ✅ Implemented | - |
| External Audit | ⏳ Planned | - |
| Bug Bounty | ⏳ Coming Soon | - |

---

**Built with ❤️ and 🔐 for a more private world**

**Available on Desktop and Android** 🖥️ 📱
