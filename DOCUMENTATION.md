# 📚 CRYPTOGRAM Documentation Guide

**Complete documentation index for CRYPTOGRAM project**

This guide helps you navigate all documentation in the CRYPTOGRAM repository.

---

## 🚀 Quick Start

**New to CRYPTOGRAM?** Start here:

1. **[README.md](README.md)** - Project overview, features, and quick start guide
2. **[CHANGELOG.md](CHANGELOG.md)** - Version history and recent changes
3. **[docs/implementation/CRYPTOGRAM_ANDROID_COMPLETE.md](docs/implementation/CRYPTOGRAM_ANDROID_COMPLETE.md)** - Android implementation guide
4. **[docs/implementation/FIVE_FEATURES_PORT.md](docs/implementation/FIVE_FEATURES_PORT.md)** - Desktop advanced features

---

## 📂 Documentation Structure

```
CRYPTOGRAM/
├── README.md                          # Main project documentation
├── CHANGELOG.md                       # Version history
├── DOCKER_BUILD.md                    # Docker build system guide
├── GITHUB_ACTIONS_BUILD.md            # CI/CD pipeline documentation
├── DOCUMENTATION.md                   # This file - documentation index
│
├── docs/
│   ├── building-linux.md              # Linux native build guide
│   ├── building-mac.md                # macOS native build guide
│   ├── building-win-x64.md            # Windows x64 build guide
│   ├── building-win.md                # Windows general build guide
│   ├── building-mas.md                # Mac App Store build guide
│   ├── api_credentials.md             # Telegram API setup
│   ├── misc.txt                       # Miscellaneous notes
│   │
│   ├── implementation/                # Implementation documentation
│   │   ├── CRYPTOGRAM_ANDROID_COMPLETE.md
│   │   ├── CRYPTOGRAM_ANDROID_PORT.md
│   │   ├── DOUBLE_RATCHET_PORT.md
│   │   ├── FIVE_FEATURES_PORT.md
│   │   ├── SECOND_WAVE_FEATURES_PORT.md
│   │   ├── MESSAGE_FLOW_COMPLETE.md
│   │   ├── SETTINGS_UI_COMPLETE.md
│   │   ├── UI_INDICATORS_COMPLETE.md
│   │   ├── I2P_INTEGRATION.md
│   │   ├── MONERO_MINING_INTEGRATION.md
│   │   └── GPU_MINING_SUPPORT.md
│   │
│   ├── status/                        # Project status reports
│   │   ├── FINAL_STATUS.md
│   │   ├── TEST_RESULTS.md
│   │   └── TESTING_PLAN.md
│   │
│   ├── features/                      # Feature documentation
│   │   ├── AVAILABLE_SPYGRAM_FEATURES.md
│   │   ├── ADDITIONAL_FEATURES_AVAILABLE.md
│   │   ├── CRYPTOGRAM_SETTINGS_UI_MOCKUP.md
│   │   └── features.md
│   │
│   └── dev/                           # Developer documentation
│       ├── PULL_REQUEST.md
│       ├── PUSH_INSTRUCTIONS.md
│       └── SECURITY_STANDARDS.md
```

---

## 📱 Platform-Specific Documentation

### Android Development

| Document | Description |
|----------|-------------|
| [CRYPTOGRAM_ANDROID_COMPLETE.md](docs/implementation/CRYPTOGRAM_ANDROID_COMPLETE.md) | Complete Android implementation with Signal/MLS protocols |
| [CRYPTOGRAM_ANDROID_PORT.md](docs/implementation/CRYPTOGRAM_ANDROID_PORT.md) | Android porting guide |
| [SETTINGS_UI_COMPLETE.md](docs/implementation/SETTINGS_UI_COMPLETE.md) | Android settings UI implementation |
| [UI_INDICATORS_COMPLETE.md](docs/implementation/UI_INDICATORS_COMPLETE.md) | Visual encryption indicators |
| [GITHUB_ACTIONS_BUILD.md](GITHUB_ACTIONS_BUILD.md) | Automated APK building |

### Desktop Development

| Document | Description |
|----------|-------------|
| [FIVE_FEATURES_PORT.md](docs/implementation/FIVE_FEATURES_PORT.md) | Advanced desktop security features |
| [SECOND_WAVE_FEATURES_PORT.md](docs/implementation/SECOND_WAVE_FEATURES_PORT.md) | Additional desktop features |
| [docs/building-linux.md](docs/building-linux.md) | Linux native build instructions |
| [docs/building-mac.md](docs/building-mac.md) | macOS native build instructions |
| [docs/building-win-x64.md](docs/building-win-x64.md) | Windows build instructions |
| [DOCKER_BUILD.md](DOCKER_BUILD.md) | Multi-platform Docker builds |

---

## 🔐 Security & Cryptography

### Core Cryptography

| Document | Description |
|----------|-------------|
| [DOUBLE_RATCHET_PORT.md](docs/implementation/DOUBLE_RATCHET_PORT.md) | Signal Protocol (Double Ratchet) implementation |
| [CRYPTOGRAM_ANDROID_COMPLETE.md#mls-protocol](docs/implementation/CRYPTOGRAM_ANDROID_COMPLETE.md#mls-protocol) | MLS Protocol for group encryption |
| [MESSAGE_FLOW_COMPLETE.md](docs/implementation/MESSAGE_FLOW_COMPLETE.md) | Encryption/decryption message flow |
| [SECURITY_STANDARDS.md](docs/dev/SECURITY_STANDARDS.md) | Security standards and best practices |

### Advanced Security Features

| Feature | Documentation |
|---------|--------------|
| **Audio Steganography** | [FIVE_FEATURES_PORT.md#1](docs/implementation/FIVE_FEATURES_PORT.md#1--audio-steganography-engine) |
| **Location Randomization** | [FIVE_FEATURES_PORT.md#2](docs/implementation/FIVE_FEATURES_PORT.md#2--location-randomization-system) |
| **Surveillance Detection** | [FIVE_FEATURES_PORT.md#3](docs/implementation/FIVE_FEATURES_PORT.md#3--surveillance-detection-system) |
| **Covert Channels** | [FIVE_FEATURES_PORT.md#4](docs/implementation/FIVE_FEATURES_PORT.md#4--covert-channel-engine) |
| **Enhanced Privacy** | [FIVE_FEATURES_PORT.md#5](docs/implementation/FIVE_FEATURES_PORT.md#5--enhanced-privacy-system) |
| **Privacy Controls** | [docs/features/](docs/features/) - Hide online status, typing, read receipts |

---

## 🛠️ Building & Deployment

### Build Systems

| Document | Description | Platforms |
|----------|-------------|-----------|
| [DOCKER_BUILD.md](DOCKER_BUILD.md) | Docker-based multi-platform builds | Linux, Windows (cross-compile) |
| [GITHUB_ACTIONS_BUILD.md](GITHUB_ACTIONS_BUILD.md) | Automated CI/CD pipeline | Android APK builds |
| [docs/building-linux.md](docs/building-linux.md) | Native Linux build | Linux (Ubuntu, Debian, etc.) |
| [docs/building-mac.md](docs/building-mac.md) | Native macOS build | macOS x64, ARM64 |
| [docs/building-win-x64.md](docs/building-win-x64.md) | Native Windows build | Windows 10+ x64 |

### Build Prerequisites

**All platforms need:**
- Telegram API credentials - see [docs/api_credentials.md](docs/api_credentials.md)

**Platform-specific:**
- **Linux**: CMake 3.25+, Qt 5.15+, Clang/GCC
- **Windows**: Visual Studio 2022, Qt 6.5+, CMake 3.25+
- **macOS**: Xcode 14+, Qt 6.5+, CMake 3.25+
- **Android**: Android Studio, NDK 25, CMake 3.22+

---

## 🎯 Feature Documentation

### Network Anonymity

| Document | Description |
|----------|-------------|
| [I2P_INTEGRATION.md](docs/implementation/I2P_INTEGRATION.md) | I2P (Invisible Internet Project) integration |
| Tor support | Built-in (see Settings → CRYPTOGRAM) |

### Privacy Features

| Feature | Platform | Documentation |
|---------|----------|--------------|
| Hide Online Status | Desktop, Android | [docs/features/](docs/features/) |
| Hide Typing Indicator | Desktop, Android | [docs/features/](docs/features/) |
| Hide Read Receipts | Desktop, Android | [docs/features/](docs/features/) |
| Location Randomization | Desktop | [FIVE_FEATURES_PORT.md#2](docs/implementation/FIVE_FEATURES_PORT.md#2--location-randomization-system) |
| Audio Steganography | Desktop | [FIVE_FEATURES_PORT.md#1](docs/implementation/FIVE_FEATURES_PORT.md#1--audio-steganography-engine) |

### Mining & Development Support

| Document | Description |
|----------|-------------|
| [MONERO_MINING_INTEGRATION.md](docs/implementation/MONERO_MINING_INTEGRATION.md) | CPU-based Monero mining for development support |
| [GPU_MINING_SUPPORT.md](docs/implementation/GPU_MINING_SUPPORT.md) | GPU mining capabilities |

---

## 📊 Testing & Status

### Test Documentation

| Document | Description |
|----------|-------------|
| [TEST_RESULTS.md](docs/status/TEST_RESULTS.md) | Comprehensive test results and coverage |
| [TESTING_PLAN.md](docs/status/TESTING_PLAN.md) | Testing strategy and test plans |

### Project Status

| Document | Description |
|----------|-------------|
| [FINAL_STATUS.md](docs/status/FINAL_STATUS.md) | Current implementation status |
| [CHANGELOG.md](CHANGELOG.md) | Version history and changes |

---

## 👨‍💻 Developer Documentation

### Contributing

| Document | Description |
|----------|-------------|
| [PULL_REQUEST.md](docs/dev/PULL_REQUEST.md) | How to create pull requests |
| [PUSH_INSTRUCTIONS.md](docs/dev/PUSH_INSTRUCTIONS.md) | Git workflow and push instructions |
| [SECURITY_STANDARDS.md](docs/dev/SECURITY_STANDARDS.md) | Security coding standards |

### Available Features

| Document | Description |
|----------|-------------|
| [AVAILABLE_SPYGRAM_FEATURES.md](docs/features/AVAILABLE_SPYGRAM_FEATURES.md) | SpyGram features available in CRYPTOGRAM |
| [ADDITIONAL_FEATURES_AVAILABLE.md](docs/features/ADDITIONAL_FEATURES_AVAILABLE.md) | Additional features that can be ported |
| [features.md](docs/features/features.md) | Feature list and roadmap |

---

## 🔍 Finding Documentation

### By Topic

- **"How do I build CRYPTOGRAM?"** → See [Building & Deployment](#-building--deployment)
- **"What encryption does CRYPTOGRAM use?"** → See [Security & Cryptography](#-security--cryptography)
- **"How do I contribute?"** → See [Developer Documentation](#-developer-documentation)
- **"What features does Android have?"** → See [CRYPTOGRAM_ANDROID_COMPLETE.md](docs/implementation/CRYPTOGRAM_ANDROID_COMPLETE.md)
- **"What advanced features are on Desktop?"** → See [FIVE_FEATURES_PORT.md](docs/implementation/FIVE_FEATURES_PORT.md)

### By Platform

- **Android** → [Platform-Specific: Android](#android-development)
- **Desktop (Linux/Windows/macOS)** → [Platform-Specific: Desktop](#desktop-development)
- **All Platforms** → [README.md](README.md)

---

## 📞 Support & Contact

- **Security Issues**: security@cryptogram.org
- **Bug Reports**: [GitHub Issues](https://github.com/SWORDOps/CRYPTOGRAM/issues)
- **Discussions**: [GitHub Discussions](https://github.com/SWORDOps/CRYPTOGRAM/discussions)
- **Documentation Improvements**: Submit PR with changes

---

## 📝 Documentation Standards

### For Contributors

When adding new documentation:

1. **User-facing docs** (README, guides) → Place in root or `docs/`
2. **Implementation details** → Place in `docs/implementation/`
3. **Project status/reports** → Place in `docs/status/`
4. **Feature proposals** → Place in `docs/features/`
5. **Developer guides** → Place in `docs/dev/`

### Markdown Style

- Use clear, descriptive headers
- Include code examples where applicable
- Link to related documentation
- Keep table of contents updated
- Use emoji sparingly for visual organization

---

## 🔗 External Resources

- **Telegram Desktop**: https://github.com/telegramdesktop/tdesktop
- **Signal Protocol**: https://signal.org/docs/
- **MLS Protocol**: https://messaginglayersecurity.rocks/
- **Docker Documentation**: https://docs.docker.com/
- **GitHub Actions**: https://docs.github.com/en/actions

---

## 📅 Last Updated

**Date**: 2025-11-09

This documentation index is maintained alongside the CRYPTOGRAM project. For the most up-to-date information, always check the [GitHub repository](https://github.com/SWORDOps/CRYPTOGRAM).

---

**🔐 CRYPTOGRAM - Military-Grade Secure Messaging**

Built with 🔐 for a more private world.
