# CRYPTOGRAM Documentation

Complete documentation for CRYPTOGRAM encrypted messenger.

---

## 📚 Documentation Structure

### 🚀 Getting Started

#### Setup Guides
Platform-specific build and installation instructions:
- [Windows Build Guide](setup/building-win-x64.md)
- [Linux Build Guide](setup/building-linux.md)
- [macOS Build Guide](setup/building-mac.md)
- [macOS App Store](setup/building-mas.md)
- [API Credentials](setup/api_credentials.md)

---

### 🔐 Features

Complete feature documentation for all platforms:

- **[Android Features](features/android-features.md)**
  - Signal Protocol (Double Ratchet)
  - MLS Protocol (Group encryption)
  - Post-Quantum cryptography
  - Hardware KeyStore integration
  - Premium features override
  - Visual indicators

- **[Desktop Features](features/desktop-features.md)**
  - All Android features plus:
  - Audio Steganography (8 methods)
  - Location Randomization
  - Surveillance Detection
  - Covert Channels
  - Tor/I2P Integration
  - OpenVINO Translation
  - Optional Monero Mining

- **[Security Overview](features/security-overview.md)**
  - Cryptographic algorithms
  - Security properties
  - Threat model
  - Best practices
  - Incident response

---

### 📖 Archived Documentation

Historical and deprecated documentation moved to [archive/](archive/):

**Feature Documentation** (superseded by current guides):
- `CRYPTOGRAM_ANDROID_COMPLETE.md` → See [Android Features](features/android-features.md)
- `FIVE_FEATURES_PORT.md` → See [Desktop Features](features/desktop-features.md)
- `AVAILABLE_SPYGRAM_FEATURES.md` → Deprecated
- `ADDITIONAL_FEATURES_AVAILABLE.md` → Deprecated

**Implementation Guides** (historical reference):
- `DOUBLE_RATCHET_PORT.md` - Signal Protocol implementation
- `MESSAGE_FLOW_COMPLETE.md` - Message encryption flow
- `SETTINGS_UI_COMPLETE.md` - Settings UI implementation
- `UI_INDICATORS_COMPLETE.md` - Visual indicators implementation

**Development Docs** (historical reference):
- `DOCKER_BUILD.md` - Docker build instructions
- `GITHUB_ACTIONS_BUILD.md` - CI/CD pipeline
- `TESTING_PLAN.md` - Testing strategy
- `TEST_RESULTS.md` - Test results

**Network & Mining**:
- `GPU_MINING_SUPPORT.md` - GPU mining support
- `I2P_INTEGRATION.md` - I2P network integration
- `MONERO_MINING_INTEGRATION.md` - Monero mining details

**Miscellaneous**:
- `CRYPTOGRAM_ANDROID_PORT.md` - Android porting process
- `CRYPTOGRAM_SETTINGS_UI_MOCKUP.md` - Settings UI mockup
- `SECOND_WAVE_FEATURES_PORT.md` - Second wave features
- `PULL_REQUEST.md` - PR template
- `PUSH_INSTRUCTIONS.md` - Git push instructions
- `FINAL_STATUS.md` - Final implementation status

---

## 🎯 Quick Links

### For Users
- [Android Features](features/android-features.md) - What can I do with CRYPTOGRAM Android?
- [Desktop Features](features/desktop-features.md) - What can I do with CRYPTOGRAM Desktop?
- [Security Overview](features/security-overview.md) - How secure is CRYPTOGRAM?

### For Developers
- [Setup Guides](setup/) - How do I build CRYPTOGRAM?
- [Archived Docs](archive/) - Implementation details and history

### For Security Researchers
- [Security Overview](features/security-overview.md) - Threat model and security architecture
- [Cryptographic Algorithms](features/security-overview.md#cryptographic-algorithms)
- [Responsible Disclosure](features/security-overview.md#reporting-security-issues)

---

## 📝 Documentation Standards

### Current Documentation
All current documentation follows these standards:
- ✅ No references to deprecated projects
- ✅ Accurate reflection of current implementation
- ✅ Platform-specific feature lists
- ✅ Complete setup instructions
- ✅ Security best practices

### Archived Documentation
Historical documentation in `archive/` may contain:
- References to implementation process
- Superseded feature descriptions
- Historical project names
- Outdated status information

**Always refer to current documentation for accurate information.**

---

## 🤝 Contributing to Documentation

### What to Document
- New features and how to use them
- Security considerations
- Platform-specific behavior
- Common troubleshooting
- Build instructions

### Documentation Style
- Use clear, concise language
- Include code examples where appropriate
- Add screenshots for UI features
- Link to related documentation
- Keep security information up-to-date

### Where to Add Documentation
- **New Features**: `features/` directory
- **Build Changes**: `setup/` directory
- **Security Updates**: `features/security-overview.md`

---

## 📧 Contact

- **Questions**: https://github.com/SWORDOps/CRYPTOGRAM/discussions
- **Issues**: https://github.com/SWORDOps/CRYPTOGRAM/issues
- **Security**: security@cryptogram.org

---

**Last Updated**: 2025-11-10

**Documentation Version**: 1.0.0
