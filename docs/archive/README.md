# Archived Documentation

**Historical and deprecated documentation**

This folder contains documentation that has been superseded by current guides or represents historical implementation details.

---

## ⚠️ Important Notice

**The documentation in this folder is ARCHIVED and may contain:**
- Outdated feature descriptions
- References to implementation process
- Historical project names (e.g., "SpyGram")
- Superseded technical details
- Old status information

**For current, accurate documentation, see:**
- [Android Features](../features/android-features.md)
- [Desktop Features](../features/desktop-features.md)
- [Security Overview](../features/security-overview.md)
- [Setup Guides](../setup/)

---

## 📚 Archive Contents

### Feature Documentation (Superseded)

**CRYPTOGRAM_ANDROID_COMPLETE.md**
- Historical: Android implementation completion status
- **Superseded by**: [Android Features](../features/android-features.md)
- **Useful for**: Understanding implementation history

**FIVE_FEATURES_PORT.md**
- Historical: Five major desktop features porting guide
- **Superseded by**: [Desktop Features](../features/desktop-features.md)
- **Useful for**: Understanding desktop feature implementation

**AVAILABLE_SPYGRAM_FEATURES.md**
- **DEPRECATED**: Lists features available from predecessor project
- **Note**: Contains references to "SpyGram" (historical name)
- **Status**: Retained for historical reference only

**ADDITIONAL_FEATURES_AVAILABLE.md**
- **DEPRECATED**: Additional features from predecessor project
- **Note**: Contains outdated feature lists
- **Status**: Retained for historical reference only

---

### Implementation Guides (Historical)

**DOUBLE_RATCHET_PORT.md**
- Signal Protocol (Double Ratchet) implementation details
- Technical implementation guide
- Still accurate for understanding the implementation

**MESSAGE_FLOW_COMPLETE.md**
- Message encryption/decryption flow
- Integration points in Telegram codebase
- Still accurate for developers

**SETTINGS_UI_COMPLETE.md**
- Settings UI implementation guide
- CRYPTOGRAM settings screen design
- Historical implementation details

**UI_INDICATORS_COMPLETE.md**
- Visual encryption indicators
- Lock icon implementation
- UI integration guide

---

### Development Documentation

**DOCKER_BUILD.md**
- Docker-based build system
- Container build instructions
- May be outdated

**GITHUB_ACTIONS_BUILD.md**
- CI/CD pipeline documentation
- Automated build workflow
- Check current `.github/workflows/` for latest

**TESTING_PLAN.md**
- Testing strategy and approach
- Test categories
- Historical test plan

**TEST_RESULTS.md**
- Test execution results
- Implementation validation
- Historical test results (may be outdated)

---

### Network & Mining Features

**GPU_MINING_SUPPORT.md**
- GPU mining implementation
- CUDA/OpenCL support
- Monero mining with GPU

**I2P_INTEGRATION.md**
- I2P (Invisible Internet Project) integration
- Anonymous routing implementation
- Network privacy features

**MONERO_MINING_INTEGRATION.md**
- Monero cryptocurrency mining
- Mining pool integration
- Optional feature documentation

---

### Miscellaneous

**CRYPTOGRAM_ANDROID_PORT.md**
- Android porting process
- Implementation steps
- Historical development log

**CRYPTOGRAM_SETTINGS_UI_MOCKUP.md**
- Settings UI mockup and design
- UI/UX planning
- Design documentation

**SECOND_WAVE_FEATURES_PORT.md**
- Second wave of features
- Additional porting work
- Historical feature additions

**PULL_REQUEST.md**
- Pull request template
- **Note**: May be outdated
- Check repository for current PR template

**PUSH_INSTRUCTIONS.md**
- Git push instructions
- Development workflow
- Historical reference

**FINAL_STATUS.md**
- Final implementation status (at time of writing)
- Completion report
- **Note**: Status may have changed since this was written

---

## 🔍 How to Use This Archive

### For Developers
- Reference implementation details
- Understand design decisions
- See historical development process

### For Security Researchers
- Review implementation approach
- Understand cryptographic integration
- Trace security feature origins

### For Documentation Writers
- Avoid repeating archived content
- Learn from historical structure
- Update current docs with improvements

---

## ⚡ Quick Reference

**Want to know...**

| Question | See Archived Doc | Or Current Doc |
|----------|------------------|----------------|
| How was Signal Protocol implemented? | DOUBLE_RATCHET_PORT.md | [Android Features](../features/android-features.md) |
| How does message flow work? | MESSAGE_FLOW_COMPLETE.md | Source code |
| What desktop features exist? | FIVE_FEATURES_PORT.md | [Desktop Features](../features/desktop-features.md) |
| How was Android ported? | CRYPTOGRAM_ANDROID_PORT.md | [Android Features](../features/android-features.md) |
| What tests were run? | TEST_RESULTS.md | Run tests yourself |
| How does CI/CD work? | GITHUB_ACTIONS_BUILD.md | `.github/workflows/` |

---

## 📝 Notes

### Why Archive Instead of Delete?

1. **Historical Record**: Shows development evolution
2. **Implementation Details**: Useful for understanding how features work
3. **Learning Resource**: Helps future contributors understand decisions
4. **Transparency**: Complete project history maintained

### When to Reference Archived Docs

✅ **Good uses**:
- Understanding implementation history
- Learning about design decisions
- Technical deep-dives
- Development process research

❌ **Bad uses**:
- As current feature reference
- For setup instructions
- For security guarantees
- For project status

---

## 🔄 Migration Guide

If you're reading old documentation and need current info:

| Old Doc | New Doc |
|---------|---------|
| AVAILABLE_SPYGRAM_FEATURES.md | [Desktop Features](../features/desktop-features.md) |
| CRYPTOGRAM_ANDROID_COMPLETE.md | [Android Features](../features/android-features.md) |
| FIVE_FEATURES_PORT.md | [Desktop Features](../features/desktop-features.md) |
| DOUBLE_RATCHET_PORT.md | [Security Overview](../features/security-overview.md) |
| Any other archived doc | [Main README](../../README.md) → find relevant link |

---

## 📧 Questions?

If you have questions about archived documentation:

- **General Questions**: https://github.com/SWORDOps/CRYPTOGRAM/discussions
- **Documentation Issues**: https://github.com/SWORDOps/CRYPTOGRAM/issues
- **Security Questions**: security@cryptogram.org

---

**Archive Created**: 2025-11-10

**Reason**: Documentation reorganization for clarity and accuracy
