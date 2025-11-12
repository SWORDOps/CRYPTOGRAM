# CRYPTOGRAM Desktop Features

**Complete guide to all features available in CRYPTOGRAM for Desktop (Windows, Linux, macOS)**

---

## Core Encryption Features

### 1. Signal Protocol (Double Ratchet)
**Status**: ✅ Implemented

End-to-end encryption for 1-on-1 chats using the Signal Protocol.

**Features**:
- X25519 ECDH key exchange
- Ed25519 digital signatures
- AES-256-GCM encryption
- Forward secrecy
- Post-compromise security
- Automatic key rotation

**Files**: `Telegram/SourceFiles/data/data_signal_protocol.cpp/h`

---

### 2. MLS Protocol (RFC 9420)
**Status**: ✅ Implemented

Scalable group encryption using the Message Layer Security protocol.

**Features**:
- TreeKEM algorithm for efficient key management
- O(log n) group operations
- Supports groups up to 10,000+ members
- Forward secrecy for all group members
- Post-compromise security

**Files**: `Telegram/SourceFiles/data/data_mls_protocol.cpp/h`

---

### 3. Post-Quantum Cryptography
**Status**: ✅ Implemented

Quantum-resistant encryption to protect against future quantum computers.

**Features**:
- ML-KEM-1024 (Kyber) key encapsulation
- ML-DSA-87 (Dilithium) digital signatures
- HKDF-SHA256 key derivation
- Hybrid classical + quantum cryptography

---

## Advanced Security Features

### 4. Audio Steganography Engine
**Status**: ✅ Implemented

Hide encrypted messages inside voice notes and audio files.

**Features**:
- **8 steganography methods**:
  - LSB (Least Significant Bit)
  - Spectral masking
  - Echo hiding
  - Phase modulation
  - Spread spectrum
  - Tone insertion
  - Amplitude modulation
  - Frequency hopping
- 100 bits/second embedding rate
- SNR >40dB (statistically undetectable)
- AES-256 encrypted payloads
- Psychoacoustic masking
- Hardware acceleration

**Use Cases**:
- Covert communication
- Plausible deniability
- Censorship bypass
- Anti-surveillance

**Files**: `Telegram/SourceFiles/data/data_voice_security.cpp/h`

---

### 5. Location Randomization System
**Status**: ✅ Implemented

Prevent geolocation tracking with realistic location spoofing.

**Features**:
- Geographic location randomization
- Phone number-based geolocation analysis
- Realistic location profiles with cultural context
- Automatic rotation (per session, daily, weekly)
- Timezone matching
- Decoy location generation

**Use Cases**:
- Anti-tracking protection
- Privacy-enhanced location sharing
- Geolocation spoofing
- Anti-surveillance

**Files**: `Telegram/SourceFiles/data/data_location_randomization.cpp/h`

---

### 6. Surveillance Detection System
**Status**: ✅ Implemented

Detect surveillance attempts and monitoring tools.

**Features**:
- Debugger detection
- Virtual machine detection
- Monitoring tool identification
- Behavioral anomaly detection
- Real-time threat alerts
- Security auditing

**Use Cases**:
- Detect government/corporate surveillance
- Identify compromised devices
- Security monitoring
- Threat detection

**Files**: `Telegram/SourceFiles/data/counterintelligence_features.cpp/h`

---

### 7. Covert Channel Engine
**Status**: ✅ Implemented

Bypass censorship and deep packet inspection.

**Features**:
- DPI-resistant communication
- Protocol mimicry
- Traffic obfuscation
- Covert timing channels
- Statistical normalization

**Use Cases**:
- Censorship bypass
- Network firewall evasion
- Anti-DPI protection
- Stealth communication

**Files**: `Telegram/SourceFiles/data/data_covert_channel.cpp/h`

---

### 8. Enhanced Privacy System
**Status**: ✅ Implemented

Advanced privacy protection and metadata stripping.

**Features**:
- EXIF data removal
- GPS location stripping
- Timestamp anonymization
- Metadata protection
- Hardware security module integration (TPM)

**Files**: `Telegram/SourceFiles/data/data_enhanced_privacy.cpp/h`

---

## Network Privacy

### 9. Tor Integration
**Status**: ✅ Implemented

Route Telegram traffic through the Tor network.

**Features**:
- Tor SOCKS5 proxy support
- Snowflake bridges
- Automatic relay selection
- Circuit rotation
- Bridge configuration

**Configuration**: Settings → CRYPTOGRAM → Network Privacy

---

### 10. I2P Integration
**Status**: ✅ Implemented

Use the Invisible Internet Project for anonymous communication.

**Features**:
- I2P tunnel support
- Relay node operation
- Distributed routing
- Anonymous messaging
- Garlic routing

**Configuration**: Settings → CRYPTOGRAM → Network Privacy

---

## Mining Features

### 11. Monero Mining (Optional)
**Status**: ✅ Implemented

Optional cryptocurrency mining to support the project.

**Features**:
- CPU mining with configurable percentage
- Idle-only mining mode
- Charging-only mining mode
- Mining pool integration
- Real-time hashrate monitoring

**Configuration**: Settings → CRYPTOGRAM → Mining
**Default**: 20% CPU, idle-only, charging-only

**Note**: Mining is entirely optional and can be disabled.

---

## Premium Features Override (Testing)
**Status**: ✅ Implemented

Enable all Telegram premium features for testing purposes.

**Enabled Features**:
- ✅ Message Privacy
- ✅ Advanced Chat Management
- ✅ No Ads
- ✅ Infinite Reactions
- ✅ Animated Profile Pictures
- ✅ Premium Stickers
- ✅ Message Effects
- ✅ Checklists
- ✅ Stories
- ✅ Unlimited Cloud Storage
- ✅ Doubled Limits
- ✅ Telegram Business
- ✅ Last Seen Times
- ✅ Voice-to-Text
- ✅ Faster Downloads
- ✅ Real-Time Translation
- ✅ Animated Emoji
- ✅ Emoji Statuses
- ✅ Tags for Messages
- ✅ Wallpapers
- ✅ Profile Badge

**How to Toggle**:
```cpp
Core::App().settings().setCryptogramPremiumOverride(false);
```

**Note**: Server-side premium features (storage, speed) still require actual Telegram Premium subscription.

---

## Translation

### 12. OpenVINO Translation (Optional)
**Status**: ✅ Implemented

Offline real-time translation using Intel OpenVINO.

**Features**:
- 100+ language pairs
- Offline translation
- Real-time message translation
- Auto-detect source language
- Quality settings (Fast, Balanced, Best)
- Hardware acceleration (CPU, GPU, NPU)
- Translation cache

**Requirements**: Download translation models (~500MB per language pair)

**Configuration**: Settings → CRYPTOGRAM → Translation

---

## Platform Support

### Windows
- **Version**: Windows 10/11 (64-bit)
- **Features**: All features available
- **TPM**: TPM 2.0 support for hardware security

### Linux
- **Distributions**: Ubuntu 20.04+, Fedora, Arch, etc.
- **Features**: All features available
- **Hardware**: TPM 2.0 optional

### macOS
- **Version**: macOS 10.15+
- **Features**: All features (except mining)
- **Security**: Keychain integration

---

## Installation

### Download
- **GitHub Releases**: https://github.com/SWORDOps/CRYPTOGRAM/releases
- **Build from Source**: See `/docs/setup/`

### First Run
1. Launch CRYPTOGRAM Desktop
2. Log in with your Telegram account
3. Go to Settings → CRYPTOGRAM
4. Enable desired features

---

## Settings Organization

### CRYPTOGRAM Settings Menu

**Encryption**:
- Double Ratchet toggle
- MLS Protocol toggle
- Post-Quantum toggle

**Advanced Security**:
- Audio Steganography
- Location Randomization
- Surveillance Detection
- Covert Channels

**Network Privacy**:
- Tor toggle
- Tor Snowflake toggle
- I2P toggle
- I2P Relay toggle

**Mining** (Optional):
- Mining toggle
- CPU percentage slider
- Idle-only toggle
- Charging-only toggle

**Translation** (Optional):
- Translation toggle
- Auto-detect toggle
- Target language selection
- Quality settings
- Device selection (CPU/GPU/NPU/AUTO)

**Testing**:
- Premium Override toggle

---

## Technical Specifications

### Cryptographic Algorithms
- **Key Exchange**: X25519, ML-KEM-1024
- **Signatures**: Ed25519, ML-DSA-87
- **Encryption**: AES-256-GCM, ChaCha20-Poly1305
- **Hashing**: SHA-256, SHA-512, BLAKE2b
- **KDF**: HKDF-SHA256

### Security Properties
- Forward secrecy
- Post-compromise security
- Deniability
- Quantum resistance
- Hardware-backed keys (TPM 2.0)

### Performance
- Message encryption: <0.1ms
- Key generation: <5ms
- Group operations: O(log n)
- Audio steganography: Real-time (<10ms latency)
- Surveillance detection: <1% CPU overhead

---

## Source Code Structure

```
Telegram/SourceFiles/
├── data/
│   ├── data_signal_protocol.cpp/h     # Signal Protocol
│   ├── data_mls_protocol.cpp/h        # MLS Protocol
│   ├── data_voice_security.cpp/h      # Audio Steganography
│   ├── data_location_randomization.cpp/h  # Location Privacy
│   ├── counterintelligence_features.cpp/h # Surveillance Detection
│   ├── data_covert_channel.cpp/h      # Covert Channels
│   ├── data_enhanced_privacy.cpp/h    # Privacy Features
│   ├── data_user.cpp/h                # User data & premium
│   └── data_quantum_storage.cpp/h     # Quantum-resistant storage
├── core/
│   └── core_settings.h/cpp            # Settings persistence
└── settings/
    └── settings_cryptogram.h/cpp      # Settings UI
```

---

## Security Considerations

### What's Protected
✅ Message content (end-to-end encrypted)
✅ Metadata stripped from media
✅ Keys stored in hardware security (TPM)
✅ Forward secrecy guaranteed
✅ Post-quantum resistant
✅ Network traffic obfuscated (Tor/I2P)
✅ Location privacy protected
✅ Surveillance detection active

### What's Not Protected
❌ Contact list (server-side)
❌ Group membership (server-side)
❌ Message timestamps (network metadata)
❌ Advanced traffic analysis
❌ Physical device compromise

### Best Practices
1. Enable Tor or I2P for maximum anonymity
2. Use location randomization when sharing location
3. Enable surveillance detection
4. Use audio steganography for covert messages
5. Keep software updated
6. Use strong disk encryption
7. Enable TPM if available

---

## Advanced Usage

### Audio Steganography
```cpp
// Send hidden message in voice note
auto engine = VoiceSecurity::AudioSteganographyEngine();
engine.embedMessage(audioData, secretMessage);
```

### Location Randomization
```cpp
// Randomize location before sharing
auto randomizer = LocationRandomization();
auto fakeLocation = randomizer.generateRealisticLocation(region);
```

### Surveillance Detection
```cpp
// Check for surveillance
auto detector = CounterIntelligence::SurveillanceDetector();
if (detector.detectThreats()) {
    // Alert user
}
```

---

## Building from Source

See documentation in `/docs/setup/`:
- [Windows Build Guide](../setup/building-win-x64.md)
- [Linux Build Guide](../setup/building-linux.md)
- [macOS Build Guide](../setup/building-mac.md)

---

## Troubleshooting

### Encryption Issues
1. Verify both users have CRYPTOGRAM
2. Check encryption toggles enabled
3. Restart application
4. Clear cache

### Network Issues
1. Check Tor/I2P configuration
2. Verify proxy settings
3. Test without VPN
4. Check firewall rules

### Performance Issues
1. Disable unused features
2. Adjust mining CPU percentage
3. Reduce translation quality
4. Update graphics drivers

---

## Support

- **Documentation**: https://github.com/SWORDOps/CRYPTOGRAM
- **Issues**: https://github.com/SWORDOps/CRYPTOGRAM/issues
- **Security**: security@cryptogram.org
- **Community**: https://github.com/SWORDOps/CRYPTOGRAM/discussions
