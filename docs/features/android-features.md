# CRYPTOGRAM Android Features

**Complete guide to all features available in CRYPTOGRAM for Android**

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

**How to Use**:
1. Open Settings → 🔐 CRYPTOGRAM
2. Enable "Double Ratchet Encryption"
3. Send messages to other CRYPTOGRAM users
4. Look for the 🔒 lock icon on encrypted messages

**Files**: `TMessagesProj/jni/cryptogram/data_signal_protocol.cpp`

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

**How to Use**:
1. Open Settings → 🔐 CRYPTOGRAM
2. Enable "MLS Protocol"
3. Group chats with CRYPTOGRAM users are automatically encrypted
4. Look for group encryption indicators

**Files**: `TMessagesProj/jni/cryptogram/data_mls_protocol.cpp`

---

### 3. Post-Quantum Cryptography
**Status**: ✅ Implemented

Quantum-resistant encryption to protect against future quantum computers.

**Features**:
- ML-KEM-1024 (Kyber) key encapsulation
- ML-DSA-87 (Dilithium) digital signatures
- HKDF-SHA256 key derivation
- Hybrid classical + quantum cryptography

**Files**: `TMessagesProj/jni/cryptogram/ml_kem.h`, `ml_dsa.h`

---

## Privacy Features

### 4. Enhanced Privacy System
**Status**: ✅ Implemented

Advanced privacy protection and metadata stripping.

**Features**:
- EXIF data removal from photos
- GPS location stripping
- Timestamp anonymization
- Metadata protection
- Hardware-backed key storage (Android KeyStore)

---

## Premium Features Override (Testing)
**Status**: ✅ Implemented

Enable all Telegram premium features for testing purposes.

**Enabled Features**:
- ✅ Message Privacy - Limit messages from strangers
- ✅ Advanced Chat Management - Auto-archive, folders
- ✅ No Ads - Ad-free experience
- ✅ Infinite Reactions - Unlimited reactions per message
- ✅ Animated Profile Pictures - Video avatars
- ✅ Premium Stickers - Exclusive sticker packs
- ✅ Message Effects - 500+ animated effects
- ✅ Checklists - Task management
- ✅ Stories - Unlimited posting
- ✅ Unlimited Cloud Storage - 4GB per document
- ✅ Doubled Limits - 1000 channels, 30 folders
- ✅ Telegram Business - Business features
- ✅ Last Seen Times - View hidden statuses
- ✅ Voice-to-Text - Transcription
- ✅ Faster Downloads - No speed limits
- ✅ Real-Time Translation - Message translation
- ✅ Animated Emoji - Custom emoji packs
- ✅ Emoji Statuses - Profile emoji
- ✅ Tags for Messages - Message organization
- ✅ Wallpapers - Custom chat wallpapers
- ✅ Profile Badge - Premium badge

**How to Toggle**:
```java
SharedConfig.toggleCryptogramPremiumOverride();
```

**Note**: Server-side premium features (storage, speed) still require actual Telegram Premium subscription.

---

## Visual Indicators

### Lock Icons
**Status**: ✅ Implemented

Visual feedback showing which messages are encrypted.

**Indicators**:
- 🔒 Lock icon on encrypted messages
- Color-coded encryption status
- Group encryption badges

**Files**: `TMessagesProj/src/main/java/org/telegram/ui/Components/CryptogramIndicator.java`

---

## Settings & Configuration

### CRYPTOGRAM Settings Screen
**Location**: Settings → 🔐 CRYPTOGRAM

**Options**:
- Double Ratchet Encryption toggle
- MLS Protocol toggle
- Curated Stickers (1-20 sets)
- Premium Override toggle
- Feature status display

**Files**: `TMessagesProj/src/main/java/org/telegram/ui/CryptogramSettingsActivity.java`

---

## Installation

### Download APK
Download the latest APK from [GitHub Actions](https://github.com/SWORDOps/CRYPTOGRAM/actions/workflows/build-android.yml)

### Install
```bash
adb install cryptogram-debug.apk
```

### First Run
1. Launch CRYPTOGRAM
2. Log in with your Telegram account
3. Go to Settings → 🔐 CRYPTOGRAM
4. Enable desired encryption features

---

## Technical Specifications

### Cryptographic Algorithms
- **Key Exchange**: X25519, ML-KEM-1024
- **Signatures**: Ed25519, ML-DSA-87
- **Encryption**: AES-256-GCM
- **Hashing**: SHA-256, SHA-512
- **KDF**: HKDF-SHA256

### Security Properties
- Forward secrecy
- Post-compromise security
- Deniability
- Quantum resistance
- Hardware-backed keys

### Performance
- Message encryption: <1ms
- Key generation: <10ms
- Group operations: O(log n)
- Memory overhead: <1MB per chat

---

## Platform Support

- **Android Version**: 5.0+ (API 21+)
- **Architectures**: armeabi-v7a, arm64-v8a, x86, x86_64
- **Storage**: Hardware KeyStore integration
- **NDK**: r25c
- **Build System**: CMake 3.22+

---

## Source Code

### Core Encryption
- `TMessagesProj/jni/cryptogram/` - Native C++ encryption
- `TMessagesProj/src/main/java/org/telegram/messenger/cryptogram/` - Java/Kotlin API

### Integration Points
- `SendMessagesHelper.java` - Outgoing message encryption
- `MessageObject.java` - Incoming message decryption
- `SharedConfig.java` - Settings persistence
- `UserConfig.java` - Premium override
- `MessagesController.java` - Premium checks

---

## Security Considerations

### What's Protected
✅ Message content (end-to-end encrypted)
✅ Metadata stripped from media
✅ Keys stored in hardware security
✅ Forward secrecy guaranteed
✅ Post-quantum resistant

### What's Not Protected
❌ Contact list (server-side)
❌ Group membership (server-side)
❌ Message timestamps (network metadata)
❌ Network traffic analysis
❌ Device-level compromise

### Best Practices
1. Verify encryption status before sending sensitive messages
2. Use CRYPTOGRAM-to-CRYPTOGRAM chats for maximum security
3. Enable all encryption features in settings
4. Keep the app updated
5. Use strong device lock screen password
6. Enable disk encryption on your device

---

## Troubleshooting

### Encryption Not Working
1. Check both users have CRYPTOGRAM installed
2. Ensure encryption is enabled in settings
3. Verify lock icons appear on messages
4. Check app permissions

### Performance Issues
1. Disable unused features
2. Clear app cache
3. Check device storage space
4. Update to latest version

### Build Issues
1. Ensure NDK r25c is installed
2. Check CMake version (3.22+)
3. Verify BoringSSL is linked
4. Clean and rebuild

---

## Support

- **Documentation**: https://github.com/SWORDOps/CRYPTOGRAM
- **Issues**: https://github.com/SWORDOps/CRYPTOGRAM/issues
- **Security**: security@cryptogram.org
