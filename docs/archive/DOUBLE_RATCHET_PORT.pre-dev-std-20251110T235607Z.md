# Double Ratchet Implementation Port from SpyGram

## Overview
This document describes the complete Double Ratchet encryption implementation that has been ported from SpyGram to CRYPTOGRAM.

## What is the Double Ratchet Algorithm?

The Double Ratchet algorithm is the core cryptographic protocol used by Signal and other secure messaging applications. It provides:

1. **End-to-End Encryption**: Messages are encrypted on the sender's device and only decrypted on the recipient's device
2. **Forward Secrecy**: Compromise of current keys does not compromise past messages
3. **Break-in Recovery**: Compromise of current keys does not compromise future messages
4. **Out-of-Order Message Handling**: Messages can arrive out of order and still be decrypted

## Files Ported

### Core Implementation
- **Telegram/SourceFiles/data/data_signal_protocol.h** - Header file defining the SignalProtocol class with Double Ratchet support
- **Telegram/SourceFiles/data/data_signal_protocol.cpp** - Full implementation of the Double Ratchet algorithm

### Supporting Files
- **Telegram/SourceFiles/data/data_tsm_interface.h** - Trusted Security Module interface for hardware-backed crypto
- **Telegram/SourceFiles/data/data_tsm_factory.cpp** - Factory for creating TSM instances

### Test Files
- **tests/unit/test_double_ratchet.cpp** - Comprehensive unit tests for the Double Ratchet implementation

## Key Features

### 1. Cryptographic Primitives
- **X25519 (Curve25519)**: Diffie-Hellman key exchange
- **Ed25519**: Digital signatures for identity keys
- **HKDF**: Key derivation function
- **AES-256-CBC**: Message encryption
- **HMAC-SHA256**: Message authentication and integrity

### 2. Double Ratchet Algorithm
- **Root Key Ratchet**: Uses Diffie-Hellman to derive new root keys
- **Chain Key Ratchet**: Uses HMAC to derive message keys from chain keys
- **Skipped Message Keys**: Stores up to 1000 skipped keys for out-of-order messages
- **Message Counters**: Tracks message sequence numbers

### 3. Session Management
- **Session Creation**: Initialize sessions with pre-key bundles
- **Session Storage**: Persistent storage with HMAC integrity protection
- **Key Rotation**: Automatic key rotation with configurable intervals
- **Multiple Devices**: Support for multiple devices per peer

### 4. Security Features
- **Perfect Forward Secrecy**: Old keys are deleted after use
- **Break-in Recovery**: New DH ratchet steps provide security even after compromise
- **Replay Protection**: Prevents replay attacks using message counters
- **Key Backup**: Encrypted backup/restore of keys using PBKDF2

### 5. Hardware Security Integration (TSM)
- **TPM 2.0**: Trusted Platform Module support on desktop
- **Android KeyStore**: Hardware-backed keys on Android
- **Apple Secure Enclave**: Hardware security on iOS/macOS
- **Software Fallback**: Graceful fallback when hardware not available

## Implementation Details

### Session State
Each session maintains:
- Root key (32 bytes)
- Sending and receiving chain keys (32 bytes each)
- DH sending/receiving public keys (32 bytes each)
- Message counters (sending/receiving)
- Skipped message keys (for out-of-order messages)
- Device identifiers
- Timestamps (creation, last used)

### Message Encryption Flow
1. Derive message key from current chain key
2. Advance chain key using HMAC
3. Encrypt plaintext using AES-256-CBC
4. Include metadata (counter, IV, sender's public key)
5. Update session state

### Message Decryption Flow
1. Check message counter
2. If expected: use current chain key
3. If future: skip ahead and store skipped keys
4. If past: look up stored skipped key
5. Decrypt using AES-256-CBC
6. Update session state

### Key Rotation
- Default interval: 7 days (configurable)
- Generates new DH key pair
- Derives new root and chain keys
- Resets message counters
- Schedules next rotation

## Security Considerations

### Strengths
1. **Post-Compromise Security**: Even if an attacker compromises current keys, future messages remain secure after the next DH ratchet step
2. **No Key Reuse**: Each message uses a unique encryption key
3. **Authentication**: Messages are authenticated using HMAC
4. **Integrity Protection**: Session data protected with HMAC

### Limitations
1. **Metadata Not Protected**: Message metadata (sender, timestamp) is not encrypted by this implementation
2. **No Group Chat**: This implementation is for 1-to-1 conversations only
3. **Storage Required**: Skipped message keys consume storage (limited to 1000)

## Usage Example

```cpp
// Initialize Signal Protocol
auto signalProtocol = std::make_unique<SignalProtocol>(session);
signalProtocol->setEnabled(true);

// Generate and exchange key bundles
auto localBundle = signalProtocol->generateLocalKeyBundle();
// ... send localBundle to peer, receive remoteBundle from peer ...

// Create session
signalProtocol->createSession(peer, remoteBundle);

// Encrypt a message
MessageMetadata metadata;
auto plaintext = bytes::make_span("Hello, secure world!");
auto ciphertext = signalProtocol->encryptMessage(plaintext, peer, metadata);

// Decrypt a message
auto decrypted = signalProtocol->decryptMessage(ciphertext, peer, metadata);
```

## Testing

The implementation includes comprehensive unit tests covering:
- Session initialization
- Message encryption/decryption
- Out-of-order message handling
- Forward secrecy properties
- Break-in recovery
- Key derivation
- Performance benchmarks
- State serialization

Run tests with:
```bash
# Build and run unit tests
./tests/unit/test_double_ratchet
```

## Future Enhancements

Potential improvements that could be made:
1. Add support for group messaging using Sender Keys
2. Implement message deletion/disappearing messages
3. Add quantum-resistant algorithms (post-quantum cryptography)
4. Optimize performance for mobile devices
5. Add support for voice/video call encryption
6. Implement cross-device synchronization

## References

1. [Signal Protocol Documentation](https://signal.org/docs/)
2. [Double Ratchet Algorithm Specification](https://signal.org/docs/specifications/doubleratchet/)
3. [X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
4. [Sesame Algorithm](https://signal.org/docs/specifications/sesame/)

## License

This implementation is part of CRYPTOGRAM and inherits the project's license.

## Credits

Ported from SpyGram's implementation with enhancements and complete serialization support.
