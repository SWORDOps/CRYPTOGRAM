# CRYPTOGRAM Security Standards

**Last Updated**: November 6, 2025
**Standard Version**: 2.0
**NIST Compliance**: FIPS 203/204/205 (August 2024)

---

## 🔒 Executive Summary

CRYPTOGRAM implements **NIST-approved post-quantum cryptography** combined with battle-tested classical algorithms to provide **quantum-resistant security** for all communications.

**Primary Standard**: **ML-KEM-1024 + X25519 Hybrid**
- **Post-Quantum**: ML-KEM-1024 (NIST FIPS 203)
- **Classical**: X25519 (Curve25519)
- **Security Level**: NIST Level 5 (384+ bit equivalent)
- **Quantum Resistance**: ✅ Yes (protects against Shor's algorithm)

---

## 📊 Current Standards (November 2025)

### Key Encapsulation Mechanism (KEM)

**PRODUCTION DEFAULT**: **ML-KEM-1024 + X25519 Hybrid**

| Component | Algorithm | Standard | Security Level |
|-----------|-----------|----------|----------------|
| **Post-Quantum KEM** | ML-KEM-1024 | NIST FIPS 203 | Level 5 (≥384-bit) |
| **Classical ECDH** | X25519 (Curve25519) | RFC 7748 | 128-bit |
| **Combined Security** | Hybrid | Industry Best Practice | **Maximum** |

**Why Hybrid?**
- ✅ **Quantum-resistant**: ML-KEM-1024 protects against quantum attacks
- ✅ **Battle-tested**: X25519 provides proven classical security
- ✅ **Defense-in-depth**: Breaking requires defeating BOTH algorithms
- ✅ **Future-proof**: Safe even if one algorithm is broken

### Digital Signatures

**PRODUCTION DEFAULT**: **ML-DSA-65 (Dilithium3)**

| Algorithm | Standard | Security Level | Use Case |
|-----------|----------|----------------|----------|
| **ML-DSA-65** | NIST FIPS 204 | Level 3 (≥192-bit) | **Default** |
| ML-DSA-87 | NIST FIPS 204 | Level 5 (≥384-bit) | High Security |
| SLH-DSA-SHAKE | NIST FIPS 205 | Configurable | Stateless |

### Symmetric Encryption

**PRODUCTION DEFAULT**: **AES-256-GCM**

| Algorithm | Key Size | Use Case |
|-----------|----------|----------|
| **AES-256-GCM** | 256-bit | **Default encryption** |
| ChaCha20-Poly1305 | 256-bit | Alternative (software-optimized) |

### Key Derivation

**PRODUCTION DEFAULT**: **HKDF-SHA3-256**

| Algorithm | Use Case |
|-----------|----------|
| **HKDF-SHA3-256** | **Default KDF** |
| HKDF-SHA-512 | Legacy compatibility |
| Argon2id | Password hashing |

---

## 🎯 NIST Post-Quantum Cryptography Standards

### NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)

**Formerly known as**: CRYSTALS-Kyber
**Standardized**: August 2024
**Status**: ✅ NIST Approved

| Variant | Security Level | Public Key | Ciphertext | Shared Secret |
|---------|----------------|------------|------------|---------------|
| ML-KEM-512 | Level 1 (AES-128) | 800 bytes | 768 bytes | 32 bytes |
| ML-KEM-768 | Level 3 (AES-192) | 1,184 bytes | 1,088 bytes | 32 bytes |
| **ML-KEM-1024** | **Level 5 (AES-256+)** | **1,568 bytes** | **1,568 bytes** | **32 bytes** |

**CRYPTOGRAM Default**: **ML-KEM-1024** (Maximum security)

**Technical Details**:
- **Problem**: Module Learning With Errors (MLWE)
- **Quantum Resistance**: Breaks require exponential time on quantum computers
- **Classical Security**: Also secure against classical attacks
- **Performance**: Fast key generation, encapsulation, decapsulation
- **Lattice Security**: Based on hardness of shortest vector problem (SVP)

### NIST FIPS 204: Module-Lattice-Based Digital Signature Algorithm (ML-DSA)

**Formerly known as**: CRYSTALS-Dilithium
**Standardized**: August 2024
**Status**: ✅ NIST Approved

| Variant | Security Level | Public Key | Signature Size |
|---------|----------------|------------|----------------|
| ML-DSA-44 | Level 2 | 1,312 bytes | 2,420 bytes |
| **ML-DSA-65** | **Level 3** | **1,952 bytes** | **3,293 bytes** |
| ML-DSA-87 | Level 5 | 2,592 bytes | 4,595 bytes |

**CRYPTOGRAM Default**: **ML-DSA-65** (Balanced security/performance)

**Technical Details**:
- **Problem**: Module Short Integer Solution (MSIS) + Module Learning With Errors (MLWE)
- **Quantum Resistance**: Based on lattice problems hard for quantum computers
- **Deterministic**: Same message + key → same signature (optional randomization)
- **Performance**: Fast signing and verification

### NIST FIPS 205: Stateless Hash-Based Digital Signature Algorithm (SLH-DSA)

**Formerly known as**: SPHINCS+
**Standardized**: August 2024
**Status**: ✅ NIST Approved

| Variant | Hash Function | Public Key | Signature Size |
|---------|---------------|------------|----------------|
| SLH-DSA-SHA2 | SHA-256 | 32/64 bytes | 7.8-49 KB |
| **SLH-DSA-SHAKE** | **SHAKE-256** | **32/64 bytes** | **7.8-49 KB** |

**CRYPTOGRAM Usage**: Backup/archival signatures (stateless = no state management)

**Technical Details**:
- **Problem**: Hash function collision resistance
- **Quantum Resistance**: Hash functions believed quantum-resistant
- **Stateless**: No secret state to maintain (unlike XMSS, LMS)
- **Trade-off**: Large signatures (~8-49 KB) vs. simplicity

---

## 🔐 Double Ratchet Protocol Implementation

**CRYPTOGRAM uses the Signal Protocol Double Ratchet** with post-quantum enhancements.

### Key Exchange Hierarchy

```
┌─────────────────────────────────────────────────────────┐
│              Initial Key Exchange (X3DH)                 │
│                                                          │
│  1. Identity Key (Long-term)                            │
│     - Classical: X25519                                 │
│     - Post-Quantum: ML-KEM-1024                         │
│     - Signature: ML-DSA-65                              │
│                                                          │
│  2. Signed PreKey (Medium-term, rotated weekly)         │
│     - Hybrid: X25519 + ML-KEM-1024                      │
│     - Signed with ML-DSA-65                             │
│                                                          │
│  3. One-Time PreKeys (Single-use)                       │
│     - Hybrid: X25519 + ML-KEM-1024                      │
│     - Unsigned (authenticated via DH)                   │
└─────────────────────────────────────────────────────────┘

                           ↓

┌─────────────────────────────────────────────────────────┐
│            Double Ratchet (Per-Message Keys)            │
│                                                          │
│  Root Chain:                                            │
│    - KDF: HKDF-SHA3-256                                 │
│    - Input: Hybrid DH output (X25519 + ML-KEM-1024)     │
│    - Output: New root key + chain keys                  │
│                                                          │
│  Sending Chain:                                         │
│    - Ratchet: HKDF-SHA3-256                             │
│    - Generates: AES-256-GCM message keys                │
│    - Counter: Per-message increment                     │
│                                                          │
│  Receiving Chain:                                       │
│    - Ratchet: HKDF-SHA3-256                             │
│    - Decrypts: AES-256-GCM encrypted messages           │
│    - Skipped keys: Stored for out-of-order messages     │
└─────────────────────────────────────────────────────────┘
```

### Perfect Forward Secrecy (PFS)

- **Ratcheting Frequency**: Every message (sending direction)
- **DH Ratchet**: Every roundtrip (sending + receiving)
- **Key Lifetime**: Single message only
- **Compromise Window**: At most 1 message (not entire conversation)

### Post-Compromise Security (PCS)

- **Recovery Time**: 1 roundtrip (send + receive)
- **Mechanism**: New DH/KEM key exchange resets security
- **Guarantee**: Old key compromise doesn't affect future messages

---

## 🛡️ Security Properties

### Threat Model

**Protected Against**:
- ✅ **Passive eavesdropping** (TLS-level attacker)
- ✅ **Active man-in-the-middle** (with authenticated keys)
- ✅ **Quantum computer attacks** (Shor's algorithm, Grover's algorithm)
- ✅ **Key compromise** (Perfect Forward Secrecy)
- ✅ **Server compromise** (End-to-end encryption)
- ✅ **Replay attacks** (Message counters, timestamps)
- ✅ **Reordering attacks** (Message authentication)

**Not Protected Against** (Out of Scope):
- ❌ **Endpoint compromise** (malware on your device)
- ❌ **Coercion** (being forced to decrypt)
- ❌ **Rubber-hose cryptanalysis** ($5 wrench attack)
- ❌ **Side-channel attacks** (timing, power analysis - mitigated where possible)
- ❌ **Traffic analysis** (message sizes, timing - use Tor/I2P)

### Security Levels

| NIST Level | Classical Security | Quantum Security | Algorithm Example |
|------------|-------------------|------------------|-------------------|
| **Level 1** | ≥128-bit (AES-128) | ≥128-bit | ML-KEM-512 |
| **Level 2** | ≥128-bit | ≥128-bit | ML-DSA-44 |
| **Level 3** | ≥192-bit (AES-192) | ≥192-bit | ML-KEM-768, ML-DSA-65 |
| **Level 5** | ≥256-bit (AES-256) | ≥256-bit | **ML-KEM-1024** ⭐ |

**CRYPTOGRAM Standard**: **Level 5** (Maximum security)

---

## 🚀 Performance Characteristics

### ML-KEM-1024 Performance (Typical Desktop CPU)

| Operation | Time | Notes |
|-----------|------|-------|
| Key Generation | ~100 µs | One-time per key pair |
| Encapsulation | ~150 µs | Per key exchange |
| Decapsulation | ~200 µs | Per key exchange |
| **Total Handshake** | **~450 µs** | **< 0.5ms overhead** |

### X25519 Performance (Comparison)

| Operation | Time | Notes |
|-----------|------|-------|
| Key Generation | ~50 µs | Faster than ML-KEM |
| ECDH | ~80 µs | Faster than ML-KEM |
| **Total Handshake** | **~130 µs** | **ML-KEM adds ~320 µs** |

### Hybrid Performance

**ML-KEM-1024 + X25519**: ~450 µs (dominated by ML-KEM)
**Overhead**: ~320 µs for quantum resistance (acceptable for security)
**Network**: +1.5 KB per key exchange (ML-KEM public key + ciphertext)

**Verdict**: ✅ **Acceptable** - Sub-millisecond quantum-resistant key exchange

---

## 📚 Implementation Details

### Key Sizes

| Component | Size | Format |
|-----------|------|--------|
| **ML-KEM-1024 Public Key** | 1,568 bytes | Raw lattice parameters |
| **ML-KEM-1024 Private Key** | 3,168 bytes | Includes public key |
| **ML-KEM-1024 Ciphertext** | 1,568 bytes | Encapsulated key |
| **ML-KEM-1024 Shared Secret** | 32 bytes | KDF input |
| **X25519 Public Key** | 32 bytes | Curve point |
| **X25519 Private Key** | 32 bytes | Scalar |
| **X25519 Shared Secret** | 32 bytes | KDF input |
| **Hybrid Shared Secret** | 64 bytes | Concatenated (ML-KEM ‖ X25519) |
| **Root Key** | 32 bytes | After KDF |
| **Chain Key** | 32 bytes | Ratcheted per message |
| **Message Key** | 32 bytes | One-time AES-256-GCM key |

### Key Derivation Flow

```
Hybrid Key Exchange:
  ML-KEM-1024 Encapsulation → 32-byte quantum-resistant secret
  +
  X25519 ECDH → 32-byte classical secret
  ↓
  Concatenate → 64-byte hybrid input
  ↓
  HKDF-SHA3-256 (info="CRYPTOGRAM-v2-Root-Key") → 32-byte root key
  ↓
  HKDF-SHA3-256 (root_key, info="Sending-Chain") → Sending chain key
  HKDF-SHA3-256 (root_key, info="Receiving-Chain") → Receiving chain key
  ↓
  Per-Message: HKDF-SHA3-256 (chain_key, counter) → Message key
```

### Encryption Flow

```
Message Encryption:
  1. Ratchet chain key → new_chain_key, message_key
  2. Generate 96-bit random nonce (GCM standard)
  3. AES-256-GCM-Encrypt(plaintext, message_key, nonce) → ciphertext, auth_tag
  4. Send: [ciphertext ‖ nonce ‖ auth_tag ‖ message_counter ‖ sender_ratchet_public_key]
  5. Update: chain_key = new_chain_key, counter++
```

### Decryption Flow

```
Message Decryption:
  1. Receive: [ciphertext ‖ nonce ‖ auth_tag ‖ message_counter ‖ sender_ratchet_public_key]
  2. Check if DH ratchet update needed (new sender public key)
  3. If yes: Perform hybrid DH/KEM exchange, update root key and chains
  4. Ratchet receiving chain to message_counter
  5. Derive message_key from chain at counter
  6. AES-256-GCM-Decrypt(ciphertext, message_key, nonce, auth_tag) → plaintext or FAIL
  7. Store skipped keys for out-of-order messages (up to 1000 keys)
```

---

## 🔬 Cryptographic Primitives

### Algorithms Used

| Purpose | Algorithm | Specification |
|---------|-----------|---------------|
| **Post-Quantum KEM** | ML-KEM-1024 | NIST FIPS 203 |
| **Classical ECDH** | X25519 | RFC 7748 |
| **Post-Quantum Signatures** | ML-DSA-65 | NIST FIPS 204 |
| **Classical Signatures** | Ed25519 | RFC 8032 |
| **Symmetric Encryption** | AES-256-GCM | NIST SP 800-38D |
| **Alternative Encryption** | ChaCha20-Poly1305 | RFC 8439 |
| **Key Derivation** | HKDF-SHA3-256 | RFC 5869 + FIPS 202 |
| **Hashing** | SHA3-256 / SHA3-512 | FIPS 202 |
| **Random Generation** | /dev/urandom (Linux) | OS CSPRNG |

### Library Dependencies

| Library | Purpose | Version |
|---------|---------|---------|
| **liboqs** | NIST PQC algorithms | 0.10.0+ |
| **OpenSSL** | Classical crypto (X25519, AES, SHA3) | 3.1.0+ |
| **libsodium** | Alternative primitives (ChaCha20-Poly1305) | 1.0.18+ |

---

## 📖 Standards Compliance

### NIST Standards

✅ **FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism Standard
✅ **FIPS 204**: Module-Lattice-Based Digital Signature Standard
✅ **FIPS 205**: Stateless Hash-Based Digital Signature Standard
✅ **SP 800-38D**: Recommendation for Block Cipher Modes of Operation (GCM)
✅ **FIPS 202**: SHA-3 Standard (Permutation-Based Hash and XOFs)

### IETF RFCs

✅ **RFC 5869**: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
✅ **RFC 7748**: Elliptic Curves for Security (X25519)
✅ **RFC 8032**: Edwards-Curve Digital Signature Algorithm (EdDSA / Ed25519)
✅ **RFC 8439**: ChaCha20 and Poly1305 for IETF Protocols

### Industry Standards

✅ **Signal Protocol**: Double Ratchet with Perfect Forward Secrecy
✅ **IETF PQXDH**: Post-Quantum Extended Diffie-Hellman (Draft)
✅ **Hybrid Post-Quantum**: Combining classical + quantum-resistant algorithms

---

## 🔄 Migration Path

### From Kyber768 to ML-KEM-1024

**Timeline**: Completed November 2025
**Breaking Change**: No (backward compatible)

| Version | Default KEM | Notes |
|---------|-------------|-------|
| **1.x** | Kyber768 | Legacy (pre-NIST standardization) |
| **2.0+** | **ML-KEM-1024** | **Current standard** |

**Compatibility**:
- Old clients (Kyber768): Will use Kyber768 until upgraded
- New clients (ML-KEM-1024): Negotiate highest common standard
- Handshake: Advertises supported algorithms, downgrades if necessary
- Minimum: Kyber768 (no weaker algorithms accepted)

### Future-Proofing

**Algorithm Agility**: CRYPTOGRAM supports multiple algorithms simultaneously
- Clients advertise supported algorithms in handshake
- Server/client negotiate strongest mutually-supported algorithm
- Easy to add new NIST standards when available

**Planned Future Algorithms**:
- **FrodoKEM**: Alternative lattice-based KEM (if NIST approves)
- **BIKE**: Code-based KEM (NIST alternate candidate)
- **HQC**: Code-based KEM (NIST alternate candidate)
- **McEliece**: Code-based KEM (NIST finalist)

---

## 🛠️ Developer Guide

### Enabling ML-KEM-1024 + X25519

CRYPTOGRAM uses **ML-KEM-1024 + X25519 by default** (no configuration needed).

To explicitly select:

```cpp
// C++ API
auto cryptoServices = QuantumCryptoServicesFactory::createOptimized();

// Generate hybrid key
auto result = cryptoServices->generateHybridKey(
    QuantumKeyType::RatchetKey,
    QuantumAlgorithm::HybridX25519_ML_KEM_1024,  // Explicit
    "X25519"  // Classical component
);

// Perform hybrid key agreement
auto keyAgreement = cryptoServices->quantumKeyAgreement(
    localPrivateKey,
    remotePublicKey,
    QuantumAlgorithm::ML_KEM_1024  // Or HybridX25519_ML_KEM_1024
);
```

### Signal Protocol Integration

```cpp
// Initialize Signal Protocol with quantum resistance
auto signalProtocol = std::make_unique<SignalProtocol>(session);
signalProtocol->setEnabled(true);

// Key bundle automatically uses ML-KEM-1024 + X25519
auto localBundle = signalProtocol->generateLocalKeyBundle();

// Session creation uses hybrid key exchange
signalProtocol->createSession(peer, remoteBundle);

// Encryption/decryption automatically quantum-resistant
auto ciphertext = signalProtocol->encryptMessage(plaintext, peer, metadata);
auto plaintext = signalProtocol->decryptMessage(ciphertext, peer, metadata);
```

### Testing Quantum Resistance

```cpp
// Verify algorithm in use
auto session = signalProtocol->getSession(peer);
assert(session.usesQuantumResistantAlgorithm());

// Check security level
auto securityLevel = session.getSecurityLevel();
assert(securityLevel >= QuantumSecurityLevel::Level5);

// Audit encryption
auto metrics = cryptoServices->getPerformanceMetrics();
LOG(("Quantum-resistant ops: %1").arg(metrics.quantumOperations));
LOG(("ML-KEM-1024 usage: %1%").arg(metrics.quantumResistantRatio * 100));
```

---

## 🔍 Security Audit Information

### Last Security Audit

**Date**: Pending (Q1 2026 planned)
**Auditor**: TBD
**Scope**: Post-quantum cryptography implementation

### Known Limitations

1. **Side-channel resistance**: ML-KEM-1024 implementation uses liboqs, which has basic side-channel protections but is not constant-time in all cases
2. **Memory safety**: C++ implementation requires careful memory management (heap allocations for large keys)
3. **Timing attacks**: HKDF and AES-GCM are generally constant-time, but system-specific variations possible
4. **Power analysis**: Not protected (requires specialized hardware/software)

### Mitigation Strategies

- Use TSM (Trusted Security Module) integration for hardware-backed keys where available
- Enable hardware acceleration (AES-NI) for constant-time AES operations
- Memory zeroization after key use (explicit zeroing, not compiler-optimized away)
- Random delays and noise injection (optional, for high-security environments)

---

## 📜 References

### NIST Publications

- **FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism Standard (August 2024)
  https://csrc.nist.gov/pubs/fips/203/final

- **FIPS 204**: Module-Lattice-Based Digital Signature Standard (August 2024)
  https://csrc.nist.gov/pubs/fips/204/final

- **FIPS 205**: Stateless Hash-Based Digital Signature Standard (August 2024)
  https://csrc.nist.gov/pubs/fips/205/final

### Research Papers

- **CRYSTALS-Kyber**: "CRYSTALS-Kyber Algorithm Specifications And Supporting Documentation"
  https://pq-crystals.org/kyber/

- **CRYSTALS-Dilithium**: "CRYSTALS-Dilithium Algorithm Specifications And Supporting Documentation"
  https://pq-crystals.org/dilithium/

- **Signal Protocol**: "The Double Ratchet Algorithm" by Trevor Perrin and Moxie Marlinspike
  https://signal.org/docs/specifications/doubleratchet/

### Open Source Libraries

- **liboqs**: Open Quantum Safe project
  https://github.com/open-quantum-safe/liboqs

- **OpenSSL**: Open source TLS and crypto library
  https://www.openssl.org/

---

## 📞 Security Contact

**Security Issues**: security@cryptogram.app (PGP key available)
**Bug Bounty**: https://cryptogram.app/security/bounty
**Responsible Disclosure**: 90-day coordinated disclosure policy

**DO NOT** publicly disclose security vulnerabilities. Use responsible disclosure.

---

**Document Version**: 2.0
**Last Updated**: November 6, 2025
**Next Review**: March 2026

---

**© 2025 CRYPTOGRAM Project. This document is released under CC BY-SA 4.0 license.**
