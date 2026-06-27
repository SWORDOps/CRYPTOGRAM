# CRYPTOGRAM Security Overview

**Comprehensive security architecture and threat model**

---

## Security Architecture

CRYPTOGRAM provides multiple layers of security to protect your communications:

```
┌─────────────────────────────────────────────┐
│         Application Layer Security          │
├─────────────────────────────────────────────┤
│  • E2EE (Signal, MLS)                       │
│  • Audio Steganography                      │
│  • Metadata Stripping                       │
│  • Surveillance Detection                   │
└─────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────┐
│         Network Layer Security              │
├─────────────────────────────────────────────┤
│  • Tor/I2P Integration                      │
│  • Covert Channels                          │
│  • DPI Resistance                           │
│  • Traffic Obfuscation                      │
└─────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────┐
│         Storage Layer Security              │
├─────────────────────────────────────────────┤
│  • Hardware Security (TPM/KeyStore)         │
│  • Post-Quantum Storage                     │
│  • Encrypted Key Storage                    │
│  • Anti-Forensics                           │
└─────────────────────────────────────────────┘
```

---

## Cryptographic Algorithms

### Symmetric Encryption
- **AES-256-GCM**: Message encryption
- **ChaCha20-Poly1305**: Alternative cipher
- **Key Size**: 256 bits
- **Mode**: Authenticated encryption with associated data (AEAD)

### Asymmetric Cryptography
- **X25519**: Elliptic curve Diffie-Hellman key exchange
- **Ed25519**: Digital signatures
- **Curve**: Curve25519

### Post-Quantum Cryptography
- **ML-KEM-1024** (Kyber1024): Quantum-resistant key encapsulation
- **ML-DSA-87** (Dilithium): Quantum-resistant signatures
- **Security Level**: NIST Level 5 (highest)

### Hashing
- **SHA-256**: General purpose hashing
- **SHA-512**: High-security hashing
- **BLAKE2b**: Fast hashing with security
- **HMAC-SHA256**: Message authentication

### Key Derivation
- **HKDF-SHA256**: Extract and expand keys
- **PBKDF2**: Password-based derivation
- **Scrypt**: Memory-hard KDF (future)

---

## Security Properties

### Forward Secrecy
**Guarantee**: Past communications remain secure even if long-term keys are compromised.

**Implementation**:
- X3DH extended triple-Diffie-Hellman key exchange for session initialization
- Double Ratchet algorithm with DH ratchet on every message round-trip
- Ephemeral keys for each session
- Automatic key rotation via HKDF-SHA256 chain key advancement
- AES-256-GCM authenticated encryption with per-message nonce
- Session key deletion after use
- Zeroization of sensitive cryptographic buffers

### Post-Compromise Security
**Guarantee**: Future communications remain secure after key compromise.

**Implementation**:
- Continuous DH ratchet key rotation
- Self-healing ratchet (new chain key per epoch)
- MLS TreeKEM group key evolution
- Fresh key generation on every received DH key
- Break-in recovery via new DH ratchet step

### Deniability
**Guarantee**: Cannot prove who sent a message.

**Implementation**:
- MAC-based authentication (not signatures)
- Repudiable transcripts
- Off-the-record messaging
- Shared authentication keys

### Quantum Resistance
**Guarantee**: Protection against quantum computer attacks.

**Implementation**:
- ML-KEM-1024 key encapsulation
- ML-DSA-87 signatures
- Hybrid classical/quantum schemes
- 256-bit post-quantum security

---

## Threat Model

### Protected Against

#### ✅ Passive Network Surveillance
**Threat**: Government or ISP monitoring network traffic.

**Protection**:
- End-to-end encryption
- Tor/I2P routing
- Traffic obfuscation
- DPI resistance

---

#### ✅ Active Network Attacks
**Threat**: Man-in-the-middle attacks, packet injection.

**Protection**:
- Authenticated encryption
- Perfect forward secrecy
- Certificate pinning
- Integrity verification

---

#### ✅ Metadata Analysis
**Threat**: Who talks to whom, when, and how often.

**Protection**:
- Metadata stripping (EXIF, GPS)
- Tor/I2P for traffic analysis resistance
- Timestamp randomization
- Location privacy

---

#### ✅ Future Quantum Computers
**Threat**: Quantum computers breaking current cryptography.

**Protection**:
- ML-KEM-1024 (Kyber)
- ML-DSA-87 (Dilithium)
- Hybrid schemes
- 256-bit quantum security

---

#### ✅ Device Surveillance
**Threat**: Spyware, keyloggers, surveillance software.

**Protection**:
- Surveillance detection system
- Debugger detection
- VM detection
- Behavioral anomaly detection

---

#### ✅ Censorship
**Threat**: Government blocking Telegram or similar apps.

**Protection**:
- Tor/I2P integration
- Covert channels
- Protocol mimicry
- DPI resistance

---

#### ✅ Location Tracking
**Threat**: Geolocation via GPS metadata or IP address.

**Protection**:
- Location randomization
- GPS stripping
- Realistic fake locations
- Timezone matching

---

### NOT Protected Against

#### ❌ Physical Device Compromise
**Threat**: Physical access to unlocked device.

**Mitigation**:
- Use strong device password
- Enable full disk encryption
- Use hardware security (TPM/Secure Enclave)
- Enable auto-lock

---

#### ❌ Malicious Recipient
**Threat**: Recipient screenshots or leaks messages.

**Mitigation**:
- Trust your recipients
- Use disappearing messages (if available)
- Don't send sensitive info to untrusted parties

---

#### ❌ Server-Side Metadata
**Threat**: Telegram servers know contact lists, group memberships.

**Mitigation**:
- Use Tor/I2P for IP privacy
- Understand server-side limitations
- Use encrypted contact discovery (future)

---

#### ❌ Advanced Targeted Attacks
**Threat**: Nation-state with unlimited resources targeting you specifically.

**Mitigation**:
- Use multiple layers of protection
- Practice good OPSEC
- Use airgapped devices for highest security
- Understand your threat model

---

#### ❌ Social Engineering
**Threat**: Phishing, impersonation, manipulation.

**Mitigation**:
- Verify contacts out-of-band
- Be suspicious of requests
- Enable 2FA
- Practice security awareness

---

## Security Audit Status

### Code Audits
- ✅ Signal Protocol: Audited by Open Whisper Systems
- ✅ MLS Protocol: IETF RFC 9420 standardized
- ⏳ CRYPTOGRAM-specific code: Not yet externally audited
- ⏳ Steganography engine: Internal review only

### Cryptographic Review
- ✅ AES-256-GCM: NIST approved
- ✅ X25519/Ed25519: Industry standard
- ✅ ML-KEM/ML-DSA: NIST post-quantum standards
- ✅ HKDF-SHA256: RFC 5869 standard

### Recommendations
1. **Do not use for life-or-death scenarios** until external audit
2. **Good for**: Journalists, activists, privacy advocates
3. **Use with caution for**: Whistleblowers in hostile countries
4. **Not recommended for**: National security secrets

---

## Best Practices

### For Maximum Security

1. **Enable All Encryption**
   - Double Ratchet
   - MLS Protocol
   - Post-Quantum crypto

2. **Use Network Privacy**
   - Enable Tor or I2P
   - Use bridges in censored countries
   - Avoid VPNs (use Tor instead)

3. **Enable Advanced Features**
   - Surveillance detection
   - Location randomization
   - Metadata stripping

4. **Device Security**
   - Full disk encryption
   - Strong password/PIN
   - Hardware security (TPM/Secure Enclave)
   - Auto-lock enabled

5. **Operational Security**
   - Verify contacts out-of-band
   - Don't reuse passwords
   - Use 2FA everywhere
   - Practice least privilege

6. **Regular Maintenance**
   - Keep CRYPTOGRAM updated
   - Review security settings
   - Check for surveillance alerts
   - Rotate credentials periodically

---

### For Whistleblowers

**CRITICAL**: If you're a whistleblower, you need extreme security.

1. **Use Tails OS** or similar amnesic operating system
2. **Use Tor Browser** for all web access
3. **Never** use your real phone number
4. **Use burner devices** purchased anonymously
5. **Never** connect to personal WiFi
6. **Use** public WiFi with MAC randomization
7. **Verify** reporter's public key out-of-band
8. **Consider** using additional tools (SecureDrop, OnionShare)

**Recommended Setup**:
- Tails OS (USB boot)
- CRYPTOGRAM over Tor
- Burner Android phone (cash purchase)
- Anonymous SIM card
- Public WiFi only

---

### For Journalists

1. **Protect Sources**
   - Enable all encryption features
   - Use Tor/I2P for anonymity
   - Location randomization for source meetings
   - Audio steganography for covert messages

2. **Secure Communication**
   - Verify source identity out-of-band
   - Use disappearing messages
   - Regular security audits
   - Separate work/personal devices

3. **Data Security**
   - Encrypted device storage
   - Secure backups (encrypted, offline)
   - Access controls
   - Regular data purging

---

### For Activists

1. **Protect Identity**
   - Location randomization
   - Tor/I2P routing
   - Metadata stripping
   - Pseudonymous accounts

2. **Secure Organization**
   - MLS group encryption
   - Verified contact lists
   - Secure meeting coordination
   - Counter-surveillance measures

3. **Operational Security**
   - Surveillance detection enabled
   - Regular security training
   - Incident response plan
   - Legal support contacts

---

## Security Updates

### How Updates Work
- **Automatic checks**: CRYPTOGRAM checks for updates daily
- **Security patches**: Critical patches released immediately
- **Feature updates**: Monthly release cycle
- **Notification**: In-app notification for critical updates

### Update Verification
- All releases signed with GPG key
- SHA-256 checksums provided
- Reproducible builds (planned)
- Open source transparency

### Security Advisories
- **Email**: security@cryptogram.org
- **GitHub**: Security advisories on repository
- **PGP Key**: Available on website

---

## Incident Response

### If You Suspect Compromise

1. **Immediate Actions**
   - Stop using the app immediately
   - Don't delete anything (evidence)
   - Document what happened
   - Take screenshots if safe

2. **Assessment**
   - Review surveillance detection alerts
   - Check for unusual device behavior
   - Scan for malware
   - Review recent activities

3. **Recovery**
   - Report to security@cryptogram.org
   - Change all passwords
   - Revoke compromised keys
   - Factory reset device (if needed)
   - Inform contacts if necessary

4. **Prevention**
   - Analyze what went wrong
   - Improve security practices
   - Update security procedures
   - Consider professional help

---

## Reporting Security Issues

### Responsible Disclosure

**DO**:
- Email security@cryptogram.org
- Include detailed description
- Provide proof of concept (if safe)
- Give us time to fix (90 days)
- Use PGP encryption

**DON'T**:
- Publicly disclose immediately
- Exploit vulnerabilities
- Harm users
- Sell vulnerabilities

### Bug Bounty Program

**Status**: Coming soon

**Scope**: All CRYPTOGRAM code
**Rewards**: Based on severity
- Critical: $5,000+
- High: $1,000-$5,000
- Medium: $500-$1,000
- Low: $100-$500

---

## Security Roadmap

### Planned Improvements

**Short-term** (3-6 months):
- External security audit
- Reproducible builds
- Enhanced anti-forensics
- Improved surveillance detection

**Medium-term** (6-12 months):
- Hardware security key support (YubiKey, etc.)
- Encrypted contact discovery
- Anonymous account creation
- Advanced traffic analysis resistance

**Long-term** (12+ months):
- Full metadata privacy
- Quantum-resistant storage
- Decentralized architecture
- Zero-knowledge proofs

---

## Compliance & Standards

### Standards Compliance
- ✅ NIST Post-Quantum Cryptography
- ✅ IETF MLS Protocol (RFC 9420)
- ✅ Signal Protocol Specification
- ✅ GDPR Privacy Requirements
- ✅ FIPS 140-2 Algorithms (where available)

### Certifications
- ⏳ SOC 2 Type II (planned)
- ⏳ ISO 27001 (planned)
- ⏳ Common Criteria EAL4+ (planned)

---

## Conclusion

CRYPTOGRAM provides strong security for most threat models. However, **no system is 100% secure**. Use CRYPTOGRAM as part of a comprehensive security strategy, not as your only protection.

**Remember**:
- Security is a process, not a product
- Understand your threat model
- Practice good operational security
- Keep software updated
- Stay informed about security

For questions or concerns, contact: **security@cryptogram.org**
