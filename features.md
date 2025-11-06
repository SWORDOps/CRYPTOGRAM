# CRYPTOGRAM Features

## 🔐 Advanced Security Features

### 1. **Audio Steganography Engine** ⭐ NEW & UNIQUE
Hide encrypted messages inside voice notes and audio files with complete statistical undetectability.

**Key Features:**
- 8 steganography methods (LSB, Spectral Masking, Echo Hiding, Phase Modulation, etc.)
- 100 bits/second undetectable embedding rate
- SNR >40dB (maintains perfect audio quality)
- AES-256 encrypted payloads
- Psychoacoustic masking for imperceptibility
- Reed-Solomon error correction

**Use Cases:** Covert communication, censorship bypass, plausible deniability, whistleblower protection

---

### 2. **Location Randomization System** ⭐ NEW & UNIQUE
Prevent geolocation tracking with realistic, culturally-appropriate fake locations.

**Key Features:**
- Phone number-based geolocation analysis
- Realistic location profiles (addresses, GPS, timezones)
- Cultural context matching
- Automatic rotation (per-session, daily, weekly)
- Decoy location generation (20% fake locations)
- 50+ geographic regions

**Use Cases:** Anti-tracking, journalist safety, activist protection, privacy enhancement

---

### 3. **Surveillance Detection System** ⭐ NEW & UNIQUE
Active detection and alerting for surveillance attempts on your device.

**Key Features:**
- Process monitoring detection (debuggers, profilers, monitoring tools)
- Memory scanning detection
- Network traffic anomaly analysis
- Behavioral anomaly detection using AI/ML
- Real-time threat alerts with severity classification
- Automatic countermeasure activation
- Forensic data collection

**Use Cases:** Government surveillance detection, corporate espionage prevention, malware detection

---

### 4. **Covert Channel Engine** ⭐ NEW & UNIQUE
Hidden communication channels that bypass censorship and Deep Packet Inspection (DPI).

**Key Features:**
- Multiple channel types (timing-based, storage-based, network-based)
- DPI (Deep Packet Inspection) evasion
- Firewall traversal and traffic shaping resistance
- Protocol whitelisting bypass
- Statistical undetectability
- Encrypted channel establishment

**Use Cases:** Censorship resistance, firewall bypass, anti-monitoring, restrictive networks

---

### 5. **Enhanced Privacy System** ⭐ NEW
Additional encryption layer with comprehensive metadata protection.

**Key Features:**
- Extra encryption layer beyond E2EE
- Passphrase-based encryption
- Time-based key derivation (TOTP-style)
- Metadata stripping (EXIF, GPS, timestamps)
- Screenshot prevention and recording detection
- Auto-deletion with secure overwrite
- File sanitization

**Use Cases:** Defense in depth, metadata privacy, temporary communication, document security

---

### 6. **Double Ratchet Protocol** ⭐ NEW
Signal Protocol implementation with forward secrecy and break-in recovery.

**Key Features:**
- X25519 (Curve25519) key exchange
- Ed25519 digital signatures
- AES-256-CBC message encryption
- HKDF key derivation
- Forward secrecy (old keys deleted after use)
- Break-in recovery (future messages secure after compromise)
- Out-of-order message handling
- Hardware security module (TSM) integration: TPM 2.0, Android KeyStore, Apple Secure Enclave

**Use Cases:** Secure end-to-end encrypted messaging, forward secrecy, hardware-backed security

---

## 🛡️ Supporting Security Modules

### 7. **Adaptive Countermeasures** ⭐ NEW
Dynamic security adjustments based on detected threats.

- Real-time threat response
- Multi-layer defense mechanisms
- Security posture adaptation
- Automated threat mitigation

---

### 8. **Countermeasure Randomizer** ⭐ NEW
Anti-fingerprinting through behavior randomization.

- Randomize security behaviors
- Unpredictable response patterns
- Traffic pattern obfuscation
- Timing obfuscation

---

### 9. **Universal Security Validator** ⭐ NEW
Comprehensive security validation and auditing.

- Multi-platform security checks
- Cryptographic validation
- Configuration auditing
- Security compliance verification

---

## 💬 Messaging Features

*(Features inherited from 64Gram/Telegram Desktop)*

### Chat Features
1. Show Chat ID
2. Show admin titles in member list
3. Show chat restriction reason on profile page
4. Ban members option in Recent Actions
5. Always show discuss button if channel has discussion group
6. Search Messages From User (Right click user pic or member list)
7. Repeat user message to current group
8. Recent Actions/Admins list button in top bar
9. Show service message time
10. Show message ID in tooltip/message box
11. Show user total sent messages when you're deleting a message
12. Always delete message option (Group/Person/Both)
13. View Channel Button in Group Info widget
14. Show online member count if supergroup member >= 200 (more accurate)
15. Show/Hide/View pinned message
16. Allow pin older message with notify
17. Hide messages from blocked user
18. Message time with seconds
19. Show sender's avatar in groups

### Account & Contact Features
20. Multiple accounts up to **10**
21. Don't share my phone number when add someone to contacts
22. Show Phone Number option
23. User Bio clickable
24. `tg://openmessage` and `tg://user` clickable
25. Mention user via Create Link with `tg://user?id=123456`

### Message Management
26. Support multiple chat forward
27. Support Forward Message without quote
28. Quick Forward to Saved Messages
29. Shortcut for Fast Forward/Copy messages (ALT+F/ALT+C)
30. Add quick forward when pressed ctrl
31. Copy inline button callback data to Clipboard
32. Expose all chat permissions setting

### Media & Files
33. Upload/Download Boost Setting
34. Support sending and viewing location
35. Sticker pack owner info
36. Recent sticker display limit

### Group Management
37. Create new supergroup
38. [Restore] Convert to Supergroup feature
39. [Restore] upgraded to supergroup service message
40. [Restore] Discussion group button
41. Show bot privacy in member list and profile
42. Show admin title in admin list
43. Ban button for Join Requests

### Voice Chat Features
44. Voice Chat Radio mode
45. Auto unmute option
46. Voice chat bitrate option
47. Allow pin Voice Chat window to top
48. Hide 1 to 1 call panel window when press X (close window)

### Interface & UX
49. Disable Cloud Draft Sync To Local
50. Always Show Scheduled Button option
51. Mark All Chats As Read for "All Chats" Folder
52. Hide "All chats" folder option
53. Remove all proxies
54. Allow open link without warning
55. Disable Premium Animation
56. Hide stories
57. "Uncolored Quote" option
58. Disable global search
59. Support to drag and drop in the filter menu

### Privacy Features (Basic)
60. **Screenshot privacy mode** 🔒
61. Location sharing with randomization 🔒 **(Enhanced by Location Randomization System)**
62. Metadata stripping 🔒 **(Enhanced by Enhanced Privacy System)**

---

## 🎨 Customization

- Multiple theme support
- Custom color schemes
- Font size adjustments
- Interface scaling
- Chat background customization

---

## 🌐 Platform Support

- **Windows** 7 and above (x64)
- **Linux** 64-bit (most distributions)
- **macOS** 10.12 and above (x64, ARM64)

---

## 📚 Documentation

For detailed information about advanced security features:
- **[FIVE_FEATURES_PORT.md](FIVE_FEATURES_PORT.md)** - Complete guide to 5 advanced security features
- **[DOUBLE_RATCHET_PORT.md](DOUBLE_RATCHET_PORT.md)** - Double Ratchet implementation details
- **[AVAILABLE_SPYGRAM_FEATURES.md](AVAILABLE_SPYGRAM_FEATURES.md)** - Catalog of available features

---

## 🆚 Feature Comparison

| Feature Category | Signal | Telegram | WhatsApp | CRYPTOGRAM |
|------------------|--------|----------|----------|------------|
| **End-to-End Encryption** | ✅ | 🟡 Secret Chats | ✅ | ✅ |
| **Audio Steganography** | ❌ | ❌ | ❌ | ✅ **UNIQUE** |
| **Location Privacy** | ❌ | ❌ | ❌ | ✅ **UNIQUE** |
| **Surveillance Detection** | ❌ | ❌ | ❌ | ✅ **UNIQUE** |
| **Covert Channels** | ❌ | ❌ | ❌ | ✅ **UNIQUE** |
| **Metadata Stripping** | 🟡 | ❌ | ❌ | ✅ |
| **Hardware Security** | ❌ | ❌ | ❌ | ✅ TPM/KeyStore |
| **Forward Secrecy** | ✅ | 🟡 | ✅ | ✅ |
| **Cloud Sync** | ❌ | ✅ | ❌ | ✅ |
| **Group Chats** | ✅ | ✅ | ✅ | ✅ |
| **Voice/Video Calls** | ✅ | ✅ | ✅ | ✅ |
| **Multi-Device** | ✅ Limited | ✅ | ✅ Limited | ✅ |
| **Open Source** | ✅ | ✅ Client | ❌ | ✅ |

---

## 🏆 What Makes CRYPTOGRAM Unique

### ✅ Only Messenger With Audio Steganography
Hide encrypted messages in voice notes - completely invisible to detection

### ✅ Most Advanced Location Privacy
Realistic fake locations with cultural context and automatic rotation

### ✅ Active Surveillance Detection
Real-time monitoring for threats and automatic countermeasures

### ✅ Covert Communication Channels
Bypass any censorship or firewall with hidden channels

### ✅ Multi-Layer Security Architecture
5 layers of protection from infrastructure to covert communication

### ✅ Hardware-Backed Encryption
TPM 2.0, Android KeyStore, Apple Secure Enclave integration

### ✅ Open Source & Auditable
All security code is open source and available for audit

---

## 🎯 Perfect For

- **Journalists** protecting sources and reporting from hostile regions
- **Activists** organizing in countries with internet censorship
- **Whistleblowers** needing plausible deniability and covert channels
- **Privacy Advocates** wanting maximum protection
- **International Users** in countries with surveillance and censorship
- **Security Professionals** requiring military-grade communication security

---

## 📊 Feature Statistics

- **Total Features**: 60+ basic features + 6 advanced security systems
- **Lines of Security Code**: ~21,000 lines
- **Steganography Methods**: 8 different techniques
- **Geographic Regions**: 50+ with realistic profiles
- **Encryption Layers**: 5-layer security architecture
- **Platform Support**: Windows, Linux, macOS

---

## 🚀 Coming Soon

- Quantum-resistant encryption
- Tor network integration
- P2P encrypted calls
- Secure group steganography
- Advanced traffic analysis resistance

---

**Last Updated**: November 2025

For the most up-to-date feature list and documentation, see [README.md](README.md)
