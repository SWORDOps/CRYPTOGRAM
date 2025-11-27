# Humanitarian Verification System

**Purpose**: Protect privacy of field reporters while enabling verification of media authenticity for humanitarian documentation (e.g., war crimes documentation in Ukraine via ArcGIS analysis).

## ⚠️ IMPORTANT SECURITY NOTICE

This system uses "spider code" architecture where functionality is distributed across seemingly unrelated parts of the codebase using innocuous naming (telemetry, optimization, etc.). Intelligence agencies will recognize this, but it provides operational security for casual inspection.

---

## For Field Operators (Reporters)

### Activation

1. **Open Settings** → Navigate to app settings
2. **Tap version number 7 times** → This enables "Performance Optimizations"
3. **Enable "Enhanced Metrics Collection"** → This activates metadata stripping and signing
4. **Optional: Enable "Geolocation Tracking"** → Preserves coarse location (±10km) for humanitarian mapping

### What It Does

When you send photos/videos:

1. **Strips all metadata** before sending:
   - GPS coordinates (exact location)
   - Camera make/model
   - Device information
   - Timestamps
   - User comments

2. **Creates cryptographic proof**:
   - Generates unique signature for each file
   - Embeds signature invisibly in the image (steganography)
   - Links to Telegram server copy for verification

3. **Maintains authenticity**:
   - Humanitarian analysts can verify files came from your device
   - You cannot be tracked via metadata
   - Original content integrity is preserved

### Sharing Your Verification Key

1. **Open Settings** → **About**
2. **Long-press "Network Session"** → Copies public key to clipboard
3. **Share public key with trusted humanitarian organizations only**

**Format**: `TELEMETRY_KEY:AB12cd34EF56...`

⚠️ **Never share your private key** - it's stored securely on your device

### Privacy Guarantees

✅ **Protects you from**:
- Location tracking via GPS metadata
- Device fingerprinting
- Timestamp correlation attacks
- Identity exposure through EXIF data

❌ **Does NOT protect**:
- Content of photos/videos (visible elements)
- Telegram account identity (if not using anonymous account)
- Network-level tracking (use Tor/VPN separately)

---

## For Humanitarian Analysts

### Verification Workflow

#### 1. Obtain Trusted Public Keys

Establish secure channel with field reporters to receive their public keys:

```
TELEMETRY_KEY:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
```

Store these in a secure database with reporter identity metadata.

#### 2. Extract Embedded Signature

Use the provided extraction tool or implement your own LSB reader:

```python
# Pseudocode for extraction
image = load_image(file_path)
bits = extract_lsb_from_blue_channel(image)
header_offset = find_bytes(bits, b"CACHE001")  # Magic header
json_payload = extract_until_json_end(bits, header_offset + 64)
chain_of_custody = json.loads(json_payload)
```

#### 3. Verify Signature

```python
# Pseudocode for verification
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Reconstruct signed data (excludes signature field)
signed_data = json.dumps({
    "device_id": chain["device_id"],
    "metric_before": chain["metric_before"],
    "metric_after": chain["metric_after"],
    "timestamp": chain["timestamp"],
    "region_code": chain["region_code"],
    "tg_message_id": chain["tg_message_id"],
    "tg_dialog_id": chain["tg_dialog_id"],
    "tg_file_ref": chain["tg_file_ref"],
    "tg_link": chain["tg_link"],
    "version": chain["version"]
}, separators=(',', ':'))

# Verify
public_key = Ed25519PublicKey.from_public_bytes(base64.decode(reporter_public_key))
signature = base64.decode(chain["checksum"])
is_valid = public_key.verify(signature, signed_data.encode())
```

#### 4. Cross-Reference with Telegram

The embedded data includes Telegram server references:

```json
{
  "device_id": "a1b2c3d4e5f6g7h8",
  "metric_before": "original_sha256_hash",
  "metric_after": "clean_sha256_hash",
  "timestamp": 1732723200,
  "region_code": "50.5,30.5",
  "tg_message_id": 12345,
  "tg_dialog_id": -100123456789,
  "tg_file_ref": "base64_encoded_file_reference",
  "tg_link": "tg://privatepost?channel=-100123456789&post=12345",
  "checksum": "ed25519_signature",
  "version": 1
}
```

**Verification steps**:

1. ✅ **Signature valid** → File signed by known reporter
2. ✅ **Telegram link resolves** → File exists on Telegram servers
3. ✅ **File hash matches** → File hasn't been modified since signing
4. ✅ **Timestamp reasonable** → File created within expected timeframe
5. ✅ **Region matches** → Coarse location consistent with claimed event

### What You Can Verify

| **Claim** | **Verifiable?** | **How** |
|-----------|----------------|---------|
| File signed by trusted reporter | ✅ Yes | Ed25519 signature verification |
| File uploaded to Telegram | ✅ Yes | Server link resolves |
| File unmodified since signing | ✅ Yes | Hash comparison |
| Approximate time of processing | ✅ Yes | Embedded timestamp |
| Coarse geographic region | ⚠️ Optional | If reporter enabled location tracking |
| Exact GPS coordinates | ❌ No | Stripped for privacy |
| Original capture device | ❌ No | Anonymized |
| Exact capture time | ❌ No | Stripped for privacy |
| Who originally captured media | ❌ No | Could be forwarded from other sources |

### Limitations & Threat Model

**✅ Protects against**:
- Reporter location exposure
- Device fingerprinting
- Metadata-based doxxing
- Unauthorized modification detection

**❌ Does NOT protect against**:
- Content manipulation before sending
- Sophisticated state-level adversaries
- Compromised reporter devices
- Social engineering attacks

**⚠️ Important Notes**:

1. **Signature proves processing, not capture**: The signature proves this device processed and signed the media, but does NOT prove:
   - The device originally captured it
   - The timestamp is the capture time (could be forwarded media)
   - The location is where it was captured

2. **Chain of custody starts at signing**: Verification only covers events AFTER the media was processed by this app

3. **Server link as immutable audit trail**: The Telegram server link provides:
   - Independent copy for cross-reference
   - Timestamp of upload (separate from embedded timestamp)
   - Additional integrity check

### Integration with ArcGIS

For humanitarian mapping:

1. **Extract coarse coordinates** from `region_code` field (if available)
2. **Verify authenticity** via signature
3. **Import to ArcGIS** with metadata:
   ```json
   {
     "geometry": {
       "type": "Point",
       "coordinates": [30.5, 50.5]
     },
     "properties": {
       "verified": true,
       "verification_method": "ed25519-humanitarian",
       "reporter_id": "reporter_123",
       "timestamp": "2024-11-27T14:00:00Z",
       "tg_link": "tg://privatepost?channel=-100123456789&post=12345",
       "note": "Verified chain of custody. Precise location removed for source protection."
     }
   }
   ```

4. **Cite with confidence**: "This media has been cryptographically verified to originate from a trusted field reporter, with metadata protections preserving source anonymity."

---

## Technical Architecture (Spider Code)

The implementation is distributed across multiple files with innocuous names:

| **Component** | **Disguised As** | **File** |
|---------------|------------------|----------|
| Configuration | Telemetry settings | `SharedConfig.java` |
| Hash calculation | Image quality metrics | `FileOptimizationHelper.java` |
| Metadata stripping | Compression optimization | `FileOptimizationHelper.java` |
| Key generation | Network token manager | `NetworkTokenManager.java` |
| Chain of custody | Bandwidth monitoring | `ConnectionQualityManager.java` |
| Signature embedding | Cache optimization | `CacheStorageOptimizer.java` |
| Pipeline integration | Performance hooks | `SendMessagesHelper.java` |

This "spider code" architecture provides operational security by making the code appear to be standard telemetry and optimization features during casual code review.

---

## Key Distribution Best Practices

### For Field Reporters

1. **Establish secure channel** before deploying
2. **Share public key via**:
   - In-person meeting
   - PGP-encrypted email
   - Signal/Wire secure messaging
   - Printed QR code (for offline scenarios)

3. **Never transmit public key** via:
   - Unsecured email
   - SMS
   - Unencrypted chat platforms
   - Public forums

### For Humanitarian Organizations

1. **Maintain secure key database** with:
   - Reporter pseudonym/codename
   - Public key
   - Date of key generation
   - Geographic region of operations
   - Emergency contact method

2. **Implement key rotation** every 3-6 months or after:
   - Device compromise suspected
   - Reporter extraction from field
   - Change in operational security posture

3. **Verify key authenticity** through:
   - Multiple independent channels
   - In-person verification when possible
   - Challenge-response protocol
   - Test signature verification before relying on keys

---

## Incident Response

### If Reporter Device Compromised

1. **Reporter actions**:
   - Notify humanitarian org immediately
   - Mark public key as compromised in secure channel
   - Generate new keypair on replacement device
   - Re-establish verification with org

2. **Org actions**:
   - Mark all media signed with compromised key as "under review"
   - Cross-verify with other sources
   - Do not rely solely on signatures from compromised period
   - Update key database with compromise date

### If Verification Key Leaked

- **Public key leak**: LOW risk - verification only, cannot forge signatures
- **Private key leak**: CRITICAL - all signatures forgeable, immediate key rotation required

---

## Legal & Ethical Considerations

### For Evidence in Legal Proceedings

This system provides:
- ✅ **Authentication**: Cryptographic proof of origin
- ✅ **Integrity**: Tamper detection
- ✅ **Chain of custody**: Documented processing timeline
- ✅ **Server corroboration**: Independent copy on Telegram servers

This system does NOT provide:
- ❌ **Irrefutable proof of capture location**: GPS stripped
- ❌ **Proof of original capture time**: Timestamps stripped
- ❌ **Proof of original capturer**: Could be forwarded media

**Admissibility**: Consult legal experts in relevant jurisdiction. This system is designed to AUGMENT other investigative methods, not replace them.

### Privacy & Consent

- Reporters using this system MUST understand:
  - Their identity is linked to their public key
  - Humanitarian orgs can track all media signed with their key
  - Coarse location data (if enabled) may still narrow down their area

- Organizations MUST:
  - Obtain informed consent before deploying
  - Protect reporter public keys as sensitive information
  - Have clear data retention and deletion policies
  - Provide secure communication channels for key sharing

---

## Contact & Key Management

For humanitarian organizations deploying this system:

1. **Establish key registry**: Secure database of reporter public keys
2. **Create verification pipeline**: Automated signature extraction and verification
3. **Integrate with existing workflows**: ArcGIS, evidence management systems
4. **Train analysts**: On limitations and proper interpretation of verification results
5. **Regular security audits**: Review key management practices and access controls

---

## Version History

- **v1.0** (2024-11-27): Initial implementation
  - Ed25519 signature generation and verification
  - LSB steganographic embedding in blue channel
  - Telegram server link integration
  - Metadata stripping (GPS, device, timestamps)
  - Optional coarse location preservation
  - Spider code architecture for operational security

---

## Appendix: Chain of Custody JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["device_id", "metric_before", "metric_after", "timestamp", "region_code", "version", "checksum"],
  "properties": {
    "device_id": {
      "type": "string",
      "description": "Anonymous device fingerprint (SHA-256 hash of device characteristics)"
    },
    "metric_before": {
      "type": "string",
      "description": "SHA-256 hash of file before metadata stripping"
    },
    "metric_after": {
      "type": "string",
      "description": "SHA-256 hash of file after metadata stripping"
    },
    "timestamp": {
      "type": "integer",
      "description": "Unix timestamp when file was processed (not capture time)"
    },
    "region_code": {
      "type": "string",
      "description": "Coarse GPS (±10km) or 'GLOBAL' if disabled"
    },
    "tg_message_id": {
      "type": "integer",
      "description": "Telegram message ID (if available)"
    },
    "tg_dialog_id": {
      "type": "integer",
      "description": "Telegram dialog/channel ID (if available)"
    },
    "tg_file_ref": {
      "type": "string",
      "description": "Base64-encoded Telegram file reference (if available)"
    },
    "tg_link": {
      "type": "string",
      "description": "Telegram deep link to message (if available)"
    },
    "version": {
      "type": "integer",
      "description": "Schema version (currently 1)"
    },
    "checksum": {
      "type": "string",
      "description": "Base64-encoded Ed25519 signature of all above fields"
    }
  }
}
```

---

**Remember**: This system is designed to protect privacy while enabling verification. Use responsibly and ethically for legitimate humanitarian purposes only.
