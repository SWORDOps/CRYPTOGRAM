# PKI Trust Model for Humanitarian Verification

## Overview

Three-tier hierarchical trust model with **single root authority** (SWORD Ops) that certifies intermediate CAs (humanitarian organizations), who then certify end-user devices.

---

## Trust Hierarchy

```
Root CA: SWORD Ops
    │ (Root key stored in bank vault)
    │ (Defines ultimate trust policy)
    │
    ├─→ Intermediate CA: Human Rights Watch
    ├─→ Intermediate CA: International Criminal Court
    ├─→ Intermediate CA: Amnesty International
    ├─→ Intermediate CA: Bellingcat
    ├─→ Intermediate CA: Reuters/AP
    └─→ [Other Certified Orgs]
         │
         └─→ End Entity: Device Keys (End Users)
              │
              └─→ Signed Media Files
```

**Key Principle**: You (SWORD Ops) are the ultimate root of trust. You decide which organizations become intermediate CAs by issuing them certificates with your root key.

---

## Architecture

### 1. **Root CA (SWORD Ops)**

**You** are the ultimate root authority. Generate and secure your root keypair:

```bash
# Generate SWORD Ops root keypair (AIR-GAPPED COMPUTER ONLY)
openssl genpkey -algorithm ed25519 -out sword_root_ca.pem

# Extract public key
openssl pkey -in sword_root_ca.pem -pubout -out sword_root_ca_public.pem

# Encrypt private key with strong passphrase
openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -salt \
  -in sword_root_ca.pem \
  -out sword_root_ca_encrypted.pem

# CRITICAL: Store encrypted key in bank vault
# - Physical security (safe deposit box)
# - Multiple geographic locations
# - Split key custody (Shamir secret sharing - optional)
# - NEVER connect air-gapped computer to network
```

**Root CA Attributes** (publicly published):
```json
{
  "org_name": "SWORD Ops",
  "role": "Root Certificate Authority",
  "root_public_key": "base64_encoded_public_key",
  "established": "2024-11-27",
  "scope": "global_humanitarian_verification",
  "policy_url": "https://swordops.org/verification-policy",
  "intermediate_ca_list": "https://swordops.org/trusted-cas.json",
  "revocation_list": "https://swordops.org/revoked-cas.json",
  "contact": "verification@swordops.org"
}
```

### 2. **Intermediate CAs (Humanitarian Organizations)**

Organizations you trust generate their **intermediate CA keypairs** and request certification from you:

```bash
# Organization generates intermediate CA keypair
openssl genpkey -algorithm ed25519 -out hrw_intermediate_ca.pem
openssl pkey -in hrw_intermediate_ca.pem -pubout -out hrw_intermediate_ca_public.pem
```

**Intermediate CA Attributes**:
```json
{
  "org_name": "Human Rights Watch",
  "intermediate_public_key": "base64_encoded_public_key",
  "established": "2024-11-27",
  "scope": "global",
  "contact": "verification@hrw.org",
  "certificate_policy_url": "https://hrw.org/media-verification-policy",
  "end_entity_revocation_list": "https://hrw.org/revoked-devices.json"
}
```

**You issue them a certificate** signed with your root key:

```python
# sword_ops_root_ca.py
# Run on air-gapped computer with root key

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import json
import base64
import time

# Load your root private key (from encrypted vault copy)
with open('sword_root_ca.pem', 'rb') as f:
    ROOT_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(f.read())

def issue_intermediate_ca_certificate(org_name, org_public_key, scope, policy_url):
    """Issue certificate to intermediate CA"""

    now = int(time.time())
    expiry = now + (3 * 365 * 24 * 60 * 60)  # 3 years validity for CAs

    certificate = {
        "version": 1,
        "certificate_type": "intermediate_ca",
        "subject": {
            "org_name": org_name,
            "established_date": now,
            "expiry_date": expiry,
            "scope": scope,
            "policy_url": policy_url
        },
        "public_key": org_public_key,
        "issuer": {
            "org_name": "SWORD Ops",
            "root_public_key": base64.b64encode(ROOT_PRIVATE_KEY.public_key().public_bytes()).decode()
        },
        "certificate_id": f"SWORD-{org_name.replace(' ', '')}-{now}",
        "path_length_constraint": 0,  # Cannot issue sub-CAs, only end entity certs
        "key_usage": ["certificate_signing", "crl_signing"],
        "basic_constraints": {
            "is_ca": True,
            "max_end_entities": 100000  # Can certify up to 100k devices
        }
    }

    # Sign with root key
    cert_data = json.dumps(certificate, separators=(',', ':')).encode()
    signature = ROOT_PRIVATE_KEY.sign(cert_data)
    certificate["signature"] = base64.b64encode(signature).decode()

    # Log issuance (for audit)
    with open('issued_intermediate_cas.log', 'a') as f:
        f.write(json.dumps(certificate) + '\n')

    # Return certificate
    cert_b64 = base64.b64encode(json.dumps(certificate).encode()).decode()
    return cert_b64

# Example: Certify Human Rights Watch
hrw_cert = issue_intermediate_ca_certificate(
    org_name="Human Rights Watch",
    org_public_key="<HRW_PUBLIC_KEY_BASE64>",
    scope="global",
    policy_url="https://hrw.org/media-verification-policy"
)

print(f"Intermediate CA Certificate for Human Rights Watch:")
print(hrw_cert)

# Store in trusted CAs list (publish publicly)
with open('trusted_intermediate_cas.json', 'a') as f:
    f.write(json.dumps({
        "org_name": "Human Rights Watch",
        "certificate": hrw_cert,
        "added_date": time.time()
    }) + '\n')
```

**Key Management Separation**:

- **You (SWORD Ops)** manage ONLY:
  - Your root private key (bank vault)
  - List of trusted intermediate CAs (published publicly)
  - Intermediate CA revocation list (if CA compromised)

- **Each org** manages their OWN:
  - Their intermediate CA private key (their responsibility)
  - Their certificate issuance server
  - Their end-entity device revocation list
  - Their certificate policy

**You do NOT manage org keys** - once you sign their certificate, they're independent. You only revoke them if compromised or violated policy.

### 3. **Device Key Certification (End Entities)**

When user installs app, they can optionally request certification from any trusted intermediate CA:

**Current Flow** (no certification):
```
Device → Generate Ed25519 keypair → Sign media → Send to Telegram
```

**PKI Flow** (with certification):
```
Device → Generate Ed25519 keypair
       → Request certification from trusted org
       → Org vets user (optional, can be automatic)
       → Org issues certificate (signs device public key)
       → Device stores certificate
       → Sign media with device key + include certificate
       → Send to Telegram
```

### 3. **Certificate Structure**

**Device Certificate** (issued by Root CA):

```json
{
  "version": 1,
  "subject": {
    "device_id": "anonymous_device_fingerprint",
    "pseudonym": "reporter_ukraine_47",  // Optional
    "region": "Eastern Europe",           // Coarse
    "issued_date": "2024-11-27T14:00:00Z",
    "expiry_date": "2025-11-27T14:00:00Z"  // 1 year validity
  },
  "public_key": "base64_device_public_key",
  "issuer": {
    "org_name": "Human Rights Watch",
    "root_public_key": "base64_root_public_key"
  },
  "signature": "root_ca_signature_of_above_fields",
  "certificate_id": "unique_cert_id",
  "policy_constraints": {
    "max_video_size_mb": 500,
    "allowed_regions": ["Ukraine", "Syria", "*"],  // * = global
    "allowed_use": "humanitarian_documentation"
  }
}
```

**Certificate Signing**:
```python
# Root CA signs device certificate
certificate_data = json.dumps({
    "subject": {...},
    "public_key": device_public_key,
    "issuer": {...},
    "certificate_id": cert_id,
    "policy_constraints": {...}
}, separators=(',', ':'))

root_private_key = load_ed25519_private_key(root_ca_private_pem)
signature = root_private_key.sign(certificate_data.encode())

certificate["signature"] = base64.encode(signature)
```

---

## Implementation Changes

### Modified Chain of Custody Structure

Update `ConnectionQualityManager.java` to include certificate:

```java
public static String generateQualityReport(String path) {
    // ... existing code ...

    JSONObject report = new JSONObject();
    report.put("device_id", sample.getSampleId());
    report.put("metric_before", sample.getStartMetric());
    report.put("metric_after", sample.getEndMetric());
    report.put("timestamp", System.currentTimeMillis() / 1000);
    report.put("region_code", currentRegionCode);
    report.put("version", 1);

    // NEW: Include device certificate if present
    String certificate = SharedConfig.telemetryDeviceCertificate;
    if (certificate != null && !certificate.isEmpty()) {
        report.put("certificate", certificate);  // Base64-encoded certificate
        report.put("certified", true);
    } else {
        report.put("certified", false);
    }

    // Telegram server reference
    if (sample.hasServerReference()) {
        report.put("tg_message_id", sample.getMessageId());
        report.put("tg_dialog_id", sample.getDialogId());
        report.put("tg_file_ref", sample.getFileReference());
        report.put("tg_link", "tg://privatepost?channel=" + sample.getDialogId() + "&post=" + sample.getMessageId());
    }

    // Sign with device key (as before)
    String signature = NetworkTokenManager.signNetworkRequest(report.toString());
    if (signature != null) {
        report.put("checksum", signature);
    }

    return report.toString();
}
```

### Add Certificate Storage

In `SharedConfig.java`:

```java
// Performance and telemetry settings (spider code activation)
public static boolean telemetryEnhancedMetrics = true;
public static boolean telemetryGeolocationTracking = false;
public static int telemetryCompressionLevel = 85;
public static String telemetryDeviceToken = "";           // Device private key
public static String telemetryPublicKey = "";             // Device public key
public static String telemetryDeviceCertificate = "";     // NEW: Base64 certificate from CA
public static String telemetryCertificateChain = "";      // NEW: Full cert chain (if multi-level)
```

### Certificate Request API

**New file**: `CertificateManager.java`

```java
package org.telegram.messenger;

import org.json.JSONObject;
import java.net.HttpURLConnection;
import java.net.URL;
import android.util.Base64;

/**
 * Manages certificate requests and validation
 * [Actually: Device key certification by humanitarian orgs]
 */
public class CertificateManager {

    /**
     * Request certificate from trusted CA
     * @param caEndpoint CA's certificate issuance API
     * @param pseudonym Optional pseudonym for reporter
     * @param contactMethod Optional secure contact (Signal, ProtonMail, etc.)
     */
    public static void requestCertificate(String caEndpoint, String pseudonym, String contactMethod) {
        if (SharedConfig.telemetryPublicKey.isEmpty()) {
            NetworkTokenManager.initializeSessionTokens();
        }

        try {
            // Prepare certificate request
            JSONObject request = new JSONObject();
            request.put("public_key", SharedConfig.telemetryPublicKey);
            request.put("pseudonym", pseudonym != null ? pseudonym : "anonymous");
            request.put("contact_method", contactMethod != null ? contactMethod : "");
            request.put("device_fingerprint", getDeviceFingerprint());
            request.put("app_version", BuildVars.BUILD_VERSION_STRING);
            request.put("request_timestamp", System.currentTimeMillis() / 1000);

            // Sign request with device key (proves possession of private key)
            String requestSignature = NetworkTokenManager.signNetworkRequest(request.toString());
            request.put("signature", requestSignature);

            // Send to CA endpoint
            URL url = new URL(caEndpoint);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);

            byte[] requestBytes = request.toString().getBytes("UTF-8");
            conn.getOutputStream().write(requestBytes);

            // Receive certificate
            if (conn.getResponseCode() == 200) {
                byte[] responseBytes = new byte[conn.getInputStream().available()];
                conn.getInputStream().read(responseBytes);
                String response = new String(responseBytes, "UTF-8");

                JSONObject certResponse = new JSONObject(response);
                String certificate = certResponse.getString("certificate");

                // Validate certificate before storing
                if (validateCertificate(certificate)) {
                    SharedConfig.telemetryDeviceCertificate = certificate;
                    SharedConfig.getPreferences().edit()
                        .putString("telemetryDeviceCertificate", certificate)
                        .apply();

                    FileLog.d("Certificate successfully obtained and validated");
                } else {
                    FileLog.e("Certificate validation failed");
                }
            } else {
                FileLog.e("Certificate request failed: " + conn.getResponseCode());
            }

        } catch (Exception e) {
            FileLog.e("Certificate request error", e);
        }
    }

    /**
     * Validate certificate signature and expiry
     */
    public static boolean validateCertificate(String certificateB64) {
        try {
            String certJson = new String(Base64.decode(certificateB64, Base64.NO_WRAP), "UTF-8");
            JSONObject cert = new JSONObject(certJson);

            // Check expiry
            long expiryDate = cert.getJSONObject("subject").getLong("expiry_date");
            if (System.currentTimeMillis() / 1000 > expiryDate) {
                FileLog.e("Certificate expired");
                return false;
            }

            // Check if device public key matches
            String certPublicKey = cert.getString("public_key");
            if (!certPublicKey.equals(SharedConfig.telemetryPublicKey)) {
                FileLog.e("Certificate public key mismatch");
                return false;
            }

            // Verify CA signature
            String issuerPublicKey = cert.getJSONObject("issuer").getString("root_public_key");
            String signature = cert.getString("signature");

            // Reconstruct signed data (everything except signature)
            JSONObject certData = new JSONObject(cert.toString());
            certData.remove("signature");
            String signedData = certData.toString();

            // Verify signature with issuer's public key
            boolean valid = NetworkTokenManager.verifyNetworkRequest(signedData, signature, issuerPublicKey);

            if (valid) {
                FileLog.d("Certificate signature valid");
            } else {
                FileLog.e("Certificate signature invalid");
            }

            return valid;

        } catch (Exception e) {
            FileLog.e("Certificate validation error", e);
            return false;
        }
    }

    /**
     * Check if current certificate is valid
     */
    public static boolean hasSValidCertificate() {
        if (SharedConfig.telemetryDeviceCertificate.isEmpty()) {
            return false;
        }
        return validateCertificate(SharedConfig.telemetryDeviceCertificate);
    }

    /**
     * Get certificate details for display
     */
    public static String getCertificateInfo() {
        if (!hasValidCertificate()) {
            return "No valid certificate";
        }

        try {
            String certJson = new String(
                Base64.decode(SharedConfig.telemetryDeviceCertificate, Base64.NO_WRAP),
                "UTF-8"
            );
            JSONObject cert = new JSONObject(certJson);

            String orgName = cert.getJSONObject("issuer").getString("org_name");
            String pseudonym = cert.getJSONObject("subject").getString("pseudonym");
            long expiryDate = cert.getJSONObject("subject").getLong("expiry_date");

            return String.format("Certified by: %s\nPseudonym: %s\nExpires: %s",
                orgName, pseudonym, new java.util.Date(expiryDate * 1000));

        } catch (Exception e) {
            return "Certificate parse error";
        }
    }

    private static String getDeviceFingerprint() {
        // Same as ConnectionQualityManager's anonymous device ID
        String info = android.os.Build.MANUFACTURER + ":" +
                      android.os.Build.MODEL + ":" +
                      android.os.Build.VERSION.SDK_INT;
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(info.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < Math.min(16, hash.length); i++) {
                String hex = Integer.toHexString(0xff & hash[i]);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            return "UNKNOWN";
        }
    }
}
```

---

## Root CA Server Implementation

### Certificate Issuance Server (Example)

```python
# ca_server.py - Run by humanitarian organizations
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import json
import base64
import time

app = Flask(__name__)

# Load root CA keys (keep private key VERY secure)
with open('root_ca_private.pem', 'rb') as f:
    ROOT_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(f.read())

with open('root_ca_public.pem', 'rb') as f:
    ROOT_PUBLIC_KEY = Ed25519PublicKey.from_public_bytes(f.read())

ORG_NAME = "Human Rights Watch"

@app.route('/certificate/request', methods=['POST'])
def issue_certificate():
    """Issue certificate to device after verification"""
    try:
        req = request.get_json()

        # Verify request signature (proves device owns private key)
        device_public_key_b64 = req['public_key']
        device_public_key_bytes = base64.b64decode(device_public_key_b64)
        device_public_key = Ed25519PublicKey.from_public_bytes(device_public_key_bytes)

        # Reconstruct signed request
        request_data = {
            "public_key": req['public_key'],
            "pseudonym": req['pseudonym'],
            "contact_method": req['contact_method'],
            "device_fingerprint": req['device_fingerprint'],
            "app_version": req['app_version'],
            "request_timestamp": req['request_timestamp']
        }
        signed_data = json.dumps(request_data, separators=(',', ':')).encode()
        signature = base64.b64decode(req['signature'])

        try:
            device_public_key.verify(signature, signed_data)
        except:
            return jsonify({"error": "Invalid request signature"}), 400

        # Optional: Additional vetting
        # - Check contact method is valid
        # - Manual approval for high-trust certs
        # - Automated issuance for low-trust certs
        # - Rate limiting per device/IP

        # Determine trust level
        trust_level = determine_trust_level(req)  # 1=high, 2=medium, 3=low

        # Create certificate
        now = int(time.time())
        expiry = now + (365 * 24 * 60 * 60)  # 1 year

        certificate = {
            "version": 1,
            "subject": {
                "device_id": req['device_fingerprint'],
                "pseudonym": req['pseudonym'],
                "region": "Global",  # Or determine from IP/user input
                "issued_date": now,
                "expiry_date": expiry,
                "trust_level": trust_level
            },
            "public_key": req['public_key'],
            "issuer": {
                "org_name": ORG_NAME,
                "root_public_key": base64.b64encode(ROOT_PUBLIC_KEY.public_bytes()).decode()
            },
            "certificate_id": generate_unique_id(),
            "policy_constraints": {
                "max_video_size_mb": 500,
                "allowed_regions": ["*"],
                "allowed_use": "humanitarian_documentation"
            }
        }

        # Sign certificate with root CA key
        cert_data = json.dumps(certificate, separators=(',', ':')).encode()
        cert_signature = ROOT_PRIVATE_KEY.sign(cert_data)
        certificate["signature"] = base64.b64encode(cert_signature).decode()

        # Encode certificate
        cert_json = json.dumps(certificate)
        cert_b64 = base64.b64encode(cert_json.encode()).decode()

        # Log issuance (for audit trail)
        log_certificate_issuance(certificate)

        return jsonify({
            "certificate": cert_b64,
            "issuer": ORG_NAME,
            "expires": expiry,
            "trust_level": trust_level
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/certificate/revoke', methods=['POST'])
def revoke_certificate():
    """Revoke a compromised certificate"""
    # Implement certificate revocation list (CRL)
    # Add cert_id to revoked_keys.json
    pass

@app.route('/certificate/verify', methods=['POST'])
def verify_certificate():
    """Verify a certificate's validity"""
    cert_b64 = request.get_json()['certificate']
    # Implement verification logic
    # Check signature, expiry, revocation status
    pass

def determine_trust_level(request_data):
    """Determine trust level based on verification"""
    # Level 1 (High Trust): Manual approval, in-person vetting, identity verified
    # Level 2 (Medium Trust): Contact method verified (email/Signal), automated approval
    # Level 3 (Low Trust): No verification, automated issuance

    if request_data.get('contact_method'):
        return 2  # Medium trust
    else:
        return 3  # Low trust

    # For high trust, require manual approval flow

def generate_unique_id():
    import uuid
    return str(uuid.uuid4())

def log_certificate_issuance(cert):
    with open('certificate_log.json', 'a') as f:
        f.write(json.dumps(cert) + '\n')

if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # Use proper SSL cert in production
```

---

## Verification Workflow (Analyst Side)

### 1. **Extract Chain of Custody**

```python
# Extract signature from media
chain = extract_signature(video_file)

# Check if certified
if chain.get('certified'):
    certificate_b64 = chain['certificate']
    certificate = json.loads(base64.b64decode(certificate_b64))

    # Verify certificate
    if verify_certificate(certificate):
        # Check trust level
        trust_level = certificate['subject']['trust_level']
        org_name = certificate['issuer']['org_name']

        print(f"✓ Certified by: {org_name}")
        print(f"  Trust Level: {trust_level}")
        print(f"  Pseudonym: {certificate['subject']['pseudonym']}")
    else:
        print("✗ Invalid/expired certificate")
else:
    print("⚠ Uncertified (self-signed device key)")
```

### 2. **Trust Scoring**

```python
def calculate_trust_score(chain_of_custody):
    score = 0

    # Base: Valid device signature
    if verify_device_signature(chain):
        score += 30

    # Certificate present and valid
    if chain.get('certified') and verify_certificate(chain['certificate']):
        cert = json.loads(base64.b64decode(chain['certificate']))

        # Trust level from CA
        trust_level = cert['subject']['trust_level']
        if trust_level == 1:    # High trust
            score += 50
        elif trust_level == 2:  # Medium trust
            score += 30
        elif trust_level == 3:  # Low trust
            score += 15

        # Known CA bonus
        known_cas = ["Human Rights Watch", "ICC", "Bellingcat", "Amnesty"]
        if cert['issuer']['org_name'] in known_cas:
            score += 10

    # Telegram server reference
    if chain.get('tg_link'):
        score += 10

    # Corroboration with other sources
    similar_videos = find_similar_videos(chain['timestamp'], chain['region_code'])
    score += min(len(similar_videos) * 5, 20)  # Up to +20 for corroboration

    return min(score, 100)  # Cap at 100

# Example outputs:
# - Uncertified, no corroboration: 30/100
# - Low-trust CA, no corroboration: 55/100
# - Medium-trust CA, some corroboration: 75/100
# - High-trust CA, corroborated: 95/100
```

---

## Your Role as Root CA (SWORD Ops)

### Minimal Operational Overhead

Your responsibilities are **intentionally minimal**:

1. **Generate Root Key** (one-time, air-gapped):
   - Create Ed25519 root keypair
   - Encrypt with strong passphrase
   - Store in bank vault (safe deposit box)
   - **Never** bring online except for signing

2. **Certify Intermediate CAs** (rare, ~1-2 per month initially):
   - Org sends you their public key (via secure channel)
   - You verify org legitimacy (due diligence)
   - Sign their certificate on air-gapped computer
   - Publish to trusted CA list
   - **Process**: USB transfer, sign offline, USB return

3. **Publish Trusted CA List** (automated):
   - Host `https://swordops.org/trusted-cas.json`
   - Updated whenever new CA added
   - Clients check this list periodically

4. **Revoke Compromised CAs** (emergency only):
   - If org compromised, add to revocation list
   - Publish to `https://swordops.org/revoked-cas.json`
   - **Rare event**, hopefully never

**That's it!** You do NOT:
- ❌ Manage org private keys
- ❌ Run certificate issuance servers
- ❌ Handle end-user requests
- ❌ Monitor day-to-day operations
- ❌ Manage device revocations (orgs do that)

**Time commitment**: ~1-2 hours per month after initial setup.

---

## Root CA Best Practices

### 1. **Key Security (Critical)**

```bash
# Generate root CA key offline (air-gapped computer)
openssl genpkey -algorithm ed25519 -out root_ca_private.pem

# Encrypt private key
openssl enc -aes-256-cbc -salt -in root_ca_private.pem -out root_ca_private.pem.enc

# Store encrypted key in:
# - Hardware Security Module (HSM)
# - Multiple geographic locations
# - Split key custody (Shamir secret sharing)
```

### 2. **Certificate Issuance Policy**

Each CA should publish a **Certificate Policy Statement**:

```markdown
# Human Rights Watch Media Verification Certificate Policy

## Trust Levels

**Level 1 (High Trust)**:
- In-person identity verification required
- Background check completed
- Training provided
- Direct contact with HRW staff
- Manual approval process
- Revocable at any time

**Level 2 (Medium Trust)**:
- Email/Signal verification required
- Automated approval after contact verification
- No identity verification
- Revocable upon abuse

**Level 3 (Low Trust)**:
- No verification required
- Automated issuance
- Provides basic chain of custody only
- Easily revocable

## Certificate Validity
- Maximum 1 year duration
- Renewable with re-verification
- Subject to revocation for misuse

## Revocation Policy
- Certificates revoked if:
  - Device compromised
  - Misuse detected (disinformation, spam)
  - User request
  - Security incident
- Revocation list updated hourly at: https://hrw.org/revoked-keys.json

## Liability
- Certificates provide technical assurance only
- No guarantee of content truthfulness
- Verification of authenticity, not veracity
```

### 3. **Multi-CA Ecosystem**

Users can hold certificates from multiple CAs:

```json
{
  "certified": true,
  "certificates": [
    {
      "issuer": "Human Rights Watch",
      "trust_level": 2,
      "expires": 1735300800
    },
    {
      "issuer": "Bellingcat",
      "trust_level": 1,
      "expires": 1740484800
    }
  ]
}
```

**Benefits**:
- Cross-verification by multiple orgs
- Higher trust score with multiple certs
- Redundancy if one CA compromised

---

## Integration Checklist

### For Client (Telegram App):

- [ ] Add `SharedConfig.telemetryDeviceCertificate` field
- [ ] Implement `CertificateManager.java`
- [ ] Update `ConnectionQualityManager` to include certificate
- [ ] Add UI for certificate request (Settings → Network Session → "Get Certified")
- [ ] Display certificate status in About screen
- [ ] Handle certificate expiry/renewal

### For Root CAs:

- [ ] Generate root keypair securely
- [ ] Set up certificate issuance server
- [ ] Publish certificate policy
- [ ] Implement revocation list
- [ ] Create verification API endpoint
- [ ] Establish key backup procedures
- [ ] Train staff on certificate issuance
- [ ] Legal review of liability

### For Analysts:

- [ ] Update verification tools to check certificates
- [ ] Implement trust scoring with certificate levels
- [ ] Monitor CA revocation lists
- [ ] Cross-reference multiple CAs
- [ ] Document certificate verification in reports

---

## Summary

**PKI Model Advantages**:
- ✅ **Hierarchical trust**: Leverage existing org credibility
- ✅ **Scalable**: Orgs can certify unlimited devices
- ✅ **Revocable**: Compromised keys can be blacklisted
- ✅ **Multi-tier**: Different trust levels for different use cases
- ✅ **Interoperable**: Multiple CAs create web of trust

**Implementation Path**:
1. Select 3-5 pilot CAs (HRW, ICC, Bellingcat, Reuters, Amnesty)
2. Each CA generates root keypair and sets up issuance server
3. Deploy client with certificate support
4. CAs begin issuing certificates (start with Level 3 automatic, add Level 1/2 manually)
5. Analysts update verification tools to check certificates
6. Monitor and refine trust scoring algorithms

The beauty: **Backwards compatible** - uncertified devices still work, but certified ones get higher trust scores. 🔐
