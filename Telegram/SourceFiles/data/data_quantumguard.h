/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#pragma once

#include "base/bytes.h"
#include "base/expected.h"
#include "base/random.h"
#include "data/data_quantum_types.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>

#include <memory>
#include <map>

// Forward-declare OpenSSL types to avoid pulling in OpenSSL headers from .h
typedef struct evp_pkey_st EVP_PKEY;

namespace Data {

struct QuantumKeyResult {
    QString keyId;
    QByteArray publicKey;   // DER-encoded raw public key bytes
    QByteArray privateKey;  // DER-encoded raw private key bytes (kept in memory only)
};

struct QuantumSignatureResult {
    QString keyId;
    QByteArray signature;   // Raw ML-DSA signature bytes
};

struct QuantumEncryptionResult {
    QString keyId;
    QuantumAlgorithm algorithm = QuantumAlgorithm::ML_KEM_1024;
    bytes::vector ciphertext;        // AES-256-GCM ciphertext of plaintext
    bytes::vector encapsulatedSecret; // ML-KEM encapsulated key ciphertext
    bytes::vector iv;                // AES-256-GCM IV (12 bytes)
    bytes::vector authTag;           // AES-256-GCM auth tag (16 bytes)
};

// Bare ML-KEM encapsulation: fresh shared secret + the ciphertext that the
// key holder must decapsulate to derive the same secret.
struct QuantumKemEncapsulation {
    bytes::vector sharedSecret;
    bytes::vector ciphertext;
};

class QuantumGuard final {
public:
    QuantumGuard() = default;
    ~QuantumGuard();

    bool initialize();
    bool isInitialized() const;
    bool enableQuantumSignalProtocol(bool enabled);
    bool enableHardwareAcceleration(bool enabled);
    bool setProtected(bool enabled);

    // Persist all keypairs to an AES-256-GCM encrypted file.
    // password is used to derive the wrapping key via PBKDF2-SHA256.
    // Returns true on success.
    bool saveKeys(const QString &filePath, const QByteArray &password) const;

    // Load keypairs from a file saved by saveKeys().
    // Clears the current key store before loading.
    // Returns true on success.
    bool loadKeys(const QString &filePath, const QByteArray &password);

    // Generate a real ML-KEM or ML-DSA keypair via OpenSSL 3.5 EVP.
    // Returns the public key; private key is stored internally keyed by keyId.
    base::expected<QuantumKeyResult, QString> generateQuantumKey(
        QuantumKeyType type,
        QuantumAlgorithm algorithm);

    // Import a PEER's ML-KEM public key for encapsulation (public half only,
    // decapsulation requires the peer's private key). Accepts a
    // SubjectPublicKeyInfo DER encoding as produced by i2d_PUBKEY(). The
    // imported key is stored under |keyId| and usable with quantumEncrypt().
    base::expected<QString, QString> importPeerKemPublicKey(
        const QString &keyId,
        QuantumAlgorithm algorithm,
        const QByteArray &derPublicKey);

    // Same as above but for the RAW (fixed-length) public key encoding
    // returned by EVP_PKEY_get_raw_public_key() / generateQuantumKey().
    // Accepts ML-KEM and ML-DSA key types.
    base::expected<QString, QString> importPeerKemPublicKeyRaw(
        const QString &keyId,
        QuantumAlgorithm algorithm,
        const QByteArray &rawPublicKey);

    // Bare ML-KEM encapsulation against the imported public key |keyId|:
    // returns the raw shared secret and the encapsulation ciphertext that
    // the key holder must decapsulate.
    base::expected<QuantumKemEncapsulation, QString> quantumEncapsulate(
        const QString &keyId);

    // Holder side of the above: decapsulate with the private ML-KEM key
    // |keyId| and return the shared secret.
    base::expected<bytes::vector, QString> quantumDecapsulate(
        const QString &keyId,
        const bytes::const_span &encapsulatedSecret);

    // Verify an ML-DSA signature over |data| with the imported public key
    // |keyId|. Returns true only on a valid signature.
    base::expected<bool, QString> quantumVerify(
        const QString &keyId,
        const QByteArray &data,
        const QByteArray &signature);

    QuantumAlgorithm selectOptimalKEM(QuantumSecurityLevel level) const;
    QuantumAlgorithm selectOptimalSignature(QuantumSecurityLevel level) const;

    // Sign data with the ML-DSA key identified by keyId.
    base::expected<QuantumSignatureResult, QString> quantumSign(
        const QString &keyId,
        const QByteArray &data);

    // Encapsulate a symmetric key using the public ML-KEM key identified by keyId,
    // then encrypt plaintext with the encapsulated secret using AES-256-GCM.
    base::expected<QuantumEncryptionResult, QString> quantumEncrypt(
        const QString &keyId,
        const bytes::const_span &plaintext);

    // Decapsulate the shared secret from encapsulatedSecret using the private ML-KEM key,
    // then decrypt AES-256-GCM ciphertext.
    base::expected<bytes::vector, QString> quantumDecrypt(
        const QString &keyId,
        const bytes::const_span &ciphertext,
        const bytes::const_span &encapsulatedSecret,
        const bytes::const_span &iv,
        const bytes::const_span &authTag);

    // Legacy overload for callers that pack iv/tag into encapsulatedSecret.
    base::expected<bytes::vector, QString> quantumDecrypt(
        const QString &keyId,
        const bytes::const_span &ciphertext,
        const bytes::const_span &encapsulatedSecret);

private:
    static const char *evpAlgorithmName(QuantumAlgorithm algorithm);
    QString makeKeyId() const;
    bytes::vector randomBytes(int size) const;

    // Stored keypairs (private key material).
    // In production this would be backed by TPM/secure enclave.
    std::map<std::string, EVP_PKEY *> _keyStore;

    bool _initialized = false;
    bool _quantumSignalEnabled = false;
    bool _hardwareAcceleration = false;
    bool _protectedMode = false;

    QuantumGuard(const QuantumGuard &other) = delete;
    QuantumGuard &operator=(const QuantumGuard &other) = delete;
};

} // namespace Data
