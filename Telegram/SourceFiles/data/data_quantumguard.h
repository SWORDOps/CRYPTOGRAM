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

class QuantumGuard final {
public:
    QuantumGuard() = default;
    ~QuantumGuard();

    bool initialize();
    bool isInitialized() const;
    bool enableQuantumSignalProtocol(bool enabled);
    bool enableHardwareAcceleration(bool enabled);
    bool setProtected(bool enabled);

    // Generate a real ML-KEM or ML-DSA keypair via OpenSSL 3.5 EVP.
    // Returns the public key; private key is stored internally keyed by keyId.
    base::expected<QuantumKeyResult, QString> generateQuantumKey(
        QuantumKeyType type,
        QuantumAlgorithm algorithm);

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
