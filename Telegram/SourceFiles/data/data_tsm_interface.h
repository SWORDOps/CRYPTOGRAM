/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#pragma once

#include "base/bytes.h"
#include "base/expected.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <memory>
#include <vector>
#include <string>

namespace Data {

// Forward declarations
class Session;

// TSM (Trusted Security Module) result types
enum class TSMResult {
    Success,
    NotInitialized,
    HardwareNotAvailable,
    KeyGenerationFailed,
    KeyNotFound,
    EncryptionFailed,
    DecryptionFailed,
    SignatureFailed,
    VerificationFailed,
    AttestationFailed,
    UnknownError
};

// Key types for different cryptographic operations
enum class TSMKeyType {
    SignalIdentity,     // Ed25519 for Signal Protocol identity
    SignalPreKey,       // X25519 for Signal Protocol pre-keys
    SignalOneTime,      // X25519 for one-time pre-keys
    DeviceAttestation,  // Device attestation key
    CustomEncryption,   // Custom encryption key
    AES256              // AES-256 symmetric key
};

// Hardware platform types
enum class TSMPlatform {
    TPM20,              // TPM 2.0 on desktop
    AndroidKeyStore,    // Android Hardware Keystore
    AppleSecureEnclave, // Apple Secure Enclave
    SoftwareFallback    // Software-based fallback
};

// TSM capabilities reported by hardware
struct TSMCapabilities {
    TSMPlatform platform;
    bool supportsKeyGeneration = false;
    bool supportsEncryption = false;
    bool supportsSigning = false;
    bool supportsAttestation = false;
    bool supportsSecureStorage = false;
    QString hardwareVersion;
    QString firmwareVersion;
    QStringList supportedAlgorithms;
};

// Key metadata for TSM operations
struct TSMKeyInfo {
    QString keyId;
    TSMKeyType keyType;
    bytes::vector publicKey;
    QDateTime created;
    bool isHardwareBacked = false;
    QString algorithmInfo;
};

// Encryption result structure
struct TSMEncryptionResult {
    bytes::vector ciphertext;
    bytes::vector iv;
    bytes::vector authTag;
    QString keyId;
};

// Signature result structure
struct TSMSignatureResult {
    bytes::vector signature;
    QString keyId;
    QString algorithm;
};

// Device attestation result
struct TSMAttestationResult {
    bytes::vector attestationData;
    bytes::vector signature;
    QString platformInfo;
    QDateTime timestamp;
};

// Abstract TSM interface for cross-platform hardware security
class TSMInterface : public QObject {
    Q_OBJECT

public:
    explicit TSMInterface(QObject *parent = nullptr);
    ~TSMInterface() override = default;

    // Initialization and capability detection
    virtual TSMResult initialize() = 0;
    virtual bool isInitialized() const = 0;
    virtual TSMCapabilities getCapabilities() const = 0;
    virtual TSMPlatform getPlatform() const = 0;

    // Key management operations
    virtual base::expected<TSMKeyInfo, TSMResult> generateKey(
        TSMKeyType keyType,
        const QString &keyId = QString()) = 0;

    virtual base::expected<TSMKeyInfo, TSMResult> getKeyInfo(
        const QString &keyId) = 0;

    virtual TSMResult deleteKey(const QString &keyId) = 0;
    virtual QStringList listKeys(TSMKeyType keyType = TSMKeyType::SignalIdentity) = 0;

    // Cryptographic operations
    virtual base::expected<TSMEncryptionResult, TSMResult> encrypt(
        const QString &keyId,
        const bytes::const_span &plaintext,
        const bytes::const_span &additionalData = {}) = 0;

    virtual base::expected<bytes::vector, TSMResult> decrypt(
        const QString &keyId,
        const bytes::const_span &ciphertext,
        const bytes::const_span &iv,
        const bytes::const_span &authTag,
        const bytes::const_span &additionalData = {}) = 0;

    virtual base::expected<TSMSignatureResult, TSMResult> sign(
        const QString &keyId,
        const bytes::const_span &data) = 0;

    virtual base::expected<bool, TSMResult> verify(
        const QString &keyId,
        const bytes::const_span &data,
        const bytes::const_span &signature) = 0;

    virtual TSMResult sealData(const bytes::const_span &data) = 0;

    // Device attestation and verification
    virtual base::expected<TSMAttestationResult, TSMResult> generateAttestation(
        const bytes::const_span &challenge = {}) = 0;

    virtual base::expected<bool, TSMResult> verifyAttestation(
        const TSMAttestationResult &attestation,
        const bytes::const_span &challenge = {}) = 0;

    // Key derivation for advanced use cases
    virtual base::expected<bytes::vector, TSMResult> deriveKey(
        const QString &baseKeyId,
        const QString &derivationInfo,
        size_t outputLength) = 0;

    // Secure random number generation
    virtual base::expected<bytes::vector, TSMResult> generateSecureRandom(
        size_t length) = 0;


protected:
    // Helper methods for implementations
    virtual QString generateUniqueKeyId() const;
    virtual bool validateKeyId(const QString &keyId) const;
    virtual TSMResult mapPlatformError(int platformErrorCode) const;
};

// Integration class for Signal Protocol + TSM
class SignalTSMIntegration : public QObject {
    Q_OBJECT

public:
    explicit SignalTSMIntegration(not_null<Session*> session);
    ~SignalTSMIntegration();

    // Initialize TSM integration with Signal Protocol
    TSMResult initializeWithSignalProtocol();

    // Hardware-backed Signal Protocol key operations
    base::expected<bytes::vector, TSMResult> generateSignalIdentityKeyPair();
    base::expected<bytes::vector, TSMResult> generateSignalPreKey();
    base::expected<bytes::vector, TSMResult> generateSignalOneTimeKey();

    // Hardware-backed Signal Protocol operations
    base::expected<bytes::vector, TSMResult> signSignalMessage(
        const QString &identityKeyId,
        const bytes::const_span &message);

    base::expected<bool, TSMResult> verifySignalMessage(
        const QString &identityKeyId,
        const bytes::const_span &message,
        const bytes::const_span &signature);

    // Device attestation for Signal Protocol
    base::expected<TSMAttestationResult, TSMResult> generateDeviceAttestation();
    base::expected<bool, TSMResult> verifyDeviceAttestation(
        const TSMAttestationResult &attestation);

    // Migration and backup
    TSMResult migrateFromSoftwareKeys();
    base::expected<QByteArray, TSMResult> exportKeyBackup(const QString &password);
    TSMResult restoreKeyBackup(const QByteArray &backup, const QString &password);

    // Status and monitoring
    TSMCapabilities getTSMCapabilities() const;
    bool isHardwareBackedSecurity() const;
    QStringList getHardwareBackedKeys() const;


private:
    std::unique_ptr<TSMInterface> _tsm;
    not_null<Session*> _session;
    QString _deviceAttestationKeyId;
    QString _signalIdentityKeyId;
    bool _initialized = false;

    // Helper methods
    QString createSignalKeyId(TSMKeyType keyType) const;
    TSMResult validateTSMCapabilities() const;
};

std::unique_ptr<TSMInterface> createSoftwareTSM();

} // namespace Data
