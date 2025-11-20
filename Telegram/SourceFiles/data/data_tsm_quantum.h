/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#pragma once

#include "data/data_tsm_interface.h"
#include "data/data_quantumguard.h"
#include "data/data_quantum_types.h"
#include "base/bytes.h"
#include "base/expected.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QDateTime>
#include <memory>
#include <variant>

namespace Data {

// Quantum-enhanced TSM key types
enum class QuantumTSMKeyType {
    // Classical keys (existing)
    SignalIdentity = static_cast<int>(TSMKeyType::SignalIdentity),
    SignalPreKey = static_cast<int>(TSMKeyType::SignalPreKey),
    SignalOneTime = static_cast<int>(TSMKeyType::SignalOneTime),
    DeviceAttestation = static_cast<int>(TSMKeyType::DeviceAttestation),
    CustomEncryption = static_cast<int>(TSMKeyType::CustomEncryption),

    // Quantum-resistant keys
    QuantumSignalIdentity = 100,     // Post-quantum identity key
    QuantumSignalPreKey = 101,       // Post-quantum pre-key
    QuantumSignalOneTime = 102,      // Post-quantum one-time key
    QuantumDeviceAttestation = 103,  // Post-quantum device attestation
    QuantumCustomEncryption = 104,   // Post-quantum custom encryption

    // Hybrid keys (classical + quantum)
    HybridSignalIdentity = 200,      // Hybrid identity key
    HybridSignalPreKey = 201,        // Hybrid pre-key
    HybridSignalOneTime = 202,       // Hybrid one-time key
    HybridDeviceAttestation = 203,   // Hybrid device attestation
    HybridCustomEncryption = 204     // Hybrid custom encryption
};

// Quantum TSM result types (extended)
enum class QuantumTSMResult {
    // Standard results
    Success = static_cast<int>(TSMResult::Success),
    NotInitialized = static_cast<int>(TSMResult::NotInitialized),
    HardwareNotAvailable = static_cast<int>(TSMResult::HardwareNotAvailable),
    KeyGenerationFailed = static_cast<int>(TSMResult::KeyGenerationFailed),
    KeyNotFound = static_cast<int>(TSMResult::KeyNotFound),
    EncryptionFailed = static_cast<int>(TSMResult::EncryptionFailed),
    DecryptionFailed = static_cast<int>(TSMResult::DecryptionFailed),
    SignatureFailed = static_cast<int>(TSMResult::SignatureFailed),
    VerificationFailed = static_cast<int>(TSMResult::VerificationFailed),
    AttestationFailed = static_cast<int>(TSMResult::AttestationFailed),
    UnknownError = static_cast<int>(TSMResult::UnknownError),

    // Quantum-specific results
    QuantumAlgorithmNotSupported = 1000,
    QuantumKeyGenerationFailed = 1001,
    QuantumEncryptionFailed = 1002,
    QuantumDecryptionFailed = 1003,
    QuantumSignatureFailed = 1004,
    QuantumVerificationFailed = 1005,
    HybridOperationFailed = 1006,
    ClassicalFallbackRequired = 1007,
    QuantumSecurityLevelInsufficient = 1008,
    PostQuantumMigrationRequired = 1009
};

// Quantum TSM capabilities (extended)
struct QuantumTSMCapabilities {
    // Base capabilities
    TSMCapabilities baseCapabilities;

    // Quantum-specific capabilities
    bool supportsQuantumKeyGeneration = false;
    bool supportsQuantumEncryption = false;
    bool supportsQuantumSigning = false;
    bool supportsQuantumAttestation = false;
    bool supportsHybridOperations = false;
    bool supportsQuantumMigration = false;

    // Supported quantum algorithms
    QList<QuantumAlgorithm> supportedKEMs;
    QList<QuantumAlgorithm> supportedSignatures;
    QList<QuantumAlgorithm> supportedHybridAlgorithms;

    // Performance characteristics
    QMap<QuantumAlgorithm, int> keyGenerationTimeMs;
    QMap<QuantumAlgorithm, int> encryptionTimeMs;
    QMap<QuantumAlgorithm, int> decryptionTimeMs;
    QMap<QuantumAlgorithm, int> signatureTimeMs;
    QMap<QuantumAlgorithm, int> verificationTimeMs;

    // Security levels
    QuantumSecurityLevel maxSecurityLevel = QuantumSecurityLevel::Level5;
    QuantumThreatLevel supportedThreatLevel = QuantumThreatLevel::Moderate;
    bool isQuantumReady = false;
    bool isNationStateReady = false;
};

// Quantum TSM key information (extended)
struct QuantumTSMKeyInfo {
    // Base key info
    TSMKeyInfo baseKeyInfo;

    // Quantum-specific information
    QuantumTSMKeyType quantumKeyType;
    QuantumAlgorithm quantumAlgorithm = QuantumAlgorithm::ML_KEM_1024;
    QuantumSecurityLevel securityLevel = QuantumSecurityLevel::Level5;
    bool isHybridKey = false;
    bool isQuantumReady = false;

    // For hybrid keys
    QString classicalKeyId;
    QString quantumKeyId;
    bytes::vector classicalPublicKey;
    bytes::vector quantumPublicKey;

    // Quantum-specific metadata
    QDateTime quantumMigrationDate;
    QString quantumVersion;
    bool requiresQuantumHardware = false;
    QStringList quantumCapabilities;
};

// Quantum TSM encryption result (extended)
struct QuantumTSMEncryptionResult {
    // Base encryption result
    TSMEncryptionResult baseResult;

    // Quantum-specific data
    QuantumAlgorithm algorithm = QuantumAlgorithm::ML_KEM_1024;
    bytes::vector quantumCiphertext;
    bytes::vector quantumEncapsulation;
    bytes::vector hybridSecret;
    bool isQuantumProtected = false;
    QuantumSecurityLevel achievedSecurityLevel = QuantumSecurityLevel::Level5;
};

// Quantum TSM signature result (extended)
struct QuantumTSMSignatureResult {
    // Base signature result
    TSMSignatureResult baseResult;

    // Quantum-specific data
    QuantumAlgorithm algorithm = QuantumAlgorithm::ML_DSA_87;
    bytes::vector quantumSignature;
    bytes::vector classicalSignature;
    bool isHybridSignature = false;
    QuantumSecurityLevel achievedSecurityLevel = QuantumSecurityLevel::Level5;
};

// Quantum-enhanced TSM interface
class QuantumTSMInterface : public TSMInterface {
    Q_OBJECT

public:
    explicit QuantumTSMInterface(QObject *parent = nullptr);
    ~QuantumTSMInterface() override = default;

    // Quantum capability detection
    virtual QuantumTSMCapabilities getQuantumCapabilities() const = 0;
    virtual bool isQuantumReady() const = 0;
    virtual bool supportsQuantumAlgorithm(QuantumAlgorithm algorithm) const = 0;
    virtual QuantumSecurityLevel getMaxQuantumSecurityLevel() const = 0;

    // Quantum key management
    virtual base::expected<QuantumTSMKeyInfo, QuantumTSMResult> generateQuantumKey(
        QuantumTSMKeyType keyType,
        QuantumAlgorithm algorithm,
        const QString &keyId = QString()) = 0;

    virtual base::expected<QuantumTSMKeyInfo, QuantumTSMResult> generateHybridKey(
        QuantumTSMKeyType keyType,
        QuantumAlgorithm quantumAlgorithm,
        const QString &classicalKeyId,
        const QString &keyId = QString()) = 0;

    virtual base::expected<QuantumTSMKeyInfo, QuantumTSMResult> getQuantumKeyInfo(
        const QString &keyId) = 0;

    virtual QuantumTSMResult deleteQuantumKey(const QString &keyId) = 0;
    virtual QStringList listQuantumKeys(QuantumTSMKeyType keyType) = 0;

    // Quantum cryptographic operations
    virtual base::expected<QuantumTSMEncryptionResult, QuantumTSMResult> quantumEncrypt(
        const QString &keyId,
        const bytes::const_span &plaintext,
        QuantumAlgorithm algorithm = QuantumAlgorithm::ML_KEM_1024,
        const bytes::const_span &additionalData = {}) = 0;

    virtual base::expected<bytes::vector, QuantumTSMResult> quantumDecrypt(
        const QString &keyId,
        const QuantumTSMEncryptionResult &encryptionResult,
        const bytes::const_span &additionalData = {}) = 0;

    virtual base::expected<QuantumTSMSignatureResult, QuantumTSMResult> quantumSign(
        const QString &keyId,
        const bytes::const_span &data,
        QuantumAlgorithm algorithm = QuantumAlgorithm::ML_DSA_87) = 0;

    virtual base::expected<bool, QuantumTSMResult> quantumVerify(
        const QString &keyId,
        const bytes::const_span &data,
        const QuantumTSMSignatureResult &signature) = 0;

    // Hybrid operations (classical + quantum)
    virtual base::expected<QuantumTSMEncryptionResult, QuantumTSMResult> hybridEncrypt(
        const QString &hybridKeyId,
        const bytes::const_span &plaintext,
        const bytes::const_span &additionalData = {}) = 0;

    virtual base::expected<bytes::vector, QuantumTSMResult> hybridDecrypt(
        const QString &hybridKeyId,
        const QuantumTSMEncryptionResult &encryptionResult,
        const bytes::const_span &additionalData = {}) = 0;

    virtual base::expected<QuantumTSMSignatureResult, QuantumTSMResult> hybridSign(
        const QString &hybridKeyId,
        const bytes::const_span &data) = 0;

    virtual base::expected<bool, QuantumTSMResult> hybridVerify(
        const QString &hybridKeyId,
        const bytes::const_span &data,
        const QuantumTSMSignatureResult &signature) = 0;

    // Migration and transition support
    virtual QuantumTSMResult migrateToQuantumKey(
        const QString &classicalKeyId,
        QuantumAlgorithm targetAlgorithm,
        const QString &newKeyId = QString()) = 0;

    virtual QuantumTSMResult createHybridFromExisting(
        const QString &classicalKeyId,
        QuantumAlgorithm quantumAlgorithm,
        const QString &hybridKeyId = QString()) = 0;

    virtual base::expected<QByteArray, QuantumTSMResult> exportQuantumKeys(
        const QStringList &keyIds,
        const QString &password) = 0;

    virtual QuantumTSMResult importQuantumKeys(
        const QByteArray &exportData,
        const QString &password) = 0;

    // Quantum-specific device attestation
    virtual base::expected<TSMAttestationResult, QuantumTSMResult> generateQuantumAttestation(
        QuantumAlgorithm algorithm = QuantumAlgorithm::ML_DSA_87,
        const bytes::const_span &challenge = {}) = 0;

    virtual base::expected<bool, QuantumTSMResult> verifyQuantumAttestation(
        const TSMAttestationResult &attestation,
        QuantumAlgorithm algorithm,
        const bytes::const_span &challenge = {}) = 0;

    // Performance optimization
    virtual QuantumAlgorithm selectOptimalKEM(QuantumSecurityLevel minLevel) const = 0;
    virtual QuantumAlgorithm selectOptimalSignature(QuantumSecurityLevel minLevel) const = 0;
    virtual void enableQuantumHardwareAcceleration(bool enabled) = 0;
    virtual bool isQuantumHardwareAccelerationEnabled() const = 0;

signals:
    void quantumCapabilitiesChanged(const QuantumTSMCapabilities &capabilities);
    void quantumKeyGenerated(const QString &keyId, QuantumAlgorithm algorithm);
    void quantumMigrationCompleted(const QString &keyId, QuantumTSMResult result);
    void quantumThreatLevelChanged(QuantumThreatLevel level);
    void quantumHardwareStatusChanged(bool available);

protected:
    // Helper methods for implementations
    virtual QString generateQuantumKeyId(QuantumTSMKeyType keyType) const;
    virtual bool validateQuantumAlgorithm(QuantumAlgorithm algorithm) const;
    virtual QuantumTSMResult mapQuantumError(int errorCode) const;
    virtual QuantumSecurityLevel assessSecurityLevel(QuantumAlgorithm algorithm) const;
};

// Platform-specific quantum TSM implementations
class QuantumTSMTPM20 : public QuantumTSMInterface {
    Q_OBJECT

public:
    explicit QuantumTSMTPM20(QObject *parent = nullptr);
    ~QuantumTSMTPM20() override;

    // TSMInterface implementation
    TSMResult initialize() override;
    bool isInitialized() const override;
    TSMCapabilities getCapabilities() const override;
    TSMPlatform getPlatform() const override;

    base::expected<TSMKeyInfo, TSMResult> generateKey(
        TSMKeyType keyType,
        const QString &keyId = QString()) override;
    base::expected<TSMKeyInfo, TSMResult> getKeyInfo(const QString &keyId) override;
    TSMResult deleteKey(const QString &keyId) override;
    QStringList listKeys(TSMKeyType keyType = TSMKeyType::SignalIdentity) override;

    base::expected<TSMEncryptionResult, TSMResult> encrypt(
        const QString &keyId,
        const bytes::const_span &plaintext,
        const bytes::const_span &additionalData = {}) override;
    base::expected<bytes::vector, TSMResult> decrypt(
        const QString &keyId,
        const bytes::const_span &ciphertext,
        const bytes::const_span &iv,
        const bytes::const_span &authTag,
        const bytes::const_span &additionalData = {}) override;

    base::expected<TSMSignatureResult, TSMResult> sign(
        const QString &keyId,
        const bytes::const_span &data) override;
    base::expected<bool, TSMResult> verify(
        const QString &keyId,
        const bytes::const_span &data,
        const bytes::const_span &signature) override;

    base::expected<TSMAttestationResult, TSMResult> generateAttestation(
        const bytes::const_span &challenge = {}) override;
    base::expected<bool, TSMResult> verifyAttestation(
        const TSMAttestationResult &attestation,
        const bytes::const_span &challenge = {}) override;

    base::expected<bytes::vector, TSMResult> deriveKey(
        const QString &baseKeyId,
        const QString &derivationInfo,
        size_t outputLength) override;
    base::expected<bytes::vector, TSMResult> generateSecureRandom(size_t length) override;

    // QuantumTSMInterface implementation
    QuantumTSMCapabilities getQuantumCapabilities() const override;
    bool isQuantumReady() const override;
    bool supportsQuantumAlgorithm(QuantumAlgorithm algorithm) const override;
    QuantumSecurityLevel getMaxQuantumSecurityLevel() const override;

    base::expected<QuantumTSMKeyInfo, QuantumTSMResult> generateQuantumKey(
        QuantumTSMKeyType keyType,
        QuantumAlgorithm algorithm,
        const QString &keyId = QString()) override;

    base::expected<QuantumTSMKeyInfo, QuantumTSMResult> generateHybridKey(
        QuantumTSMKeyType keyType,
        QuantumAlgorithm quantumAlgorithm,
        const QString &classicalKeyId,
        const QString &keyId = QString()) override;

    base::expected<QuantumTSMKeyInfo, QuantumTSMResult> getQuantumKeyInfo(
        const QString &keyId) override;

    QuantumTSMResult deleteQuantumKey(const QString &keyId) override;
    QStringList listQuantumKeys(QuantumTSMKeyType keyType) override;

    base::expected<QuantumTSMEncryptionResult, QuantumTSMResult> quantumEncrypt(
        const QString &keyId,
        const bytes::const_span &plaintext,
        QuantumAlgorithm algorithm = QuantumAlgorithm::ML_KEM_1024,
        const bytes::const_span &additionalData = {}) override;

    base::expected<bytes::vector, QuantumTSMResult> quantumDecrypt(
        const QString &keyId,
        const QuantumTSMEncryptionResult &encryptionResult,
        const bytes::const_span &additionalData = {}) override;

    base::expected<QuantumTSMSignatureResult, QuantumTSMResult> quantumSign(
        const QString &keyId,
        const bytes::const_span &data,
        QuantumAlgorithm algorithm = QuantumAlgorithm::ML_DSA_87) override;

    base::expected<bool, QuantumTSMResult> quantumVerify(
        const QString &keyId,
        const bytes::const_span &data,
        const QuantumTSMSignatureResult &signature) override;

    base::expected<QuantumTSMEncryptionResult, QuantumTSMResult> hybridEncrypt(
        const QString &hybridKeyId,
        const bytes::const_span &plaintext,
        const bytes::const_span &additionalData = {}) override;

    base::expected<bytes::vector, QuantumTSMResult> hybridDecrypt(
        const QString &hybridKeyId,
        const QuantumTSMEncryptionResult &encryptionResult,
        const bytes::const_span &additionalData = {}) override;

    base::expected<QuantumTSMSignatureResult, QuantumTSMResult> hybridSign(
        const QString &hybridKeyId,
        const bytes::const_span &data) override;

    base::expected<bool, QuantumTSMResult> hybridVerify(
        const QString &hybridKeyId,
        const bytes::const_span &data,
        const QuantumTSMSignatureResult &signature) override;

    QuantumTSMResult migrateToQuantumKey(
        const QString &classicalKeyId,
        QuantumAlgorithm targetAlgorithm,
        const QString &newKeyId = QString()) override;

    QuantumTSMResult createHybridFromExisting(
        const QString &classicalKeyId,
        QuantumAlgorithm quantumAlgorithm,
        const QString &hybridKeyId = QString()) override;

    base::expected<QByteArray, QuantumTSMResult> exportQuantumKeys(
        const QStringList &keyIds,
        const QString &password) override;

    QuantumTSMResult importQuantumKeys(
        const QByteArray &exportData,
        const QString &password) override;

    base::expected<TSMAttestationResult, QuantumTSMResult> generateQuantumAttestation(
        QuantumAlgorithm algorithm = QuantumAlgorithm::ML_DSA_87,
        const bytes::const_span &challenge = {}) override;

    base::expected<bool, QuantumTSMResult> verifyQuantumAttestation(
        const TSMAttestationResult &attestation,
        QuantumAlgorithm algorithm,
        const bytes::const_span &challenge = {}) override;

    QuantumAlgorithm selectOptimalKEM(QuantumSecurityLevel minLevel) const override;
    QuantumAlgorithm selectOptimalSignature(QuantumSecurityLevel minLevel) const override;
    void enableQuantumHardwareAcceleration(bool enabled) override;
    bool isQuantumHardwareAccelerationEnabled() const override;

private:
    class QuantumTSMTPM20Private;
    std::unique_ptr<QuantumTSMTPM20Private> d;
};

// Quantum TSM factory (extended)
class QuantumTSMFactory {
public:
    // Create quantum-ready TSM implementation
    static std::unique_ptr<QuantumTSMInterface> createQuantumTSM();
    static std::unique_ptr<QuantumTSMInterface> createQuantumTSMForPlatform(TSMPlatform platform);

    // Migration support
    static std::unique_ptr<QuantumTSMInterface> migrateToQuantumTSM(
        std::unique_ptr<TSMInterface> classicalTSM);

    // Quantum capability detection
    static bool isQuantumTSMAvailable();
    static QList<QuantumAlgorithm> getAvailableQuantumAlgorithms();
    static QuantumSecurityLevel getMaxAvailableSecurityLevel();
    static QuantumThreatLevel assessCurrentQuantumThreatLevel();

    // Performance optimization
    static QuantumAlgorithm getBestKEMForPlatform(TSMPlatform platform);
    static QuantumAlgorithm getBestSignatureForPlatform(TSMPlatform platform);
    static QMap<QuantumAlgorithm, int> benchmarkQuantumAlgorithms();
};

} // namespace Data