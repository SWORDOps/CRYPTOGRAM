/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#pragma once

#include "base/bytes.h"
#include "base/expected.h"
#include "data/data_tsm_interface.h"
#include "data/data_signal_protocol.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <memory>
#include <vector>
#include <variant>

namespace Data {

// NIST Post-Quantum Cryptography algorithms
enum class QuantumAlgorithm {
    // Key Encapsulation Mechanisms (KEM)
    Kyber512,      // CRYSTALS-Kyber 512-bit security
    Kyber768,      // CRYSTALS-Kyber 768-bit security
    Kyber1024,     // CRYSTALS-Kyber 1024-bit security

    // Digital Signature algorithms
    Dilithium2,    // CRYSTALS-Dilithium Level 2
    Dilithium3,    // CRYSTALS-Dilithium Level 3
    Dilithium5,    // CRYSTALS-Dilithium Level 5

    // Hash-based signatures
    SPHINCS_SHA256, // SPHINCS+ with SHA-256
    SPHINCS_SHAKE,  // SPHINCS+ with SHAKE-256

    // Hybrid approaches
    HybridX25519_Kyber768,     // X25519 + Kyber768
    HybridEd25519_Dilithium3   // Ed25519 + Dilithium3
};

// Security levels for quantum resistance
enum class QuantumSecurityLevel {
    Level1 = 128,  // AES-128 equivalent
    Level2 = 192,  // AES-192 equivalent
    Level3 = 256,  // AES-256 equivalent
    Level5 = 384   // AES-384+ equivalent
};

// Quantum-resistant key types
enum class QuantumKeyType {
    IdentityKey,        // Long-term identity signing key
    PreKey,            // Medium-term key exchange key
    OneTimeKey,        // Single-use key exchange key
    RatchetKey,        // Double Ratchet chain key
    DeviceAttestation, // Device attestation key
    Backup             // Key backup encryption
};

// Quantum key information
struct QuantumKeyInfo {
    QString keyId;
    QuantumKeyType keyType;
    QuantumAlgorithm algorithm;
    QuantumSecurityLevel securityLevel;
    bytes::vector publicKey;
    QDateTime created;
    QDateTime expires;
    bool isHardwareBacked = false;
    bool isHybridKey = false;
    QString classicalKeyId; // For hybrid keys
};

// Quantum encryption result
struct QuantumEncryptionResult {
    bytes::vector ciphertext;
    bytes::vector encapsulatedSecret;
    bytes::vector iv;
    bytes::vector authTag;
    QuantumAlgorithm algorithm;
    QString keyId;
};

// Quantum signature result
struct QuantumSignatureResult {
    bytes::vector signature;
    QuantumAlgorithm algorithm;
    QString keyId;
    QDateTime timestamp;
};

// Quantum key agreement result
struct QuantumKeyAgreementResult {
    bytes::vector sharedSecret;
    bytes::vector publicKey;
    QuantumAlgorithm kemAlgorithm;
    QuantumAlgorithm signatureAlgorithm;
    QString sessionId;
};

// Migration status for quantum transition
enum class QuantumMigrationStatus {
    NotStarted,
    ClassicalOnly,
    HybridTransition,
    QuantumReady,
    QuantumNative,
    MigrationComplete
};

// Threat assessment levels
enum class QuantumThreatLevel {
    Minimal,        // No quantum threat detected
    Emerging,       // Early quantum capabilities observed
    Moderate,       // Significant quantum development
    High,          // Advanced quantum capabilities
    Critical,      // Quantum supremacy achieved
    Compromised    // Classical crypto assumed broken
};

// QUANTUMGUARD - Quantum-Resistant Security Module
class QuantumGuard : public QObject {
    Q_OBJECT

public:
    explicit QuantumGuard(QObject *parent = nullptr);
    ~QuantumGuard();

    // Initialization and configuration
    bool initialize();
    bool isInitialized() const;
    void setQuantumThreatLevel(QuantumThreatLevel level);
    QuantumThreatLevel getCurrentThreatLevel() const;

    // Algorithm selection and validation
    QuantumAlgorithm selectOptimalKEM(QuantumSecurityLevel minLevel = QuantumSecurityLevel::Level3);
    QuantumAlgorithm selectOptimalSignature(QuantumSecurityLevel minLevel = QuantumSecurityLevel::Level3);
    bool isAlgorithmSupported(QuantumAlgorithm algorithm) const;
    QList<QuantumAlgorithm> getSupportedAlgorithms() const;

    // Quantum key management
    base::expected<QuantumKeyInfo, TSMResult> generateQuantumKey(
        QuantumKeyType keyType,
        QuantumAlgorithm algorithm,
        const QString &keyId = QString());

    base::expected<QuantumKeyInfo, TSMResult> generateHybridKey(
        QuantumKeyType keyType,
        QuantumAlgorithm quantumAlgorithm,
        const QString &classicalKeyId,
        const QString &keyId = QString());

    base::expected<QuantumKeyInfo, TSMResult> getQuantumKeyInfo(const QString &keyId);
    TSMResult deleteQuantumKey(const QString &keyId);
    QStringList listQuantumKeys(QuantumKeyType keyType = QuantumKeyType::IdentityKey);

    // Quantum cryptographic operations
    base::expected<QuantumEncryptionResult, TSMResult> quantumEncrypt(
        const QString &keyId,
        const bytes::const_span &plaintext,
        const bytes::const_span &additionalData = {});

    base::expected<bytes::vector, TSMResult> quantumDecrypt(
        const QString &keyId,
        const QuantumEncryptionResult &encryptionResult,
        const bytes::const_span &additionalData = {});

    base::expected<QuantumSignatureResult, TSMResult> quantumSign(
        const QString &keyId,
        const bytes::const_span &data);

    base::expected<bool, TSMResult> quantumVerify(
        const QString &keyId,
        const bytes::const_span &data,
        const QuantumSignatureResult &signature);

    // Quantum key agreement (post-quantum X3DH)
    base::expected<QuantumKeyAgreementResult, TSMResult> performQuantumKeyAgreement(
        const QString &localIdentityKeyId,
        const QString &localPreKeyId,
        const bytes::const_span &remoteIdentityKey,
        const bytes::const_span &remotePreKey,
        const bytes::const_span &remoteOneTimeKey = {});

    // Migration and transition support
    QuantumMigrationStatus assessMigrationStatus();
    base::expected<QString, TSMResult> migrateToQuantumKey(
        const QString &classicalKeyId,
        QuantumAlgorithm targetAlgorithm);

    base::expected<QByteArray, TSMResult> createMigrationBundle(
        const QStringList &keyIds,
        const QString &password);

    TSMResult restoreMigrationBundle(
        const QByteArray &bundle,
        const QString &password);

    // Quantum-safe Signal Protocol integration
    void enableQuantumSignalProtocol(bool enabled);
    bool isQuantumSignalProtocolEnabled() const;

    base::expected<SignalProtocol::KeyBundle, TSMResult> generateQuantumSignalKeyBundle(
        const SignalProtocol::DeviceId &deviceId);

    base::expected<bytes::vector, TSMResult> quantumDoubleRatchetEncrypt(
        const QString &sessionId,
        const bytes::const_span &plaintext,
        SignalProtocol::MessageMetadata &metadata);

    base::expected<bytes::vector, TSMResult> quantumDoubleRatchetDecrypt(
        const QString &sessionId,
        const bytes::const_span &ciphertext,
        const SignalProtocol::MessageMetadata &metadata);

    // Hardware acceleration integration
    void enableHardwareAcceleration(bool enabled);
    bool isHardwareAccelerationEnabled() const;
    void setTSMInterface(std::shared_ptr<TSMInterface> tsm);
    std::shared_ptr<TSMInterface> getTSMInterface() const;

    // Performance monitoring
    struct QuantumPerformanceMetrics {
        uint64 keyGenerationsPerformed = 0;
        uint64 encryptionOperations = 0;
        uint64 decryptionOperations = 0;
        uint64 signatureOperations = 0;
        uint64 verificationOperations = 0;
        double averageKeyGenTime = 0.0;
        double averageEncryptTime = 0.0;
        double averageDecryptTime = 0.0;
        double averageSignTime = 0.0;
        double averageVerifyTime = 0.0;
        QuantumAlgorithm fastestKEM = QuantumAlgorithm::Kyber768;
        QuantumAlgorithm fastestSignature = QuantumAlgorithm::Dilithium3;
    };

    QuantumPerformanceMetrics getPerformanceMetrics() const;
    void resetPerformanceMetrics();

signals:
    void quantumThreatLevelChanged(QuantumThreatLevel level);
    void quantumKeyGenerated(const QString &keyId, QuantumAlgorithm algorithm);
    void quantumOperationCompleted(const QString &operation, double timeMs);
    void migrationStatusChanged(QuantumMigrationStatus status);
    void quantumAlgorithmUpdated(QuantumAlgorithm oldAlg, QuantumAlgorithm newAlg);

private:
    // Core implementation
    class QuantumGuardPrivate;
    std::unique_ptr<QuantumGuardPrivate> d;

    // Algorithm implementations
    bytes::vector kyberKeyGen(int securityLevel);
    bytes::vector kyberEncrypt(const bytes::const_span &publicKey, const bytes::const_span &plaintext);
    bytes::vector kyberDecrypt(const bytes::const_span &privateKey, const bytes::const_span &ciphertext);

    bytes::vector dilithiumKeyGen(int securityLevel);
    bytes::vector dilithiumSign(const bytes::const_span &privateKey, const bytes::const_span &message);
    bool dilithiumVerify(const bytes::const_span &publicKey, const bytes::const_span &message, const bytes::const_span &signature);

    bytes::vector sphincsKeyGen(bool useSHA256);
    bytes::vector sphincsSign(const bytes::const_span &privateKey, const bytes::const_span &message);
    bool sphincsVerify(const bytes::const_span &publicKey, const bytes::const_span &message, const bytes::const_span &signature);

    // Hybrid implementations
    struct HybridResult {
        bytes::vector classicalResult;
        bytes::vector quantumResult;
        bool success;
    };

    HybridResult hybridKeyAgreement(
        const bytes::const_span &classicalKey,
        const bytes::const_span &quantumKey);

    HybridResult hybridSign(
        const bytes::const_span &classicalPrivateKey,
        const bytes::const_span &quantumPrivateKey,
        const bytes::const_span &message);

    bool hybridVerify(
        const bytes::const_span &classicalPublicKey,
        const bytes::const_span &quantumPublicKey,
        const bytes::const_span &message,
        const HybridResult &signature);

    // Performance optimization
    void optimizeForHardware();
    void benchmarkAlgorithms();
    QuantumAlgorithm selectFastestAlgorithm(QuantumKeyType keyType, QuantumSecurityLevel minLevel);

    // Threat assessment
    void updateThreatAssessment();
    bool shouldUseHybridApproach() const;
    bool shouldMigrateToQuantum() const;

    // State management
    bool _initialized = false;
    bool _quantumSignalEnabled = false;
    bool _hardwareAccelEnabled = false;
    QuantumThreatLevel _currentThreatLevel = QuantumThreatLevel::Moderate;
    QuantumMigrationStatus _migrationStatus = QuantumMigrationStatus::NotStarted;
    std::shared_ptr<TSMInterface> _tsmInterface;
    mutable QuantumPerformanceMetrics _performanceMetrics;
};

// Factory for creating optimized quantum implementations
class QuantumGuardFactory {
public:
    // Create QUANTUMGUARD instance optimized for current hardware
    static std::unique_ptr<QuantumGuard> createOptimized();

    // Create with specific configuration
    static std::unique_ptr<QuantumGuard> createWithThreatLevel(QuantumThreatLevel level);
    static std::unique_ptr<QuantumGuard> createWithTSM(std::shared_ptr<TSMInterface> tsm);

    // Platform detection and optimization
    static bool isQuantumHardwareAvailable();
    static QStringList getAvailableAccelerators();
    static QuantumSecurityLevel getRecommendedSecurityLevel();
    static QuantumThreatLevel assessCurrentThreatLevel();
};

} // namespace Data