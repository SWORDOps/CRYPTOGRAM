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
#include "data/data_quantumguard.h"
#include "data/data_nsa_security.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QDateTime>
#include <QtCore/QJsonObject>
#include <memory>
#include <map>

namespace Data {

// Secure storage tiers for Universal Accessibility
enum class SecureStorageTier {
    Tier0_Quantum,      // GNA + NPU + TPM 2.0 quantum-secured storage
    Tier1_Premium,      // NPU + TPM 2.0 hardware-backed storage
    Tier2_Enhanced,     // TPM 2.0 hardware-secured storage
    Tier3_Standard,     // Software TSM encrypted storage
    Tier4_Universal     // AES-256 encrypted file storage
};

// Storage security classification levels
enum class StorageClassificationLevel {
    Unclassified,       // Basic encrypted storage
    Confidential,       // Enhanced encryption with integrity protection
    Secret,            // Hardware-backed encryption with attestation
    TopSecret,         // Quantum-resistant encryption with NSA-grade protection
    SCI                // Special Compartmented Information with full quantum security
};

// Storage operation results
enum class SecureStorageResult {
    Success,
    KeyNotFound,
    DecryptionFailed,
    IntegrityCheckFailed,
    HardwareUnavailable,
    QuotaExceeded,
    PermissionDenied,
    QuantumThreatDetected,
    NSASecurityViolation
};

// Encrypted data container
struct EncryptedDataContainer {
    QString dataId;
    bytes::vector encryptedData;
    bytes::vector iv;
    bytes::vector authTag;
    bytes::vector quantumSignature;

    // Encryption metadata
    QString encryptionAlgorithm;
    QuantumAlgorithm quantumAlgorithm = QuantumAlgorithm::ML_KEM_1024;
    QuantumSecurityLevel securityLevel = QuantumSecurityLevel::Level5;
    StorageClassificationLevel classification = StorageClassificationLevel::Secret;

    // Storage metadata
    SecureStorageTier storageTier;
    QString tsmKeyId;
    bool isHardwareBacked = false;
    bool isQuantumProtected = false;
    bool hasIntegrityProtection = true;

    QDateTime created;
    QDateTime lastAccessed;
    QDateTime expires;

    // NSA-grade metadata
    NSAClassificationLevel nsaClassification = NSAClassificationLevel::Secret;
    QStringList appliedDefenses;
    bool antiForensicsEnabled = false;
    QString accessControlPolicy;
};

// Storage access policy
struct StorageAccessPolicy {
    QString policyId;
    QString description;

    // Access controls
    QStringList authorizedUsers;
    QStringList authorizedApplications;
    QStringList requiredPermissions;

    // Time-based controls
    QDateTime validFrom;
    QDateTime validUntil;
    QStringList allowedTimeWindows;

    // Classification controls
    StorageClassificationLevel minClassificationLevel;
    NSAClassificationLevel minNSAClassification;
    bool requiresHardwareAttestation = false;
    bool requiresQuantumProtection = false;

    // Emergency controls
    bool allowEmergencyAccess = false;
    QString emergencyAccessPolicy;
    bool hasBurnAfterReading = false;
    int maxAccessCount = -1; // -1 = unlimited

    // Audit controls
    bool requiresAuditLogging = true;
    QString auditLogPolicy;
    bool notifyOnAccess = false;
};

// Quantum-secure storage vault interface
class QuantumSecureStorage : public QObject {
    Q_OBJECT

public:
    explicit QuantumSecureStorage(QObject *parent = nullptr);
    ~QuantumSecureStorage();

    // Initialization and configuration
    bool initialize(SecureStorageTier targetTier = SecureStorageTier::Tier3_Standard);
    bool isInitialized() const;
    SecureStorageTier getCurrentStorageTier() const;

    // Hardware detection and configuration
    bool detectAndConfigureHardware();
    QStringList getAvailableHardware() const;
    bool enableHardwareAcceleration(bool enabled);

    // TSM integration
    void setTSMInterface(std::shared_ptr<TSMInterface> tsm);
    std::shared_ptr<TSMInterface> getTSMInterface() const;
    bool isTSMAvailable() const;

    // Quantum security integration
    void setQuantumGuard(std::shared_ptr<QuantumGuard> quantumGuard);
    void setNSASecurity(std::shared_ptr<NSASecurity> nsaSecurity);

    // Storage tier management
    bool upgradeTo(SecureStorageTier newTier);
    bool downgradeTo(SecureStorageTier newTier);
    base::expected<SecureStorageTier, QString> recommendOptimalTier() const;

    // Data storage operations
    base::expected<QString, SecureStorageResult> storeData(
        const QString &dataId,
        const bytes::const_span &data,
        StorageClassificationLevel classification = StorageClassificationLevel::Secret,
        const StorageAccessPolicy &policy = {});

    base::expected<bytes::vector, SecureStorageResult> retrieveData(
        const QString &dataId,
        const QString &requestingApplication = QString());

    SecureStorageResult deleteData(const QString &dataId);
    SecureStorageResult secureDeleteData(const QString &dataId); // NSA-grade secure deletion

    // Bulk operations
    base::expected<QStringList, SecureStorageResult> storeDataBatch(
        const QMap<QString, bytes::vector> &dataBatch,
        StorageClassificationLevel classification = StorageClassificationLevel::Secret);

    base::expected<QMap<QString, bytes::vector>, SecureStorageResult> retrieveDataBatch(
        const QStringList &dataIds);

    // Quantum key storage (specialized for Signal Protocol)
    base::expected<QString, SecureStorageResult> storeQuantumKey(
        const QString &keyId,
        const bytes::const_span &keyData,
        QuantumKeyType keyType,
        QuantumAlgorithm algorithm);

    base::expected<bytes::vector, SecureStorageResult> retrieveQuantumKey(
        const QString &keyId);

    SecureStorageResult rotateQuantumKey(const QString &keyId);

    // Session state storage (for Signal Protocol sessions)
    base::expected<QString, SecureStorageResult> storeSessionState(
        const QString &sessionId,
        const QByteArray &sessionData,
        bool isQuantumSession = false);

    base::expected<QByteArray, SecureStorageResult> retrieveSessionState(
        const QString &sessionId);

    SecureStorageResult deleteSessionState(const QString &sessionId);

    // Access policy management
    void setDefaultAccessPolicy(const StorageAccessPolicy &policy);
    StorageAccessPolicy getDefaultAccessPolicy() const;

    bool setDataAccessPolicy(const QString &dataId, const StorageAccessPolicy &policy);
    base::expected<StorageAccessPolicy, SecureStorageResult> getDataAccessPolicy(
        const QString &dataId) const;

    // Security features
    void enableAntiForensics(bool enabled);
    void enableBurnAfterReading(const QString &dataId, int accessCount = 1);
    void enableEmergencyWipe(const QString &trigger);

    // Backup and recovery
    base::expected<QByteArray, SecureStorageResult> createSecureBackup(
        const QStringList &dataIds,
        const QString &password,
        bool includeMetadata = true);

    base::expected<QStringList, SecureStorageResult> restoreSecureBackup(
        const QByteArray &backupData,
        const QString &password);

    // Migration and synchronization
    base::expected<bool, SecureStorageResult> migrateToHigherSecurity(
        const QString &dataId,
        SecureStorageTier targetTier);

    base::expected<bool, SecureStorageResult> synchronizeWithRemoteVault(
        const QString &remoteVaultUrl,
        const QString &authToken);

    // Auditing and monitoring
    struct StorageAuditEntry {
        QString entryId;
        QDateTime timestamp;
        QString operation;
        QString dataId;
        QString requestingApplication;
        QString userId;
        bool success;
        QString errorMessage;
        SecureStorageTier tierUsed;
        QString hardwareUsed;
    };

    QList<StorageAuditEntry> getAuditLog(
        const QDateTime &from = QDateTime(),
        const QDateTime &to = QDateTime()) const;

    void clearAuditLog();
    void enableAuditLogging(bool enabled);

    // Performance metrics
    struct StoragePerformanceMetrics {
        uint64 totalOperations = 0;
        uint64 storeOperations = 0;
        uint64 retrieveOperations = 0;
        uint64 deleteOperations = 0;

        double averageStoreTime = 0.0;
        double averageRetrieveTime = 0.0;
        double averageDeleteTime = 0.0;

        uint64 hardwareOperations = 0;
        uint64 softwareOperations = 0;
        uint64 quantumOperations = 0;

        double hardwareAccelerationRatio = 0.0;
        double quantumProtectionRatio = 0.0;

        QString fastestTier;
        QString mostSecureTier;

        uint64 totalDataStored = 0; // bytes
        uint64 totalDataRetrieved = 0; // bytes
        uint64 compressionRatio = 100; // percentage
    };

    StoragePerformanceMetrics getPerformanceMetrics() const;
    void resetPerformanceMetrics();

    // Emergency and security features
    void activateEmergencyMode();
    void deactivateEmergencyMode();
    bool isEmergencyModeActive() const;

    void initiateSecureWipe(const QString &reason = QString());
    void cancelSecureWipe();

    // Quantum threat response
    void enableQuantumThreatMode();
    void upgradeAllDataToQuantumSecurity();
    bool isQuantumThreatModeActive() const;

signals:
    void dataStored(const QString &dataId, SecureStorageTier tier);
    void dataRetrieved(const QString &dataId, SecureStorageTier tier);
    void dataDeleted(const QString &dataId);
    void tierUpgraded(SecureStorageTier oldTier, SecureStorageTier newTier);
    void hardwareStatusChanged(bool available);
    void emergencyModeActivated();
    void secureWipeInitiated(const QString &reason);
    void quantumThreatDetected();
    void nsaSecurityViolation(const QString &violation);
    void auditLogEntry(const StorageAuditEntry &entry);

private:
    // Core implementation
    class QuantumSecureStoragePrivate;
    std::unique_ptr<QuantumSecureStoragePrivate> d;

    // Tier-specific implementations
    SecureStorageResult storeDataTier0(const QString &dataId, const bytes::const_span &data,
                                      const EncryptedDataContainer &container);
    SecureStorageResult storeDataTier1(const QString &dataId, const bytes::const_span &data,
                                      const EncryptedDataContainer &container);
    SecureStorageResult storeDataTier2(const QString &dataId, const bytes::const_span &data,
                                      const EncryptedDataContainer &container);
    SecureStorageResult storeDataTier3(const QString &dataId, const bytes::const_span &data,
                                      const EncryptedDataContainer &container);
    SecureStorageResult storeDataTier4(const QString &dataId, const bytes::const_span &data,
                                      const EncryptedDataContainer &container);

    base::expected<bytes::vector, SecureStorageResult> retrieveDataTier0(const QString &dataId);
    base::expected<bytes::vector, SecureStorageResult> retrieveDataTier1(const QString &dataId);
    base::expected<bytes::vector, SecureStorageResult> retrieveDataTier2(const QString &dataId);
    base::expected<bytes::vector, SecureStorageResult> retrieveDataTier3(const QString &dataId);
    base::expected<bytes::vector, SecureStorageResult> retrieveDataTier4(const QString &dataId);

    // Encryption implementations
    EncryptedDataContainer encryptWithQuantumSecurity(
        const bytes::const_span &data,
        QuantumAlgorithm algorithm,
        const QString &keyId);

    EncryptedDataContainer encryptWithHardwareSecurity(
        const bytes::const_span &data,
        const QString &keyId);

    EncryptedDataContainer encryptWithSoftwareSecurity(
        const bytes::const_span &data,
        const QString &password);

    // Security validation
    bool validateAccessPolicy(const QString &dataId, const QString &requestingApp);
    bool validateHardwareIntegrity();
    bool validateQuantumSecurity();

    // Emergency procedures
    void performSecureWipe();
    void destroyEncryptionKeys();
    void obfuscateStorageMetadata();

    // State management
    bool _initialized = false;
    bool _hardwareAcceleration = false;
    bool _antiForensics = false;
    bool _emergencyMode = false;
    bool _quantumThreatMode = false;

    SecureStorageTier _currentTier = SecureStorageTier::Tier3_Standard;
    StorageAccessPolicy _defaultPolicy;
    mutable StoragePerformanceMetrics _performanceMetrics;

    std::shared_ptr<TSMInterface> _tsmInterface;
    std::shared_ptr<QuantumGuard> _quantumGuard;
    std::shared_ptr<NSASecurity> _nsaSecurity;

    // Storage containers
    std::map<QString, EncryptedDataContainer> _dataContainers;
    std::map<QString, StorageAccessPolicy> _accessPolicies;
    mutable std::vector<StorageAuditEntry> _auditLog;
};

// Factory for creating optimized storage instances
class QuantumSecureStorageFactory {
public:
    // Create storage optimized for current hardware
    static std::unique_ptr<QuantumSecureStorage> createOptimized();

    // Create with specific tier requirements
    static std::unique_ptr<QuantumSecureStorage> createForTier(SecureStorageTier tier);

    // Create with specific classification requirements
    static std::unique_ptr<QuantumSecureStorage> createForClassification(
        StorageClassificationLevel classification);

    // Create with TSM integration
    static std::unique_ptr<QuantumSecureStorage> createWithTSM(
        std::shared_ptr<TSMInterface> tsm);

    // Hardware capability detection
    static SecureStorageTier detectOptimalTier();
    static QStringList getAvailableHardwareFeatures();
    static bool isQuantumStorageAvailable();

    // Universal Accessibility helpers
    static QuantumSecureStorage* createUniversalInstance(SecureStorageTier fallbackTier);
    static void configureUniversalFallbacks(QuantumSecureStorage* storage);
};

} // namespace Data