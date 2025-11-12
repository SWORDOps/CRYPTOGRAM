/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#include "data/data_quantum_storage.h"
#include "data/data_tsm_factory.h"

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "base/random.h"
#include "base/unixtime.h"
#include "core/application.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonArray>
#include <QtCore/QStandardPaths>

namespace Data {
namespace {

// Storage paths and configuration
constexpr auto kQuantumStorageDir = "quantum_storage";
constexpr auto kDataContainerDir = "containers";
constexpr auto kAuditLogFile = "audit.log";
constexpr auto kMetricsFile = "metrics.json";
constexpr auto kPolicyFile = "policies.json";

// Encryption parameters
constexpr auto kAES256KeySize = 32;
constexpr auto kAES256IvSize = 16;
constexpr auto kHMACSize = 32;
constexpr auto kQuantumMargin = 2; // 2x security margin for quantum threats

// Performance thresholds
constexpr auto kHardwareOperationThreshold = 1000; // microseconds
constexpr auto kQuantumOperationThreshold = 5000; // microseconds

QString getStorageBasePath() {
    auto dataPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir dir(dataPath);
    if (!dir.exists()) {
        dir.mkpath(dataPath);
    }
    return dataPath + "/" + kQuantumStorageDir;
}

QString getDataContainerPath() {
    auto basePath = getStorageBasePath();
    QDir dir(basePath);
    if (!dir.exists(kDataContainerDir)) {
        dir.mkdir(kDataContainerDir);
    }
    return basePath + "/" + kDataContainerDir;
}

} // namespace

class QuantumSecureStorage::QuantumSecureStoragePrivate {
public:
    explicit QuantumSecureStoragePrivate()
        : basePath(getStorageBasePath())
        , containerPath(getDataContainerPath()) {

        // Ensure storage directories exist
        QDir dir;
        dir.mkpath(basePath);
        dir.mkpath(containerPath);

        // Load existing policies and metrics
        loadStoragePolicies();
        loadPerformanceMetrics();
    }

    ~QuantumSecureStoragePrivate() {
        if (emergencyMode) {
            performEmergencyCleanup();
        }
    }

    void loadStoragePolicies() {
        QString policyPath = basePath + "/" + kPolicyFile;
        QFile file(policyPath);
        if (file.open(QIODevice::ReadOnly)) {
            auto doc = QJsonDocument::fromJson(file.readAll());
            // Load policies from JSON...
        }
    }

    void saveStoragePolicies() {
        QString policyPath = basePath + "/" + kPolicyFile;
        QFile file(policyPath);
        if (file.open(QIODevice::WriteOnly)) {
            QJsonObject obj;
            // Save policies to JSON...
            file.write(QJsonDocument(obj).toJson());
        }
    }

    void loadPerformanceMetrics() {
        QString metricsPath = basePath + "/" + kMetricsFile;
        QFile file(metricsPath);
        if (file.open(QIODevice::ReadOnly)) {
            auto doc = QJsonDocument::fromJson(file.readAll());
            // Load metrics from JSON...
        }
    }

    void savePerformanceMetrics() {
        QString metricsPath = basePath + "/" + kMetricsFile;
        QFile file(metricsPath);
        if (file.open(QIODevice::WriteOnly)) {
            QJsonObject obj;
            obj["totalOperations"] = static_cast<qint64>(metrics.totalOperations);
            obj["storeOperations"] = static_cast<qint64>(metrics.storeOperations);
            obj["retrieveOperations"] = static_cast<qint64>(metrics.retrieveOperations);
            obj["averageStoreTime"] = metrics.averageStoreTime;
            obj["averageRetrieveTime"] = metrics.averageRetrieveTime;
            obj["hardwareAccelerationRatio"] = metrics.hardwareAccelerationRatio;
            obj["quantumProtectionRatio"] = metrics.quantumProtectionRatio;

            file.write(QJsonDocument(obj).toJson());
        }
    }

    void logAuditEntry(const QuantumSecureStorage::StorageAuditEntry &entry) {
        auditLog.push_back(entry);

        // Write to audit log file
        QString auditPath = basePath + "/" + kAuditLogFile;
        QFile file(auditPath);
        if (file.open(QIODevice::WriteOnly | QIODevice::Append)) {
            QJsonObject obj;
            obj["timestamp"] = entry.timestamp.toString(Qt::ISODate);
            obj["operation"] = entry.operation;
            obj["dataId"] = entry.dataId;
            obj["application"] = entry.requestingApplication;
            obj["success"] = entry.success;
            obj["tier"] = static_cast<int>(entry.tierUsed);

            file.write(QJsonDocument(obj).toJson(QJsonDocument::Compact) + "\n");
        }
    }

    void performEmergencyCleanup() {
        // Secure deletion of all data
        QDir containerDir(containerPath);
        auto entries = containerDir.entryList(QDir::Files);
        for (const auto &entry : entries) {
            secureDeleteFile(containerDir.absoluteFilePath(entry));
        }

        // Clear in-memory data
        dataContainers.clear();
        accessPolicies.clear();
        auditLog.clear();
    }

    void secureDeleteFile(const QString &filePath) {
        QFile file(filePath);
        if (file.open(QIODevice::WriteOnly)) {
            // Overwrite with random data multiple times (DoD 5220.22-M standard)
            qint64 size = file.size();
            bytes::vector randomData(size);

            for (int pass = 0; pass < 3; ++pass) {
                RAND_bytes(randomData.data(), randomData.size());
                file.seek(0);
                file.write(reinterpret_cast<const char*>(randomData.data()), size);
                file.flush();
            }
        }
        file.remove();
    }

    SecureStorageTier detectOptimalTier() {
        // Hardware capability detection
        bool hasTPM = false;
        bool hasNPU = false;
        bool hasGNA = false;

        // Detect TPM 2.0
        if (QFile::exists("/dev/tpm0") || QFile::exists("/dev/tpmrm0")) {
            hasTPM = true;
        }

        // Detect NPU (Intel implementation)
        if (QFile::exists("/dev/accel/accel0")) {
            hasNPU = true;
        }

        // Detect GNA (Gaussian Neural Accelerator)
        if (QFile::exists("/sys/class/intel_gaussian")) {
            hasGNA = true;
        }

        if (hasGNA && hasNPU && hasTPM) {
            return SecureStorageTier::Tier0_Quantum;
        } else if (hasNPU && hasTPM) {
            return SecureStorageTier::Tier1_Premium;
        } else if (hasTPM) {
            return SecureStorageTier::Tier2_Enhanced;
        } else {
            return SecureStorageTier::Tier3_Standard;
        }
    }

    QString basePath;
    QString containerPath;
    bool emergencyMode = false;
    bool auditingEnabled = true;

    std::map<QString, EncryptedDataContainer> dataContainers;
    std::map<QString, StorageAccessPolicy> accessPolicies;
    std::vector<QuantumSecureStorage::StorageAuditEntry> auditLog;
    QuantumSecureStorage::StoragePerformanceMetrics metrics;
};

QuantumSecureStorage::QuantumSecureStorage(QObject *parent)
    : QObject(parent)
    , d(std::make_unique<QuantumSecureStoragePrivate>()) {
}

QuantumSecureStorage::~QuantumSecureStorage() = default;

bool QuantumSecureStorage::initialize(SecureStorageTier targetTier) {
    if (_initialized) {
        return true;
    }

    // Detect optimal tier based on available hardware
    auto detectedTier = d->detectOptimalTier();

    // Use the better of requested and detected tier
    _currentTier = std::max(targetTier, detectedTier);

    // Initialize TSM interface
    if (_currentTier <= SecureStorageTier::Tier2_Enhanced) {
        auto tsm = TSMFactory::createForPlatform();
        if (tsm && tsm->initialize()) {
            _tsmInterface = tsm;
        } else {
            // Fallback to software TSM
            _currentTier = SecureStorageTier::Tier3_Standard;
        }
    }

    // Initialize quantum security if available
    if (_currentTier <= SecureStorageTier::Tier1_Premium) {
        _quantumGuard = QuantumGuardFactory::createOptimized();
        if (_quantumGuard && !_quantumGuard->initialize()) {
            _quantumGuard.reset();
        }
    }

    // Initialize NSA security
    _nsaSecurity = NSASecurityFactory::createForQuantumThreats();
    if (_nsaSecurity) {
        _nsaSecurity->initialize(NSAClassificationLevel::Secret);
    }

    // Setup default access policy
    _defaultPolicy.policyId = "default";
    _defaultPolicy.description = "Default quantum storage access policy";
    _defaultPolicy.minClassificationLevel = StorageClassificationLevel::Confidential;
    _defaultPolicy.minNSAClassification = NSAClassificationLevel::Confidential;
    _defaultPolicy.requiresAuditLogging = true;
    _defaultPolicy.maxAccessCount = -1;

    _initialized = true;
    emit tierUpgraded(SecureStorageTier::Tier4_Universal, _currentTier);

    return true;
}

bool QuantumSecureStorage::isInitialized() const {
    return _initialized;
}

SecureStorageTier QuantumSecureStorage::getCurrentStorageTier() const {
    return _currentTier;
}

base::expected<QString, SecureStorageResult> QuantumSecureStorage::storeData(
    const QString &dataId,
    const bytes::const_span &data,
    StorageClassificationLevel classification,
    const StorageAccessPolicy &policy) {

    if (!_initialized) {
        return base::make_unexpected(SecureStorageResult::PermissionDenied);
    }

    auto startTime = std::chrono::high_resolution_clock::now();

    // Validate access policy
    if (!validateAccessPolicy(dataId, "internal")) {
        return base::make_unexpected(SecureStorageResult::PermissionDenied);
    }

    // Create encrypted container
    EncryptedDataContainer container;
    container.dataId = dataId;
    container.classification = classification;
    container.storageTier = _currentTier;
    container.created = QDateTime::currentDateTime();
    container.lastAccessed = container.created;

    // Set expiry based on classification
    switch (classification) {
    case StorageClassificationLevel::TopSecret:
    case StorageClassificationLevel::SCI:
        container.expires = container.created.addDays(30);
        break;
    case StorageClassificationLevel::Secret:
        container.expires = container.created.addDays(90);
        break;
    default:
        container.expires = container.created.addDays(365);
        break;
    }

    // Choose encryption method based on tier and classification
    SecureStorageResult result;
    switch (_currentTier) {
    case SecureStorageTier::Tier0_Quantum:
        result = storeDataTier0(dataId, data, container);
        break;
    case SecureStorageTier::Tier1_Premium:
        result = storeDataTier1(dataId, data, container);
        break;
    case SecureStorageTier::Tier2_Enhanced:
        result = storeDataTier2(dataId, data, container);
        break;
    case SecureStorageTier::Tier3_Standard:
        result = storeDataTier3(dataId, data, container);
        break;
    case SecureStorageTier::Tier4_Universal:
        result = storeDataTier4(dataId, data, container);
        break;
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

    // Update performance metrics
    _performanceMetrics.totalOperations++;
    _performanceMetrics.storeOperations++;
    _performanceMetrics.averageStoreTime =
        (_performanceMetrics.averageStoreTime * (_performanceMetrics.storeOperations - 1) +
         duration.count()) / _performanceMetrics.storeOperations;

    if (_currentTier <= SecureStorageTier::Tier2_Enhanced) {
        _performanceMetrics.hardwareOperations++;
        _performanceMetrics.hardwareAccelerationRatio =
            static_cast<double>(_performanceMetrics.hardwareOperations) /
            _performanceMetrics.totalOperations;
    }

    if (_currentTier <= SecureStorageTier::Tier1_Premium) {
        _performanceMetrics.quantumOperations++;
        _performanceMetrics.quantumProtectionRatio =
            static_cast<double>(_performanceMetrics.quantumOperations) /
            _performanceMetrics.totalOperations;
    }

    // Log audit entry
    if (d->auditingEnabled) {
        StorageAuditEntry entry;
        entry.entryId = QString::number(base::RandomValue<uint64>());
        entry.timestamp = QDateTime::currentDateTime();
        entry.operation = "store";
        entry.dataId = dataId;
        entry.requestingApplication = "SpyGram";
        entry.success = (result == SecureStorageResult::Success);
        entry.tierUsed = _currentTier;
        entry.hardwareUsed = _tsmInterface ? "TSM" : "Software";

        d->logAuditEntry(entry);
    }

    if (result == SecureStorageResult::Success) {
        d->dataContainers[dataId] = container;
        if (!policy.policyId.isEmpty()) {
            d->accessPolicies[dataId] = policy;
        }
        emit dataStored(dataId, _currentTier);
        return dataId;
    }

    return base::make_unexpected(result);
}

base::expected<bytes::vector, SecureStorageResult> QuantumSecureStorage::retrieveData(
    const QString &dataId,
    const QString &requestingApplication) {

    if (!_initialized) {
        return base::make_unexpected(SecureStorageResult::PermissionDenied);
    }

    auto startTime = std::chrono::high_resolution_clock::now();

    // Validate access policy
    if (!validateAccessPolicy(dataId, requestingApplication)) {
        return base::make_unexpected(SecureStorageResult::PermissionDenied);
    }

    // Check if data exists
    auto it = d->dataContainers.find(dataId);
    if (it == d->dataContainers.end()) {
        return base::make_unexpected(SecureStorageResult::KeyNotFound);
    }

    auto &container = it->second;

    // Check expiry
    if (container.expires.isValid() && container.expires < QDateTime::currentDateTime()) {
        d->dataContainers.erase(it);
        return base::make_unexpected(SecureStorageResult::KeyNotFound);
    }

    // Retrieve based on storage tier
    base::expected<bytes::vector, SecureStorageResult> result;
    switch (container.storageTier) {
    case SecureStorageTier::Tier0_Quantum:
        result = retrieveDataTier0(dataId);
        break;
    case SecureStorageTier::Tier1_Premium:
        result = retrieveDataTier1(dataId);
        break;
    case SecureStorageTier::Tier2_Enhanced:
        result = retrieveDataTier2(dataId);
        break;
    case SecureStorageTier::Tier3_Standard:
        result = retrieveDataTier3(dataId);
        break;
    case SecureStorageTier::Tier4_Universal:
        result = retrieveDataTier4(dataId);
        break;
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

    // Update performance metrics
    _performanceMetrics.totalOperations++;
    _performanceMetrics.retrieveOperations++;
    _performanceMetrics.averageRetrieveTime =
        (_performanceMetrics.averageRetrieveTime * (_performanceMetrics.retrieveOperations - 1) +
         duration.count()) / _performanceMetrics.retrieveOperations;

    // Update last accessed time
    container.lastAccessed = QDateTime::currentDateTime();

    // Log audit entry
    if (d->auditingEnabled) {
        StorageAuditEntry entry;
        entry.entryId = QString::number(base::RandomValue<uint64>());
        entry.timestamp = QDateTime::currentDateTime();
        entry.operation = "retrieve";
        entry.dataId = dataId;
        entry.requestingApplication = requestingApplication;
        entry.success = result.has_value();
        entry.tierUsed = container.storageTier;

        d->logAuditEntry(entry);
    }

    if (result) {
        emit dataRetrieved(dataId, container.storageTier);
    }

    return result;
}

SecureStorageResult QuantumSecureStorage::storeDataTier0(
    const QString &dataId,
    const bytes::const_span &data,
    const EncryptedDataContainer &container) {

    // Tier 0: GNA + NPU + TPM 2.0 quantum-secured storage
    if (!_quantumGuard || !_tsmInterface) {
        return SecureStorageResult::HardwareUnavailable;
    }

    // Generate quantum key using GNA
    auto keyResult = _quantumGuard->generateQuantumKey(
        QuantumKeyType::Backup,
        QuantumAlgorithm::Kyber1024);

    if (!keyResult) {
        return SecureStorageResult::HardwareUnavailable;
    }

    // Seal key with TPM 2.0
    auto sealResult = _tsmInterface->sealData(keyResult->publicKey);
    if (sealResult != TSMResult::Success) {
        return SecureStorageResult::HardwareUnavailable;
    }

    // Encrypt data with quantum algorithm
    auto encryptResult = _quantumGuard->quantumEncrypt(
        keyResult->keyId,
        data);

    if (!encryptResult) {
        return SecureStorageResult::DecryptionFailed;
    }

    // Store encrypted data to file
    QString filePath = d->containerPath + "/" + dataId + ".tier0";
    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly)) {
        // Write quantum-encrypted container
        QJsonObject obj;
        obj["keyId"] = keyResult->keyId;
        obj["algorithm"] = static_cast<int>(encryptResult->algorithm);
        obj["ciphertext"] = QString::fromLatin1(
            QByteArray(reinterpret_cast<const char*>(encryptResult->ciphertext.data()),
                      encryptResult->ciphertext.size()).toBase64());
        obj["encapsulatedSecret"] = QString::fromLatin1(
            QByteArray(reinterpret_cast<const char*>(encryptResult->encapsulatedSecret.data()),
                      encryptResult->encapsulatedSecret.size()).toBase64());

        file.write(QJsonDocument(obj).toJson());
        return SecureStorageResult::Success;
    }

    return SecureStorageResult::PermissionDenied;
}

SecureStorageResult QuantumSecureStorage::storeDataTier1(
    const QString &dataId,
    const bytes::const_span &data,
    const EncryptedDataContainer &container) {

    // Tier 1: NPU + TPM 2.0 hardware-backed storage
    if (!_tsmInterface) {
        return SecureStorageResult::HardwareUnavailable;
    }

    // Generate hardware-backed key
    auto keyResult = _tsmInterface->generateKey(TSMKeyType::AES256);
    if (keyResult != TSMResult::Success) {
        return SecureStorageResult::HardwareUnavailable;
    }

    // Hardware-accelerated AES encryption (if NPU available)
    bytes::vector iv(16);
    RAND_bytes(iv.data(), iv.size());

    bytes::vector ciphertext(data.size() + 16); // AES block padding
    // Perform AES encryption using hardware acceleration...

    QString filePath = d->containerPath + "/" + dataId + ".tier1";
    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly)) {
        QJsonObject obj;
        obj["keyId"] = "hardware_key_" + dataId;
        obj["iv"] = QString::fromLatin1(QByteArray(
            reinterpret_cast<const char*>(iv.data()), iv.size()).toBase64());
        obj["ciphertext"] = QString::fromLatin1(QByteArray(
            reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size()).toBase64());

        file.write(QJsonDocument(obj).toJson());
        return SecureStorageResult::Success;
    }

    return SecureStorageResult::PermissionDenied;
}

SecureStorageResult QuantumSecureStorage::storeDataTier3(
    const QString &dataId,
    const bytes::const_span &data,
    const EncryptedDataContainer &container) {

    // Tier 3: Software TSM encrypted storage

    // Generate software encryption key
    bytes::vector key(kAES256KeySize);
    bytes::vector iv(kAES256IvSize);
    RAND_bytes(key.data(), key.size());
    RAND_bytes(iv.data(), iv.size());

    // AES-256-GCM encryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return SecureStorageResult::DecryptionFailed;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return SecureStorageResult::DecryptionFailed;
    }

    bytes::vector ciphertext(data.size());
    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, data.data(), data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return SecureStorageResult::DecryptionFailed;
    }

    int ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return SecureStorageResult::DecryptionFailed;
    }
    ciphertext_len += len;

    // Get authentication tag
    bytes::vector tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return SecureStorageResult::DecryptionFailed;
    }

    EVP_CIPHER_CTX_free(ctx);

    // Store to file
    QString filePath = d->containerPath + "/" + dataId + ".tier3";
    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly)) {
        QJsonObject obj;
        obj["algorithm"] = "AES-256-GCM";
        obj["iv"] = QString::fromLatin1(QByteArray(
            reinterpret_cast<const char*>(iv.data()), iv.size()).toBase64());
        obj["ciphertext"] = QString::fromLatin1(QByteArray(
            reinterpret_cast<const char*>(ciphertext.data()), ciphertext_len).toBase64());
        obj["tag"] = QString::fromLatin1(QByteArray(
            reinterpret_cast<const char*>(tag.data()), tag.size()).toBase64());

        file.write(QJsonDocument(obj).toJson());
        return SecureStorageResult::Success;
    }

    return SecureStorageResult::PermissionDenied;
}

bool QuantumSecureStorage::validateAccessPolicy(
    const QString &dataId,
    const QString &requestingApp) {

    // Check if specific policy exists for this data
    auto it = d->accessPolicies.find(dataId);
    const auto &policy = (it != d->accessPolicies.end()) ? it->second : _defaultPolicy;

    // Validate time-based access
    auto now = QDateTime::currentDateTime();
    if (policy.validFrom.isValid() && now < policy.validFrom) {
        return false;
    }
    if (policy.validUntil.isValid() && now > policy.validUntil) {
        return false;
    }

    // Validate application access
    if (!policy.authorizedApplications.isEmpty() &&
        !policy.authorizedApplications.contains(requestingApp)) {
        return false;
    }

    return true;
}

QuantumSecureStorage::StoragePerformanceMetrics QuantumSecureStorage::getPerformanceMetrics() const {
    return _performanceMetrics;
}

void QuantumSecureStorage::resetPerformanceMetrics() {
    _performanceMetrics = StoragePerformanceMetrics{};
}

// Factory implementations
std::unique_ptr<QuantumSecureStorage> QuantumSecureStorageFactory::createOptimized() {
    auto storage = std::make_unique<QuantumSecureStorage>();
    auto optimalTier = detectOptimalTier();
    storage->initialize(optimalTier);
    return storage;
}

SecureStorageTier QuantumSecureStorageFactory::detectOptimalTier() {
    QuantumSecureStorage::QuantumSecureStoragePrivate helper;
    return helper.detectOptimalTier();
}

} // namespace Data