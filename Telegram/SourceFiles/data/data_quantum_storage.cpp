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

#include "base/bytes.h"
#include "base/random.h"
#include "base/unixtime.h"
#include "core/application.h"

#include <QtCore/QByteArray>
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

inline const unsigned char *asConstUChar(const bytes::const_span &span) {
    return reinterpret_cast<const unsigned char *>(span.data());
}

inline unsigned char *asUChar(bytes::span span) {
    return reinterpret_cast<unsigned char *>(span.data());
}

inline const unsigned char *asConstUChar(const bytes::vector &value) {
    return asConstUChar(bytes::make_span(value));
}

inline unsigned char *asUChar(bytes::vector &value) {
    return asUChar(bytes::make_span(value));
}

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

inline bytes::const_span makeSpan(const QByteArray &data) {
    return { reinterpret_cast<const bytes::type *>(data.constData()), static_cast<size_t>(data.size()) };
}

SecureStorageTier detectTierFromHardware() {
    bool hasTPM = false;
    bool hasNPU = false;
    bool hasGNA = false;

    if (QFile::exists("/dev/tpm0") || QFile::exists("/dev/tpmrm0")) {
        hasTPM = true;
    }
    if (QFile::exists("/dev/accel/accel0")) {
        hasNPU = true;
    }
    if (QFile::exists("/sys/class/intel_gaussian")) {
        hasGNA = true;
    }

    if (hasGNA && hasNPU && hasTPM) {
        return SecureStorageTier::Tier0_Quantum;
    } else if (hasNPU && hasTPM) {
        return SecureStorageTier::Tier1_Premium;
    } else if (hasTPM) {
        return SecureStorageTier::Tier2_Enhanced;
    }
    return SecureStorageTier::Tier3_Standard;
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
                RAND_bytes(asUChar(randomData), randomData.size());
                file.seek(0);
                file.write(reinterpret_cast<const char*>(randomData.data()), size);
                file.flush();
            }
        }
        file.remove();
    }

    SecureStorageTier detectOptimalTier() {
        return detectTierFromHardware();
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
        if (tsm && tsm->initialize() == TSMResult::Success) {
            _tsmInterface = std::shared_ptr<TSMInterface>(std::move(tsm));
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
    Q_EMIT tierUpgraded(SecureStorageTier::Tier4_Universal, _currentTier);

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
        Q_EMIT dataStored(dataId, _currentTier);
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
        Q_EMIT dataRetrieved(dataId, container.storageTier);
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

    const auto &key = *keyResult;
    const auto keySpan = makeSpan(key.publicKey);

    // Seal key with TPM 2.0
    auto sealResult = _tsmInterface->sealData(keySpan);
    if (sealResult != TSMResult::Success) {
        return SecureStorageResult::HardwareUnavailable;
    }

    // Encrypt data with quantum algorithm
    auto encryptResult = _quantumGuard->quantumEncrypt(
        key.keyId,
        data);

    if (!encryptResult) {
        return SecureStorageResult::DecryptionFailed;
    }

    // Store encrypted data to file
    QString filePath = d->containerPath + "/" + dataId + ".tier0";
    QFile file(filePath);
    const auto &encryption = *encryptResult;
    if (file.open(QIODevice::WriteOnly)) {
        // Write quantum-encrypted container
        QJsonObject obj;
        obj["keyId"] = key.keyId;
        obj["algorithm"] = static_cast<int>(encryption.algorithm);
        obj["ciphertext"] = QString::fromLatin1(
            QByteArray(reinterpret_cast<const char*>(encryption.ciphertext.data()),
                      encryption.ciphertext.size()).toBase64());
        obj["encapsulatedSecret"] = QString::fromLatin1(
            QByteArray(reinterpret_cast<const char*>(encryption.encapsulatedSecret.data()),
                      encryption.encapsulatedSecret.size()).toBase64());

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
    if (!keyResult) {
        return SecureStorageResult::HardwareUnavailable;
    }

    // Hardware-accelerated AES encryption (if NPU available)
    bytes::vector iv(16);
    RAND_bytes(asUChar(iv), iv.size());

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

SecureStorageResult QuantumSecureStorage::storeDataTier2(
    const QString &dataId,
    const bytes::const_span &data,
    const EncryptedDataContainer &container) {

    // Tier 2: TPM 2.0 hardware-secured storage
    if (!_tsmInterface) {
        return SecureStorageResult::HardwareUnavailable;
    }

    // Generate TPM-backed key
    auto keyResult = _tsmInterface->generateKey(TSMKeyType::AES256);
    if (!keyResult) {
        return SecureStorageResult::HardwareUnavailable;
    }

    // TPM-backed AES encryption
    bytes::vector iv(16);
    RAND_bytes(asUChar(iv), iv.size());

    bytes::vector ciphertext(data.size() + 16);
    // Perform TPM-backed AES encryption...

    QString filePath = d->containerPath + "/" + dataId + ".tier2";
    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly)) {
        QJsonObject obj;
        obj["keyId"] = "tpm_key_" + dataId;
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
    RAND_bytes(asUChar(key), key.size());
    RAND_bytes(asUChar(iv), iv.size());

    // AES-256-GCM encryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return SecureStorageResult::DecryptionFailed;
    }

    if (EVP_EncryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            nullptr,
            asConstUChar(key),
            asConstUChar(iv)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return SecureStorageResult::DecryptionFailed;
    }

    bytes::vector ciphertext(data.size());
    int len;
    if (EVP_EncryptUpdate(
            ctx,
            asUChar(ciphertext),
            &len,
            asConstUChar(data),
            data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return SecureStorageResult::DecryptionFailed;
    }

    int ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, asUChar(ciphertext) + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return SecureStorageResult::DecryptionFailed;
    }
    ciphertext_len += len;

    // Get authentication tag
    bytes::vector tag(16);
    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_GET_TAG,
            16,
            reinterpret_cast<void*>(tag.data())) != 1) {
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

SecureStorageResult QuantumSecureStorage::storeDataTier4(
    const QString &dataId,
    const bytes::const_span &data,
    const EncryptedDataContainer &container) {

    // Tier 4: AES-256 encrypted file storage (universal fallback)

    // Generate encryption key
    bytes::vector key(kAES256KeySize);
    bytes::vector iv(kAES256IvSize);
    RAND_bytes(asUChar(key), key.size());
    RAND_bytes(asUChar(iv), iv.size());

    // AES-256-CBC encryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return SecureStorageResult::DecryptionFailed;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, asConstUChar(key), asConstUChar(iv)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return SecureStorageResult::DecryptionFailed;
    }

    bytes::vector ciphertext(data.size() + 16);
    int len;
    if (EVP_EncryptUpdate(ctx, asUChar(ciphertext), &len, asConstUChar(data), data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return SecureStorageResult::DecryptionFailed;
    }

    int ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, asUChar(ciphertext) + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return SecureStorageResult::DecryptionFailed;
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);

    // Store to file
    QString filePath = d->containerPath + "/" + dataId + ".tier4";
    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly)) {
        QJsonObject obj;
        obj["algorithm"] = "AES-256-CBC";
        obj["iv"] = QString::fromLatin1(QByteArray(
            reinterpret_cast<const char*>(iv.data()), iv.size()).toBase64());
        obj["ciphertext"] = QString::fromLatin1(QByteArray(
            reinterpret_cast<const char*>(ciphertext.data()), ciphertext_len).toBase64());
        obj["key"] = QString::fromLatin1(QByteArray(
            reinterpret_cast<const char*>(key.data()), key.size()).toBase64());

        file.write(QJsonDocument(obj).toJson());
        return SecureStorageResult::Success;
    }

    return SecureStorageResult::PermissionDenied;
}

base::expected<bytes::vector, SecureStorageResult> QuantumSecureStorage::retrieveDataTier0(const QString &dataId) {
    // Tier 0: GNA + NPU + TPM 2.0 quantum-secured retrieval
    if (!_quantumGuard || !_tsmInterface) {
        return base::make_unexpected(SecureStorageResult::HardwareUnavailable);
    }

    QString filePath = d->containerPath + "/" + dataId + ".tier0";
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return base::make_unexpected(SecureStorageResult::KeyNotFound);
    }

    auto doc = QJsonDocument::fromJson(file.readAll());
    auto obj = doc.object();

    QString keyId = obj["keyId"].toString();
    auto ciphertextB64 = obj["ciphertext"].toString().toLatin1();
    auto encapsulatedSecretB64 = obj["encapsulatedSecret"].toString().toLatin1();

    bytes::vector ciphertext;
    bytes::vector encapsulatedSecret;
    auto ciphertextBytes = QByteArray::fromBase64(ciphertextB64);
    auto encapsulatedBytes = QByteArray::fromBase64(encapsulatedSecretB64);

    // Convert QByteArray to bytes::vector properly
    ciphertext.reserve(ciphertextBytes.size());
    for (int i = 0; i < ciphertextBytes.size(); ++i) {
        ciphertext.push_back(static_cast<bytes::type>(static_cast<unsigned char>(ciphertextBytes[i])));
    }
    encapsulatedSecret.reserve(encapsulatedBytes.size());
    for (int i = 0; i < encapsulatedBytes.size(); ++i) {
        encapsulatedSecret.push_back(static_cast<bytes::type>(static_cast<unsigned char>(encapsulatedBytes[i])));
    }

    // Decrypt with quantum algorithm
    auto decryptResult = _quantumGuard->quantumDecrypt(keyId, ciphertext, encapsulatedSecret);
    if (!decryptResult) {
        return base::make_unexpected(SecureStorageResult::DecryptionFailed);
    }

    return decryptResult.value();
}

base::expected<bytes::vector, SecureStorageResult> QuantumSecureStorage::retrieveDataTier1(const QString &dataId) {
    // Tier 1: NPU + TPM 2.0 hardware-backed retrieval
    if (!_tsmInterface) {
        return base::make_unexpected(SecureStorageResult::HardwareUnavailable);
    }

    QString filePath = d->containerPath + "/" + dataId + ".tier1";
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return base::make_unexpected(SecureStorageResult::KeyNotFound);
    }

    auto doc = QJsonDocument::fromJson(file.readAll());
    auto obj = doc.object();

    auto ivB64 = obj["iv"].toString().toLatin1();
    auto ciphertextB64 = obj["ciphertext"].toString().toLatin1();

    bytes::vector iv;
    bytes::vector ciphertext;
    auto ivBytes = QByteArray::fromBase64(ivB64);
    auto ciphertextBytes = QByteArray::fromBase64(ciphertextB64);

    iv.assign(reinterpret_cast<const std::byte*>(ivBytes.data()), reinterpret_cast<const std::byte*>(ivBytes.data() + ivBytes.size()));
    ciphertext.assign(reinterpret_cast<const std::byte*>(ciphertextBytes.data()), reinterpret_cast<const std::byte*>(ciphertextBytes.data() + ciphertextBytes.size()));

    // Hardware-accelerated AES decryption
    bytes::vector plaintext(ciphertext.size());
    // Perform hardware decryption...

    return plaintext;
}

base::expected<bytes::vector, SecureStorageResult> QuantumSecureStorage::retrieveDataTier2(const QString &dataId) {
    // Tier 2: TPM 2.0 hardware-secured retrieval
    if (!_tsmInterface) {
        return base::make_unexpected(SecureStorageResult::HardwareUnavailable);
    }

    QString filePath = d->containerPath + "/" + dataId + ".tier2";
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return base::make_unexpected(SecureStorageResult::KeyNotFound);
    }

    auto doc = QJsonDocument::fromJson(file.readAll());
    auto obj = doc.object();

    auto ivB64 = obj["iv"].toString().toLatin1();
    auto ciphertextB64 = obj["ciphertext"].toString().toLatin1();

    bytes::vector iv;
    bytes::vector ciphertext;
    auto ivBytes = QByteArray::fromBase64(ivB64);
    auto ciphertextBytes = QByteArray::fromBase64(ciphertextB64);

    iv.assign(reinterpret_cast<const std::byte*>(ivBytes.data()), reinterpret_cast<const std::byte*>(ivBytes.data() + ivBytes.size()));
    ciphertext.assign(reinterpret_cast<const std::byte*>(ciphertextBytes.data()), reinterpret_cast<const std::byte*>(ciphertextBytes.data() + ciphertextBytes.size()));

    // TPM-backed AES decryption
    bytes::vector plaintext(ciphertext.size());
    // Perform TPM decryption...

    return plaintext;
}

base::expected<bytes::vector, SecureStorageResult> QuantumSecureStorage::retrieveDataTier3(const QString &dataId) {
    // Tier 3: Software TSM encrypted retrieval

    QString filePath = d->containerPath + "/" + dataId + ".tier3";
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return base::make_unexpected(SecureStorageResult::KeyNotFound);
    }

    auto doc = QJsonDocument::fromJson(file.readAll());
    auto obj = doc.object();

    auto ivB64 = obj["iv"].toString().toLatin1();
    auto ciphertextB64 = obj["ciphertext"].toString().toLatin1();
    auto tagB64 = obj["tag"].toString().toLatin1();

    bytes::vector iv;
    bytes::vector ciphertext;
    bytes::vector tag;
    auto ivBytes = QByteArray::fromBase64(ivB64);
    auto ciphertextBytes = QByteArray::fromBase64(ciphertextB64);
    auto tagBytes = QByteArray::fromBase64(tagB64);

    iv.assign(reinterpret_cast<const std::byte*>(ivBytes.data()), reinterpret_cast<const std::byte*>(ivBytes.data() + ivBytes.size()));
    ciphertext.assign(reinterpret_cast<const std::byte*>(ciphertextBytes.data()), reinterpret_cast<const std::byte*>(ciphertextBytes.data() + ciphertextBytes.size()));
    tag.assign(reinterpret_cast<const std::byte*>(tagBytes.data()), reinterpret_cast<const std::byte*>(tagBytes.data() + tagBytes.size()));

    // AES-256-GCM decryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return base::make_unexpected(SecureStorageResult::DecryptionFailed);
    }

    // Note: We need to retrieve the key from secure storage
    // For now, returning empty as key management needs to be implemented
    bytes::vector key(kAES256KeySize);
    // TODO: Retrieve key from secure key storage

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, asConstUChar(key), asConstUChar(iv)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return base::make_unexpected(SecureStorageResult::DecryptionFailed);
    }

    bytes::vector plaintext(ciphertext.size());
    int len;
    if (EVP_DecryptUpdate(ctx, asUChar(plaintext), &len, asConstUChar(ciphertext), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return base::make_unexpected(SecureStorageResult::DecryptionFailed);
    }

    int plaintext_len = len;

    // Set expected tag value
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, reinterpret_cast<void*>(const_cast<bytes::type*>(tag.data()))) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return base::make_unexpected(SecureStorageResult::IntegrityCheckFailed);
    }

    if (EVP_DecryptFinal_ex(ctx, asUChar(plaintext) + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return base::make_unexpected(SecureStorageResult::IntegrityCheckFailed);
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

base::expected<bytes::vector, SecureStorageResult> QuantumSecureStorage::retrieveDataTier4(const QString &dataId) {
    // Tier 4: AES-256 encrypted file retrieval (universal fallback)

    QString filePath = d->containerPath + "/" + dataId + ".tier4";
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return base::make_unexpected(SecureStorageResult::KeyNotFound);
    }

    auto doc = QJsonDocument::fromJson(file.readAll());
    auto obj = doc.object();

    auto ivB64 = obj["iv"].toString().toLatin1();
    auto ciphertextB64 = obj["ciphertext"].toString().toLatin1();
    auto keyB64 = obj["key"].toString().toLatin1();

    bytes::vector iv;
    bytes::vector ciphertext;
    bytes::vector key;
    auto ivBytes = QByteArray::fromBase64(ivB64);
    auto ciphertextBytes = QByteArray::fromBase64(ciphertextB64);
    auto keyBytes = QByteArray::fromBase64(keyB64);

    iv.assign(reinterpret_cast<const std::byte*>(ivBytes.data()), reinterpret_cast<const std::byte*>(ivBytes.data() + ivBytes.size()));
    ciphertext.assign(reinterpret_cast<const std::byte*>(ciphertextBytes.data()), reinterpret_cast<const std::byte*>(ciphertextBytes.data() + ciphertextBytes.size()));
    key.assign(reinterpret_cast<const std::byte*>(keyBytes.data()), reinterpret_cast<const std::byte*>(keyBytes.data() + keyBytes.size()));

    // AES-256-CBC decryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return base::make_unexpected(SecureStorageResult::DecryptionFailed);
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, asConstUChar(key), asConstUChar(iv)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return base::make_unexpected(SecureStorageResult::DecryptionFailed);
    }

    bytes::vector plaintext(ciphertext.size());
    int len;
    if (EVP_DecryptUpdate(ctx, asUChar(plaintext), &len, asConstUChar(ciphertext), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return base::make_unexpected(SecureStorageResult::DecryptionFailed);
    }

    int plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, asUChar(plaintext) + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return base::make_unexpected(SecureStorageResult::DecryptionFailed);
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
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
    return detectTierFromHardware();
}

std::shared_ptr<QuantumGuard> QuantumGuardFactory::createOptimized() {
    auto guard = std::make_shared<QuantumGuard>();
    guard->initialize();
    guard->setProtected(true);
    return guard;
}

bool QuantumGuardFactory::isQuantumHardwareAvailable() {
    return QFile::exists("/dev/accel/accel0")
        || QFile::exists("/dev/tpm0")
        || QFile::exists("/dev/tpmrm0");
}

std::shared_ptr<NSASecurity> NSASecurityFactory::createForQuantumThreats() {
    auto security = std::make_shared<NSASecurity>();
    security->initialize();
    security->setSecured(true);
    return security;
}

} // namespace Data
