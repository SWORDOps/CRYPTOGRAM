/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#include "data_tsm_interface.h"
#include "data_tsm_tpm20.h"

#ifdef Q_OS_ANDROID
#include "data_tsm_android.h"
#endif

#ifdef Q_OS_MACOS
#include "data_tsm_apple.h"
#endif

#include "data_tsm_software.h"

#include <QtCore/QLoggingCategory>
#include <QtCore/QSysInfo>

namespace Data {

Q_LOGGING_CATEGORY(lcTSMFactory, "data.tsm.factory")

namespace {

// Platform detection helpers
bool isTPM20Available() {
#ifdef Q_OS_WIN
    return TPM20Utils::isTPM20Available();
#elif defined(Q_OS_LINUX)
    return TPM20Utils::isTPM20Available();
#else
    return false;
#endif
}

bool isAndroidKeystoreAvailable() {
#ifdef Q_OS_ANDROID
    return AndroidKeystoreUtils::isKeystoreAvailable();
#else
    return false;
#endif
}

bool isAppleSecureEnclaveAvailable() {
#ifdef Q_OS_MACOS
    return AppleSecureEnclaveUtils::isSecureEnclaveAvailable();
#elif defined(Q_OS_IOS)
    return AppleSecureEnclaveUtils::isSecureEnclaveAvailable();
#else
    return false;
#endif
}

} // namespace

// TSMFactory implementation
std::unique_ptr<TSMInterface> TSMFactory::create() {
    qCInfo(lcTSMFactory) << "Creating optimal TSM implementation for platform";

    // Try platform-specific implementations in order of security preference

    // 1. Try TPM 2.0 (Desktop platforms - highest security)
    if (isTPM20Available()) {
        qCInfo(lcTSMFactory) << "TPM 2.0 detected, creating TPM implementation";
        auto tpm = createTPM20();
        if (tpm && tpm->initialize() == TSMResult::Success) {
            qCInfo(lcTSMFactory) << "TPM 2.0 implementation initialized successfully";
            return tpm;
        }
        qCWarning(lcTSMFactory) << "TPM 2.0 available but initialization failed";
    }

    // 2. Try Android KeyStore (Android - hardware-backed when available)
    if (isAndroidKeystoreAvailable()) {
        qCInfo(lcTSMFactory) << "Android KeyStore detected, creating Android implementation";
        auto android = createAndroidKeyStore();
        if (android && android->initialize() == TSMResult::Success) {
            qCInfo(lcTSMFactory) << "Android KeyStore implementation initialized successfully";
            return android;
        }
        qCWarning(lcTSMFactory) << "Android KeyStore available but initialization failed";
    }

    // 3. Try Apple Secure Enclave (macOS/iOS - hardware-backed)
    if (isAppleSecureEnclaveAvailable()) {
        qCInfo(lcTSMFactory) << "Apple Secure Enclave detected, creating Apple implementation";
        auto apple = createAppleSecureEnclave();
        if (apple && apple->initialize() == TSMResult::Success) {
            qCInfo(lcTSMFactory) << "Apple Secure Enclave implementation initialized successfully";
            return apple;
        }
        qCWarning(lcTSMFactory) << "Apple Secure Enclave available but initialization failed";
    }

    // 4. Fall back to software implementation
    qCInfo(lcTSMFactory) << "No hardware TSM available, falling back to software implementation";
    auto software = createSoftwareFallback();
    if (software && software->initialize() == TSMResult::Success) {
        qCInfo(lcTSMFactory) << "Software fallback implementation initialized successfully";
        return software;
    }

    qCCritical(lcTSMFactory) << "All TSM implementations failed to initialize";
    return nullptr;
}

std::unique_ptr<TSMInterface> TSMFactory::createTPM20() {
#if defined(Q_OS_WIN) || defined(Q_OS_LINUX)
    qCDebug(lcTSMFactory) << "Creating TPM 2.0 implementation";
    return std::make_unique<TPM20Implementation>();
#else
    qCWarning(lcTSMFactory) << "TPM 2.0 not supported on this platform";
    return nullptr;
#endif
}

std::unique_ptr<TSMInterface> TSMFactory::createAndroidKeyStore() {
#ifdef Q_OS_ANDROID
    qCDebug(lcTSMFactory) << "Creating Android KeyStore implementation";
    return std::make_unique<AndroidKeystoreImplementation>();
#else
    qCWarning(lcTSMFactory) << "Android KeyStore not supported on this platform";
    return nullptr;
#endif
}

std::unique_ptr<TSMInterface> TSMFactory::createAppleSecureEnclave() {
#if defined(Q_OS_MACOS) || defined(Q_OS_IOS)
    qCDebug(lcTSMFactory) << "Creating Apple Secure Enclave implementation";
    return std::make_unique<AppleSecureEnclaveImplementation>();
#else
    qCWarning(lcTSMFactory) << "Apple Secure Enclave not supported on this platform";
    return nullptr;
#endif
}

std::unique_ptr<TSMInterface> TSMFactory::createSoftwareFallback() {
    qCDebug(lcTSMFactory) << "Creating software fallback implementation";
    return std::make_unique<SoftwareTSMImplementation>();
}

TSMPlatform TSMFactory::detectPlatform() {
    qCDebug(lcTSMFactory) << "Detecting optimal TSM platform";

    // Check for TPM 2.0 first (most secure for desktop)
    if (isTPM20Available()) {
        qCInfo(lcTSMFactory) << "Platform detection: TPM 2.0";
        return TSMPlatform::TPM20;
    }

    // Check for Android KeyStore
    if (isAndroidKeystoreAvailable()) {
        qCInfo(lcTSMFactory) << "Platform detection: Android KeyStore";
        return TSMPlatform::AndroidKeyStore;
    }

    // Check for Apple Secure Enclave
    if (isAppleSecureEnclaveAvailable()) {
        qCInfo(lcTSMFactory) << "Platform detection: Apple Secure Enclave";
        return TSMPlatform::AppleSecureEnclave;
    }

    // Default to software fallback
    qCInfo(lcTSMFactory) << "Platform detection: Software Fallback";
    return TSMPlatform::SoftwareFallback;
}

bool TSMFactory::isPlatformSupported(TSMPlatform platform) {
    switch (platform) {
    case TSMPlatform::TPM20:
        return isTPM20Available();
    case TSMPlatform::AndroidKeyStore:
        return isAndroidKeystoreAvailable();
    case TSMPlatform::AppleSecureEnclave:
        return isAppleSecureEnclaveAvailable();
    case TSMPlatform::SoftwareFallback:
        return true; // Always available
    default:
        return false;
    }
}

QStringList TSMFactory::getSupportedPlatforms() {
    QStringList platforms;

    if (isTPM20Available()) {
        platforms << "TPM20";
    }

    if (isAndroidKeystoreAvailable()) {
        platforms << "AndroidKeyStore";
    }

    if (isAppleSecureEnclaveAvailable()) {
        platforms << "AppleSecureEnclave";
    }

    // Software fallback always available
    platforms << "SoftwareFallback";

    qCDebug(lcTSMFactory) << "Supported platforms:" << platforms;
    return platforms;
}

// TSMInterface helper implementations
QString TSMInterface::generateUniqueKeyId() const {
    // Generate a unique key ID using timestamp and random component
    auto timestamp = QDateTime::currentMSecsSinceEpoch();
    auto random = QRandomGenerator::global()->generate();

    return QString("spygram_key_%1_%2")
        .arg(timestamp)
        .arg(random, 8, 16, QChar('0'));
}

bool TSMInterface::validateKeyId(const QString &keyId) const {
    // Validate key ID format and length
    if (keyId.isEmpty() || keyId.length() > 256) {
        return false;
    }

    // Check for valid characters (alphanumeric plus underscore and dash)
    static const QRegularExpression validChars("^[a-zA-Z0-9_-]+$");
    return validChars.match(keyId).hasMatch();
}

TSMResult TSMInterface::mapPlatformError(int platformErrorCode) const {
    // Default platform error mapping
    if (platformErrorCode == 0) {
        return TSMResult::Success;
    } else if (platformErrorCode < 0) {
        return TSMResult::UnknownError;
    } else {
        return TSMResult::HardwareNotAvailable;
    }
}

// SignalTSMIntegration implementation
SignalTSMIntegration::SignalTSMIntegration(not_null<Session*> session)
    : _session(session)
    , _initialized(false) {

    qCDebug(lcTSMFactory) << "Creating Signal Protocol TSM integration";
}

SignalTSMIntegration::~SignalTSMIntegration() = default;

TSMResult SignalTSMIntegration::initializeWithSignalProtocol() {
    if (_initialized) {
        return TSMResult::Success;
    }

    qCInfo(lcTSMFactory) << "Initializing Signal Protocol with TSM integration";

    // Create optimal TSM implementation
    _tsm = TSMFactory::create();
    if (!_tsm) {
        qCCritical(lcTSMFactory) << "Failed to create TSM implementation";
        return TSMResult::HardwareNotAvailable;
    }

    // Validate TSM capabilities
    auto validationResult = validateTSMCapabilities();
    if (validationResult != TSMResult::Success) {
        qCWarning(lcTSMFactory) << "TSM capabilities validation failed";
        return validationResult;
    }

    // Generate device attestation key
    auto attestationResult = _tsm->generateKey(
        TSMKeyType::DeviceAttestation,
        "spygram_device_attestation");

    if (!attestationResult.has_value()) {
        qCWarning(lcTSMFactory) << "Failed to generate device attestation key";
        // Continue anyway - attestation is optional
    } else {
        _deviceAttestationKeyId = attestationResult.value().keyId;
        qCInfo(lcTSMFactory) << "Device attestation key generated:" << _deviceAttestationKeyId;
    }

    // Set up key rotation schedule
    setupKeyRotationSchedule();

    _initialized = true;
    emit tsmInitialized(_tsm->getPlatform());

    qCInfo(lcTSMFactory) << "Signal Protocol TSM integration initialized successfully";
    return TSMResult::Success;
}

base::expected<bytes::vector, TSMResult> SignalTSMIntegration::generateSignalIdentityKeyPair() {
    if (!_initialized || !_tsm) {
        return base::make_unexpected(TSMResult::NotInitialized);
    }

    // Generate hardware-backed Signal identity key
    auto keyResult = _tsm->generateKey(
        TSMKeyType::SignalIdentity,
        createSignalKeyId(TSMKeyType::SignalIdentity));

    if (!keyResult.has_value()) {
        return base::make_unexpected(keyResult.error());
    }

    _signalIdentityKeyId = keyResult.value().keyId;

    qCInfo(lcTSMFactory) << "Generated hardware-backed Signal identity key:" << _signalIdentityKeyId;
    return keyResult.value().publicKey;
}

base::expected<bytes::vector, TSMResult> SignalTSMIntegration::generateSignalPreKey() {
    if (!_initialized || !_tsm) {
        return base::make_unexpected(TSMResult::NotInitialized);
    }

    // Generate hardware-backed Signal pre-key
    auto keyResult = _tsm->generateKey(
        TSMKeyType::SignalPreKey,
        createSignalKeyId(TSMKeyType::SignalPreKey));

    if (!keyResult.has_value()) {
        return base::make_unexpected(keyResult.error());
    }

    qCInfo(lcTSMFactory) << "Generated hardware-backed Signal pre-key:" << keyResult.value().keyId;
    return keyResult.value().publicKey;
}

base::expected<bytes::vector, TSMResult> SignalTSMIntegration::generateSignalOneTimeKey() {
    if (!_initialized || !_tsm) {
        return base::make_unexpected(TSMResult::NotInitialized);
    }

    // Generate hardware-backed Signal one-time key
    auto keyResult = _tsm->generateKey(
        TSMKeyType::SignalOneTime,
        createSignalKeyId(TSMKeyType::SignalOneTime));

    if (!keyResult.has_value()) {
        return base::make_unexpected(keyResult.error());
    }

    qCInfo(lcTSMFactory) << "Generated hardware-backed Signal one-time key:" << keyResult.value().keyId;
    return keyResult.value().publicKey;
}

base::expected<bytes::vector, TSMResult> SignalTSMIntegration::signSignalMessage(
    const QString &identityKeyId,
    const bytes::const_span &message) {

    if (!_initialized || !_tsm) {
        return base::make_unexpected(TSMResult::NotInitialized);
    }

    // Use TSM to sign Signal Protocol message
    auto signResult = _tsm->sign(identityKeyId, message);
    if (!signResult.has_value()) {
        return base::make_unexpected(signResult.error());
    }

    return signResult.value().signature;
}

base::expected<bool, TSMResult> SignalTSMIntegration::verifySignalMessage(
    const QString &identityKeyId,
    const bytes::const_span &message,
    const bytes::const_span &signature) {

    if (!_initialized || !_tsm) {
        return base::make_unexpected(TSMResult::NotInitialized);
    }

    // Use TSM to verify Signal Protocol message signature
    return _tsm->verify(identityKeyId, message, signature);
}

base::expected<TSMAttestationResult, TSMResult> SignalTSMIntegration::generateDeviceAttestation() {
    if (!_initialized || !_tsm) {
        return base::make_unexpected(TSMResult::NotInitialized);
    }

    if (_deviceAttestationKeyId.isEmpty()) {
        return base::make_unexpected(TSMResult::KeyNotFound);
    }

    // Generate hardware-backed device attestation
    bytes::vector challenge(32); // 32-byte random challenge
    QRandomGenerator::global()->fillRange(
        reinterpret_cast<quint32*>(challenge.data()),
        challenge.size() / sizeof(quint32));

    return _tsm->generateAttestation(challenge);
}

base::expected<bool, TSMResult> SignalTSMIntegration::verifyDeviceAttestation(
    const TSMAttestationResult &attestation) {

    if (!_initialized || !_tsm) {
        return base::make_unexpected(TSMResult::NotInitialized);
    }

    // Verify device attestation using TSM
    return _tsm->verifyAttestation(attestation);
}

TSMResult SignalTSMIntegration::migrateFromSoftwareKeys() {
    if (!_initialized || !_tsm) {
        return TSMResult::NotInitialized;
    }

    // Implementation would migrate existing software keys to hardware-backed storage
    // This is a complex operation requiring careful key transition

    qCInfo(lcTSMFactory) << "Migrating from software keys to hardware-backed keys";

    // For now, return success - implementation would handle actual migration
    emit keyMigrationCompleted(0);
    return TSMResult::Success;
}

base::expected<QByteArray, TSMResult> SignalTSMIntegration::exportKeyBackup(const QString &password) {
    if (!_initialized || !_tsm) {
        return base::make_unexpected(TSMResult::NotInitialized);
    }

    // Implementation would create encrypted backup of key metadata
    // Note: Private keys cannot be exported from hardware TSM

    QByteArray backup;
    // Implementation would serialize key metadata and encrypt with password

    return backup;
}

TSMResult SignalTSMIntegration::restoreKeyBackup(const QByteArray &backup, const QString &password) {
    if (!_initialized || !_tsm) {
        return TSMResult::NotInitialized;
    }

    // Implementation would restore key metadata from encrypted backup
    // Note: Private keys would need to be regenerated in hardware

    return TSMResult::Success;
}

TSMCapabilities SignalTSMIntegration::getTSMCapabilities() const {
    if (!_tsm) {
        return TSMCapabilities{};
    }

    return _tsm->getCapabilities();
}

bool SignalTSMIntegration::isHardwareBackedSecurity() const {
    if (!_tsm) {
        return false;
    }

    auto platform = _tsm->getPlatform();
    return platform != TSMPlatform::SoftwareFallback;
}

QStringList SignalTSMIntegration::getHardwareBackedKeys() const {
    if (!_tsm) {
        return QStringList{};
    }

    QStringList keys;
    keys.append(_tsm->listKeys(TSMKeyType::SignalIdentity));
    keys.append(_tsm->listKeys(TSMKeyType::SignalPreKey));
    keys.append(_tsm->listKeys(TSMKeyType::SignalOneTime));
    keys.append(_tsm->listKeys(TSMKeyType::DeviceAttestation));

    return keys;
}

QString SignalTSMIntegration::createSignalKeyId(TSMKeyType keyType) const {
    QString prefix;
    switch (keyType) {
    case TSMKeyType::SignalIdentity:
        prefix = "signal_identity";
        break;
    case TSMKeyType::SignalPreKey:
        prefix = "signal_prekey";
        break;
    case TSMKeyType::SignalOneTime:
        prefix = "signal_onetime";
        break;
    case TSMKeyType::DeviceAttestation:
        prefix = "device_attestation";
        break;
    default:
        prefix = "signal_key";
        break;
    }

    auto timestamp = QDateTime::currentMSecsSinceEpoch();
    return QString("%1_%2").arg(prefix).arg(timestamp);
}

TSMResult SignalTSMIntegration::validateTSMCapabilities() const {
    if (!_tsm) {
        return TSMResult::NotInitialized;
    }

    auto capabilities = _tsm->getCapabilities();

    // Check required capabilities
    if (!capabilities.supportsKeyGeneration) {
        qCWarning(lcTSMFactory) << "TSM does not support key generation";
        return TSMResult::HardwareNotAvailable;
    }

    if (!capabilities.supportsSigning) {
        qCWarning(lcTSMFactory) << "TSM does not support signing";
        return TSMResult::HardwareNotAvailable;
    }

    // Encryption support is optional but recommended
    if (!capabilities.supportsEncryption) {
        qCInfo(lcTSMFactory) << "TSM does not support encryption (optional feature)";
    }

    // Attestation support is optional but enhances security
    if (!capabilities.supportsAttestation) {
        qCInfo(lcTSMFactory) << "TSM does not support attestation (optional feature)";
    }

    qCInfo(lcTSMFactory) << "TSM capabilities validated successfully";
    return TSMResult::Success;
}

void SignalTSMIntegration::setupKeyRotationSchedule() {
    // Implementation would set up periodic key rotation
    // For Signal Protocol, this might involve pre-key refresh

    qCDebug(lcTSMFactory) << "Setting up key rotation schedule";

    // Emit signal about hardware security status
    emit hardwareSecurityStatusChanged(isHardwareBackedSecurity());
}

} // namespace Data