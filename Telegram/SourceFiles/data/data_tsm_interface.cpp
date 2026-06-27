/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#include "data/data_tsm_interface.h"

#include "base/bytes.h"
#include "base/random.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <QtCore/QByteArray>
#include <QtCore/QDateTime>
#include <QtCore/QCryptographicHash>
#include <unordered_map>
#include <vector>

namespace Data {
namespace {

constexpr auto kTSMDefaultKeySize = 32;
constexpr auto kTSMIVSize = 12;
constexpr auto kTSMAuthTagSize = 16;

int keySizeForType(TSMKeyType type) {
    switch (type) {
        case TSMKeyType::SignalIdentity:
        case TSMKeyType::SignalPreKey:
        case TSMKeyType::SignalOneTime:
        case TSMKeyType::DeviceAttestation:
        case TSMKeyType::CustomEncryption:
        case TSMKeyType::AES256:
            return kTSMDefaultKeySize;
    }
    return kTSMDefaultKeySize;
}

struct KeyEntry {
    TSMKeyInfo info;
    bytes::vector rawKey;
};

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

bytes::vector randomBytes(int size) {
    bytes::vector result(size);
    RAND_bytes(asUChar(result), size);
    return result;
}

QString makeKeyId() {
    bytes::vector randomData(16);
    base::RandomFill(bytes::make_span(randomData));
    const QByteArray raw(
        reinterpret_cast<const char*>(randomData.data()),
        randomData.size());
    const auto hash = QCryptographicHash::hash(raw, QCryptographicHash::Sha256);
    return QString::fromLatin1(hash.toHex());
}

bool aesGcmEncrypt(
        const bytes::const_span &key,
        const bytes::const_span &plaintext,
        const bytes::const_span &ad,
        bytes::vector &ciphertext,
        bytes::vector &iv,
        bytes::vector &authTag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    iv = randomBytes(kTSMIVSize);
    ciphertext.resize(plaintext.size());
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, asConstUChar(key), asConstUChar(iv)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (!ad.empty()) {
        int len = 0;
        EVP_EncryptUpdate(ctx, nullptr, &len, asConstUChar(ad), ad.size());
    }
    int outLen = 0;
    EVP_EncryptUpdate(
        ctx,
        asUChar(ciphertext),
        &outLen,
        asConstUChar(plaintext),
        plaintext.size());
    int flushLen = 0;
    EVP_EncryptFinal_ex(ctx, asUChar(ciphertext) + outLen, &flushLen);
    ciphertext.resize(outLen + flushLen);
    authTag.resize(kTSMAuthTagSize);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, authTag.size(), reinterpret_cast<void*>(authTag.data()));
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aesGcmDecrypt(
        const bytes::const_span &key,
        const bytes::const_span &ciphertext,
        const bytes::const_span &iv,
        const bytes::const_span &authTag,
        const bytes::const_span &ad,
        bytes::vector &plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_DecryptInit_ex(
            ctx,
            nullptr,
            nullptr,
            asConstUChar(key),
            asConstUChar(iv)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (!ad.empty()) {
        int len = 0;
        EVP_DecryptUpdate(ctx, nullptr, &len, asConstUChar(ad), ad.size());
    }
    plaintext.resize(ciphertext.size());
    int outLen = 0;
    if (EVP_DecryptUpdate(
            ctx,
            asUChar(plaintext),
            &outLen,
            asConstUChar(ciphertext),
            ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_GCM_SET_TAG,
                authTag.size(),
                const_cast<void*>(reinterpret_cast<const void*>(authTag.data()))) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int len = 0;
    if (EVP_DecryptFinal_ex(ctx, asUChar(plaintext) + outLen, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext.resize(outLen + len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bytes::vector hmacSha256(
        const bytes::const_span &key,
        const bytes::const_span &data) {
    bytes::vector result(EVP_MAX_MD_SIZE);
    unsigned int len = 0;
    HMAC(
        EVP_sha256(),
        asConstUChar(key),
        key.size(),
        asConstUChar(data),
        data.size(),
        asUChar(result),
        &len);
    result.resize(len);
    return result;
}

} // namespace

TSMInterface::TSMInterface(QObject *parent)
    : QObject(parent) {
}

class SoftwareTSM final : public TSMInterface {

public:
    SoftwareTSM(QObject *parent = nullptr)
        : TSMInterface(parent)
        , _platform(TSMPlatform::SoftwareFallback) {
    }

    TSMResult initialize() override {
        _initialized = true;
        _capabilities.platform = _platform;
        _capabilities.supportsKeyGeneration = true;
        _capabilities.supportsEncryption = true;
        _capabilities.supportsSigning = true;
        _capabilities.supportsAttestation = false;
        _capabilities.supportsSecureStorage = false;
        _capabilities.supportedAlgorithms = {"AES-256-GCM", "HMAC-SHA256"};
        return TSMResult::Success;
    }

    bool isInitialized() const override {
        return _initialized;
    }

    TSMCapabilities getCapabilities() const override {
        return _capabilities;
    }

    TSMPlatform getPlatform() const override {
        return _platform;
    }

    base::expected<TSMKeyInfo, TSMResult> generateKey(
            TSMKeyType type,
            const QString &keyId) override {
        if (!_initialized) {
            return base::make_unexpected(TSMResult::NotInitialized);
        }
        const auto actualKeyId = keyId.isEmpty() ? makeKeyId() : keyId;
        const auto size = keySizeForType(type);
        const auto keyBytes = randomBytes(size);
        TSMKeyInfo info;
        info.keyId = actualKeyId;
        info.keyType = type;
        info.publicKey = bytes::vector(size);
        info.created = QDateTime::currentDateTimeUtc();
        info.isHardwareBacked = false;
        info.algorithmInfo = (type == TSMKeyType::CustomEncryption)
            ? "AES-256-GCM" : "X25519";

        _keys[actualKeyId] = KeyEntry{info, keyBytes};
        return info;
    }

    base::expected<TSMKeyInfo, TSMResult> getKeyInfo(const QString &keyId) override {
        auto it = _keys.find(keyId);
        if (it == _keys.end()) {
            return base::make_unexpected(TSMResult::KeyNotFound);
        }
        return it->second.info;
    }

    TSMResult deleteKey(const QString &keyId) override {
        if (_keys.erase(keyId) == 0) {
            return TSMResult::KeyNotFound;
        }
        return TSMResult::Success;
    }

    QStringList listKeys(TSMKeyType type) override {
        QStringList result;
        for (const auto &entry : _keys) {
            if (entry.second.info.keyType == type) {
                result.append(entry.first);
            }
        }
        return result;
    }

    base::expected<TSMEncryptionResult, TSMResult> encrypt(
            const QString &keyId,
            const bytes::const_span &plaintext,
            const bytes::const_span &additionalData) override {
        auto it = _keys.find(keyId);
        if (it == _keys.end()) {
            return base::make_unexpected(TSMResult::KeyNotFound);
        }
        bytes::vector ciphertext;
        bytes::vector iv;
        bytes::vector authTag;
        if (!aesGcmEncrypt(it->second.rawKey, plaintext, additionalData, ciphertext, iv, authTag)) {
            return base::make_unexpected(TSMResult::EncryptionFailed);
        }
        TSMEncryptionResult result;
        result.ciphertext = std::move(ciphertext);
        result.iv = std::move(iv);
        result.authTag = std::move(authTag);
        result.keyId = keyId;
        return result;
    }

    base::expected<bytes::vector, TSMResult> decrypt(
            const QString &keyId,
            const bytes::const_span &ciphertext,
            const bytes::const_span &iv,
            const bytes::const_span &authTag,
            const bytes::const_span &additionalData) override {
        auto it = _keys.find(keyId);
        if (it == _keys.end()) {
            return base::make_unexpected(TSMResult::KeyNotFound);
        }
        bytes::vector plaintext;
        if (!aesGcmDecrypt(it->second.rawKey, ciphertext, iv, authTag, additionalData, plaintext)) {
            return base::make_unexpected(TSMResult::DecryptionFailed);
        }
        return plaintext;
    }

    base::expected<TSMSignatureResult, TSMResult> sign(
            const QString &keyId,
            const bytes::const_span &data) override {
        auto it = _keys.find(keyId);
        if (it == _keys.end()) {
            return base::make_unexpected(TSMResult::KeyNotFound);
        }
        TSMSignatureResult result;
        result.keyId = keyId;
        result.algorithm = "HMAC-SHA256";
        result.signature = hmacSha256(it->second.rawKey, data);
        return result;
    }

    base::expected<bool, TSMResult> verify(
            const QString &keyId,
            const bytes::const_span &data,
            const bytes::const_span &signature) override {
        auto it = _keys.find(keyId);
        if (it == _keys.end()) {
            return base::make_unexpected(TSMResult::KeyNotFound);
        }
        auto expected = hmacSha256(it->second.rawKey, data);
        return bytes::vector(signature.begin(), signature.end()) == expected;
    }

    TSMResult sealData(const bytes::const_span &data) override {
        _sealedData.emplace_back(bytes::vector(data.begin(), data.end()));
        return TSMResult::Success;
    }

    base::expected<TSMAttestationResult, TSMResult> generateAttestation(
            const bytes::const_span &challenge) override {
        TSMAttestationResult result;
        result.timestamp = QDateTime::currentDateTimeUtc();
        result.platformInfo = "SoftwareTSM";
        result.attestationData = randomBytes(32);
        result.signature = hmacSha256(result.attestationData, challenge);
        return result;
    }

    base::expected<bool, TSMResult> verifyAttestation(
            const TSMAttestationResult &attestation,
            const bytes::const_span &challenge) override {
        auto expected = hmacSha256(attestation.attestationData, challenge);
        return expected == attestation.signature;
    }

    base::expected<bytes::vector, TSMResult> deriveKey(
            const QString &baseKeyId,
            const QString &derivationInfo,
            size_t outputLength) override {
        auto it = _keys.find(baseKeyId);
        if (it == _keys.end()) {
            return base::make_unexpected(TSMResult::KeyNotFound);
        }
        const auto data = derivationInfo.toUtf8();
        const auto dataSpan = bytes::const_span(
            reinterpret_cast<const gsl::byte *>(data.constData()),
            data.size());
        auto derived = hmacSha256(it->second.rawKey, dataSpan);
        if (outputLength == 0 || outputLength >= derived.size()) {
            return derived;
        }
        return bytes::vector(derived.begin(), derived.begin() + outputLength);
    }

    base::expected<bytes::vector, TSMResult> generateSecureRandom(
            size_t length) override {
        bytes::vector result(length);
        if (length && RAND_bytes(asUChar(result), length) != 1) {
            return base::make_unexpected(TSMResult::HardwareNotAvailable);
        }
        return result;
    }

private:
    bool _initialized = false;
    TSMCapabilities _capabilities;
    TSMPlatform _platform = TSMPlatform::SoftwareFallback;
    std::unordered_map<QString, KeyEntry> _keys;
    std::vector<bytes::vector> _sealedData;
};

std::unique_ptr<TSMInterface> createSoftwareTSM() {
    return std::make_unique<SoftwareTSM>();
}

} // namespace Data

namespace Data {
SignalTSMIntegration::~SignalTSMIntegration() {}
SignalTSMIntegration::SignalTSMIntegration(not_null<Session*> session) : QObject(nullptr), _session(session) {}
TSMResult SignalTSMIntegration::initializeWithSignalProtocol() { return TSMResult::Success; }
bool SignalTSMIntegration::isHardwareBackedSecurity() const { return false; }
base::expected<bytes::vector, TSMResult> SignalTSMIntegration::generateSignalIdentityKeyPair() { return base::make_unexpected(TSMResult::HardwareNotAvailable); }
TSMCapabilities SignalTSMIntegration::getTSMCapabilities() const { return {}; }

QString TSMInterface::generateUniqueKeyId() const { return QString(); }
bool TSMInterface::validateKeyId(const QString &) const { return false; }
TSMResult TSMInterface::mapPlatformError(int e) const { return TSMResult::UnknownError; }
}
