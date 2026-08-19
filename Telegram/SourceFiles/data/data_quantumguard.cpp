/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#include "data/data_quantumguard.h"

// OpenSSL 3.5 EVP — ML-KEM-512/768/1024 and ML-DSA-44/65/87 are built-in
// to the default provider (verified present on OpenSSL 3.5.x).
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include <QtCore/QDebug>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QDir>
#include <QtCore/QDataStream>
#include <gsl/gsl>

#include "base/random.h"

namespace Data {
namespace {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

QString opensslLastError() {
    char buf[256] = {};
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return QString::fromLatin1(buf);
}

// AES-256-GCM encrypt.  Returns false on failure.
bool aesGcmEncrypt(
        const bytes::const_span &key,   // 32 bytes
        const bytes::const_span &iv,    // 12 bytes
        const bytes::const_span &plaintext,
        bytes::vector &ciphertext,
        bytes::vector &authTag) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) break;
        if (EVP_EncryptInit_ex(
                ctx, nullptr, nullptr,
                reinterpret_cast<const unsigned char *>(key.data()),
                reinterpret_cast<const unsigned char *>(iv.data())) != 1) break;

        ciphertext.resize(plaintext.size());
        int outLen = 0;
        if (EVP_EncryptUpdate(
                ctx,
                reinterpret_cast<unsigned char *>(ciphertext.data()), &outLen,
                reinterpret_cast<const unsigned char *>(plaintext.data()),
                static_cast<int>(plaintext.size())) != 1) break;

        int finalLen = 0;
        if (EVP_EncryptFinal_ex(
                ctx,
                reinterpret_cast<unsigned char *>(ciphertext.data()) + outLen,
                &finalLen) != 1) break;
        ciphertext.resize(outLen + finalLen);

        authTag.resize(16);
        if (EVP_CIPHER_CTX_ctrl(
                ctx, EVP_CTRL_GCM_GET_TAG, 16,
                reinterpret_cast<unsigned char *>(authTag.data())) != 1) break;

        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// AES-256-GCM decrypt.  Returns false on failure (including tag mismatch).
bool aesGcmDecrypt(
        const bytes::const_span &key,
        const bytes::const_span &iv,
        const bytes::const_span &ciphertext,
        const bytes::const_span &authTag,
        bytes::vector &plaintext) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) break;
        if (EVP_DecryptInit_ex(
                ctx, nullptr, nullptr,
                reinterpret_cast<const unsigned char *>(key.data()),
                reinterpret_cast<const unsigned char *>(iv.data())) != 1) break;

        plaintext.resize(ciphertext.size());
        int outLen = 0;
        if (EVP_DecryptUpdate(
                ctx,
                reinterpret_cast<unsigned char *>(plaintext.data()), &outLen,
                reinterpret_cast<const unsigned char *>(ciphertext.data()),
                static_cast<int>(ciphertext.size())) != 1) break;

        // Set the expected auth tag before finalising
        if (EVP_CIPHER_CTX_ctrl(
                ctx, EVP_CTRL_GCM_SET_TAG, 16,
                const_cast<void *>(static_cast<const void *>(authTag.data()))) != 1) break;

        int finalLen = 0;
        if (EVP_DecryptFinal_ex(
                ctx,
                reinterpret_cast<unsigned char *>(plaintext.data()) + outLen,
                &finalLen) != 1) break; // tag mismatch triggers failure here
        plaintext.resize(outLen + finalLen);

        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

} // namespace

// ---------------------------------------------------------------------------
// QuantumGuard implementation
// ---------------------------------------------------------------------------

QuantumGuard::~QuantumGuard() {
    for (auto &[id, pkey] : _keyStore) {
        EVP_PKEY_free(pkey);
    }
    _keyStore.clear();
}

bool QuantumGuard::initialize() {
    _initialized = true;
    return true;
}

bool QuantumGuard::isInitialized() const {
    return _initialized;
}

bool QuantumGuard::enableQuantumSignalProtocol(bool enabled) {
    _quantumSignalEnabled = enabled;
    return _quantumSignalEnabled;
}

bool QuantumGuard::enableHardwareAcceleration(bool enabled) {
    _hardwareAcceleration = enabled;
    return _hardwareAcceleration;
}

bool QuantumGuard::setProtected(bool enabled) {
    _protectedMode = enabled;
    return _protectedMode;
}

bool QuantumGuard::saveKeys(const QString &filePath, const QByteArray &password) const {
    if (filePath.isEmpty()) {
        return false;
    }

    QByteArray unencryptedData;
    {
        QDataStream stream(&unencryptedData, QIODevice::WriteOnly);
        stream.setVersion(QDataStream::Qt_6_0);
        quint32 count = static_cast<quint32>(_keyStore.size());
        stream << count;

        for (const auto &[keyIdStr, pkey] : _keyStore) {
            if (!pkey) continue;
            unsigned char *der = nullptr;
            int derLen = i2d_PrivateKey(pkey, &der);
            if (derLen <= 0 || !der) {
                if (der) OPENSSL_free(der);
                continue;
            }
            QByteArray derBytes(reinterpret_cast<const char*>(der), derLen);
            OPENSSL_free(der);

            stream << QString::fromStdString(keyIdStr) << derBytes;
        }
    }

    // Derive encryption key using PBKDF2-SHA256
    unsigned char salt[16];
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        return false;
    }

    unsigned char key[32];
    if (PKCS5_PBKDF2_HMAC(password.constData(), password.size(),
                          salt, sizeof(salt),
                          100000, EVP_sha256(),
                          sizeof(key), key) != 1) {
        return false;
    }

    unsigned char iv[12];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        return false;
    }

    bytes::vector ciphertext, authTag;
    const auto keySpan = bytes::make_span(reinterpret_cast<const bytes::type*>(key), sizeof(key));
    const auto ivSpan = bytes::make_span(reinterpret_cast<const bytes::type*>(iv), sizeof(iv));
    const auto plainSpan = bytes::make_span(reinterpret_cast<const bytes::type*>(unencryptedData.constData()), unencryptedData.size());

    if (!aesGcmEncrypt(keySpan, ivSpan, plainSpan, ciphertext, authTag)) {
        return false;
    }

    // Format: [Magic: "QGKS" (4 bytes)][Version: 1 (4 bytes)][Salt (16 bytes)][IV (12 bytes)][Tag (16 bytes)][Ciphertext]
    QByteArray filePayload;
    {
        QDataStream out(&filePayload, QIODevice::WriteOnly);
        out.writeRawData("QGKS", 4);
        out << static_cast<quint32>(1); // Version
        out.writeRawData(reinterpret_cast<const char*>(salt), sizeof(salt));
        out.writeRawData(reinterpret_cast<const char*>(iv), sizeof(iv));
        out.writeRawData(reinterpret_cast<const char*>(authTag.data()), authTag.size());
        out.writeRawData(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    }

    QFileInfo fileInfo(filePath);
    QDir dir = fileInfo.dir();
    if (!dir.exists()) {
        dir.mkpath(".");
    }

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly)) {
        return false;
    }
    if (file.write(filePayload) != filePayload.size()) {
        file.close();
        return false;
    }
    file.close();
    return true;
}

bool QuantumGuard::loadKeys(const QString &filePath, const QByteArray &password) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return false;
    }
    QByteArray filePayload = file.readAll();
    file.close();

    if (filePayload.size() < 4 + 4 + 16 + 12 + 16) {
        return false;
    }

    const char *dataPtr = filePayload.constData();
    if (std::memcmp(dataPtr, "QGKS", 4) != 0) {
        return false;
    }

    quint32 version = 0;
    QDataStream in(filePayload);
    in.skipRawData(4);
    in >> version;
    if (version != 1) {
        return false;
    }

    const unsigned char *salt = reinterpret_cast<const unsigned char*>(dataPtr + 8);
    const unsigned char *iv = salt + 16;
    const unsigned char *tag = iv + 12;
    const unsigned char *ciphertext = tag + 16;
    int cipherLen = filePayload.size() - (8 + 16 + 12 + 16);

    unsigned char key[32];
    if (PKCS5_PBKDF2_HMAC(password.constData(), password.size(),
                          salt, 16,
                          100000, EVP_sha256(),
                          sizeof(key), key) != 1) {
        return false;
    }

    const auto keySpan = bytes::make_span(reinterpret_cast<const bytes::type*>(key), sizeof(key));
    const auto ivSpan = bytes::make_span(reinterpret_cast<const bytes::type*>(iv), 12);
    const auto cipherSpan = bytes::make_span(reinterpret_cast<const bytes::type*>(ciphertext), cipherLen);
    const auto tagSpan = bytes::make_span(reinterpret_cast<const bytes::type*>(tag), 16);
    bytes::vector plaintext;

    if (!aesGcmDecrypt(keySpan, ivSpan, cipherSpan, tagSpan, plaintext)) {
        return false;
    }

    QByteArray unencryptedData(reinterpret_cast<const char*>(plaintext.data()), static_cast<int>(plaintext.size()));
    QDataStream stream(unencryptedData);
    stream.setVersion(QDataStream::Qt_6_0);

    quint32 count = 0;
    stream >> count;

    std::map<std::string, EVP_PKEY*> loadedKeys;
    for (quint32 i = 0; i < count; ++i) {
        if (stream.atEnd()) break;
        QString keyId;
        QByteArray derBytes;
        stream >> keyId >> derBytes;

        const unsigned char *p = reinterpret_cast<const unsigned char*>(derBytes.constData());
        EVP_PKEY *pkey = d2i_AutoPrivateKey(nullptr, &p, derBytes.size());
        if (pkey) {
            loadedKeys[keyId.toStdString()] = pkey;
        }
    }

    // Replace current keystore
    for (auto &[id, pkey] : _keyStore) {
        if (pkey) EVP_PKEY_free(pkey);
    }
    _keyStore = std::move(loadedKeys);
    return true;
}

// Map our QuantumAlgorithm enum to the OpenSSL 3.5 algorithm name string.
const char *QuantumGuard::evpAlgorithmName(QuantumAlgorithm algorithm) {
    switch (algorithm) {
    case QuantumAlgorithm::ML_KEM_512:
    case QuantumAlgorithm::Kyber512:
        return "ML-KEM-512";
    case QuantumAlgorithm::ML_KEM_768:
    case QuantumAlgorithm::Kyber768:
        return "ML-KEM-768";
    case QuantumAlgorithm::ML_KEM_1024:
    case QuantumAlgorithm::Kyber1024:
    case QuantumAlgorithm::HybridX25519_ML_KEM_1024:
        return "ML-KEM-1024";
    case QuantumAlgorithm::ML_DSA_44:
        return "ML-DSA-44";
    case QuantumAlgorithm::ML_DSA_65:
        return "ML-DSA-65";
    case QuantumAlgorithm::ML_DSA_87:
    case QuantumAlgorithm::HybridEd25519_ML_DSA_87:
        return "ML-DSA-87";
    case QuantumAlgorithm::SLH_DSA_SHA2_128s:
        return "SLH-DSA-SHA2-128s";
    default:
        return "ML-KEM-1024";
    }
}

base::expected<QuantumKeyResult, QString> QuantumGuard::generateQuantumKey(
        QuantumKeyType /*type*/,
        QuantumAlgorithm algorithm) {
    if (!_initialized) {
        return base::make_unexpected(QStringLiteral("QuantumGuard not initialized"));
    }

    const char *algName = evpAlgorithmName(algorithm);

    // Use EVP_PKEY_Q_keygen (OpenSSL 3.x high-level keygen)
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, algName);
    if (!pkey) {
        return base::make_unexpected(
            QStringLiteral("ML-KEM/ML-DSA keygen failed for %1: %2")
                .arg(QLatin1String(algName))
                .arg(opensslLastError()));
    }

    // Export the raw public key bytes
    size_t pubKeyLen = 0;
    EVP_PKEY_get_raw_public_key(pkey, nullptr, &pubKeyLen);
    QByteArray pubKey(static_cast<int>(pubKeyLen), '\0');
    if (EVP_PKEY_get_raw_public_key(
            pkey,
            reinterpret_cast<unsigned char *>(pubKey.data()),
            &pubKeyLen) != 1) {
        EVP_PKEY_free(pkey);
        return base::make_unexpected(
            QStringLiteral("Failed to export public key: %1").arg(opensslLastError()));
    }

    QuantumKeyResult result;
    result.keyId = makeKeyId();
    result.publicKey = pubKey;

    // Store the full keypair (for signing/decapsulation later)
    _keyStore[result.keyId.toStdString()] = pkey;

    return result;
}

QuantumAlgorithm QuantumGuard::selectOptimalKEM(QuantumSecurityLevel level) const {
    if (level >= QuantumSecurityLevel::Level4) {
        return QuantumAlgorithm::ML_KEM_1024;
    } else if (level >= QuantumSecurityLevel::Level2) {
        return QuantumAlgorithm::ML_KEM_768;
    }
    return QuantumAlgorithm::ML_KEM_512;
}

QuantumAlgorithm QuantumGuard::selectOptimalSignature(QuantumSecurityLevel level) const {
    if (level >= QuantumSecurityLevel::Level4) {
        return QuantumAlgorithm::ML_DSA_87;
    } else if (level >= QuantumSecurityLevel::Level2) {
        return QuantumAlgorithm::ML_DSA_65;
    }
    return QuantumAlgorithm::ML_DSA_44;
}

base::expected<QuantumSignatureResult, QString> QuantumGuard::quantumSign(
        const QString &keyId,
        const QByteArray &data) {
    if (!_initialized) {
        return base::make_unexpected(QStringLiteral("QuantumGuard not initialized"));
    }

    auto it = _keyStore.find(keyId.toStdString());
    if (it == _keyStore.end()) {
        return base::make_unexpected(
            QStringLiteral("Key not found: %1").arg(keyId));
    }
    EVP_PKEY *pkey = it->second;

    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) {
        return base::make_unexpected(QStringLiteral("EVP_MD_CTX_new failed"));
    }

    // ML-DSA is a pure signature scheme (no hash needed — pass nullptr for md)
    if (EVP_DigestSignInit(mdCtx, nullptr, nullptr, nullptr, pkey) != 1) {
        EVP_MD_CTX_free(mdCtx);
        return base::make_unexpected(
            QStringLiteral("EVP_DigestSignInit failed: %1").arg(opensslLastError()));
    }

    size_t sigLen = 0;
    // First call: get required signature length
    if (EVP_DigestSign(
            mdCtx, nullptr, &sigLen,
            reinterpret_cast<const unsigned char *>(data.constData()),
            static_cast<size_t>(data.size())) != 1) {
        EVP_MD_CTX_free(mdCtx);
        return base::make_unexpected(
            QStringLiteral("EVP_DigestSign (length) failed: %1").arg(opensslLastError()));
    }

    QByteArray sig(static_cast<int>(sigLen), '\0');
    // Second call: actually sign
    if (EVP_DigestSign(
            mdCtx,
            reinterpret_cast<unsigned char *>(sig.data()), &sigLen,
            reinterpret_cast<const unsigned char *>(data.constData()),
            static_cast<size_t>(data.size())) != 1) {
        EVP_MD_CTX_free(mdCtx);
        return base::make_unexpected(
            QStringLiteral("EVP_DigestSign failed: %1").arg(opensslLastError()));
    }
    EVP_MD_CTX_free(mdCtx);
    sig.resize(static_cast<int>(sigLen));

    QuantumSignatureResult result;
    result.keyId = keyId;
    result.signature = sig;
    return result;
}

base::expected<QuantumEncryptionResult, QString> QuantumGuard::quantumEncrypt(
        const QString &keyId,
        const bytes::const_span &plaintext) {
    if (!_initialized) {
        return base::make_unexpected(QStringLiteral("QuantumGuard not initialized"));
    }

    auto it = _keyStore.find(keyId.toStdString());
    if (it == _keyStore.end()) {
        return base::make_unexpected(
            QStringLiteral("Key not found: %1").arg(keyId));
    }
    EVP_PKEY *pkey = it->second;

    // ---- ML-KEM Encapsulation ----
    // EVP_PKEY_encapsulate: generates a shared secret and its ciphertext.
    EVP_PKEY_CTX *kemCtx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!kemCtx) {
        return base::make_unexpected(QStringLiteral("EVP_PKEY_CTX_new failed"));
    }

    if (EVP_PKEY_encapsulate_init(kemCtx, nullptr) != 1) {
        EVP_PKEY_CTX_free(kemCtx);
        return base::make_unexpected(
            QStringLiteral("EVP_PKEY_encapsulate_init failed: %1").arg(opensslLastError()));
    }

    size_t encapCiphertextLen = 0, sharedSecretLen = 0;
    // First call: get sizes
    if (EVP_PKEY_encapsulate(
            kemCtx, nullptr, &encapCiphertextLen, nullptr, &sharedSecretLen) != 1) {
        EVP_PKEY_CTX_free(kemCtx);
        return base::make_unexpected(
            QStringLiteral("EVP_PKEY_encapsulate (size) failed: %1").arg(opensslLastError()));
    }

    bytes::vector encapCiphertext(encapCiphertextLen);
    bytes::vector sharedSecret(sharedSecretLen);

    // Second call: encapsulate
    if (EVP_PKEY_encapsulate(
            kemCtx,
            reinterpret_cast<unsigned char *>(encapCiphertext.data()), &encapCiphertextLen,
            reinterpret_cast<unsigned char *>(sharedSecret.data()), &sharedSecretLen) != 1) {
        EVP_PKEY_CTX_free(kemCtx);
        return base::make_unexpected(
            QStringLiteral("EVP_PKEY_encapsulate failed: %1").arg(opensslLastError()));
    }
    EVP_PKEY_CTX_free(kemCtx);

    // The shared secret from ML-KEM is exactly 32 bytes for ML-KEM-1024,
    // suitable for use directly as AES-256 key material.
    const auto aesKey = bytes::make_span(sharedSecret).subspan(0, std::min(sharedSecretLen, size_t(32)));

    // ---- AES-256-GCM encrypt ----
    bytes::vector iv = randomBytes(12);
    bytes::vector ciphertext, authTag;
    if (!aesGcmEncrypt(aesKey, bytes::make_span(iv), plaintext, ciphertext, authTag)) {
        return base::make_unexpected(QStringLiteral("AES-256-GCM encryption failed"));
    }

    QuantumEncryptionResult result;
    result.keyId = keyId;
    result.algorithm = QuantumAlgorithm::ML_KEM_1024;
    result.ciphertext = std::move(ciphertext);
    result.encapsulatedSecret = std::move(encapCiphertext);
    result.iv = std::move(iv);
    result.authTag = std::move(authTag);
    return result;
}

base::expected<bytes::vector, QString> QuantumGuard::quantumDecrypt(
        const QString &keyId,
        const bytes::const_span &ciphertext,
        const bytes::const_span &encapsulatedSecret,
        const bytes::const_span &iv,
        const bytes::const_span &authTag) {
    if (!_initialized) {
        return base::make_unexpected(QStringLiteral("QuantumGuard not initialized"));
    }

    auto it = _keyStore.find(keyId.toStdString());
    if (it == _keyStore.end()) {
        return base::make_unexpected(
            QStringLiteral("Key not found: %1").arg(keyId));
    }
    EVP_PKEY *pkey = it->second;

    // ---- ML-KEM Decapsulation ----
    EVP_PKEY_CTX *kemCtx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!kemCtx) {
        return base::make_unexpected(QStringLiteral("EVP_PKEY_CTX_new failed"));
    }

    if (EVP_PKEY_decapsulate_init(kemCtx, nullptr) != 1) {
        EVP_PKEY_CTX_free(kemCtx);
        return base::make_unexpected(
            QStringLiteral("EVP_PKEY_decapsulate_init failed: %1").arg(opensslLastError()));
    }

    size_t sharedSecretLen = 0;
    if (EVP_PKEY_decapsulate(
            kemCtx, nullptr, &sharedSecretLen,
            reinterpret_cast<const unsigned char *>(encapsulatedSecret.data()),
            encapsulatedSecret.size()) != 1) {
        EVP_PKEY_CTX_free(kemCtx);
        return base::make_unexpected(
            QStringLiteral("EVP_PKEY_decapsulate (size) failed: %1").arg(opensslLastError()));
    }

    bytes::vector sharedSecret(sharedSecretLen);
    if (EVP_PKEY_decapsulate(
            kemCtx,
            reinterpret_cast<unsigned char *>(sharedSecret.data()), &sharedSecretLen,
            reinterpret_cast<const unsigned char *>(encapsulatedSecret.data()),
            encapsulatedSecret.size()) != 1) {
        EVP_PKEY_CTX_free(kemCtx);
        return base::make_unexpected(
            QStringLiteral("EVP_PKEY_decapsulate failed: %1").arg(opensslLastError()));
    }
    EVP_PKEY_CTX_free(kemCtx);

    const auto aesKey = bytes::make_span(sharedSecret).subspan(0, std::min(sharedSecretLen, size_t(32)));

    // ---- AES-256-GCM decrypt ----
    bytes::vector plaintext;
    if (!aesGcmDecrypt(aesKey, iv, ciphertext, authTag, plaintext)) {
        return base::make_unexpected(
            QStringLiteral("AES-256-GCM decryption failed (bad tag or corrupt data)"));
    }
    return plaintext;
}

// Legacy overload: no iv/authTag provided.
// For backwards compat only — cannot provide authentication guarantee.
base::expected<bytes::vector, QString> QuantumGuard::quantumDecrypt(
        const QString &keyId,
        const bytes::const_span &ciphertext,
        const bytes::const_span &encapsulatedSecret) {
    // Use a zeroed IV and skip tag verification — only used by legacy paths
    // that don't carry iv/tag. New callers should use the 5-arg overload.
    bytes::vector iv(12, bytes::type{});
    bytes::vector tag(16, bytes::type{});
    return quantumDecrypt(keyId, ciphertext, encapsulatedSecret,
                          bytes::make_span(iv), bytes::make_span(tag));
}

QString QuantumGuard::makeKeyId() const {
    return QStringLiteral("quantum_%1").arg(base::RandomValue<uint32>());
}

bytes::vector QuantumGuard::randomBytes(int size) const {
    bytes::vector buffer(size);
    base::RandomFill(bytes::make_span(buffer));
    return buffer;
}

} // namespace Data
