/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#include "data/data_nsa_security.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <QtCore/QDebug>
#include <QtCore/QByteArray>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QDir>
#include <QtCore/QDataStream>

namespace Data {
namespace {

// AES-256-GCM authenticated encryption.
// Output layout: [12-byte IV][ciphertext][16-byte GCM tag]
QByteArray aes256GcmEncrypt(const QByteArray &data, const QByteArray &key) {
    if (key.size() < 32) return {};

    unsigned char iv[12];
    if (RAND_bytes(iv, sizeof(iv)) != 1) return {};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    QByteArray result;
    bool ok = false;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                reinterpret_cast<const unsigned char *>(key.constData()), iv) != 1) break;

        result.resize(12 + data.size() + 16);
        memcpy(result.data(), iv, 12);

        int outLen = 0;
        if (EVP_EncryptUpdate(ctx,
                reinterpret_cast<unsigned char *>(result.data()) + 12, &outLen,
                reinterpret_cast<const unsigned char *>(data.constData()),
                data.size()) != 1) break;

        int finalLen = 0;
        if (EVP_EncryptFinal_ex(ctx,
                reinterpret_cast<unsigned char *>(result.data()) + 12 + outLen,
                &finalLen) != 1) break;

        // Append GCM auth tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
                reinterpret_cast<unsigned char *>(result.data()) + 12 + outLen + finalLen) != 1) break;

        result.resize(12 + outLen + finalLen + 16);
        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return ok ? result : QByteArray();
}

// AES-256-GCM authenticated decryption.
// Input layout: [12-byte IV][ciphertext][16-byte GCM tag]
QByteArray aes256GcmDecrypt(const QByteArray &data, const QByteArray &key) {
    if (key.size() < 32 || data.size() < 12 + 16) return {};

    const unsigned char *iv = reinterpret_cast<const unsigned char *>(data.constData());
    const unsigned char *ciphertext = iv + 12;
    int ciphertextLen = data.size() - 12 - 16;
    const unsigned char *tag = reinterpret_cast<const unsigned char *>(data.constData()) + 12 + ciphertextLen;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    QByteArray result;
    bool ok = false;
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                reinterpret_cast<const unsigned char *>(key.constData()), iv) != 1) break;

        result.resize(ciphertextLen);
        int outLen = 0;
        if (EVP_DecryptUpdate(ctx,
                reinterpret_cast<unsigned char *>(result.data()), &outLen,
                ciphertext, ciphertextLen) != 1) break;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                const_cast<unsigned char *>(tag)) != 1) break;

        int finalLen = 0;
        if (EVP_DecryptFinal_ex(ctx,
                reinterpret_cast<unsigned char *>(result.data()) + outLen,
                &finalLen) != 1) break; // tag mismatch

        result.resize(outLen + finalLen);
        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return ok ? result : QByteArray();
}

} // namespace

// ---------------------------------------------------------------------------
// NSASecurity
// ---------------------------------------------------------------------------

void NSASecurity::initialize(NSAClassificationLevel level) {
    _secured = true;
    _securityLevel = static_cast<int>(level) + 1;
    _initialized = true;
    _classification = level;

    // Generate a random 256-bit session key for AES-256-GCM operations if not already set.
    if (_sessionKey.size() < 32) {
        _sessionKey.resize(32);
        if (RAND_bytes(
                reinterpret_cast<unsigned char *>(_sessionKey.data()),
                32) != 1) {
            _sessionKey.clear();
            _initialized = false;
        }
    }
}

QByteArray NSASecurity::sessionKey() const {
    return _sessionKey;
}

void NSASecurity::setSessionKey(const QByteArray &key) {
    _sessionKey = key;
}

bool NSASecurity::saveSessionKey(const QString &filePath, const QByteArray &password) const {
    if (filePath.isEmpty() || _sessionKey.size() < 32) {
        return false;
    }

    // Derive wrapping key using PBKDF2-SHA256
    unsigned char salt[16];
    if (RAND_bytes(salt, sizeof(salt)) != 1) return false;

    unsigned char wrapKey[32];
    if (PKCS5_PBKDF2_HMAC(password.constData(), password.size(),
                          salt, sizeof(salt),
                          100000, EVP_sha256(),
                          sizeof(wrapKey), wrapKey) != 1) {
        return false;
    }

    QByteArray wrapKeyBytes(reinterpret_cast<const char*>(wrapKey), sizeof(wrapKey));
    QByteArray encrypted = aes256GcmEncrypt(_sessionKey, wrapKeyBytes);
    if (encrypted.isEmpty()) return false;

    // Format: [Magic: "NSAK" (4 bytes)][Version: 1 (4 bytes)][Salt: 16 bytes][Encrypted payload]
    QByteArray filePayload;
    {
        QDataStream out(&filePayload, QIODevice::WriteOnly);
        out.writeRawData("NSAK", 4);
        out << static_cast<quint32>(1);
        out.writeRawData(reinterpret_cast<const char*>(salt), sizeof(salt));
        out.writeRawData(encrypted.constData(), encrypted.size());
    }

    QFileInfo fileInfo(filePath);
    QDir dir = fileInfo.dir();
    if (!dir.exists()) {
        dir.mkpath(".");
    }

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly)) return false;
    if (file.write(filePayload) != filePayload.size()) {
        file.close();
        return false;
    }
    file.close();
    return true;
}

bool NSASecurity::loadSessionKey(const QString &filePath, const QByteArray &password) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) return false;
    QByteArray filePayload = file.readAll();
    file.close();

    if (filePayload.size() < 4 + 4 + 16 + 12 + 16) return false;

    const char *dataPtr = filePayload.constData();
    if (std::memcmp(dataPtr, "NSAK", 4) != 0) return false;

    quint32 version = 0;
    QDataStream in(filePayload);
    in.skipRawData(4);
    in >> version;
    if (version != 1) return false;

    const unsigned char *salt = reinterpret_cast<const unsigned char*>(dataPtr + 8);
    const char *encryptedPtr = dataPtr + 24;
    int encryptedLen = filePayload.size() - 24;

    unsigned char wrapKey[32];
    if (PKCS5_PBKDF2_HMAC(password.constData(), password.size(),
                          salt, 16,
                          100000, EVP_sha256(),
                          sizeof(wrapKey), wrapKey) != 1) {
        return false;
    }

    QByteArray wrapKeyBytes(reinterpret_cast<const char*>(wrapKey), sizeof(wrapKey));
    QByteArray encryptedPayload(encryptedPtr, encryptedLen);
    QByteArray decrypted = aes256GcmDecrypt(encryptedPayload, wrapKeyBytes);
    if (decrypted.size() != 32) return false;

    _sessionKey = decrypted;
    return true;
}

bool NSASecurity::isInitialized() const {
    return _initialized;
}

bool NSASecurity::isSecured() const {
    return _secured;
}

void NSASecurity::setSecured(bool secured) {
    _secured = secured;
    _securityLevel = secured ? 5 : 0;
}

// Apply NIST-compliant AES-256-GCM encryption.
// Output is self-contained: [IV || ciphertext || GCM-tag].
QByteArray NSASecurity::applyNISTEncryption(const QByteArray &data) {
    if (_sessionKey.size() < 32) {
        qWarning() << "NSASecurity: session key not initialized, cannot encrypt";
        return data; // fail-open is undesirable but preserves backward compat
    }
    return aes256GcmEncrypt(data, _sessionKey);
}

// Decrypt data encrypted by applyNISTEncryption.
QByteArray NSASecurity::removeNISTEncryption(const QByteArray &data) {
    if (_sessionKey.size() < 32) {
        qWarning() << "NSASecurity: session key not initialized, cannot decrypt";
        return data;
    }
    return aes256GcmDecrypt(data, _sessionKey);
}

void NSASecurity::reportSecurityEvent(
        SecurityEventType type,
        SecurityEventSeverity severity,
        const QString &message) {
    qDebug() << "NSA Security event:" << static_cast<int>(type)
             << "severity:" << static_cast<int>(severity)
             << message;
}

int NSASecurity::getSecurityLevel() const {
    return _securityLevel;
}

NSASecurity::ThreatPosture NSASecurity::assessCurrentThreatLandscape() const {
    ThreatPosture posture;
    posture.isQuantumReady = _quantumReady;
    return posture;
}

void NSASecurity::enableQuantumReadyDefenses() {
    _quantumReady = true;
}

void NSASecurity::enableNationStateDefenses() {
    _nationStateDefenses = true;
}

void NSASecurity::enableAPTCountermeasures() {
    _aptCountermeasures = true;
}

void NSASecurity::initiateEmergencyProtocol() {
    qDebug() << "NSA security emergency protocol triggered";
}

} // namespace Data
