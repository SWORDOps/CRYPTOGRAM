/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "data/enhanced_privacy_crypto.h"

#include "base/random.h"

#include <QtCore/QCryptographicHash>

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace EnhancedPrivacyCrypto {
namespace {

constexpr int kIvSize = 12; // Standard 12-byte IV for AES-256-GCM
constexpr int kTagSize = 16; // AES-GCM authentication tag size
constexpr int kKeySize = 32; // AES-256 key size
const QString kFormatPrefix = QStringLiteral("CR2:");

// Fill a buffer from the OpenSSL CSPRNG, falling back to base::RandomValue.
void FillRandom(char *data, int size) {
    if (RAND_bytes(reinterpret_cast<unsigned char*>(data), size) != 1) {
        for (int i = 0; i < size; ++i) {
            data[i] = static_cast<char>(base::RandomValue<uchar>());
        }
    }
}

// Encrypt plaintext with AES-256-GCM, returning the ciphertext with the
// authentication tag appended. Returns an empty array on failure.
QByteArray AesGcmEncrypt(
        const QByteArray &key,
        const QByteArray &iv,
        const QByteArray &plaintext) {
    QByteArray ciphertext(plaintext.size(), 0);
    unsigned char tag[kTagSize] = {0};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return QByteArray();
    }

    int len = 0;
    int ciphertextLen = 0;
    bool ok = true;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        ok = false;
    }
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1) {
        ok = false;
    }
    if (ok && EVP_EncryptInit_ex(ctx, nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(key.constData()),
            reinterpret_cast<const unsigned char*>(iv.constData())) != 1) {
        ok = false;
    }
    if (ok && !plaintext.isEmpty() && EVP_EncryptUpdate(ctx,
            reinterpret_cast<unsigned char*>(ciphertext.data()),
            &len,
            reinterpret_cast<const unsigned char*>(plaintext.constData()),
            plaintext.size()) != 1) {
        ok = false;
    }
    ciphertextLen = len;

    if (ok && EVP_EncryptFinal_ex(ctx,
            reinterpret_cast<unsigned char*>(ciphertext.data()) + ciphertextLen,
            &len) != 1) {
        ok = false;
    }
    ciphertextLen += len;

    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagSize, tag) != 1) {
        ok = false;
    }

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        return QByteArray();
    }

    ciphertext.resize(ciphertextLen);

    // GCM is a stream cipher: ciphertext and plaintext share the same length,
    // and an empty plaintext still yields the authentication tag.
    return ciphertext + QByteArray(reinterpret_cast<const char*>(tag), kTagSize);
}

// Decrypt AES-256-GCM ciphertext with an appended authentication tag.
// Returns an empty array on failure (including tag mismatch).
QByteArray AesGcmDecrypt(
        const QByteArray &key,
        const QByteArray &iv,
        const QByteArray &ciphertext,
        const QByteArray &tag) {
    QByteArray decrypted(ciphertext.size(), 0);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return QByteArray();
    }

    int len = 0;
    int plaintextLen = 0;
    bool ok = true;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        ok = false;
    }
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1) {
        ok = false;
    }
    if (ok && EVP_DecryptInit_ex(ctx, nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(key.constData()),
            reinterpret_cast<const unsigned char*>(iv.constData())) != 1) {
        ok = false;
    }
    if (ok && !ciphertext.isEmpty() && EVP_DecryptUpdate(ctx,
            reinterpret_cast<unsigned char*>(decrypted.data()),
            &len,
            reinterpret_cast<const unsigned char*>(ciphertext.constData()),
            ciphertext.size()) != 1) {
        ok = false;
    }
    plaintextLen = len;

    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(),
            const_cast<char*>(tag.constData())) != 1) {
        ok = false;
    }

    if (ok && EVP_DecryptFinal_ex(ctx,
            reinterpret_cast<unsigned char*>(decrypted.data()) + plaintextLen,
            &len) != 1) {
        ok = false; // Authentication failed
    }
    plaintextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        return QByteArray();
    }

    decrypted.resize(plaintextLen);
    return decrypted;
}

// Old key derivation kept byte-exact for legacy envelope decryption only:
// a single unsalted SHA-256 round truncated to the AES-256 key size.
QByteArray LegacyDeriveKey(const QString &passphrase) {
    return QCryptographicHash::hash(
        passphrase.toUtf8(),
        QCryptographicHash::Sha256
    ).left(kKeySize);
}

} // namespace

QByteArray DeriveKey(const QString &passphrase, const QByteArray &salt, int iterations) {
    if (iterations <= 0 || salt.isEmpty()) {
        return QByteArray();
    }
    const auto password = passphrase.toUtf8();

    QByteArray key(kKeySize, 0);
    if (PKCS5_PBKDF2_HMAC(
            password.constData(),
            password.size(),
            reinterpret_cast<const unsigned char*>(salt.constData()),
            salt.size(),
            iterations,
            EVP_sha256(),
            kKeySize,
            reinterpret_cast<unsigned char*>(key.data())) != 1) {
        return QByteArray();
    }
    return key;
}

QString EncryptString(const QString &text, const QString &passphrase) {
    // Per-envelope random salt and IV, both from the CSPRNG.
    QByteArray salt(kSaltSize, 0);
    FillRandom(salt.data(), kSaltSize);
    QByteArray iv(kIvSize, 0);
    FillRandom(iv.data(), kIvSize);

    const auto key = DeriveKey(passphrase, salt, kPbkdf2Iterations);
    if (key.isEmpty()) {
        return QString();
    }

    const auto sealed = AesGcmEncrypt(key, iv, text.toUtf8());
    if (sealed.isEmpty()) {
        return QString();
    }

    // Envelope: base64(salt || iv || ciphertext || tag) behind the prefix.
    const auto envelope = salt + iv + sealed;
    return kFormatPrefix + QString::fromLatin1(envelope.toBase64());
}

QString DecryptString(const QString &text, const QString &passphrase) {
    if (text.startsWith(kFormatPrefix)) {
        // Current format: base64(salt || iv || ciphertext || tag).
        const auto envelope = QByteArray::fromBase64(
            text.mid(kFormatPrefix.size()).toLatin1());
        if (envelope.size() < kSaltSize + kIvSize + kTagSize) {
            return QString(); // Too short: salt(16) + IV(12) + tag(16)
        }

        const auto salt = envelope.left(kSaltSize);
        const auto iv = envelope.mid(kSaltSize, kIvSize);
        const auto tag = envelope.right(kTagSize);
        const auto ciphertext = envelope.mid(
            kSaltSize + kIvSize,
            envelope.size() - kSaltSize - kIvSize - kTagSize);

        const auto key = DeriveKey(passphrase, salt, kPbkdf2Iterations);
        if (key.isEmpty()) {
            return QString();
        }

        const auto decrypted = AesGcmDecrypt(key, iv, ciphertext, tag);
        // On authentication failure this is empty; an empty ciphertext
        // (empty plaintext) legitimately decrypts to an empty string.
        return QString::fromUtf8(decrypted);
    }

    // Legacy format: base64(iv || ciphertext || tag) under the old unsalted
    // single-round SHA-256 key. Kept byte-exact so payloads persisted by
    // older builds still decrypt.
    QByteArray encryptedData = QByteArray::fromBase64(text.toLatin1());
    if (encryptedData.size() <= kIvSize + kTagSize) {
        return QString(); // Too short: IV(12) + tag(16) + at least 1 byte
    }

    QByteArray iv = encryptedData.left(kIvSize);
    QByteArray tag = encryptedData.right(kTagSize);
    QByteArray data = encryptedData.mid(kIvSize, encryptedData.size() - kIvSize - kTagSize);

    const auto decrypted = AesGcmDecrypt(LegacyDeriveKey(passphrase), iv, data, tag);
    // On authentication failure this is empty.
    return QString::fromUtf8(decrypted);
}

} // namespace EnhancedPrivacyCrypto
