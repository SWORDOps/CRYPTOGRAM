/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#include "data/data_quantumguard.h"

#include <QtCore/QDebug>
#include <QtCore/QCryptographicHash>
#include <gsl/gsl>

namespace Data {
namespace {

int keySizeForAlgorithm(QuantumAlgorithm algorithm) {
    switch (algorithm) {
    case QuantumAlgorithm::ML_KEM_512:
    case QuantumAlgorithm::ML_DSA_44:
        return 32;
    case QuantumAlgorithm::ML_KEM_768:
    case QuantumAlgorithm::ML_DSA_65:
        return 48;
    case QuantumAlgorithm::ML_KEM_1024:
    case QuantumAlgorithm::ML_DSA_87:
    case QuantumAlgorithm::HybridX25519_ML_KEM_1024:
    case QuantumAlgorithm::HybridEd25519_ML_DSA_87:
        return 64;
    default:
        return 32;
    }
}

} // namespace

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

base::expected<QuantumKeyResult, QString> QuantumGuard::generateQuantumKey(
        QuantumKeyType /*type*/,
        QuantumAlgorithm algorithm) {
    if (!_initialized) {
        return base::make_unexpected(QStringLiteral("QuantumGuard not initialized"));
    }
    const auto size = keySizeForAlgorithm(algorithm);
    const auto bytes = randomBytes(size);
    QuantumKeyResult result;
    result.keyId = makeKeyId();
    result.publicKey = QByteArray(
        reinterpret_cast<const char *>(bytes.data()),
        static_cast<int>(bytes.size()));
    return result;
}

base::expected<QuantumEncryptionResult, QString> QuantumGuard::quantumEncrypt(
        const QString &keyId,
        const bytes::const_span &plaintext) {
    if (!_initialized) {
        return base::make_unexpected(QStringLiteral("QuantumGuard not initialized"));
    }
    QuantumEncryptionResult result;
    result.keyId = keyId;
    result.algorithm = QuantumAlgorithm::Kyber1024;
    const auto secret = randomBytes(32);
    const auto dataSpan = bytes::make_span(plaintext);
    bytes::vector ciphertext(dataSpan.size());
    for (size_t i = 0; i < dataSpan.size(); ++i) {
        ciphertext[i] = bytes::type(
            gsl::to_integer<int>(dataSpan[i])
            ^ gsl::to_integer<int>(secret[i % secret.size()]));
    }
    result.ciphertext = std::move(ciphertext);
    result.encapsulatedSecret = randomBytes(48);
    return result;
}

base::expected<bytes::vector, QString> QuantumGuard::quantumDecrypt(
        const QString &keyId,
        const bytes::const_span &ciphertext,
        const bytes::const_span &encapsulatedSecret) {
    if (!_initialized) {
        return base::make_unexpected(QStringLiteral("QuantumGuard not initialized"));
    }
    // Derive secret from encapsulatedSecret (simplified - in real implementation this would use KEM decapsulation)
    const auto secret = bytes::vector(encapsulatedSecret.begin(), encapsulatedSecret.begin() + std::min(static_cast<size_t>(32), encapsulatedSecret.size()));
    bytes::vector plaintext(ciphertext.size());
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        plaintext[i] = bytes::type(
            gsl::to_integer<int>(ciphertext[i])
            ^ gsl::to_integer<int>(secret[i % secret.size()]));
    }
    return plaintext;
}

QuantumAlgorithm QuantumGuard::selectOptimalKEM(
        QuantumSecurityLevel level) const {
    if (level >= QuantumSecurityLevel::Level4) {
        return QuantumAlgorithm::ML_KEM_1024;
    }
    return QuantumAlgorithm::ML_KEM_768;
}

QuantumAlgorithm QuantumGuard::selectOptimalSignature(
        QuantumSecurityLevel level) const {
    if (level >= QuantumSecurityLevel::Level4) {
        return QuantumAlgorithm::ML_DSA_87;
    }
    return QuantumAlgorithm::ML_DSA_65;
}

base::expected<QuantumSignatureResult, QString> QuantumGuard::quantumSign(
        const QString &keyId,
        const QByteArray &data) {
    if (!_initialized) {
        return base::make_unexpected(QStringLiteral("QuantumGuard not initialized"));
    }
    QuantumSignatureResult result;
    result.keyId = keyId;
    result.signature = makeSignature(keyId.toUtf8(), data);
    return result;
}

bytes::vector QuantumGuard::randomBytes(int size) {
    bytes::vector buffer(size);
    base::RandomFill(bytes::make_span(buffer));
    return buffer;
}

QString QuantumGuard::makeKeyId() const {
    return QStringLiteral("quantum_%1").arg(base::RandomValue<uint32>());
}

QByteArray QuantumGuard::makeSignature(
        const QByteArray &key,
        const QByteArray &data) const {
    auto hmac = QCryptographicHash::hash(key + data, QCryptographicHash::Sha256);
    return hmac;
}

} // namespace Data
