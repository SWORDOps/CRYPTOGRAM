/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#pragma once

#include "base/bytes.h"
#include "base/expected.h"
#include "base/random.h"
#include "data/data_quantum_types.h"

#include <QtCore/QByteArray>
#include <QtCore/QCryptographicHash>
#include <QtCore/QString>

#include <memory>

namespace Data {

struct QuantumKeyResult {
    QString keyId;
    QByteArray publicKey;
};

struct QuantumSignatureResult {
    QString keyId;
    QByteArray signature;
};

class QuantumGuard final {
public:
    QuantumGuard() = default;
    ~QuantumGuard() = default;

    bool initialize();
    bool isInitialized() const;
    bool enableQuantumSignalProtocol(bool enabled);
    bool enableHardwareAcceleration(bool enabled);
    base::expected<QuantumKeyResult, QString> generateQuantumKey(
        QuantumKeyType type,
        QuantumAlgorithm algorithm);
    QuantumAlgorithm selectOptimalKEM(QuantumSecurityLevel level) const;
    QuantumAlgorithm selectOptimalSignature(QuantumSecurityLevel level) const;
    base::expected<QuantumSignatureResult, QString> quantumSign(
        const QString &keyId,
        const QByteArray &data);

private:
    bytes::vector randomBytes(int size);
    QString makeKeyId() const;
    QByteArray makeSignature(const QByteArray &key, const QByteArray &data) const;

    bool _initialized = false;
    bool _quantumSignalEnabled = false;
    bool _hardwareAcceleration = false;
    QuantumGuard(const QuantumGuard &other) = delete;
    QuantumGuard &operator=(const QuantumGuard &other) = delete;
};

} // namespace Data
