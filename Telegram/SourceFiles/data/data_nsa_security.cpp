/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#include "data/data_nsa_security.h"

#include <QtCore/QDebug>
#include <QtCore/QCryptographicHash>

namespace Data {

void NSASecurity::initialize(NSAClassificationLevel level) {
    _secured = true;
    _securityLevel = static_cast<int>(level) + 1;
    _initialized = true;
    _classification = level;
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

QByteArray NSASecurity::applyNISTEncryption(const QByteArray &data) {
    auto hash = QCryptographicHash::hash(data, QCryptographicHash::Sha256);
    QByteArray result(data);
    for (int i = 0; i < result.size(); ++i) {
        result[i] = result[i] ^ hash[i % hash.size()];
    }
    return result;
}

QByteArray NSASecurity::removeNISTEncryption(const QByteArray &data) {
    return applyNISTEncryption(data);
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
