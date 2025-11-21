/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#pragma once

#include "data/data_quantum_types.h"

#include <memory>
#include <QString>

namespace Data {

// NSA Security - Provides enhanced security module following NIST standards
class NSASecurity {
public:
    NSASecurity() = default;
    ~NSASecurity() = default;

    // Initialize the NSA security module
    void initialize(NSAClassificationLevel level = NSAClassificationLevel::Secret);

    bool isInitialized() const;

    // Check if NSA security protocols are active
    bool isSecured() const;

    // Enable/disable NSA security protocols
    void setSecured(bool secured);

    // Apply NIST-compliant encryption
    QByteArray applyNISTEncryption(const QByteArray &data);

    // Remove NIST-compliant encryption
    QByteArray removeNISTEncryption(const QByteArray &data);

    void reportSecurityEvent(
        SecurityEventType type,
        SecurityEventSeverity severity,
        const QString &message);

    struct ThreatPosture {
        bool isQuantumReady = false;
    };
    ThreatPosture assessCurrentThreatLandscape() const;
    void enableQuantumReadyDefenses();
    void enableNationStateDefenses();
    void enableAPTCountermeasures();
    void initiateEmergencyProtocol();

    // Get current security level
    int getSecurityLevel() const;

private:
    bool _secured = false;
    bool _initialized = false;
    int _securityLevel = 0;
    bool _quantumReady = false;
    bool _nationStateDefenses = false;
    bool _aptCountermeasures = false;
    NSAClassificationLevel _classification = NSAClassificationLevel::Secret;
    NSASecurity(const NSASecurity &other) = delete;
    NSASecurity &operator=(const NSASecurity &other) = delete;
};

} // namespace Data
