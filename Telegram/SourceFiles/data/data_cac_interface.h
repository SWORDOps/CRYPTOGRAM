/*
This file is part of CRYPTOGRAM Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LEGAL
*/
#pragma once

#include "base/bytes.h"
#include <QtCore/QString>
#include <QtCore/QStringList>
#include <memory>

namespace Data {

// CAC (Common Access Card) Integration
// Supports DoD/Military smart cards with PIV (Personal Identity Verification) applet
//
// Features:
// - Hardware-backed cryptography
// - X.509 certificate authentication
// - Multiple algorithm support (RSA-2048/4096, ECC P-256/P-384)
// - Digital signatures for message authentication
// - Green name identification for CAC-authenticated users

// Supported cryptographic algorithms
enum class CACAlgorithm {
    ECC_P384_SHA384,      // NIST P-384 curve with SHA-384 (CNSA 2.0 Compliant)
    ECC_P521_SHA512,      // NIST P-521 curve with SHA-512 (CNSA 2.0 Compliant)
};

// CAC card information
struct CACCardInfo {
    QString cardSerialNumber;
    QString holderName;
    QString holderDN;             // Distinguished Name from certificate
    QString issuerDN;             // Issuer Distinguished Name
    QDateTime certificateExpiry;
    bool isValid = false;
    bool isHardwareBacked = true;
    CACAlgorithm defaultAlgorithm = CACAlgorithm::ECC_P384_SHA384;
    QStringList supportedAlgorithms;
};

// CAC operation result
enum class CACResult {
    Success,
    CardNotFound,
    CardLocked,
    PINRequired,
    PINIncorrect,
    CertificateInvalid,
    CertificateExpired,
    AlgorithmNotSupported,
    SignatureFailed,
    VerificationFailed,
    UnknownError
};

// CAC signature result
struct CACSignatureResult {
    bytes::vector signature;
    bytes::vector certificate;    // X.509 certificate
    CACAlgorithm algorithm;
    QString signerDN;
    QDateTime timestamp;
    bool verified = false;
};

// CAC Interface for smart card operations
class CACInterface {
public:
    virtual ~CACInterface() = default;

    // Card detection and initialization
    virtual CACResult initialize() = 0;
    virtual bool isCardPresent() const = 0;
    virtual bool isInitialized() const = 0;

    // Card information
    virtual base::expected<CACCardInfo, CACResult> getCardInfo() = 0;
    virtual QStringList enumerateCards() = 0;  // List all connected CAC cards

    // PIN management
    virtual CACResult verifyPIN(const QString &pin) = 0;
    virtual bool isPINVerified() const = 0;
    virtual int getRemainingPINAttempts() = 0;

    // Cryptographic operations
    virtual base::expected<CACSignatureResult, CACResult> signData(
        const bytes::const_span &data,
        CACAlgorithm algorithm = CACAlgorithm::ECC_P384_SHA384) = 0;

    virtual base::expected<bool, CACResult> verifySignature(
        const bytes::const_span &data,
        const CACSignatureResult &signature) = 0;

    // Certificate operations
    virtual base::expected<bytes::vector, CACResult> getCertificate() = 0;
    virtual base::expected<bytes::vector, CACResult> getPublicKey() = 0;

    // Algorithm management
    virtual QStringList getSupportedAlgorithms() = 0;
    virtual CACResult setAlgorithm(CACAlgorithm algorithm) = 0;
    virtual CACAlgorithm getCurrentAlgorithm() const = 0;

    // User identification (for green names)
    virtual QString getUserDN() const = 0;
    virtual QString getCardSerial() const = 0;
};

// Factory for creating CAC interface instances
class CACFactory {
public:
    // Create platform-specific CAC interface
    static std::unique_ptr<CACInterface> create();

    // Detect if CAC card is available
    static bool isCACardAvailable();

    // Get list of connected CAC cards
    static QStringList enumerateCACards();
};

// CAC User Registry (for green name identification)
class CACUserRegistry {
public:
    // Register user as CAC-authenticated
    static void registerCACUser(UserId userId, const QString &userDN);

    // Unregister CAC user
    static void unregisterCACUser(UserId userId);

    // Check if user is CAC-authenticated
    static bool isCACUser(UserId userId);

    // Get user's CAC DN (Distinguished Name)
    static QString getUserDN(UserId userId);

    // Get all CAC users
    static QSet<UserId> getCACUsers();

    // Clear registry
    static void clearRegistry();

private:
    static QMap<UserId, QString> _cacUsers;  // userId -> DN mapping
};

// Algorithm information helper
struct CACAlgorithmInfo {
    CACAlgorithm algorithm;
    QString name;
    QString description;
    int keySize;            // Key size in bits
    QString hashAlgorithm;
    int securityLevel;      // 1-5 (1=lowest, 5=highest)
};

// Get information about an algorithm
CACAlgorithmInfo getAlgorithmInfo(CACAlgorithm algorithm);

// Get algorithm from string name
CACAlgorithm algorithmFromString(const QString &name);

// Convert algorithm to display string
QString algorithmToString(CACAlgorithm algorithm);

} // namespace Data
