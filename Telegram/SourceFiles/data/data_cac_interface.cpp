/*
This file is part of CRYPTOGRAM Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LEGAL
*/
#include "data/data_cac_interface.h"

#include "base/platform/base_platform_info.h"
#include <QMap>

namespace Data {

// Static registry for CAC users
QMap<UserId, QString> CACUserRegistry::_cacUsers;

// ========== CAC User Registry Implementation ==========

void CACUserRegistry::registerCACUser(UserId userId, const QString &userDN) {
    _cacUsers[userId] = userDN;
}

void CACUserRegistry::unregisterCACUser(UserId userId) {
    _cacUsers.remove(userId);
}

bool CACUserRegistry::isCACUser(UserId userId) {
    return _cacUsers.contains(userId);
}

QString CACUserRegistry::getUserDN(UserId userId) {
    return _cacUsers.value(userId, QString());
}

QString CACUserRegistry::getUserFlag(UserId userId) {
    QString dn = getUserDN(userId);
    if (dn.isEmpty()) return QString();
    
    // Find C= or c=
    int idx = dn.indexOf("C=", 0, Qt::CaseInsensitive);
    if (idx < 0) idx = dn.indexOf("c=", 0, Qt::CaseInsensitive);
    if (idx >= 0 && idx + 4 <= dn.size()) {
        QString cc = dn.mid(idx + 2, 2).toUpper();
        
        // Convert to emoji flag using Regional Indicator Symbols
        // ASCII A is 65, Regional Indicator Symbol A is 0x1F1E6
        if (cc[0] >= 'A' && cc[0] <= 'Z' && cc[1] >= 'A' && cc[1] <= 'Z') {
            QString flag;
            flag += QString::fromUcs4(new char32_t[2]{(char32_t)(cc[0].unicode() - 65 + 0x1F1E6), 0}, 1);
            flag += QString::fromUcs4(new char32_t[2]{(char32_t)(cc[1].unicode() - 65 + 0x1F1E6), 0}, 1);
            return flag;
        }
    }
    
    return QString();
}

QSet<UserId> CACUserRegistry::getCACUsers() {
    QSet<UserId> users;
    for (auto it = _cacUsers.begin(); it != _cacUsers.end(); ++it) {
        users.insert(it.key());
    }
    return users;
}

void CACUserRegistry::clearRegistry() {
    _cacUsers.clear();
}

// ========== Algorithm Information ==========

CACAlgorithmInfo getAlgorithmInfo(CACAlgorithm algorithm) {
    switch (algorithm) {
    case CACAlgorithm::ECC_P384_SHA384:
        return {
            CACAlgorithm::ECC_P384_SHA384,
            "ECDSA P-384/SHA-384",
            "NIST P-384 curve with SHA-384 (CNSA 2.0 Compliant)",
            384,
            "SHA-384",
            4  // High security
        };

    case CACAlgorithm::ECC_P521_SHA512:
        return {
            CACAlgorithm::ECC_P521_SHA512,
            "ECDSA P-521/SHA-512",
            "NIST P-521 curve with SHA-512 (CNSA 2.0 Compliant)",
            521,
            "SHA-512",
            5  // Maximum security
        };

    default:
        return {
            CACAlgorithm::ECC_P384_SHA384,
            "Unknown",
            "Unknown algorithm",
            0,
            "Unknown",
            0
        };
    }
}

CACAlgorithm algorithmFromString(const QString &name) {
    if (name.contains("P-384") || name.contains("P384")) {
        return CACAlgorithm::ECC_P384_SHA384;
    } else if (name.contains("P-521") || name.contains("P521")) {
        return CACAlgorithm::ECC_P521_SHA512;
    }

    // Default to P-384 (CNSA 2.0 Compliant)
    return CACAlgorithm::ECC_P384_SHA384;
}

QString algorithmToString(CACAlgorithm algorithm) {
    return getAlgorithmInfo(algorithm).name;
}

// ========== Platform-Specific CAC Implementation ==========

#ifdef Q_OS_WIN
// Windows implementation using WinSCard API
class WindowsCACInterface : public CACInterface {
public:
    CACResult initialize() override {
        // TODO: Initialize PC/SC (Windows Smart Card API)
        _initialized = true;
        return CACResult::Success;
    }

    bool isCardPresent() const override {
        // TODO: Check if CAC card is inserted
        return false;
    }

    bool isInitialized() const override {
        return _initialized;
    }

    base::expected<CACCardInfo, CACResult> getCardInfo() override {
        CACCardInfo info;
        info.cardSerialNumber = "Simulated-CAC-001";
        info.holderName = "DOE, JOHN A.";
        info.holderDN = "CN=DOE.JOHN.A.1234567890,OU=DoD,O=U.S. Government,C=US";
        info.issuerDN = "CN=DoD Root CA,O=U.S. Government,C=US";
        info.certificateExpiry = QDateTime::currentDateTime().addYears(1);
        info.isValid = true;
        info.defaultAlgorithm = CACAlgorithm::ECC_P384_SHA384;
        info.supportedAlgorithms = {"ECC P-384/SHA-384", "ECC P-521/SHA-512"};
        return info;
    }

    QStringList enumerateCards() override {
        // TODO: Enumerate connected CAC cards
        return QStringList();
    }

    CACResult verifyPIN(const QString &pin) override {
        // TODO: Verify PIN against CAC card
        _pinVerified = true;
        return CACResult::Success;
    }

    bool isPINVerified() const override {
        return _pinVerified;
    }

    int getRemainingPINAttempts() override {
        return 3;
    }

    base::expected<CACSignatureResult, CACResult> signData(
            const bytes::const_span &data,
            CACAlgorithm algorithm) override {
        // TODO: Sign data using CAC card
        CACSignatureResult result;
        result.algorithm = algorithm;
        result.signerDN = "CN=DOE.JOHN.A.1234567890,OU=DoD,O=U.S. Government,C=US";
        result.timestamp = QDateTime::currentDateTime();
        result.verified = false;
        return result;
    }

    base::expected<bool, CACResult> verifySignature(
            const bytes::const_span &data,
            const CACSignatureResult &signature) override {
        // TODO: Verify signature
        return true;
    }

    base::expected<bytes::vector, CACResult> getCertificate() override {
        // TODO: Read certificate from CAC card
        return bytes::vector();
    }

    base::expected<bytes::vector, CACResult> getPublicKey() override {
        // TODO: Extract public key from certificate
        return bytes::vector();
    }

    QStringList getSupportedAlgorithms() override {
        return {"ECC P-384/SHA-384", "ECC P-521/SHA-512"};
    }

    CACResult setAlgorithm(CACAlgorithm algorithm) override {
        _currentAlgorithm = algorithm;
        return CACResult::Success;
    }

    CACAlgorithm getCurrentAlgorithm() const override {
        return _currentAlgorithm;
    }

    QString getUserDN() const override {
        return "CN=DOE.JOHN.A.1234567890,OU=DoD,O=U.S. Government,C=US";
    }

    QString getCardSerial() const override {
        return "Simulated-CAC-001";
    }

private:
    bool _initialized = false;
    bool _pinVerified = false;
    CACAlgorithm _currentAlgorithm = CACAlgorithm::ECC_P384_SHA384;
};

#elif defined(Q_OS_LINUX)
// Linux implementation using PC/SC Lite
class LinuxCACInterface : public CACInterface {
public:
    CACResult initialize() override {
        // TODO: Initialize PC/SC Lite
        _initialized = true;
        return CACResult::Success;
    }

    bool isCardPresent() const override {
        return false;
    }

    bool isInitialized() const override {
        return _initialized;
    }

    base::expected<CACCardInfo, CACResult> getCardInfo() override {
        return base::make_unexpected(CACResult::CardNotFound);
    }

    QStringList enumerateCards() override {
        return QStringList();
    }

    CACResult verifyPIN(const QString &pin) override {
        return CACResult::CardNotFound;
    }

    bool isPINVerified() const override {
        return false;
    }

    int getRemainingPINAttempts() override {
        return 0;
    }

    base::expected<CACSignatureResult, CACResult> signData(
            const bytes::const_span &data,
            CACAlgorithm algorithm) override {
        return base::make_unexpected(CACResult::CardNotFound);
    }

    base::expected<bool, CACResult> verifySignature(
            const bytes::const_span &data,
            const CACSignatureResult &signature) override {
        return base::make_unexpected(CACResult::CardNotFound);
    }

    base::expected<bytes::vector, CACResult> getCertificate() override {
        return base::make_unexpected(CACResult::CardNotFound);
    }

    base::expected<bytes::vector, CACResult> getPublicKey() override {
        return base::make_unexpected(CACResult::CardNotFound);
    }

    QStringList getSupportedAlgorithms() override {
        return QStringList();
    }

    CACResult setAlgorithm(CACAlgorithm algorithm) override {
        _currentAlgorithm = algorithm;
        return CACResult::Success;
    }

    CACAlgorithm getCurrentAlgorithm() const override {
        return _currentAlgorithm;
    }

    QString getUserDN() const override {
        return QString();
    }

    QString getCardSerial() const override {
        return QString();
    }

private:
    bool _initialized = false;
    CACAlgorithm _currentAlgorithm = CACAlgorithm::ECC_P384_SHA384;
};

#elif defined(Q_OS_MAC)
// macOS implementation using CryptoTokenKit
class MacCACInterface : public CACInterface {
public:
    CACResult initialize() override {
        _initialized = true;
        return CACResult::Success;
    }

    bool isCardPresent() const override {
        return false;
    }

    bool isInitialized() const override {
        return _initialized;
    }

    base::expected<CACCardInfo, CACResult> getCardInfo() override {
        return base::make_unexpected(CACResult::CardNotFound);
    }

    QStringList enumerateCards() override {
        return QStringList();
    }

    CACResult verifyPIN(const QString &pin) override {
        return CACResult::CardNotFound;
    }

    bool isPINVerified() const override {
        return false;
    }

    int getRemainingPINAttempts() override {
        return 0;
    }

    base::expected<CACSignatureResult, CACResult> signData(
            const bytes::const_span &data,
            CACAlgorithm algorithm) override {
        return base::make_unexpected(CACResult::CardNotFound);
    }

    base::expected<bool, CACResult> verifySignature(
            const bytes::const_span &data,
            const CACSignatureResult &signature) override {
        return base::make_unexpected(CACResult::CardNotFound);
    }

    base::expected<bytes::vector, CACResult> getCertificate() override {
        return base::make_unexpected(CACResult::CardNotFound);
    }

    base::expected<bytes::vector, CACResult> getPublicKey() override {
        return base::make_unexpected(CACResult::CardNotFound);
    }

    QStringList getSupportedAlgorithms() override {
        return QStringList();
    }

    CACResult setAlgorithm(CACAlgorithm algorithm) override {
        _currentAlgorithm = algorithm;
        return CACResult::Success;
    }

    CACAlgorithm getCurrentAlgorithm() const override {
        return _currentAlgorithm;
    }

    QString getUserDN() const override {
        return QString();
    }

    QString getCardSerial() const override {
        return QString();
    }

private:
    bool _initialized = false;
    CACAlgorithm _currentAlgorithm = CACAlgorithm::ECC_P384_SHA384;
};
#endif

// ========== CAC Factory Implementation ==========

std::unique_ptr<CACInterface> CACFactory::create() {
#ifdef Q_OS_WIN
    return std::make_unique<WindowsCACInterface>();
#elif defined(Q_OS_LINUX)
    return std::make_unique<LinuxCACInterface>();
#elif defined(Q_OS_MAC)
    return std::make_unique<MacCACInterface>();
#else
    return nullptr;
#endif
}

bool CACFactory::isCACardAvailable() {
    auto cac = create();
    if (!cac) {
        return false;
    }

    cac->initialize();
    return cac->isCardPresent();
}

QStringList CACFactory::enumerateCACards() {
    auto cac = create();
    if (!cac) {
        return QStringList();
    }

    cac->initialize();
    return cac->enumerateCards();
}

} // namespace Data
