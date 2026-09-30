/*
This file is part of CRYPTOGRAM Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LEGAL
*/
#include "data/data_cac_interface.h"

#include "base/platform/base_platform_info.h"
#include "logs.h"
#include <QMap>

#include <algorithm>
#include <array>
#include <cstring>
#include <ctime>
#include <iterator>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

// Linux CAC/PIV backend talks to the smartcard through PC/SC Lite (pcsclite),
// which is already a CI/host dependency (libpcsclite-dev). Guarded with
// __has_include so machines without the headers keep the inert stub below.
#if defined(Q_OS_LINUX) && defined(__has_include)
#if __has_include(<PCSC/winscard.h>)
#define CRYPTOGRAM_HAS_PCSC 1
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>
#endif
#endif

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

#ifdef CRYPTOGRAM_HAS_PCSC
// Linux implementation using PC/SC Lite + the PIV card application
// (NIST SP 800-73-4). Minimal hardware-tested spike path:
//
//   1. SCardEstablishContext / SCardListReaders        -> reader discovery
//   2. SCardGetStatusChange (0 ms)                     -> card presence
//   3. SELECT AID  A0 00 00 03 08                      -> PIV applet select
//   4. GET DATA    00 CB 3F FF, tag 5F C1 05           -> X.509 cert, slot 9a
//   5. GENERAL AUTHENTICATE 00 87 07 9A (alg 0x07 =    -> RSA-2048 signature
//      RSA 2048, key 9A), PKCS#1 v1.5 + SHA-256           (EM built locally)
//
// A FIPS YubiKey in PIV/CCID mode exercises exactly this path — it is NOT a
// DoD CAC (no DoD certificates). Chain-of-trust validation against NATO/DoD
// roots stays in SignalProtocol::verifyCacMutualAuth() and is NOT weakened
// here. See docs/CAC_YUBIKEY_PROVISIONING.md for provisioning the YubiKey.
class LinuxCACInterface : public CACInterface {
public:
    LinuxCACInterface() = default;
    ~LinuxCACInterface() override {
        std::lock_guard lock(_mutex);
        disconnectLocked();
        if (_contextValid) {
            SCardReleaseContext(_context);
            _contextValid = false;
        }
    }

    LinuxCACInterface(const LinuxCACInterface &other) = delete;
    LinuxCACInterface &operator=(const LinuxCACInterface &other) = delete;

    CACResult initialize() override {
        std::lock_guard lock(_mutex);
        if (!_ensureContextLocked()) {
            return CACResult::CardNotFound;
        }
        _readerNames = _listReadersLocked();
        if (_readerNames.empty()) {
            LOG(("CAC [PCSC] No readers found. Plug in the YubiKey "
                 "(CCID interface) and re-run."));
            return CACResult::CardNotFound;
        }
        for (const auto &name : _readerNames) {
            LOG(("CAC [PCSC] Reader: %1").arg(QString::fromStdString(name)));
        }
        return CACResult::Success;
    }

    bool isCardPresent() const override {
        std::lock_guard lock(_mutex);
        return _findCardReaderLocked(nullptr);
    }

    bool isInitialized() const override {
        std::lock_guard lock(_mutex);
        return _contextValid;
    }

    base::expected<CACCardInfo, CACResult> getCardInfo() override {
        std::lock_guard lock(_mutex);
        const auto cert = _ensureCertificateLocked();
        if (!cert) {
            return base::make_unexpected(cert.error());
        }
        const auto &parsed = *_parsedCert;
        CACCardInfo info;
        info.cardSerialNumber = parsed.serialHex;
        info.holderName = parsed.commonName;
        info.holderDN = parsed.subjectDn;
        info.issuerDN = parsed.issuerDn;
        info.certificateExpiry = parsed.notAfter;
        info.isValid = parsed.validAt;
        info.isHardwareBacked = true;
        info.certChainDer = parsed.der;
        info.supportedAlgorithms = getSupportedAlgorithms();
        return info;
    }

    QStringList enumerateCards() override {
        std::lock_guard lock(_mutex);
        QStringList result;
        if (!_ensureContextLocked()) {
            return result;
        }
        for (const auto &name : _listReadersLocked()) {
            SCARD_READERSTATE state = {};
            state.szReader = name.c_str();
            state.dwCurrentState = SCARD_STATE_UNAWARE;
            if (SCardGetStatusChange(_context, 0, &state, 1) == SCARD_S_SUCCESS
                && (state.dwEventState & SCARD_STATE_PRESENT)) {
                result.append(QString::fromStdString(name));
            }
        }
        return result;
    }

    CACResult verifyPIN(const QString &pin) override {
        std::lock_guard lock(_mutex);
        if (!_ensurePivReadyLocked()) {
            return _lastError;
        }
        // PIV VERIFY: 00 20 00 80 | PIN, right-padded with 0xFF to 8 bytes.
        std::vector<uint8_t> pinBlock(8, 0xFF);
        const QByteArray latin = pin.toLatin1();
        const auto copied = std::min<size_t>(8, size_t(latin.size()));
        std::memcpy(pinBlock.data(), latin.constData(), copied);

        std::vector<uint8_t> response;
        const std::vector<uint8_t> header = {0x00, 0x20, 0x00, 0x80};
        if (!_transmitPivCommandLocked(header, pinBlock, response, false)) {
            return _lastError;
        }
        const CACResult result = _mapSwLocked();
        if (result == CACResult::Success) {
            _pinVerified = true;
            LOG(("CAC [PIV] PIN verified."));
        }
        return result;
    }

    bool isPINVerified() const override {
        std::lock_guard lock(_mutex);
        return _pinVerified;
    }

    int getRemainingPINAttempts() override {
        std::lock_guard lock(_mutex);
        if (!_ensurePivReadyLocked()) {
            return 0;
        }
        // VERIFY with an empty data field asks for the retry counter without
        // consuming an attempt (SP 800-73-4 Part 2, 4.2.2). SW 63 CX reports
        // the remaining attempts in the low nibble of CX.
        std::vector<uint8_t> response;
        const std::vector<uint8_t> header = {0x00, 0x20, 0x00, 0x80};
        if (!_transmitPivCommandLocked(header, {}, response, false)) {
            return 0;
        }
        if (_lastSw1 == 0x63) {
            _pinAttempts = int(_lastSw2 & 0x0F);
        }
        return _pinAttempts;
    }

    base::expected<CACSignatureResult, CACResult> signData(
            const bytes::const_span &data,
            CACAlgorithm algorithm) override {
        std::lock_guard lock(_mutex);
        // Spike path: RSA-2048 with PKCS#1 v1.5 / SHA-256 (PIV algorithm
        // reference 0x07) against key reference 9A. The CNSA-oriented ECC
        // enum values are not wired yet; provision an RSA-2048 key in slot
        // 9a per docs/CAC_YUBIKEY_PROVISIONING.md.
        (void)algorithm;

        if (data.empty()) {
            return base::make_unexpected(CACResult::UnknownError);
        }
        if (!_ensurePivReadyLocked()) {
            return base::make_unexpected(_lastError);
        }

        // SHA-256 over the caller-provided data, then PKCS#1 v1.5 EM:
        // 00 01 FF..FF 00 || DigestInfo(SHA-256) || digest
        std::array<unsigned char, SHA256_DIGEST_LENGTH> digest = {};
        ::SHA256(
            reinterpret_cast<const unsigned char *>(data.data()),
            data.size(),
            digest.data());
        const auto em = _buildPkcs1V15Sha256Em(digest.data(), digest.size());

        // GENERAL AUTHENTICATE dynamic authentication template:
        // 7C L | 81 L | EM   (81 = challenge/response input, RSA)
        std::vector<uint8_t> body;
        body.reserve(em.size() + 8);
        body.push_back(0x7C);
        appendDerLength(body, em.size() + 4);
        body.push_back(0x81);
        appendDerLength(body, em.size());
        body.insert(body.end(), em.begin(), em.end());

        std::vector<uint8_t> response;
        const std::vector<uint8_t> header = {0x00, 0x87, 0x07, 0x9A};
        if (!_transmitPivCommandLocked(header, body, response, true)) {
            return base::make_unexpected(_lastError);
        }
        const CACResult swResult = _mapSwLocked();
        if (swResult != CACResult::Success) {
            if (swResult == CACResult::PINIncorrect) {
                LOG(("CAC [PIV] GENERAL AUTHENTICATE needs PIN verification "
                     "(retry counter: %1).").arg(_pinAttempts));
                return base::make_unexpected(CACResult::PINRequired);
            }
            return base::make_unexpected(swResult);
        }

        const auto outer = parseTlvList(response);
        const auto t7c = findTlv(outer, 0x7C);
        if (!t7c) {
            LOG(("CAC [PIV] GENERAL AUTHENTICATE: no 7C template in response."));
            return base::make_unexpected(CACResult::SignatureFailed);
        }
        const auto inner = parseTlvList(t7c->value);
        const auto t82 = findTlv(inner, 0x82);
        if (!t82 || t82->value.empty()) {
            LOG(("CAC [PIV] GENERAL AUTHENTICATE: no 82 signature in response."));
            return base::make_unexpected(CACResult::SignatureFailed);
        }

        CACSignatureResult result;
        result.signature = toBytesVector(t82->value);
        const auto cert = _ensureCertificateLocked();
        if (cert) {
            result.certificate = *cert;
            if (const auto parsed = parseCertificate(*cert)) {
                result.signerDN = parsed->subjectDn;
            }
        }
        result.algorithm = algorithm;
        result.timestamp = QDateTime::currentDateTime();
        result.verified = false;
        return result;
    }

    base::expected<bool, CACResult> verifySignature(
            const bytes::const_span &data,
            const CACSignatureResult &signature) override {
        // Local verification of what signData() produced: RSA PKCS#1 v1.5
        // with SHA-256, keyed by the certificate's public key. This does NOT
        // replace SignalProtocol::verifyCacMutualAuth() chain validation.
        if (signature.certificate.empty() || signature.signature.empty()) {
            return base::make_unexpected(CACResult::VerificationFailed);
        }
        const auto *der = reinterpret_cast<const unsigned char *>(
            signature.certificate.data());
        X509 *x509 = d2i_X509(nullptr, &der, unsigned(signature.certificate.size()));
        if (!x509) {
            return base::make_unexpected(CACResult::CertificateInvalid);
        }
        EVP_PKEY *publicKey = X509_get_pubkey(x509);
        X509_free(x509);
        if (!publicKey) {
            return base::make_unexpected(CACResult::CertificateInvalid);
        }
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        const bool ok = ctx
            && EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, publicKey) == 1
            && EVP_DigestVerify(
                ctx,
                reinterpret_cast<const unsigned char *>(signature.signature.data()),
                signature.signature.size(),
                reinterpret_cast<const unsigned char *>(data.data()),
                data.size()) == 1;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        if (!ok) {
            return base::make_unexpected(CACResult::VerificationFailed);
        }
        return true;
    }

    base::expected<bytes::vector, CACResult> getCertificate() override {
        std::lock_guard lock(_mutex);
        const auto cert = _ensureCertificateLocked();
        if (!cert) {
            return base::make_unexpected(cert.error());
        }
        return *cert;
    }

    base::expected<bytes::vector, CACResult> getPublicKey() override {
        std::lock_guard lock(_mutex);
        const auto cert = _ensureCertificateLocked();
        if (!cert) {
            return base::make_unexpected(cert.error());
        }
        const auto *der = reinterpret_cast<const unsigned char *>(cert->data());
        X509 *x509 = d2i_X509(nullptr, &der, unsigned(cert->size()));
        if (!x509) {
            return base::make_unexpected(CACResult::CertificateInvalid);
        }
        unsigned char *spki = nullptr;
        const int length = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x509), &spki);
        bytes::vector result;
        if (length > 0 && spki) {
            result.reserve(size_t(length));
            for (int i = 0; i < length; ++i) {
                result.push_back(static_cast<bytes::type>(spki[i]));
            }
            OPENSSL_free(spki);
        }
        X509_free(x509);
        if (result.empty()) {
            return base::make_unexpected(CACResult::CertificateInvalid);
        }
        return result;
    }

    QStringList getSupportedAlgorithms() override {
        // What this spike backend actually signs with today.
        return {QStringLiteral("RSA-2048/SHA-256")};
    }

    CACResult setAlgorithm(CACAlgorithm algorithm) override {
        _currentAlgorithm = algorithm;
        return CACResult::Success;
    }

    CACAlgorithm getCurrentAlgorithm() const override {
        return _currentAlgorithm;
    }

    QString getUserDN() const override {
        std::lock_guard lock(_mutex);
        if (_parsedCert) {
            return _parsedCert->subjectDn;
        }
        return QString();
    }

    QString getCardSerial() const override {
        std::lock_guard lock(_mutex);
        if (_parsedCert) {
            return _parsedCert->serialHex;
        }
        return QString();
    }

private:
    // ----- parsed certificate cache -----------------------------------------

    struct ParsedCertificate {
        bytes::vector der;
        QString subjectDn;
        QString issuerDn;
        QString commonName;
        QString serialHex;
        QDateTime notBefore;
        QDateTime notAfter;
        bool validAt = false;
    };

    // ----- PC/SC plumbing (all *_Locked require _mutex held) ----------------
    //
    // PC/SC state members are mutable: presence checks are const getters that
    // may lazily establish the context / connection. Logical configuration is
    // never changed by them.

    bool _ensureContextLocked() const {
        if (_contextValid) {
            return true;
        }
        const LONG rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &_context);
        if (rc != SCARD_S_SUCCESS) {
            LOG(("CAC [PCSC] SCardEstablishContext failed: %1 (%2)")
                .arg(QString::fromLocal8Bit(pcsc_stringify_error(rc)))
                .arg(rc));
            return false;
        }
        _contextValid = true;
        return true;
    }

    std::vector<std::string> _listReadersLocked() const {
        std::vector<std::string> names;
        if (!_ensureContextLocked()) {
            return names;
        }
        DWORD length = 0;
        LONG rc = SCardListReaders(_context, nullptr, nullptr, &length);
        if (rc != SCARD_S_SUCCESS || length == 0) {
            return names;
        }
        std::vector<char> buffer(length, '\0');
        rc = SCardListReaders(_context, nullptr, buffer.data(), &length);
        if (rc != SCARD_S_SUCCESS) {
            LOG(("CAC [PCSC] SCardListReaders failed: %1")
                .arg(QString::fromLocal8Bit(pcsc_stringify_error(rc))));
            return names;
        }
        for (const char *p = buffer.data(); *p != '\0'; p += std::strlen(p) + 1) {
            names.emplace_back(p);
        }
        return names;
    }

    bool _findCardReaderLocked(std::string *outReader) const {
        if (!_ensureContextLocked()) {
            return false;
        }
        for (const auto &name : _listReadersLocked()) {
            SCARD_READERSTATE state = {};
            state.szReader = name.c_str();
            state.dwCurrentState = SCARD_STATE_UNAWARE;
            if (SCardGetStatusChange(_context, 0, &state, 1) != SCARD_S_SUCCESS) {
                continue;
            }
            if (state.dwEventState & SCARD_STATE_PRESENT) {
                if (outReader) {
                    *outReader = name;
                }
                return true;
            }
        }
        return false;
    }

    void disconnectLocked() {
        if (_cardValid) {
            SCardDisconnect(_card, SCARD_LEAVE_CARD);
            _cardValid = false;
            _pivSelected = false;
            _pinVerified = false;
            _parsedCert.reset();
        }
    }

    bool _ensureCardConnectedLocked() {
        if (_cardValid) {
            char readerName[128] = {};
            DWORD readerNameLen = sizeof(readerName);
            DWORD state = 0;
            DWORD protocol = 0;
            std::array<BYTE, MAX_ATR_SIZE> atr = {};
            DWORD atrLen = DWORD(atr.size());
            const LONG rc = SCardStatus(
                _card, readerName, &readerNameLen, &state, &protocol, atr.data(), &atrLen);
            if (rc == SCARD_S_SUCCESS && !(state & SCARD_ABSENT)) {
                return true;
            }
            disconnectLocked();
        }
        std::string reader;
        if (!_findCardReaderLocked(&reader)) {
            return false;
        }
        DWORD activeProtocol = 0;
        const LONG rc = SCardConnect(
            _context,
            reader.c_str(),
            SCARD_SHARE_SHARED,
            SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
            &_card,
            &activeProtocol);
        if (rc != SCARD_S_SUCCESS) {
            LOG(("CAC [PCSC] SCardConnect(%1) failed: %2")
                .arg(QString::fromStdString(reader))
                .arg(QString::fromLocal8Bit(pcsc_stringify_error(rc))));
            return false;
        }
        _cardValid = true;
        _protocol = activeProtocol;
        _pivSelected = false;
        _pinVerified = false;
        _pinAttempts = 3;
        _parsedCert.reset();
        LOG(("CAC [PCSC] Connected to %1 (protocol %2).")
            .arg(QString::fromStdString(reader))
            .arg(activeProtocol == SCARD_PROTOCOL_T1 ? u"T=1"_q : u"T=0"_q));
        return true;
    }

    bool _selectPivLocked() {
        // Yubico uses the short 5-byte AID (A0 00 00 03 08); try it first,
        // then the full 9-byte PIV card application AID as fallback.
        static const std::vector<std::vector<uint8_t>> aids = {
            {0xA0, 0x00, 0x00, 0x03, 0x08},
            {0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00},
        };
        for (const auto &aid : aids) {
            std::vector<uint8_t> response;
            const std::vector<uint8_t> header = {0x00, 0xA4, 0x04, 0x00};
            if (!_transmitPivCommandLocked(header, aid, response, false)) {
                return false;
            }
            if (_lastSw1 == 0x90 && _lastSw2 == 0x00) {
                _pivSelected = true;
                LOG(("CAC [PIV] PIV card application selected."));
                return true;
            }
        }
        LOG(("CAC [PIV] SELECT AID failed (SW %02X %02X) — card has no PIV applet?")
            .arg(_lastSw1, 2, 16, QChar('0'))
            .arg(_lastSw2, 2, 16, QChar('0')));
        return false;
    }

    bool _ensurePivReadyLocked() {
        if (!_ensureCardConnectedLocked()) {
            _lastError = CACResult::CardNotFound;
            return false;
        }
        if (!_pivSelected && !_selectPivLocked()) {
            _lastError = CACResult::UnknownError;
            return false;
        }
        _lastError = CACResult::Success;
        return true;
    }

    bool _transmitLocked(const std::vector<uint8_t> &request, std::vector<uint8_t> &response) {
        response.clear();
        if (!_cardValid) {
            return false;
        }
        const auto *pci = (_protocol == SCARD_PROTOCOL_T1) ? SCARD_PCI_T1 : SCARD_PCI_T0;
        std::vector<uint8_t> buffer(65538, 0);
        std::vector<uint8_t> outgoing = request;

        // SW 6C XX (wrong Le) -> single retransmit with Le = XX.
        for (int attempt = 0; attempt < 2; ++attempt) {
            DWORD receivedLength = DWORD(buffer.size());
            const LONG rc = SCardTransmit(
                _card,
                pci,
                outgoing.data(),
                DWORD(outgoing.size()),
                nullptr,
                buffer.data(),
                &receivedLength);
            if (rc != SCARD_S_SUCCESS) {
                LOG(("CAC [PCSC] SCardTransmit failed: %1")
                    .arg(QString::fromLocal8Bit(pcsc_stringify_error(rc))));
                disconnectLocked();
                return false;
            }
            if (receivedLength < 2) {
                disconnectLocked();
                return false;
            }
            _lastSw1 = buffer[receivedLength - 2];
            _lastSw2 = buffer[receivedLength - 1];
            response.insert(
                response.end(),
                buffer.data(),
                buffer.data() + receivedLength - 2);
            if (_lastSw1 != 0x6C) {
                break;
            }
            outgoing = request;
            outgoing.push_back(_lastSw2);
            response.clear();
        }

        // SW 61 XX -> GET RESPONSE chain (response data still buffered).
        int guard = 0;
        while (_lastSw1 == 0x61 && guard++ < 64) {
            std::vector<uint8_t> getResponse = {0x00, 0xC0, 0x00, 0x00, _lastSw2};
            DWORD receivedLength = DWORD(buffer.size());
            const LONG rc = SCardTransmit(
                _card,
                pci,
                getResponse.data(),
                DWORD(getResponse.size()),
                nullptr,
                buffer.data(),
                &receivedLength);
            if (rc != SCARD_S_SUCCESS || receivedLength < 2) {
                LOG(("CAC [PCSC] GET RESPONSE failed."));
                disconnectLocked();
                return false;
            }
            response.insert(
                response.end(),
                buffer.data(),
                buffer.data() + receivedLength - 2);
            _lastSw1 = buffer[receivedLength - 2];
            _lastSw2 = buffer[receivedLength - 1];
        }
        return true;
    }

    // header = CLA INS P1 P2; appends Lc/body/Le in the right APDU encoding.
    bool _transmitPivCommandLocked(
            const std::vector<uint8_t> &header,
            const std::vector<uint8_t> &body,
            std::vector<uint8_t> &response,
            bool wantsResponse) {
        std::vector<uint8_t> apdu = header;
        if (body.size() <= 255) {
            apdu.push_back(uint8_t(body.size()));
            apdu.insert(apdu.end(), body.begin(), body.end());
            if (wantsResponse && _protocol == SCARD_PROTOCOL_T1) {
                apdu.push_back(0x00); // Le. Over T=0, rely on SW 61/6C.
            }
        } else {
            // Extended APDU (3-byte Lc) — required for RSA-2048 GENERAL
            // AUTHENTICATE (264-byte body). YubiKey CCID runs T=1 with
            // extended APDU support.
            if (_protocol != SCARD_PROTOCOL_T1) {
                LOG(("CAC [PIV] Body of %1 bytes needs an extended APDU, "
                     "unsupported on T=0.").arg(body.size()));
                _lastSw1 = _lastSw2 = 0x6F;
                return false;
            }
            apdu.push_back(0x00);
            apdu.push_back(uint8_t(body.size() >> 8));
            apdu.push_back(uint8_t(body.size() & 0xFF));
            apdu.insert(apdu.end(), body.begin(), body.end());
            apdu.push_back(0x00);
            apdu.push_back(0x00);
        }
        return _transmitLocked(apdu, response);
    }

    CACResult _mapSwLocked() {
        const uint8_t sw1 = _lastSw1;
        const uint8_t sw2 = _lastSw2;
        if (sw1 == 0x90 && sw2 == 0x00) {
            return CACResult::Success;
        }
        if (sw1 == 0x63) {
            // 63 CX: verification failed, X attempts remaining.
            _pinAttempts = int(sw2 & 0x0F);
            _pinVerified = false;
            return (sw2 & 0x0F) ? CACResult::PINIncorrect : CACResult::CardLocked;
        }
        if (sw1 == 0x69 && sw2 == 0x83) {
            return CACResult::CardLocked; // authentication method blocked
        }
        if (sw1 == 0x6A && (sw2 == 0x80 || sw2 == 0x86)) {
            // Wrong parameters — usually algorithm/key mismatch (e.g. ECC key
            // in 9a while we issue an RSA-2048 GENERAL AUTHENTICATE).
            return CACResult::AlgorithmNotSupported;
        }
        return CACResult::UnknownError;
    }

    // ----- PIV objects -------------------------------------------------------

    base::expected<bytes::vector, CACResult> _ensureCertificateLocked() {
        if (_parsedCert) {
            return _parsedCert->der;
        }
        if (!_ensurePivReadyLocked()) {
            return base::make_unexpected(_lastError);
        }
        // GET DATA for the X.509 Certificate for PIV Authentication:
        // 00 CB 3F FF | 5C 03 5F C1 05 | Le 00
        std::vector<uint8_t> response;
        const std::vector<uint8_t> header = {0x00, 0xCB, 0x3F, 0xFF};
        const std::vector<uint8_t> body = {0x5C, 0x03, 0x5F, 0xC1, 0x05};
        if (!_transmitPivCommandLocked(header, body, response, true)) {
            return base::make_unexpected(_lastError);
        }
        const CACResult swResult = _mapSwLocked();
        if (swResult == CACResult::AlgorithmNotSupported) {
            return base::make_unexpected(CACResult::CertificateInvalid);
        }
        if (swResult != CACResult::Success) {
            return base::make_unexpected(swResult);
        }

        // Response: 53 L { 70 L <DER cert> 71 L <certinfo> [72 L <uid>] }
        const auto outer = parseTlvList(response);
        const auto dataObject = findTlv(outer, 0x53);
        if (!dataObject) {
            LOG(("CAC [PIV] GET DATA: no 53 data object in response."));
            return base::make_unexpected(CACResult::CertificateInvalid);
        }
        const auto entries = parseTlvList(dataObject->value);
        const auto certInfo = findTlv(entries, 0x71);
        if (certInfo && !certInfo->value.empty() && (certInfo->value[0] & 0x08)) {
            LOG(("CAC [PIV] Compressed certificate unsupported."));
            return base::make_unexpected(CACResult::CertificateInvalid);
        }
        const auto certificate = findTlv(entries, 0x70);
        if (!certificate || certificate->value.empty()) {
            LOG(("CAC [PIV] GET DATA: no 70 certificate in 53 object."));
            return base::make_unexpected(CACResult::CertificateInvalid);
        }

        auto parsed = parseCertificate(toBytesVector(certificate->value));
        if (!parsed) {
            return base::make_unexpected(CACResult::CertificateInvalid);
        }
        _parsedCert = std::move(parsed);
        return _parsedCert->der;
    }

    // ----- helpers -----------------------------------------------------------

    static void appendDerLength(std::vector<uint8_t> &out, size_t length) {
        if (length <= 0x7F) {
            out.push_back(uint8_t(length));
        } else if (length <= 0xFF) {
            out.push_back(0x81);
            out.push_back(uint8_t(length));
        } else {
            out.push_back(0x82);
            out.push_back(uint8_t(length >> 8));
            out.push_back(uint8_t(length & 0xFF));
        }
    }

    struct PivTlv {
        uint16_t tag = 0;
        std::vector<uint8_t> value;
    };

    static std::vector<PivTlv> parseTlvList(const std::vector<uint8_t> &buffer) {
        std::vector<PivTlv> result;
        size_t i = 0;
        while (i + 2 <= buffer.size()) {
            uint16_t tag = buffer[i++];
            if ((tag & 0x1F) == 0x1F && i < buffer.size()) {
                tag = uint16_t((tag << 8) | buffer[i++]);
            }
            if (i >= buffer.size()) {
                break;
            }
            const uint8_t first = buffer[i++];
            size_t length = 0;
            if (first < 0x80) {
                length = first;
            } else if (first == 0x81 && i < buffer.size()) {
                length = buffer[i++];
            } else if (first == 0x82 && i + 1 < buffer.size()) {
                length = (size_t(buffer[i]) << 8) | buffer[i + 1];
                i += 2;
            } else {
                break;
            }
            if (i + length > buffer.size()) {
                break;
            }
            result.push_back(
                {tag, std::vector<uint8_t>(buffer.begin() + i, buffer.begin() + i + long(length))});
            i += length;
        }
        return result;
    }

    static const PivTlv *findTlv(
            const std::vector<PivTlv> &list,
            uint16_t tag) {
        for (const auto &tlv : list) {
            if (tlv.tag == tag) {
                return &tlv;
            }
        }
        return nullptr;
    }

    static bytes::vector toBytesVector(const std::vector<uint8_t> &data) {
        bytes::vector result;
        result.reserve(data.size());
        for (const uint8_t byte : data) {
            result.push_back(static_cast<bytes::type>(byte));
        }
        return result;
    }

    static std::vector<uint8_t> _buildPkcs1V15Sha256Em(
            const unsigned char *digest,
            size_t digestLength) {
        // DigestInfo prefix for SHA-256 (RFC 8017, section 9.2 note 1).
        static const uint8_t kDigestInfoSha256[] = {
            0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
            0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
        };
        constexpr size_t kModulusBytes = 256; // RSA-2048
        const size_t tLength = std::size(kDigestInfoSha256) + digestLength;
        std::vector<uint8_t> em(kModulusBytes, 0xFF);
        em[0] = 0x00;
        em[1] = 0x01;
        const size_t ffLength = kModulusBytes - 3 - tLength; // >= 8 enforced by callers
        em[2 + ffLength] = 0x00;
        std::memcpy(em.data() + 3 + ffLength, kDigestInfoSha256, std::size(kDigestInfoSha256));
        std::memcpy(em.data() + 3 + ffLength + std::size(kDigestInfoSha256), digest, digestLength);
        return em;
    }

    static std::optional<ParsedCertificate> parseCertificate(
            const bytes::vector &der) {
        if (der.empty()) {
            return std::nullopt;
        }
        const auto *pointer = reinterpret_cast<const unsigned char *>(der.data());
        X509 *x509 = d2i_X509(nullptr, &pointer, unsigned(der.size()));
        if (!x509) {
            LOG(("CAC [PIV] d2i_X509 failed on the 9a certificate."));
            return std::nullopt;
        }

        ParsedCertificate parsed;
        parsed.der = der;
        parsed.subjectDn = dnToQString(X509_get_subject_name(x509));
        parsed.issuerDn = dnToQString(X509_get_issuer_name(x509));

        std::array<char, 256> commonName = {};
        X509_NAME_get_text_by_NID(
            X509_get_subject_name(x509), NID_commonName, commonName.data(), int(commonName.size()));
        parsed.commonName = QString::fromUtf8(commonName.data());

        if (const auto *serial = X509_get_serialNumber(x509)) {
            if (BIGNUM *bignum = BN_new()) {
                if (ASN1_INTEGER_to_BN(serial, bignum)) {
                    if (char *decimal = BN_bn2hex(bignum)) {
                        parsed.serialHex = QString::fromUtf8(decimal);
                        OPENSSL_free(decimal);
                    }
                }
                BN_free(bignum);
            }
        }

        parsed.notBefore = asn1TimeToQDateTime(X509_get_notBefore(x509));
        parsed.notAfter = asn1TimeToQDateTime(X509_get_notAfter(x509));
        const QDateTime now = QDateTime::currentDateTimeUtc();
        parsed.validAt = parsed.notBefore.isValid()
            && parsed.notAfter.isValid()
            && parsed.notBefore <= now
            && now <= parsed.notAfter;
        X509_free(x509);
        return parsed;
    }

    static QString dnToQString(const X509_NAME *name) {
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio) {
            return QString();
        }
        X509_NAME_print_ex(bio, const_cast<X509_NAME *>(name), 0, XN_FLAG_RFC2253);
        char *data = nullptr;
        const long length = BIO_get_mem_data(bio, &data);
        const QString result = QString::fromUtf8(data, int(length));
        BIO_free(bio);
        return result;
    }

    static QDateTime asn1TimeToQDateTime(const ASN1_TIME *time) {
        struct tm broken = {};
        if (!time || !ASN1_TIME_to_tm(time, &broken)) {
            return QDateTime();
        }
        return QDateTime::fromSecsSinceEpoch(qint64(timegm(&broken)), Qt::UTC);
    }

    // PC/SC + card session state. Mutable so const getters (isCardPresent)
    // can lazily establish context/connection without changing any logical
    // configuration.
    mutable std::mutex _mutex;
    mutable SCARDCONTEXT _context = 0;
    mutable bool _contextValid = false;
    mutable std::vector<std::string> _readerNames;
    mutable SCARDHANDLE _card = 0;
    mutable bool _cardValid = false;
    mutable DWORD _protocol = 0;
    mutable bool _pivSelected = false;

    // PIV session state (reset on reconnect).
    bool _pinVerified = false;
    int _pinAttempts = 3;
    std::optional<ParsedCertificate> _parsedCert;

    // Result of the last card status word.
    uint8_t _lastSw1 = 0;
    uint8_t _lastSw2 = 0;
    CACResult _lastError = CACResult::Success;

    CACAlgorithm _currentAlgorithm = CACAlgorithm::ECC_P384_SHA384;
};

#else // !CRYPTOGRAM_HAS_PCSC
// Fallback stub for Linux machines without the PC/SC headers. The backend
// reports "no card" exactly like before; see docs/CAC_YUBIKEY_PROVISIONING.md
// for the PC/SC + PIV implementation that gets compiled in with the headers
// installed (libpcsclite-dev).
class LinuxCACInterface : public CACInterface {
public:
    CACResult initialize() override {
        LOG(("CAC [PCSC] Built without PC/SC headers (libpcsclite-dev missing)."));
        return CACResult::CardNotFound;
    }

    bool isCardPresent() const override {
        return false;
    }

    bool isInitialized() const override {
        return false;
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
    CACAlgorithm _currentAlgorithm = CACAlgorithm::ECC_P384_SHA384;
};
#endif // CRYPTOGRAM_HAS_PCSC

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
