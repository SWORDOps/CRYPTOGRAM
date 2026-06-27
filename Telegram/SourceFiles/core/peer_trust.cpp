#include "peer_trust.h"
#include "credential_helper.h"
#include "core/application.h"
#include "storage/storage_account.h"

#include <QSettings>
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QStandardPaths>
#include <QObject>

namespace Core {

class PeerTrustManager::Private {
public:
    std::unique_ptr<CredentialHelper> credHelper;
    std::unique_ptr<TrustValidator> validator;
    std::map<uint64, PeerTrustInfo> trustedPeers;
    std::map<uint64, QByteArray> pendingChallenges;

    bool enabled = false;
    QString preferredCipher = "AES256-GCM";

    QSettings *settings = nullptr;
};

PeerTrustManager::PeerTrustManager(QObject *parent)
    : QObject(parent)
    , _private(std::make_unique<Private>()) {

    _private->credHelper = std::make_unique<CredentialHelper>(this);
    _private->validator = std::make_unique<TrustValidator>();

    auto appDataPath = QStandardPaths::writableLocation(
        QStandardPaths::AppDataLocation);
    _private->settings = new QSettings(
        appDataPath + "/peer_trust.ini",
        QSettings::IniFormat,
        this);

    loadPeerTrusts();
}

PeerTrustManager::~PeerTrustManager() {
    savePeerTrusts();
}

bool PeerTrustManager::isEnabled() const {
    return _private->enabled;
}

void PeerTrustManager::setEnabled(bool enabled) {
    _private->enabled = enabled;
    _private->settings->setValue("enabled", enabled);
}

bool PeerTrustManager::hasPeerTrust(uint64 userId) const {
    auto it = _private->trustedPeers.find(userId);
    if (it == _private->trustedPeers.end()) {
        return false;
    }

    return it->second.verified &&
           it->second.expiresAt > QDateTime::currentDateTime();
}

PeerTrustInfo PeerTrustManager::getPeerTrust(uint64 userId) const {
    auto it = _private->trustedPeers.find(userId);
    if (it != _private->trustedPeers.end()) {
        return it->second;
    }
    return PeerTrustInfo();
}

void PeerTrustManager::requestVerification(uint64 userId) {
    auto challenge = generateChallenge();
    _private->pendingChallenges[userId] = challenge;

    Q_EMIT verificationRequested(userId, challenge);
}

std::map<uint64, PeerTrustInfo> PeerTrustManager::getTrustedPeers() const {
    return _private->trustedPeers;
}

QByteArray PeerTrustManager::generateChallenge() {
    QByteArray challenge(32, 0);
    for (int i = 0; i < 32; ++i) {
        challenge[i] = static_cast<char>(
            QRandomGenerator::global()->bounded(256));
    }

    auto timestamp = QDateTime::currentSecsSinceEpoch();
    challenge.append(reinterpret_cast<const char*>(&timestamp), sizeof(timestamp));

    return challenge;
}

void PeerTrustManager::respondToChallenge(
    uint64 userId,
    const QByteArray &challenge) {

    auto cred = _private->credHelper->readToken();
    if (!cred) {
        Q_EMIT verificationComplete(userId, false);
        return;
    }

    QString pin;

    auto signature = _private->credHelper->signData(challenge, pin);
    if (!signature) {
        Q_EMIT verificationComplete(userId, false);
        return;
    }

}

void PeerTrustManager::handleChallengeResponse(
    uint64 userId,
    const QByteArray &signature,
    const QByteArray &certificate) {

    auto it = _private->pendingChallenges.find(userId);
    if (it == _private->pendingChallenges.end()) {
        Q_EMIT verificationComplete(userId, false);
        return;
    }

    const auto &challenge = it->second;

    if (!_private->validator->validateChain(certificate)) {
        Q_EMIT verificationComplete(userId, false);
        _private->pendingChallenges.erase(it);
        return;
    }

    if (!_private->validator->checkRevocation(certificate)) {
        Q_EMIT verificationComplete(userId, false);
        _private->pendingChallenges.erase(it);
        return;
    }

    DeviceCredential cred;
    cred.certificate = certificate;
    cred.isValid = true;

    if (!_private->credHelper->verifySignature(cred, challenge, signature)) {
        Q_EMIT verificationComplete(userId, false);
        _private->pendingChallenges.erase(it);
        return;
    }

    auto domain = _private->validator->getTrustDomain(certificate);
    auto flag = _private->validator->getDomainFlag(domain);

    PeerTrustInfo info;
    info.userId = userId;
    info.domain = domain;
    info.flag = flag;
    info.certificate = certificate;
    info.verifiedAt = QDateTime::currentDateTime();
    info.expiresAt = info.verifiedAt.addMonths(6);
    info.verified = true;

    storePeerTrust(userId, info);

    Q_EMIT verificationComplete(userId, true);
    Q_EMIT peerVerified(userId, domain);

    _private->pendingChallenges.erase(it);
}

void PeerTrustManager::storePeerTrust(uint64 userId, const PeerTrustInfo &info) {
    _private->trustedPeers[userId] = info;
    savePeerTrusts();
}

void PeerTrustManager::loadPeerTrusts() {
    int count = _private->settings->beginReadArray("trusts");
    for (int i = 0; i < count; ++i) {
        _private->settings->setArrayIndex(i);

        PeerTrustInfo info;
        info.userId = _private->settings->value("userId").toULongLong();
        info.domain = _private->settings->value("domain").toString();
        info.flag = _private->settings->value("flag").toString();
        info.certificate = _private->settings->value("cert").toByteArray();
        info.verifiedAt = _private->settings->value("verified").toDateTime();
        info.expiresAt = _private->settings->value("expires").toDateTime();
        info.verified = true;

        if (info.expiresAt > QDateTime::currentDateTime()) {
            _private->trustedPeers[info.userId] = info;
        }
    }
    _private->settings->endArray();

    _private->enabled = _private->settings->value("enabled", false).toBool();
}

void PeerTrustManager::savePeerTrusts() {
    _private->settings->beginWriteArray("trusts");
    int idx = 0;
    for (const auto &[userId, info] : _private->trustedPeers) {
        if (info.expiresAt > QDateTime::currentDateTime()) {
            _private->settings->setArrayIndex(idx++);
            _private->settings->setValue("userId", userId);
            _private->settings->setValue("domain", info.domain);
            _private->settings->setValue("flag", info.flag);
            _private->settings->setValue("cert", info.certificate);
            _private->settings->setValue("verified", info.verifiedAt);
            _private->settings->setValue("expires", info.expiresAt);
        }
    }
    _private->settings->endArray();
    _private->settings->sync();
}

QString PeerTrustManager::getPreferredCipher() const {
    return _private->preferredCipher;
}

void PeerTrustManager::setPreferredCipher(const QString &cipher) {
    _private->preferredCipher = cipher;
    _private->settings->setValue("cipher", cipher);
}

} // namespace Core
