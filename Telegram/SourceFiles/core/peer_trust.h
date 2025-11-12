#pragma once

#include "credential_helper.h"
#include <QObject>
#include <QString>
#include <QByteArray>
#include <QDateTime>
#include <map>
#include <memory>

namespace Core {

struct PeerTrustInfo {
    uint64 userId;
    QString domain;
    QString flag;
    QByteArray certificate;
    QDateTime verifiedAt;
    QDateTime expiresAt;
    bool verified = false;
};

class PeerTrustManager : public QObject {
    Q_OBJECT

public:
    explicit PeerTrustManager(QObject *parent = nullptr);
    ~PeerTrustManager();

    [[nodiscard]] bool isEnabled() const;
    void setEnabled(bool enabled);

    [[nodiscard]] bool hasPeerTrust(uint64 userId) const;
    [[nodiscard]] PeerTrustInfo getPeerTrust(uint64 userId) const;

    void requestVerification(uint64 userId);
    void respondToChallenge(uint64 userId, const QByteArray &challenge);

    [[nodiscard]] QByteArray generateChallenge();
    [[nodiscard]] std::map<uint64, PeerTrustInfo> getTrustedPeers() const;

    [[nodiscard]] QString getPreferredCipher() const;
    void setPreferredCipher(const QString &cipher);

Q_SIGNALS:
    void verificationRequested(uint64 userId, QByteArray challenge);
    void verificationComplete(uint64 userId, bool success);
    void peerVerified(uint64 userId, QString domain);

private:
    class Private;
    std::unique_ptr<Private> _private;

    void handleChallengeResponse(
        uint64 userId,
        const QByteArray &signature,
        const QByteArray &certificate);

    void storePeerTrust(uint64 userId, const PeerTrustInfo &info);
    void loadPeerTrusts();
    void savePeerTrusts();
};

} // namespace Core
