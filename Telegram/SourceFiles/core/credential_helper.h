#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <memory>
#include <optional>

namespace Core {

struct DeviceCredential {
    QString subjectName;
    QString issuerName;
    QByteArray publicKey;
    QByteArray certificate;
    QDateTime expiryDate;
    QString countryCode;
    bool isValid = false;
};

class CredentialHelper : public QObject {
    Q_OBJECT

public:
    explicit CredentialHelper(QObject *parent = nullptr);
    ~CredentialHelper();

    [[nodiscard]] bool hasSecureToken() const;
    [[nodiscard]] std::optional<DeviceCredential> readToken();
    [[nodiscard]] std::optional<QByteArray> signData(
        const QByteArray &data,
        const QString &pin);
    [[nodiscard]] bool verifySignature(
        const DeviceCredential &cred,
        const QByteArray &data,
        const QByteArray &signature);

Q_SIGNALS:
    void tokenInserted();
    void tokenRemoved();

private:
    class Private;
    std::unique_ptr<Private> _private;

    bool initializeCardReader();
    void cleanupCardReader();
    DeviceCredential parseX509Certificate(const QByteArray &certData);
};

class TrustValidator {
public:
    TrustValidator();

    [[nodiscard]] bool validateChain(const QByteArray &certificate);
    [[nodiscard]] bool checkRevocation(const QByteArray &certificate);
    [[nodiscard]] QString getTrustDomain(const QByteArray &certificate);
    [[nodiscard]] QString getDomainFlag(const QString &domain);

private:
    struct TrustRoot {
        QString name;
        QString domain;
        QString flag;
        QByteArray rootCert;
        QStringList crlUrls;
        QStringList ocspUrls;
    };

    std::vector<TrustRoot> _roots;

    void initializeTrustRoots();
    bool verifyAgainstRoot(const QByteArray &cert, const TrustRoot &root);
};

} // namespace Core
