#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <memory>
#include <vector>
#include <rpl/producer.h>

namespace Core {

struct TSMSession {
    QString id;
    QString name;
    int64_t created = 0;
    int64_t size = 0;
    bool encrypted = false;

    bool operator==(const TSMSession &other) const = default;
};

class TSMClient : public QObject {
    Q_OBJECT

public:
    explicit TSMClient(QObject *parent = nullptr);
    ~TSMClient();

    void connect(const QString &address = "localhost:50051");
    [[nodiscard]] bool isConnected() const;

    [[nodiscard]] rpl::producer<std::vector<TSMSession>> sessionsValue() const;
    void refreshSessions();

    void startZKAuth(const QString &username);
    void verifyZKProof(const QString &username, const QString &proof);

    [[nodiscard]] rpl::producer<bool> authSuccess() const;
    [[nodiscard]] rpl::producer<QString> authError() const;

private:
    class Private;
    std::unique_ptr<Private> _private;

};

} // namespace Core
