#include "core/tsm_client.h"
#include <rpl/variable.h>
#include <rpl/event_stream.h>

namespace Core {

class TSMClient::Private {
public:
    rpl::variable<std::vector<TSMSession>> sessions;
    rpl::event_stream<bool> authSuccess;
    rpl::event_stream<QString> authError;
    bool connected = false;
};

TSMClient::TSMClient(QObject *parent)
    : QObject(parent)
    , _private(std::make_unique<Private>()) {
}

TSMClient::~TSMClient() = default;

void TSMClient::connect(const QString &address) {
    _private->connected = true;
    refreshSessions();
}

bool TSMClient::isConnected() const {
    return _private->connected;
}

rpl::producer<std::vector<TSMSession>> TSMClient::sessionsValue() const {
    return _private->sessions.value();
}

void TSMClient::refreshSessions() {
    _private->sessions = std::vector<TSMSession>();
}

void TSMClient::startZKAuth(const QString &username) {
}

void TSMClient::verifyZKProof(const QString &username, const QString &proof) {
}

rpl::producer<bool> TSMClient::authSuccess() const {
    return _private->authSuccess.events();
}

rpl::producer<QString> TSMClient::authError() const {
    return _private->authError.events();
}

} // namespace Core
