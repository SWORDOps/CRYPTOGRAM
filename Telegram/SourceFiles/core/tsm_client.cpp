#include "core/tsm_client.h"
#include <grpcpp/grpcpp.h>
#include "TSMService.grpc.pb.h"
#include <rpl/variable.h>
#include <rpl/event_stream.h>
#include <crl/crl_async.h>

namespace Core {

class TSMClient::Private {
public:
    std::unique_ptr<tsm::TSMService::Stub> stub;
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
    auto channel = grpc::CreateChannel(
        address.toStdString(),
        grpc::InsecureChannelCredentials());
    _private->stub = tsm::TSMService::NewStub(channel);
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
    if (!_private->stub) return;

    crl::async([=] {
        tsm::Empty request;
        tsm::SessionList response;
        grpc::ClientContext context;

        auto status = _private->stub->ListSessions(&context, request, &response);
        if (status.ok()) {
            std::vector<TSMSession> list;
            for (const auto &s : response.sessions()) {
                list.push_back({
                    QString::fromStdString(s.id()),
                    QString::fromStdString(s.name()),
                    s.created_timestamp(),
                    s.size_bytes(),
                    s.is_encrypted()
                });
            }
            crl::on_main([=, list = std::move(list)] {
                _private->sessions = std::move(list);
            });
        }
    });
}

void TSMClient::startZKAuth(const QString &username) {
    if (!_private->stub) return;

    crl::async([=] {
        tsm::ZKAuthenticationRequest request;
        request.set_username(username.toStdString());
        
        tsm::ZKChallengeResponse response;
        grpc::ClientContext context;

        auto status = _private->stub->StartZKAuthentication(&context, request, &response);
        if (status.ok()) {
            auto challenge = QString::fromStdString(response.h());
            // In a real app, we'd emit a challengeReceived signal
        } else {
            crl::on_main([=] {
                _private->authError.fire(QString::fromStdString(status.error_message()));
            });
        }
    });
}

void TSMClient::verifyZKProof(const QString &username, const QString &proof) {
    if (!_private->stub) return;

    crl::async([=] {
        tsm::ZKProofRequest request;
        request.set_username(username.toStdString());
        request.set_proof(proof.toStdString());
        
        tsm::ZKProofResponse response;
        grpc::ClientContext context;

        auto status = _private->stub->VerifyZKProof(&context, request, &response);
        if (status.ok()) {
            crl::on_main([=] {
                _private->authSuccess.fire(true);
            });
        } else {
            crl::on_main([=] {
                _private->authError.fire(QString::fromStdString(status.error_message()));
            });
        }
    });
}

rpl::producer<bool> TSMClient::authSuccess() const {
    return _private->authSuccess.events();
}

rpl::producer<QString> TSMClient::authError() const {
    return _private->authError.events();
}

} // namespace Core
