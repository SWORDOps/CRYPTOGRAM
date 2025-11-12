// Peer trust menu actions
#include "window/window_peer_trust_menu.h"

#include "ui/widgets/popup_menu.h"
#include "core/application.h"
#include "core/peer_trust.h"
#include "data/data_user.h"
#include "main/main_session.h"
#include "boxes/device_trust_box.h"
#include "ui/boxes/confirm_box.h"

namespace Window::PeerTrustMenu {

bool HasVerifyIdentityAction(
    not_null<Main::Session*> session,
    not_null<UserData*> user) {

    if (user->isSelf() || user->isBot()) {
        return false;
    }

    auto trustManager = Core::App().peerTrustManager();
    if (!trustManager || !trustManager->isEnabled()) {
        return false;
    }

    return true;
}

void AddVerifyIdentityAction(
    not_null<Ui::PopupMenu*> menu,
    not_null<Main::Session*> session,
    not_null<UserData*> user,
    Fn<void()> callback) {

    if (!HasVerifyIdentityAction(session, user)) {
        return;
    }

    auto trustManager = Core::App().peerTrustManager();
    const auto hasTrust = trustManager->hasPeerTrust(user->id);

    const auto text = hasTrust
        ? QString("Re-verify Identity")
        : QString("Verify Identity (CAC)");

    menu->addAction(text, [=] {
        auto challenge = trustManager->generateChallenge();

        Ui::show(Box<VerifyIdentityBox>(
            session,
            user,
            challenge));

        if (callback) {
            callback();
        }
    });
}

} // namespace Window::PeerTrustMenu
