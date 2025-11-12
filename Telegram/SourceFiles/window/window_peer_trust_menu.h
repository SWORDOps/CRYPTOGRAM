// Peer trust menu actions
#pragma once

namespace Ui {
class PopupMenu;
} // namespace Ui

namespace Main {
class Session;
} // namespace Main

namespace Window::PeerTrustMenu {

void AddVerifyIdentityAction(
    not_null<Ui::PopupMenu*> menu,
    not_null<Main::Session*> session,
    not_null<UserData*> user,
    Fn<void()> callback = nullptr);

bool HasVerifyIdentityAction(
    not_null<Main::Session*> session,
    not_null<UserData*> user);

} // namespace Window::PeerTrustMenu
