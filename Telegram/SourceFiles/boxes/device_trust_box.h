// Device trust verification dialogs
#pragma once

#include "boxes/abstract_box.h"
#include "core/peer_trust.h"

class UserData;

namespace Ui {
class InputField;
class FlatButton;
} // namespace Ui

namespace Main {
class Session;
} // namespace Main

class VerifyIdentityBox : public Ui::BoxContent {
public:
    VerifyIdentityBox(
        QWidget*,
        not_null<Main::Session*> session,
        not_null<UserData*> user,
        QByteArray challenge);

protected:
    void prepare() override;

private:
    void verify();
    void updateState(bool verifying);

    const not_null<Main::Session*> _session;
    const not_null<UserData*> _user;
    QByteArray _challenge;

    QPointer<Ui::InputField> _pin;
    QPointer<Ui::FlatButton> _verifyButton;

};

class RespondChallengeBox : public Ui::BoxContent {
public:
    RespondChallengeBox(
        QWidget*,
        not_null<Main::Session*> session,
        not_null<UserData*> requestingUser,
        QByteArray challenge);

protected:
    void prepare() override;

private:
    void respond();
    void updateState(bool responding);

    const not_null<Main::Session*> _session;
    const not_null<UserData*> _requestingUser;
    QByteArray _challenge;

    QPointer<Ui::InputField> _pin;
    QPointer<Ui::FlatButton> _respondButton;

};
