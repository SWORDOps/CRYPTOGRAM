// Device trust verification dialogs
#include "boxes/device_trust_box.h"

#include "lang/lang_keys.h"
#include "ui/widgets/labels.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/input_fields.h"
#include "ui/wrap/vertical_layout.h"
#include "ui/wrap/padding_wrap.h"
#include "core/application.h"
#include "core/peer_trust.h"
#include "data/data_user.h"
#include "main/main_session.h"
#include "styles/style_layers.h"
#include "styles/style_boxes.h"

VerifyIdentityBox::VerifyIdentityBox(
    QWidget*,
    not_null<Main::Session*> session,
    not_null<UserData*> user,
    QByteArray challenge)
: _session(session)
, _user(user)
, _challenge(challenge) {
}

void VerifyIdentityBox::prepare() {
    setTitle(rpl::single(QString("Verify Identity")));

    const auto content = Ui::CreateChild<Ui::VerticalLayout>(this);

    content->add(
        object_ptr<Ui::FlatLabel>(
            content,
            rpl::single(QString(
                "Insert your CAC card and enter your PIN to verify "
                "your identity to %1.").arg(_user->name())),
            st::boxLabel),
        st::boxPadding);

    _pin = content->add(
        object_ptr<Ui::InputField>(
            content,
            st::defaultInputField,
            rpl::single(QString("CAC PIN")),
            QString()),
        st::boxPadding);

    _pin->setMaxLength(8);
    _pin->setPlaceholderHidden(false);

    connect(_pin, &Ui::InputField::submitted, [=] { verify(); });

    addButton(rpl::single(QString("Cancel")), [=] { closeBox(); });
    _verifyButton = addButton(
        rpl::single(QString("Verify")),
        [=] { verify(); });

    setDimensionsToContent(st::boxWidth, content);
    _pin->setFocus();
}

void VerifyIdentityBox::verify() {
    const auto pin = _pin->getLastText();
    if (pin.isEmpty()) {
        _pin->showError();
        return;
    }

    updateState(true);

    auto trustManager = Core::App().peerTrustManager();
    if (!trustManager) {
        closeBox();
        return;
    }

    trustManager->respondToChallenge(_user->id, _challenge);

    QObject::connect(
        trustManager,
        &Core::PeerTrustManager::verificationComplete,
        this,
        [=](uint64 userId, bool success) {
            if (userId == _user->id) {
                if (success) {
                    Ui::show(Ui::MakeInformBox(
                        QString("Identity verified successfully!")));
                } else {
                    Ui::show(Ui::MakeInformBox(
                        QString("Verification failed. Please try again.")));
                }
                closeBox();
            }
        });
}

void VerifyIdentityBox::updateState(bool verifying) {
    _pin->setDisabled(verifying);
    if (_verifyButton) {
        _verifyButton->setText(verifying
            ? rpl::single(QString("Verifying..."))
            : rpl::single(QString("Verify")));
        _verifyButton->setDisabled(verifying);
    }
}

RespondChallengeBox::RespondChallengeBox(
    QWidget*,
    not_null<Main::Session*> session,
    not_null<UserData*> requestingUser,
    QByteArray challenge)
: _session(session)
, _requestingUser(requestingUser)
, _challenge(challenge) {
}

void RespondChallengeBox::prepare() {
    setTitle(rpl::single(QString("Identity Verification Request")));

    const auto content = Ui::CreateChild<Ui::VerticalLayout>(this);

    content->add(
        object_ptr<Ui::FlatLabel>(
            content,
            rpl::single(QString(
                "%1 is requesting to verify your identity.\n\n"
                "Insert your CAC card and enter your PIN to respond.")
                .arg(_requestingUser->name())),
            st::boxLabel),
        st::boxPadding);

    _pin = content->add(
        object_ptr<Ui::InputField>(
            content,
            st::defaultInputField,
            rpl::single(QString("CAC PIN")),
            QString()),
        st::boxPadding);

    _pin->setMaxLength(8);
    _pin->setPlaceholderHidden(false);

    connect(_pin, &Ui::InputField::submitted, [=] { respond(); });

    addButton(rpl::single(QString("Decline")), [=] { closeBox(); });
    _respondButton = addButton(
        rpl::single(QString("Respond")),
        [=] { respond(); });

    setDimensionsToContent(st::boxWidth, content);
    _pin->setFocus();
}

void RespondChallengeBox::respond() {
    const auto pin = _pin->getLastText();
    if (pin.isEmpty()) {
        _pin->showError();
        return;
    }

    updateState(true);

    auto trustManager = Core::App().peerTrustManager();
    if (!trustManager) {
        closeBox();
        return;
    }

    trustManager->respondToChallenge(_requestingUser->id, _challenge);

    Ui::show(Ui::MakeInformBox(
        QString("Response sent. Verification in progress...")));
    closeBox();
}

void RespondChallengeBox::updateState(bool responding) {
    _pin->setDisabled(responding);
    if (_respondButton) {
        _respondButton->setText(responding
            ? rpl::single(QString("Responding..."))
            : rpl::single(QString("Respond")));
        _respondButton->setDisabled(responding);
    }
}
