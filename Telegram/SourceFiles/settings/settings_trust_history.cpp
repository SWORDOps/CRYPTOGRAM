// Verification history UI
#include "settings/settings_trust_history.h"

#include "ui/wrap/vertical_layout.h"
#include "ui/widgets/labels.h"
#include "ui/widgets/buttons.h"
#include "ui/vertical_list.h"
#include "core/application.h"
#include "core/peer_trust.h"
#include "data/data_user.h"
#include "data/data_session.h"
#include "main/main_session.h"
#include "window/window_session_controller.h"
#include "styles/style_settings.h"
#include "styles/style_menu_icons.h"

namespace Settings {

TrustHistory::TrustHistory(
    QWidget *parent,
    not_null<Window::SessionController*> controller)
: Section(parent)
, _controller(controller) {
    setupContent();
}

rpl::producer<QString> TrustHistory::title() {
    return rpl::single(QString("Verified Identities"));
}

void TrustHistory::setupContent() {
    const auto content = Ui::CreateChild<Ui::VerticalLayout>(this);

    auto trustManager = Core::App().peerTrustManager();
    if (!trustManager || !trustManager->isEnabled()) {
        content->add(
            object_ptr<Ui::FlatLabel>(
                content,
                rpl::single(QString(
                    "Device trust is not enabled.\n\n"
                    "Enable it in CRYPTOGRAM settings to verify "
                    "identities of other users with CAC cards.")),
                st::boxLabel),
            st::settingsPadding);

        Ui::ResizeFitChild(this, content);
        return;
    }

    const auto trustedPeers = trustManager->getTrustedPeers();

    if (trustedPeers.empty()) {
        content->add(
            object_ptr<Ui::FlatLabel>(
                content,
                rpl::single(QString(
                    "No verified identities yet.\n\n"
                    "Verify other users with CAC cards using the "
                    "\"Verify Identity\" option in their profile menu.")),
                st::boxLabel),
            st::settingsPadding);
    } else {
        Ui::AddSkip(content);
        Ui::AddSubsectionTitle(
            content,
            rpl::single(QString("Verified Users")));

        for (const auto &[userId, trustInfo] : trustedPeers) {
            const auto user = _controller->session().data().user(userId);

            const auto domain = (trustInfo.domain == "US_DOD") ? "US DoD"
                : (trustInfo.domain == "UK_MOD") ? "UK MOD"
                : (trustInfo.domain == "NATO") ? "NATO"
                : (trustInfo.domain == "IT_MOD") ? "Italian Defense"
                : (trustInfo.domain == "CA_DND") ? "Canadian Forces"
                : (trustInfo.domain == "AU_ADF") ? "Australian Defense"
                : trustInfo.domain;

            const auto row = content->add(object_ptr<Ui::SettingsButton>(
                content,
                rpl::single(QString("%1 %2").arg(
                    trustInfo.flag,
                    user->name())),
                st::settingsButton));

            const auto verified = trustInfo.verifiedAt.toString("yyyy-MM-dd");
            const auto expires = trustInfo.expiresAt.toString("yyyy-MM-dd");

            row->setClickedCallback([=] {
                Ui::show(Ui::MakeInformBox(
                    QString("CAC Verified Identity\n\n"
                        "User: %1\n"
                        "Domain: %2\n"
                        "Verified: %3\n"
                        "Expires: %4")
                        .arg(user->name())
                        .arg(domain)
                        .arg(verified)
                        .arg(expires)));
            });
        }

        Ui::AddSkip(content);
        Ui::AddDividerText(
            content,
            rpl::single(QString(
                "Verified identities expire after 6 months. "
                "Re-verify to extend trust period.")));
    }

    Ui::ResizeFitChild(this, content);
}

} // namespace Settings
