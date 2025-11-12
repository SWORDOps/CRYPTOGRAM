// Verification history UI
#pragma once

#include "settings/settings_common_session.h"

namespace Settings {

class TrustHistory : public Section<TrustHistory> {
public:
    TrustHistory(
        QWidget *parent,
        not_null<Window::SessionController*> controller);

    [[nodiscard]] rpl::producer<QString> title() override;

private:
    void setupContent();

    const not_null<Window::SessionController*> _controller;

};

} // namespace Settings
