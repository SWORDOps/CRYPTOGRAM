// Trust flag indicator for verified peers
#include "info/profile/info_profile_trust_flag.h"

#include "ui/widgets/labels.h"
#include "base/event_filter.h"
#include "styles/style_info.h"

namespace Info::Profile {

TrustFlag::TrustFlag(
    not_null<QWidget*> parent,
    QString flag,
    QString domain,
    QDateTime verifiedAt)
: _widget(object_ptr<Ui::RpWidget>(parent))
, _flag(flag)
, _domain(domain)
, _verifiedAt(verifiedAt) {

    const auto label = Ui::CreateChild<Ui::FlatLabel>(
        _widget.data(),
        rpl::single(_flag),
        st::infoProfileStatus);

    const auto size = label->naturalWidth();
    _widget->resize(size, label->height());
    label->resizeToWidth(size);
    label->show();

    base::install_event_filter(_widget.data(), [=](not_null<QEvent*> e) {
        if (e->type() == QEvent::Enter || e->type() == QEvent::Leave) {
            Ui::Tooltip::Show(1000, this);
        }
        return base::EventFilterResult::Continue;
    }, _widget->lifetime());
}

Ui::RpWidget *TrustFlag::widget() const {
    return _widget.data();
}

int TrustFlag::width() const {
    return _widget->width();
}

void TrustFlag::move(int left, int top) {
    _widget->move(left, top);
}

QString TrustFlag::tooltipText() const {
    const auto domainName = (_domain == "US_DOD") ? "US DoD"
        : (_domain == "UK_MOD") ? "UK MOD"
        : (_domain == "NATO") ? "NATO"
        : (_domain == "IT_MOD") ? "Italian Defense"
        : (_domain == "CA_DND") ? "Canadian Forces"
        : (_domain == "AU_ADF") ? "Australian Defense"
        : _domain;

    return QString("CAC Verified\n%1\nVerified: %2")
        .arg(domainName)
        .arg(_verifiedAt.toString("yyyy-MM-dd"));
}

QPoint TrustFlag::tooltipPos() const {
    return _widget->mapToGlobal(
        QPoint(_widget->width() / 2, _widget->height()));
}

bool TrustFlag::tooltipWindowActive() const {
    return _widget->window()->isActiveWindow();
}

} // namespace Info::Profile
