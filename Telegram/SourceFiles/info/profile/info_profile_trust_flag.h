// Trust flag indicator for verified peers
#pragma once

#include "ui/widgets/tooltip.h"
#include "ui/text/text_utilities.h"

namespace Ui {
class RpWidget;
} // namespace Ui

namespace Info::Profile {

class TrustFlag final : public Ui::AbstractTooltipShower {
public:
    TrustFlag(
        not_null<QWidget*> parent,
        QString flag,
        QString domain,
        QDateTime verifiedAt);

    [[nodiscard]] Ui::RpWidget *widget() const;
    [[nodiscard]] int width() const;

    void move(int left, int top);

    QString tooltip() const override;
    QPoint tooltipPos() const override;
    bool tooltipWindowActive() const override;

private:
    object_ptr<Ui::RpWidget> _widget;
    QString _flag;
    QString _domain;
    QDateTime _verifiedAt;

};

} // namespace Info::Profile
