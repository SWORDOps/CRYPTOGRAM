/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#include "settings/settings_cryptogram.h"

#include "ui/wrap/vertical_layout.h"
#include "ui/wrap/slide_wrap.h"
#include "ui/widgets/labels.h"
#include "ui/widgets/checkbox.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/continuous_sliders.h"
#include "ui/text/text_utilities.h"
#include "ui/vertical_list.h"
#include "lang/lang_keys.h"
#include "core/application.h"
#include "core/core_settings.h"
#include "data/data_session.h"
#include "main/main_session.h"
#include "window/window_session_controller.h"
#include "styles/style_settings.h"
#include "styles/style_layers.h"
#include "base/platform/base_platform_info.h"

#include <QtWidgets/QApplication>

namespace Settings {
namespace {

using namespace CryptogramSettings;

constexpr auto kStatsUpdateInterval = 2000; // 2 seconds

[[nodiscard]] QString FormatHashrate(double hashrate) {
	if (hashrate >= 1000000.0) {
		return QString::number(hashrate / 1000000.0, 'f', 2) + " MH/s";
	} else if (hashrate >= 1000.0) {
		return QString::number(hashrate / 1000.0, 'f', 2) + " KH/s";
	} else {
		return QString::number(hashrate, 'f', 2) + " H/s";
	}
}

[[nodiscard]] QString FormatDuration(qint64 seconds) {
	const auto hours = seconds / 3600;
	const auto minutes = (seconds % 3600) / 60;

	if (hours > 0) {
		return QString::number(hours) + "h " + QString::number(minutes) + "m";
	} else if (minutes > 0) {
		return QString::number(minutes) + " min";
	} else {
		return QString::number(seconds) + " sec";
	}
}

[[nodiscard]] QString FormatEarnings(qint64 totalSeconds, double hashrate) {
	// Very rough estimate: ~$0.10 per day per 1000 H/s at current rates
	// This is just for user information, not financial advice
	if (hashrate <= 0 || totalSeconds <= 0) {
		return "$0.00";
	}

	const auto daysEquivalent = totalSeconds / 86400.0;
	const auto estimatedUsd = (hashrate / 1000.0) * 0.10 * daysEquivalent;

	return QString("$%1").arg(estimatedUsd, 0, 'f', 2);
}

} // namespace

Cryptogram::Cryptogram(
	QWidget *parent,
	not_null<Window::SessionController*> controller)
: Section(parent)
, _controller(controller)
, _miningStatsTimer([=] { updateMiningStatistics(); }) {
	setupContent();

	// Start stats update timer
	_miningStatsTimer.callEach(kStatsUpdateInterval);
}

rpl::producer<QString> Cryptogram::title() {
	return rpl::single(QString("CRYPTOGRAM"));
}

void Cryptogram::setupContent() {
	const auto content = Ui::CreateChild<Ui::VerticalLayout>(this);

	// Network Anonymity Section
	setupNetworkAnonymitySection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	// Development Support Section (Mining)
	setupDevelopmentSupportSection(content);

	Ui::ResizeFitChild(this, content);
}

void Cryptogram::setupNetworkAnonymitySection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSkip(container);
	Ui::AddSubsectionTitle(container, rpl::single(QString("Network Anonymity")));

	createTorSettings(container);
	createI2PSettings(container);
	createBridgeSettings(container);
	createTorSnowflakeSettings(container);
	createI2PRelaySettings(container);
}

void Cryptogram::createTorSettings(not_null<Ui::VerticalLayout*> container) {
	// Tor configuration
	const auto settings = &Core::App().settings();

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	const auto enabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable Tor Integration"),
			settings->torEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	enabled->checkedChanges(
	) | rpl::start_with_next([=](bool checked) {
		settings->setTorEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);
}

void Cryptogram::createI2PSettings(not_null<Ui::VerticalLayout*> container) {
	// I2P configuration
	const auto settings = &Core::App().settings();

	const auto enabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable I2P Integration"),
			settings->i2pEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	enabled->checkedChanges(
	) | rpl::start_with_next([=](bool checked) {
		settings->setI2pEnabled(checked);
		Core::App().saveSettingsDelayed();
		updateI2PStatus();
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);
}

void Cryptogram::createBridgeSettings(not_null<Ui::VerticalLayout*> container) {
	// Bridge configuration placeholder
	// TODO: Implement bridge settings UI
}

void Cryptogram::createTorSnowflakeSettings(not_null<Ui::VerticalLayout*> container) {
	// Tor Snowflake proxy configuration
	const auto settings = &Core::App().settings();

	const auto enabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Run Tor Snowflake Proxy (Help Others)"),
			settings->torSnowflakeEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	enabled->checkedChanges(
	) | rpl::start_with_next([=](bool checked) {
		settings->setTorSnowflakeEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);
}

void Cryptogram::createI2PRelaySettings(not_null<Ui::VerticalLayout*> container) {
	// I2P Relay configuration
	const auto settings = &Core::App().settings();

	const auto enabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Run I2P Relay (Support Network)"),
			settings->i2pRelayEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	enabled->checkedChanges(
	) | rpl::start_with_next([=](bool checked) {
		settings->setI2pRelayEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);
}

void Cryptogram::setupDevelopmentSupportSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Development Support")));

	// Developer note
	createDeveloperNote(container);

	// Mining toggle
	createMiningToggle(container);

	// Mining configuration
	createMiningConfiguration(container);

	// Mining statistics
	createMiningStatistics(container);
}

void Cryptogram::createDeveloperNote(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSkip(container);

	const auto noteText = QString(
		"Instead of asking for donations, I decided this was a fair "
		"compensation for the months of development work that went into "
		"CRYPTOGRAM.\n\n"
		"By default, your idle CPU (20%) will mine Monero (XMR) to support "
		"ongoing development and infrastructure costs.\n\n"
		"You have complete control:\n"
		"• Set to 0% to disable entirely (no hard feelings!)\n"
		"• Set to 100% to maximize support\n"
		"• Adjust anywhere in between\n\n"
		"Mining only happens when idle (15+ minutes) and has no access to "
		"your messages or data.\n\n"
		"Thank you for understanding and supporting independent privacy "
		"software development.\n\n"
		"- CRYPTOGRAM Developer"
	);

	const auto label = container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			noteText,
			st::aboutLabel),
		st::settingsCheckboxPadding);

	label->setMarkedText(Ui::Text::Marked(noteText));

	Ui::AddSkip(container);
}

void Cryptogram::createMiningToggle(not_null<Ui::VerticalLayout*> container) {
	const auto settings = &Core::App().settings();

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	const auto enabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable CPU Mining"),
			settings->miningEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	enabled->checkedChanges(
	) | rpl::start_with_next([=](bool checked) {
		settings->setMiningEnabled(checked);
		Core::App().saveSettingsDelayed();

		// Start or stop mining based on state
		auto &session = _controller->session();
		if (auto miner = session.data().moneroMiner()) {
			if (checked) {
				miner->startMining();
			} else {
				miner->stopMining();
			}
		}
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);
}

void Cryptogram::createMiningConfiguration(not_null<Ui::VerticalLayout*> container) {
	const auto settings = &Core::App().settings();

	// CPU Usage Slider
	Ui::AddSkip(container);
	Ui::AddSubsectionTitle(container, rpl::single(QString("CPU Usage")));

	const auto cpuPercentLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString::number(settings->miningCpuPercent()) + "%",
		st::settingsUpdateState);

	const auto slider = container->add(
		object_ptr<Ui::MediaSlider>(container, st::settingsSlider),
		st::settingsCheckboxPadding);

	slider->resize(st::settingsSlider.seekSize);
	slider->setPseudoDiscrete(
		101, // 0-100%
		[](int value) { return value; },
		settings->miningCpuPercent(),
		[=](int value) {
			settings->setMiningCpuPercent(value);
			Core::App().saveSettingsDelayed();
			cpuPercentLabel->setText(QString::number(value) + "%");

			// Update mining configuration
			auto &session = _controller->session();
			if (auto miner = session.data().moneroMiner()) {
				miner->setCpuPercent(value);
			}
		});

	// Position label
	cpuPercentLabel->moveToLeft(
		st::settingsCheckboxPadding.left(),
		container->height() - cpuPercentLabel->height());

	Ui::AddSkip(container);

	// Only when idle checkbox
	const auto onlyIdle = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Only mine when idle (15+ minutes)"),
			settings->miningOnlyWhenIdle(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	onlyIdle->checkedChanges(
	) | rpl::start_with_next([=](bool checked) {
		settings->setMiningOnlyWhenIdle(checked);
		Core::App().saveSettingsDelayed();
	}, onlyIdle->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Only when charging checkbox
	const auto onlyCharging = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Only mine when charging"),
			settings->miningOnlyWhenCharging(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	onlyCharging->checkedChanges(
	) | rpl::start_with_next([=](bool checked) {
		settings->setMiningOnlyWhenCharging(checked);
		Core::App().saveSettingsDelayed();
	}, onlyCharging->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);
}

void Cryptogram::createMiningStatistics(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSkip(container);
	Ui::AddSubsectionTitle(container, rpl::single(QString("Statistics")));

	// Status
	const auto statusLabel = container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Status: Initializing..."),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	// Hardware
	const auto hardwareLabel = container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Hardware: Detecting..."),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	// Performance
	const auto performanceLabel = container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Performance: 0 H/s"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	// Lifetime stats
	const auto lifetimeLabel = container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Lifetime: 0 hours, $0.00"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	Ui::AddSkip(container);

	// Store labels for updates
	_statusLabel = statusLabel;
	_hardwareLabel = hardwareLabel;
	_performanceLabel = performanceLabel;
	_lifetimeLabel = lifetimeLabel;

	// Initial update
	updateMiningStatistics();
}

void Cryptogram::updateI2PStatus() {
	// TODO: Implement I2P status update
}

void Cryptogram::updateMiningStatistics() {
	auto &session = _controller->session();
	auto miner = session.data().moneroMiner();

	if (!miner) {
		if (_statusLabel) {
			_statusLabel->setText(QString("Status: Not initialized"));
		}
		return;
	}

	const auto stats = miner->getStatistics();

	// Update status
	if (_statusLabel) {
		QString status;
		if (stats.isConnected) {
			if (stats.hashrate > 0) {
				status = QString("Status: ⚡ Mining");
			} else {
				status = QString("Status: 🔌 Connected (waiting for idle)");
			}
		} else {
			status = QString("Status: 🔴 Stopped");
		}
		_statusLabel->setText(status);
	}

	// Update hardware
	if (_hardwareLabel) {
		QString hardware = "Hardware: ";
		if (stats.activeHardware.isEmpty()) {
			hardware += "None active";
		} else {
			hardware += stats.activeHardware;
		}
		_hardwareLabel->setText(hardware);
	}

	// Update performance
	if (_performanceLabel) {
		_performanceLabel->setText(
			QString("Performance: %1").arg(FormatHashrate(stats.hashrate))
		);
	}

	// Update lifetime
	if (_lifetimeLabel) {
		const auto duration = FormatDuration(stats.totalMiningSeconds);
		const auto earnings = FormatEarnings(stats.totalMiningSeconds, stats.hashrate);
		_lifetimeLabel->setText(
			QString("Lifetime: %1, %2").arg(duration).arg(earnings)
		);
	}
}

void Cryptogram::saveSettings() {
	Core::App().saveSettingsDelayed();
}

} // namespace Settings
