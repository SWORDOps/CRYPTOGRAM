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
, _miningStatsTimer([=] { updateMiningStatistics(); })
, _translationStatsTimer([=] { updateTranslationStatus(); }) {
	setupContent();

	// Start stats update timers
	_miningStatsTimer.callEach(kStatsUpdateInterval);
	_translationStatsTimer.callEach(kStatsUpdateInterval);
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

	// Translation Section (OpenVINO)
	setupTranslationSection(content);

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

void Cryptogram::setupTranslationSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSkip(container);
	Ui::AddSubsectionTitle(container, rpl::single(QString("Translation (OpenVINO)")));

	Ui::AddSkip(container);

	// Info text
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"CRYPTOGRAM uses OpenVINO-powered AI translation for Russian (Cyrillic) "
			"and Chinese (Mandarin). Translation runs locally on your device - "
			"no data is sent to external servers. Hardware acceleration (GPU/NPU) "
			"is used when available for better performance."
		))
	);

	createTranslationToggle(container);
	createLanguageSettings(container);
	createHardwareSettings(container);
	createModelSelection(container);
	createDownloadedModels(container);
}

void Cryptogram::createTranslationToggle(not_null<Ui::VerticalLayout*> container) {
	const auto settings = &Core::App().settings();

	Ui::AddSkip(container);
	Ui::AddSubsectionTitle(container, rpl::single(QString("Enable Translation")));

	const auto enabledCheckbox = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable AI-powered translation"),
			settings->translationEnabled()),
		st::settingsCheckboxPadding);

	enabledCheckbox->checkedChanges(
	) | rpl::start_with_next([=](bool checked) {
		settings->setTranslationEnabled(checked);
		Core::App().saveSettingsDelayed();
		updateTranslationStatus();
	}, enabledCheckbox->lifetime());

	Ui::AddSkip(container);
}

void Cryptogram::createLanguageSettings(not_null<Ui::VerticalLayout*> container) {
	const auto settings = &Core::App().settings();

	Ui::AddSubsectionTitle(container, rpl::single(QString("Language Settings")));

	// Auto-detect language
	const auto autoDetect = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Auto-detect source language"),
			settings->translationAutoDetect()),
		st::settingsCheckboxPadding);

	autoDetect->checkedChanges(
	) | rpl::start_with_next([=](bool checked) {
		settings->setTranslationAutoDetect(checked);
		Core::App().saveSettingsDelayed();
	}, autoDetect->lifetime());

	// Target language selection
	Ui::AddSkip(container);
	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Default target language:"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	const auto targetLang = container->add(
		object_ptr<Ui::RadiobuttonGroup>(
			container,
			settings->translationTargetLanguage()),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			targetLang,
			0,  // English
			QString("English"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			targetLang,
			1,  // Russian
			QString("Russian (Cyrillic)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			targetLang,
			2,  // Chinese
			QString("Chinese (Mandarin)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	targetLang->setChangedCallback([=](int value) {
		settings->setTranslationTargetLanguage(value);
		Core::App().saveSettingsDelayed();
	});

	Ui::AddSkip(container);
}

void Cryptogram::createHardwareSettings(not_null<Ui::VerticalLayout*> container) {
	const auto settings = &Core::App().settings();

	Ui::AddSubsectionTitle(container, rpl::single(QString("Hardware Acceleration")));

	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Select compute device for translation:"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	const auto deviceGroup = container->add(
		object_ptr<Ui::RadiobuttonGroup>(
			container,
			settings->translationDevice()),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			deviceGroup,
			3,  // AUTO
			QString("🔄 Auto (recommended) - Best available device"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			deviceGroup,
			0,  // CPU
			QString("💻 CPU - Always available"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			deviceGroup,
			1,  // GPU
			QString("🎮 GPU - Faster if available"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			deviceGroup,
			2,  // NPU
			QString("⚡ NPU - Best efficiency (Intel only)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	deviceGroup->setChangedCallback([=](int value) {
		settings->setTranslationDevice(value);
		Core::App().saveSettingsDelayed();
		updateTranslationStatus();
	});

	// Device status label
	Ui::AddSkip(container);
	_translationDeviceLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString("Detected: Checking..."),
		st::settingsUpdateState);
	container->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_translationDeviceLabel),
		st::settingsCheckboxPadding);

	Ui::AddSkip(container);
}

void Cryptogram::createModelSelection(not_null<Ui::VerticalLayout*> container) {
	const auto settings = &Core::App().settings();

	Ui::AddSubsectionTitle(container, rpl::single(QString("Translation Quality")));

	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Select translation quality (affects model size):"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	const auto qualityGroup = container->add(
		object_ptr<Ui::RadiobuttonGroup>(
			container,
			settings->translationQuality()),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			qualityGroup,
			0,  // Fast
			QString("⚡ Fast - ~100MB per model, good quality"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			qualityGroup,
			1,  // Balanced
			QString("⚖️ Balanced - ~300MB per model (recommended)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			qualityGroup,
			2,  // Best
			QString("🏆 Best - ~600MB per model, highest quality"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	qualityGroup->setChangedCallback([=](int value) {
		settings->setTranslationQuality(value);
		Core::App().saveSettingsDelayed();
	});

	Ui::AddSkip(container);

	// Cache settings
	const auto cacheEnabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable translation cache (faster repeated translations)"),
			settings->translationCacheEnabled()),
		st::settingsCheckboxPadding);

	cacheEnabled->checkedChanges(
	) | rpl::start_with_next([=](bool checked) {
		settings->setTranslationCacheEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, cacheEnabled->lifetime());

	Ui::AddSkip(container);
}

void Cryptogram::createDownloadedModels(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Downloaded Models")));

	_translationModelsLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString("Models: None downloaded yet"),
		st::settingsUpdateState);
	container->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_translationModelsLabel),
		st::settingsCheckboxPadding);

	Ui::AddSkip(container);
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"💡 Tip: Models will be automatically downloaded when you first use translation. "
			"Bidirectional models (~400MB) are more efficient than separate models."
		))
	);

	// Translation statistics
	Ui::AddSkip(container);
	_translationStatsLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString("Statistics: No translations yet"),
		st::settingsUpdateState);
	container->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_translationStatsLabel),
		st::settingsCheckboxPadding);

	Ui::AddSkip(container);
}

void Cryptogram::updateTranslationStatus() {
	const auto settings = &Core::App().settings();

	if (!settings->translationEnabled()) {
		if (_translationDeviceLabel) {
			_translationDeviceLabel->setText(QString("Translation disabled"));
		}
		if (_translationModelsLabel) {
			_translationModelsLabel->setText(QString("Models: Translation disabled"));
		}
		if (_translationStatsLabel) {
			_translationStatsLabel->setText(QString("Statistics: Translation disabled"));
		}
		return;
	}

	// Update device status
	if (_translationDeviceLabel) {
		QString deviceText;
		const auto device = settings->translationDevice();
		switch (device) {
			case 0: deviceText = "Detected: ✅ CPU available"; break;
			case 1: deviceText = "Detected: 🎮 GPU (checking...)"; break;
			case 2: deviceText = "Detected: ⚡ NPU (Intel GNA, checking...)"; break;
			case 3: deviceText = "Detected: 🔄 Auto-selecting best device..."; break;
			default: deviceText = "Detected: ✅ CPU available"; break;
		}
		_translationDeviceLabel->setText(deviceText);
	}

	// Update models
	if (_translationModelsLabel) {
		// TODO: Query actual downloaded models from OpenVINOTranslation
		_translationModelsLabel->setText(QString(
			"Models: Ready to download on first use\n"
			"• Russian (Cyrillic) ↔ English\n"
			"• Chinese (Mandarin) ↔ English"
		));
	}

	// Update statistics
	if (_translationStatsLabel) {
		// TODO: Query actual statistics from OpenVINOTranslation
		const auto quality = settings->translationQuality();
		QString qualityText;
		switch (quality) {
			case 0: qualityText = "Fast"; break;
			case 1: qualityText = "Balanced"; break;
			case 2: qualityText = "Best"; break;
			default: qualityText = "Balanced"; break;
		}

		_translationStatsLabel->setText(QString(
			"Quality: %1 | Cache: %2"
		).arg(qualityText).arg(
			settings->translationCacheEnabled() ? "Enabled" : "Disabled"
		));
	}
}
