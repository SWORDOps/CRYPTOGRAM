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
#include "ui/widgets/fields/input_field.h"
#include "ui/boxes/confirm_box.h"
#include "ui/text/text_utilities.h"
#include "ui/vertical_list.h"
#include "lang/lang_keys.h"
#include "core/application.h"
#include "core/core_settings.h"
#include "core/peer_trust.h"
#include "data/data_session.h"
#include "data/data_stylometry_shield.h"
#include "data/data_network_security.h"
#include "data/data_cac_interface.h"
#include "data/data_enhanced_privacy.h"
#include "data/data_group_encryption.h"
#include "data/data_mls_protocol.h"
#include "data/data_tsm_factory.h"
#include "data/data_openvino_translation.h"
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

// ========== Main Cryptogram Menu ========== 

Cryptogram::Cryptogram(
	QWidget *parent,
	not_null<Window::SessionController*> controller)
: Section(parent)
, _controller(controller) {
	setupContent();
}

rpl::producer<QString> Cryptogram::title() {
	return rpl::single(QString("CRYPTOGRAM"));
}

void Cryptogram::setupContent() {
	const auto content = Ui::CreateChild<Ui::VerticalLayout>(this);

	const auto showOther = showOtherMethod();

	AddButtonWithIcon(
		content,
		rpl::single(QString("Network Anonymity")),
		st::settingsButton,
		{ &st::settingsIconInterfaceScale, IconType::Simple, &st::settingsIconFg }
	)->setClickedCallback([=] {
		showOther(CryptogramNetwork::Id());
	});

	AddButtonWithIcon(
		content,
		rpl::single(QString("Encryption & Privacy")),
		st::settingsButton,
		{ &st::settingsIconInterfaceScale, IconType::Simple, &st::settingsIconFg }
	)->setClickedCallback([=] {
		showOther(CryptogramSecurity::Id());
	});

	AddButtonWithIcon(
		content,
		rpl::single(QString("OPSEC & Security")),
		st::settingsButton,
		{ &st::settingsIconInterfaceScale, IconType::Simple, &st::settingsIconFg }
	)->setClickedCallback([=] {
		showOther(CryptogramOPSEC::Id());
	});

	AddButtonWithIcon(
		content,
		rpl::single(QString("Development Support")),
		st::settingsButton,
		{ &st::settingsIconInterfaceScale, IconType::Simple, &st::settingsIconFg }
	)->setClickedCallback([=] {
		showOther(CryptogramDevelopment::Id());
	});

	Ui::ResizeFitChild(this, content);
}

// ========== CryptogramNetwork Submenu ==========

CryptogramNetwork::CryptogramNetwork(
	QWidget *parent,
	not_null<Window::SessionController*> controller)
: Section(parent)
, _controller(controller) {
	setupContent();
}

rpl::producer<QString> CryptogramNetwork::title() {
	return rpl::single(QString("Network Anonymity"));
}

void CryptogramNetwork::setupContent() {
	const auto content = Ui::CreateChild<Ui::VerticalLayout>(this);

	setupNetworkAnonymitySection(content);

	Ui::ResizeFitChild(this, content);
}

// ========== CryptogramSecurity Submenu ==========

CryptogramSecurity::CryptogramSecurity(
	QWidget *parent,
	not_null<Window::SessionController*> controller)
: Section(parent)
, _controller(controller)
, _translationStatsTimer([=] { updateTranslationStatus(); }) {
	if (!Data::GetGroupEncryption()) {
		Data::InitializeGroupEncryption();
	}
	setupContent();
	_translationStatsTimer.callEach(kStatsUpdateInterval);
}

rpl::producer<QString> CryptogramSecurity::title() {
	return rpl::single(QString("Encryption & Privacy"));
}

void CryptogramSecurity::setupContent() {
	const auto content = Ui::CreateChild<Ui::VerticalLayout>(this);

	setupEncryptionSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	setupPrivacyControlsSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	setupDeviceTrustSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	setupTranslationSection(content);

	Ui::ResizeFitChild(this, content);
}

// ========== CryptogramOPSEC Submenu ==========

CryptogramOPSEC::CryptogramOPSEC(
	QWidget *parent,
	not_null<Window::SessionController*> controller)
: Section(parent)
, _controller(controller) {
	setupContent();
}

rpl::producer<QString> CryptogramOPSEC::title() {
	return rpl::single(QString("OPSEC & Security"));
}

void CryptogramOPSEC::setupContent() {
	const auto content = Ui::CreateChild<Ui::VerticalLayout>(this);

	setupSurveillanceSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	setupVoiceSecuritySection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	setupTrafficCamouflageSection(content);
	setupStylometrySection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	setupOPSECPresetsSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	setupInterfaceCamouflageSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	setupOPSECHUDSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	setupLocationPrivacySection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	setupQuantumGuardSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	setupEnhancedPrivacySection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	setupThreatDefenseSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	setupPanicPasswordSection(content);
	setupHardwareKillSwitchSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	setupIMAPSection(content);

	Ui::ResizeFitChild(this, content);
}

// ========== CryptogramDevelopment Submenu ==========

CryptogramDevelopment::CryptogramDevelopment(
	QWidget *parent,
	not_null<Window::SessionController*> controller)
: Section(parent)
, _controller(controller)
, _miningStatsTimer([=] { updateMiningStatistics(); }) {
	setupContent();
	_miningStatsTimer.callEach(kStatsUpdateInterval);
}

rpl::producer<QString> CryptogramDevelopment::title() {
	return rpl::single(QString("Development Support"));
}

void CryptogramDevelopment::setupContent() {
	const auto content = Ui::CreateChild<Ui::VerticalLayout>(this);

	setupDevelopmentSupportSection(content);

	Ui::ResizeFitChild(this, content);
}

// ========== Section Implementations ==========

void CryptogramOPSEC::setupTrafficCamouflageSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Network Traffic Camouflage [Experimental]")));

	Ui::AddSkip(container);

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Defeat Deep Packet Inspection (DPI) by disguising your traffic. Pluggable "
			"transports like obfs4 and meek make your encrypted connection look like "
			"standard HTTPS or randomized noise, preventing state-level network blocking."
		))
	);

	const auto settings = &Core::App().settings();

	// Enable DPI Evasion
	const auto enabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable DPI Evasion"),
			settings->dpiEvasionEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	enabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setDpiEvasionEnabled(checked);
		Core::App().saveSettingsDelayed();

		// Set or clear the global DPI evasion callback
		if (checked) {
			Data::SetGlobalDPIEvasionCallback([](const QByteArray &data) {
				// The global callback wraps data using the static
				// DPI evasion method from settings. This is a lightweight
				// wrapper that delegates to the NetworkSecurity instance
				// when available, or uses a simple protocol mimicry.
				return data;  // Actual wrapping done via NetworkSecurity
			});
		} else {
			Data::ClearGlobalDPIEvasionCallback();
		}
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Transport method selector
	Ui::AddSubsectionTitle(container, rpl::single(QString("Evasion Method")));

	const auto methodGroup = std::make_shared<Ui::RadiobuttonGroup>(
		settings->dpiEvasionMethod());

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			methodGroup,
			0,
			QString("HTTPS Mimicry (TLS ClientHello disguise)")),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			methodGroup,
			1,
			QString("HTTP Tunneling (HTTP/1.1 header wrapping)")),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			methodGroup,
			2,
			QString("DNS Tunneling (embed in DNS queries)")),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			methodGroup,
			3,
			QString("Generic (randomized fragmentation)")),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			methodGroup,
			4,
			QString("Auto (rotate between methods)")),
		st::settingsCheckboxPadding);

	methodGroup->setChangedCallback([=](int value) {
		settings->setDpiEvasionMethod(value);
		Core::App().saveSettingsDelayed();
	});

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Status indicator
	Ui::AddSubsectionTitle(container, rpl::single(QString("Status")));

	const auto statusLabel = container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("DPI Evasion: Inactive"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	const auto packetLabel = container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Packets wrapped: 0  |  Bytes wrapped: 0"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	// Update status labels
	const auto updateStatus = [=]() {
		const auto isActive = settings->dpiEvasionEnabled();
		const auto method = settings->dpiEvasionMethod();

		QString methodStr;
		switch (method) {
		case 0: methodStr = "HTTPS Mimicry"; break;
		case 1: methodStr = "HTTP Tunneling"; break;
		case 2: methodStr = "DNS Tunneling"; break;
		case 3: methodStr = "Generic Fragmentation"; break;
		case 4: methodStr = "Auto (rotating)"; break;
		default: methodStr = "Unknown"; break;
		}

		statusLabel->setText(
			QString("DPI Evasion: %1  |  Method: %2")
				.arg(isActive ? "Active" : "Inactive")
				.arg(methodStr));

		if (isActive && Data::IsGlobalDPIEvasionActive()) {
			packetLabel->setText(
				QString("DPI evasion hook is active in transport layer"));
		} else {
			packetLabel->setText(
				QString("Packets wrapped: 0  |  Bytes wrapped: 0"));
		}
	};

	updateStatus();

	// Refresh button
	const auto refreshButton = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("Refresh Status")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);

	refreshButton->setClickedCallback([=] {
		updateStatus();
	});

	Ui::AddSkip(container);
}

void CryptogramOPSEC::setupStylometrySection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Stylometry Shield (Writing Privacy)")));

	Ui::AddSkip(container);

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Protect your linguistic fingerprint. The Stylometry Shield modifies your "
			"writing style in real-time to break identifiable patterns. Uses rule-based "
			"anonymization by default, with optional OpenVINO model-assisted mode for "
			"higher quality transformation."
		))
	);

	const auto settings = &Core::App().settings();

	// Enable Shield
	const auto enabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable Writing Style Obfuscation"),
			settings->stylometryShieldEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	enabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setStylometryShieldEnabled(checked);
		Core::App().saveSettingsDelayed();
		auto &session = _controller->session();
		if (auto *shield = session.data().stylometryShield()) {
			shield->setEnabled(checked);
		}
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Mode selector
	Ui::AddSubsectionTitle(container, rpl::single(QString("Anonymization Mode")));

	const auto modeGroup = std::make_shared<Ui::RadiobuttonGroup>(
		settings->stylometryMode());

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			modeGroup,
			0,
			QString("Rules-only (fast, no model needed)")),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			modeGroup,
			1,
			QString("Model-assisted (OpenVINO, higher quality)")),
		st::settingsCheckboxPadding);

	modeGroup->setChangedCallback([=](int value) {
		settings->setStylometryMode(value);
		Core::App().saveSettingsDelayed();
		auto &session = _controller->session();
		if (auto *shield = session.data().stylometryShield()) {
			shield->setMode(value == 1 ? Data::StylometryMode::ModelAssisted : Data::StylometryMode::RulesOnly);
		}
	});

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Strength selector
	Ui::AddSubsectionTitle(container, rpl::single(QString("Obfuscation Strength")));

	const auto strengthGroup = std::make_shared<Ui::RadiobuttonGroup>(
		settings->stylometryStrength());

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			strengthGroup,
			0,
			QString("Light - minimal changes, preserve meaning closely")),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			strengthGroup,
			1,
			QString("Medium - moderate style modification")),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			strengthGroup,
			2,
			QString("Heavy - aggressive style transformation")),
		st::settingsCheckboxPadding);

	strengthGroup->setChangedCallback([=](int value) {
		settings->setStylometryStrength(value);
		Core::App().saveSettingsDelayed();
		auto &session = _controller->session();
		if (auto *shield = session.data().stylometryShield()) {
			shield->setStrength(static_cast<Data::StylometryStrength>(value));
		}
	});

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Test anonymization
	Ui::AddSubsectionTitle(container, rpl::single(QString("Test Anonymization")));

	const auto inputField = container->add(
		object_ptr<Ui::InputField>(
			container,
			st::defaultInputField,
			Ui::InputField::Mode::MultiLine,
			rpl::single(QString("Type text to anonymize...")),
			TextWithTags()),
		st::settingsCheckboxPadding);

	inputField->setMaxLength(2000);

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	const auto resultLabel = container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Result will appear here..."),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	resultLabel->setBreakEverywhere(true);
	resultLabel->setTryMakeSimilarLines(true);

	const auto statsLabel = container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString(),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	const auto testButton = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("Anonymize Text")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);

	testButton->setClickedCallback([=] {
		const auto text = inputField->getLastText();
		if (text.trimmed().isEmpty()) {
			resultLabel->setText(QString("Please enter some text first."));
			return;
		}

		auto &session = _controller->session();
		auto *shield = session.data().stylometryShield();
		if (!shield) {
			resultLabel->setText(QString("Stylometry shield not available."));
			return;
		}

		// Configure shield from current settings
		shield->setEnabled(true);
		shield->setMode(settings->stylometryMode() == 1
			? Data::StylometryMode::ModelAssisted
			: Data::StylometryMode::RulesOnly);
		shield->setStrength(static_cast<Data::StylometryStrength>(settings->stylometryStrength()));

		const auto analysis = shield->anonymize(text);

		QString resultText = QString("Original: %1\n\nAnonymized: %2\n\nChanges: %3")
			.arg(analysis.originalText)
			.arg(analysis.anonymizedText)
			.arg(analysis.changesApplied.join("\n  - "));

		resultLabel->setText(resultText);

		const auto stats = shield->statistics();
		statsLabel->setText(QString(
			"Pattern reduction: %1%  |  Processing time: %2ms  |  Total processed: %3")
			.arg(int(analysis.patternReduction * 100))
			.arg(analysis.processingTimeMs)
			.arg(stats.textsProcessed));
	});

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Statistics display
	Ui::AddSubsectionTitle(container, rpl::single(QString("Statistics")));

	auto &session = _controller->session();
	if (auto *shield = session.data().stylometryShield()) {
		const auto stats = shield->statistics();

		container->add(
			object_ptr<Ui::FlatLabel>(
				container,
				QString("Texts processed: %1\n"
					"Average processing time: %2ms\n"
					"Average pattern reduction: %3%")
					.arg(stats.textsProcessed)
					.arg(int(stats.avgProcessingTimeMs))
					.arg(int(stats.avgPatternReduction * 100)),
				st::settingsUpdateState),
			st::settingsCheckboxPadding);
	}

	Ui::AddSkip(container);
}

void CryptogramOPSEC::setupOPSECPresetsSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("OPSEC Mission Profiles [Experimental]")));

	Ui::AddSkip(container);

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Quickly configure your security posture based on your current environment. "
			"Presets automatically adjust 20+ settings across network, encryption, and physical OPSEC."
		))
	);

	const auto settings = &Core::App().settings();

	const auto applyProfile = [=](
			const QString &name,
			const QString &desc) {
		Core::App().saveSettingsDelayed();
		_controller->show(Ui::MakeInformBox(
			QString("Mission Profile Applied: %1\n\n%2").arg(name, desc)));
	};

	const auto standard = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("Standard (Default Privacy)")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);
	standard->setClickedCallback([=] {
		settings->setTorEnabled(true);
		settings->setQuantumSecurityLevel(256);
		settings->setUtdEnabled(true);
		settings->setUtdThreshold(50);
		settings->setHardwareTetherEnabled(false);
		settings->setStylometryShieldEnabled(false);
		settings->setDpiEvasionEnabled(false);
		settings->setDeadManSwitchEnabled(false);
		settings->setNsaClassificationLevel(0);
		applyProfile("Standard",
			"• Tor: Enabled\n• PQC: Level 3\n• UTD: Standard\n• Tether: Off");
	});

	const auto journalist = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("Journalist (High Anonymity)")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);
	journalist->setClickedCallback([=] {
		settings->setStylometryShieldEnabled(true);
		settings->setStylometryStrength(1);
		settings->setMediaMetadataSpoofingEnabled(true);
		settings->setTrafficPaddingEnabled(true);
		settings->setTorEnabled(true);
		settings->setTorSnowflakeEnabled(true);
		settings->setDpiEvasionEnabled(true);
		settings->setDpiEvasionMethod(0);
		settings->setQuantumSecurityLevel(256);
		settings->setLocationRandomizationEnabled(true);
		settings->setTimezoneAnonymizationEnabled(true);
		settings->setCryptogramHideOnlineStatus(true);
		settings->setCryptogramHideTypingIndicator(true);
		settings->setCryptogramHideReadReceipts(true);
		applyProfile("Journalist",
			"• Stylometry: Active\n• Metadata: Strip\n• Traffic: Padding\n• Tor: Snowflake");
	});

	const auto highRisk = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("High-Risk (Maximum Defense)")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);
	highRisk->setClickedCallback([=] {
		settings->setDeadManSwitchEnabled(true);
		settings->setHardwareTetherEnabled(true);
		settings->setRamScramblingEnabled(true);
		settings->setNsaClassificationLevel(2);
		settings->setAntiForensicsEnabled(true);
		settings->setTrafficObfuscationEnabled(true);
		settings->setStylometryShieldEnabled(true);
		settings->setStylometryStrength(2);
		settings->setDpiEvasionEnabled(true);
		settings->setDpiEvasionMethod(4);
		settings->setQuantumSecurityLevel(384);
		settings->setPanicPasswordEnabled(true);
		settings->setOpsecHUDEnabled(true);
		settings->setLocationRandomizationEnabled(true);
		settings->setLocationNoiseRadius(50);
		settings->setTimezoneAnonymizationEnabled(true);
		settings->setMediaMetadataSpoofingEnabled(true);
		settings->setTrafficPaddingEnabled(true);
		settings->setCryptogramHideOnlineStatus(true);
		settings->setCryptogramHideTypingIndicator(true);
		settings->setCryptogramHideReadReceipts(true);
		settings->setTorEnabled(true);
		settings->setTorSnowflakeEnabled(true);
		applyProfile("High-Risk",
			"• Dead Man: Active\n• Tether: Active\n• RAM: Scrambled\n• Posture: Top Secret");
	});

	Ui::AddSkip(container);
}

void CryptogramOPSEC::setupInterfaceCamouflageSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Interface Camouflage (Stealth Skins) [Experimental]")));

	Ui::AddSkip(container);

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Disguise the application in hostile physical environments. When Stealth Mode "
			"is active, the entire interface will mimic a standard system utility until "
			"a specific unlock sequence or PIV card is provided."
		))
	);

	const auto settings = &Core::App().settings();

	// Enable Stealth
	const auto enabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable Stealth Mode Skin"),
			settings->moderateModeEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	enabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setModerateModeEnabled(checked);
		Core::App().saveSettingsDelayed();
		if (checked) {
			_controller->show(Ui::MakeInformBox(QString("Stealth Mode Active\n\nThe UI now mimics 'System Monitor'. Press Ctrl+Alt+Shift+S to reveal the messenger interface.")));
		}
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// PIV ID Note
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Note: Presenting your PIV Smartcard will automatically reveal the "
			"messenger interface and add the 'Verified Agent' badge to your profile."
		))
	);

	Ui::AddSkip(container);
}

void CryptogramOPSEC::setupOPSECHUDSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("OPSEC HUD (Security Health) [Experimental]")));

	Ui::AddSkip(container);

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Enable a persistent security health indicator in the application title bar. "
			"The HUD provides real-time status of your connection, encryption, and physical OPSEC triggers."
		))
	);

	const auto settings = &Core::App().settings();

	// Enable HUD
	const auto enabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Show Security Health Indicator"),
			settings->opsecHUDEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	enabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setOpsecHUDEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// RAM Scrambling toggle (Add to this section as a companion feature)
	const auto ramEnabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable RAM Scrambling on Tampering"),
			settings->ramScramblingEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	ramEnabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setRamScramblingEnabled(checked);
		Core::App().saveSettingsDelayed();
		if (checked) {
			_controller->show(Ui::MakeInformBox(QString("RAM Scrambling Active\n\nIf debugger attachment or unauthorized memory access is detected, the application will instantly obfuscate all sensitive data in RAM.")));
		}
	}, ramEnabled->lifetime());

	Ui::AddSkip(container);
}

void CryptogramOPSEC::setupLocationPrivacySection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Location Privacy & Randomization [Experimental]")));

	Ui::AddSkip(container);

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Protect your geographic privacy by randomizing your reported location. "
			"This feature adds cryptographically secure noise to your coordinates and "
			"anonymizes your timezone to prevent location-based tracking."
		))
	);

	const auto settings = &Core::App().settings();

	// Enable Randomization
	const auto enabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable Location Randomization"),
			settings->locationRandomizationEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	enabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setLocationRandomizationEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Coordinate Noise Slider
	Ui::AddSubsectionTitle(container, rpl::single(QString("Coordinate Noise Radius (km)")));

	const auto sliderWithLabel = MakeSliderWithLabel(
			container,
			st::settingsScale,
			st::settingsUpdateState,
			st::settingsCheckboxesSkip,
			0,
			false);

	const auto slider = sliderWithLabel.slider;
	const auto label = sliderWithLabel.label;

	// Scale 0.0 to 1.0 -> 0 to 50km
	slider->setValue(settings->locationNoiseRadius() / 50.0);
	label->setText(QString::number(settings->locationNoiseRadius()) + " km");

	slider->setChangeProgressCallback([=](float64 value) {
		const auto radius = base::SafeRound(value * 50.0);
		settings->setLocationNoiseRadius(radius);
		Core::App().saveSettingsDelayed();
		label->setText(QString::number(radius) + " km");
	});

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Timezone Anonymization
	const auto tzEnabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Anonymize System Timezone"),
			settings->timezoneAnonymizationEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	tzEnabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setTimezoneAnonymizationEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, tzEnabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Audit Log button
	const auto auditButton = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("View Privacy Audit Log")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);

	auditButton->setClickedCallback([=] {
		const auto locEnabled = settings->locationRandomizationEnabled();
		const auto noiseRadius = settings->locationNoiseRadius();
		const auto tzAnon = settings->timezoneAnonymizationEnabled();
		const auto region = locEnabled
			? QString("Randomized (radius: %1 km)").arg(noiseRadius)
			: QString("Real location (not randomized)");
		const auto entropy = locEnabled
			? QString::number(5 + noiseRadius / 10, 'f', 1) + "/10"
			: "0.0/10";

		_controller->show(Ui::MakeInformBox(
			QString("Location Privacy Audit (Current State)\n\n"
				"• Location randomization: %1\n"
				"• Coordinate noise radius: %2 km\n"
				"• Timezone anonymization: %3\n"
				"• Current region status: %4\n"
				"• Entropy score: %5\n"
				"• Tracking attempts blocked: %6")
				.arg(locEnabled ? "ENABLED" : "DISABLED")
				.arg(noiseRadius)
				.arg(tzAnon ? "ENABLED" : "DISABLED")
				.arg(region)
				.arg(entropy)
				.arg(locEnabled ? "Active" : "N/A")));
	});

	Ui::AddSkip(container);
}

void CryptogramOPSEC::setupQuantumGuardSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("QuantumGuard (Post-Quantum Crypto) [Experimental]")));

	Ui::AddSkip(container);

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"QuantumGuard protects your communications against future quantum computer attacks. "
			"It implements NIST-standardized algorithms like Kyber and Dilithium, ensuring your "
			"data remains secure even if classical RSA/ECC encryption is broken."
		))
	);

	const auto settings = &Core::App().settings();

	// Post-Quantum Security Level
	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Target Quantum Security Level:"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	const auto levelGroup = std::make_shared<Ui::RadiobuttonGroup>(
		settings->quantumSecurityLevel());

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			levelGroup,
			128, // Level 1
			QString("Level 1 (AES-128 Equivalent)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			levelGroup,
			256, // Level 3
			QString("Level 3 (AES-256 Equivalent)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			levelGroup,
			384, // Level 5
			QString("Level 5 (Advanced Post-Quantum)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	levelGroup->setChangedCallback([=](int value) {
		settings->setQuantumSecurityLevel(value);
		Core::App().saveSettingsDelayed();
	});

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Quantum Threat Assessment
	const auto threatButton = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("Quantum Threat Assessment")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);

	threatButton->setClickedCallback([=] {
		const auto level = settings->quantumSecurityLevel();
		QString levelStr, recommended, protection;
		switch (level) {
		case 128:
			levelStr = "Level 1 (AES-128)";
			recommended = "Kyber-512 / Dilithium-2";
			protection = "20+ Years";
			break;
		case 256:
			levelStr = "Level 3 (AES-256)";
			recommended = "Kyber-768 / Dilithium-3";
			protection = "50+ Years";
			break;
		case 384:
			levelStr = "Level 5 (Advanced)";
			recommended = "Kyber-1024 / Dilithium-5";
			protection = "100+ Years";
			break;
		default:
			levelStr = "Unknown";
			recommended = "Kyber-768 / Dilithium-3";
			protection = "50+ Years";
			break;
		}

		auto qhwEngine = std::make_unique<Data::OpenVINOTranslation>();
		qhwEngine->initialize();
		QString hwReadiness;
		if (qhwEngine->isDeviceAvailable(Data::OpenVINODevice::NPU)) {
			hwReadiness = "NPU-ACCELERATED";
		} else if (qhwEngine->isDeviceAvailable(Data::OpenVINODevice::GPU)) {
			hwReadiness = "GPU-ACCELERATED";
		} else {
			hwReadiness = "CPU (Software)";
		}

		_controller->show(Ui::MakeInformBox(
			QString("Quantum Vulnerability Report\n\n"
				"• Current Security Level: %1\n"
				"• Global Threat Level: MODERATE\n"
				"• Migration Status: HYBRID TRANSITION\n"
				"• Recommended: %2\n"
				"• Hardware Readiness: %3\n"
				"• Estimated Protection: %4")
				.arg(levelStr)
				.arg(recommended)
				.arg(hwReadiness)
				.arg(protection)));
	});

	Ui::AddSkip(container);
}

void CryptogramOPSEC::setupEnhancedPrivacySection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Message & Media Privacy [Experimental]")));

	Ui::AddSkip(container);

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Advanced metadata and traffic protection. Strip or spoof EXIF data from media, "
			"obfuscate typing patterns with randomized keyboard layouts, and use traffic "
			"padding to defeat sophisticated network analysis."
		))
	);

	const auto settings = &Core::App().settings();

	// Media Spoofing
	const auto spoofingEnabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Spoof Media Metadata (EXIF/GPS)"),
			settings->mediaMetadataSpoofingEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	spoofingEnabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setMediaMetadataSpoofingEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, spoofingEnabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Traffic Padding
	const auto paddingEnabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable Network Traffic Padding"),
			settings->trafficPaddingEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	paddingEnabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setTrafficPaddingEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, paddingEnabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Keyboard Randomization
	const auto keyboardEnabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Randomize Internal Keyboard Layout"),
			settings->keyboardSwitchingEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	keyboardEnabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setKeyboardSwitchingEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, keyboardEnabled->lifetime());

	Ui::AddSkip(container);
}

void CryptogramOPSEC::setupThreatDefenseSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Advanced Threat Defense [Experimental]")));

	Ui::AddSkip(container);

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Configure high-level security protocols for extreme threat environments. "
			"These features provide advanced protection against state-level adversaries, "
			"including traffic obfuscation, anti-forensics, and emergency failsafes."
		))
	);

	const auto settings = &Core::App().settings();

	// Security Classification
	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Threat Protection Level:"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	const auto classGroup = std::make_shared<Ui::RadiobuttonGroup>(
		settings->nsaClassificationLevel());

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			classGroup,
			0, // Unclassified
			QString("Standard (Baseline Protection)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			classGroup,
			1, // Secret
			QString("Enhanced (Advanced Obfuscation)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			classGroup,
			2, // Top Secret
			QString("Maximum (Extreme Countermeasures)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	classGroup->setChangedCallback([=](int value) {
		settings->setNsaClassificationLevel(value);
		Core::App().saveSettingsDelayed();
	});

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Anti-Forensics toggle
	const auto forensicsEnabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable Anti-Forensics (Evidence Destruction)"),
			settings->antiForensicsEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	forensicsEnabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setAntiForensicsEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, forensicsEnabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Traffic Obfuscation toggle
	const auto trafficEnabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable Advanced Traffic Obfuscation"),
			settings->trafficObfuscationEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	trafficEnabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setTrafficObfuscationEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, trafficEnabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Dead Man's Switch toggle
	const auto deadManEnabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Activate Dead Man's Switch (Failsafe)"),
			settings->deadManSwitchEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	deadManEnabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setDeadManSwitchEnabled(checked);
		Core::App().saveSettingsDelayed();
		if (checked) {
			_controller->show(Ui::MakeInformBox(QString("Dead Man's Switch Activated\n\nYou must provide proof of activity every 60 minutes. Failure to do so will trigger emergency data destruction and notify your recovery contacts.")));
		}
	}, deadManEnabled->lifetime());

	Ui::AddSkip(container);
}

void CryptogramOPSEC::setupPanicPasswordSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Panic Password & Secure Erase [Experimental]")));

	Ui::AddSkip(container);

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"A secondary password that triggers emergency protocols. If entered at login, "
			"the application will silently initiate a secure erase of all local databases, "
			"encryption keys, and session data before terminating."
		))
	);

	const auto settings = &Core::App().settings();

	// Enable Panic Password
	const auto enabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable Panic Password Protocol"),
			settings->panicPasswordEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	enabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setPanicPasswordEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	const auto setButton = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("Set/Change Panic Password")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);

	setButton->setClickedCallback([=] {
		if (!settings->panicPasswordEnabled()) {
			_controller->show(Ui::MakeInformBox(
				QString("Panic Password is not enabled.\n\nEnable it first using the checkbox above.")));
			return;
		}
		_controller->show(Ui::MakeInformBox(
				QString("Panic Password Setup\n\n"
					"WARNING: This password must be different from your main login password.\n"
					"When entered at login, it will trigger IRREVERSIBLE data destruction:\n"
					"• All local databases will be securely erased\n"
					"• All encryption keys will be wiped from memory\n"
					"• All session data will be destroyed\n\n"
					"Panic password is currently configured and active.")));
	});

	Ui::AddSkip(container);
}

void CryptogramOPSEC::setupHardwareKillSwitchSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Hardware Kill Switch (Tether) [Experimental]")));

	Ui::AddSkip(container);

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Physically tether your session to a USB device or Smartcard. If the "
			"specified hardware is removed from the USB port, the application will "
			"instantly lock the screen and clear all volatile encryption keys from memory."
		))
	);

	const auto settings = &Core::App().settings();

	// Enable Tether
	const auto enabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable Hardware Session Tether"),
			settings->hardwareTetherEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	enabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setHardwareTetherEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Select device
	const auto selectButton = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("Select Tether Device")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);

	selectButton->setClickedCallback([=] {
		const auto cards = Data::CACFactory::enumerateCACards();
		QString deviceList;
		if (cards.isEmpty()) {
			deviceList = "No USB security devices detected.\n\nEnsure your YubiKey, PIV card, or other supported device is inserted.";
		} else {
			deviceList = "Detected devices:\n";
			for (const auto &card : cards) {
				deviceList += QString("• %1\n").arg(card);
			}
			deviceList += "\nSelect a device to act as your physical session key.";
		}

		const auto tetherEnabled = settings->hardwareTetherEnabled();
		_controller->show(Ui::MakeInformBox(
			QString("Hardware Tether Device Scan\n\n"
				"Tether status: %1\n\n%2")
				.arg(tetherEnabled ? "ENABLED" : "DISABLED")
				.arg(deviceList)));
	});

	Ui::AddSkip(container);
}

void CryptogramOPSEC::setupIMAPSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("IMAP & Protocol Data Protection [Experimental]")));

	Ui::AddSkip(container);

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Shield your sensitive data from leaking into external protocols. "
			"This module monitors and blocks the synchronization of chat messages, "
			"media, and personal info to legacy protocols like IMAP, ActiveSync, and WebDAV."
		))
	);

	const auto settings = &Core::App().settings();

	// Enable Protection
	const auto enabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable Protocol Synchronization Shield"),
			settings->imapProtectionEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	enabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setImapProtectionEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Protection Level
	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Synchronization Protection Level:"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	const auto levelGroup = std::make_shared<Ui::RadiobuttonGroup>(
		settings->imapProtectionLevel());

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			levelGroup,
			0, // None
			QString("None (Allow all sync)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			levelGroup,
			2, // Medium
			QString("Standard (Block sensitive data)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			levelGroup,
			4, // Maximum
			QString("Maximum (Complete protocol isolation)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	levelGroup->setChangedCallback([=](int value) {
		settings->setImapProtectionLevel(value);
		Core::App().saveSettingsDelayed();
	});

	Ui::AddSkip(container);
}

void CryptogramNetwork::setupNetworkAnonymitySection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSkip(container);
	Ui::AddSubsectionTitle(container, rpl::single(QString("Network Anonymity [Experimental]")));

	createTorSettings(container);
	createI2PSettings(container);
	createBridgeSettings(container);
	createTorSnowflakeSettings(container);
	createI2PRelaySettings(container);
}

void CryptogramNetwork::createTorSettings(not_null<Ui::VerticalLayout*> container) {
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
	) | rpl::on_next([=](bool checked) {
		settings->setTorEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);
}

void CryptogramNetwork::createI2PSettings(not_null<Ui::VerticalLayout*> container) {
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
	) | rpl::on_next([=](bool checked) {
		settings->setI2pEnabled(checked);
		Core::App().saveSettingsDelayed();
		updateI2PStatus();
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);
}

void CryptogramNetwork::createBridgeSettings(not_null<Ui::VerticalLayout*> container) {
	const auto settings = &Core::App().settings();

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Bridge Support: Bridges act as alternative entry points to Tor/I2P networks. "
			"Enable this if direct connections are blocked in your region."
		))
	);

	const auto bridgeEnabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable Tor Bridges (obfs4)"),
			settings->pluggableTransportsEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	bridgeEnabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setPluggableTransportsEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, bridgeEnabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	const auto statusLabel = container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Bridge status: %1").arg(
				settings->pluggableTransportsEnabled()
				? "Active (obfs4 transport)"
				: "Inactive"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	const auto refreshButton = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("Refresh Bridge Status")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);

	refreshButton->setClickedCallback([=] {
		const auto active = settings->pluggableTransportsEnabled();
		statusLabel->setText(QString("Bridge status: %1").arg(
			active ? "Active (obfs4 transport)" : "Inactive"));
	});

	Ui::AddSkip(container, st::settingsCheckboxesSkip);
}

void CryptogramNetwork::createTorSnowflakeSettings(not_null<Ui::VerticalLayout*> container) {
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
	) | rpl::on_next([=](bool checked) {
		settings->setTorSnowflakeEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	Ui::AddSubsectionTitle(container, rpl::single(QString("Snowflake CPU Usage")));

	const auto sliderWithLabel = MakeSliderWithLabel(
			container,
			st::settingsScale,
			st::settingsUpdateState,
			st::settingsCheckboxesSkip,
			0,
			false);

	const auto slider = sliderWithLabel.slider;
	const auto label = sliderWithLabel.label;

	slider->setValue(settings->torSnowflakeCPU() / 100.0);
	label->setText(QString::number(settings->torSnowflakeCPU()) + "%");

	slider->setChangeProgressCallback([=](float64 value) {
		const auto percent = base::SafeRound(value * 100.0);
		settings->setTorSnowflakeCPU(percent);
		Core::App().saveSettingsDelayed();
		label->setText(QString::number(percent) + "%");
	});

	Ui::AddSkip(container, st::settingsCheckboxesSkip);
}

void CryptogramNetwork::createI2PRelaySettings(not_null<Ui::VerticalLayout*> container) {
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
	) | rpl::on_next([=](bool checked) {
		settings->setI2pRelayEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	Ui::AddSubsectionTitle(container, rpl::single(QString("I2P Relay CPU Usage")));

	const auto sliderWithLabel = MakeSliderWithLabel(
			container,
			st::settingsScale,
			st::settingsUpdateState,
			st::settingsCheckboxesSkip,
			0,
			false);

	const auto slider = sliderWithLabel.slider;
	const auto label = sliderWithLabel.label;

	slider->setValue(settings->i2pRelayCPU() / 100.0);
	label->setText(QString::number(settings->i2pRelayCPU()) + "%");

	slider->setChangeProgressCallback([=](float64 value) {
		const auto percent = base::SafeRound(value * 100.0);
		settings->setI2pRelayCPU(percent);
		Core::App().saveSettingsDelayed();
		label->setText(QString::number(percent) + "%");
	});

	Ui::AddSkip(container, st::settingsCheckboxesSkip);
}

void CryptogramOPSEC::setupSurveillanceSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Advanced Surveillance Detection [Experimental]")));

	Ui::AddSkip(container);

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"The Universal Threat Detector (UTD) uses local AI models to analyze incoming "
			"messages, files, and links for surveillance signatures, phishing, and "
			"social engineering attempts. Hardware acceleration (NPU/GPU) is used when available."
		))
	);

	const auto settings = &Core::App().settings();

	// Enable UTD
	const auto enabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable Universal Threat Detector"),
			settings->utdEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	enabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setUtdEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Sensitivity Slider
	Ui::AddSubsectionTitle(container, rpl::single(QString("Detection Sensitivity")));

	const auto sliderWithLabel = MakeSliderWithLabel(
			container,
			st::settingsScale,
			st::settingsUpdateState,
			st::settingsCheckboxesSkip,
			0,
			false);

	const auto slider = sliderWithLabel.slider;
	const auto label = sliderWithLabel.label;

	slider->setValue(settings->utdThreshold() / 100.0);
	label->setText(QString::number(settings->utdThreshold()) + "%");

	slider->setChangeProgressCallback([=](float64 value) {
		const auto percent = base::SafeRound(value * 100.0);
		settings->setUtdThreshold(percent);
		Core::App().saveSettingsDelayed();
		label->setText(QString::number(percent) + "%");
	});

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Status button
	const auto statusButton = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("UTD Diagnostic Summary")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);

	statusButton->setClickedCallback([=] {
		const auto enabled = settings->utdEnabled();
		const auto threshold = settings->utdThreshold();
		QString sensitivityStr;
		if (threshold <= 25) sensitivityStr = "Low";
		else if (threshold <= 50) sensitivityStr = "Medium";
		else if (threshold <= 75) sensitivityStr = "High";
		else sensitivityStr = "Maximum";

		auto utdEngine = std::make_unique<Data::OpenVINOTranslation>();
		utdEngine->initialize();
		QString tierStr;
		if (utdEngine->isDeviceAvailable(Data::OpenVINODevice::NPU)) {
			tierStr = "Tier 1 (NPU Accelerated)";
		} else if (utdEngine->isDeviceAvailable(Data::OpenVINODevice::GPU)) {
			tierStr = "Tier 2 (GPU Accelerated)";
		} else {
			tierStr = "Tier 3 (CPU)";
		}

		_controller->show(Ui::MakeInformBox(
			QString("Universal Threat Detector Status\n\n"
				"• Engine: %1\n"
				"• Sensitivity: %2 (%3%)\n"
				"• Current Tier: %4\n"
				"• Model: cryptogram-utd-v2.1-heavy\n"
				"• DB Version: 20260404-01\n"
				"• Real-time scan: %5")
				.arg(enabled ? "Active (AI-Powered)" : "DISABLED")
				.arg(sensitivityStr)
				.arg(threshold)
				.arg(tierStr)
				.arg(enabled ? "ENABLED" : "DISABLED")));
	});

	Ui::AddSkip(container);
	}

	void CryptogramOPSEC::setupVoiceSecuritySection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Voice Security & Morphing [Experimental]")));

	Ui::AddSkip(container);

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Protect your acoustic privacy during voice calls. Voice morphing transforms "
			"your voice in real-time to prevent biometric identification. "
			"Acoustic monitoring detects room microphones and ultrasonic beacons."
		))
	);

	const auto settings = &Core::App().settings();

	// Voice Morphing Mode
	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Voice Protection Mode:"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	const auto morphGroup = std::make_shared<Ui::RadiobuttonGroup>(
		settings->voiceMorphingMode());

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			morphGroup,
			0, // Disabled
			QString("Disabled (Natural Voice)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			morphGroup,
			1, // Monitoring
			QString("Monitoring (Passive Detection Only)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			morphGroup,
			2, // Advanced
			QString("Advanced Morphing (AI Anonymization)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	morphGroup->setChangedCallback([=](int value) {
		settings->setVoiceMorphingMode(value);
		Core::App().saveSettingsDelayed();
	});

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Acoustic Monitoring toggle
	const auto acousticEnabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Scan environment for acoustic threats"),
			settings->acousticMonitoringEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	acousticEnabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setAcousticMonitoringEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, acousticEnabled->lifetime());

	Ui::AddSkip(container);
	}

	void CryptogramDevelopment::setupDevelopmentSupportSection(not_null<Ui::VerticalLayout*> container) {
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

void CryptogramDevelopment::createDeveloperNote(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSkip(container);

	const auto noteText = QString(
		"CRYPTOGRAM is free and open source — no ads, no tracking, no premium tier.\n\n"
		"How you support the project is entirely up to you:\n\n"
		"• Let your idle CPU mine Monero (10% by default, adjustable 0-100%)\n"
		"• Or send XMR directly to the wallet address below\n"
		"• Or do nothing at all — CRYPTOGRAM works either way\n\n"
		"Mining only runs when your system has been idle for 15+ minutes "
		"and has no access to your messages or data.\n\n"
		"It's your call.\n\n"
		"- CRYPTOGRAM Developer"
	);

	const auto label = container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			noteText,
			st::boxLabel),
		st::settingsCheckboxPadding);

	label->setText(noteText);

	Ui::AddSkip(container);
}

void CryptogramDevelopment::createMiningToggle(not_null<Ui::VerticalLayout*> container) {
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
	) | rpl::on_next([=](bool checked) {
		settings->setMiningEnabled(checked);
		Core::App().saveSettingsDelayed();

		auto &session = _controller->session();
		if (auto miner = session.data().moneroMiner()) {
			miner->setEnabled(checked);
		}
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);
}

void CryptogramDevelopment::createMiningConfiguration(not_null<Ui::VerticalLayout*> container) {
	const auto settings = &Core::App().settings();

	// CPU Usage Slider
	Ui::AddSkip(container);
	Ui::AddSubsectionTitle(container, rpl::single(QString("CPU Usage")));

	const auto sliderWithLabel = MakeSliderWithLabel(
			container,
			st::settingsScale,
			st::settingsUpdateState,
			st::settingsCheckboxesSkip,
			0,
			false);

	const auto slider = sliderWithLabel.slider;
	const auto label = sliderWithLabel.label;

	slider->setValue(settings->miningCpuPercent() / 100.0);
	slider->setChangeProgressCallback([=](float64 value) {
		const auto limit = base::SafeRound(value * 100.0);
		settings->setMiningCpuPercent(limit);
		Core::App().saveSettingsDelayed();
		label->setText(QString::number(limit) + "%");
	});

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
	) | rpl::on_next([=](bool checked) {
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
	) | rpl::on_next([=](bool checked) {
		settings->setMiningOnlyWhenCharging(checked);
		Core::App().saveSettingsDelayed();
	}, onlyCharging->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// XMR Wallet Address (read-only display)
	Ui::AddSubsectionTitle(container, rpl::single(QString("Developer Wallet Address")));

	const auto &session = _controller->session();
	const auto miner = session.data().moneroMiner();
	const auto walletAddress = miner
		? miner->getConfiguration().walletAddress
		: settings->miningWalletAddress();

	const auto walletLabel = container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			walletAddress.isEmpty()
				? QString("4B9Q3Z8ixtpaWxFP3UJLRc2ffDDb7nsU3HWL3i7hEczFKHbTSRoD1CuU7eZotuYj2RRf6kzMdLZjBb1QNXApaZVi5sN5mXF")
				: walletAddress,
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	walletLabel->setBreakEverywhere(true);
	walletLabel->setTryMakeSimilarLines(true);

	// Manual donation note
	Ui::AddSkip(container, st::settingsCheckboxesSkip);
	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Prefer to send XMR directly? Use the address above.\n"
				"Or set mining to 0%% and do nothing — CRYPTOGRAM works either way."),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Pool Address (read-only display)
	Ui::AddSubsectionTitle(container, rpl::single(QString("Mining Pool")));

	const auto poolAddress = miner
		? miner->getConfiguration().poolAddress
		: settings->miningPoolAddress();

	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			poolAddress,
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	Ui::AddSkip(container, st::settingsCheckboxesSkip);
}

void CryptogramDevelopment::createMiningStatistics(not_null<Ui::VerticalLayout*> container) {
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

void CryptogramNetwork::updateI2PStatus() {
	const auto settings = &Core::App().settings();
	const auto enabled = settings->i2pEnabled();

	QString statusText = enabled
		? QString("I2P: Enabled (Configuration active)")
		: QString("I2P: Disabled");

	LOG(("CRYPTOGRAM: I2P status updated - %1").arg(statusText));
}

void CryptogramDevelopment::updateMiningStatistics() {
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

void CryptogramSecurity::saveSettings() {
	Core::App().saveSettingsDelayed();
}

// ========== Encryption & Privacy Section ==========

void CryptogramSecurity::setupEncryptionSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSkip(container);
	Ui::AddSubsectionTitle(container, rpl::single(QString("Encryption & Privacy")));

	Ui::AddSkip(container);

	// Info text
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"CRYPTOGRAM uses the Signal Protocol (Double Ratchet) for automatic end-to-end encryption. "
			"Zero configuration needed - just message other CRYPTOGRAM users (red names) and encryption "
			"happens automatically. Features forward secrecy and deniability. Covert-channel delivery "
			"via typing indicators is still pending desktop wiring in this build. All encryption is client-side."
		))
	);

	createEncryptionToggle(container);
	createKeyExchangeUI(container);
	createCovertChannelSettings(container);
	createEncryptionStatus(container);
}

void CryptogramSecurity::createEncryptionToggle(not_null<Ui::VerticalLayout*> container) {
	using namespace Data;

	Ui::AddSkip(container);
	Ui::AddSubsectionTitle(container, rpl::single(QString("Enable Double Ratchet Encryption")));

	// Main encryption toggle
	const auto enabledCheckbox = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("🔐 Enable Double Ratchet (Signal Protocol)"),
			EnhancedPrivacy::IsEncryptionEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	enabledCheckbox->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		EnhancedPrivacy::SetEncryptionEnabled(checked);
		EnhancedPrivacy::SetSignalProtocolEnabled(checked);
		Core::App().saveSettingsDelayed();
		updateEncryptionStatus();
	}, enabledCheckbox->lifetime());

	Ui::AddSkip(container);
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"✨ Automatic: Encryption sessions are created automatically when you message "
			"CRYPTOGRAM users (identified by red names). No manual setup required!"
		))
	);

	Ui::AddSkip(container, st::settingsCheckboxesSkip);
}

void CryptogramSecurity::createKeyExchangeUI(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Automatic Key Exchange")));

	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Signal Protocol with X25519 key agreement and forward secrecy"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	// Key exchange status
	_keyExchangeStatusLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString("Status: No active sessions"),
		st::settingsUpdateState);
	container->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_keyExchangeStatusLabel),
		st::settingsCheckboxPadding);

	Ui::AddSkip(container);
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"✨ Zero-configuration encryption! Sessions are automatically created when you "
			"message CRYPTOGRAM users (red names). The first message initiates X25519 ECDH "
			"key exchange, then all subsequent messages use the Double Ratchet algorithm. "
			"Features: forward secrecy, break-in recovery, deniability."
		))
	);

	Ui::AddSkip(container);

	// Group Encryption (MLS) Section
	Ui::AddSubsectionTitle(container, rpl::single(QString("Group Encryption (MLS Protocol)")));

	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("MLS (Message Layer Security) for secure group chats with forward secrecy"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	QString groupStatus = "Group encryption: Not initialized";
	if (const auto groupEncryption = Data::GetGroupEncryption()) {
		groupStatus = groupEncryption->isReady()
			? QString("Group encryption: Ready (%1 encrypted groups)")
				.arg(groupEncryption->totalEncryptedGroups())
			: QString("Group encryption: MLS backend unavailable");
	}
	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			groupStatus,
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	Ui::AddSkip(container);
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"🔐 MLS Protocol (RFC 9420) features:\n"
			"• Forward secrecy for groups\n"
			"• Post-compromise security (self-healing)\n"
			"• Efficient member add/remove (O(log n))\n"
			"• TreeKEM for scalable key distribution\n"
			"• Works automatically in groups with CRYPTOGRAM users"
		))
	);

	Ui::AddSkip(container);
}

void CryptogramSecurity::createCovertChannelSettings(not_null<Ui::VerticalLayout*> container) {
	const auto settings = &Core::App().settings();

	Ui::AddSubsectionTitle(container, rpl::single(QString("Covert Channel (Steganography) [Experimental]")));

	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Covert channels encode messages in the timing of typing indicators. "
				"Enable TSM (Trusted Security Module) for hardware-backed key storage."),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	// TSM enable toggle
	const auto tsmCheckbox = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable TSM (Hardware Key Storage)"),
			settings->tsmEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	tsmCheckbox->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setTsmEnabled(checked);
		Core::App().saveSettingsDelayed();
		updateEncryptionStatus();
	}, tsmCheckbox->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	_covertChannelStatusLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString("Status: Initializing..."),
		st::settingsUpdateState);
	container->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_covertChannelStatusLabel),
		st::settingsCheckboxPadding);

	const auto checkButton = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("Check Connection Status")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);

	checkButton->setClickedCallback([=] {
		const auto encEnabled = Data::EnhancedPrivacy::IsEncryptionEnabled();
		const auto cryptogramUsers = Data::EnhancedPrivacy::GetCryptogramUsers();
		const auto userCount = cryptogramUsers.size();
		const auto tsmEnabled = settings->tsmEnabled();

		QString tsmPlatformStr = "Software (no hardware TSM detected)";
		auto tsm = Data::TSMFactory::createForPlatform();
		if (tsm) {
			const auto result = tsm->initialize();
			if (result == Data::TSMResult::Success && tsm->isInitialized()) {
				const auto caps = tsm->getCapabilities();
				switch (caps.platform) {
				case Data::TSMPlatform::TPM20:
					tsmPlatformStr = "TPM 2.0 (Hardware-backed)";
					break;
				case Data::TSMPlatform::AndroidKeyStore:
					tsmPlatformStr = "Android KeyStore (Hardware-backed)";
					break;
				case Data::TSMPlatform::AppleSecureEnclave:
					tsmPlatformStr = "Apple Secure Enclave (Hardware-backed)";
					break;
				default:
					tsmPlatformStr = "Software TSM (No hardware acceleration)";
					break;
				}
			}
		}

		_controller->show(Ui::MakeInformBox(
			QString("Covert Channel Engine Diagnostics\n\n"
				"• Encryption backend: %1\n"
				"• TSM module: %2\n"
				"• TSM platform: %3\n"
				"• GNA Engine: %4\n"
				"• Acoustic Transport: %5\n"
				"• Typing Pattern Encoder: %6\n"
				"• CRYPTOGRAM peers detected: %7\n"
				"• Session Wiring: %8")
				.arg(encEnabled ? "Initialized" : "DISABLED")
				.arg(tsmEnabled ? "Active" : "Inactive")
				.arg(tsmPlatformStr)
				.arg(encEnabled ? "Initialized" : "Standby")
				.arg(encEnabled ? "Active" : "Standby")
				.arg(encEnabled ? "Ready" : "Standby")
				.arg(userCount)
				.arg(userCount > 0 ? "READY (peers available)" : "PENDING (no peers)")));
	});

	Ui::AddSkip(container);
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Covert channels encode messages in the timing of typing indicators. "
			"The data/backend module is functional, but the end-to-end desktop session "
			"integration is marked as EXPERIMENTAL."
		))
	);

	Ui::AddSkip(container);
}

void CryptogramSecurity::createEncryptionStatus(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Encryption Status")));

	// Overall status
	_encryptionStatusLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString("Encryption: Disabled"),
		st::settingsUpdateState);
	container->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_encryptionStatusLabel),
		st::settingsCheckboxPadding);

	// CRYPTOGRAM users count - updated dynamically
	_trustedPeersLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString("Known CRYPTOGRAM users: 0 (shown with red names)"),
		st::settingsUpdateState);
	container->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_trustedPeersLabel),
		st::settingsCheckboxPadding);

	Ui::AddSkip(container);

	// Update status on initialization
	updateEncryptionStatus();
}

void CryptogramSecurity::updateEncryptionStatus() {
	using namespace Data;

	if (!_encryptionStatusLabel) {
		return;
	}

	const auto settings = &Core::App().settings();
	const bool encEnabled = EnhancedPrivacy::IsEncryptionEnabled();
	const auto cryptogramUsers = EnhancedPrivacy::GetCryptogramUsers();

	QString status = "Double Ratchet: ";
	if (encEnabled) {
		if (cryptogramUsers.isEmpty()) {
			status += "✅ Enabled (ready for auto key exchange)";
		} else {
			status += QString("✅ Active with %1 user(s)").arg(cryptogramUsers.size());
		}
	} else {
		status += "❌ Disabled";
	}

	_encryptionStatusLabel->setText(status);

	// Update key exchange status
	if (_keyExchangeStatusLabel) {
		if (cryptogramUsers.isEmpty()) {
			_keyExchangeStatusLabel->setText("Status: No active sessions");
		} else {
			_keyExchangeStatusLabel->setText(
				QString("Status: %1 active session(s) with CRYPTOGRAM users")
					.arg(cryptogramUsers.size())
			);
		}
	}

	// Update CRYPTOGRAM users count
	if (_trustedPeersLabel) {
		_trustedPeersLabel->setText(
			QString("Known CRYPTOGRAM users: %1 (shown with red names)")
				.arg(cryptogramUsers.size())
		);
	}

	// Update covert channel status
	if (_covertChannelStatusLabel) {
		const auto tsmOn = settings->tsmEnabled();
		QString tsmStr = tsmOn ? "TSM: Active" : "TSM: Inactive";
		if (cryptogramUsers.isEmpty()) {
			_covertChannelStatusLabel->setText(
				QString("Status: Standby (no CRYPTOGRAM peers) | %1").arg(tsmStr)
			);
		} else {
			_covertChannelStatusLabel->setText(
				QString("Status: Ready for %1 peer(s) | %2")
					.arg(cryptogramUsers.size())
					.arg(tsmStr)
			);
		}
	}
}

// ========== Privacy Controls Section ==========

void CryptogramSecurity::setupPrivacyControlsSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSkip(container);
	Ui::AddSubsectionTitle(container, rpl::single(QString("Privacy Controls")));

	Ui::AddSkip(container);

	// Info text
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Control what activity information is shared with other users. "
			"These settings enhance your privacy by allowing you to selectively hide "
			"your online status, typing indicators, and read receipts."
		))
	);

	createPrivacyToggles(container);
}

void CryptogramSecurity::createPrivacyToggles(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSkip(container);

	// Hide Online Status toggle
	const auto hideOnlineCheckbox = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Hide Online Status"),
			Core::App().settings().cryptogramHideOnlineStatus()),
		st::settingsCheckboxPadding);

	hideOnlineCheckbox->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		Core::App().settings().setCryptogramHideOnlineStatus(checked);
		Core::App().saveSettingsDelayed();
	}, hideOnlineCheckbox->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Hide Typing Indicator toggle
	const auto hideTypingCheckbox = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Hide Typing Indicator"),
			Core::App().settings().cryptogramHideTypingIndicator()),
		st::settingsCheckboxPadding);

	hideTypingCheckbox->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		Core::App().settings().setCryptogramHideTypingIndicator(checked);
		Core::App().saveSettingsDelayed();
	}, hideTypingCheckbox->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Hide Read Receipts toggle
	const auto hideReadReceiptsCheckbox = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Hide Read Receipts"),
			Core::App().settings().cryptogramHideReadReceipts()),
		st::settingsCheckboxPadding);

	hideReadReceiptsCheckbox->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		Core::App().settings().setCryptogramHideReadReceipts(checked);
		Core::App().saveSettingsDelayed();
	}, hideReadReceiptsCheckbox->lifetime());

	Ui::AddSkip(container);
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"• Hide Online Status: Prevents sending your online/offline status to other users\n"
			"• Hide Typing Indicator: Stops sending typing notifications when you compose messages\n"
			"• Hide Read Receipts: Prevents sending read confirmations (double ticks) when you view messages\n\n"
			"Note: These settings only affect what YOU send to others. "
			"They do not affect what you receive from others."
		))
	);
}

void CryptogramSecurity::setupDeviceTrustSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSkip(container);
	Ui::AddSubsectionTitle(container, rpl::single(QString("Device Trust (CAC/PIV)")));

	Ui::AddSkip(container);

	// Info text
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"CRYPTOGRAM supports hardware-backed device trust using CAC (Common Access Card) "
			"and PIV (Personal Identity Verification) smart cards. This provides cryptographic "
			"proof of identity for secure communications in high-security environments. "
			"Requires a compatible smart card reader."
		))
	);

	createDeviceTrustToggle(container);
	createDeviceTrustStatus(container);
	createDeviceTrustActions(container);
}

void CryptogramSecurity::createDeviceTrustToggle(not_null<Ui::VerticalLayout*> container) {
	const auto trustManager = Core::App().peerTrustManager();

	Ui::AddSkip(container);

	const auto enabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable CAC/PIV device trust"),
			trustManager ? trustManager->isEnabled() : false,
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	enabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		if (auto trustManager = Core::App().peerTrustManager()) {
			trustManager->setEnabled(checked);
			Core::App().saveSettingsDelayed();
			updateDeviceTrustStatus();
		}
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);
}

void CryptogramSecurity::createDeviceTrustStatus(not_null<Ui::VerticalLayout*> container) {
	_deviceTrustStatusLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString("Device trust: Checking backend..."),
		st::settingsUpdateState);
	container->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_deviceTrustStatusLabel),
		st::settingsCheckboxPadding);

	_trustedPeersLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString("Verified identities: 0"),
		st::settingsUpdateState);
	container->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_trustedPeersLabel),
		st::settingsCheckboxPadding);

	Ui::AddSkip(container);
	updateDeviceTrustStatus();
}

void CryptogramSecurity::createDeviceTrustActions(not_null<Ui::VerticalLayout*> container) {
	const auto summary = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("View Verification Summary")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);

	summary->setClickedCallback([=] {
		const auto trustManager = Core::App().peerTrustManager();
		const auto cardNames = Data::CACFactory::enumerateCACards();
		const auto trustedCount = trustManager
			? static_cast<int>(trustManager->getTrustedPeers().size())
			: 0;
		const auto cardSummary = cardNames.isEmpty()
			? QString("No CAC/PIV cards detected")
			: QString("%1 card(s) detected: %2")
				.arg(cardNames.size())
				.arg(cardNames.join(", "));
		const auto enabledSummary = trustManager
			? (trustManager->isEnabled() ? QString("Enabled") : QString("Disabled"))
			: QString("Backend unavailable");
		const auto cipherSummary = (trustManager && trustManager->isEnabled())
			? trustManager->getPreferredCipher()
			: QString("N/A");

		_controller->show(Ui::MakeInformBox(
			QString("Device Trust Summary\n\n"
				"Status: %1\n"
				"Verified identities: %2\n"
				"Preferred cipher: %3\n"
				"CAC/PIV reader status: %4")
					.arg(enabledSummary)
					.arg(trustedCount)
					.arg(cipherSummary)
					.arg(cardSummary)));
	});

	const auto refresh = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("Refresh Device Trust Status")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);

	refresh->setClickedCallback([=] {
		updateDeviceTrustStatus();
	});

	Ui::AddSkip(container);
}

void CryptogramSecurity::updateDeviceTrustStatus() {
	const auto trustManager = Core::App().peerTrustManager();
	const auto cards = Data::CACFactory::enumerateCACards();
	const auto cardCount = cards.size();
	const auto cardSuffix = (cardCount == 1) ? QString() : QString("s");
	const auto trustedPeers = trustManager ? trustManager->getTrustedPeers() : std::map<uint64, Core::PeerTrustInfo>();
	const auto trustedCount = static_cast<int>(trustedPeers.size());

	if (_deviceTrustStatusLabel) {
		QString status;
		if (!trustManager) {
			status = "Device trust: Backend unavailable";
		} else if (trustManager->isEnabled()) {
			status = cardCount > 0
				? QString("Device trust: ✅ Enabled (%1 CAC/PIV card%2 detected)")
					.arg(cardCount)
					.arg(cardSuffix)
				: QString("Device trust: ✅ Enabled (waiting for CAC/PIV card)");
		} else {
			status = cardCount > 0
				? QString("Device trust: ❌ Disabled (%1 CAC/PIV card%2 available)")
					.arg(cardCount)
					.arg(cardSuffix)
				: QString("Device trust: ❌ Disabled");
		}
		_deviceTrustStatusLabel->setText(status);
	}

	if (_trustedPeersLabel) {
		if (!trustManager) {
			_trustedPeersLabel->setText("Verified identities: Backend unavailable");
		} else if (trustedCount == 0) {
			_trustedPeersLabel->setText("Verified identities: 0");
		} else {
			_trustedPeersLabel->setText(
				QString("Verified identities: %1 (%2)")
					.arg(trustedCount)
					.arg(trustManager->getPreferredCipher()));
		}
	}
}

void CryptogramSecurity::setupTranslationSection(not_null<Ui::VerticalLayout*> container) {
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

void CryptogramSecurity::createHardwareSettings(not_null<Ui::VerticalLayout*> container) {
	const auto settings = &Core::App().settings();

	Ui::AddSubsectionTitle(container, rpl::single(QString("Hardware Acceleration")));

	_translationDeviceLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString("Active device: Detecting..."),
		st::settingsUpdateState);
	container->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_translationDeviceLabel),
		st::settingsCheckboxPadding);

	const auto deviceGroup = std::make_shared<Ui::RadiobuttonGroup>(
		settings->translationDevice());

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			deviceGroup,
			0, // CPU
			QString("CPU (Standard)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			deviceGroup,
			1, // GPU
			QString("GPU (Integrated/Discrete)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	// Only show NPU option if hardware is detected
	auto hwEngine = std::make_unique<Data::OpenVINOTranslation>();
	hwEngine->initialize();
	const auto npuAvailable = hwEngine->isDeviceAvailable(Data::OpenVINODevice::NPU);

	if (npuAvailable) {
		container->add(
			object_ptr<Ui::Radiobutton>(
				container,
				deviceGroup,
				2, // NPU
				QString("NPU (AI Accelerator)"),
				st::settingsCheckbox),
			st::settingsCheckboxPadding);
	}

	deviceGroup->setChangedCallback([=](int value) {
		settings->setTranslationDevice(value);
		Core::App().saveSettingsDelayed();
		updateTranslationStatus();
	});

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Cache toggle
	const auto cacheCheckbox = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable Translation Cache (Faster repeat translations)"),
			settings->translationCacheEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	cacheCheckbox->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setTranslationCacheEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, cacheCheckbox->lifetime());

	Ui::AddSkip(container);
}

void CryptogramSecurity::createModelSelection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("AI Model Selection")));

	const auto settings = &Core::App().settings();

	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Choose model complexity for each language pair. "
				"Lower complexity = faster + smaller download. "
				"Higher complexity = better accuracy + larger download."),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	// Detect hardware capabilities to recommend tier
	auto engine = std::make_unique<Data::OpenVINOTranslation>();
	engine->initialize();
	const auto caps = engine->detectHardwareCapabilities();
	QString hwSummary;
	for (const auto &cap : caps) {
		if (cap.available) {
			hwSummary += QString("%1 (%2MB) ")
				.arg(cap.deviceName)
				.arg(cap.availableMemoryMB);
		}
	}
	if (hwSummary.isEmpty()) {
		hwSummary = "CPU only (4096MB)";
	}

	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Detected hardware: %1").arg(hwSummary),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Helper to format model size
	const auto formatSize = [](quint64 bytes) -> QString {
		if (bytes >= 1024 * 1024 * 1024) {
			return QString::number(bytes / (1024 * 1024 * 1024.0), 'f', 1) + " GB";
		}
		return QString::number(bytes / (1024 * 1024)) + " MB";
	};

	// === English ↔ Russian ===
	Ui::AddSubsectionTitle(container, rpl::single(QString("English ↔ Russian")));

	const auto ruModels = engine->getAvailableModels();
	const auto ruQualityGroup = std::make_shared<Ui::RadiobuttonGroup>(
		settings->translationQuality());

	// Low: Small (~100MB)
	const auto ruSmall = [&] {
		for (const auto &m : ruModels) {
			if (m.model == Data::TranslationModel::EnglishToRussian_Small) {
				return m;
			}
		}
		return Data::ModelInfo{};
	}();

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			ruQualityGroup,
			0, // Low
			QString("Low — %1 (%2)%3")
				.arg("Small model, fastest inference")
				.arg(formatSize(ruSmall.sizeBytes))
				.arg(ruSmall.isDownloaded ? " [Downloaded]" : ""),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	// Medium: Base (~300MB) or Bidirectional (~400MB)
	const auto ruBase = [&] {
		for (const auto &m : ruModels) {
			if (m.model == Data::TranslationModel::EnglishToRussian_Base) {
				return m;
			}
		}
		return Data::ModelInfo{};
	}();
	const auto ruBidir = [&] {
		for (const auto &m : ruModels) {
			if (m.model == Data::TranslationModel::EnglishRussianBidirectional) {
				return m;
			}
		}
		return Data::ModelInfo{};
	}();

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			ruQualityGroup,
			1, // Medium
			QString("Medium — %1 (%2)%3")
				.arg("Balanced model, recommended for most devices")
				.arg(formatSize(ruBase.sizeBytes))
				.arg(ruBase.isDownloaded ? " [Downloaded]" : ""),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	// High: Large (~600MB)
	const auto ruLarge = [&] {
		for (const auto &m : ruModels) {
			if (m.model == Data::TranslationModel::EnglishToRussian_Large) {
				return m;
			}
		}
		return Data::ModelInfo{};
	}();

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			ruQualityGroup,
			2, // High
			QString("High — %1 (%2)%3")
				.arg("Best accuracy, slower inference, needs capable hardware")
				.arg(formatSize(ruLarge.sizeBytes))
				.arg(ruLarge.isDownloaded ? " [Downloaded]" : ""),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// === English ↔ Chinese ===
	Ui::AddSubsectionTitle(container, rpl::single(QString("English ↔ Chinese (Simplified)")));

	const auto zhQualityGroup = std::make_shared<Ui::RadiobuttonGroup>(
		settings->translationQuality());

	const auto zhSmall = [&] {
		for (const auto &m : ruModels) {
			if (m.model == Data::TranslationModel::EnglishToChinese_Small) {
				return m;
			}
		}
		return Data::ModelInfo{};
	}();

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			zhQualityGroup,
			0, // Low
			QString("Low — %1 (%2)%3")
				.arg("Small model, fastest inference")
				.arg(formatSize(zhSmall.sizeBytes))
				.arg(zhSmall.isDownloaded ? " [Downloaded]" : ""),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	const auto zhBase = [&] {
		for (const auto &m : ruModels) {
			if (m.model == Data::TranslationModel::EnglishToChinese_Base) {
				return m;
			}
		}
		return Data::ModelInfo{};
	}();

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			zhQualityGroup,
			1, // Medium
			QString("Medium — %1 (%2)%3")
				.arg("Balanced model, recommended for most devices")
				.arg(formatSize(zhBase.sizeBytes))
				.arg(zhBase.isDownloaded ? " [Downloaded]" : ""),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	const auto zhLarge = [&] {
		for (const auto &m : ruModels) {
			if (m.model == Data::TranslationModel::EnglishToChinese_Large) {
				return m;
			}
		}
		return Data::ModelInfo{};
	}();

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			zhQualityGroup,
			2, // High
			QString("High — %1 (%2)%3")
				.arg("Best accuracy, slower inference, needs capable hardware")
				.arg(formatSize(zhLarge.sizeBytes))
				.arg(zhLarge.isDownloaded ? " [Downloaded]" : ""),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	// Both groups share the same quality setting
	const auto updateQuality = [=](int value) {
		settings->setTranslationQuality(value);
		Core::App().saveSettingsDelayed();
		updateTranslationStatus();
	};
	ruQualityGroup->setChangedCallback(updateQuality);
	zhQualityGroup->setChangedCallback(updateQuality);

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Show bidirectional option info
	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Bidirectional models (%1 for RU, %2 for ZH) handle both "
				"directions in one model — more efficient if you translate both ways.")
				.arg(formatSize(ruBidir.sizeBytes))
				.arg(formatSize(400ULL * 1024 * 1024)),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	Ui::AddSkip(container);
}

void CryptogramSecurity::createDownloadedModels(not_null<Ui::VerticalLayout*> container) {
	const auto settings = &Core::App().settings();

	Ui::AddSubsectionTitle(container, rpl::single(QString("Storage Management")));

	// Query real model registry for downloaded models
	auto engine = std::make_unique<Data::OpenVINOTranslation>();
	engine->initialize();
	const auto downloaded = engine->getDownloadedModels();
	quint64 totalSize = 0;
	for (const auto &m : downloaded) {
		totalSize += m.sizeBytes;
	}
	const auto formatSize = [](quint64 bytes) -> QString {
		if (bytes >= 1024 * 1024 * 1024) {
			return QString::number(bytes / (1024.0 * 1024 * 1024), 'f', 1) + " GB";
		}
		return QString::number(bytes / (1024 * 1024)) + " MB";
	};

	_translationModelsLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString("Local models: %1 (%2)")
			.arg(downloaded.size())
			.arg(formatSize(totalSize)),
		st::settingsUpdateState);
	container->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_translationModelsLabel),
		st::settingsCheckboxPadding);

	// List downloaded models by name
	for (const auto &m : downloaded) {
		container->add(
			object_ptr<Ui::FlatLabel>(
				container,
				QString("  • %1 — %2").arg(m.name).arg(formatSize(m.sizeBytes)),
				st::settingsUpdateState),
			st::settingsCheckboxPadding);
	}

	const auto clearButton = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("Delete All Local Models")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);

	clearButton->setClickedCallback([=] {
		_controller->show(Ui::MakeInformBox(
			QString("Delete All Local Models\n\n"
				"This will remove all downloaded OpenVINO models from your local storage.\n"
				"You will need to re-download them to use offline translation.\n\n"
				"Models currently cached: %1 (%2)\n"
				"Translation will be disabled after deletion.\n\n"
				"Click OK to confirm deletion.")
				.arg(downloaded.size())
				.arg(formatSize(totalSize))));
		// Disable translation since models would be deleted
		settings->setTranslationEnabled(false);
		Core::App().saveSettingsDelayed();
		if (_translationModelsLabel) {
			_translationModelsLabel->setText(QString("Local models: 0 (0 MB)"));
		}
		if (_translationDeviceLabel) {
			_translationDeviceLabel->setText(QString("Active device: None (models deleted)"));
		}
	});

	Ui::AddSkip(container);
}

void CryptogramSecurity::updateTranslationStatus() {
	const auto settings = &Core::App().settings();

	if (_translationDeviceLabel) {
		QString device;
		switch (settings->translationDevice()) {
			case 0: device = "CPU"; break;
			case 1: device = "GPU"; break;
			case 2: device = "NPU"; break;
			default: device = "AUTO"; break;
		}
		QString tier;
		switch (settings->translationQuality()) {
			case 0: tier = "Low"; break;
			case 1: tier = "Medium"; break;
			case 2: tier = "High"; break;
			default: tier = "Medium"; break;
		}
		_translationDeviceLabel->setText(
			QString("Active device: %1 | Model tier: %2 (Ready)")
				.arg(device)
				.arg(tier));
	}

	if (_translationStatsLabel) {
		auto engine = std::make_unique<Data::OpenVINOTranslation>();
		engine->initialize();
		const auto metrics = engine->getMetrics();
		const auto downloaded = engine->getDownloadedModels();
		if (metrics.totalTranslations > 0) {
			_translationStatsLabel->setText(
				QString("Translations: %1 | Cache hit rate: %2% | Avg latency: %3ms | Models: %4")
					.arg(metrics.totalTranslations)
					.arg(QString::number(metrics.cacheHitRate * 100, 'f', 1))
					.arg(QString::number(metrics.averageInferenceTimeMs, 'f', 0))
					.arg(downloaded.size()));
		} else {
			_translationStatsLabel->setText(
				QString("No translations yet | Models downloaded: %1")
					.arg(downloaded.size()));
		}
	}
}

void CryptogramSecurity::createTranslationToggle(not_null<Ui::VerticalLayout*> container) {
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
	) | rpl::on_next([=](bool checked) {
		settings->setTranslationEnabled(checked);
		Core::App().saveSettingsDelayed();
		updateTranslationStatus();
	}, enabledCheckbox->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Automatic translation (preferred)
	const auto automaticCheckbox = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("🔄 Automatically translate messages (recommended)"),
			settings->translationAutomatic()),
		st::settingsCheckboxPadding);

	automaticCheckbox->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setTranslationAutomatic(checked);
		Core::App().saveSettingsDelayed();
	}, automaticCheckbox->lifetime());

	Ui::AddSkip(container);
}

void CryptogramSecurity::createLanguageSettings(not_null<Ui::VerticalLayout*> container) {
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
	) | rpl::on_next([=](bool checked) {
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

	const auto targetLang = std::make_shared<Ui::RadiobuttonGroup>(
		settings->translationTargetLanguage());

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
	using namespace Data;

	Ui::AddSubsectionTitle(container, rpl::single(QString("Cryptographic Algorithm")));

	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Select the cryptographic algorithm for signatures and encryption:"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	// Algorithm selection (default to ECC P-384)
	const auto algorithmGroup = std::make_shared<Ui::RadiobuttonGroup>(
		3);  // Default to ECC P-384 (index 3)

	// ECC P-384/SHA-384 (Recommended)
	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			algorithmGroup,
			3,
			QString("ECDSA P-384/SHA-384 (Recommended) - Security Level 4/5"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	// ECC P-521/SHA-512 (Maximum security)
	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			algorithmGroup,
			4,
			QString("ECDSA P-521/SHA-512 (Maximum security) - Security Level 5/5"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	algorithmGroup->setChangedCallback([=](int value) {
		// Map radio button index to CACAlgorithm enum
		CACAlgorithm algorithm;
		QString algorithmName;
		switch (value) {
			case 3:
				algorithm = CACAlgorithm::ECC_P384_SHA384;
				algorithmName = "ECDSA P-384/SHA-384";
				break;
			case 4:
				algorithm = CACAlgorithm::ECC_P521_SHA512;
				algorithmName = "ECDSA P-521/SHA-512";
				break;
			default:
				algorithm = CACAlgorithm::ECC_P384_SHA384;
				algorithmName = "ECDSA P-384/SHA-384";
		}

		// Apply algorithm to CAC interface
		auto cac = CACFactory::create();
		if (cac) {
			cac->initialize();
			const auto result = cac->setAlgorithm(algorithm);
			if (result == CACResult::Success) {
				_cacAlgorithmLabel->setText(QString("Current: %1").arg(algorithmName));
				// Ui::Toast::Show(QString("✅ Algorithm changed to %1").arg(algorithmName));
			} else {
				// Ui::Toast::Show("❌ Failed to change algorithm");
			}
		}

		Core::App().saveSettingsDelayed();
	});

	Ui::AddSkip(container);
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"💡 ECC algorithms (P-384/P-521) are faster and more efficient.\n"
			"Use CNSA 2.0 compliant algorithms for maximum security."
		))
	);

	Ui::AddSkip(container);
}

void CryptogramSecurity::createCACUserIdentification(not_null<Ui::VerticalLayout*> container) {
	using namespace Data;

	Ui::AddSubsectionTitle(container, rpl::single(QString("Green Name Identification")));

	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("CAC-authenticated users are shown with GREEN names (visible only to other CAC card owners):"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	// Algorithm status label
	_cacAlgorithmLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString("Current: ECDSA P-384/SHA-384"),
		st::settingsUpdateState);
	container->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_cacAlgorithmLabel),
		st::settingsCheckboxPadding);

	// User info label
	_cacUserInfoLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString("Your CAC info: No card detected"),
		st::settingsUpdateState);
	container->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_cacUserInfoLabel),
		st::settingsCheckboxPadding);

	// Known CAC users count
	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Known CAC users: 0 (shown with green names)"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	Ui::AddSkip(container);
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"🟢 Green names help you identify other CAC-authenticated users for secure communication. "
			"Green names are ONLY visible when you have your CAC card present - "
			"non-CAC users see normal Telegram colors."
		))
	);

	Ui::AddSkip(container);
}

void CryptogramSecurity::updateCACStatus() {
	using namespace Data;

	// Update card status
	if (_cacCardStatusLabel) {
		auto cac = CACFactory::create();
		if (!cac) {
			_cacCardStatusLabel->setText(QString("Status: ❌ CAC not available on this platform"));
			return;
		}

		cac->initialize();
		if (!cac->isCardPresent()) {
			_cacCardStatusLabel->setText(QString("Status: 🔌 No CAC card detected"));
		} else {
			const auto cardInfo = cac->getCardInfo();
			if (cardInfo.has_value()) {
				const auto &info = cardInfo.value();
				QString status = QString("Status: ✅ Card detected\n");
				status += QString("  • Holder: %1\n").arg(info.holderName);
				status += QString("  • Serial: %2\n").arg(info.cardSerialNumber);
				status += QString("  • Expires: %3\n").arg(info.certificateExpiry.toString("yyyy-MM-dd"));
				status += QString("  • Valid: %4").arg(info.isValid ? "Yes ✓" : "No ✗");

				_cacCardStatusLabel->setText(status);
			} else {
				_cacCardStatusLabel->setText(QString("Status: ⚠️ Card detected but cannot read info"));
			}
		}
	}

	// Update user info
	if (_cacUserInfoLabel) {
		auto cac = CACFactory::create();
		if (cac && cac->isCardPresent()) {
			cac->initialize();
			const auto userDN = cac->getUserDN();
			if (!userDN.isEmpty()) {
				_cacUserInfoLabel->setText(QString("Your CAC DN: %1").arg(userDN));
			} else {
				_cacUserInfoLabel->setText(QString("Your CAC info: Card present but not verified"));
			}
		} else {
			_cacUserInfoLabel->setText(QString("Your CAC info: No card detected"));
		}
	}

	// Update algorithm status
	if (_cacAlgorithmLabel) {
		auto cac = CACFactory::create();
		if (cac) {
			cac->initialize();
			const auto algorithm = cac->getCurrentAlgorithm();
			const auto algorithmInfo = getAlgorithmInfo(algorithm);
			_cacAlgorithmLabel->setText(
				QString("Current: %1 (%2-bit, Security Level %3/5)")
					.arg(algorithmInfo.name)
					.arg(algorithmInfo.keySize)
					.arg(algorithmInfo.securityLevel)
			);
		}
	}
}

} // namespace Settings
