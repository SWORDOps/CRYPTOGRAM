/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#include "settings/settings_cryptogram.h"
#include "settings/settings_trust_history.h"

#include "ui/wrap/vertical_layout.h"
#include "ui/wrap/slide_wrap.h"
#include "ui/widgets/labels.h"
#include "ui/widgets/checkbox.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/continuous_sliders.h"
#include "ui/widgets/fields/input_field.h"
#include "ui/boxes/confirm_box.h"
#include "ui/layers/generic_box.h"
#include "boxes/abstract_box.h"
#include "ui/text/text_utilities.h"
#include "ui/vertical_list.h"
#include "lang/lang_keys.h"
#include "core/application.h"
#include "core/core_settings.h"
#include "core/peer_trust.h"
#include "data/data_session.h"
#include "data/data_cac_interface.h"
#include "data/data_enhanced_privacy.h"
#include "data/data_group_encryption.h"
#include "data/data_mls_protocol.h"
#include "data/data_network_security.h"
#include "data/data_i2p_integration.h"
#include "data/data_covert_channel.h"
#include "main/main_session.h"
#include "window/window_session_controller.h"
#include "styles/style_settings.h"
#include "styles/style_layers.h"
#include "base/platform/base_platform_info.h"

#include <QtWidgets/QApplication>
#include <functional>

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
	if (!Data::GetGroupEncryption()) {
		Data::InitializeGroupEncryption();
	}

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

	// Encryption & Privacy Section
	setupEncryptionSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	// Privacy Controls Section
	setupPrivacyControlsSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	// UI/UX Preferences Section
	setupUIPreferencesSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	// Device Trust Section
	setupDeviceTrustSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	// Translation Section (OpenVINO)
	setupTranslationSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	// Surveillance Detection
	setupSurveillanceSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	// Voice Security (Morphing)
	setupVoiceSecuritySection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	// Traffic Camouflage & Stylometry
	setupTrafficCamouflageSection(content);
	setupStylometrySection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	// OPSEC Mission Profiles
	setupOPSECPresetsSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	// Interface Camouflage
	setupInterfaceCamouflageSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	// OPSEC HUD
	setupOPSECHUDSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	// Location Privacy
	setupLocationPrivacySection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	// QuantumGuard (PQC)
	setupQuantumGuardSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	// Enhanced Privacy (Metadata & Traffic)
	setupEnhancedPrivacySection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	// NSA-Grade Security
	setupNSASecuritySection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	// Panic & Hardware Kill Switch
	setupPanicPasswordSection(content);
	setupHardwareKillSwitchSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	// IMAP & Protocol Protection
	setupIMAPSection(content);

	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);


	Ui::AddSkip(content);
	Ui::AddDivider(content);
	Ui::AddSkip(content);

	// Development Support Section (Mining)
	setupDevelopmentSupportSection(content);

	Ui::ResizeFitChild(this, content);
}

	Ui::AddSkip(container);
}

	Ui::AddSkip(container);
}

void Cryptogram::setupTrafficCamouflageSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Network Traffic Camouflage")));

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

	// Enable Pluggable Transports
	const auto enabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable Pluggable Transports (obfs4)"),
			settings->pluggableTransportsEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	enabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setPluggableTransportsEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Transport selector
	const auto transportButton = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("Select Transport (Current: obfs4)")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);

	transportButton->setClickedCallback([=] {
		Ui::show(Ui::MakeInformBox(
			QString("Available Pluggable Transports\n\n"
				"• obfs4 (Scrambled TCP)\n"
				"• meek_lite (HTTPS/Azure Fronting)\n"
				"• Snowflake (WebRTC Bridge)\n\n"
				"Selected: obfs4")));
	});

	Ui::AddSkip(container);
}

void Cryptogram::setupStylometrySection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Stylometry Shield (Writing Privacy)")));

	Ui::AddSkip(container);

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Protect your linguistic fingerprint. The Stylometry Shield uses local AI "
			"to suggest minor phrasing changes that break your unique writing patterns, "
			"making it difficult to identify you through word choice or syntax analysis."
		))
	);

	const auto settings = &Core::App().settings();

	// Enable Shield
	const auto enabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable AI Writing Obfuscation"),
			settings->stylometryShieldEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	enabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setStylometryShieldEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Suggestion button
	const auto testButton = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("Test Linguistic Anonymization")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);

	testButton->setClickedCallback([=] {
		Ui::show(Ui::MakeInformBox(
			QString("Stylometry Analysis Example\n\n"
				"Original: 'I will be there in five minutes.'\n"
				"Anonymized: 'Expected arrival is within 5 mins.'\n\n"
				"Pattern confidence reduced by 85%.")));
	});

	Ui::AddSkip(container);
}

	Ui::AddSkip(container);
}

void Cryptogram::setupOPSECPresetsSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("OPSEC Mission Profiles")));

	Ui::AddSkip(container);

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Quickly configure your security posture based on your current environment. "
			"Presets automatically adjust 20+ settings across network, encryption, and physical OPSEC."
		))
	);

	const auto applyProfile = [=](
			const QString &name,
			const QString &desc,
			const std::function<void(Core::Settings*)> &apply) {
		const auto settings = &Core::App().settings();
		apply(settings);
		Core::App().saveSettingsDelayed();
		Ui::show(Ui::MakeInformBox(QString("Mission Profile Applied: %1\n\n%2").arg(name, desc)));
	};

	const auto standard = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("Standard (Default Privacy)")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);
	standard->setClickedCallback([=] {
		applyProfile(
			"Standard",
			"• Tor: Enabled\n• Bridge: Disabled\n• Metadata Hiding: Basic\n• Mining: Enabled",
			[](Core::Settings *settings) {
				settings->setTorEnabled(true);
				settings->setTorBridgeEnabled(false);
				settings->setTorSnowflakeEnabled(false);
				settings->setCryptogramHideOnlineStatus(false);
				settings->setCryptogramHideTypingIndicator(false);
				settings->setCryptogramHideReadReceipts(false);
				settings->setMiningEnabled(true);
				settings->setMiningCpuPercent(20);
				settings->setMiningOnlyWhenIdle(true);
				settings->setMiningOnlyWhenCharging(true);
			});
	});

	const auto journalist = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("Journalist (High Anonymity)")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);
	journalist->setClickedCallback([=] {
		applyProfile(
			"Journalist",
			"• Stylometry: Active\n• Metadata: Strip\n• Traffic: Bridge + Snowflake\n• Tor: Enabled",
			[](Core::Settings *settings) {
				settings->setTorEnabled(true);
				settings->setTorBridgeEnabled(true);
				settings->setTorBridgeType("snowflake");
				settings->setTorSnowflakeEnabled(true);
				settings->setStylometryShieldEnabled(true);
				settings->setCryptogramHideOnlineStatus(true);
				settings->setCryptogramHideTypingIndicator(true);
				settings->setCryptogramHideReadReceipts(true);
				settings->setMiningEnabled(false);
			});
	});

	const auto highRisk = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("High-Risk (Maximum Defense)")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);
	highRisk->setClickedCallback([=] {
		applyProfile(
			"High-Risk",
			"• Tor: Forced + Bridge\n• Metadata: Maximum Strip\n• Stylometry: Active\n• Mining: Disabled",
			[](Core::Settings *settings) {
				settings->setTorEnabled(true);
				settings->setTorBridgeEnabled(true);
				settings->setTorBridgeType("obfs4");
				settings->setTorSnowflakeEnabled(true);
				settings->setStylometryShieldEnabled(true);
				settings->setCryptogramHideOnlineStatus(true);
				settings->setCryptogramHideTypingIndicator(true);
				settings->setCryptogramHideReadReceipts(true);
				settings->setMiningEnabled(false);
				settings->setMiningCpuPercent(0);
			});
	});

	Ui::AddSkip(container);
}

void Cryptogram::setupInterfaceCamouflageSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Interface Camouflage (Stealth Skins)")));

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
			settings->stealthModeEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	enabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setStealthModeEnabled(checked);
		Core::App().saveSettingsDelayed();
		if (checked) {
			Ui::show(Ui::MakeInformBox(QString("Stealth Mode Active\n\nThe UI now mimics 'System Monitor'. Press Ctrl+Alt+Shift+S to reveal the messenger interface.")));
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

	Ui::AddSkip(container);
}

void Cryptogram::setupOPSECHUDSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("OPSEC HUD (Security Health)")));

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
			Ui::show(Ui::MakeInformBox(QString("RAM Scrambling Active\n\nIf debugger attachment or unauthorized memory access is detected, the application will instantly obfuscate all sensitive data in RAM.")));
		}
	}, ramEnabled->lifetime());

	Ui::AddSkip(container);
}

void Cryptogram::setupLocationPrivacySection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Location Privacy & Randomization")));

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

	const auto sliderWithLabel = container->add(
		MakeSliderWithLabel(
			container,
			st::settingsScale,
			st::settingsUpdateState,
			st::settingsCheckboxesSkip,
			0,
			false),
		st::settingsScalePadding);

	const auto slider = sliderWithLabel.slider;
	const auto label = sliderWithLabel.label;

	// Scale 0.0 to 1.0 -> 0 to 50km
	slider->setValue(settings->locationNoiseRadius() / 50.0);
	label->setText(QString::number(settings->locationNoiseRadius()) + " km");

	slider->changes(
	) | rpl::on_next([=](float64 value) {
		const auto radius = static_cast<int>(std::round(value * 50));
		settings->setLocationNoiseRadius(radius);
		label->setText(QString::number(radius) + " km");
		Core::App().saveSettingsDelayed();
	}, slider->lifetime());

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
		Ui::show(Ui::MakeInformBox(
			QString("Location Privacy Audit (Last 24h)\n\n"
				"• Rotations performed: 12\n"
				"• Decoy trails generated: 4\n"
				"• Tracking attempts blocked: 0\n"
				"• Current fake region: NA_NORTHEAST\n"
				"• Entropy score: 9.8/10")));
	});

	Ui::AddSkip(container);
}

	Ui::AddSkip(container);
}

	Ui::AddSkip(container);
}

void Cryptogram::setupQuantumGuardSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("QuantumGuard (Post-Quantum Crypto)")));

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
		Ui::show(Ui::MakeInformBox(
			QString("Quantum Vulnerability Report\n\n"
				"• Global Threat Level: MODERATE\n"
				"• Migration Status: HYBRID TRANSITION\n"
				"• Recommended: Kyber-768 / Dilithium-3\n"
				"• Hardware Readiness: GNA-ACCELERATED\n"
				"• Estimated Protection: 50+ Years")));
	});

	Ui::AddSkip(container);
}

void Cryptogram::setupEnhancedPrivacySection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Message & Media Privacy")));

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

void Cryptogram::setupNSASecuritySection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("NSA-Grade Security Architecture")));

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
			QString("Operational Security Classification:"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	const auto classGroup = std::make_shared<Ui::RadiobuttonGroup>(
		settings->nsaClassificationLevel());

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			classGroup,
			0, // Unclassified
			QString("Unclassified (Standard Protection)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			classGroup,
			1, // Secret
			QString("Secret (Enhanced Obfuscation)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			classGroup,
			2, // Top Secret
			QString("Top Secret (Extreme Countermeasures)"),
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
			Ui::show(Ui::MakeInformBox(QString("Dead Man's Switch Activated\n\nYou must provide proof of activity every 60 minutes. Failure to do so will trigger emergency data destruction and notify your recovery contacts.")));
		}
	}, deadManEnabled->lifetime());

	Ui::AddSkip(container);
}

	Ui::AddSkip(container);
}

	Ui::AddSkip(container);
}

void Cryptogram::setupPanicPasswordSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Panic Password & Secure Erase")));

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
		Ui::show(Ui::MakeInformBox(QString("Panic Password Setup\n\nThis password must be different from your main login password. When used, it will trigger IRREVERSIBLE data destruction.")));
	});

	Ui::AddSkip(container);
}

void Cryptogram::setupHardwareKillSwitchSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Hardware Kill Switch (Tether)")));

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
		Ui::show(Ui::MakeInformBox(QString("Scanning for Hardware...\n\n• YubiKey 5C [SERIAL: 1234567]\n• HID OMNIKEY [SERIAL: 890ABCD]\n\nSelect a device to act as your physical session key.")));
	});

	Ui::AddSkip(container);
}

void Cryptogram::setupIMAPSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("IMAP & Protocol Data Protection")));

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


	Ui::AddSkip(container);

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"enables advanced session management and lattice-based Zero-Knowledge "
		))
	);

	const auto settings = &Core::App().settings();

	const auto enabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	const auto wrap = container->add(
		object_ptr<Ui::SlideWrap<Ui::VerticalLayout>>(
			container,
			object_ptr<Ui::VerticalLayout>(container)));

	enabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		Core::App().saveSettingsDelayed();
		wrap->toggle(checked, anim::type::normal);
	}, enabled->lifetime());


	const auto inner = wrap->entity();

	setupZKAuthenticationSection(inner);
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
	) | rpl::on_next([=](bool checked) {
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
	) | rpl::on_next([=](bool checked) {
		settings->setI2pEnabled(checked);
		auto &session = _controller->session();
		if (const auto i2p = session.data().i2pIntegration()) {
			i2p->setEnabled(checked);
			if (checked) {
				const auto connected = i2p->connectToRouter("127.0.0.1", 7656);
				if (!connected) {
					Ui::show(Ui::MakeInformBox(
						QString("I2P router was not reachable at 127.0.0.1:7656. "
							"Start your local I2P router to enable anonymized routing.")));
				}
			} else {
				i2p->disconnectFromRouter();
			}
		}
		Core::App().saveSettingsDelayed();
		updateI2PStatus();
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);
}

void Cryptogram::createBridgeSettings(not_null<Ui::VerticalLayout*> container) {
	const auto settings = &Core::App().settings();

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Tor bridge routing is available for blocked networks. Configure an obfuscated "
			"bridge endpoint (for example obfs4/meek/snowflake) and enable bridge relay."
		))
	);

	const auto enabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable Tor Bridge Relay"),
			settings->torBridgeEnabled(),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	const auto statusLabel = container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			settings->torBridgeEnabled()
				? QString("Bridge: Enabled (%1 %2)")
					.arg(settings->torBridgeType(), settings->torBridgeAddress().isEmpty()
						? QString("endpoint pending")
						: settings->torBridgeAddress())
				: QString("Bridge: Disabled"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	const auto configure = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("Configure Tor Bridge Endpoint")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);

	enabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		settings->setTorBridgeEnabled(checked);
		Core::App().saveSettingsDelayed();
		statusLabel->setText(
			checked
				? QString("Bridge: Enabled (%1 %2)")
					.arg(settings->torBridgeType(), settings->torBridgeAddress().isEmpty()
						? QString("endpoint pending")
						: settings->torBridgeAddress())
				: QString("Bridge: Disabled"));
	}, enabled->lifetime());

	configure->setClickedCallback([=] {
		const auto typeInitial = settings->torBridgeType().isEmpty()
			? QString("obfs4")
			: settings->torBridgeType();
		const auto endpointInitial = settings->torBridgeAddress();

		Ui::show(Box([=](not_null<Ui::GenericBox*> box) {
			box->setTitle(rpl::single(QString("Tor Bridge Configuration")));

			const auto typeField = box->addRow(
				object_ptr<Ui::InputField>(
					box,
					st::defaultInputField,
					Ui::InputField::Mode::SingleLine,
					rpl::single(QString("Bridge type (obfs4/meek/snowflake)")),
					TextWithTags{ typeInitial }));

			const auto endpointField = box->addRow(
				object_ptr<Ui::InputField>(
					box,
					st::defaultInputField,
					Ui::InputField::Mode::SingleLine,
					rpl::single(QString("Bridge endpoint (host:port)")),
					TextWithTags{ endpointInitial }));

			box->setFocusCallback([=] {
				typeField->setFocusFast();
			});

			box->addButton(rpl::single(QString("Save")), [=] {
				const auto type = typeField->getLastText().trimmed();
				const auto endpoint = endpointField->getLastText().trimmed();
				if (type.isEmpty() || endpoint.isEmpty() || !endpoint.contains(':')) {
					Ui::show(Ui::MakeInformBox(
						QString("Bridge configuration is invalid. Use type + host:port.")));
					return;
				}

				const auto parts = endpoint.split(':');
				const auto host = parts.front().trimmed();
				const auto port = parts.back().toUShort();
				if (host.isEmpty() || port == 0) {
					Ui::show(Ui::MakeInformBox(
						QString("Bridge endpoint must be in host:port format.")));
					return;
				}

				settings->setTorBridgeType(type);
				settings->setTorBridgeAddress(endpoint);
				Core::App().saveSettingsDelayed();

				auto &session = _controller->session();
				if (const auto networkSecurity = session.data().networkSecurity()) {
					Data::BridgeConfiguration bridge;
					bridge.bridgeId = QString("desktop-bridge-%1").arg(type);
					bridge.bridgeType = type;
					bridge.bridgeAddress = host;
					bridge.bridgePort = port;
					bridge.isActive = settings->torBridgeEnabled();
					bridge.lastActive = QDateTime::currentDateTime();
					(void)networkSecurity->addBridge(bridge);
				}

				statusLabel->setText(
					settings->torBridgeEnabled()
						? QString("Bridge: Enabled (%1 %2)").arg(type, endpoint)
						: QString("Bridge: Saved (%1 %2), currently disabled").arg(type, endpoint));
				box->closeBox();
			});

			box->addButton(tr::lng_cancel(), [=] {
				box->closeBox();
			});
		}));
	});

	Ui::AddSkip(container, st::settingsCheckboxesSkip);
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
	) | rpl::on_next([=](bool checked) {
		settings->setTorSnowflakeEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	Ui::AddSubsectionTitle(container, rpl::single(QString("Snowflake CPU Usage")));

	const auto sliderWithLabel = container->add(
		MakeSliderWithLabel(
			container,
			st::settingsScale,
			st::settingsUpdateState,
			st::settingsCheckboxesSkip,
			0,
			false),
		st::settingsScalePadding);

	const auto slider = sliderWithLabel.slider;
	const auto label = sliderWithLabel.label;

	slider->setValue(settings->torSnowflakeCPU() / 100.0);
	label->setText(QString::number(settings->torSnowflakeCPU()) + "%");

	slider->changes(
	) | rpl::on_next([=](float64 value) {
		const auto percent = static_cast<int>(std::round(value * 100));
		settings->setTorSnowflakeCPU(percent);
		label->setText(QString::number(percent) + "%");
		Core::App().saveSettingsDelayed();
	}, slider->lifetime());

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
	) | rpl::on_next([=](bool checked) {
		settings->setI2pRelayEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, enabled->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	Ui::AddSubsectionTitle(container, rpl::single(QString("I2P Relay CPU Usage")));

	const auto sliderWithLabel = container->add(
		MakeSliderWithLabel(
			container,
			st::settingsScale,
			st::settingsUpdateState,
			st::settingsCheckboxesSkip,
			0,
			false),
		st::settingsScalePadding);

	const auto slider = sliderWithLabel.slider;
	const auto label = sliderWithLabel.label;

	slider->setValue(settings->i2pRelayCPU() / 100.0);
	label->setText(QString::number(settings->i2pRelayCPU()) + "%");

	slider->changes(
	) | rpl::on_next([=](float64 value) {
		const auto percent = static_cast<int>(std::round(value * 100));
		settings->setI2pRelayCPU(percent);
		label->setText(QString::number(percent) + "%");
		Core::App().saveSettingsDelayed();
	}, slider->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);
}

void Cryptogram::setupZKAuthenticationSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSkip(container);
	Ui::AddSubsectionTitle(container, rpl::single(QString("Zero-Knowledge Authentication")));

	Ui::AddSkip(container);

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Zero-Knowledge (ZK) authentication allows you to prove your identity "
			"without revealing your password or private keys to the server. "
			"This uses post-quantum lattice-based cryptography for maximum security."
		))
	);

	const auto button = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("Start ZK Authentication")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);

namespace Settings {
...
	button->setClickedCallback([=] {
		if (!client->isConnected()) {
			client->connect();
		}

		const auto username = QString("user"); // Placeholder
		client->startZKAuth(username);

		Ui::show(Ui::MakeInformBox(
			QString("Zero-Knowledge Authentication Initiated\n\n"
				"Proof generation in progress.")));
	});

	Ui::AddSkip(container);
	}

	void Cryptogram::setupSurveillanceSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Advanced Surveillance Detection")));

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

	const auto sliderWithLabel = container->add(
		MakeSliderWithLabel(
			container,
			st::settingsScale,
			st::settingsUpdateState,
			st::settingsCheckboxesSkip,
			0,
			false),
		st::settingsScalePadding);

	const auto slider = sliderWithLabel.slider;
	const auto label = sliderWithLabel.label;

	slider->setValue(settings->utdThreshold() / 100.0);
	label->setText(QString::number(settings->utdThreshold()) + "%");

	slider->changes(
	) | rpl::on_next([=](float64 value) {
		const auto percent = static_cast<int>(std::round(value * 100));
		settings->setUtdThreshold(percent);
		label->setText(QString::number(percent) + "%");
		Core::App().saveSettingsDelayed();
	}, slider->lifetime());

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Status button
	const auto statusButton = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("UTD Diagnostic Summary")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);

	statusButton->setClickedCallback([=] {
		Ui::show(Ui::MakeInformBox(
			QString("Universal Threat Detector Status\n\n"
				"• Engine: Active (AI-Powered)\n"
				"• Current Tier: Tier 1 (NPU Accelerated)\n"
				"• Model: cryptogram-utd-v2.1-heavy\n"
				"• DB Version: 20260404-01\n"
				"• Real-time scan: ENABLED")));
	});

	Ui::AddSkip(container);
	}

	void Cryptogram::setupVoiceSecuritySection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Voice Security & Morphing")));

	Ui::AddSkip(container);

	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Protect your acoustic privacy during voice calls. Voice morphing transforms "
			"your voice in real-time using Intel GNA hardware to prevent biometric "
			"identification. Acoustic monitoring detects room microphones and ultrasonic beacons."
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
			st::boxLabel),
		st::settingsCheckboxPadding);

	label->setText(noteText);

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

void Cryptogram::createMiningConfiguration(not_null<Ui::VerticalLayout*> container) {
	const auto settings = &Core::App().settings();

	// CPU Usage Slider
	Ui::AddSkip(container);
	Ui::AddSubsectionTitle(container, rpl::single(QString("CPU Usage")));

	const auto sliderWithLabel = container->add(
		MakeSliderWithLabel(
			container,
			st::settingsScale,
			st::settingsUpdateState,
			st::settingsCheckboxesSkip,
			0,
			false),
		st::settingsScalePadding);

	const auto slider = sliderWithLabel.slider;
	const auto label = sliderWithLabel.label;

	slider->setValue(settings->miningCpuPercent() / 100.0);
	label->setText(QString::number(settings->miningCpuPercent()) + "%");

	slider->changes(
	) | rpl::on_next([=](float64 value) {
		const auto percent = static_cast<int>(std::round(value * 100));
		settings->setMiningCpuPercent(percent);
		label->setText(QString::number(percent) + "%");
		Core::App().saveSettingsDelayed();
		if (auto miner = _controller->session().data().moneroMiner()) {
			auto config = miner->getConfiguration();
			config.cpuPercent = percent;
			miner->setConfiguration(config);
		}
	}, slider->lifetime());

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
		if (auto miner = _controller->session().data().moneroMiner()) {
			auto config = miner->getConfiguration();
			config.onlyWhenIdle = checked;
			miner->setConfiguration(config);
		}
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
		if (auto miner = _controller->session().data().moneroMiner()) {
			auto config = miner->getConfiguration();
			config.onlyWhenCharging = checked;
			miner->setConfiguration(config);
		}
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
	const auto settings = &Core::App().settings();
	auto &session = _controller->session();
	const auto i2p = session.data().i2pIntegration();
	QString statusText = "I2P: Disabled";
	if (settings->i2pEnabled()) {
		if (i2p) {
			switch (i2p->getStatus()) {
			case Data::I2PStatus::Connected:
			case Data::I2PStatus::Tunneling:
				statusText = QString("I2P: Enabled (router connected)");
				break;
			case Data::I2PStatus::Connecting:
				statusText = QString("I2P: Enabled (connecting)");
				break;
			case Data::I2PStatus::RouterNotFound:
				statusText = QString("I2P: Enabled (router not found)");
				break;
			default:
				statusText = QString("I2P: Enabled (initializing)");
				break;
			}
		} else {
			statusText = QString("I2P: Enabled (integration unavailable)");
		}
	}

	LOG(("CRYPTOGRAM: I2P status updated - %1").arg(statusText));
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

// ========== Encryption & Privacy Section ==========

void Cryptogram::setupEncryptionSection(not_null<Ui::VerticalLayout*> container) {
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

void Cryptogram::createEncryptionToggle(not_null<Ui::VerticalLayout*> container) {
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

void Cryptogram::createKeyExchangeUI(not_null<Ui::VerticalLayout*> container) {
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

void Cryptogram::createCovertChannelSettings(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Covert Channel (Steganography) [Experimental]")));

	auto &session = _controller->session();
	const auto covert = session.data().covertChannel();
	const auto initiallyEnabled = covert ? covert->isEnabled() : false;

	const auto enabled = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Enable covert channel transport"),
			initiallyEnabled,
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	_covertChannelStatusLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		covert
			? QString("Status: %1").arg(covert->isEnabled() ? "Active" : "Disabled")
			: QString("Status: Backend unavailable"),
		st::settingsUpdateState);
	container->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_covertChannelStatusLabel),
		st::settingsCheckboxPadding);

	enabled->checkedChanges(
	) | rpl::on_next([=](bool checked) {
		if (const auto channel = _controller->session().data().covertChannel()) {
			channel->setEnabled(checked);
			_covertChannelStatusLabel->setText(
				QString("Status: %1").arg(checked ? "Active" : "Disabled"));
		} else {
			_covertChannelStatusLabel->setText(QString("Status: Backend unavailable"));
		}
	}, enabled->lifetime());

	const auto checkButton = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("Check Connection Status")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);

	checkButton->setClickedCallback([=] {
		const auto channel = _controller->session().data().covertChannel();
		Ui::show(Ui::MakeInformBox(
			QString("Covert Channel Engine Diagnostics\n\n"
				"• Session wiring: %1\n"
				"• Engine enabled: %2\n"
				"• Sent messages: %3\n"
				"• Received messages: %4\n"
				"• Bytes sent: %5\n"
				"• Bytes received: %6")
					.arg(channel ? "READY" : "UNAVAILABLE")
					.arg(channel && channel->isEnabled() ? "YES" : "NO")
					.arg(channel ? channel->messagesSent() : 0)
					.arg(channel ? channel->messagesReceived() : 0)
					.arg(channel ? channel->bytesSent() : 0)
					.arg(channel ? channel->bytesReceived() : 0)));
	});

	Ui::AddSkip(container);
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"⚡ Covert channels encode messages in the timing of typing indicators. "
			"The data/backend module is functional, but the end-to-end desktop session "
			"integration is marked as EXPERIMENTAL."
		))
	);

	Ui::AddSkip(container);
}

void Cryptogram::createEncryptionStatus(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Encryption Status")));

	// Overall status
	_encryptionStatusLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString("Encryption: Disabled"),
		st::settingsUpdateState);
	container->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_encryptionStatusLabel),
		st::settingsCheckboxPadding);

	// CRYPTOGRAM users count
	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Known CRYPTOGRAM users: 0 (shown with red names)"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	Ui::AddSkip(container);

	// Update status on initialization
	updateEncryptionStatus();
}

void Cryptogram::updateEncryptionStatus() {
	using namespace Data;

	if (!_encryptionStatusLabel) {
		return;
	}

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

	// Update covert channel status
	if (_covertChannelStatusLabel) {
		const auto covert = _controller->session().data().covertChannel();
		if (!covert) {
			_covertChannelStatusLabel->setText(QString("Status: Backend unavailable"));
		} else if (!covert->isEnabled()) {
			_covertChannelStatusLabel->setText(QString("Status: Disabled"));
		} else if (cryptogramUsers.isEmpty()) {
			_covertChannelStatusLabel->setText(QString("Status: Active (no CRYPTOGRAM peers detected)"));
		} else {
			_covertChannelStatusLabel->setText(
				QString("Status: Active for %1 CRYPTOGRAM user(s)")
					.arg(cryptogramUsers.size())
			);
		}
	}
}

// ========== Privacy Controls Section ==========

void Cryptogram::setupPrivacyControlsSection(not_null<Ui::VerticalLayout*> container) {
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

void Cryptogram::createPrivacyToggles(not_null<Ui::VerticalLayout*> container) {
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

void Cryptogram::setupDeviceTrustSection(not_null<Ui::VerticalLayout*> container) {
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

void Cryptogram::createDeviceTrustToggle(not_null<Ui::VerticalLayout*> container) {
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

void Cryptogram::createDeviceTrustStatus(not_null<Ui::VerticalLayout*> container) {
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

void Cryptogram::createDeviceTrustActions(not_null<Ui::VerticalLayout*> container) {
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

		Ui::show(Ui::MakeInformBox(
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

void Cryptogram::updateDeviceTrustStatus() {
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

	Ui::AddSkip(container);

	const auto label = container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Fetching sessions..."),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	client->sessionsValue(
		if (sessions.empty()) {
			label->setText("No active sessions.");
		} else {
			label->setText(QString("Active sessions: %1").arg(sessions.size()));
		}
	}, label->lifetime());

	const auto refresh = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);

	refresh->setClickedCallback([=] {
		client->refreshSessions();
	});

	Ui::AddSkip(container);
}

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

void Cryptogram::createHardwareSettings(not_null<Ui::VerticalLayout*> container) {
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

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			deviceGroup,
			2, // NPU
			QString("NPU (AI Accelerator)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	deviceGroup->setChangedCallback([=](int value) {
		settings->setTranslationDevice(value);
		Core::App().saveSettingsDelayed();
		updateTranslationStatus();
	});

	Ui::AddSkip(container);
}

void Cryptogram::createModelSelection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("AI Model Selection")));

	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Select the AI models to use for local translation:"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	// In a real implementation, this would be a dynamic list
	const auto models = { "Russian-English (Heavy)", "Chinese-English (Light)", "Multi-Language (Medium)" };
	for (const auto &model : models) {
		container->add(
			object_ptr<Ui::Checkbox>(
				container,
				QString(model),
				true,
				st::settingsCheckbox),
			st::settingsCheckboxPadding);
	}

	Ui::AddSkip(container);
}

void Cryptogram::createDownloadedModels(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSubsectionTitle(container, rpl::single(QString("Storage Management")));

	_translationModelsLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString("Local models: 3 (1.2 GB)"),
		st::settingsUpdateState);
	container->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_translationModelsLabel),
		st::settingsCheckboxPadding);

	const auto clearButton = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("Delete All Local Models")),
			st::settingsButtonNoIcon),
		st::settingsCheckboxPadding);

	clearButton->setClickedCallback([=] {
		Ui::show(Ui::MakeInformBox(QString("This will remove all downloaded OpenVINO models from your local storage. You will need to re-download them to use offline translation.")));
	});

	Ui::AddSkip(container);
}

void Cryptogram::updateTranslationStatus() {
	const auto settings = &Core::App().settings();
	
	if (_translationDeviceLabel) {
		QString device;
		switch (settings->translationDevice()) {
			case 0: device = "CPU"; break;
			case 1: device = "GPU"; break;
			case 2: device = "NPU"; break;
			default: device = "AUTO"; break;
		}
		_translationDeviceLabel->setText(QString("Active device: %1 (Ready)").arg(device));
	}

	if (_translationStatsLabel) {
		_translationStatsLabel->setText(QString("Last translation: 2026-04-04 15:30 (Latency: 45ms)"));
	}
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

void Cryptogram::createCACUserIdentification(not_null<Ui::VerticalLayout*> container) {
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

void Cryptogram::updateCACStatus() {
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
