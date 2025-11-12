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
#include "ui/widgets/input_fields.h"
#include "ui/text/text_utilities.h"
#include "ui/vertical_list.h"
#include "lang/lang_keys.h"
#include "core/application.h"
#include "core/core_settings.h"
#include "data/data_session.h"
#include "data/data_cac_interface.h"
#include "data/data_enhanced_privacy.h"
#include "data/data_group_encryption.h"
#include "data/data_mls_protocol.h"
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

	setupDeviceTrustSection(content);

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
	// Bridge configuration - placeholder for future implementation
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"💡 Bridge Support: Bridges act as alternative entry points to Tor/I2P networks. "
			"Enable this if direct connections are blocked in your region. "
			"Bridge configuration will be available in a future update."
		))
	);
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
	const auto settings = &Core::App().settings();
	const auto enabled = settings->i2pEnabled();

	QString statusText = enabled
		? QString("I2P: Enabled (Configuration active)")
		: QString("I2P: Disabled");

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
			"happens automatically. Features forward secrecy, deniability, and covert channels via "
			"typing indicators (completely invisible messages). All encryption is client-side."
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
	) | rpl::start_with_next([=](bool checked) {
		EnhancedPrivacy::SetEncryptionEnabled(checked);
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

	// Group encryption status
	auto groupEncryption = GetGroupEncryption();
	if (groupEncryption) {
		const auto totalGroups = groupEncryption->totalEncryptedGroups();
		container->add(
			object_ptr<Ui::FlatLabel>(
				container,
				QString("Encrypted groups: %1").arg(totalGroups),
				st::settingsUpdateState),
			st::settingsCheckboxPadding);
	} else {
		container->add(
			object_ptr<Ui::FlatLabel>(
				container,
				QString("Group encryption: Not initialized"),
				st::settingsUpdateState),
			st::settingsCheckboxPadding);
	}

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
	Ui::AddSubsectionTitle(container, rpl::single(QString("Covert Channel (Steganography)")));

	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Ultra-covert: Send messages via typing indicators - NO message appears at all!"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	// Covert channel toggle
	const auto& session = _controller->session();
	bool covertEnabled = false;
	if (auto covert = session.data().covertChannel()) {
		covertEnabled = covert->isEnabled();
	}

	const auto covertCheckbox = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("👻 Enable covert channel (invisible messaging)"),
			covertEnabled,
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	covertCheckbox->checkedChanges(
	) | rpl::start_with_next([=](bool checked) {
		// Enable/disable covert channel
		auto& session = _controller->session();
		if (auto covert = session.data().covertChannel()) {
			covert->setEnabled(checked);
			Core::App().saveSettingsDelayed();
			Ui::Toast::Show(checked ?
				"✅ Covert channel enabled - messages will be invisible" :
				"❌ Covert channel disabled - using visible encryption");
			updateEncryptionStatus();

			LOG(("CRYPTOGRAM: Covert channel %1").arg(checked ? "enabled" : "disabled"));
		}
	}, covertCheckbox->lifetime());

	// Status label
	_covertChannelStatusLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString("Active peers: None"),
		st::settingsUpdateState);
	container->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_covertChannelStatusLabel),
		st::settingsCheckboxPadding);

	Ui::AddSkip(container);
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"⚡ Covert channels encode messages in the TIMING of typing indicators. "
			"Non-CRYPTOGRAM users only see 'typing...' - NO message bubble appears! "
			"Perfect operational security and plausible deniability."
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
		const auto cryptogramUsers = EnhancedPrivacy::GetCryptogramUsers();
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
		const auto cryptogramUsers = EnhancedPrivacy::GetCryptogramUsers();
		_covertChannelStatusLabel->setText(
			QString("Available for: %1 CRYPTOGRAM user(s)")
				.arg(cryptogramUsers.size())
		);
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
		st::settingsCheckbox);

	hideOnlineCheckbox->checkedChanges(
	) | rpl::start_with_next([=](bool checked) {
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
		st::settingsCheckbox);

	hideTypingCheckbox->checkedChanges(
	) | rpl::start_with_next([=](bool checked) {
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
		st::settingsCheckbox);

	hideReadReceiptsCheckbox->checkedChanges(
	) | rpl::start_with_next([=](bool checked) {
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

	Ui::AddSkip(container, st::settingsCheckboxesSkip);

	// Automatic translation (preferred)
	const auto automaticCheckbox = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("🔄 Automatically translate messages (recommended)"),
			settings->translationAutomatic()),
		st::settingsCheckboxPadding);

	automaticCheckbox->checkedChanges(
	) | rpl::start_with_next([=](bool checked) {
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

	Ui::AddSubsectionTitle(container, rpl::single(QString("Translation Quality & Models")));

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
			QString("⚡ Fast (Small) - 100MB per model, good quality"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			qualityGroup,
			1,  // Balanced
			QString("⚖️ Balanced (Base) - 300MB per model (recommended)"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			qualityGroup,
			2,  // Best
			QString("🏆 Best (Large) - 600MB per model, highest quality"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	qualityGroup->setChangedCallback([=](int value) {
		settings->setTranslationQuality(value);
		Core::App().saveSettingsDelayed();
	});

	Ui::AddSkip(container);

	// Available models based on quality selection
	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("📦 Available models for selected quality:"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	const auto quality = settings->translationQuality();
	const QString modelSize = (quality == 0) ? "100MB" : (quality == 1) ? "300MB" : "600MB";

	// Russian models
	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("  • English ↔ Russian: ") + modelSize + " (unidirectional)\n"
			"  • English ↔ Russian: 400MB (bidirectional, more efficient)",
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	// Chinese models
	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("  • English ↔ Chinese: ") + modelSize + " (unidirectional)\n"
			"  • English ↔ Chinese: 400MB (bidirectional, more efficient)",
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

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
	Ui::AddSubsectionTitle(container, rpl::single(QString("Model Downloads & Status")));

	const auto settings = &Core::App().settings();

	// Model download section
	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Download models to enable translation:"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	Ui::AddSkip(container);

	// Russian bidirectional model
	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("🇷🇺 Russian (Bidirectional) - 400MB"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	// Russian download progress bar
	const auto ruProgressSlider = container->add(
		object_ptr<Ui::MediaSlider>(container, st::settingsSlider),
		st::settingsCheckboxPadding);
	ruProgressSlider->resize(st::settingsSlider.seekSize);
	ruProgressSlider->setValue(0.0);  // 0% initially
	ruProgressSlider->setDisabled(true);

	const auto ruDownloadLabel = container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Status: Not downloaded | 0 MB / 400 MB"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	const auto ruDownloadButton = container->add(
		object_ptr<Ui::RoundButton>(
			container,
			rpl::single(QString("Download Russian Model")),
			st::defaultBoxButton),
		st::settingsCheckboxPadding);

	ruDownloadButton->setTextTransform(Ui::RoundButton::TextTransform::NoTransform);
	ruDownloadButton->setClickedCallback([=] {
		// Trigger download
		ruDownloadLabel->setText(QString("Status: Downloading... | 0 MB / 400 MB"));
		// This will be connected to actual OpenVINO model download
	});

	Ui::AddSkip(container);

	// Chinese bidirectional model
	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("🇨🇳 Chinese (Bidirectional) - 400MB"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	// Chinese download progress bar
	const auto zhProgressSlider = container->add(
		object_ptr<Ui::MediaSlider>(container, st::settingsSlider),
		st::settingsCheckboxPadding);
	zhProgressSlider->resize(st::settingsSlider.seekSize);
	zhProgressSlider->setValue(0.0);  // 0% initially
	zhProgressSlider->setDisabled(true);

	const auto zhDownloadLabel = container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Status: Not downloaded | 0 MB / 400 MB"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	const auto zhDownloadButton = container->add(
		object_ptr<Ui::RoundButton>(
			container,
			rpl::single(QString("Download Chinese Model")),
			st::defaultBoxButton),
		st::settingsCheckboxPadding);

	zhDownloadButton->setTextTransform(Ui::RoundButton::TextTransform::NoTransform);
	zhDownloadButton->setClickedCallback([=] {
		// Trigger download
		zhDownloadLabel->setText(QString("Status: Downloading... | 0 MB / 400 MB"));
		// This will be connected to actual OpenVINO model download
	});

	Ui::AddSkip(container);

	// Downloaded models summary
	_translationModelsLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString("📦 Downloaded: 0 models (0 MB total)"),
		st::settingsUpdateState);
	container->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_translationModelsLabel),
		st::settingsCheckboxPadding);

	Ui::AddSkip(container);
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"💡 Tip: Models are downloaded once and stored locally. "
			"Bidirectional models (400MB) support both directions efficiently. "
			"Quality-specific models (100/300/600MB) can be downloaded for fine-tuned performance."
		))
	);

	// Translation statistics
	Ui::AddSkip(container);
	_translationStatsLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString("📊 Statistics: No translations yet"),
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

	if (_translationModelsLabel) {
		const auto quality = settings->translationQuality();
		QString modelSize = (quality == 0) ? "100MB" : (quality == 1) ? "300MB" : "600MB";

		_translationModelsLabel->setText(QString(
			"Models: Available for download\n"
			"• Russian (Cyrillic) ↔ English (%1 per direction)\n"
			"• Chinese (Mandarin) ↔ English (%1 per direction)\n"
			"• Or bidirectional models (400MB each)\n\n"
			"Models download automatically on first translation"
		).arg(modelSize));
	}

	if (_translationStatsLabel) {
		const auto quality = settings->translationQuality();
		QString qualityText;
		switch (quality) {
			case 0: qualityText = "Fast (Small)"; break;
			case 1: qualityText = "Balanced (Base)"; break;
			case 2: qualityText = "Best (Large)"; break;
			default: qualityText = "Balanced (Base)"; break;
		}

		const auto cacheStatus = settings->translationCacheEnabled() ? "Enabled" : "Disabled";
		const auto device = settings->translationDevice();
		QString deviceText;
		switch (device) {
			case 0: deviceText = "CPU"; break;
			case 1: deviceText = "GPU"; break;
			case 2: deviceText = "NPU"; break;
			case 3: deviceText = "Auto"; break;
			default: deviceText = "Auto"; break;
		}

		_translationStatsLabel->setText(QString(
			"📊 Quality: %1 | Device: %2 | Cache: %3"
		).arg(qualityText).arg(deviceText).arg(cacheStatus));
	}
}

// ========== UI/UX Preferences Section ==========

void Cryptogram::setupUIPreferencesSection(not_null<Ui::VerticalLayout*> container) {
	Ui::AddSkip(container);
	Ui::AddSubsectionTitle(container, rpl::single(QString("UI/UX Preferences")));

	Ui::AddSkip(container);

	// Info text
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"Customize your CRYPTOGRAM experience with curated interface options. "
			"Curated Stickers adds a favorites section at the top of your sticker picker with "
			"your most-used sets for quick access. All stickers remain searchable."
		))
	);

	// Curated Stickers toggle
	Ui::AddSkip(container);
	Ui::AddSubsectionTitle(container, rpl::single(QString("Curated Stickers Favorites")));

	const auto curatedStickersCheckbox = container->add(
		object_ptr<Ui::Checkbox>(
			container,
			QString("Show curated favorites section"),
			Core::App().settings().curatedStickersEnabled()),
		st::settingsCheckbox);

	curatedStickersCheckbox->checkedChanges(
	) | rpl::start_with_next([=](bool checked) {
		Core::App().settings().setCuratedStickersEnabled(checked);
		Core::App().saveSettingsDelayed();
	}, curatedStickersCheckbox->lifetime());

	Ui::AddSkip(container);
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"When enabled, adds a 'Curated' tab with your favorite sticker sets at the top of "
			"the sticker picker. Right-click any sticker set and select 'Add to Curated' to pin it. "
			"All stickers remain accessible through search and browsing."
		))
	);
}

// ========== CAC Card Section (Hardware Security) ==========

void Cryptogram::setupCACSection(not_null<Ui::VerticalLayout*> container) {
	using namespace Data;

	Ui::AddSkip(container);
	Ui::AddSubsectionTitle(container, rpl::single(QString("CAC Card (Hardware Security)")));

	Ui::AddSkip(container);

	// Info text
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"CAC (Common Access Card) support provides hardware-backed cryptography "
			"using DoD/Military PIV smart cards. Features include X.509 certificate "
			"authentication, digital signatures, and multiple algorithm support. "
			"CAC-authenticated users are identified with GREEN names (visible only to other CAC card owners)."
		))
	);

	createCACCardStatus(container);
	createCACPINEntry(container);
	createCACAlgorithmSelection(container);
	createCACUserIdentification(container);

	// Add Trust History button
	Ui::AddSkip(container);
	Ui::AddSubsectionTitle(container, rpl::single(QString("Verified Identities")));

	const auto trustHistoryButton = container->add(
		object_ptr<Ui::SettingsButton>(
			container,
			rpl::single(QString("View Verified Identities")),
			st::settingsButton),
		st::settingsCheckboxPadding);

	trustHistoryButton->setClickedCallback([=] {
		_controller->showSettings(Settings::TrustHistory::Id());
	});

	Ui::AddSkip(container);
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"View and manage all CAC-verified user identities. "
			"Verified identities expire after 6 months and require re-verification."
		))
	);

	// Initial status update
	updateCACStatus();
}

void Cryptogram::createCACCardStatus(not_null<Ui::VerticalLayout*> container) {
	using namespace Data;

	Ui::AddSkip(container);
	Ui::AddSubsectionTitle(container, rpl::single(QString("Card Status")));

	// Card detection status
	_cacCardStatusLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString("Status: Checking for CAC card..."),
		st::settingsUpdateState);
	container->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_cacCardStatusLabel),
		st::settingsCheckboxPadding);

	// Refresh button
	const auto refreshButton = container->add(
		object_ptr<Ui::RoundButton>(
			container,
			rpl::single(QString("🔄 Refresh Card Status")),
			st::defaultBoxButton),
		st::settingsCheckboxPadding);

	refreshButton->setTextTransform(Ui::RoundButton::TextTransform::NoTransform);
	refreshButton->setClickedCallback([=] {
		updateCACStatus();
		Ui::Toast::Show("Card status refreshed");
	});

	Ui::AddSkip(container);
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"💡 Insert your CAC card and click Refresh. "
			"Supported: Windows (WinSCard), Linux (PC/SC Lite), macOS (CryptoTokenKit)"
		))
	);

	Ui::AddSkip(container);
}

void Cryptogram::createCACPINEntry(not_null<Ui::VerticalLayout*> container) {
	using namespace Data;

	Ui::AddSubsectionTitle(container, rpl::single(QString("PIN Verification")));

	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Enter your CAC PIN to unlock the card:"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	// PIN input field (password style)
	const auto pinInput = container->add(
		object_ptr<Ui::InputField>(
			container,
			st::defaultInputField,
			rpl::single(QString("Enter PIN...")),
			QString()),
		st::settingsCheckboxPadding);

	pinInput->setMaxLength(8);  // CAC PINs are typically 4-8 digits

	// Verify PIN button
	const auto verifyButton = container->add(
		object_ptr<Ui::RoundButton>(
			container,
			rpl::single(QString("🔐 Verify PIN")),
			st::defaultBoxButton),
		st::settingsCheckboxPadding);

	verifyButton->setTextTransform(Ui::RoundButton::TextTransform::NoTransform);
	verifyButton->setClickedCallback([=] {
		const auto pin = pinInput->getLastText();
		if (pin.isEmpty()) {
			Ui::Toast::Show("Please enter your PIN");
			return;
		}

		// Try to verify PIN with CAC card
		auto cac = CACFactory::create();
		if (!cac) {
			Ui::Toast::Show("❌ CAC interface not available on this platform");
			return;
		}

		cac->initialize();
		if (!cac->isCardPresent()) {
			Ui::Toast::Show("❌ No CAC card detected - please insert card");
			return;
		}

		const auto result = cac->verifyPIN(pin);
		if (result == CACResult::Success) {
			Ui::Toast::Show("✅ PIN verified successfully");
			pinInput->setText(QString());  // Clear PIN for security
			updateCACStatus();
		} else if (result == CACResult::PINIncorrect) {
			const auto remaining = cac->getRemainingPINAttempts();
			Ui::Toast::Show(QString("❌ Incorrect PIN - %1 attempts remaining").arg(remaining));
		} else if (result == CACResult::CardLocked) {
			Ui::Toast::Show("🔒 Card locked - too many incorrect attempts");
		} else {
			Ui::Toast::Show("❌ PIN verification failed");
		}
	});

	Ui::AddSkip(container);
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"⚠️ Warning: After 3 incorrect PIN attempts, your CAC card will be locked. "
			"Contact your security officer to unlock."
		))
	);

	Ui::AddSkip(container);
}

void Cryptogram::createCACAlgorithmSelection(not_null<Ui::VerticalLayout*> container) {
	using namespace Data;

	Ui::AddSubsectionTitle(container, rpl::single(QString("Cryptographic Algorithm")));

	container->add(
		object_ptr<Ui::FlatLabel>(
			container,
			QString("Select the cryptographic algorithm for signatures and encryption:"),
			st::settingsUpdateState),
		st::settingsCheckboxPadding);

	// Algorithm selection (default to ECC P-256)
	const auto algorithmGroup = container->add(
		object_ptr<Ui::RadiobuttonGroup>(
			container,
			2),  // Default to ECC P-256 (index 2)
		st::settingsCheckboxPadding);

	// RSA-2048/SHA-256 (Standard DoD)
	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			algorithmGroup,
			0,
			QString("RSA-2048/SHA-256 (2048-bit, Standard DoD) - Security Level 3/5"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	// RSA-4096/SHA-384 (High security)
	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			algorithmGroup,
			1,
			QString("RSA-4096/SHA-384 (4096-bit, High security) - Security Level 4/5"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

	// ECC P-256/SHA-256 (Fast, standard)
	container->add(
		object_ptr<Ui::Radiobutton>(
			container,
			algorithmGroup,
			2,
			QString("ECDSA P-256/SHA-256 (Fast, standard) - Security Level 3/5 ✓ Recommended"),
			st::settingsCheckbox),
		st::settingsCheckboxPadding);

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

	// Algorithm status label
	_cacAlgorithmLabel = Ui::CreateChild<Ui::FlatLabel>(
		container,
		QString("Current: ECDSA P-256/SHA-256"),
		st::settingsUpdateState);
	container->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_cacAlgorithmLabel),
		st::settingsCheckboxPadding);

	algorithmGroup->setChangedCallback([=](int value) {
		// Map radio button index to CACAlgorithm enum
		CACAlgorithm algorithm;
		QString algorithmName;
		switch (value) {
			case 0:
				algorithm = CACAlgorithm::RSA_2048_SHA256;
				algorithmName = "RSA-2048/SHA-256";
				break;
			case 1:
				algorithm = CACAlgorithm::RSA_4096_SHA384;
				algorithmName = "RSA-4096/SHA-384";
				break;
			case 2:
				algorithm = CACAlgorithm::ECC_P256_SHA256;
				algorithmName = "ECDSA P-256/SHA-256";
				break;
			case 3:
				algorithm = CACAlgorithm::ECC_P384_SHA384;
				algorithmName = "ECDSA P-384/SHA-384";
				break;
			case 4:
				algorithm = CACAlgorithm::ECC_P521_SHA512;
				algorithmName = "ECDSA P-521/SHA-512";
				break;
			default:
				algorithm = CACAlgorithm::ECC_P256_SHA256;
				algorithmName = "ECDSA P-256/SHA-256";
		}

		// Apply algorithm to CAC interface
		auto cac = CACFactory::create();
		if (cac) {
			cac->initialize();
			const auto result = cac->setAlgorithm(algorithm);
			if (result == CACResult::Success) {
				_cacAlgorithmLabel->setText(QString("Current: %1").arg(algorithmName));
				Ui::Toast::Show(QString("✅ Algorithm changed to %1").arg(algorithmName));
			} else {
				Ui::Toast::Show("❌ Failed to change algorithm");
			}
		}

		Core::App().saveSettingsDelayed();
	});

	Ui::AddSkip(container);
	Ui::AddDividerText(
		container,
		rpl::single(QString(
			"💡 ECC algorithms (P-256/P-384/P-521) are faster and more efficient than RSA. "
			"P-256 is recommended for most users. Use P-384 or P-521 for maximum security. "
			"RSA algorithms provide compatibility with older systems."
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
