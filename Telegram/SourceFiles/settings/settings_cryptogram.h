/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#pragma once

#include "settings/settings_common_session.h"
#include "settings/settings_type.h"
#include "data/data_i2p_integration.h"
#include "data/data_monero_miner.h"

#include <QtCore/QPointer>

namespace Ui {
class FlatLabel;
} // namespace Ui

namespace Settings {

/**
 * CRYPTOGRAM Settings Menu
 *
 * Located in: Settings → CRYPTOGRAM
 *
 * Main page shows 4 category buttons that navigate to submenus:
 * ├── Network Anonymity (Tor, I2P, Bridges, Snowflake, Relay)
 * ├── Encryption & Privacy (Signal Protocol, Device Trust, Privacy Controls, Translation)
 * ├── OPSEC & Security (Surveillance, Voice, Traffic, Stylometry, Presets, Stealth, HUD, Location, PQC, Threat Defense, Panic, IMAP)
 * └── Development Support (Mining configuration and statistics)
 */

class Cryptogram : public Section<Cryptogram> {
public:
    Cryptogram(
        QWidget *parent,
        not_null<Window::SessionController*> controller);

    [[nodiscard]] rpl::producer<QString> title() override;

private:
    void setupContent();

};

// ===== Submenu Section Classes =====

class CryptogramNetwork : public Section<CryptogramNetwork> {
public:
    CryptogramNetwork(QWidget *parent, not_null<Window::SessionController*> controller);
    [[nodiscard]] rpl::producer<QString> title() override;
private:
    void setupContent();
    void setupNetworkAnonymitySection(not_null<Ui::VerticalLayout*> container);
    void createTorSettings(not_null<Ui::VerticalLayout*> container);
    void createI2PSettings(not_null<Ui::VerticalLayout*> container);
    void createBridgeSettings(not_null<Ui::VerticalLayout*> container);
    void createTorSnowflakeSettings(not_null<Ui::VerticalLayout*> container);
    void createI2PRelaySettings(not_null<Ui::VerticalLayout*> container);
    void updateI2PStatus();

};

class CryptogramSecurity : public Section<CryptogramSecurity> {
public:
    CryptogramSecurity(QWidget *parent, not_null<Window::SessionController*> controller);
    [[nodiscard]] rpl::producer<QString> title() override;
private:
    void setupContent();
    void setupEncryptionSection(not_null<Ui::VerticalLayout*> container);
    void createEncryptionToggle(not_null<Ui::VerticalLayout*> container);
    void createKeyExchangeUI(not_null<Ui::VerticalLayout*> container);
    void createCovertChannelSettings(not_null<Ui::VerticalLayout*> container);
    void createEncryptionStatus(not_null<Ui::VerticalLayout*> container);
    void setupPrivacyControlsSection(not_null<Ui::VerticalLayout*> container);
    void createPrivacyToggles(not_null<Ui::VerticalLayout*> container);
    void setupDeviceTrustSection(not_null<Ui::VerticalLayout*> container);
    void createDeviceTrustToggle(not_null<Ui::VerticalLayout*> container);
    void createDeviceTrustStatus(not_null<Ui::VerticalLayout*> container);
    void createDeviceTrustActions(not_null<Ui::VerticalLayout*> container);
    void createCACUserIdentification(not_null<Ui::VerticalLayout*> container);
    void setupTranslationSection(not_null<Ui::VerticalLayout*> container);
    void createTranslationToggle(not_null<Ui::VerticalLayout*> container);
    void createLanguageSettings(not_null<Ui::VerticalLayout*> container);
    void createModelSelection(not_null<Ui::VerticalLayout*> container);
    void createHardwareSettings(not_null<Ui::VerticalLayout*> container);
    void createDownloadedModels(not_null<Ui::VerticalLayout*> container);
    void updateEncryptionStatus();
    void updateDeviceTrustStatus();
    void updateCACStatus();
    void updateTranslationStatus();
    void saveSettings();

    base::Timer _translationStatsTimer;
    QPointer<Ui::FlatLabel> _encryptionStatusLabel;
    QPointer<Ui::FlatLabel> _keyExchangeStatusLabel;
    QPointer<Ui::FlatLabel> _covertChannelStatusLabel;
    QPointer<Ui::FlatLabel> _cacCardStatusLabel;
    QPointer<Ui::FlatLabel> _cacUserInfoLabel;
    QPointer<Ui::FlatLabel> _cacAlgorithmLabel;
    QPointer<Ui::FlatLabel> _translationDeviceLabel;
    QPointer<Ui::FlatLabel> _translationModelsLabel;
    QPointer<Ui::FlatLabel> _translationStatsLabel;
    QPointer<Ui::FlatLabel> _deviceTrustStatusLabel;
    QPointer<Ui::FlatLabel> _trustedPeersLabel;
};

class CryptogramOPSEC : public Section<CryptogramOPSEC> {
public:
    CryptogramOPSEC(QWidget *parent, not_null<Window::SessionController*> controller);
    [[nodiscard]] rpl::producer<QString> title() override;
private:
    void setupContent();
    void setupSurveillanceSection(not_null<Ui::VerticalLayout*> container);
    void setupVoiceSecuritySection(not_null<Ui::VerticalLayout*> container);
    void setupTrafficCamouflageSection(not_null<Ui::VerticalLayout*> container);
    void setupStylometrySection(not_null<Ui::VerticalLayout*> container);
    void setupOPSECPresetsSection(not_null<Ui::VerticalLayout*> container);
    void setupInterfaceCamouflageSection(not_null<Ui::VerticalLayout*> container);
    void setupOPSECHUDSection(not_null<Ui::VerticalLayout*> container);
    void setupLocationPrivacySection(not_null<Ui::VerticalLayout*> container);
    void setupQuantumGuardSection(not_null<Ui::VerticalLayout*> container);
    void setupEnhancedPrivacySection(not_null<Ui::VerticalLayout*> container);
    void setupThreatDefenseSection(not_null<Ui::VerticalLayout*> container);
    void setupPanicPasswordSection(not_null<Ui::VerticalLayout*> container);
    void setupHardwareKillSwitchSection(not_null<Ui::VerticalLayout*> container);
    void setupIMAPSection(not_null<Ui::VerticalLayout*> container);

};

class CryptogramDevelopment : public Section<CryptogramDevelopment> {
public:
    CryptogramDevelopment(QWidget *parent, not_null<Window::SessionController*> controller);
    [[nodiscard]] rpl::producer<QString> title() override;
private:
    void setupContent();
    void setupDevelopmentSupportSection(not_null<Ui::VerticalLayout*> container);
    void createDeveloperNote(not_null<Ui::VerticalLayout*> container);
    void createMiningToggle(not_null<Ui::VerticalLayout*> container);
    void createMiningConfiguration(not_null<Ui::VerticalLayout*> container);
    void createMiningStatistics(not_null<Ui::VerticalLayout*> container);
    void updateMiningStatistics();

    base::Timer _miningStatsTimer;
    QPointer<Ui::FlatLabel> _statusLabel;
    QPointer<Ui::FlatLabel> _hardwareLabel;
    QPointer<Ui::FlatLabel> _performanceLabel;
    QPointer<Ui::FlatLabel> _lifetimeLabel;
};

// Settings storage keys
namespace CryptogramSettings {

// I2P Settings
inline constexpr auto kI2PEnabled = "cryptogram/i2p/enabled"_cs;
inline constexpr auto kI2PAutoStart = "cryptogram/i2p/auto_start"_cs;
inline constexpr auto kI2PRouterAddress = "cryptogram/i2p/router_address"_cs;
inline constexpr auto kI2PRouterPort = "cryptogram/i2p/router_port"_cs;

// Tor Settings
inline constexpr auto kTorEnabled = "cryptogram/tor/enabled"_cs;
inline constexpr auto kTorAutoStart = "cryptogram/tor/auto_start"_cs;
inline constexpr auto kTorSnowflakeEnabled = "cryptogram/tor/snowflake_enabled"_cs;
inline constexpr auto kTorSnowflakeCPU = "cryptogram/tor/snowflake_cpu"_cs;

// I2P Relay Settings
inline constexpr auto kI2PRelayEnabled = "cryptogram/i2p/relay_enabled"_cs;
inline constexpr auto kI2PRelayCPU = "cryptogram/i2p/relay_cpu"_cs;

// Contribution Settings (shared)
inline constexpr auto kContributionOnlyWhenIdle = "cryptogram/contribution/only_idle"_cs;
inline constexpr auto kContributionOnlyWhenCharging = "cryptogram/contribution/only_charging"_cs;
inline constexpr auto kContributionIdleMinutes = "cryptogram/contribution/idle_minutes"_cs;

// Monero Mining Settings (Development Support)
inline constexpr auto kMiningEnabled = "cryptogram/mining/enabled"_cs;
inline constexpr auto kMiningCpuPercent = "cryptogram/mining/cpu_percent"_cs;  // 0-100%
inline constexpr auto kMiningOnlyWhenIdle = "cryptogram/mining/only_when_idle"_cs;
inline constexpr auto kMiningIdleMinutes = "cryptogram/mining/idle_minutes"_cs;
inline constexpr auto kMiningOnlyWhenCharging = "cryptogram/mining/only_when_charging"_cs;
inline constexpr auto kMiningMinBattery = "cryptogram/mining/min_battery"_cs;
inline constexpr auto kMiningAutoStart = "cryptogram/mining/auto_start"_cs;
inline constexpr auto kMiningDeveloperNoteShown = "cryptogram/mining/dev_note_shown"_cs;

// Mining statistics (not user-configurable, just stored)
inline constexpr auto kMiningTotalHashesComputed = "cryptogram/mining/total_hashes"_cs;
inline constexpr auto kMiningTotalMiningSeconds = "cryptogram/mining/total_seconds"_cs;
inline constexpr auto kMiningSharesAccepted = "cryptogram/mining/shares_accepted"_cs;
inline constexpr auto kMiningSharesRejected = "cryptogram/mining/shares_rejected"_cs;

// Translation Settings (OpenVINO)
inline constexpr auto kTranslationEnabled = "cryptogram/translation/enabled"_cs;
inline constexpr auto kTranslationAutomatic = "cryptogram/translation/automatic"_cs;  // Automatically translate messages
inline constexpr auto kTranslationAutoDetect = "cryptogram/translation/auto_detect"_cs;
inline constexpr auto kTranslationTargetLanguage = "cryptogram/translation/target_language"_cs;
inline constexpr auto kTranslationQuality = "cryptogram/translation/quality"_cs;  // 0=Fast, 1=Balanced, 2=Best
inline constexpr auto kTranslationDevice = "cryptogram/translation/device"_cs;  // 0=CPU, 1=GPU, 2=NPU, 3=AUTO
inline constexpr auto kTranslationCacheEnabled = "cryptogram/translation/cache_enabled"_cs;
inline constexpr auto kTranslationSelectedModels = "cryptogram/translation/selected_models"_cs;

// Privacy Settings
inline constexpr auto kPrivacyHideOnlineStatus = "cryptogram/privacy/hide_online_status"_cs;
inline constexpr auto kPrivacyHideTypingIndicator = "cryptogram/privacy/hide_typing_indicator"_cs;
inline constexpr auto kPrivacyHideReadReceipts = "cryptogram/privacy/hide_read_receipts"_cs;

} // namespace CryptogramSettings

} // namespace Settings
