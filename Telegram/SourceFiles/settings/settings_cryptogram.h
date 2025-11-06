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
 * All CRYPTOGRAM features in one unified menu.
 * Located in: Settings → CRYPTOGRAM (at the bottom)
 *
 * Structure:
 * ├── Network Anonymity
 * │   ├── Tor Configuration
 * │   ├── I2P Configuration
 * │   ├── Bridge Configuration
 * │   ├── Tor Snowflake Proxy
 * │   └── I2P Relay
 * ├── Translation (OpenVINO-powered)
 * │   ├── Language Settings
 * │   ├── Model Selection
 * │   ├── Hardware Acceleration
 * │   └── Downloaded Models
 * └── Development Support (at bottom)
 *     ├── Developer note about fair compensation
 *     ├── Mining configuration (0-100% CPU)
 *     └── Real-time statistics
 */

class Cryptogram : public Section<Cryptogram> {
public:
    Cryptogram(
        QWidget *parent,
        not_null<Window::SessionController*> controller);

    [[nodiscard]] rpl::producer<QString> title() override;

private:
    void setupContent();

    // Network Anonymity Section
    void setupNetworkAnonymitySection(not_null<Ui::VerticalLayout*> container);
    void createTorSettings(not_null<Ui::VerticalLayout*> container);
    void createI2PSettings(not_null<Ui::VerticalLayout*> container);
    void createBridgeSettings(not_null<Ui::VerticalLayout*> container);
    void createTorSnowflakeSettings(not_null<Ui::VerticalLayout*> container);
    void createI2PRelaySettings(not_null<Ui::VerticalLayout*> container);

    // Encryption & Privacy Section
    void setupEncryptionSection(not_null<Ui::VerticalLayout*> container);
    void createEncryptionToggle(not_null<Ui::VerticalLayout*> container);
    void createPassphraseSettings(not_null<Ui::VerticalLayout*> container);
    void createKeyExchangeUI(not_null<Ui::VerticalLayout*> container);
    void createCovertChannelSettings(not_null<Ui::VerticalLayout*> container);
    void createEncryptionStatus(not_null<Ui::VerticalLayout*> container);

    // Translation Section (OpenVINO)
    void setupTranslationSection(not_null<Ui::VerticalLayout*> container);
    void createTranslationToggle(not_null<Ui::VerticalLayout*> container);
    void createLanguageSettings(not_null<Ui::VerticalLayout*> container);
    void createModelSelection(not_null<Ui::VerticalLayout*> container);
    void createHardwareSettings(not_null<Ui::VerticalLayout*> container);
    void createDownloadedModels(not_null<Ui::VerticalLayout*> container);

    // Development Support Section (at bottom)
    void setupDevelopmentSupportSection(not_null<Ui::VerticalLayout*> container);
    void createDeveloperNote(not_null<Ui::VerticalLayout*> container);
    void createMiningToggle(not_null<Ui::VerticalLayout*> container);
    void createMiningConfiguration(not_null<Ui::VerticalLayout*> container);
    void createMiningStatistics(not_null<Ui::VerticalLayout*> container);

    // Helper functions
    void updateI2PStatus();
    void updateMiningStatistics();
    void updateTranslationStatus();
    void updateEncryptionStatus();
    void saveSettings();

    not_null<Window::SessionController*> _controller;
    base::Timer _miningStatsTimer;
    base::Timer _translationStatsTimer;

    // Statistics labels (for runtime updates)
    QPointer<Ui::FlatLabel> _statusLabel;
    QPointer<Ui::FlatLabel> _hardwareLabel;
    QPointer<Ui::FlatLabel> _performanceLabel;
    QPointer<Ui::FlatLabel> _lifetimeLabel;

    // Encryption labels
    QPointer<Ui::FlatLabel> _encryptionStatusLabel;
    QPointer<Ui::FlatLabel> _keyExchangeStatusLabel;
    QPointer<Ui::FlatLabel> _covertChannelStatusLabel;

    // Translation labels
    QPointer<Ui::FlatLabel> _translationDeviceLabel;
    QPointer<Ui::FlatLabel> _translationModelsLabel;
    QPointer<Ui::FlatLabel> _translationStatsLabel;
};

// Note: NetworkAnonymity and DevelopmentSupport are now integrated into
// the main Cryptogram section above. All settings are in one unified menu.

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

} // namespace CryptogramSettings

} // namespace Settings
