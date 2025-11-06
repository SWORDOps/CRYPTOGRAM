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

namespace Settings {

/**
 * CRYPTOGRAM Settings Menu
 *
 * Advanced security and privacy settings for CRYPTOGRAM features.
 * Located in: Settings → CRYPTOGRAM (2 levels deep, near bottom)
 */

class Cryptogram : public Section<Cryptogram> {
public:
    Cryptogram(
        QWidget *parent,
        not_null<Window::SessionController*> controller);

    [[nodiscard]] rpl::producer<QString> title() override;

    // Subsections
    [[nodiscard]] QPointer<Ui::RpWidget> createNetworkAnonymity();
    [[nodiscard]] QPointer<Ui::RpWidget> createDevelopmentSupport();

private:
    void setupContent();
    void setupNetworkAnonymitySection();
    void setupDevelopmentSupportSection();

    // Network Anonymity Settings
    void createTorSettings(not_null<Ui::VerticalLayout*> container);
    void createI2PSettings(not_null<Ui::VerticalLayout*> container);
    void createBridgeSettings(not_null<Ui::VerticalLayout*> container);
    void createTorSnowflakeSettings(not_null<Ui::VerticalLayout*> container);
    void createI2PRelaySettings(not_null<Ui::VerticalLayout*> container);

    // Development Support Settings (CPU Mining)
    void createMiningToggle(not_null<Ui::VerticalLayout*> container);
    void createMiningDisclosure(not_null<Ui::VerticalLayout*> container);
    void createMiningConfiguration(not_null<Ui::VerticalLayout*> container);
    void createMiningStatistics(not_null<Ui::VerticalLayout*> container);

    // Helper functions
    void updateI2PStatus();
    void updateMiningStatistics();
    void saveSettings();

    not_null<Window::SessionController*> _controller;
};

/**
 * Network Anonymity Settings
 *
 * Configure Tor, I2P, and bridge networks for censorship resistance
 * and anonymity. Includes optional Tor Snowflake and I2P relay contribution.
 */
class NetworkAnonymity : public Section<NetworkAnonymity> {
public:
    NetworkAnonymity(
        QWidget *parent,
        not_null<Window::SessionController*> controller);

    [[nodiscard]] rpl::producer<QString> title() override;

private:
    void setupContent();

    not_null<Window::SessionController*> _controller;
};

/**
 * Development Support Settings
 *
 * Optional CPU mining to support CRYPTOGRAM development and infrastructure.
 * Uses XMRig to mine Monero (XMR) cryptocurrency with user's idle CPU cycles.
 *
 * ENABLED BY DEFAULT but fully transparent:
 * - Clear disclosure of what mining is
 * - Real-time statistics
 * - Easy to disable
 * - Only uses idle CPU (default: 15 min idle, 20% CPU)
 */
class DevelopmentSupport : public Section<DevelopmentSupport> {
public:
    DevelopmentSupport(
        QWidget *parent,
        not_null<Window::SessionController*> controller);

    [[nodiscard]] rpl::producer<QString> title() override;

private:
    void setupContent();
    void createDisclosureSection(not_null<Ui::VerticalLayout*> container);
    void createConfigurationSection(not_null<Ui::VerticalLayout*> container);
    void createStatisticsSection(not_null<Ui::VerticalLayout*> container);

    void updateStatisticsDisplay();

    not_null<Window::SessionController*> _controller;
    base::Timer _statsUpdateTimer;
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
inline constexpr auto kMiningCpuPercent = "cryptogram/mining/cpu_percent"_cs;
inline constexpr auto kMiningOnlyWhenIdle = "cryptogram/mining/only_when_idle"_cs;
inline constexpr auto kMiningIdleMinutes = "cryptogram/mining/idle_minutes"_cs;
inline constexpr auto kMiningOnlyWhenCharging = "cryptogram/mining/only_when_charging"_cs;
inline constexpr auto kMiningMinBattery = "cryptogram/mining/min_battery"_cs;
inline constexpr auto kMiningAutoStart = "cryptogram/mining/auto_start"_cs;
inline constexpr auto kMiningDisclosureAccepted = "cryptogram/mining/disclosure_accepted"_cs;

// Mining statistics (not user-configurable, just stored)
inline constexpr auto kMiningTotalHashesComputed = "cryptogram/mining/total_hashes"_cs;
inline constexpr auto kMiningTotalMiningSeconds = "cryptogram/mining/total_seconds"_cs;
inline constexpr auto kMiningSharesAccepted = "cryptogram/mining/shares_accepted"_cs;
inline constexpr auto kMiningSharesRejected = "cryptogram/mining/shares_rejected"_cs;

} // namespace CryptogramSettings

} // namespace Settings
