/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

Phase 5: Network Security Implementation - Complete Integration Header

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#pragma once

#include "data/data_network_security.h"
#include "data/data_signal_protocol.h"
#include "data/data_tsm_interface.h"
#include "mtproto/connection_abstract.h"

#include <QtCore/QObject>
#include <memory>

namespace Data {

// Forward declarations
class Session;

/**
 * Phase 5 Network Security - Complete Implementation
 *
 * This class provides the main interface for SpyGram's Phase 5 Network Security
 * implementation, integrating all components into a unified system.
 *
 * Key Features:
 * - Traffic Obfuscation & DPI Evasion
 * - Anti-surveillance Mesh Networking
 * - VPN/Tor Integration with Auto-configuration
 * - Network Anomaly Detection & Response
 * - Signal Protocol & TSM Integration
 * - Universal Hardware Compatibility (5-tier architecture)
 * - MTPProto Connection Security
 *
 * Universal Compatibility:
 * - Tier 0 (Quantum): GNA + NPU + TPM 2.0 - Maximum security & performance
 * - Tier 1 (Premium): NPU + TPM 2.0 - Hardware-accelerated security
 * - Tier 2 (Enhanced): GPU + TPM 2.0 - GPU-accelerated processing
 * - Tier 3 (Standard): CPU + AES-NI - Software-optimized security
 * - Tier 4 (Universal): Any CPU - Basic compatibility mode
 *
 * Security Guarantees:
 * - Identical security level across ALL tiers
 * - Performance scales with hardware, security never degrades
 * - Graceful fallbacks ensure universal compatibility
 * - No user left behind regardless of hardware capabilities
 */
class Phase5NetworkSecurity : public QObject {
    Q_OBJECT

public:
    explicit Phase5NetworkSecurity(not_null<Session*> session);
    ~Phase5NetworkSecurity();

    // === MAIN INTERFACE ===

    /**
     * Initialize Phase 5 Network Security with automatic tier detection
     * @return NetworkSecurityResult indicating success or failure
     */
    NetworkSecurityResult initialize();

    /**
     * Initialize with specific configuration
     * @param config Custom network security configuration
     * @return NetworkSecurityResult indicating success or failure
     */
    NetworkSecurityResult initializeWithConfig(const NetworkSecurityConfig &config);

    /**
     * Check if Phase 5 Network Security is initialized and ready
     * @return true if initialized, false otherwise
     */
    bool isInitialized() const;

    /**
     * Get current hardware tier and capabilities
     * @return Current NetworkSecurityTier
     */
    NetworkSecurityTier getCurrentTier() const;

    /**
     * Get list of available features for current tier
     * @return QStringList of available feature names
     */
    QStringList getAvailableFeatures() const;

    // === CORE SECURITY OPERATIONS ===

    /**
     * Secure outgoing MTPProto data with network obfuscation
     * @param mtpData Raw MTPProto data to secure
     * @return Obfuscated data ready for transmission
     */
    bytes::vector secureOutgoingMTPData(const bytes::const_span &mtpData);

    /**
     * Process incoming MTPProto data and check for threats
     * @param securedData Incoming data to process
     * @return Original data if safe, error if threat detected
     */
    base::expected<bytes::vector, NetworkSecurityResult> processIncomingMTPData(
        const bytes::const_span &securedData);

    /**
     * Create secure proxy configuration for MTPProto connections
     * @return QNetworkProxy configured for current security setup
     */
    QNetworkProxy createSecureProxy();

    /**
     * Update MTPProto proxy settings with network security integration
     * @param proxy MTPProto proxy configuration to integrate
     * @return NetworkSecurityResult indicating success or failure
     */
    NetworkSecurityResult updateMTPProxySettings(const MTP::ProxyData &proxy);

    // === ADVANCED SECURITY FEATURES ===

    /**
     * Enable/disable continuous traffic monitoring and threat detection
     * @param enable true to enable monitoring, false to disable
     */
    void enableContinuousMonitoring(bool enable);

    /**
     * Get recent security threats detected by the system
     * @param maxResults Maximum number of results to return
     * @return Vector of recent threat analysis results
     */
    QVector<TrafficAnalysisResult> getRecentThreats(int maxResults = 50) const;

    /**
     * Force connection through Tor network
     * @return NetworkSecurityResult indicating success or failure
     */
    NetworkSecurityResult forceTorConnection();

    /**
     * Connect through VPN with automatic server selection
     * @return NetworkSecurityResult indicating success or failure
     */
    NetworkSecurityResult connectVPN();

    /**
     * Join mesh network for decentralized communication
     * @return NetworkSecurityResult indicating success or failure
     */
    NetworkSecurityResult joinMeshNetwork();

    /**
     * Disconnect all advanced security features (VPN, Tor, Mesh)
     * @return NetworkSecurityResult indicating success or failure
     */
    NetworkSecurityResult disconnectAdvancedFeatures();

    // === INTEGRATION INTERFACES ===

    /**
     * Integrate with Signal Protocol for cryptographic binding
     * @param signalProtocol Signal Protocol instance to integrate with
     */
    void integrateSignalProtocol(not_null<SignalProtocol*> signalProtocol);

    /**
     * Integrate with TSM for hardware-backed security
     * @param tsm TSM interface instance to integrate with
     */
    void integrateTSM(std::shared_ptr<TSMInterface> tsm);

    /**
     * Generate network-specific keys using integrated security systems
     * @return Generated network keys or error
     */
    base::expected<bytes::vector, NetworkSecurityResult> generateSecureNetworkKeys();

    // === MONITORING AND DIAGNOSTICS ===

    /**
     * Get current network performance metrics
     * @return NetworkPerformanceMetrics with current statistics
     */
    NetworkPerformanceMetrics getPerformanceMetrics() const;

    /**
     * Get current security status summary
     * @return QString with human-readable security status
     */
    QString getSecurityStatusSummary() const;

    /**
     * Test network security functionality
     * @return true if all tests pass, false if any issues detected
     */
    bool runSelfTest();

    /**
     * Get detailed configuration information
     * @return NetworkSecurityConfig with current settings
     */
    NetworkSecurityConfig getCurrentConfiguration() const;

    // === UNIVERSAL COMPATIBILITY ===

    /**
     * Check if specific feature is available on current hardware
     * @param featureName Name of feature to check
     * @return true if available, false otherwise
     */
    bool isFeatureAvailable(const QString &featureName) const;

    /**
     * Get performance impact estimate for current configuration
     * @return Percentage impact (0.0 = no impact, 1.0 = 100% impact)
     */
    float getPerformanceImpact() const;

    /**
     * Optimize settings for current hardware automatically
     */
    void optimizeForCurrentHardware();

    /**
     * Get hardware compatibility report
     * @return QString with detailed hardware compatibility information
     */
    QString getHardwareCompatibilityReport() const;

    // Initialization and status

    // Security events

    // Network status

    // Performance and monitoring

    // Errors and warnings

private:
    // Core components
    std::unique_ptr<NetworkSecurity> _networkSecurity;
    std::unique_ptr<UniversalNetworkSecurity> _universalSecurity;

    // Integration interfaces
    SignalProtocol* _signalProtocol = nullptr;
    std::shared_ptr<TSMInterface> _tsmInterface;

    // MTPProto integration
    class NetworkSecuredMTPConnection;
    std::unique_ptr<NetworkSecuredMTPConnection> _mtpIntegration;

    // Session and state
    not_null<Session*> _session;
    NetworkSecurityTier _currentTier = NetworkSecurityTier::Tier3_Standard;
    QStringList _availableFeatures;
    bool _initialized = false;

    // Helper methods
    QString _formatSecurityStatus() const;
    QString _formatHardwareReport() const;
    bool _validateConfiguration() const;
};

/**
 * Global factory function for creating Phase 5 Network Security instances
 */
namespace Phase5 {

/**
 * Create Phase 5 Network Security instance with automatic configuration
 * @param session Data session to use
 * @return Unique pointer to configured Phase5NetworkSecurity instance
 */
std::unique_ptr<Phase5NetworkSecurity> createNetworkSecurity(not_null<Session*> session);

/**
 * Create Phase 5 Network Security instance with custom configuration
 * @param session Data session to use
 * @param config Custom network security configuration
 * @return Unique pointer to configured Phase5NetworkSecurity instance
 */
std::unique_ptr<Phase5NetworkSecurity> createNetworkSecurityWithConfig(
    not_null<Session*> session,
    const NetworkSecurityConfig &config);

/**
 * Detect optimal network security tier for current hardware
 * @return NetworkSecurityTier representing optimal configuration
 */
NetworkSecurityTier detectOptimalSecurityTier();

/**
 * Get default configuration for specific hardware tier
 * @param tier Hardware tier to get configuration for
 * @return NetworkSecurityConfig with tier-appropriate settings
 */
NetworkSecurityConfig getDefaultConfigurationForTier(NetworkSecurityTier tier);

/**
 * Validate Phase 5 implementation for universal compatibility
 * @return true if validation passes, false if issues detected
 */
bool validateUniversalCompatibility();

/**
 * Get version information for Phase 5 Network Security
 * @return QString with version and build information
 */
QString getVersionInfo();

} // namespace Phase5

} // namespace Data

/**
 * USAGE EXAMPLE:
 *
 * // Basic initialization
 * auto phase5 = Data::Phase5::createNetworkSecurity(session);
 * auto result = phase5->initialize();
 *
 * if (result == Data::NetworkSecurityResult::Success) {
 *     // Integration with existing systems
 *     phase5->integrateSignalProtocol(signalProtocol);
 *     phase5->integrateTSM(tsmInterface);
 *
 *     // Enable monitoring
 *     phase5->enableContinuousMonitoring(true);
 *
 *     // Secure MTPProto traffic
 *     auto securedData = phase5->secureOutgoingMTPData(originalData);
 *
 *     // Connect through secure channels
 *     phase5->forceTorConnection();
 * }
 *
 * // Monitor security events
 * connect(phase5.get(), &Data::Phase5NetworkSecurity::threatDetected,
 *         [](const auto &threat) {
 *             qWarning() << "Security threat detected:" << threat.threatType;
 *         });
 */