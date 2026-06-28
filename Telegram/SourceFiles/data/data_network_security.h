/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#pragma once

#include "base/bytes.h"
#include "base/expected.h"
#include "mtproto/mtproto_proxy_data.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <QtCore/QDateTime>
#include <QtNetwork/QNetworkProxy>
#include <memory>
#include <vector>
#include <functional>

namespace Data {

// Forward declarations
class Session;
class SignalProtocol;

// Network performance metrics (used by multiple classes)
struct NetworkPerformanceMetrics {
    float averageLatency = 0.0f;        // milliseconds
    float bandwidth = 0.0f;             // Mbps
    float packetLoss = 0.0f;            // percentage (0.0-1.0)
    int activeConnections = 0;
    int obfuscatedPackets = 0;
    int threatsDetected = 0;
    QDateTime lastUpdate;
};

// Network security operation results
enum class NetworkSecurityResult {
    Success,
    InitializationFailed,
    ObfuscationFailed,
    TunnelCreationFailed,
    TorConnectionFailed,
    VPNConnectionFailed,
    DNSQueryFailed,
    TrafficAnalysisDetected,
    BridgeConnectionFailed,
    MeshNetworkFailed,
    AnomalyDetected,
    UnknownError
};

// Traffic obfuscation methods
enum class ObfuscationMethod {
    None,               // Direct connection (debug only)
    HTTPSMimicry,       // HTTPS traffic mimicry
    HTTP2Tunneling,     // HTTP/2 protocol tunneling
    WebSocketTunnel,    // WebSocket-based tunneling
    CustomProtocol,     // Custom obfuscation protocol
    MultiLayered        // Multiple obfuscation layers
};

// Anti-surveillance strategies
enum class AntiSurveillanceStrategy {
    Standard,           // Basic protection
    Paranoid,           // Maximum protection
    Stealth,            // Maximum stealth
    Performance,        // Balanced performance/security
    Adaptive            // Adaptive based on threat level
};

// Network security tier for universal compatibility
enum class NetworkSecurityTier {
    Tier0_Quantum,      // GNA + NPU + Hardware acceleration
    Tier1_Premium,      // NPU + Hardware optimization
    Tier2_Enhanced,     // GPU acceleration + hardware crypto
    Tier3_Standard,     // CPU optimized with software crypto
    Tier4_Universal     // Basic CPU implementation
};

// Traffic analysis detection result
struct TrafficAnalysisResult {
    bool threatDetected = false;
    QString threatType;
    float riskLevel = 0.0f;       // 0.0 = no risk, 1.0 = maximum risk
    QStringList indicators;
    QDateTime detectionTime;
    QString mitigationStrategy;
};

// Network bridge configuration
struct BridgeConfiguration {
    QString bridgeId;
    QString bridgeAddress;
    uint16 bridgePort;
    bytes::vector bridgeKey;
    QString bridgeType;           // "obfs4", "meek", "snowflake", etc.
    bool isActive = false;
    float reliability = 0.0f;     // 0.0 = unreliable, 1.0 = highly reliable
    QDateTime lastActive;
};

// Mesh network node information
struct MeshNetworkNode {
    QString nodeId;
    QString nodeAddress;
    uint16 nodePort;
    bytes::vector nodePublicKey;
    float trustLevel = 0.0f;      // 0.0 = untrusted, 1.0 = fully trusted
    int hopDistance = 0;          // Distance from current node
    QDateTime lastSeen;
    bool isRelay = false;
    bool isGuard = false;
    bool isExit = false;
};

// VPN configuration for automatic integration
struct VPNConfiguration {
    QString vpnProvider;
    QString serverAddress;
    uint16 serverPort;
    QString protocol;             // "OpenVPN", "WireGuard", "IKEv2", etc.
    bytes::vector credentials;
    QString region;
    bool isActive = false;
    float latency = 0.0f;         // milliseconds
    float bandwidth = 0.0f;       // Mbps
    QDateTime connectedAt;
};

// DNS over HTTPS configuration
struct DoHConfiguration {
    QString provider;             // "Cloudflare", "Quad9", "AdGuard", etc.
    QString endpoint;
    bool useCustomEndpoint = false;
    bool enableECSDecryption = false;
    QStringList blockedDomains;
    QStringList allowedDomains;
    int queryTimeout = 5000;      // milliseconds
};

// Network obfuscation result
struct ObfuscationResult {
    bytes::vector obfuscatedData;
    ObfuscationMethod method;
    QByteArray obfuscationKey;
    QString protocolMimicry;
    int paddingBytes = 0;
    QDateTime processedAt;
};

// Network security configuration
struct NetworkSecurityConfig {
    ObfuscationMethod obfuscationMethod = ObfuscationMethod::MultiLayered;
    AntiSurveillanceStrategy surveillanceStrategy = AntiSurveillanceStrategy::Adaptive;
    NetworkSecurityTier securityTier = NetworkSecurityTier::Tier3_Standard;

    bool enableTrafficObfuscation = true;
    bool enableDPIEvasion = true;
    bool enableBridgeRelay = true;
    bool enableMeshNetworking = true;
    bool enableVPNIntegration = true;
    bool enableTorIntegration = true;
    bool enableDoH = true;
    bool enableAnomalyDetection = true;

    int maxBridges = 10;
    int maxMeshNodes = 50;
    int trafficAnalysisInterval = 30000;  // milliseconds
    float threatDetectionThreshold = 0.7f; // 0.0-1.0

    DoHConfiguration dohConfig;
};

// Main network security interface
class NetworkSecurity : public QObject {
    Q_OBJECT

public:
    explicit NetworkSecurity(not_null<Session*> session);
    Q_DISABLE_COPY_MOVE(NetworkSecurity)
    ~NetworkSecurity();

    // Initialization and configuration
    NetworkSecurityResult initialize(const NetworkSecurityConfig &config = {});
    bool isInitialized() const;
    NetworkSecurityConfig getConfiguration() const;
    void updateConfiguration(const NetworkSecurityConfig &config);

    // Hardware tier detection and adaptation
    NetworkSecurityTier detectNetworkSecurityTier() const;
    void adaptToHardwareTier(NetworkSecurityTier tier);
    bool isFeatureAvailable(const QString &feature) const;

    // Traffic obfuscation
    base::expected<ObfuscationResult, NetworkSecurityResult> obfuscateTraffic(
        const bytes::const_span &data,
        ObfuscationMethod method = ObfuscationMethod::MultiLayered);

    base::expected<bytes::vector, NetworkSecurityResult> deobfuscateTraffic(
        const ObfuscationResult &obfuscatedData);

    // Deep Packet Inspection (DPI) evasion
    base::expected<bytes::vector, NetworkSecurityResult> evadeDPI(
        const bytes::const_span &data,
        const QString &targetProtocol = "https");

    // DPI evasion transport wrapping — wraps outgoing MTP data in a
    // protocol mimicry layer (HTTPS/HTTP/DNS/Generic) to defeat DPI.
    // Returns the wrapped bytes, or empty on failure.
    QByteArray wrapOutgoingData(const QByteArray &data);

    // Apply DPI evasion settings to a socket connection (e.g. set proxy,
    // adjust TLS settings). Returns true if applied successfully.
    bool applyToSocket(class QAbstractSocket *socket);

    // DPI evasion state
    bool isDPIEvasionActive() const { return _dpiEvasionActive; }
    void setDPIEvasionActive(bool active) { _dpiEvasionActive = active; }
    void setDPIEvasionMethod(int method) { _dpiEvasionMethod = method; }
    int dpiEvasionMethod() const { return _dpiEvasionMethod; }
    qint64 dpiPacketsWrapped() const { return _dpiPacketsWrapped; }
    qint64 dpiBytesWrapped() const { return _dpiBytesWrapped; }

    // Bridge relay management
    NetworkSecurityResult addBridge(const BridgeConfiguration &bridge);
    NetworkSecurityResult removeBridge(const QString &bridgeId);
    QVector<BridgeConfiguration> getActiveBridges() const;
    base::expected<BridgeConfiguration, NetworkSecurityResult> selectOptimalBridge();

    // Mesh networking
    NetworkSecurityResult joinMeshNetwork();
    NetworkSecurityResult leaveMeshNetwork();
    QVector<MeshNetworkNode> getMeshNodes() const;
    base::expected<QVector<QString>, NetworkSecurityResult> findOptimalRoute(
        const QString &destination);

    // VPN integration
    NetworkSecurityResult configureVPN(const VPNConfiguration &config);
    NetworkSecurityResult connectVPN();
    NetworkSecurityResult disconnectVPN();
    bool isVPNConnected() const;
    VPNConfiguration getVPNStatus() const;

    // Tor integration
    NetworkSecurityResult configureTor(const QString &torConfigPath = {});
    NetworkSecurityResult connectTor();
    NetworkSecurityResult disconnectTor();
    bool isTorConnected() const;
    QString getTorCircuitInfo() const;

    // DNS over HTTPS
    NetworkSecurityResult configureDNS(const DoHConfiguration &config);
    base::expected<QString, NetworkSecurityResult> resolveHostname(
        const QString &hostname);
    base::expected<QStringList, NetworkSecurityResult> reverseResolve(
        const QString &ipAddress);

    // Traffic analysis and anomaly detection
    TrafficAnalysisResult analyzeTraffic(const bytes::const_span &data);
    void enableContinuousMonitoring(bool enable);
    bool isContinuousMonitoringEnabled() const;
    QVector<TrafficAnalysisResult> getRecentThreats(int maxResults = 100) const;

    // Network proxy integration
    QNetworkProxy createSecureProxy() const;
    NetworkSecurityResult updateProxyConfiguration(const MTP::ProxyData &proxy);

    // Performance monitoring
    NetworkPerformanceMetrics getPerformanceMetrics() const;

    // Integration with Signal Protocol
    void integrateWithSignalProtocol(not_null<SignalProtocol*> signalProtocol);
    base::expected<bytes::vector, NetworkSecurityResult> secureNetworkKey(
        const bytes::const_span &networkKey);

    base::expected<bytes::vector, NetworkSecurityResult> generateNetworkKeys();

Q_SIGNALS:
    void threatDetected(const TrafficAnalysisResult &threat);
    void vpnConnectionStatusChanged(bool connected, const QString &status);
    void torConnectionStatusChanged(bool connected, const QString &status);

private:
    // Traffic obfuscation implementations
    class TrafficObfuscator;
    class DPIEvasion;
    class ProtocolMimicry;

    // Anti-surveillance implementations
    class BridgeManager;
    class MeshNetworkManager;
    class TorIntegration;
    class VPNIntegration;

    // Detection and analysis
    class TrafficAnalyzer;
    class AnomalyDetector;
    class ThreatMitigator;

    // DNS and networking
    class DNSOverHTTPS;
    class NetworkPerformanceMonitor;

    std::shared_ptr<TrafficObfuscator> _obfuscator;
    std::shared_ptr<DPIEvasion> _dpiEvasion;
    std::shared_ptr<ProtocolMimicry> _protocolMimicry;
    std::shared_ptr<BridgeManager> _bridgeManager;
    std::shared_ptr<MeshNetworkManager> _meshManager;
    std::shared_ptr<TorIntegration> _torIntegration;
    std::shared_ptr<VPNIntegration> _vpnIntegration;
    std::shared_ptr<TrafficAnalyzer> _trafficAnalyzer;
    std::shared_ptr<AnomalyDetector> _anomalyDetector;
    std::shared_ptr<ThreatMitigator> _threatMitigator;
    std::shared_ptr<DNSOverHTTPS> _dnsOverHTTPS;
    std::shared_ptr<NetworkPerformanceMonitor> _performanceMonitor;

    not_null<Session*> _session;
    NetworkSecurityConfig _config;
    NetworkSecurityTier _currentTier = NetworkSecurityTier::Tier3_Standard;
    bool _initialized = false;
    bool _continuousMonitoring = false;

    // DPI evasion state
    bool _dpiEvasionActive = false;
    int _dpiEvasionMethod = 0;  // 0=HTTPS, 1=HTTP, 2=DNS, 3=Generic, 4=Auto
    qint64 _dpiPacketsWrapped = 0;
    qint64 _dpiBytesWrapped = 0;

    // Integration interfaces
    SignalProtocol* _signalProtocol = nullptr;

    // Helper methods
    NetworkSecurityResult validateConfiguration(const NetworkSecurityConfig &config);
    void initializeNetworkComponents();
    void setupHardwareTierOptimizations();
    void configureUniversalFallbacks();
    void setupPerformanceMonitoring();
    void adaptFeatureToTier(const QString &feature, NetworkSecurityTier tier);

    // Universal compatibility helpers
    bool isHardwareFeatureAvailable(const QString &feature) const;
    NetworkSecurityResult fallbackToSoftwareImplementation(const QString &feature);
};

// Factory class for creating network security instances
class NetworkSecurityFactory {
public:
    // Create network security instance for current platform
    static std::unique_ptr<NetworkSecurity> create(not_null<Session*> session);

    // Create with specific configuration
    static std::unique_ptr<NetworkSecurity> createWithConfig(
        not_null<Session*> session,
        const NetworkSecurityConfig &config);

    // Platform and tier detection
    static NetworkSecurityTier detectOptimalTier();
    static QStringList getAvailableFeatures(NetworkSecurityTier tier);
    static NetworkSecurityConfig getDefaultConfig(NetworkSecurityTier tier);
};

// Universal network security coordinator for cross-tier compatibility
class UniversalNetworkSecurity : public QObject {
    Q_OBJECT

public:
    explicit UniversalNetworkSecurity(not_null<Session*> session);
    Q_DISABLE_COPY_MOVE(UniversalNetworkSecurity)
    ~UniversalNetworkSecurity();

    // Universal initialization that works across all hardware tiers
    NetworkSecurityResult initializeUniversalSecurity();

    // Tier-adaptive operations
    base::expected<ObfuscationResult, NetworkSecurityResult> universalObfuscation(
        const bytes::const_span &data);

    // Guaranteed fallback operations
    NetworkSecurityResult establishSecureConnection(const QString &target);
    NetworkSecurityResult detectAndMitigateThreats();

    // Cross-tier performance optimization
    void optimizeForCurrentHardware();
    NetworkPerformanceMetrics getUniversalMetrics() const;


private:
    std::unique_ptr<NetworkSecurity> _networkSecurity;
    NetworkSecurityTier _detectedTier;
    QStringList _availableFeatures;
    not_null<Session*> _session;

};

} // namespace Data

// Global DPI evasion hook — allows the MTP transport layer to
// wrap outgoing data without direct access to Data::Session.
// Set by the session when DPI evasion is enabled.
namespace Data {
void SetGlobalDPIEvasionCallback(std::function<QByteArray(const QByteArray&)> callback);
void ClearGlobalDPIEvasionCallback();
QByteArray ApplyGlobalDPIEvasion(const QByteArray &data);
bool IsGlobalDPIEvasionActive();
} // namespace Data