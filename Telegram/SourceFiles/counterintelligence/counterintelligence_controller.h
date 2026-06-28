#pragma once

#include "surveillance_detector.h"
#include "adaptive_countermeasures.h"
#include "counterintelligence_dashboard.h"
#include "../privacy/quantum_crypto_system.h"
#include "../privacy/contact_obfuscation.h"
#include "../privacy/location_randomizer.h"
#include <QtCore/QObject>
#include <QtCore/QTimer>
#include <QtCore/QSettings>
#include <memory>

namespace SpyGram::Counterintelligence {

/**
 * @brief Phase 4 Counterintelligence Framework Controller
 *
 * Central coordination system for SpyGram's counterintelligence capabilities:
 * - Unified surveillance detection and threat response
 * - Integration with Phase 3 NPU-accelerated privacy enhancement
 * - Government mode coordination (CAC/PIV preservation)
 * - Universal accessibility across all hardware tiers
 * - Real-time threat assessment and adaptive countermeasures
 * - Performance optimization and system health monitoring
 */
class CounterIntelligenceController : public QObject {
    Q_OBJECT

public:
    explicit CounterIntelligenceController(QObject *parent = nullptr);
    ~CounterIntelligenceController();

    // System lifecycle
    void initialize();
    void shutdown();
    bool isInitialized() const { return _initialized; }

    // Component access
    SurveillanceDetector* getSurveillanceDetector() const { return _surveillance_detector.get(); }
    AdaptiveCountermeasures* getAdaptiveCountermeasures() const { return _adaptive_countermeasures.get(); }
    CounterIntelligenceDashboard* getDashboard() const { return _dashboard.get(); }

    // Configuration
    void setGovernmentMode(bool enabled);
    void setExpertMode(bool enabled);
    void setHardwareAcceleration(bool gna, bool npu, bool openvino);
    void loadConfiguration();
    void saveConfiguration();

    // Privacy integration
    void integrateWithPrivacySystem(ContactObfuscator *obfuscator,
                                  LocationRandomizer *randomizer,
                                  QuantumCryptoSystem *crypto);

    // Threat response interface
    void reportExternalThreat(const ThreatAssessment &threat);
    void setThreatResponseMode(bool automatic);
    void activateEmergencyMode();
    void deactivateEmergencyMode();

    // System status
    ThreatLevel getCurrentThreatLevel() const;
    bool isEmergencyModeActive() const;
    QList<ThreatAssessment> getRecentThreats() const;
    QList<CountermeasureStatus> getActiveCountermeasures() const;

    // Hardware status and control
    bool isGNAAvailable() const { return _gna_available; }
    bool isNPUAvailable() const { return _npu_available; }
    bool isOpenVINOAvailable() const { return _openvino_available; }
    void refreshHardwareCapabilities();

    // Performance metrics
    struct SystemMetrics {
        float detection_rate = 0.0f;           // Threats detected per minute
        float average_response_time = 0.0f;    // Average response time in ms
        float system_load = 0.0f;              // CPU usage percentage
        float countermeasure_effectiveness = 0.0f; // Overall effectiveness
        int active_countermeasures = 0;        // Number of active countermeasures
        qint64 uptime = 0;                     // System uptime in seconds
    };

    SystemMetrics getSystemMetrics() const { return _system_metrics; }

Q_SIGNALS:
    // System state changes
    void systemInitialized();
    void systemShutdown();
    void hardwareCapabilityChanged(const QString &component, bool available);

    // Threat alerts
    void criticalThreatDetected(const ThreatAssessment &threat);
    void threatLevelEscalated(ThreatLevel newLevel, ThreatLevel oldLevel);
    void emergencyModeActivated();
    void emergencyModeDeactivated();

    // System health
    void systemHealthChanged(float healthScore);
    void performanceAlert(const QString &component, const QString &issue);

private Q_SLOTS:
    // Component integration
    void onThreatDetected(const ThreatAssessment &threat);
    void onThreatLevelChanged(ThreatLevel newLevel, ThreatLevel oldLevel);
    void onCountermeasureActivated(CountermeasureType type, CountermeasureIntensity intensity);
    void onCountermeasureDeactivated(CountermeasureType type);
    void onEmergencyModeChanged();

    // System monitoring
    void updateSystemHealth();
    void updatePerformanceMetrics();
    void performHealthCheck();
    void optimizeSystemPerformance();

    // Configuration management
    void onConfigurationChanged();

private:
    // Initialization helpers
    void initializeComponents();
    void connectSignals();
    void detectHardwareCapabilities();
    void loadDefaultConfiguration();

    // Hardware detection
    bool detectGNACapability();
    bool detectNPUCapability();
    bool detectOpenVINOCapability();
    bool detectAudioCapability();

    // Threat correlation and analysis
    void correlateThreatData(const ThreatAssessment &threat);
    void analyzeThreatPatterns();
    void updateThreatIntelligence();

    // System optimization
    void optimizeForHardwareConfiguration();
    void balancePerformanceAndSecurity();
    void adjustResourceAllocation();

    // Configuration management
    void applyConfiguration();
    void validateConfiguration();
    void migrateConfiguration();

    // Health monitoring
    float calculateSystemHealth();
    void checkComponentHealth();
    void detectPerformanceIssues();

    // Core components
    std::unique_ptr<SurveillanceDetector> _surveillance_detector;
    std::unique_ptr<AdaptiveCountermeasures> _adaptive_countermeasures;
    std::unique_ptr<CounterIntelligenceDashboard> _dashboard;

    // System state
    bool _initialized = false;
    bool _government_mode = false;
    bool _expert_mode = false;
    bool _emergency_mode = false;
    bool _automatic_response = true;

    // Hardware capabilities
    bool _gna_available = false;
    bool _npu_available = false;
    bool _openvino_available = false;
    bool _audio_available = false;

    // External system integration
    ContactObfuscator *_contact_obfuscator = nullptr;
    LocationRandomizer *_location_randomizer = nullptr;
    QuantumCryptoSystem *_quantum_crypto = nullptr;

    // System monitoring
    SystemMetrics _system_metrics;
    float _system_health = 1.0f;
    QList<ThreatAssessment> _threat_intelligence;

    // Configuration storage
    std::unique_ptr<QSettings> _settings;

    // System timers
    std::unique_ptr<QTimer> _health_check_timer;
    std::unique_ptr<QTimer> _metrics_update_timer;
    std::unique_ptr<QTimer> _optimization_timer;
    std::unique_ptr<QTimer> _intelligence_timer;

    // Performance tracking
    qint64 _initialization_time = 0;
    qint64 _last_health_check = 0;
    int _threat_count_last_minute = 0;
    int _total_threats_detected = 0;
    QList<qint64> _response_times;

    // Configuration keys
    static constexpr const char* CONFIG_GROUP_GENERAL = "CounterIntelligence/General";
    static constexpr const char* CONFIG_GROUP_HARDWARE = "CounterIntelligence/Hardware";
    static constexpr const char* CONFIG_GROUP_DETECTION = "CounterIntelligence/Detection";
    static constexpr const char* CONFIG_GROUP_COUNTERMEASURES = "CounterIntelligence/Countermeasures";

    // Default configuration values
    static constexpr float DEFAULT_SENSITIVITY = 0.7f;
    static constexpr int DEFAULT_MAX_INTENSITY = static_cast<int>(CountermeasureIntensity::Maximum);
    static constexpr bool DEFAULT_AUTOMATIC_RESPONSE = true;
    static constexpr bool DEFAULT_AUDIO_ANALYSIS = true;
    static constexpr bool DEFAULT_NETWORK_ANALYSIS = true;

    // Performance thresholds
    static constexpr float HEALTH_WARNING_THRESHOLD = 0.8f;
    static constexpr float HEALTH_CRITICAL_THRESHOLD = 0.6f;
    static constexpr float RESPONSE_TIME_WARNING_MS = 1000.0f;
    static constexpr float SYSTEM_LOAD_WARNING = 0.8f;

    // Timer intervals
    static constexpr int HEALTH_CHECK_INTERVAL_MS = 5000;    // 5 seconds
    static constexpr int METRICS_UPDATE_INTERVAL_MS = 2000;  // 2 seconds
    static constexpr int OPTIMIZATION_INTERVAL_MS = 30000;   // 30 seconds
    static constexpr int INTELLIGENCE_UPDATE_INTERVAL_MS = 10000; // 10 seconds

    // Threat intelligence parameters
    static constexpr int MAX_THREAT_INTELLIGENCE_SIZE = 500;
    static constexpr int THREAT_PATTERN_ANALYSIS_WINDOW = 100;
    static constexpr int MINUTES_FOR_RESPONSE_TIME_CALC = 5;
};

} // namespace SpyGram::Counterintelligence