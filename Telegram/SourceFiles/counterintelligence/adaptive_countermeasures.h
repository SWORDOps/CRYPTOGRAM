#pragma once

#include "surveillance_detector.h"
#include <QtCore/QObject>
#include <QtCore/QTimer>
#ifdef __has_include
#if __has_include(<QtMultimedia/QAudioOutput>)
#include <QtMultimedia/QAudioOutput>
#endif
#endif
#include <memory>

namespace SpyGram::Counterintelligence {

enum class CountermeasureType {
    None,
    AudioNoise,           // White/pink noise generation
    UltrasonicJamming,    // Ultrasonic interference
    PrivacyEnhancement,   // Enhanced privacy settings
    NetworkObfuscation,   // Network traffic masking
    VisualScrambling,     // Display interference
    CommunicationHiding,  // Message steganography
    EmergencyMode         // Maximum protection mode
};

enum class CountermeasureIntensity {
    Minimal = 1,    // Subtle countermeasures
    Moderate = 2,   // Balanced protection
    Aggressive = 3, // Strong countermeasures
    Maximum = 4     // All available countermeasures
};

struct CountermeasureStatus {
    CountermeasureType type = CountermeasureType::None;
    CountermeasureIntensity intensity = CountermeasureIntensity::Minimal;
    bool active = false;
    float effectiveness = 0.0f;     // Estimated effectiveness (0.0-1.0)
    QString description;
    qint64 activated_time = 0;
    bool government_compatible = true; // Safe for government mode
};

/**
 * @brief Adaptive Countermeasures System
 *
 * Implements dynamic threat response with privacy enhancement scaling:
 * - Real-time threat assessment integration
 * - Hardware-appropriate countermeasure deployment
 * - Government mode compatibility (CAC/PIV preservation)
 * - Universal fallback system for all hardware tiers
 * - Adaptive intensity based on threat level and environment
 */
class AdaptiveCountermeasures : public QObject {
    Q_OBJECT

public:
    explicit AdaptiveCountermeasures(QObject *parent = nullptr);
    ~AdaptiveCountermeasures();

    // Core countermeasure interface
    void startCountermeasures();
    void stopCountermeasures();
    bool isActive() const { return _active; }

    // Threat response integration
    void respondToThreat(const ThreatAssessment &threat);
    void setThreatLevel(ThreatLevel level);

    // Configuration
    void setMaxIntensity(CountermeasureIntensity max) { _max_intensity = max; }
    void setGovernmentMode(bool enabled) { _government_mode = enabled; }
    void setAutomaticResponse(bool enabled) { _automatic_response = enabled; }

    // Hardware capabilities
    void setGNAAvailable(bool available) { _gna_available = available; }
    void setNPUAvailable(bool available) { _npu_available = available; }
    void setAudioOutputAvailable(bool available) { _audio_output_available = available; }

    // Manual countermeasure control
    void activateCountermeasure(CountermeasureType type, CountermeasureIntensity intensity);
    void deactivateCountermeasure(CountermeasureType type);
    void activateEmergencyMode();
    void deactivateEmergencyMode();

    // Status queries
    QList<CountermeasureStatus> getActiveCountermeasures() const { return _active_countermeasures; }
    CountermeasureIntensity getCurrentIntensity() const { return _current_intensity; }
    bool isEmergencyModeActive() const { return _emergency_mode; }

Q_SIGNALS:
    void countermeasureActivated(CountermeasureType type, CountermeasureIntensity intensity);
    void countermeasureDeactivated(CountermeasureType type);
    void emergencyModeActivated();
    void emergencyModeDeactivated();
    void intensityChanged(CountermeasureIntensity newIntensity, CountermeasureIntensity oldIntensity);

private Q_SLOTS:
    void updateCountermeasures();
    void generateAudioNoise();
    void updatePrivacySettings();
    void obfuscateNetworkTraffic();

private:
    // Initialization
    void initializeAudioSystem();
    void initializeHardwareCapabilities();

    // Threat assessment and response
    CountermeasureIntensity calculateRequiredIntensity(const ThreatAssessment &threat);
    QList<CountermeasureType> selectCountermeasures(ThreatLevel threatLevel, CountermeasureIntensity intensity);
    void deployCountermeasures(const QList<CountermeasureType> &measures, CountermeasureIntensity intensity);

    // Specific countermeasure implementations
    void activateAudioNoise(CountermeasureIntensity intensity);
    void activateUltrasonicJamming(CountermeasureIntensity intensity);
    void activatePrivacyEnhancement(CountermeasureIntensity intensity);
    void activateNetworkObfuscation(CountermeasureIntensity intensity);
    void activateVisualScrambling(CountermeasureIntensity intensity);
    void activateCommunicationHiding(CountermeasureIntensity intensity);

    void deactivateAudioNoise();
    void deactivateUltrasonicJamming();
    void deactivatePrivacyEnhancement();
    void deactivateNetworkObfuscation();
    void deactivateVisualScrambling();
    void deactivateCommunicationHiding();

    // Audio countermeasures
    void generateWhiteNoise(float amplitude);
    void generatePinkNoise(float amplitude);
    void generateUltrasonicInterference(float frequency, float amplitude);

    // Privacy enhancement
    void enhanceContactObfuscation(CountermeasureIntensity intensity);
    void enhanceLocationRandomization(CountermeasureIntensity intensity);
    void enhanceMetadataProtection(CountermeasureIntensity intensity);

    // Network obfuscation
    void activateDummyTraffic(CountermeasureIntensity intensity);
    void activateTrafficPadding(CountermeasureIntensity intensity);
    void activateTimingObfuscation(CountermeasureIntensity intensity);

    // Government mode handling
    bool isCountermeasureGovernmentCompatible(CountermeasureType type);
    void adjustForGovernmentMode(CountermeasureStatus &status);

    // Effectiveness assessment
    float assessCountermeasureEffectiveness(CountermeasureType type, const ThreatAssessment &threat);
    void updateEffectivenessMetrics();

    // System state
    bool _active = false;
    bool _government_mode = false;
    bool _automatic_response = true;
    bool _emergency_mode = false;

    // Hardware capabilities
    bool _gna_available = false;
    bool _npu_available = false;
    bool _audio_output_available = false;

    // Current configuration
    ThreatLevel _current_threat_level = ThreatLevel::None;
    CountermeasureIntensity _current_intensity = CountermeasureIntensity::Minimal;
    CountermeasureIntensity _max_intensity = CountermeasureIntensity::Maximum;

    // Active countermeasures
    QList<CountermeasureStatus> _active_countermeasures;
    QHash<CountermeasureType, CountermeasureStatus> _countermeasure_status;

    // Audio system for countermeasures
#ifdef __has_include
#if __has_include(<QtMultimedia/QAudioOutput>)
    std::unique_ptr<QAudioOutput> _audio_output;
#endif
#endif
    QIODevice *_audio_device = nullptr;
    QByteArray _noise_buffer;

    // Timers
    std::unique_ptr<QTimer> _update_timer;
    std::unique_ptr<QTimer> _audio_noise_timer;
    std::unique_ptr<QTimer> _network_timer;
    std::unique_ptr<QTimer> _privacy_timer;

    // Audio parameters
    static constexpr int NOISE_SAMPLE_RATE = 44100;
    static constexpr int NOISE_BUFFER_SIZE = 4096;
    static constexpr float ULTRASONIC_BASE_FREQ = 19000.0f;
    static constexpr float ULTRASONIC_MAX_FREQ = 23000.0f;

    // Privacy enhancement levels
    static constexpr float MINIMAL_OBFUSCATION = 0.3f;
    static constexpr float MODERATE_OBFUSCATION = 0.6f;
    static constexpr float AGGRESSIVE_OBFUSCATION = 0.8f;
    static constexpr float MAXIMUM_OBFUSCATION = 1.0f;

    // Network timing parameters
    static constexpr int DUMMY_TRAFFIC_MIN_INTERVAL = 100;  // ms
    static constexpr int DUMMY_TRAFFIC_MAX_INTERVAL = 1000; // ms
    static constexpr int PADDING_MIN_SIZE = 64;             // bytes
    static constexpr int PADDING_MAX_SIZE = 1024;           // bytes

    // Recent threat history for adaptive response
    QList<ThreatAssessment> _recent_threats;
    qint64 _last_threat_time = 0;
    int _threat_escalation_count = 0;

    // Performance metrics
    QHash<CountermeasureType, float> _effectiveness_history;
    QHash<CountermeasureType, int> _activation_count;
    qint64 _total_active_time = 0;
};

} // namespace SpyGram::Counterintelligence