#pragma once

#include <QtCore/QObject>
#include <QtCore/QTimer>
#include <QtCore/QQueue>
#ifdef __has_include
#if __has_include(<QtMultimedia/QAudioInput>)
#include <QtMultimedia/QAudioInput>
#include <QtMultimedia/QAudioFormat>
#endif
#endif
#include <memory>
#include <array>

// Forward declarations for optional hardware acceleration
class NPUAcousticEngine;
class OpenVINOAcousticProcessor;
class QuantumCryptoSystem;
namespace SpyGram::Counterintelligence { class UniversalSecurityValidator; }

namespace SpyGram::Counterintelligence {

enum class ThreatLevel {
    None = 0,           // No surveillance detected
    Ambient = 1,        // Background surveillance possible
    Targeted = 2,       // Directed surveillance likely
    Active = 3,         // Active surveillance confirmed
    Hostile = 4         // Hostile surveillance with immediate countermeasures required
};

enum class SurveillanceType {
    Unknown,
    AudioRecording,     // Microphone/recording device detected
    LaserMicrophone,    // Laser-based audio surveillance
    RFEmission,         // RF-based surveillance equipment
    UltrasonicBeacon,   // Ultrasonic tracking beacons
    NetworkAnalysis,    // Network traffic surveillance
    VisualSurveillance, // Camera/visual monitoring
    TempestAttack      // TEMPEST/electromagnetic surveillance
};

struct ThreatAssessment {
    ThreatLevel level = ThreatLevel::None;
    SurveillanceType type = SurveillanceType::Unknown;
    float confidence = 0.0f;          // 0.0-1.0 confidence score
    QString details;                  // Human-readable threat description
    qint64 timestamp = 0;            // When threat was detected
    QString mitigation_suggestion;    // Recommended user action
    bool government_exemption = false; // True if CAC/PIV detected - reduce countermeasures
};

/**
 * @brief Universal Surveillance Detection System
 *
 * Implements comprehensive surveillance detection with graceful fallback:
 * - GNA Hardware: 0.1W always-on acoustic analysis (when available)
 * - NPU Acceleration: Intel NPU + OpenVINO processing
 * - OpenVINO CPU/GPU: Software acceleration on standard hardware
 * - CPU Heuristics: Pattern-based detection on any hardware
 * - Basic Analysis: Rule-based detection for universal compatibility
 */
class SurveillanceDetector : public QObject {
    Q_OBJECT

public:
    explicit SurveillanceDetector(QObject *parent = nullptr);
    ~SurveillanceDetector();

    // Core detection interface
    void startDetection();
    void stopDetection();
    bool isDetectionActive() const { return _detection_active; }

    // Hardware capability management
    void setGNAAvailable(bool available) { _gna_available = available; }
    void setNPUAvailable(bool available) { _npu_available = available; }
    void setOpenVINOAvailable(bool available) { _openvino_available = available; }

    // Government mode (CAC/PIV detected)
    void setGovernmentMode(bool enabled) { _government_mode = enabled; }
    bool isGovernmentMode() const { return _government_mode; }

    // Threat assessment
    ThreatLevel getCurrentThreatLevel() const { return _current_threat_level; }
    QList<ThreatAssessment> getRecentThreats() const { return _recent_threats; }

    // Configuration
    void setSensitivity(float sensitivity); // 0.0-1.0 (higher = more sensitive)
    void setAudioAnalysisEnabled(bool enabled) { _audio_analysis_enabled = enabled; }
    void setNetworkAnalysisEnabled(bool enabled) { _network_analysis_enabled = enabled; }

Q_SIGNALS:
    void threatDetected(const ThreatAssessment &threat);
    void threatLevelChanged(ThreatLevel newLevel, ThreatLevel oldLevel);
    void hardwareCapabilityChanged(const QString &component, bool available);
    void securityViolationDetected(const QString &violation);

private Q_SLOTS:
    void processAudioData();
    void analyzeNetworkTraffic();
    void performPeriodicScan();
    void updateThreatLevel();

private:
    // Hardware detection and initialization
    void initializeHardwareCapabilities();
    void initializeAudioSystem();
    void initializeGNASystem();
    void initializeNPUSystem();
    void initializeOpenVINOSystem();

    // Multi-tier detection algorithms
    ThreatAssessment analyzeWithGNA(const QByteArray &audioData);
    ThreatAssessment analyzeWithNPU(const QByteArray &audioData);
    ThreatAssessment analyzeWithOpenVINO(const QByteArray &audioData);
    ThreatAssessment analyzeWithCPUHeuristics(const QByteArray &audioData);
    ThreatAssessment analyzeWithBasicPatterns(const QByteArray &audioData);

    // Specialized detection methods
    bool detectLaserMicrophone(const QByteArray &audioData);
    bool detectUltrasonicBeacons(const QByteArray &audioData);
    bool detectRFEmissions();
    bool detectNetworkSurveillance();
    bool detectTEMPESTSignals();

    // Threat correlation and fusion
    void correlateThreats();
    void updateThreatHistory(const ThreatAssessment &threat);
    ThreatLevel calculateOverallThreatLevel();

    // Government mode handling
    void adjustForGovernmentMode(ThreatAssessment &threat);
    bool isAuthorizedGovernmentActivity(const ThreatAssessment &threat);

    // Audio processing
#ifdef __has_include
#if __has_include(<QtMultimedia/QAudioInput>)
    std::unique_ptr<QAudioInput> _audio_input;
    QAudioFormat _audio_format;
#endif
#endif
    QIODevice *_audio_device = nullptr;
    QByteArray _audio_buffer;
    static constexpr int AUDIO_BUFFER_SIZE = 4096;

    // Hardware acceleration systems
    NPUAcousticEngine *_npu_engine = nullptr;
    OpenVINOAcousticProcessor *_openvino_processor = nullptr;
    std::unique_ptr<QuantumCryptoSystem> _quantum_crypto;

    // Security validation system
    std::unique_ptr<UniversalSecurityValidator> _security_validator;

    // Hardware availability flags
    bool _gna_available = false;
    bool _npu_available = false;
    bool _openvino_available = false;
    bool _cpu_optimized = true;  // Always available

    // Detection state
    bool _detection_active = false;
    bool _government_mode = false;
    ThreatLevel _current_threat_level = ThreatLevel::None;
    float _sensitivity = 0.7f;  // Default medium sensitivity

    // Feature toggles
    bool _audio_analysis_enabled = true;
    bool _network_analysis_enabled = true;
    bool _rf_analysis_enabled = true;
    bool _tempest_analysis_enabled = false; // Advanced feature

    // Threat tracking
    QList<ThreatAssessment> _recent_threats;
    QQueue<ThreatAssessment> _threat_history;
    static constexpr int MAX_THREAT_HISTORY = 100;

    // Timers for continuous monitoring
    std::unique_ptr<QTimer> _audio_timer;
    std::unique_ptr<QTimer> _network_timer;
    std::unique_ptr<QTimer> _periodic_timer;
    std::unique_ptr<QTimer> _threat_update_timer;

    // Performance optimization
    qint64 _last_analysis_time = 0;
    int _analysis_count = 0;
    float _average_analysis_time = 0.0f;

    // Audio analysis parameters
    static constexpr int SAMPLE_RATE = 44100;
    static constexpr int SAMPLE_SIZE = 16;
    static constexpr int CHANNEL_COUNT = 1;
    static constexpr int ANALYSIS_WINDOW_MS = 100;

    // Frequency analysis ranges
    static constexpr float ULTRASONIC_LOW_FREQ = 18000.0f;   // 18kHz+
    static constexpr float ULTRASONIC_HIGH_FREQ = 25000.0f;  // Up to 25kHz
    static constexpr float LASER_MIC_FREQ_LOW = 1000.0f;     // Typical laser mic range
    static constexpr float LASER_MIC_FREQ_HIGH = 8000.0f;    // Human voice range
};

} // namespace SpyGram::Counterintelligence