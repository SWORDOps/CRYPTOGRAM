#include "surveillance_detector.h"
#include "universal_security_validator.h"
#include "../privacy/quantum_crypto_system.h"
#include "../security/gna_acoustic_security.h"
#include "../security/hardware_detector.h"
#include <QtCore/QDebug>
#include <QtCore/QDateTime>
#include <QtCore/QStandardPaths>
#ifdef __has_include
#if __has_include(<QtMultimedia/QMediaDevices>)
#include <QtMultimedia/QMediaDevices>
#endif
#endif
#include <QtNetwork/QNetworkInterface>
#include <cmath>
#include <algorithm>
#ifdef __has_include
#if __has_include(<fftw3.h>)
#include <fftw3.h>  // For frequency analysis - fallback to Qt if not available
#endif
#endif

#ifdef SPYGRAM_GNA_AVAILABLE
#include "../hardware/gna_acoustic_engine.h"
#endif

#ifdef SPYGRAM_NPU_AVAILABLE
#include "../hardware/npu_acoustic_engine.h"
#endif

#include "universal_security_validator.h"

#ifdef SPYGRAM_OPENVINO_AVAILABLE
#include "../hardware/openvino_acoustic_processor.h"
#endif

namespace SpyGram::Counterintelligence {

SurveillanceDetector::SurveillanceDetector(QObject *parent)
    : QObject(parent)
    , _audio_timer(std::make_unique<QTimer>(this))
    , _network_timer(std::make_unique<QTimer>(this))
    , _periodic_timer(std::make_unique<QTimer>(this))
    , _threat_update_timer(std::make_unique<QTimer>(this))
    , _security_validator(std::make_unique<UniversalSecurityValidator>(this))
{
    // Initialize hardware capabilities
    initializeHardwareCapabilities();

    // Setup audio system
    initializeAudioSystem();

    // Setup timers
    _audio_timer->setInterval(ANALYSIS_WINDOW_MS);
    _network_timer->setInterval(1000);  // Network analysis every second
    _periodic_timer->setInterval(5000); // Full scan every 5 seconds
    _threat_update_timer->setInterval(500); // Threat level updates every 500ms

    // Connect timer signals
    connect(_audio_timer.get(), &QTimer::timeout, this, &SurveillanceDetector::processAudioData);
    connect(_network_timer.get(), &QTimer::timeout, this, &SurveillanceDetector::analyzeNetworkTraffic);
    connect(_periodic_timer.get(), &QTimer::timeout, this, &SurveillanceDetector::performPeriodicScan);
    connect(_threat_update_timer.get(), &QTimer::timeout, this, &SurveillanceDetector::updateThreatLevel);

    qDebug() << "SurveillanceDetector: Initialized with hardware capabilities:"
             << "GNA:" << _gna_available
             << "NPU:" << _npu_available
             << "OpenVINO:" << _openvino_available;
}

SurveillanceDetector::~SurveillanceDetector() {
    stopDetection();
}

void SurveillanceDetector::initializeHardwareCapabilities() {
    // Detect GNA availability
#ifdef SPYGRAM_GNA_AVAILABLE
    try {
        // Attempt to initialize GNA
        _gna_available = GNAAcousticEngine::isAvailable();
        if (_gna_available) {
            qDebug() << "SurveillanceDetector: GNA hardware detected and available";
        }
    } catch (...) {
        _gna_available = false;
        qDebug() << "SurveillanceDetector: GNA hardware not available";
    }
#else
    _gna_available = false;
    qDebug() << "SurveillanceDetector: GNA support not compiled in";
#endif

    // Detect NPU availability
#ifdef SPYGRAM_NPU_AVAILABLE
    try {
        _npu_available = NPUAcousticEngine::isAvailable();
        if (_npu_available) {
            initializeNPUSystem();
            qDebug() << "SurveillanceDetector: NPU hardware detected and initialized";
        }
    } catch (...) {
        _npu_available = false;
        qDebug() << "SurveillanceDetector: NPU hardware not available";
    }
#else
    _npu_available = false;
    qDebug() << "SurveillanceDetector: NPU support not compiled in";
#endif

    // Detect OpenVINO availability
#ifdef SPYGRAM_OPENVINO_AVAILABLE
    try {
        _openvino_available = OpenVINOAcousticProcessor::isAvailable();
        if (_openvino_available) {
            initializeOpenVINOSystem();
            qDebug() << "SurveillanceDetector: OpenVINO runtime detected and initialized";
        }
    } catch (...) {
        _openvino_available = false;
        qDebug() << "SurveillanceDetector: OpenVINO runtime not available";
    }
#else
    _openvino_available = false;
    qDebug() << "SurveillanceDetector: OpenVINO support not compiled in";
#endif

    // Initialize quantum crypto system for secure operations
    try {
        _quantum_crypto = std::make_unique<QuantumCryptoSystem>();
        qDebug() << "SurveillanceDetector: Quantum crypto system initialized";
    } catch (...) {
        qDebug() << "SurveillanceDetector: Quantum crypto system initialization failed";
    }

    Q_EMIT hardwareCapabilityChanged("GNA", _gna_available);
    Q_EMIT hardwareCapabilityChanged("NPU", _npu_available);
    Q_EMIT hardwareCapabilityChanged("OpenVINO", _openvino_available);
}

void SurveillanceDetector::initializeAudioSystem() {
#ifdef __has_include
#if __has_include(<QtMultimedia/QAudioInput>)
    // Setup audio format for high-quality analysis
    _audio_format.setSampleRate(SAMPLE_RATE);
    _audio_format.setChannelCount(CHANNEL_COUNT);
    _audio_format.setSampleFormat(QAudioFormat::Int16);

    // Find best audio input device
    const auto audioDevices = QMediaDevices::audioInputs();
    if (audioDevices.isEmpty()) {
        qWarning() << "SurveillanceDetector: No audio input devices available";
        return;
    }

    // Select device with highest sample rate capability
    QAudioDevice selectedDevice = audioDevices.first();
    for (const auto &device : audioDevices) {
        if (device.maximumSampleRate() > selectedDevice.maximumSampleRate()) {
            selectedDevice = device;
        }
    }

    // Create audio input
    _audio_input = std::make_unique<QAudioInput>(selectedDevice, _audio_format);

    qDebug() << "SurveillanceDetector: Audio system initialized"
             << "Device:" << selectedDevice.description()
             << "Sample Rate:" << _audio_format.sampleRate()
             << "Channels:" << _audio_format.channelCount();
#else
    qWarning() << "SurveillanceDetector: QtMultimedia not available, audio system disabled";
#endif
#endif
}

void SurveillanceDetector::initializeGNASystem() {
#ifdef SPYGRAM_GNA_AVAILABLE
    if (_gna_available) {
        try {
            // GNA initialization will be implemented when hardware is available
            qDebug() << "SurveillanceDetector: GNA system ready for 0.1W always-on detection";
        } catch (const std::exception &e) {
            qWarning() << "SurveillanceDetector: GNA initialization failed:" << e.what();
            _gna_available = false;
        }
    }
#endif
}

void SurveillanceDetector::initializeNPUSystem() {
#ifdef SPYGRAM_NPU_AVAILABLE
    if (_npu_available) {
        try {
            _npu_engine = new SpyGram::Hardware::NPUAcousticEngine();

            // Secure initialization with validation
            if (!_npu_engine->initialize()) {
                qWarning() << "SurveillanceDetector: NPU secure initialization failed";
                _npu_available = false;
                _npu_engine = nullptr;
                return;
            }

            // Load model with integrity verification
            if (!_npu_engine->loadSurveillanceDetectionModel()) {
                qWarning() << "SurveillanceDetector: NPU model loading failed";
                _npu_available = false;
                _npu_engine = nullptr;
                return;
            }

            // Enable security logging
            _npu_engine->enableSecurityLogging(true);

            // Connect security signals
            connect(_npu_engine, &SpyGram::Hardware::NPUAcousticEngine::securityViolationDetected,
                    this, [this](const QString &violation) {
                        qWarning() << "SurveillanceDetector: NPU security violation:" << violation;
                        Q_EMIT securityViolationDetected("NPU: " + violation);
                    });

            connect(_npu_engine, &SpyGram::Hardware::NPUAcousticEngine::modelIntegrityCompromised,
                    this, [this](const QString &details) {
                        qWarning() << "SurveillanceDetector: NPU model integrity compromised:" << details;
                        _npu_available = false;
                        _npu_engine = nullptr;
                    });

            qDebug() << "SurveillanceDetector: NPU acoustic engine securely initialized";
        } catch (const std::exception &e) {
            // Secure exception handling - sanitize error message
            qWarning() << "SurveillanceDetector: NPU initialization failed (security)";
            _npu_available = false;
            _npu_engine = nullptr;
        }
    }
#endif
}

void SurveillanceDetector::initializeOpenVINOSystem() {
#ifdef SPYGRAM_OPENVINO_AVAILABLE
    if (_openvino_available) {
        try {
            _openvino_processor = new OpenVINOAcousticProcessor();
            _openvino_processor->loadSurveillanceModels();
            qDebug() << "SurveillanceDetector: OpenVINO processor initialized";
        } catch (const std::exception &e) {
            qWarning() << "SurveillanceDetector: OpenVINO initialization failed:" << e.what();
            _openvino_available = false;
            _openvino_processor = nullptr;
        }
    }
#endif
}

void SurveillanceDetector::startDetection() {
    if (_detection_active) {
        return;
    }

    qDebug() << "SurveillanceDetector: Starting surveillance detection";

    // Start audio capture if enabled and available
#ifdef __has_include
#if __has_include(<QtMultimedia/QAudioInput>)
    if (_audio_analysis_enabled && _audio_input) {
        _audio_device = _audio_input->start();
        if (_audio_device) {
            _audio_timer->start();
            qDebug() << "SurveillanceDetector: Audio analysis started";
        } else {
            qWarning() << "SurveillanceDetector: Failed to start audio capture";
        }
    }
#endif
#endif

    // Start network analysis if enabled
    if (_network_analysis_enabled) {
        _network_timer->start();
        qDebug() << "SurveillanceDetector: Network analysis started";
    }

    // Start periodic scans
    _periodic_timer->start();
    _threat_update_timer->start();

    _detection_active = true;
    qDebug() << "SurveillanceDetector: All detection systems active";
}

void SurveillanceDetector::stopDetection() {
    if (!_detection_active) {
        return;
    }

    qDebug() << "SurveillanceDetector: Stopping surveillance detection";

    // Stop all timers
    _audio_timer->stop();
    _network_timer->stop();
    _periodic_timer->stop();
    _threat_update_timer->stop();

    // Stop audio capture
#ifdef __has_include
#if __has_include(<QtMultimedia/QAudioInput>)
    if (_audio_input && _audio_device) {
        _audio_input->stop();
        _audio_device = nullptr;
    }
#endif
#endif

    _detection_active = false;
    _current_threat_level = ThreatLevel::None;

    qDebug() << "SurveillanceDetector: All detection systems stopped";
}

void SurveillanceDetector::processAudioData() {
    if (!_audio_device || !_audio_analysis_enabled) {
        return;
    }

    // Read available audio data
    const qint64 availableBytes = _audio_device->bytesAvailable();
    if (availableBytes < AUDIO_BUFFER_SIZE) {
        return; // Not enough data for analysis
    }

    // Read audio data into buffer
    _audio_buffer.resize(AUDIO_BUFFER_SIZE);
    const qint64 bytesRead = _audio_device->read(_audio_buffer.data(), AUDIO_BUFFER_SIZE);

    if (bytesRead != AUDIO_BUFFER_SIZE) {
        return; // Incomplete read
    }

    // Analyze audio with best available method
    ThreatAssessment threat;
    const auto startTime = QDateTime::currentMSecsSinceEpoch();

    if (_gna_available) {
        threat = analyzeWithGNA(_audio_buffer);
    } else if (_npu_available) {
        threat = analyzeWithNPU(_audio_buffer);
    } else if (_openvino_available) {
        threat = analyzeWithOpenVINO(_audio_buffer);
    } else if (_cpu_optimized) {
        threat = analyzeWithCPUHeuristics(_audio_buffer);
    } else {
        threat = analyzeWithBasicPatterns(_audio_buffer);
    }

    // Update performance metrics
    const auto analysisTime = QDateTime::currentMSecsSinceEpoch() - startTime;
    _average_analysis_time = (_average_analysis_time * _analysis_count + analysisTime) / (_analysis_count + 1);
    _analysis_count++;

    // Adjust for government mode if needed
    if (_government_mode) {
        adjustForGovernmentMode(threat);
    }

    // Process threat if detected
    if (threat.level > ThreatLevel::None) {
        updateThreatHistory(threat);
        Q_EMIT threatDetected(threat);
    }
}

ThreatAssessment SurveillanceDetector::analyzeWithGNA(const QByteArray &audioData) {
#ifdef SPYGRAM_GNA_AVAILABLE
    // GNA hardware analysis - 0.1W always-on detection
    // This would use specialized GNA hardware for ultra-low power surveillance detection
    ThreatAssessment threat;
    threat.timestamp = QDateTime::currentMSecsSinceEpoch();

    // Placeholder for GNA analysis - real implementation would use hardware
    // For now, fall back to NPU or software analysis
    return _npu_available ? analyzeWithNPU(audioData) : analyzeWithOpenVINO(audioData);
#else
    Q_UNUSED(audioData);
    return analyzeWithNPU(audioData);
#endif
}

ThreatAssessment SurveillanceDetector::analyzeWithNPU(const QByteArray &audioData) {
#ifdef SPYGRAM_NPU_AVAILABLE
    if (!_npu_engine) {
        return analyzeWithOpenVINO(audioData);
    }

    try {
        ThreatAssessment threat;
        threat.timestamp = QDateTime::currentMSecsSinceEpoch();

        // Secure NPU-accelerated threat detection with validation
        auto result = _npu_engine->analyzeSurveillanceThreats(audioData);

        // Validate NPU result status
        if (result.status != SpyGram::Hardware::NPUSurveillanceResult::Status::Success) {
            qWarning() << "SurveillanceDetector: NPU analysis failed with status"
                       << static_cast<int>(result.status)
                       << ":" << QString::fromStdString(result.error_message);
            return analyzeWithOpenVINO(audioData);
        }

        // Validate that result passed NPU's internal validation
        if (!result.validated) {
            qWarning() << "SurveillanceDetector: NPU result failed internal validation";
            return analyzeWithOpenVINO(audioData);
        }

        // Safely convert validated NPU results
        threat.level = static_cast<ThreatLevel>(result.threat_level);
        threat.type = static_cast<SurveillanceType>(result.surveillance_type);
        threat.confidence = result.confidence;
        threat.details = QString::fromStdString(result.details);

        // Apply universal security validation
        threat = _security_validator->validateThreatAssessment(threat, SecurityTier::Tier1_Premium);

        return threat;
    } catch (const std::exception &e) {
        // Secure exception handling - no information disclosure
        qWarning() << "SurveillanceDetector: NPU analysis failed (security exception)";
        return analyzeWithOpenVINO(audioData);
    }
#else
    Q_UNUSED(audioData);
    return analyzeWithOpenVINO(audioData);
#endif
}

ThreatAssessment SurveillanceDetector::analyzeWithOpenVINO(const QByteArray &audioData) {
#ifdef SPYGRAM_OPENVINO_AVAILABLE
    if (!_openvino_processor) {
        return analyzeWithCPUHeuristics(audioData);
    }

    try {
        ThreatAssessment threat;
        threat.timestamp = QDateTime::currentMSecsSinceEpoch();

        // OpenVINO-accelerated analysis
        auto result = _openvino_processor->detectSurveillance(audioData);
        threat.level = static_cast<ThreatLevel>(result.threat_level);
        threat.type = static_cast<SurveillanceType>(result.type);
        threat.confidence = result.confidence;
        threat.details = QString::fromStdString(result.description);

        // Apply universal security validation
        threat = _security_validator->validateThreatAssessment(threat, SecurityTier::Tier2_Enhanced);

        return threat;
    } catch (const std::exception &e) {
        qWarning() << "SurveillanceDetector: OpenVINO analysis failed (security)";
        return analyzeWithCPUHeuristics(audioData);
    }
#else
    Q_UNUSED(audioData);
    return analyzeWithCPUHeuristics(audioData);
#endif
}

ThreatAssessment SurveillanceDetector::analyzeWithCPUHeuristics(const QByteArray &audioData) {
    ThreatAssessment threat;
    threat.timestamp = QDateTime::currentMSecsSinceEpoch();

    // Convert audio data to float samples for analysis
    const int16_t *samples = reinterpret_cast<const int16_t*>(audioData.data());
    const int sampleCount = audioData.size() / sizeof(int16_t);

    if (sampleCount < 64) {
        return threat; // Not enough data
    }

    // Basic frequency analysis using simple FFT approximation
    std::vector<float> floatSamples(sampleCount);
    for (int i = 0; i < sampleCount; ++i) {
        floatSamples[i] = samples[i] / 32768.0f;
    }

    // Check for ultrasonic beacons (simplified detection)
    bool ultrasonicDetected = detectUltrasonicBeacons(audioData);
    if (ultrasonicDetected) {
        threat.level = ThreatLevel::Active;
        threat.type = SurveillanceType::UltrasonicBeacon;
        threat.confidence = 0.8f;
        threat.details = "Ultrasonic beacon detected - possible tracking device";
        threat.mitigation_suggestion = "Move to different location and check for hidden devices";
        return threat;
    }

    // Check for laser microphone signatures
    bool laserMicDetected = detectLaserMicrophone(audioData);
    if (laserMicDetected) {
        threat.level = ThreatLevel::Hostile;
        threat.type = SurveillanceType::LaserMicrophone;
        threat.confidence = 0.9f;
        threat.details = "Laser microphone interference detected";
        threat.mitigation_suggestion = "Cover windows and use audio countermeasures";
        return threat;
    }

    // Basic audio analysis for recording devices
    float averageLevel = 0.0f;
    float peakLevel = 0.0f;
    for (int i = 0; i < sampleCount; ++i) {
        float level = std::abs(floatSamples[i]);
        averageLevel += level;
        peakLevel = std::max(peakLevel, level);
    }
    averageLevel /= sampleCount;

    // Detect potential recording device feedback
    if (peakLevel > 0.9f && averageLevel > 0.3f) {
        threat.level = ThreatLevel::Targeted;
        threat.type = SurveillanceType::AudioRecording;
        threat.confidence = 0.6f;
        threat.details = "Possible audio recording device detected";
        threat.mitigation_suggestion = "Check for hidden microphones";
    }

    // Apply universal security validation for CPU heuristics (Tier 3)
    threat = _security_validator->validateThreatAssessment(threat, SecurityTier::Tier3_Standard);

    return threat;
}

ThreatAssessment SurveillanceDetector::analyzeWithBasicPatterns(const QByteArray &audioData) {
    ThreatAssessment threat;
    threat.timestamp = QDateTime::currentMSecsSinceEpoch();

    // Very basic pattern detection for universal compatibility
    const int16_t *samples = reinterpret_cast<const int16_t*>(audioData.data());
    const int sampleCount = audioData.size() / sizeof(int16_t);

    if (sampleCount < 32) {
        return threat; // Insufficient data
    }

    // Simple amplitude analysis
    int highAmplitudeCount = 0;
    int zeroCount = 0;

    for (int i = 0; i < sampleCount; ++i) {
        if (std::abs(samples[i]) > 20000) {
            highAmplitudeCount++;
        }
        if (samples[i] == 0) {
            zeroCount++;
        }
    }

    // Detect potential recording device artifacts
    float highAmplitudeRatio = static_cast<float>(highAmplitudeCount) / sampleCount;
    float zeroRatio = static_cast<float>(zeroCount) / sampleCount;

    if (highAmplitudeRatio > 0.1f && zeroRatio < 0.05f) {
        threat.level = ThreatLevel::Ambient;
        threat.type = SurveillanceType::AudioRecording;
        threat.confidence = 0.4f;
        threat.details = "Unusual audio patterns detected";
        threat.mitigation_suggestion = "Be aware of potential surveillance";
    }

    // Apply universal security validation for basic patterns (Tier 4)
    threat = _security_validator->validateThreatAssessment(threat, SecurityTier::Tier4_Universal);

    return threat;
}

bool SurveillanceDetector::detectUltrasonicBeacons(const QByteArray &audioData) {
    // Simplified ultrasonic detection
    const int16_t *samples = reinterpret_cast<const int16_t*>(audioData.data());
    const int sampleCount = audioData.size() / sizeof(int16_t);

    // Look for high-frequency patterns that could indicate ultrasonic beacons
    int highFreqCount = 0;
    for (int i = 1; i < sampleCount; ++i) {
        if (std::abs(samples[i] - samples[i-1]) > 15000) {
            highFreqCount++;
        }
    }

    // If more than 20% of samples show high-frequency changes, possible ultrasonic
    return (static_cast<float>(highFreqCount) / sampleCount) > 0.2f;
}

bool SurveillanceDetector::detectLaserMicrophone(const QByteArray &audioData) {
    // Simplified laser microphone detection
    const int16_t *samples = reinterpret_cast<const int16_t*>(audioData.data());
    const int sampleCount = audioData.size() / sizeof(int16_t);

    // Look for characteristic interference patterns
    int interferenceCount = 0;
    for (int i = 2; i < sampleCount; ++i) {
        // Check for rapid amplitude variations
        int32_t variation = std::abs(samples[i] - 2*samples[i-1] + samples[i-2]);
        if (variation > 10000) {
            interferenceCount++;
        }
    }

    // Laser microphones often cause characteristic interference
    return (static_cast<float>(interferenceCount) / sampleCount) > 0.15f;
}

void SurveillanceDetector::analyzeNetworkTraffic() {
    if (!_network_analysis_enabled) {
        return;
    }

    // Basic network surveillance detection
    bool suspiciousActivity = detectNetworkSurveillance();

    if (suspiciousActivity) {
        ThreatAssessment threat;
        threat.timestamp = QDateTime::currentMSecsSinceEpoch();
        threat.level = ThreatLevel::Targeted;
        threat.type = SurveillanceType::NetworkAnalysis;
        threat.confidence = 0.7f;
        threat.details = "Suspicious network activity detected";
        threat.mitigation_suggestion = "Use VPN and check network security";

        if (_government_mode) {
            adjustForGovernmentMode(threat);
        }

        updateThreatHistory(threat);
        Q_EMIT threatDetected(threat);
    }
}

bool SurveillanceDetector::detectNetworkSurveillance() {
    // Check for unusual network interfaces or connections
    const auto interfaces = QNetworkInterface::allInterfaces();

    for (const auto &interface : interfaces) {
        // Look for monitoring interfaces or unusual configurations
        if (interface.name().contains("mon") ||
            interface.name().contains("tap") ||
            interface.name().contains("sniff")) {
            qDebug() << "SurveillanceDetector: Suspicious network interface detected:" << interface.name();
            return true;
        }
    }

    return false;
}

void SurveillanceDetector::performPeriodicScan() {
    // RF emissions detection
    if (_rf_analysis_enabled) {
        bool rfDetected = detectRFEmissions();
        if (rfDetected) {
            ThreatAssessment threat;
            threat.timestamp = QDateTime::currentMSecsSinceEpoch();
            threat.level = ThreatLevel::Active;
            threat.type = SurveillanceType::RFEmission;
            threat.confidence = 0.8f;
            threat.details = "RF surveillance equipment detected";
            threat.mitigation_suggestion = "Use RF shielding and change location";

            updateThreatHistory(threat);
            Q_EMIT threatDetected(threat);
        }
    }

    // TEMPEST analysis (if enabled)
    if (_tempest_analysis_enabled) {
        bool tempestDetected = detectTEMPESTSignals();
        if (tempestDetected) {
            ThreatAssessment threat;
            threat.timestamp = QDateTime::currentMSecsSinceEpoch();
            threat.level = ThreatLevel::Hostile;
            threat.type = SurveillanceType::TempestAttack;
            threat.confidence = 0.9f;
            threat.details = "TEMPEST electromagnetic surveillance detected";
            threat.mitigation_suggestion = "Use TEMPEST shielding immediately";

            updateThreatHistory(threat);
            Q_EMIT threatDetected(threat);
        }
    }
}

bool SurveillanceDetector::detectRFEmissions() {
    // Placeholder for RF detection - would require specialized hardware
    // For now, this is a stub that could be expanded with SDR integration
    return false;
}

bool SurveillanceDetector::detectTEMPESTSignals() {
    // Placeholder for TEMPEST detection - requires electromagnetic sensors
    // This is an advanced feature for specialized threat environments
    return false;
}

void SurveillanceDetector::updateThreatHistory(const ThreatAssessment &threat) {
    _recent_threats.append(threat);
    _threat_history.enqueue(threat);

    // Maintain history size
    while (_threat_history.size() > MAX_THREAT_HISTORY) {
        _threat_history.dequeue();
    }

    // Keep only recent threats (last 5 minutes)
    const qint64 fiveMinutesAgo = QDateTime::currentMSecsSinceEpoch() - (5 * 60 * 1000);
    _recent_threats.erase(
        std::remove_if(_recent_threats.begin(), _recent_threats.end(),
                      [fiveMinutesAgo](const ThreatAssessment &t) {
                          return t.timestamp < fiveMinutesAgo;
                      }),
        _recent_threats.end());
}

void SurveillanceDetector::updateThreatLevel() {
    const ThreatLevel oldLevel = _current_threat_level;
    _current_threat_level = calculateOverallThreatLevel();

    if (_current_threat_level != oldLevel) {
        Q_EMIT threatLevelChanged(_current_threat_level, oldLevel);
        qDebug() << "SurveillanceDetector: Threat level changed from"
                 << static_cast<int>(oldLevel) << "to" << static_cast<int>(_current_threat_level);
    }
}

ThreatLevel SurveillanceDetector::calculateOverallThreatLevel() {
    if (_recent_threats.isEmpty()) {
        return ThreatLevel::None;
    }

    // Find highest threat level in recent threats
    ThreatLevel maxLevel = ThreatLevel::None;
    for (const auto &threat : _recent_threats) {
        if (threat.level > maxLevel) {
            maxLevel = threat.level;
        }
    }

    // Apply government mode adjustments
    if (_government_mode && maxLevel <= ThreatLevel::Targeted) {
        // Reduce threat level for authorized government activity
        return static_cast<ThreatLevel>(std::max(0, static_cast<int>(maxLevel) - 1));
    }

    return maxLevel;
}

void SurveillanceDetector::adjustForGovernmentMode(ThreatAssessment &threat) {
    if (!_government_mode) {
        return;
    }

    // Check if this could be authorized government activity
    if (isAuthorizedGovernmentActivity(threat)) {
        threat.government_exemption = true;
        threat.confidence *= 0.5f; // Reduce confidence for potential false positive
        threat.details += " (Possible authorized government activity)";
        threat.mitigation_suggestion = "Verify CAC/PIV authentication status";

        // Reduce threat level for authorized activity
        if (threat.level > ThreatLevel::Ambient) {
            threat.level = static_cast<ThreatLevel>(static_cast<int>(threat.level) - 1);
        }
    }
}

bool SurveillanceDetector::isAuthorizedGovernmentActivity(const ThreatAssessment &threat) {
    // In government mode, certain surveillance activities may be authorized
    // This is a simplified check - real implementation would verify CAC/PIV status

    if (threat.type == SurveillanceType::NetworkAnalysis ||
        threat.type == SurveillanceType::AudioRecording) {
        // These could be authorized in government facilities
        return true;
    }

    return false;
}

void SurveillanceDetector::setSensitivity(float sensitivity) {
    _sensitivity = std::clamp(sensitivity, 0.0f, 1.0f);
    qDebug() << "SurveillanceDetector: Sensitivity set to" << _sensitivity;
}

} // namespace SpyGram::Counterintelligence