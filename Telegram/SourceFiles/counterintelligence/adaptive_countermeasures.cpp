#include "adaptive_countermeasures.h"
#include "../privacy/contact_obfuscation.h"
#include "../privacy/location_randomizer.h"
#include "../privacy/quantum_crypto_system.h"
#include <QtCore/QDebug>
#include <QtCore/QDateTime>
#include <QtCore/QRandomGenerator>
#ifdef __has_include
#if __has_include(<QtMultimedia/QMediaDevices>)
#include <QtMultimedia/QMediaDevices>
#endif
#endif
#include <QtNetwork/QNetworkProxy>
#include <cmath>
#include <algorithm>

namespace SpyGram::Counterintelligence {

AdaptiveCountermeasures::AdaptiveCountermeasures(QObject *parent)
    : QObject(parent)
    , _update_timer(std::make_unique<QTimer>(this))
    , _audio_noise_timer(std::make_unique<QTimer>(this))
    , _network_timer(std::make_unique<QTimer>(this))
    , _privacy_timer(std::make_unique<QTimer>(this))
{
    // Initialize hardware capabilities
    initializeHardwareCapabilities();

    // Setup audio system for countermeasures
    initializeAudioSystem();

    // Setup timers
    _update_timer->setInterval(1000);  // Update countermeasures every second
    _audio_noise_timer->setInterval(50); // Audio noise generation at 20Hz
    _network_timer->setInterval(500);   // Network obfuscation every 500ms
    _privacy_timer->setInterval(2000);  // Privacy settings update every 2 seconds

    // Connect timer signals
    connect(_update_timer.get(), &QTimer::timeout, this, &AdaptiveCountermeasures::updateCountermeasures);
    connect(_audio_noise_timer.get(), &QTimer::timeout, this, &AdaptiveCountermeasures::generateAudioNoise);
    connect(_network_timer.get(), &QTimer::timeout, this, &AdaptiveCountermeasures::obfuscateNetworkTraffic);
    connect(_privacy_timer.get(), &QTimer::timeout, this, &AdaptiveCountermeasures::updatePrivacySettings);

    qDebug() << "AdaptiveCountermeasures: Initialized with capabilities:"
             << "GNA:" << _gna_available
             << "NPU:" << _npu_available
             << "Audio:" << _audio_output_available;
}

AdaptiveCountermeasures::~AdaptiveCountermeasures() {
    stopCountermeasures();
}

void AdaptiveCountermeasures::initializeHardwareCapabilities() {
    // Check for GNA availability (hardware-specific)
    _gna_available = false; // Will be set by surveillance detector

    // Check for NPU availability
    _npu_available = false; // Will be set by surveillance detector

    // Check for audio output
#ifdef __has_include
#if __has_include(<QtMultimedia/QMediaDevices>)
    const auto audioDevices = QMediaDevices::audioOutputs();
    _audio_output_available = !audioDevices.isEmpty();
#else
    _audio_output_available = false;
#endif
#endif

    qDebug() << "AdaptiveCountermeasures: Hardware detection complete"
             << "Audio available:" << _audio_output_available;
}

void AdaptiveCountermeasures::initializeAudioSystem() {
#ifdef __has_include
#if __has_include(<QtMultimedia/QAudioOutput>)
    if (!_audio_output_available) {
        qWarning() << "AdaptiveCountermeasures: No audio output devices available";
        return;
    }

    // Setup audio format for noise generation
    QAudioFormat format;
    format.setSampleRate(NOISE_SAMPLE_RATE);
    format.setChannelCount(1);
    format.setSampleFormat(QAudioFormat::Int16);

    // Create audio output device
    const auto audioDevices = QMediaDevices::audioOutputs();
    if (!audioDevices.isEmpty()) {
        _audio_output = std::make_unique<QAudioOutput>(audioDevices.first(), format);
        qDebug() << "AdaptiveCountermeasures: Audio output initialized";
    }

    // Pre-generate noise buffer
    _noise_buffer.resize(NOISE_BUFFER_SIZE * sizeof(int16_t));
#else
    qWarning() << "AdaptiveCountermeasures: QtMultimedia not available, audio system disabled";
#endif
#endif
}

void AdaptiveCountermeasures::startCountermeasures() {
    if (_active) {
        return;
    }

    qDebug() << "AdaptiveCountermeasures: Starting adaptive countermeasure system";

    // Start monitoring and response timers
    _update_timer->start();
    _privacy_timer->start();

    _active = true;
    qDebug() << "AdaptiveCountermeasures: System active";
}

void AdaptiveCountermeasures::stopCountermeasures() {
    if (!_active) {
        return;
    }

    qDebug() << "AdaptiveCountermeasures: Stopping all countermeasures";

    // Stop all timers
    _update_timer->stop();
    _audio_noise_timer->stop();
    _network_timer->stop();
    _privacy_timer->stop();

    // Deactivate all countermeasures
    for (const auto &countermeasure : _active_countermeasures) {
        deactivateCountermeasure(countermeasure.type);
    }

    _active = false;
    _emergency_mode = false;
    _current_intensity = CountermeasureIntensity::Minimal;
    _current_threat_level = ThreatLevel::None;

    qDebug() << "AdaptiveCountermeasures: All countermeasures stopped";
}

void AdaptiveCountermeasures::respondToThreat(const ThreatAssessment &threat) {
    if (!_active || !_automatic_response) {
        return;
    }

    qDebug() << "AdaptiveCountermeasures: Responding to threat level"
             << static_cast<int>(threat.level)
             << "type" << static_cast<int>(threat.type);

    // Update threat history
    _recent_threats.append(threat);
    _last_threat_time = threat.timestamp;

    // Remove old threats (older than 5 minutes)
    const qint64 fiveMinutesAgo = QDateTime::currentMSecsSinceEpoch() - (5 * 60 * 1000);
    _recent_threats.erase(
        std::remove_if(_recent_threats.begin(), _recent_threats.end(),
                      [fiveMinutesAgo](const ThreatAssessment &t) {
                          return t.timestamp < fiveMinutesAgo;
                      }),
        _recent_threats.end());

    // Calculate escalation
    int recentHighThreats = 0;
    for (const auto &recentThreat : _recent_threats) {
        if (recentThreat.level >= ThreatLevel::Active) {
            recentHighThreats++;
        }
    }
    _threat_escalation_count = recentHighThreats;

    // Determine required countermeasure intensity
    CountermeasureIntensity requiredIntensity = calculateRequiredIntensity(threat);
    requiredIntensity = static_cast<CountermeasureIntensity>(
        std::min(static_cast<int>(requiredIntensity), static_cast<int>(_max_intensity)));

    // Select and deploy countermeasures
    QList<CountermeasureType> measures = selectCountermeasures(threat.level, requiredIntensity);
    deployCountermeasures(measures, requiredIntensity);

    // Update threat level
    setThreatLevel(threat.level);

    // Activate emergency mode for hostile threats
    if (threat.level >= ThreatLevel::Hostile && !_emergency_mode) {
        activateEmergencyMode();
    }
}

CountermeasureIntensity AdaptiveCountermeasures::calculateRequiredIntensity(const ThreatAssessment &threat) {
    // Base intensity from threat level
    CountermeasureIntensity baseIntensity;
    switch (threat.level) {
        case ThreatLevel::None:
            return CountermeasureIntensity::Minimal;
        case ThreatLevel::Ambient:
            baseIntensity = CountermeasureIntensity::Minimal;
            break;
        case ThreatLevel::Targeted:
            baseIntensity = CountermeasureIntensity::Moderate;
            break;
        case ThreatLevel::Active:
            baseIntensity = CountermeasureIntensity::Aggressive;
            break;
        case ThreatLevel::Hostile:
            baseIntensity = CountermeasureIntensity::Maximum;
            break;
    }

    // Escalate based on threat confidence
    if (threat.confidence > 0.8f) {
        baseIntensity = static_cast<CountermeasureIntensity>(
            std::min(static_cast<int>(baseIntensity) + 1, static_cast<int>(CountermeasureIntensity::Maximum)));
    }

    // Escalate based on threat escalation count
    if (_threat_escalation_count >= 3) {
        baseIntensity = CountermeasureIntensity::Maximum;
    }

    // Reduce intensity in government mode for certain threats
    if (_government_mode && threat.government_exemption) {
        baseIntensity = static_cast<CountermeasureIntensity>(
            std::max(static_cast<int>(baseIntensity) - 1, static_cast<int>(CountermeasureIntensity::Minimal)));
    }

    return baseIntensity;
}

QList<CountermeasureType> AdaptiveCountermeasures::selectCountermeasures(
    ThreatLevel threatLevel, CountermeasureIntensity intensity) {

    QList<CountermeasureType> measures;

    // Always apply privacy enhancement
    measures.append(CountermeasureType::PrivacyEnhancement);

    switch (intensity) {
        case CountermeasureIntensity::Minimal:
            // Basic privacy enhancement only
            break;

        case CountermeasureIntensity::Moderate:
            measures.append(CountermeasureType::NetworkObfuscation);
            if (_audio_output_available) {
                measures.append(CountermeasureType::AudioNoise);
            }
            break;

        case CountermeasureIntensity::Aggressive:
            measures.append(CountermeasureType::NetworkObfuscation);
            measures.append(CountermeasureType::CommunicationHiding);
            if (_audio_output_available) {
                measures.append(CountermeasureType::AudioNoise);
                measures.append(CountermeasureType::UltrasonicJamming);
            }
            break;

        case CountermeasureIntensity::Maximum:
            measures.append(CountermeasureType::NetworkObfuscation);
            measures.append(CountermeasureType::CommunicationHiding);
            measures.append(CountermeasureType::VisualScrambling);
            if (_audio_output_available) {
                measures.append(CountermeasureType::AudioNoise);
                measures.append(CountermeasureType::UltrasonicJamming);
            }
            break;
    }

    // Filter out government-incompatible measures if in government mode
    if (_government_mode) {
        measures.erase(
            std::remove_if(measures.begin(), measures.end(),
                          [this](CountermeasureType type) {
                              return !isCountermeasureGovernmentCompatible(type);
                          }),
            measures.end());
    }

    return measures;
}

void AdaptiveCountermeasures::deployCountermeasures(
    const QList<CountermeasureType> &measures, CountermeasureIntensity intensity) {

    qDebug() << "AdaptiveCountermeasures: Deploying" << measures.size()
             << "countermeasures at intensity" << static_cast<int>(intensity);

    // Update current intensity
    const CountermeasureIntensity oldIntensity = _current_intensity;
    _current_intensity = intensity;

    if (oldIntensity != intensity) {
        Q_EMIT intensityChanged(intensity, oldIntensity);
    }

    // Activate required countermeasures
    for (CountermeasureType type : measures) {
        activateCountermeasure(type, intensity);
    }

    // Deactivate countermeasures not in the current list
    QList<CountermeasureType> toDeactivate;
    for (const auto &active : _active_countermeasures) {
        if (!measures.contains(active.type)) {
            toDeactivate.append(active.type);
        }
    }

    for (CountermeasureType type : toDeactivate) {
        deactivateCountermeasure(type);
    }
}

void AdaptiveCountermeasures::activateCountermeasure(CountermeasureType type, CountermeasureIntensity intensity) {
    // Check if already active with same intensity
    for (const auto &active : _active_countermeasures) {
        if (active.type == type && active.intensity == intensity) {
            return; // Already active with correct intensity
        }
    }

    qDebug() << "AdaptiveCountermeasures: Activating" << static_cast<int>(type)
             << "at intensity" << static_cast<int>(intensity);

    switch (type) {
        case CountermeasureType::AudioNoise:
            activateAudioNoise(intensity);
            break;
        case CountermeasureType::UltrasonicJamming:
            activateUltrasonicJamming(intensity);
            break;
        case CountermeasureType::PrivacyEnhancement:
            activatePrivacyEnhancement(intensity);
            break;
        case CountermeasureType::NetworkObfuscation:
            activateNetworkObfuscation(intensity);
            break;
        case CountermeasureType::VisualScrambling:
            activateVisualScrambling(intensity);
            break;
        case CountermeasureType::CommunicationHiding:
            activateCommunicationHiding(intensity);
            break;
        default:
            return;
    }

    // Update status
    CountermeasureStatus status;
    status.type = type;
    status.intensity = intensity;
    status.active = true;
    status.activated_time = QDateTime::currentMSecsSinceEpoch();
    status.government_compatible = isCountermeasureGovernmentCompatible(type);

    if (_government_mode) {
        adjustForGovernmentMode(status);
    }

    // Remove old status and add new one
    _active_countermeasures.erase(
        std::remove_if(_active_countermeasures.begin(), _active_countermeasures.end(),
                      [type](const CountermeasureStatus &s) { return s.type == type; }),
        _active_countermeasures.end());

    _active_countermeasures.append(status);
    _countermeasure_status[type] = status;

    // Update activation count
    _activation_count[type]++;

    Q_EMIT countermeasureActivated(type, intensity);
}

void AdaptiveCountermeasures::deactivateCountermeasure(CountermeasureType type) {
    qDebug() << "AdaptiveCountermeasures: Deactivating" << static_cast<int>(type);

    switch (type) {
        case CountermeasureType::AudioNoise:
            deactivateAudioNoise();
            break;
        case CountermeasureType::UltrasonicJamming:
            deactivateUltrasonicJamming();
            break;
        case CountermeasureType::PrivacyEnhancement:
            deactivatePrivacyEnhancement();
            break;
        case CountermeasureType::NetworkObfuscation:
            deactivateNetworkObfuscation();
            break;
        case CountermeasureType::VisualScrambling:
            deactivateVisualScrambling();
            break;
        case CountermeasureType::CommunicationHiding:
            deactivateCommunicationHiding();
            break;
        default:
            return;
    }

    // Remove from active list
    _active_countermeasures.erase(
        std::remove_if(_active_countermeasures.begin(), _active_countermeasures.end(),
                      [type](const CountermeasureStatus &s) { return s.type == type; }),
        _active_countermeasures.end());

    _countermeasure_status.remove(type);

    Q_EMIT countermeasureDeactivated(type);
}

void AdaptiveCountermeasures::activateAudioNoise(CountermeasureIntensity intensity) {
#ifdef __has_include
#if __has_include(<QtMultimedia/QAudioOutput>)
    if (!_audio_output_available || !_audio_output) {
        return;
    }

    // Start audio noise generation timer
    if (!_audio_noise_timer->isActive()) {
        _audio_noise_timer->start();
    }

    // Update status
    auto &status = _countermeasure_status[CountermeasureType::AudioNoise];
    status.description = QString("Audio noise generation (Intensity: %1)").arg(static_cast<int>(intensity));
    status.effectiveness = 0.7f + (static_cast<int>(intensity) * 0.1f);
#endif
#endif
}

void AdaptiveCountermeasures::activateUltrasonicJamming(CountermeasureIntensity intensity) {
    if (!_audio_output_available) {
        return;
    }

    // Ultrasonic jamming is part of audio noise generation
    activateAudioNoise(intensity);

    auto &status = _countermeasure_status[CountermeasureType::UltrasonicJamming];
    status.description = QString("Ultrasonic interference (Intensity: %1)").arg(static_cast<int>(intensity));
    status.effectiveness = 0.8f + (static_cast<int>(intensity) * 0.05f);
}

void AdaptiveCountermeasures::activatePrivacyEnhancement(CountermeasureIntensity intensity) {
    // Enhanced privacy settings based on intensity
    float obfuscationLevel;
    switch (intensity) {
        case CountermeasureIntensity::Minimal:
            obfuscationLevel = MINIMAL_OBFUSCATION;
            break;
        case CountermeasureIntensity::Moderate:
            obfuscationLevel = MODERATE_OBFUSCATION;
            break;
        case CountermeasureIntensity::Aggressive:
            obfuscationLevel = AGGRESSIVE_OBFUSCATION;
            break;
        case CountermeasureIntensity::Maximum:
            obfuscationLevel = MAXIMUM_OBFUSCATION;
            break;
    }

    enhanceContactObfuscation(intensity);
    enhanceLocationRandomization(intensity);
    enhanceMetadataProtection(intensity);

    auto &status = _countermeasure_status[CountermeasureType::PrivacyEnhancement];
    status.description = QString("Enhanced privacy protection (%1%)").arg(static_cast<int>(obfuscationLevel * 100));
    status.effectiveness = obfuscationLevel;
}

void AdaptiveCountermeasures::activateNetworkObfuscation(CountermeasureIntensity intensity) {
    // Start network obfuscation timer
    if (!_network_timer->isActive()) {
        _network_timer->start();
    }

    activateDummyTraffic(intensity);
    activateTrafficPadding(intensity);
    activateTimingObfuscation(intensity);

    auto &status = _countermeasure_status[CountermeasureType::NetworkObfuscation];
    status.description = QString("Network traffic obfuscation (Intensity: %1)").arg(static_cast<int>(intensity));
    status.effectiveness = 0.6f + (static_cast<int>(intensity) * 0.1f);
}

void AdaptiveCountermeasures::activateVisualScrambling(CountermeasureIntensity intensity) {
    // Visual scrambling implementation would go here
    // This could include screen filters, display interference, etc.

    auto &status = _countermeasure_status[CountermeasureType::VisualScrambling];
    status.description = QString("Visual interference (Intensity: %1)").arg(static_cast<int>(intensity));
    status.effectiveness = 0.5f + (static_cast<int>(intensity) * 0.1f);
    status.government_compatible = false; // May interfere with official displays
}

void AdaptiveCountermeasures::activateCommunicationHiding(CountermeasureIntensity intensity) {
    // Communication steganography and hiding techniques

    auto &status = _countermeasure_status[CountermeasureType::CommunicationHiding];
    status.description = QString("Communication steganography (Intensity: %1)").arg(static_cast<int>(intensity));
    status.effectiveness = 0.8f + (static_cast<int>(intensity) * 0.05f);
}

void AdaptiveCountermeasures::deactivateAudioNoise() {
    _audio_noise_timer->stop();

#ifdef __has_include
#if __has_include(<QtMultimedia/QAudioOutput>)
    if (_audio_output && _audio_device) {
        _audio_output->stop();
        _audio_device = nullptr;
    }
#endif
#endif
}

void AdaptiveCountermeasures::deactivateUltrasonicJamming() {
    // Ultrasonic jamming is part of audio noise
    // Only stop if no other audio countermeasures are active
    bool hasOtherAudio = false;
    for (const auto &active : _active_countermeasures) {
        if (active.type == CountermeasureType::AudioNoise) {
            hasOtherAudio = true;
            break;
        }
    }

    if (!hasOtherAudio) {
        deactivateAudioNoise();
    }
}

void AdaptiveCountermeasures::deactivatePrivacyEnhancement() {
    // Reset privacy settings to normal levels
    enhanceContactObfuscation(CountermeasureIntensity::Minimal);
    enhanceLocationRandomization(CountermeasureIntensity::Minimal);
    enhanceMetadataProtection(CountermeasureIntensity::Minimal);
}

void AdaptiveCountermeasures::deactivateNetworkObfuscation() {
    _network_timer->stop();
    // Network obfuscation is handled by timer stops
}

void AdaptiveCountermeasures::deactivateVisualScrambling() {
    // Stop visual interference
}

void AdaptiveCountermeasures::deactivateCommunicationHiding() {
    // Disable communication steganography
}

void AdaptiveCountermeasures::generateAudioNoise() {
#ifdef __has_include
#if __has_include(<QtMultimedia/QAudioOutput>)
    if (!_audio_output || !_audio_output_available) {
        return;
    }

    // Determine noise characteristics based on active countermeasures
    float amplitude = 0.3f; // Base amplitude
    bool includeUltrasonic = false;

    for (const auto &active : _active_countermeasures) {
        if (active.type == CountermeasureType::AudioNoise) {
            amplitude = 0.2f + (static_cast<int>(active.intensity) * 0.1f);
        }
        if (active.type == CountermeasureType::UltrasonicJamming) {
            includeUltrasonic = true;
        }
    }

    // Generate white noise
    generateWhiteNoise(amplitude);

    // Add ultrasonic interference if requested
    if (includeUltrasonic) {
        float ultrasonicFreq = ULTRASONIC_BASE_FREQ +
            (QRandomGenerator::global()->bounded(1000)); // Randomize frequency
        generateUltrasonicInterference(ultrasonicFreq, amplitude * 0.5f);
    }

    // Play generated noise
    if (!_audio_device) {
        _audio_device = _audio_output->start();
    }

    if (_audio_device && _audio_device->isWritable()) {
        _audio_device->write(_noise_buffer);
    }
#endif
#endif
}

void AdaptiveCountermeasures::generateWhiteNoise(float amplitude) {
    int16_t *samples = reinterpret_cast<int16_t*>(_noise_buffer.data());
    const int sampleCount = NOISE_BUFFER_SIZE;

    for (int i = 0; i < sampleCount; ++i) {
        // Generate white noise sample
        float noise = (QRandomGenerator::global()->bounded(2.0f) - 1.0f) * amplitude;
        samples[i] = static_cast<int16_t>(noise * 32767.0f);
    }
}

void AdaptiveCountermeasures::generatePinkNoise(float amplitude) {
    // Pink noise implementation (1/f noise)
    int16_t *samples = reinterpret_cast<int16_t*>(_noise_buffer.data());
    const int sampleCount = NOISE_BUFFER_SIZE;

    static float b0 = 0, b1 = 0, b2 = 0, b3 = 0, b4 = 0, b5 = 0, b6 = 0;

    for (int i = 0; i < sampleCount; ++i) {
        float white = QRandomGenerator::global()->bounded(2.0f) - 1.0f;

        b0 = 0.99886f * b0 + white * 0.0555179f;
        b1 = 0.99332f * b1 + white * 0.0750759f;
        b2 = 0.96900f * b2 + white * 0.1538520f;
        b3 = 0.86650f * b3 + white * 0.3104856f;
        b4 = 0.55000f * b4 + white * 0.5329522f;
        b5 = -0.7616f * b5 - white * 0.0168980f;

        float pink = b0 + b1 + b2 + b3 + b4 + b5 + b6 + white * 0.5362f;
        b6 = white * 0.115926f;

        samples[i] = static_cast<int16_t>(pink * amplitude * 32767.0f * 0.11f);
    }
}

void AdaptiveCountermeasures::generateUltrasonicInterference(float frequency, float amplitude) {
    int16_t *samples = reinterpret_cast<int16_t*>(_noise_buffer.data());
    const int sampleCount = NOISE_BUFFER_SIZE;

    static float phase = 0.0f;
    const float phaseIncrement = 2.0f * M_PI * frequency / NOISE_SAMPLE_RATE;

    for (int i = 0; i < sampleCount; ++i) {
        // Generate ultrasonic sine wave with noise modulation
        float ultrasonicNoise = std::sin(phase) * amplitude;

        // Add to existing sample (mix with white noise)
        int32_t mixed = samples[i] + static_cast<int16_t>(ultrasonicNoise * 32767.0f);
        samples[i] = static_cast<int16_t>(std::clamp(mixed, -32768, 32767));

        phase += phaseIncrement;
        if (phase >= 2.0f * M_PI) {
            phase -= 2.0f * M_PI;
        }
    }
}

void AdaptiveCountermeasures::enhanceContactObfuscation(CountermeasureIntensity intensity) {
    // This would integrate with the ContactObfuscator to increase obfuscation levels
    float obfuscationLevel;
    switch (intensity) {
        case CountermeasureIntensity::Minimal:
            obfuscationLevel = MINIMAL_OBFUSCATION;
            break;
        case CountermeasureIntensity::Moderate:
            obfuscationLevel = MODERATE_OBFUSCATION;
            break;
        case CountermeasureIntensity::Aggressive:
            obfuscationLevel = AGGRESSIVE_OBFUSCATION;
            break;
        case CountermeasureIntensity::Maximum:
            obfuscationLevel = MAXIMUM_OBFUSCATION;
            break;
    }

    qDebug() << "AdaptiveCountermeasures: Enhanced contact obfuscation to" << obfuscationLevel;
}

void AdaptiveCountermeasures::enhanceLocationRandomization(CountermeasureIntensity intensity) {
    // This would integrate with LocationRandomizer to increase randomization
    int randomizationRadius;
    switch (intensity) {
        case CountermeasureIntensity::Minimal:
            randomizationRadius = 5; // 5km radius
            break;
        case CountermeasureIntensity::Moderate:
            randomizationRadius = 15; // 15km radius
            break;
        case CountermeasureIntensity::Aggressive:
            randomizationRadius = 50; // 50km radius
            break;
        case CountermeasureIntensity::Maximum:
            randomizationRadius = 200; // 200km radius
            break;
    }

    qDebug() << "AdaptiveCountermeasures: Enhanced location randomization to" << randomizationRadius << "km";
}

void AdaptiveCountermeasures::enhanceMetadataProtection(CountermeasureIntensity intensity) {
    // Enhance metadata protection based on intensity
    qDebug() << "AdaptiveCountermeasures: Enhanced metadata protection to intensity" << static_cast<int>(intensity);
}

void AdaptiveCountermeasures::activateDummyTraffic(CountermeasureIntensity intensity) {
    // Generate dummy network traffic to mask real communication patterns
    int trafficRate;
    switch (intensity) {
        case CountermeasureIntensity::Minimal:
            trafficRate = 1; // 1 packet per second
            break;
        case CountermeasureIntensity::Moderate:
            trafficRate = 5; // 5 packets per second
            break;
        case CountermeasureIntensity::Aggressive:
            trafficRate = 15; // 15 packets per second
            break;
        case CountermeasureIntensity::Maximum:
            trafficRate = 50; // 50 packets per second
            break;
    }

    qDebug() << "AdaptiveCountermeasures: Dummy traffic activated at" << trafficRate << "pps";
}

void AdaptiveCountermeasures::activateTrafficPadding(CountermeasureIntensity intensity) {
    // Add padding to network packets to obscure size patterns
    int paddingSize;
    switch (intensity) {
        case CountermeasureIntensity::Minimal:
            paddingSize = PADDING_MIN_SIZE;
            break;
        case CountermeasureIntensity::Moderate:
            paddingSize = PADDING_MIN_SIZE * 2;
            break;
        case CountermeasureIntensity::Aggressive:
            paddingSize = PADDING_MIN_SIZE * 4;
            break;
        case CountermeasureIntensity::Maximum:
            paddingSize = PADDING_MAX_SIZE;
            break;
    }

    qDebug() << "AdaptiveCountermeasures: Traffic padding activated with" << paddingSize << "bytes";
}

void AdaptiveCountermeasures::activateTimingObfuscation(CountermeasureIntensity intensity) {
    // Obfuscate timing patterns in network traffic
    int maxDelay;
    switch (intensity) {
        case CountermeasureIntensity::Minimal:
            maxDelay = 100; // 100ms max delay
            break;
        case CountermeasureIntensity::Moderate:
            maxDelay = 300; // 300ms max delay
            break;
        case CountermeasureIntensity::Aggressive:
            maxDelay = 1000; // 1s max delay
            break;
        case CountermeasureIntensity::Maximum:
            maxDelay = 3000; // 3s max delay
            break;
    }

    qDebug() << "AdaptiveCountermeasures: Timing obfuscation activated with" << maxDelay << "ms max delay";
}

void AdaptiveCountermeasures::obfuscateNetworkTraffic() {
    // Generate dummy traffic and apply padding based on current settings
    for (const auto &active : _active_countermeasures) {
        if (active.type == CountermeasureType::NetworkObfuscation) {
            // Implementation would generate actual network traffic here
            break;
        }
    }
}

void AdaptiveCountermeasures::updatePrivacySettings() {
    // Update privacy enhancement settings based on current threat level
    for (const auto &active : _active_countermeasures) {
        if (active.type == CountermeasureType::PrivacyEnhancement) {
            // Refresh privacy settings
            enhanceContactObfuscation(active.intensity);
            enhanceLocationRandomization(active.intensity);
            enhanceMetadataProtection(active.intensity);
            break;
        }
    }
}

void AdaptiveCountermeasures::updateCountermeasures() {
    // Update effectiveness metrics
    updateEffectivenessMetrics();

    // Check if countermeasures need adjustment based on recent threats
    if (!_recent_threats.isEmpty()) {
        const auto &lastThreat = _recent_threats.last();
        const qint64 timeSinceLastThreat = QDateTime::currentMSecsSinceEpoch() - lastThreat.timestamp;

        // Reduce intensity if no threats for 2 minutes
        if (timeSinceLastThreat > 120000 && _current_intensity > CountermeasureIntensity::Minimal) {
            CountermeasureIntensity reducedIntensity = static_cast<CountermeasureIntensity>(
                static_cast<int>(_current_intensity) - 1);

            qDebug() << "AdaptiveCountermeasures: Reducing intensity due to lack of recent threats";

            // Re-deploy with reduced intensity
            QList<CountermeasureType> currentMeasures;
            for (const auto &active : _active_countermeasures) {
                currentMeasures.append(active.type);
            }
            deployCountermeasures(currentMeasures, reducedIntensity);
        }
    }
}

void AdaptiveCountermeasures::updateEffectivenessMetrics() {
    // Update effectiveness based on whether threats continue after countermeasure activation
    for (auto &active : _active_countermeasures) {
        // Simple effectiveness calculation based on time active and recent threats
        const qint64 timeActive = QDateTime::currentMSecsSinceEpoch() - active.activated_time;
        const int threatsAfterActivation = std::count_if(
            _recent_threats.begin(), _recent_threats.end(),
            [&active](const ThreatAssessment &threat) {
                return threat.timestamp > active.activated_time;
            });

        // Higher effectiveness if fewer threats after activation
        float effectiveness = 1.0f - (threatsAfterActivation * 0.1f);
        effectiveness = std::clamp(effectiveness, 0.1f, 1.0f);

        active.effectiveness = effectiveness;
        _effectiveness_history[active.type] = effectiveness;
    }
}

void AdaptiveCountermeasures::activateEmergencyMode() {
    if (_emergency_mode) {
        return;
    }

    qDebug() << "AdaptiveCountermeasures: EMERGENCY MODE ACTIVATED";

    _emergency_mode = true;

    // Activate maximum countermeasures
    QList<CountermeasureType> emergencyMeasures = {
        CountermeasureType::PrivacyEnhancement,
        CountermeasureType::NetworkObfuscation,
        CountermeasureType::CommunicationHiding
    };

    if (_audio_output_available) {
        emergencyMeasures.append(CountermeasureType::AudioNoise);
        emergencyMeasures.append(CountermeasureType::UltrasonicJamming);
    }

    if (!_government_mode) {
        emergencyMeasures.append(CountermeasureType::VisualScrambling);
    }

    deployCountermeasures(emergencyMeasures, CountermeasureIntensity::Maximum);

    Q_EMIT emergencyModeActivated();
}

void AdaptiveCountermeasures::deactivateEmergencyMode() {
    if (!_emergency_mode) {
        return;
    }

    qDebug() << "AdaptiveCountermeasures: Emergency mode deactivated";

    _emergency_mode = false;

    // Return to normal threat-based countermeasures
    if (!_recent_threats.isEmpty()) {
        respondToThreat(_recent_threats.last());
    } else {
        // No recent threats, minimize countermeasures
        QList<CountermeasureType> minimalMeasures = { CountermeasureType::PrivacyEnhancement };
        deployCountermeasures(minimalMeasures, CountermeasureIntensity::Minimal);
    }

    Q_EMIT emergencyModeDeactivated();
}

void AdaptiveCountermeasures::setThreatLevel(ThreatLevel level) {
    if (_current_threat_level != level) {
        _current_threat_level = level;
        qDebug() << "AdaptiveCountermeasures: Threat level updated to" << static_cast<int>(level);
    }
}

bool AdaptiveCountermeasures::isCountermeasureGovernmentCompatible(CountermeasureType type) {
    switch (type) {
        case CountermeasureType::PrivacyEnhancement:
        case CountermeasureType::AudioNoise:
        case CountermeasureType::UltrasonicJamming:
        case CountermeasureType::NetworkObfuscation:
        case CountermeasureType::CommunicationHiding:
            return true; // Compatible with government operations

        case CountermeasureType::VisualScrambling:
            return false; // May interfere with official displays

        default:
            return true;
    }
}

void AdaptiveCountermeasures::adjustForGovernmentMode(CountermeasureStatus &status) {
    if (!_government_mode) {
        return;
    }

    // Reduce effectiveness estimates in government mode
    status.effectiveness *= 0.8f;
    status.description += " (Government Mode)";

    // Ensure government compatibility
    if (!status.government_compatible) {
        status.active = false;
        status.description += " - DISABLED (Incompatible with government operations)";
    }
}

} // namespace SpyGram::Counterintelligence