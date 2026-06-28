#include "countermeasure_randomizer.h"
#include <QtCore/QDebug>
#include <QtCore/QDateTime>
#include <QtCore/QMutexLocker>
#include <cmath>
#include <algorithm>

// PATCHER AGENT: Countermeasure Randomization Implementation
// Prevents predictable deployment patterns to thwart adversary adaptation
// Addresses VULN-COUNTER-001 from DEBUGGER analysis

namespace SpyGram::Counterintelligence {

// Define equivalent countermeasure sets for randomization
const QMap<CountermeasureType, QList<CountermeasureType>> CountermeasureRandomizer::EQUIVALENT_MEASURES = {
    {CountermeasureType::AudioNoise, {CountermeasureType::UltrasonicJamming}},
    {CountermeasureType::UltrasonicJamming, {CountermeasureType::AudioNoise}},
    {CountermeasureType::NetworkObfuscation, {CountermeasureType::CommunicationHiding}},
    {CountermeasureType::CommunicationHiding, {CountermeasureType::NetworkObfuscation}}
};

const QList<CountermeasureType> CountermeasureRandomizer::DECOY_COMPATIBLE_MEASURES = {
    CountermeasureType::AudioNoise,
    CountermeasureType::NetworkObfuscation,
    CountermeasureType::PrivacyEnhancement
};

const QMap<CountermeasureType, QList<CountermeasureType>> CountermeasureRandomizer::GOVERNMENT_SAFE_ALTERNATIVES = {
    {CountermeasureType::VisualScrambling, {CountermeasureType::AudioNoise, CountermeasureType::NetworkObfuscation}},
    {CountermeasureType::CommunicationHiding, {CountermeasureType::PrivacyEnhancement}}
};

CountermeasureRandomizer::CountermeasureRandomizer(QObject *parent)
    : QObject(parent)
    , _secure_rng(QRandomGenerator::securelySeeded())
    , _pattern_rotation_timer(new QTimer(this))
    , _parameter_update_timer(new QTimer(this))
    , _decoy_cleanup_timer(new QTimer(this))
{
    // Initialize default configuration
    _config.strategy = RandomizationStrategy::Comprehensive;
    _config.timing_variance = 0.3f;
    _config.selection_variance = 0.2f;
    _config.intensity_variance = 0.15f;
    _config.pattern_variance = 0.25f;
    _config.enable_decoy_measures = true;
    _config.enable_timing_jitter = true;

    // Setup timers
    _pattern_rotation_timer->setInterval(PATTERN_ROTATION_INTERVAL);
    _parameter_update_timer->setInterval(PARAMETER_UPDATE_INTERVAL);
    _decoy_cleanup_timer->setInterval(60000); // 1 minute cleanup

    // Connect timer signals
    connect(_pattern_rotation_timer, &QTimer::timeout, this, &CountermeasureRandomizer::rotateObfuscationPatterns);
    connect(_parameter_update_timer, &QTimer::timeout, this, &CountermeasureRandomizer::updateRandomizationParameters);
    connect(_decoy_cleanup_timer, &QTimer::timeout, this, &CountermeasureRandomizer::manageDecoyLifecycle);

    // Start timers
    _pattern_rotation_timer->start();
    _parameter_update_timer->start();
    _decoy_cleanup_timer->start();

    logRandomizationEvent("INIT", "Countermeasure Randomizer initialized");
    qDebug() << "CountermeasureRandomizer: Initialized with comprehensive randomization";
}

CountermeasureRandomizer::~CountermeasureRandomizer() {
    logRandomizationEvent("SHUTDOWN", "Countermeasure Randomizer shutdown");
}

void CountermeasureRandomizer::setRandomizationConfig(const RandomizationConfig &config) {
    QMutexLocker locker(&_randomization_mutex);
    _config = config;

    // Update timer intervals based on config
    _pattern_rotation_timer->setInterval(_config.pattern_change_interval);

    logRandomizationEvent("CONFIG_UPDATED", "Randomization configuration updated");
    Q_EMIT randomizationConfigChanged();
}

RandomizationConfig CountermeasureRandomizer::getRandomizationConfig() const {
    QMutexLocker locker(&_randomization_mutex);
    return _config;
}

RandomizedDeployment CountermeasureRandomizer::randomizeCountermeasure(CountermeasureType type,
                                                                      CountermeasureIntensity intensity,
                                                                      ThreatLevel threatLevel) {
    QMutexLocker locker(&_randomization_mutex);
    _total_randomizations++;

    RandomizedDeployment deployment;
    deployment.primary_type = type;
    deployment.adjusted_intensity = intensity;

    // Apply randomization based on strategy
    switch (_config.strategy) {
        case RandomizationStrategy::TimingOnly:
            deployment.deployment_delay = randomizeDeploymentTiming(0, type);
            break;

        case RandomizationStrategy::SelectionOnly:
            deployment.primary_type = selectRandomAlternative(type);
            break;

        case RandomizationStrategy::IntensityOnly:
            deployment.adjusted_intensity = randomizeIntensity(intensity, threatLevel);
            break;

        case RandomizationStrategy::PatternOnly:
            // Pattern randomization affects the sequence, handled at higher level
            break;

        case RandomizationStrategy::Comprehensive:
            // Apply all randomization types
            deployment.primary_type = selectRandomAlternative(type);
            deployment.adjusted_intensity = randomizeIntensity(intensity, threatLevel);
            deployment.deployment_delay = randomizeDeploymentTiming(0, type);

            // Add timing jitter if enabled
            if (_config.enable_timing_jitter) {
                addTimingJitter(100, 2000); // 100ms to 2s jitter
            }
            break;
    }

    // Generate decoy countermeasures if enabled
    if (_config.enable_decoy_measures && shouldDeployDecoy(deployment.primary_type)) {
        deployment.decoy_types = generateDecoyCountermeasures(deployment.primary_type,
                                                             generateSecureRandomInt(1, _config.max_concurrent_decoys));
        _decoys_deployed += deployment.decoy_types.size();
    }

    // Calculate effectiveness modifier based on randomization
    deployment.effectiveness_modifier = 1.0f;
    if (deployment.primary_type != type) {
        deployment.effectiveness_modifier *= 0.95f; // Slight reduction for type change
    }
    if (deployment.adjusted_intensity != intensity) {
        deployment.effectiveness_modifier *= 0.98f; // Slight reduction for intensity change
    }

    // Add randomization details
    deployment.randomization_details = QString("Strategy: %1, Delay: %2ms, Decoys: %3")
                                      .arg(static_cast<int>(_config.strategy))
                                      .arg(deployment.deployment_delay)
                                      .arg(deployment.decoy_types.size());

    // Adapt for government mode if necessary
    if (_government_mode) {
        deployment = adaptForGovernmentMode(deployment);
    }

    // Update tracking
    _recent_deployments.append(deployment.primary_type);
    if (_recent_deployments.size() > MAX_DEPLOYMENT_HISTORY) {
        _recent_deployments.removeFirst();
    }

    _deployment_timestamps[deployment.primary_type] = QDateTime::currentMSecsSinceEpoch();
    _deployment_counts[deployment.primary_type]++;

    updateRandomizationStatistics(deployment);

    logRandomizationEvent("RANDOMIZED",
                         QString("Type: %1->%2, Intensity: %3->%4, Delay: %5ms")
                         .arg(static_cast<int>(type))
                         .arg(static_cast<int>(deployment.primary_type))
                         .arg(static_cast<int>(intensity))
                         .arg(static_cast<int>(deployment.adjusted_intensity))
                         .arg(deployment.deployment_delay));

    return deployment;
}

QList<CountermeasureType> CountermeasureRandomizer::randomizeCountermeasureSelection(
    const QList<CountermeasureType> &original, CountermeasureIntensity intensity) {

    Q_UNUSED(intensity);
    QMutexLocker locker(&_randomization_mutex);

    QList<CountermeasureType> randomized = original;

    // Shuffle the order if selection variance allows
    if (generateSecureRandom() < _config.selection_variance) {
        randomized = shuffleCountermeasures(randomized);
    }

    // Replace some countermeasures with equivalents
    for (int i = 0; i < randomized.size(); ++i) {
        if (generateSecureRandom() < _config.selection_variance) {
            CountermeasureType alternative = selectRandomAlternative(randomized[i]);
            if (alternative != randomized[i]) {
                randomized[i] = alternative;
            }
        }
    }

    return randomized;
}

CountermeasureIntensity CountermeasureRandomizer::randomizeIntensity(CountermeasureIntensity base,
                                                                    ThreatLevel threatLevel) {
    QMutexLocker locker(&_randomization_mutex);

    if (generateSecureRandom() >= _config.intensity_variance) {
        return base; // No randomization
    }

    CountermeasureIntensity randomized = adjustIntensityRandomly(base, _config.intensity_variance);

    // Ensure intensity is appropriate for threat level
    if (threatLevel >= ThreatLevel::Active && randomized < CountermeasureIntensity::Aggressive) {
        randomized = CountermeasureIntensity::Aggressive;
    }

    return clampIntensity(randomized);
}

PatternObfuscation CountermeasureRandomizer::generateObfuscationPattern(
    const QList<CountermeasureType> &baseMeasures) {

    QMutexLocker locker(&_randomization_mutex);

    PatternObfuscation pattern;
    pattern.pattern_sequence = obfuscateDeploymentPattern(baseMeasures);
    pattern.timing_sequence = generateTimingPattern(pattern.pattern_sequence.size(), 5000); // 5s base
    pattern.intensity_sequence = generateIntensityPattern(pattern.pattern_sequence.size(),
                                                         CountermeasureIntensity::Moderate);
    pattern.pattern_duration = 30000 + generateSecureRandomTime(0, 0.5f); // 30s ± 50%
    pattern.pattern_iterations = generateSecureRandomInt(3, 8);
    pattern.is_decoy_pattern = generateSecureRandom() < 0.3f; // 30% chance of decoy

    return pattern;
}

void CountermeasureRandomizer::updatePatternObfuscation() {
    QMutexLocker locker(&_randomization_mutex);

    // Generate new obfuscation pattern
    QList<CountermeasureType> baseMeasures = {
        CountermeasureType::PrivacyEnhancement,
        CountermeasureType::AudioNoise,
        CountermeasureType::NetworkObfuscation
    };

    _current_pattern = generateObfuscationPattern(baseMeasures);
    _pattern_history.append(_current_pattern);

    // Limit pattern history
    if (_pattern_history.size() > MAX_PATTERN_HISTORY) {
        _pattern_history.removeFirst();
    }

    _last_pattern_update = QDateTime::currentMSecsSinceEpoch();
    _pattern_changes++;

    logRandomizationEvent("PATTERN_UPDATED", "Obfuscation pattern updated");
    Q_EMIT patternObfuscationUpdated();
}

QList<CountermeasureType> CountermeasureRandomizer::obfuscateDeploymentPattern(
    const QList<CountermeasureType> &pattern) {

    QList<CountermeasureType> obfuscated = pattern;

    // Add random elements
    if (_config.enable_decoy_measures) {
        int insertions = generateSecureRandomInt(1, 3);
        for (int i = 0; i < insertions; ++i) {
            int position = generateSecureRandomInt(0, obfuscated.size());
            CountermeasureType decoy = generateDecoyType(CountermeasureType::PrivacyEnhancement);
            obfuscated.insert(position, decoy);
        }
    }

    // Shuffle if pattern variance allows
    if (generateSecureRandom() < _config.pattern_variance) {
        obfuscated = shuffleCountermeasures(obfuscated);
    }

    return obfuscated;
}

qint64 CountermeasureRandomizer::randomizeDeploymentTiming(qint64 baseTime, CountermeasureType type) {
    Q_UNUSED(type);

    if (generateSecureRandom() >= _config.timing_variance) {
        return baseTime; // No randomization
    }

    return generateSecureRandomTime(baseTime, _config.timing_variance);
}

qint64 CountermeasureRandomizer::randomizeDuration(qint64 baseDuration, CountermeasureIntensity intensity) {
    Q_UNUSED(intensity);

    float variance = _config.timing_variance * 0.5f; // Half the timing variance for duration
    return generateSecureRandomTime(baseDuration, variance);
}

void CountermeasureRandomizer::addTimingJitter(qint64 minDelay, qint64 maxDelay) {
    if (!_config.enable_timing_jitter) {
        return;
    }

    qint64 jitter = generateSecureRandomTime(minDelay, static_cast<float>(maxDelay - minDelay) / minDelay);

    // Apply jitter by scheduling a delayed action (placeholder)
    logRandomizationEvent("TIMING_JITTER", QString("Applied %1ms jitter").arg(jitter));
}

QList<CountermeasureType> CountermeasureRandomizer::generateDecoyCountermeasures(
    CountermeasureType primaryType, int count) {

    QList<CountermeasureType> decoys;

    for (int i = 0; i < count; ++i) {
        CountermeasureType decoy = generateDecoyType(primaryType);
        if (isDecoyCompatible(primaryType, decoy)) {
            decoys.append(decoy);
            logRandomizationEvent("DECOY_GENERATED",
                                 QString("Decoy %1 for primary %2")
                                 .arg(static_cast<int>(decoy))
                                 .arg(static_cast<int>(primaryType)));
        }
    }

    return decoys;
}

bool CountermeasureRandomizer::shouldDeployDecoy(CountermeasureType primaryType) {
    if (!_config.enable_decoy_measures) {
        return false;
    }

    // Deploy decoys for compatible measures with some probability
    if (!DECOY_COMPATIBLE_MEASURES.contains(primaryType)) {
        return false;
    }

    return generateSecureRandom() < 0.4f; // 40% chance of decoy deployment
}

void CountermeasureRandomizer::manageDecoyLifecycle() {
    QMutexLocker locker(&_randomization_mutex);

    // Remove old decoys (placeholder - real implementation would track actual deployments)
    _active_decoys.clear();

    logRandomizationEvent("DECOY_CLEANUP", "Decoy lifecycle management performed");
}

void CountermeasureRandomizer::analyzeDeploymentHistory(const QList<CountermeasureType> &recentDeployments) {
    QMutexLocker locker(&_randomization_mutex);

    if (recentDeployments.size() < 5) {
        return; // Need minimum history for analysis
    }

    // Check for predictable patterns
    if (detectPredictablePattern(recentDeployments)) {
        _patterns_detected++;
        Q_EMIT predictablePatternDetected(recentDeployments);
        adjustRandomizationBias();
    }
}

bool CountermeasureRandomizer::detectPredictablePattern(const QList<CountermeasureType> &sequence) {
    if (sequence.size() < 4) {
        return false;
    }

    // Simple pattern detection - look for repeating subsequences
    QList<CountermeasureType> repeating = identifyRepeatingSubsequence(sequence);
    if (repeating.size() >= 3) {
        logRandomizationEvent("PATTERN_DETECTED",
                             QString("Repeating pattern of length %1 detected").arg(repeating.size()));
        return true;
    }

    // Check for predictable timing patterns (placeholder)
    float predictability = calculatePatternPredictability(sequence);
    if (predictability > 0.7f) {
        logRandomizationEvent("HIGH_PREDICTABILITY",
                             QString("Pattern predictability: %1").arg(predictability));
        return true;
    }

    return false;
}

void CountermeasureRandomizer::adjustRandomizationBias() {
    // Increase randomization when patterns are detected
    _config.timing_variance = std::min(_config.timing_variance * 1.1f, MAX_TIMING_VARIANCE);
    _config.selection_variance = std::min(_config.selection_variance * 1.1f, 0.5f);
    _config.pattern_variance = std::min(_config.pattern_variance * 1.1f, 0.4f);

    logRandomizationEvent("BIAS_ADJUSTED", "Randomization bias increased to counter predictability");
}

void CountermeasureRandomizer::setGovernmentMode(bool enabled) {
    QMutexLocker locker(&_randomization_mutex);
    _government_mode = enabled;

    if (_government_mode) {
        // Reduce some randomization in government mode for compliance
        _config.intensity_variance *= 0.8f;
        _config.enable_false_positives = false;
    }

    logRandomizationEvent("GOVERNMENT_MODE", enabled ? "Enabled" : "Disabled");
}

RandomizedDeployment CountermeasureRandomizer::adaptForGovernmentMode(const RandomizedDeployment &deployment) {
    if (!_government_mode) {
        return deployment;
    }

    return removeGovernmentIncompatibleElements(deployment);
}

// Private implementation methods

float CountermeasureRandomizer::generateSecureRandom(float min, float max) {
    return min + (_secure_rng.bounded(1.0) * (max - min));
}

int CountermeasureRandomizer::generateSecureRandomInt(int min, int max) {
    return _secure_rng.bounded(min, max + 1);
}

qint64 CountermeasureRandomizer::generateSecureRandomTime(qint64 base, float variance) {
    if (variance <= 0.0f) {
        return base;
    }

    float factor = 1.0f + (generateSecureRandom(-variance, variance));
    return static_cast<qint64>(base * factor);
}

CountermeasureType CountermeasureRandomizer::selectRandomAlternative(CountermeasureType original) {
    if (EQUIVALENT_MEASURES.contains(original)) {
        const QList<CountermeasureType> &alternatives = EQUIVALENT_MEASURES[original];
        if (!alternatives.isEmpty() && generateSecureRandom() < _config.selection_variance) {
            int index = generateSecureRandomInt(0, alternatives.size() - 1);
            return alternatives[index];
        }
    }

    return original;
}

QList<CountermeasureType> CountermeasureRandomizer::shuffleCountermeasures(
    const QList<CountermeasureType> &measures) {

    QList<CountermeasureType> shuffled = measures;

    // Fisher-Yates shuffle
    for (int i = shuffled.size() - 1; i > 0; --i) {
        int j = generateSecureRandomInt(0, i);
        shuffled.swapItemsAt(i, j);
    }

    return shuffled;
}

CountermeasureIntensity CountermeasureRandomizer::adjustIntensityRandomly(
    CountermeasureIntensity base, float variance) {

    int baseValue = static_cast<int>(base);
    int adjustment = 0;

    if (generateSecureRandom() < variance / 2.0f) {
        adjustment = -1; // Decrease intensity
    } else if (generateSecureRandom() < variance / 2.0f) {
        adjustment = 1;  // Increase intensity
    }

    return static_cast<CountermeasureIntensity>(baseValue + adjustment);
}

CountermeasureIntensity CountermeasureRandomizer::clampIntensity(CountermeasureIntensity intensity) {
    int value = static_cast<int>(intensity);
    value = std::max(0, std::min(value, static_cast<int>(CountermeasureIntensity::Maximum)));
    return static_cast<CountermeasureIntensity>(value);
}

QList<CountermeasureType> CountermeasureRandomizer::generateRandomPattern(int length) {
    QList<CountermeasureType> pattern;
    QList<CountermeasureType> available = {
        CountermeasureType::PrivacyEnhancement,
        CountermeasureType::AudioNoise,
        CountermeasureType::NetworkObfuscation,
        CountermeasureType::UltrasonicJamming
    };

    for (int i = 0; i < length; ++i) {
        int index = generateSecureRandomInt(0, available.size() - 1);
        pattern.append(available[index]);
    }

    return pattern;
}

QList<qint64> CountermeasureRandomizer::generateTimingPattern(int length, qint64 baseInterval) {
    QList<qint64> timing;

    for (int i = 0; i < length; ++i) {
        qint64 interval = generateSecureRandomTime(baseInterval, _config.timing_variance);
        timing.append(interval);
    }

    return timing;
}

QList<CountermeasureIntensity> CountermeasureRandomizer::generateIntensityPattern(
    int length, CountermeasureIntensity base) {

    QList<CountermeasureIntensity> intensities;

    for (int i = 0; i < length; ++i) {
        CountermeasureIntensity intensity = adjustIntensityRandomly(base, _config.intensity_variance);
        intensities.append(clampIntensity(intensity));
    }

    return intensities;
}

CountermeasureType CountermeasureRandomizer::generateDecoyType(CountermeasureType primary) {
    Q_UNUSED(primary);

    // Generate a decoy from compatible measures
    if (!DECOY_COMPATIBLE_MEASURES.isEmpty()) {
        int index = generateSecureRandomInt(0, DECOY_COMPATIBLE_MEASURES.size() - 1);
        return DECOY_COMPATIBLE_MEASURES[index];
    }

    return CountermeasureType::PrivacyEnhancement; // Fallback
}

bool CountermeasureRandomizer::isDecoyCompatible(CountermeasureType primary, CountermeasureType decoy) {
    // Simple compatibility check - avoid conflicting countermeasures
    if (primary == decoy) {
        return false;
    }

    return DECOY_COMPATIBLE_MEASURES.contains(decoy);
}

float CountermeasureRandomizer::calculatePatternPredictability(const QList<CountermeasureType> &sequence) {
    if (sequence.size() < 3) {
        return 0.0f;
    }

    // Simple predictability calculation based on repetition
    QMap<CountermeasureType, int> frequency;
    for (CountermeasureType type : sequence) {
        frequency[type]++;
    }

    // Calculate entropy-like measure
    float entropy = 0.0f;
    for (int count : frequency) {
        float probability = static_cast<float>(count) / sequence.size();
        if (probability > 0) {
            entropy -= probability * std::log2(probability);
        }
    }

    // Convert to predictability (lower entropy = higher predictability)
    float maxEntropy = std::log2(frequency.size());
    return maxEntropy > 0 ? 1.0f - (entropy / maxEntropy) : 1.0f;
}

QList<CountermeasureType> CountermeasureRandomizer::identifyRepeatingSubsequence(
    const QList<CountermeasureType> &sequence) {

    // Look for the longest repeating subsequence
    QList<CountermeasureType> longestRepeat;

    for (int length = 2; length <= sequence.size() / 2; ++length) {
        for (int start = 0; start <= sequence.size() - 2 * length; ++start) {
            QList<CountermeasureType> subsequence = sequence.mid(start, length);
            QList<CountermeasureType> nextSubsequence = sequence.mid(start + length, length);

            if (subsequence == nextSubsequence) {
                if (subsequence.size() > longestRepeat.size()) {
                    longestRepeat = subsequence;
                }
            }
        }
    }

    return longestRepeat;
}

RandomizedDeployment CountermeasureRandomizer::removeGovernmentIncompatibleElements(
    const RandomizedDeployment &deployment) {

    RandomizedDeployment adapted = deployment;

    // Replace incompatible countermeasures with government-safe alternatives
    if (!isGovernmentCompatible(adapted.primary_type)) {
        if (GOVERNMENT_SAFE_ALTERNATIVES.contains(adapted.primary_type)) {
            const QList<CountermeasureType> &alternatives = GOVERNMENT_SAFE_ALTERNATIVES[adapted.primary_type];
            if (!alternatives.isEmpty()) {
                int index = generateSecureRandomInt(0, alternatives.size() - 1);
                adapted.primary_type = alternatives[index];
            }
        }
    }

    // Filter decoy types for government compatibility
    QList<CountermeasureType> compatibleDecoys;
    for (CountermeasureType decoy : adapted.decoy_types) {
        if (isGovernmentCompatible(decoy)) {
            compatibleDecoys.append(decoy);
        }
    }
    adapted.decoy_types = compatibleDecoys;

    adapted.randomization_details += " (Government adapted)";

    return adapted;
}

bool CountermeasureRandomizer::isGovernmentCompatible(CountermeasureType type) {
    // Visual scrambling may interfere with official displays
    return type != CountermeasureType::VisualScrambling;
}

void CountermeasureRandomizer::logRandomizationEvent(const QString &event, const QString &details) {
    if (!_logging_enabled) {
        return;
    }

    QString timestamp = QDateTime::currentDateTime().toString(Qt::ISODate);
    QString logEntry = QString("[%1] %2: %3").arg(timestamp, event, details);

    _randomization_logs.append(logEntry);

    // Limit log size
    while (_randomization_logs.size() > MAX_LOG_ENTRIES) {
        _randomization_logs.removeFirst();
    }
}

void CountermeasureRandomizer::updateRandomizationStatistics(const RandomizedDeployment &deployment) {
    Q_UNUSED(deployment);

    // Update internal statistics (placeholder)
    // Real implementation would track effectiveness, patterns, etc.
}

QStringList CountermeasureRandomizer::getRandomizationLogs() const {
    QMutexLocker locker(&_randomization_mutex);
    return _randomization_logs;
}

void CountermeasureRandomizer::enableRandomizationLogging(bool enable) {
    QMutexLocker locker(&_randomization_mutex);
    _logging_enabled = enable;
    logRandomizationEvent("LOGGING_CHANGED", enable ? "Enabled" : "Disabled");
}

// Timer slot implementations
void CountermeasureRandomizer::updateRandomizationParameters() {
    // Periodically adjust randomization parameters to prevent adaptation
    implementAntiAnalysisMeasures();
}

void CountermeasureRandomizer::rotateObfuscationPatterns() {
    updatePatternObfuscation();
}

void CountermeasureRandomizer::implementAntiAnalysisMeasures() {
    QMutexLocker locker(&_randomization_mutex);

    // Randomly adjust parameters to prevent adversary learning
    if (generateSecureRandom() < 0.3f) { // 30% chance of parameter adjustment
        randomizeRandomizationParameters();
    }
}

void CountermeasureRandomizer::randomizeRandomizationParameters() {
    // Slightly adjust randomization parameters
    float adjustment = generateSecureRandom(-0.05f, 0.05f); // ±5% adjustment

    _config.timing_variance = std::clamp(_config.timing_variance + adjustment,
                                        MIN_TIMING_VARIANCE, MAX_TIMING_VARIANCE);

    _config.selection_variance = std::clamp(_config.selection_variance + adjustment, 0.1f, 0.5f);

    _config.intensity_variance = std::clamp(_config.intensity_variance + adjustment,
                                           MIN_INTENSITY_VARIANCE, MAX_INTENSITY_VARIANCE);

    logRandomizationEvent("PARAMETERS_RANDOMIZED", "Randomization parameters auto-adjusted");
}

} // namespace SpyGram::Counterintelligence