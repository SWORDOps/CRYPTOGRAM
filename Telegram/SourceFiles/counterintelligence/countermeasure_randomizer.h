#pragma once

// Countermeasure Randomizer - Prevents Predictable Deployment Patterns
// PATCHER AGENT: Critical Security Implementation for Phase 4 Counterintelligence
// Addresses VULN-COUNTER-001 from DEBUGGER analysis

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QMutex>
#include <QtCore/QTimer>
#include <QtCore/QRandomGenerator>
#include "adaptive_countermeasures.h"

namespace SpyGram::Counterintelligence {

// Randomization strategy types
enum class RandomizationStrategy {
    TimingOnly,          // Randomize only deployment timing
    SelectionOnly,       // Randomize countermeasure selection
    IntensityOnly,       // Randomize intensity levels
    PatternOnly,         // Randomize deployment patterns
    Comprehensive        // Randomize all aspects
};

// Randomization configuration
struct RandomizationConfig {
    RandomizationStrategy strategy = RandomizationStrategy::Comprehensive;
    float timing_variance = 0.3f;        // 30% timing variance
    float selection_variance = 0.2f;     // 20% selection variance
    float intensity_variance = 0.15f;    // 15% intensity variance
    float pattern_variance = 0.25f;      // 25% pattern variance
    bool enable_decoy_measures = true;   // Deploy decoy countermeasures
    bool enable_timing_jitter = true;    // Add random timing delays
    bool enable_false_positives = false; // Generate controlled false positives
    int max_concurrent_decoys = 3;       // Maximum decoy countermeasures
    qint64 pattern_change_interval = 300000; // Change patterns every 5 minutes
};

// Randomized countermeasure deployment
struct RandomizedDeployment {
    CountermeasureType primary_type;
    CountermeasureIntensity adjusted_intensity;
    QList<CountermeasureType> decoy_types;
    qint64 deployment_delay;
    qint64 duration_adjustment;
    QString randomization_details;
    float effectiveness_modifier;
};

// Pattern obfuscation data
struct PatternObfuscation {
    QList<CountermeasureType> pattern_sequence;
    QList<qint64> timing_sequence;
    QList<CountermeasureIntensity> intensity_sequence;
    qint64 pattern_duration;
    int pattern_iterations;
    bool is_decoy_pattern;
};

class CountermeasureRandomizer : public QObject {
    Q_OBJECT

public:
    explicit CountermeasureRandomizer(QObject *parent = nullptr);
    ~CountermeasureRandomizer();

    // Configuration management
    void setRandomizationConfig(const RandomizationConfig &config);
    RandomizationConfig getRandomizationConfig() const;

    // Core randomization interface
    RandomizedDeployment randomizeCountermeasure(CountermeasureType type,
                                               CountermeasureIntensity intensity,
                                               ThreatLevel threatLevel);

    QList<CountermeasureType> randomizeCountermeasureSelection(const QList<CountermeasureType> &original,
                                                              CountermeasureIntensity intensity);

    CountermeasureIntensity randomizeIntensity(CountermeasureIntensity base, ThreatLevel threatLevel);

    // Pattern obfuscation
    PatternObfuscation generateObfuscationPattern(const QList<CountermeasureType> &baseMeasures);
    void updatePatternObfuscation();
    QList<CountermeasureType> obfuscateDeploymentPattern(const QList<CountermeasureType> &pattern);

    // Timing randomization
    qint64 randomizeDeploymentTiming(qint64 baseTime, CountermeasureType type);
    qint64 randomizeDuration(qint64 baseDuration, CountermeasureIntensity intensity);
    void addTimingJitter(qint64 minDelay, qint64 maxDelay);

    // Decoy management
    QList<CountermeasureType> generateDecoyCountermeasures(CountermeasureType primaryType, int count);
    bool shouldDeployDecoy(CountermeasureType primaryType);
    void manageDecoyLifecycle();

    // Anti-pattern detection
    void analyzeDeploymentHistory(const QList<CountermeasureType> &recentDeployments);
    bool detectPredictablePattern(const QList<CountermeasureType> &sequence);
    void adjustRandomizationBias();

    // Security monitoring
    void enableRandomizationLogging(bool enable);
    QStringList getRandomizationLogs() const;
    void clearRandomizationHistory();

    // Government mode adaptation
    void setGovernmentMode(bool enabled);
    RandomizedDeployment adaptForGovernmentMode(const RandomizedDeployment &deployment);

signals:
    void randomizationConfigChanged();
    void patternObfuscationUpdated();
    void predictablePatternDetected(const QList<CountermeasureType> &pattern);
    void decoyCountermeasureDeployed(CountermeasureType decoyType);

private slots:
    void updateRandomizationParameters();
    void rotateObfuscationPatterns();

private:
    // Randomization algorithms
    float generateSecureRandom(float min = 0.0f, float max = 1.0f);
    int generateSecureRandomInt(int min, int max);
    qint64 generateSecureRandomTime(qint64 base, float variance);

    // Selection randomization
    CountermeasureType selectRandomAlternative(CountermeasureType original);
    QList<CountermeasureType> shuffleCountermeasures(const QList<CountermeasureType> &measures);
    CountermeasureType selectFromEquivalentSet(CountermeasureType type);

    // Intensity randomization
    CountermeasureIntensity adjustIntensityRandomly(CountermeasureIntensity base, float variance);
    bool shouldIntensityEscalate(ThreatLevel threatLevel);
    CountermeasureIntensity clampIntensity(CountermeasureIntensity intensity);

    // Pattern generation
    QList<CountermeasureType> generateRandomPattern(int length);
    QList<qint64> generateTimingPattern(int length, qint64 baseInterval);
    QList<CountermeasureIntensity> generateIntensityPattern(int length, CountermeasureIntensity base);

    // Decoy implementation
    CountermeasureType generateDecoyType(CountermeasureType primary);
    bool isDecoyCompatible(CountermeasureType primary, CountermeasureType decoy);
    void scheduleDecoyRemoval(CountermeasureType decoyType, qint64 delay);

    // Pattern analysis
    float calculatePatternPredictability(const QList<CountermeasureType> &sequence);
    QList<CountermeasureType> identifyRepeatingSubsequence(const QList<CountermeasureType> &sequence);
    void updateBiasParameters(const QList<CountermeasureType> &predictablePattern);

    // Anti-analysis measures
    void implementAntiAnalysisMeasures();
    void randomizeRandomizationParameters();
    void obfuscateTimingPatterns();

    // Government mode adjustments
    RandomizedDeployment removeGovernmentIncompatibleElements(const RandomizedDeployment &deployment);
    bool isGovernmentCompatible(CountermeasureType type);

    // Security and monitoring
    void logRandomizationEvent(const QString &event, const QString &details);
    void updateRandomizationStatistics(const RandomizedDeployment &deployment);

private:
    RandomizationConfig _config;
    QMutex _randomization_mutex;
    bool _government_mode = false;
    bool _logging_enabled = true;

    // Randomization state
    QRandomGenerator *_secure_rng;
    qint64 _last_pattern_update = 0;
    PatternObfuscation _current_pattern;
    QList<PatternObfuscation> _pattern_history;

    // Deployment tracking
    QList<CountermeasureType> _recent_deployments;
    QList<CountermeasureType> _active_decoys;
    QMap<CountermeasureType, qint64> _deployment_timestamps;
    QMap<CountermeasureType, int> _deployment_counts;

    // Bias and adaptation
    QMap<CountermeasureType, float> _selection_bias;
    QMap<CountermeasureIntensity, float> _intensity_bias;
    float _timing_bias = 0.0f;
    int _pattern_changes = 0;

    // Statistics and monitoring
    QStringList _randomization_logs;
    qint64 _total_randomizations = 0;
    qint64 _decoys_deployed = 0;
    qint64 _patterns_detected = 0;

    // Timers
    QTimer *_pattern_rotation_timer;
    QTimer *_parameter_update_timer;
    QTimer *_decoy_cleanup_timer;

    // Equivalent countermeasure sets for randomization
    static const QMap<CountermeasureType, QList<CountermeasureType>> EQUIVALENT_MEASURES;
    static const QList<CountermeasureType> DECOY_COMPATIBLE_MEASURES;
    static const QMap<CountermeasureType, QList<CountermeasureType>> GOVERNMENT_SAFE_ALTERNATIVES;

    // Randomization constants
    static constexpr float MIN_TIMING_VARIANCE = 0.05f;
    static constexpr float MAX_TIMING_VARIANCE = 0.5f;
    static constexpr float MIN_INTENSITY_VARIANCE = 0.1f;
    static constexpr float MAX_INTENSITY_VARIANCE = 0.3f;
    static constexpr int MAX_PATTERN_HISTORY = 20;
    static constexpr int MAX_DEPLOYMENT_HISTORY = 100;
    static constexpr qint64 PATTERN_ROTATION_INTERVAL = 300000; // 5 minutes
    static constexpr qint64 PARAMETER_UPDATE_INTERVAL = 120000; // 2 minutes
    static constexpr int MAX_LOG_ENTRIES = 200;
};

} // namespace SpyGram::Counterintelligence