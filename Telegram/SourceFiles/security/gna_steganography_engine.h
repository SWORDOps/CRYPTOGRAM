/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#pragma once

#include "gna_acoustic_security.h"
#include "base/bytes.h"

#include <QtCore/QObject>
#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtCore/QVariantMap>
#include <QtCore/QDateTime>
#include <QtMultimedia/QAudioFormat>
#include <memory>

namespace Security {

// Forward declarations
struct GNACapabilities;

namespace GNAEngines {

// Steganography method types
enum class SteganographyMethod {
    LSB,                    // Least Significant Bit hiding
    SpectralMasking,        // Frequency domain hiding
    EchoHiding,             // Echo-based steganography
    PhaseModulation,        // Phase-based embedding
    SpreadSpectrum,         // Spread spectrum steganography
    AdaptiveLSB,            // Adaptive LSB based on audio content
    PsychoacousticMasking,  // Psychoacoustic model-based hiding
    CepstrumModulation      // Cepstral domain steganography
};

// Steganography configuration
struct SteganographyConfig {
    SteganographyMethod method = SteganographyMethod::LSB;
    QString encryptionKey;               // AES-256 encryption key
    double embeddingStrength = 0.5;      // 0.0 - 1.0 (higher = more robust, lower = more imperceptible)
    bool adaptiveEmbedding = true;       // Adapt to audio content
    double targetSNR = 40.0;             // Target Signal-to-Noise Ratio in dB
    int maxPayloadSize = 1024;           // Maximum payload in bytes
    bool errorCorrection = true;         // Enable Reed-Solomon error correction
    QString compressionMethod = "zlib";   // Data compression before embedding
    double psychoacousticThreshold = 0.1; // Threshold for psychoacoustic masking
};

// Steganography analysis result
struct SteganographyAnalysis {
    bool dataDetected = false;
    SteganographyMethod detectedMethod = SteganographyMethod::LSB;
    double confidence = 0.0;             // 0.0 - 1.0
    int estimatedPayloadSize = 0;        // Estimated hidden data size in bytes
    double statisticalSignificance = 0.0; // Statistical test result
    QString analysisDetails;
    QDateTime analysisTime;
    qint64 analysisTimeMs = 0;
    double audioQualityScore = 0.0;      // Quality degradation measure
    QStringList detectionIndicators;     // List of detection indicators
};

// Steganography performance metrics
struct SteganographyMetrics {
    qint64 totalEmbeddings = 0;
    qint64 successfulEmbeddings = 0;
    qint64 totalExtractions = 0;
    qint64 successfulExtractions = 0;
    qint64 bytesEmbedded = 0;
    qint64 bytesExtracted = 0;
    double averageEmbeddingTime = 0.0;   // ms
    double averageExtractionTime = 0.0;  // ms
    double averageSNR = 0.0;             // dB
    double averageQualityScore = 0.0;    // Audio quality score
    QDateTime metricsStartTime;
    QDateTime lastUpdate;
};

// Embedding capacity estimation
struct EmbeddingCapacity {
    int maxBytesLSB = 0;                 // LSB method capacity
    int maxBytesSpectral = 0;            // Spectral masking capacity
    int maxBytesEcho = 0;                // Echo hiding capacity
    int maxBytesPhase = 0;               // Phase modulation capacity
    int recommendedBytes = 0;            // Recommended payload size
    double qualityImpactEstimate = 0.0;  // Estimated quality degradation
    QString optimalMethod;               // Recommended steganography method
};

/**
 * GNA Steganography Engine
 *
 * Provides advanced audio steganography capabilities for hiding data in audio streams
 * with statistical undetectability and high Signal-to-Noise Ratio maintenance.
 *
 * Key Features:
 * - Multiple steganography methods (LSB, spectral masking, echo hiding, etc.)
 * - 100 bits/second statistically undetectable embedding rate
 * - AES-256 encrypted payload protection
 * - SNR maintenance >40dB for detection resistance
 * - Adaptive embedding based on audio content analysis
 * - Psychoacoustic masking for imperceptible embedding
 * - Hardware acceleration with software fallback
 */
class GNASteganographyEngine final {
public:
    explicit GNASteganographyEngine(const GNACapabilities& capabilities);
    ~GNASteganographyEngine();

    // Initialization and configuration
    bool initialize();
    bool isInitialized() const { return _initialized; }
    void shutdown();

    // Core steganography operations
    QByteArray embedData(const QByteArray& audioData, const QByteArray& hiddenData);
    QByteArray extractData(const QByteArray& audioData);
    bool detectSteganography(const QByteArray& audioData);

    // Method-specific embedding
    QByteArray embedLSB(const QByteArray& audioData, const QByteArray& hiddenData);
    QByteArray embedSpectralMasking(const QByteArray& audioData, const QByteArray& hiddenData);
    QByteArray embedEchoHiding(const QByteArray& audioData, const QByteArray& hiddenData);
    QByteArray embedPhaseModulation(const QByteArray& audioData, const QByteArray& hiddenData);
    QByteArray embedSpreadSpectrum(const QByteArray& audioData, const QByteArray& hiddenData);

    // Method-specific extraction
    QByteArray extractLSB(const QByteArray& audioData);
    QByteArray extractSpectralMasking(const QByteArray& audioData);
    QByteArray extractEchoHiding(const QByteArray& audioData);
    QByteArray extractPhaseModulation(const QByteArray& audioData);
    QByteArray extractSpreadSpectrum(const QByteArray& audioData);

    // Advanced steganography analysis
    SteganographyAnalysis analyzeAudioForSteganography(const QByteArray& audioData);
    EmbeddingCapacity estimateEmbeddingCapacity(const QByteArray& audioData);
    double calculateAudioQualityScore(const QByteArray& original, const QByteArray& modified);

    // Configuration management
    void setConfiguration(const SteganographyConfig& config);
    SteganographyConfig getConfiguration() const { return _config; }
    void setMethod(SteganographyMethod method);
    SteganographyMethod getCurrentMethod() const { return _config.method; }

    // Encryption and security
    void setEncryptionKey(const QString& key);
    void clearEncryptionKey();
    bool isEncryptionEnabled() const { return !_config.encryptionKey.isEmpty(); }

    // Quality and robustness control
    void setEmbeddingStrength(double strength);
    void setTargetSNR(double targetSNR);
    void enableAdaptiveEmbedding(bool enabled);
    void setPsychoacousticThreshold(double threshold);

    // Capacity and performance
    int getMaxPayloadSize(const QByteArray& audioData, SteganographyMethod method = SteganographyMethod::LSB);
    double estimateQualityImpact(const QByteArray& audioData, int payloadSize);
    SteganographyMethod selectOptimalMethod(const QByteArray& audioData, int payloadSize);

    // Hardware acceleration
    void enableHardwareAcceleration();
    void disableHardwareAcceleration();
    bool isHardwareAccelerated() const { return _hardwareAccelerated; }

    // Performance monitoring
    SteganographyMetrics getPerformanceMetrics() const { return _metrics; }
    void resetMetrics();
    double getCurrentProcessingSpeed() const;

    // Testing and validation
    bool performSelfTest();
    QVariantMap getEngineStatistics() const;
    bool validateEmbeddingIntegrity(const QByteArray& original, const QByteArray& modified);

    // Statistical analysis
    double performChiSquareTest(const QByteArray& audioData);
    double performKolmogorovSmirnovTest(const QByteArray& audioData);
    bool passesStatisticalTests(const QByteArray& audioData);
    QStringList getStatisticalTestResults(const QByteArray& audioData);

private:
    // Initialization helpers
    void initializeSteganographyMethods();
    void initializePsychoacousticModel();
    void initializeStatisticalTests();
    void loadQualityMetrics();

    // Audio preprocessing
    QByteArray preprocessAudio(const QByteArray& audioData);
    QByteArray normalizeAudio(const QByteArray& audioData);
    QList<double> extractAudioFeatures(const QByteArray& audioData);
    QList<double> calculatePsychoacousticMask(const QByteArray& audioData);

    // LSB steganography implementation
    QByteArray embedLSBInternal(const QByteArray& audioData, const QByteArray& data);
    QByteArray extractLSBInternal(const QByteArray& audioData);
    QByteArray adaptiveLSBEmbedding(const QByteArray& audioData, const QByteArray& data);

    // Spectral masking implementation
    QByteArray embedSpectralMaskingInternal(const QByteArray& audioData, const QByteArray& data);
    QByteArray extractSpectralMaskingInternal(const QByteArray& audioData);
    QList<double> calculateSpectralMask(const QList<double>& spectrum);

    // Echo hiding implementation
    QByteArray embedEchoHidingInternal(const QByteArray& audioData, const QByteArray& data);
    QByteArray extractEchoHidingInternal(const QByteArray& audioData);
    QByteArray addEcho(const QByteArray& audioData, double delay, double amplitude);

    // Phase modulation implementation
    QByteArray embedPhaseModulationInternal(const QByteArray& audioData, const QByteArray& data);
    QByteArray extractPhaseModulationInternal(const QByteArray& audioData);
    QList<double> calculatePhaseSpectrum(const QByteArray& audioData);

    // Spread spectrum implementation
    QByteArray embedSpreadSpectrumInternal(const QByteArray& audioData, const QByteArray& data);
    QByteArray extractSpreadSpectrumInternal(const QByteArray& audioData);
    QByteArray generatePseudoRandomSequence(int length, const QString& seed);

    // Data preparation and recovery
    QByteArray prepareDataForEmbedding(const QByteArray& data);
    QByteArray recoverEmbeddedData(const QByteArray& extractedData);
    QByteArray addSteganographyHeader(const QByteArray& data);
    QByteArray removeSteganographyHeader(const QByteArray& data);

    // Encryption and compression
    QByteArray encryptData(const QByteArray& data);
    QByteArray decryptData(const QByteArray& encryptedData);
    QByteArray compressData(const QByteArray& data);
    QByteArray decompressData(const QByteArray& compressedData);

    // Error correction
    QByteArray addErrorCorrection(const QByteArray& data);
    QByteArray removeErrorCorrection(const QByteArray& data);
    bool validateErrorCorrection(const QByteArray& data);

    // Quality assessment
    double calculateSNR(const QByteArray& original, const QByteArray& modified);
    double calculatePSNR(const QByteArray& original, const QByteArray& modified);
    double calculatePerceptualQuality(const QByteArray& original, const QByteArray& modified);
    double calculateSpectralDistortion(const QByteArray& original, const QByteArray& modified);

    // Statistical analysis implementation
    double performChiSquareTestInternal(const QByteArray& audioData);
    double performKSTestInternal(const QByteArray& audioData);
    double calculateEntropy(const QByteArray& audioData);
    double calculateAutocorrelation(const QByteArray& audioData);

    // Hardware acceleration
    bool initializeGNAHardware();
    void configureHardwareAcceleration();
    void optimizeHardwareSettings();

    // Performance optimization
    void optimizeForAudioContent(const QByteArray& audioData);
    void selectOptimalParameters(const QByteArray& audioData, int payloadSize);
    void updatePerformanceMetrics(bool success, qint64 operationTime, const QString& operation);

    // Internal state
    bool _initialized = false;
    bool _hardwareAccelerated = false;
    GNACapabilities _capabilities;

    // Configuration
    SteganographyConfig _config;
    QAudioFormat _audioFormat;

    // Performance metrics
    mutable SteganographyMetrics _metrics;
    QDateTime _metricsStartTime;

    // Psychoacoustic model
    QList<double> _psychoacousticThresholds;
    QList<double> _maskingThresholds;
    QList<double> _criticalBandFrequencies;

    // Statistical test parameters
    double _chiSquareThreshold = 0.05;
    double _ksTestThreshold = 0.05;
    double _entropyThreshold = 7.8;

    // Hardware optimization
    bool _gnaHardwareAvailable = false;
    QString _hardwareProfile;
    QVariantMap _optimizationSettings;

    // Processing buffers
    QByteArray _processingBuffer;
    QByteArray _embeddingBuffer;
    QList<double> _spectralBuffer;
    QList<double> _phaseBuffer;

    // Quality assessment cache
    QHash<QString, double> _qualityCache;
    QHash<QString, EmbeddingCapacity> _capacityCache;

    // Method-specific parameters
    struct LSBParameters {
        int bitsPerSample = 1;
        bool adaptiveBits = true;
        QList<int> embeddingPattern;
    } _lsbParams;

    struct SpectralParameters {
        int fftSize = 1024;
        int overlapSize = 512;
        double maskingThreshold = 0.1;
        QList<int> embeddingBins;
    } _spectralParams;

    struct EchoParameters {
        double delayMs = 1.0;
        double amplitudeRatio = 0.1;
        int kernelSize = 256;
    } _echoParams;

    struct PhaseParameters {
        int fftSize = 1024;
        double phaseShift = M_PI / 8;
        QList<int> phaseIndices;
    } _phaseParams;

    struct SpreadSpectrumParameters {
        QString pseudoRandomSeed = "SPYGRAM_STEGO";
        int sequenceLength = 1023;
        double spreadingGain = 10.0;
    } _spreadParams;
};

} // namespace GNAEngines
} // namespace Security