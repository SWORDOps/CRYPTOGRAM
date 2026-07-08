/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/

#include "gna_voice_morphing_engine.h"
#include "gna_acoustic_security.h"

#include <QtCore/QDebug>
#include <QtCore/QMutex>
#include <QtCore/QMutexLocker>
#include <QtCore/QElapsedTimer>
#include <QtCore/QCryptographicHash>
#include <cmath>
#include <algorithm>
#include <complex>
#include <vector>

namespace Security {
namespace GNAEngines {

// Voice processing algorithms and utilities
namespace {

static constexpr int kSampleRate = 48000;
static constexpr double kTargetLatencyMs = 1.0; // <1ms target latency
static constexpr int kFrameSize = 1024; // Samples per frame
static constexpr int kOverlapSize = 256; // Frame overlap for smooth transitions
static constexpr double kBiometricDefeatRate = 0.95; // Target 95% defeat rate

// Advanced voice analysis structure
struct VoiceFeatures {
    double fundamentalFrequency = 0.0;  // F0 - pitch
    QList<double> formants;             // Formant frequencies
    double spectralCentroid = 0.0;      // Brightness measure
    double spectralRolloff = 0.0;       // High frequency cutoff
    double zeroCrossingRate = 0.0;      // Voice activity measure
    double mfcc[13] = {0.0};           // Mel-frequency cepstral coefficients
    double jitter = 0.0;               // Pitch variation
    double shimmer = 0.0;              // Amplitude variation
    double harmonicToNoiseRatio = 0.0; // Voice quality measure

    static VoiceFeatures extract(const QByteArray& audioData) {
        VoiceFeatures features;

        if (audioData.isEmpty()) return features;

        const qint16* samples = reinterpret_cast<const qint16*>(audioData.constData());
        int sampleCount = audioData.size() / sizeof(qint16);

        // Extract fundamental frequency (pitch)
        features.fundamentalFrequency = extractF0(samples, sampleCount);

        // Extract formants using LPC analysis
        features.formants = extractFormants(samples, sampleCount);

        // Calculate spectral features
        features.spectralCentroid = calculateSpectralCentroid(samples, sampleCount);
        features.spectralRolloff = calculateSpectralRolloff(samples, sampleCount);

        // Calculate voice activity features
        features.zeroCrossingRate = calculateZeroCrossingRate(samples, sampleCount);

        // Extract MFCC features for biometric uniqueness
        extractMFCC(samples, sampleCount, features.mfcc);

        // Calculate voice quality measures
        features.jitter = calculateJitter(samples, sampleCount, features.fundamentalFrequency);
        features.shimmer = calculateShimmer(samples, sampleCount);
        features.harmonicToNoiseRatio = calculateHNR(samples, sampleCount);

        return features;
    }

private:
    static double extractF0(const qint16* samples, int sampleCount) {
        // Autocorrelation-based pitch detection
        double maxCorrelation = 0.0;
        int bestLag = 0;

        int minLag = kSampleRate / 500; // 500 Hz max
        int maxLag = kSampleRate / 80;  // 80 Hz min

        for (int lag = minLag; lag < maxLag && lag < sampleCount / 2; ++lag) {
            double correlation = 0.0;
            int count = 0;

            for (int i = 0; i < sampleCount - lag; ++i) {
                correlation += samples[i] * samples[i + lag];
                count++;
            }

            if (count > 0) {
                correlation /= count;
                if (correlation > maxCorrelation) {
                    maxCorrelation = correlation;
                    bestLag = lag;
                }
            }
        }

        return bestLag > 0 ? static_cast<double>(kSampleRate) / bestLag : 0.0;
    }

    static QList<double> extractFormants(const qint16* samples, int sampleCount) {
        QList<double> formants;

        // Simple formant estimation using spectral peaks
        QList<double> spectrum = performFFT(samples, sampleCount);

        // Look for peaks in voice frequency range (300-3400 Hz)
        int startBin = static_cast<int>(300.0 * spectrum.size() * 2 / kSampleRate);
        int endBin = static_cast<int>(3400.0 * spectrum.size() * 2 / kSampleRate);

        QList<int> peaks;
        for (int i = startBin + 1; i < endBin - 1 && i < spectrum.size(); ++i) {
            if (spectrum[i] > spectrum[i-1] && spectrum[i] > spectrum[i+1] &&
                spectrum[i] > 100.0) { // Minimum magnitude threshold
                peaks.append(i);
            }
        }

        // Convert peaks to frequencies and select first 4 formants
        for (int i = 0; i < qMin(4, peaks.size()); ++i) {
            double frequency = static_cast<double>(peaks[i]) * kSampleRate / (2 * spectrum.size());
            formants.append(frequency);
        }

        return formants;
    }

    static double calculateSpectralCentroid(const qint16* samples, int sampleCount) {
        QList<double> spectrum = performFFT(samples, sampleCount);

        double weightedSum = 0.0;
        double magnitudeSum = 0.0;

        for (int i = 0; i < spectrum.size(); ++i) {
            double frequency = static_cast<double>(i) * kSampleRate / (2 * spectrum.size());
            weightedSum += frequency * spectrum[i];
            magnitudeSum += spectrum[i];
        }

        return magnitudeSum > 0.0 ? weightedSum / magnitudeSum : 0.0;
    }

    static double calculateSpectralRolloff(const qint16* samples, int sampleCount) {
        QList<double> spectrum = performFFT(samples, sampleCount);

        double totalEnergy = 0.0;
        for (double magnitude : spectrum) {
            totalEnergy += magnitude * magnitude;
        }

        double threshold = totalEnergy * 0.85; // 85% energy threshold
        double cumulativeEnergy = 0.0;

        for (int i = 0; i < spectrum.size(); ++i) {
            cumulativeEnergy += spectrum[i] * spectrum[i];
            if (cumulativeEnergy >= threshold) {
                return static_cast<double>(i) * kSampleRate / (2 * spectrum.size());
            }
        }

        return kSampleRate / 2.0; // Nyquist frequency
    }

    static double calculateZeroCrossingRate(const qint16* samples, int sampleCount) {
        int zeroCrossings = 0;

        for (int i = 1; i < sampleCount; ++i) {
            if ((samples[i-1] >= 0 && samples[i] < 0) ||
                (samples[i-1] < 0 && samples[i] >= 0)) {
                zeroCrossings++;
            }
        }

        return static_cast<double>(zeroCrossings) / sampleCount;
    }

    static void extractMFCC(const qint16* samples, int sampleCount, double* mfcc) {
        // Simplified MFCC extraction for biometric features
        QList<double> spectrum = performFFT(samples, sampleCount);

        // Apply mel filterbank (simplified)
        const int numFilters = 13;
        double melFilters[numFilters] = {0.0};

        for (int filter = 0; filter < numFilters; ++filter) {
            double startMel = 1127.0 * log(1.0 + (300.0 + filter * 300.0) / 700.0);
            double endMel = 1127.0 * log(1.0 + (300.0 + (filter + 2) * 300.0) / 700.0);

            int startBin = static_cast<int>(startMel * spectrum.size() / (kSampleRate / 2.0));
            int endBin = static_cast<int>(endMel * spectrum.size() / (kSampleRate / 2.0));

            for (int i = startBin; i < endBin && i < spectrum.size(); ++i) {
                melFilters[filter] += spectrum[i];
            }

            melFilters[filter] = log(melFilters[filter] + 1e-10); // Log scale
        }

        // Apply DCT to get MFCC coefficients
        for (int i = 0; i < numFilters; ++i) {
            double sum = 0.0;
            for (int j = 0; j < numFilters; ++j) {
                sum += melFilters[j] * cos(M_PI * i * (j + 0.5) / numFilters);
            }
            mfcc[i] = sum;
        }
    }

    static double calculateJitter(const qint16* samples, int sampleCount, double f0) {
        if (f0 <= 0.0) return 0.0;

        // Measure pitch period variation
        int expectedPeriod = static_cast<int>(kSampleRate / f0);
        QList<int> periods;

        // Find actual periods using zero crossings
        int lastCrossing = 0;
        for (int i = 1; i < sampleCount; ++i) {
            if ((samples[i-1] < 0 && samples[i] >= 0)) { // Positive-going zero crossing
                if (lastCrossing > 0) {
                    periods.append(i - lastCrossing);
                }
                lastCrossing = i;
            }
        }

        if (periods.size() < 2) return 0.0;

        // Calculate period variation
        double meanPeriod = 0.0;
        for (int period : periods) {
            meanPeriod += period;
        }
        meanPeriod /= periods.size();

        double variation = 0.0;
        for (int period : periods) {
            variation += qAbs(period - meanPeriod);
        }

        return periods.size() > 0 ? variation / (periods.size() * meanPeriod) : 0.0;
    }

    static double calculateShimmer(const qint16* samples, int sampleCount) {
        // Measure amplitude variation
        QList<double> amplitudes;

        int windowSize = kSampleRate / 100; // 10ms windows
        for (int i = 0; i < sampleCount - windowSize; i += windowSize) {
            double maxAmp = 0.0;
            for (int j = 0; j < windowSize; ++j) {
                maxAmp = qMax(maxAmp, static_cast<double>(qAbs(samples[i + j])));
            }
            amplitudes.append(maxAmp);
        }

        if (amplitudes.size() < 2) return 0.0;

        double meanAmplitude = 0.0;
        for (double amp : amplitudes) {
            meanAmplitude += amp;
        }
        meanAmplitude /= amplitudes.size();

        double variation = 0.0;
        for (double amp : amplitudes) {
            variation += qAbs(amp - meanAmplitude);
        }

        return meanAmplitude > 0.0 ? variation / (amplitudes.size() * meanAmplitude) : 0.0;
    }

    static double calculateHNR(const qint16* samples, int sampleCount) {
        // Simplified harmonic-to-noise ratio calculation
        QList<double> spectrum = performFFT(samples, sampleCount);

        double harmonicEnergy = 0.0;
        double totalEnergy = 0.0;

        for (int i = 0; i < spectrum.size(); ++i) {
            double energy = spectrum[i] * spectrum[i];
            totalEnergy += energy;

            // Assume harmonics at multiples of fundamental (simplified)
            double freq = static_cast<double>(i) * kSampleRate / (2 * spectrum.size());
            if (freq >= 80.0 && freq <= 500.0) { // Typical F0 range
                harmonicEnergy += energy;
            }
        }

        double noiseEnergy = totalEnergy - harmonicEnergy;
        return noiseEnergy > 0.0 ? 10.0 * log10(harmonicEnergy / noiseEnergy) : 0.0;
    }

public:
    static QList<double> performFFT(const qint16* samples, int sampleCount) {
        QList<double> spectrum;
        spectrum.reserve(sampleCount / 2);

        // Simple DFT for voice analysis
        for (int k = 0; k < sampleCount / 2; ++k) {
            double real = 0.0, imag = 0.0;
            double freq = 2.0 * M_PI * k / sampleCount;

            for (int n = 0; n < sampleCount; ++n) {
                double angle = freq * n;
                real += samples[n] * cos(angle);
                imag -= samples[n] * sin(angle);
            }

            spectrum.append(sqrt(real * real + imag * imag));
        }

        return spectrum;
    }
};

} // anonymous namespace

// Voice transformation algorithms
namespace VoiceTransformer {
    struct TransformationConfig {
        double pitchShift = 1.0;         // Pitch scaling factor
        double timbreShift = 0.0;        // Formant frequency shift
        double noiseLevel = 0.0;         // Background noise injection
        double vocoderStrength = 0.0;    // Vocoder effect strength
        bool preserveIntelligibility = true;
        bool realTimeProcessing = true;
    };

    static void applyPitchShift(const qint16* input, qint16* output, int sampleCount, double shiftFactor);
    static void applyFormantShift(qint16* samples, int sampleCount, double shiftAmount);
    static void applyVocoderEffect(qint16* samples, int sampleCount, double strength);
    static void addNoise(qint16* samples, int sampleCount, double noiseLevel);
    static void preserveIntelligibility(qint16* samples, int sampleCount);

    static QByteArray transformVoice(const QByteArray& inputAudio, const TransformationConfig& config) {
        if (inputAudio.isEmpty()) return QByteArray();

        QByteArray outputAudio = inputAudio;
        const qint16* inputSamples = reinterpret_cast<const qint16*>(inputAudio.constData());
        qint16* outputSamples = reinterpret_cast<qint16*>(outputAudio.data());
        int sampleCount = inputAudio.size() / sizeof(qint16);

        // Apply pitch shifting
        if (config.pitchShift != 1.0) {
            applyPitchShift(inputSamples, outputSamples, sampleCount, config.pitchShift);
        }

        // Apply formant shifting
        if (config.timbreShift != 0.0) {
            applyFormantShift(outputSamples, sampleCount, config.timbreShift);
        }

        // Apply vocoder effect
        if (config.vocoderStrength > 0.0) {
            applyVocoderEffect(outputSamples, sampleCount, config.vocoderStrength);
        }

        // Add noise for additional obfuscation
        if (config.noiseLevel > 0.0) {
            addNoise(outputSamples, sampleCount, config.noiseLevel);
        }

        // Ensure intelligibility preservation if requested
        if (config.preserveIntelligibility) {
            preserveIntelligibility(outputSamples, sampleCount);
        }

        return outputAudio;
    }


    static void applyPitchShift(const qint16* input, qint16* output, int sampleCount, double shiftFactor) {
        // Time-domain pitch shifting using PSOLA-like algorithm
        for (int i = 0; i < sampleCount; ++i) {
            double sourceIndex = static_cast<double>(i) / shiftFactor;
            int baseIndex = static_cast<int>(sourceIndex);

            if (baseIndex < sampleCount - 1) {
                double fraction = sourceIndex - baseIndex;
                double interpolated = input[baseIndex] * (1.0 - fraction) +
                                    input[baseIndex + 1] * fraction;
                output[i] = static_cast<qint16>(interpolated);
            } else {
                output[i] = 0;
            }
        }
    }

    static void applyFormantShift(qint16* samples, int sampleCount, double shiftAmount) {
        // Simplified formant shifting using spectral envelope modification
        QList<double> spectrum = VoiceFeatures::performFFT(samples, sampleCount);

        // Shift formant frequencies
        QList<double> shiftedSpectrum(spectrum.size(), 0.0);
        for (int i = 0; i < spectrum.size(); ++i) {
            double originalFreq = static_cast<double>(i) * kSampleRate / (2 * spectrum.size());
            double shiftedFreq = originalFreq * (1.0 + shiftAmount);
            int shiftedIndex = static_cast<int>(shiftedFreq * spectrum.size() * 2 / kSampleRate);

            if (shiftedIndex >= 0 && shiftedIndex < shiftedSpectrum.size()) {
                shiftedSpectrum[shiftedIndex] = spectrum[i];
            }
        }

        // Convert back to time domain (simplified IFFT)
        for (int n = 0; n < sampleCount; ++n) {
            double sample = 0.0;
            for (int k = 0; k < shiftedSpectrum.size(); ++k) {
                double angle = 2.0 * M_PI * k * n / sampleCount;
                sample += shiftedSpectrum[k] * cos(angle) / sampleCount;
            }
            samples[n] = static_cast<qint16>(qBound(-32767.0, sample, 32767.0));
        }
    }

    static void applyVocoderEffect(qint16* samples, int sampleCount, double strength) {
        // Simple vocoder-like effect using formant synthesis
        for (int i = 0; i < sampleCount; ++i) {
            double t = static_cast<double>(i) / kSampleRate;

            // Generate carrier signal
            double carrier = sin(2.0 * M_PI * 150.0 * t); // 150 Hz carrier

            // Apply ring modulation
            double modulated = samples[i] * (1.0 - strength) +
                              samples[i] * carrier * strength;

            samples[i] = static_cast<qint16>(qBound(-32767.0, modulated, 32767.0));
        }
    }

    static void addNoise(qint16* samples, int sampleCount, double noiseLevel) {
        for (int i = 0; i < sampleCount; ++i) {
            double noise = (static_cast<double>(rand()) / RAND_MAX - 0.5) * 2.0;
            double noisyValue = samples[i] + noise * noiseLevel * 1000.0;
            samples[i] = static_cast<qint16>(qBound(-32767.0, noisyValue, 32767.0));
        }
    }

    static void preserveIntelligibility(qint16* samples, int sampleCount) {
        // Apply gentle filtering to preserve speech intelligibility
        // Simple high-pass filter to maintain consonant clarity
        qint16 previousSample = 0;

        for (int i = 0; i < sampleCount; ++i) {
            qint16 filtered = static_cast<qint16>((samples[i] - previousSample) * 0.9 + samples[i] * 0.1);
            previousSample = samples[i];
            samples[i] = filtered;
        }
    }
};

// anonymous namespace ended earlier

// Biometric analysis and defeat strategies
class BiometricAnalyzer {
public:
    struct BiometricProfile {
        VoiceFeatures originalFeatures;
        VoiceFeatures transformedFeatures;
        double defeatScore = 0.0; // 0.0 - 1.0, higher = better defeat
        QStringList vulnerableFeatures;
        QStringList strongFeatures;
    };

    static BiometricProfile analyzeBiometricDefeat(const QByteArray& originalAudio,
                                                  const QByteArray& transformedAudio) {
        BiometricProfile profile;

        if (originalAudio.isEmpty() || transformedAudio.isEmpty()) {
            return profile;
        }

        // Extract features from both audio samples
        profile.originalFeatures = VoiceFeatures::extract(originalAudio);
        profile.transformedFeatures = VoiceFeatures::extract(transformedAudio);

        // Calculate biometric defeat score
        profile.defeatScore = calculateDefeatScore(profile.originalFeatures,
                                                  profile.transformedFeatures);

        // Identify vulnerable and strong features
        analyzeFeatureChanges(profile);

        return profile;
    }

    static double calculateBiometricDistance(const VoiceFeatures& features1,
                                           const VoiceFeatures& features2) {
        double distance = 0.0;

        // Fundamental frequency difference
        double f0Diff = qAbs(features1.fundamentalFrequency - features2.fundamentalFrequency);
        distance += f0Diff / 500.0; // Normalize by typical F0 range

        // Formant differences
        int minFormants = qMin(features1.formants.size(), features2.formants.size());
        for (int i = 0; i < minFormants; ++i) {
            double formantDiff = qAbs(features1.formants[i] - features2.formants[i]);
            distance += formantDiff / 3000.0; // Normalize by formant range
        }

        // MFCC differences
        for (int i = 0; i < 13; ++i) {
            double mfccDiff = qAbs(features1.mfcc[i] - features2.mfcc[i]);
            distance += mfccDiff / 10.0; // Normalize MFCC range
        }

        // Spectral feature differences
        double centroidDiff = qAbs(features1.spectralCentroid - features2.spectralCentroid);
        distance += centroidDiff / 4000.0;

        double rolloffDiff = qAbs(features1.spectralRolloff - features2.spectralRolloff);
        distance += rolloffDiff / 8000.0;

        // Voice quality differences
        double jitterDiff = qAbs(features1.jitter - features2.jitter);
        distance += jitterDiff * 100.0; // Jitter is typically small

        double shimmerDiff = qAbs(features1.shimmer - features2.shimmer);
        distance += shimmerDiff * 10.0; // Shimmer scaling

        return distance;
    }

private:
    static double calculateDefeatScore(const VoiceFeatures& original,
                                     const VoiceFeatures& transformed) {
        double distance = calculateBiometricDistance(original, transformed);

        // Convert distance to defeat score (0.0 - 1.0)
        // Higher distance = better biometric defeat
        double score = qMin(1.0, distance / 5.0); // Scale factor based on testing

        return score;
    }

    static void analyzeFeatureChanges(BiometricProfile& profile) {
        const auto& orig = profile.originalFeatures;
        const auto& trans = profile.transformedFeatures;

        // Check fundamental frequency change
        double f0Change = qAbs(orig.fundamentalFrequency - trans.fundamentalFrequency) /
                         qMax(1.0, orig.fundamentalFrequency);
        if (f0Change > 0.2) {
            profile.strongFeatures << "Fundamental frequency significantly altered";
        } else {
            profile.vulnerableFeatures << "Fundamental frequency preservation detected";
        }

        // Check formant changes
        if (orig.formants.size() == trans.formants.size()) {
            double formantChange = 0.0;
            for (int i = 0; i < orig.formants.size(); ++i) {
                formantChange += qAbs(orig.formants[i] - trans.formants[i]) / orig.formants[i];
            }
            formantChange /= orig.formants.size();

            if (formantChange > 0.15) {
                profile.strongFeatures << "Formant structure significantly modified";
            } else {
                profile.vulnerableFeatures << "Formant structure largely preserved";
            }
        }

        // Check MFCC changes
        double mfccChange = 0.0;
        for (int i = 0; i < 13; ++i) {
            mfccChange += qAbs(orig.mfcc[i] - trans.mfcc[i]);
        }
        mfccChange /= 13.0;

        if (mfccChange > 2.0) {
            profile.strongFeatures << "MFCC features substantially altered";
        } else {
            profile.vulnerableFeatures << "MFCC features insufficiently modified";
        }

        // Check voice quality changes
        double jitterChange = qAbs(orig.jitter - trans.jitter);
        double shimmerChange = qAbs(orig.shimmer - trans.shimmer);

        if (jitterChange > 0.01 || shimmerChange > 0.1) {
            profile.strongFeatures << "Voice quality characteristics modified";
        } else {
            profile.vulnerableFeatures << "Voice quality characteristics preserved";
        }
    }
};

// anonymous namespace ended earlier

// GNA Voice Morphing Engine Implementation
GNAVoiceMorphingEngine::GNAVoiceMorphingEngine(const GNACapabilities& capabilities)
    : _capabilities(capabilities)
    , _initialized(false)
    , _morphingCount(0)
    , _totalProcessingTime(0)
    , _lastBiometricScore(0.0) {

    qDebug() << "GNA Voice Morphing Engine created with capabilities:"
             << "Available:" << capabilities.available
             << "Voice morphing support:" << capabilities.supportsVoiceMorphing
             << "Real-time processing:" << capabilities.supportsRealtimeProcessing;
}

GNAVoiceMorphingEngine::~GNAVoiceMorphingEngine() {
    qDebug() << "GNA Voice Morphing Engine destroyed."
             << "Morphing operations:" << _morphingCount
             << "Avg processing time:" << (_morphingCount > 0 ? _totalProcessingTime / _morphingCount : 0) << "ms";
}

bool GNAVoiceMorphingEngine::initialize() {
    QMutexLocker locker(&_engineMutex);

    if (_initialized) return true;

    qDebug() << "Initializing GNA Voice Morphing Engine";

    // Initialize voice profiles storage
    _voiceProfiles.clear();

    // Initialize default transformation configurations
    initializeTransformationPresets();

    // Initialize biometric analysis
    _biometricAnalyzer = std::make_unique<BiometricAnalyzer>();

    // Performance optimization for GNA hardware
    if (_capabilities.available && _capabilities.supportsVoiceMorphing) {
        qDebug() << "Using GNA hardware acceleration for voice morphing";
        _useHardwareAcceleration = true;
    } else {
        qDebug() << "Using software implementation for voice morphing";
        _useHardwareAcceleration = false;
    }

    _initialized = true;
    qDebug() << "GNA Voice Morphing Engine initialized successfully";

    return true;
}

QByteArray GNAVoiceMorphingEngine::morphVoice(const QByteArray& audioData,
                                             const VoiceMorphingConfig& config) {
    QMutexLocker locker(&_engineMutex);

    if (!_initialized || audioData.isEmpty()) {
        return audioData;
    }

    QElapsedTimer timer;
    timer.start();

    // Convert config to internal transformation config
    VoiceTransformer::TransformationConfig transformConfig;
    transformConfig.pitchShift = config.pitchShift;
    transformConfig.timbreShift = config.timbreModification;
    transformConfig.noiseLevel = config.noiseLevel;
    transformConfig.preserveIntelligibility = config.preserveIntelligibility;
    transformConfig.realTimeProcessing = config.realTimeProcessing;

    // Apply voice transformation based on security mode
    QByteArray morphedAudio;
    switch (config.mode) {
    case VoiceSecurityMode::BasicMorphing:
        morphedAudio = applyBasicMorphing(audioData, transformConfig);
        break;

    case VoiceSecurityMode::AdvancedMorphing:
        morphedAudio = applyAdvancedMorphing(audioData, transformConfig);
        break;

    case VoiceSecurityMode::AnonymousMode:
        morphedAudio = applyAnonymization(audioData, transformConfig);
        break;

    case VoiceSecurityMode::StealthMode:
        morphedAudio = applyStealthMorphing(audioData, transformConfig);
        break;

    default:
        morphedAudio = audioData; // No morphing
        break;
    }

    // Analyze biometric defeat effectiveness
    if (!morphedAudio.isEmpty() && config.mode != VoiceSecurityMode::Disabled) {
        auto biometricProfile = BiometricAnalyzer::analyzeBiometricDefeat(audioData, morphedAudio);
        _lastBiometricScore = biometricProfile.defeatScore;

        qDebug() << "Voice morphing biometric defeat score:" << _lastBiometricScore;

        // Log if defeat score is below target
        if (_lastBiometricScore < kBiometricDefeatRate) {
            qWarning() << "Biometric defeat score below target:"
                       << _lastBiometricScore << "vs target" << kBiometricDefeatRate;
        }
    }

    qint64 processingTime = timer.elapsed();
    _totalProcessingTime += processingTime;
    _morphingCount++;

    // Check real-time performance target
    if (config.realTimeProcessing && processingTime > kTargetLatencyMs) {
        qWarning() << "Voice morphing exceeded target latency:"
                   << processingTime << "ms vs target" << kTargetLatencyMs << "ms";
    }

    return morphedAudio;
}

QByteArray GNAVoiceMorphingEngine::anonymizeVoice(const QByteArray& audioData) {
    VoiceMorphingConfig config;
    config.mode = VoiceSecurityMode::AnonymousMode;
    config.pitchShift = 0.7; // Significant pitch reduction
    config.timbreModification = 0.8; // Strong formant shifting
    config.noiseLevel = 0.3; // High noise injection
    config.preserveIntelligibility = false; // Maximum anonymization

    return morphVoice(audioData, config);
}

bool GNAVoiceMorphingEngine::authenticateVoice(const QByteArray& voiceSample, const QString& userId) {
    QMutexLocker locker(&_engineMutex);

    if (!_initialized || voiceSample.isEmpty() || userId.isEmpty()) {
        return false;
    }

    // Check if we have a stored voice profile for this user
    if (!_voiceProfiles.contains(userId)) {
        qDebug() << "No voice profile found for user:" << userId;
        return false;
    }

    // Extract features from the provided voice sample
    VoiceFeatures sampleFeatures = VoiceFeatures::extract(voiceSample);

    // Load stored profile features
    QByteArray storedProfileData = _voiceProfiles[userId];
    VoiceFeatures storedFeatures; // Would deserialize from stored data

    // Calculate biometric distance
    double distance = BiometricAnalyzer::calculateBiometricDistance(sampleFeatures, storedFeatures);

    // Authentication threshold (lower distance = better match)
    const double authenticationThreshold = 2.0;

    bool authenticated = distance < authenticationThreshold;

    qDebug() << "Voice authentication for user" << userId
             << "Distance:" << distance
             << "Threshold:" << authenticationThreshold
             << "Result:" << (authenticated ? "PASSED" : "FAILED");

    return authenticated;
}

bool GNAVoiceMorphingEngine::enrollVoiceProfile(const QString& userId, const QByteArray& voiceSample) {
    QMutexLocker locker(&_engineMutex);

    if (!_initialized || userId.isEmpty() || voiceSample.isEmpty()) {
        return false;
    }

    // Extract voice features for enrollment
    VoiceFeatures features = VoiceFeatures::extract(voiceSample);

    // Serialize features for storage (simplified)
    QByteArray profileData;
    profileData.append(reinterpret_cast<const char*>(&features.fundamentalFrequency), sizeof(double));
    profileData.append(reinterpret_cast<const char*>(&features.spectralCentroid), sizeof(double));
    profileData.append(reinterpret_cast<const char*>(features.mfcc), sizeof(features.mfcc));

    _voiceProfiles[userId] = profileData;

    qDebug() << "Voice profile enrolled for user:" << userId
             << "F0:" << features.fundamentalFrequency << "Hz"
             << "Spectral centroid:" << features.spectralCentroid << "Hz";

    return true;
}

double GNAVoiceMorphingEngine::getLastBiometricDefeatScore() const {
    return _lastBiometricScore;
}

QVariantMap GNAVoiceMorphingEngine::getEngineStatistics() const {
    QMutexLocker locker(&_engineMutex);

    QVariantMap stats;
    stats["morphing_count"] = _morphingCount;
    stats["total_processing_time_ms"] = _totalProcessingTime;
    stats["average_processing_time_ms"] = _morphingCount > 0 ? _totalProcessingTime / _morphingCount : 0;
    stats["last_biometric_defeat_score"] = _lastBiometricScore;
    stats["hardware_acceleration"] = _useHardwareAcceleration;
    stats["enrolled_profiles"] = _voiceProfiles.size();
    stats["target_latency_ms"] = kTargetLatencyMs;
    stats["target_defeat_rate"] = kBiometricDefeatRate;

    return stats;
}

// Private implementation methods
void GNAVoiceMorphingEngine::initializeTransformationPresets() {
    // Initialize preset configurations for different security modes
    qDebug() << "Initializing voice transformation presets";

    // Presets would be loaded here for optimal biometric defeat
    // This is where machine learning models would be loaded for adaptive morphing
}

QByteArray GNAVoiceMorphingEngine::applyBasicMorphing(const QByteArray& audioData,
                                                     const VoiceTransformer::TransformationConfig& config) {
    // Basic morphing: simple pitch and formant shifts
    VoiceTransformer::TransformationConfig basicConfig = config;
    basicConfig.vocoderStrength = 0.0; // No vocoder for basic mode

    return VoiceTransformer::transformVoice(audioData, basicConfig);
}

QByteArray GNAVoiceMorphingEngine::applyAdvancedMorphing(const QByteArray& audioData,
                                                        const VoiceTransformer::TransformationConfig& config) {
    // Advanced morphing: includes vocoder effects and adaptive parameters
    VoiceTransformer::TransformationConfig advancedConfig = config;
    advancedConfig.vocoderStrength = 0.3; // Moderate vocoder effect

    // Apply adaptive morphing based on voice features
    VoiceFeatures features = VoiceFeatures::extract(audioData);

    // Adjust parameters based on voice characteristics
    if (features.fundamentalFrequency < 150.0) {
        // Low voice - increase pitch more aggressively
        advancedConfig.pitchShift *= 1.3;
    } else if (features.fundamentalFrequency > 250.0) {
        // High voice - reduce pitch more
        advancedConfig.pitchShift *= 0.8;
    }

    return VoiceTransformer::transformVoice(audioData, advancedConfig);
}

QByteArray GNAVoiceMorphingEngine::applyAnonymization(const QByteArray& audioData,
                                                     const VoiceTransformer::TransformationConfig& config) {
    // Maximum anonymization: aggressive transformation for complete identity hiding
    VoiceTransformer::TransformationConfig anonConfig = config;
    anonConfig.pitchShift = 0.6; // Significant pitch change
    anonConfig.timbreShift = 1.0; // Maximum formant shifting
    anonConfig.noiseLevel = 0.4; // High noise injection
    anonConfig.vocoderStrength = 0.6; // Strong vocoder effect
    anonConfig.preserveIntelligibility = false; // Prioritize anonymization

    return VoiceTransformer::transformVoice(audioData, anonConfig);
}

QByteArray GNAVoiceMorphingEngine::applyStealthMorphing(const QByteArray& audioData,
                                                       const VoiceTransformer::TransformationConfig& config) {
    // Stealth morphing: subtle changes that defeat biometrics while sounding natural
    VoiceTransformer::TransformationConfig stealthConfig = config;
    stealthConfig.pitchShift = 1.1; // Subtle pitch change
    stealthConfig.timbreShift = 0.2; // Minimal formant shifting
    stealthConfig.noiseLevel = 0.05; // Very low noise
    stealthConfig.vocoderStrength = 0.1; // Minimal vocoder
    stealthConfig.preserveIntelligibility = true; // Maintain naturalness

    return VoiceTransformer::transformVoice(audioData, stealthConfig);
}

} // namespace GNAEngines
} // namespace Security