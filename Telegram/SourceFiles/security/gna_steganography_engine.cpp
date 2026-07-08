/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#include "gna_steganography_engine.h"
#include "gna_acoustic_security.h"

#include <QtCore/QDebug>
#include <QtCore/QCryptographicHash>
#include <QtCore/QRandomGenerator>
#include <QtCore/QDataStream>
#include <QtCore/qglobal.h>
#include <QtCore/QByteArray>
#include <QtMultimedia/QAudioFormat>
#include <cmath>
#include <algorithm>
#include <complex>

namespace Security {
namespace GNAEngines {

// Constants for steganography operations
constexpr int DEFAULT_EMBEDDING_RATE = 100;  // bits per second
constexpr double DEFAULT_TARGET_SNR = 40.0;  // dB
constexpr double MIN_QUALITY_THRESHOLD = 0.8;  // Audio quality threshold
constexpr int MAX_PAYLOAD_BYTES = 1024;  // Maximum hidden payload
constexpr int HEADER_SIZE = 16;  // Steganography header size in bytes
constexpr double PSYCHOACOUSTIC_THRESHOLD = 0.1;
constexpr int FFT_SIZE = 1024;
constexpr int OVERLAP_SIZE = 512;

GNASteganographyEngine::GNASteganographyEngine(const GNACapabilities& capabilities)
    : _capabilities(capabilities) {

    qDebug() << "GNA Steganography Engine created with capabilities:"
             << "Device:" << capabilities.deviceName
             << "Power:" << capabilities.powerConsumptionWatts << "W"
             << "Max Channels:" << capabilities.maxChannels
             << "Sample Rate:" << capabilities.sampleRateHz << "Hz";

    // Initialize audio format
    _audioFormat.setSampleRate(_capabilities.sampleRateHz);
    _audioFormat.setChannelCount(qMin(_capabilities.maxChannels, 2));
    _audioFormat.setSampleFormat(QAudioFormat::Int16);
    // _audioFormat.setByteOrder(QAudioFormat::LittleEndian);

    // Initialize default configuration
    _config.method = SteganographyMethod::LSB;
    _config.embeddingStrength = 0.5;
    _config.adaptiveEmbedding = true;
    _config.targetSNR = DEFAULT_TARGET_SNR;
    _config.maxPayloadSize = MAX_PAYLOAD_BYTES;
    _config.errorCorrection = true;
    _config.compressionMethod = "zlib";
    _config.psychoacousticThreshold = PSYCHOACOUSTIC_THRESHOLD;

    // Initialize method-specific parameters
    _lsbParams.bitsPerSample = 1;
    _lsbParams.adaptiveBits = true;

    _spectralParams.fftSize = FFT_SIZE;
    _spectralParams.overlapSize = OVERLAP_SIZE;
    _spectralParams.maskingThreshold = 0.1;

    _echoParams.delayMs = 1.0;
    _echoParams.amplitudeRatio = 0.1;
    _echoParams.kernelSize = 256;

    _phaseParams.fftSize = FFT_SIZE;
    _phaseParams.phaseShift = M_PI / 8;

    _spreadParams.pseudoRandomSeed = "SPYGRAM_STEGO";
    _spreadParams.sequenceLength = 1023;
    _spreadParams.spreadingGain = 10.0;

    // Initialize statistics
    _metrics.metricsStartTime = QDateTime::currentDateTime();
    _metricsStartTime = _metrics.metricsStartTime;
}

GNASteganographyEngine::~GNASteganographyEngine() {
    qDebug() << "GNA Steganography Engine destroyed."
             << "Total embeddings:" << _metrics.totalEmbeddings
             << "Success rate:" << (_metrics.totalEmbeddings > 0 ?
                (double(_metrics.successfulEmbeddings) / _metrics.totalEmbeddings) * 100.0 : 0.0) << "%"
             << "Average SNR:" << _metrics.averageSNR << "dB";

    shutdown();
}

bool GNASteganographyEngine::initialize() {
    qDebug() << "Initializing GNA Steganography Engine";

    if (_initialized) {
        qDebug() << "Engine already initialized";
        return true;
    }

    try {
        // Initialize steganography methods
        initializeSteganographyMethods();

        // Initialize psychoacoustic model
        initializePsychoacousticModel();

        // Initialize statistical tests
        initializeStatisticalTests();

        // Load quality metrics
        loadQualityMetrics();

        // Initialize hardware if available
        if (_capabilities.available) {
            initializeGNAHardware();
        }

        _initialized = true;
        qDebug() << "GNA Steganography Engine initialized successfully";
        return true;

    } catch (const std::exception& e) {
        qCritical() << "Failed to initialize GNA Steganography Engine:" << e.what();
        return false;
    }
}

void GNASteganographyEngine::shutdown() {
    if (!_initialized) return;

    // Clear processing buffers
    _processingBuffer.clear();
    _embeddingBuffer.clear();
    _spectralBuffer.clear();
    _phaseBuffer.clear();

    // Clear caches
    _qualityCache.clear();
    _capacityCache.clear();

    _initialized = false;
    qDebug() << "GNA Steganography Engine shutdown complete";
}

QByteArray GNASteganographyEngine::embedData(const QByteArray& audioData, const QByteArray& hiddenData) {
    if (!_initialized) {
        qWarning() << "Engine not initialized";
        return QByteArray();
    }

    if (hiddenData.size() > _config.maxPayloadSize) {
        qWarning() << "Payload too large:" << hiddenData.size() << "bytes (max:" << _config.maxPayloadSize << ")";
        return QByteArray();
    }

    QDateTime startTime = QDateTime::currentDateTime();
    _metrics.totalEmbeddings++;

    try {
        // Prepare data for embedding
        QByteArray preparedData = prepareDataForEmbedding(hiddenData);

        // Select optimal method if adaptive embedding is enabled
        if (_config.adaptiveEmbedding) {
            SteganographyMethod optimalMethod = selectOptimalMethod(audioData, preparedData.size());
            if (optimalMethod != _config.method) {
                qDebug() << "Switching to optimal method:" << static_cast<int>(optimalMethod);
                _config.method = optimalMethod;
            }
        }

        // Embed data using selected method
        QByteArray result;
        switch (_config.method) {
            case SteganographyMethod::LSB:
                result = embedLSBInternal(audioData, preparedData);
                break;
            case SteganographyMethod::SpectralMasking:
                result = embedSpectralMaskingInternal(audioData, preparedData);
                break;
            case SteganographyMethod::EchoHiding:
                result = embedEchoHidingInternal(audioData, preparedData);
                break;
            case SteganographyMethod::PhaseModulation:
                result = embedPhaseModulationInternal(audioData, preparedData);
                break;
            case SteganographyMethod::SpreadSpectrum:
                result = embedSpreadSpectrumInternal(audioData, preparedData);
                break;
            case SteganographyMethod::AdaptiveLSB:
                result = adaptiveLSBEmbedding(audioData, preparedData);
                break;
            default:
                result = embedLSBInternal(audioData, preparedData);
                break;
        }

        // Calculate quality metrics
        double snr = calculateSNR(audioData, result);
        double qualityScore = calculateAudioQualityScore(audioData, result);

        // Update statistics
        qint64 operationTime = startTime.msecsTo(QDateTime::currentDateTime());
        bool success = !result.isEmpty() && snr >= _config.targetSNR && qualityScore >= MIN_QUALITY_THRESHOLD;

        updatePerformanceMetrics(success, operationTime, "embedding");

        if (success) {
            _metrics.bytesEmbedded += hiddenData.size();
            _metrics.successfulEmbeddings++;
            _metrics.averageSNR = (_metrics.averageSNR * (_metrics.successfulEmbeddings - 1) + snr) / _metrics.successfulEmbeddings;

            qDebug() << "Successfully embedded" << hiddenData.size() << "bytes"
                     << "Method:" << static_cast<int>(_config.method)
                     << "SNR:" << snr << "dB"
                     << "Quality:" << qualityScore
                     << "Time:" << operationTime << "ms";
        } else {
            qWarning() << "Embedding failed or quality below threshold"
                      << "SNR:" << snr << "dB (target:" << _config.targetSNR << ")"
                      << "Quality:" << qualityScore << "(min:" << MIN_QUALITY_THRESHOLD << ")";
        }

        return success ? result : QByteArray();

    } catch (const std::exception& e) {
        qCritical() << "Embedding exception:" << e.what();
        updatePerformanceMetrics(false, startTime.msecsTo(QDateTime::currentDateTime()), "embedding");
        return QByteArray();
    }
}

QByteArray GNASteganographyEngine::extractData(const QByteArray& audioData) {
    if (!_initialized) {
        qWarning() << "Engine not initialized";
        return QByteArray();
    }

    QDateTime startTime = QDateTime::currentDateTime();
    _metrics.totalExtractions++;

    try {
        // Try each method to find embedded data
        QByteArray extractedData;

        // First, try the current configured method
        switch (_config.method) {
            case SteganographyMethod::LSB:
            case SteganographyMethod::AdaptiveLSB:
                extractedData = extractLSBInternal(audioData);
                break;
            case SteganographyMethod::SpectralMasking:
                extractedData = extractSpectralMaskingInternal(audioData);
                break;
            case SteganographyMethod::EchoHiding:
                extractedData = extractEchoHidingInternal(audioData);
                break;
            case SteganographyMethod::PhaseModulation:
                extractedData = extractPhaseModulationInternal(audioData);
                break;
            case SteganographyMethod::SpreadSpectrum:
                extractedData = extractSpreadSpectrumInternal(audioData);
                break;
            default:
                extractedData = extractLSBInternal(audioData);
                break;
        }

        // If current method failed, try other methods
        if (extractedData.isEmpty()) {
            QList<SteganographyMethod> methodsToTry = {
                SteganographyMethod::LSB,
                SteganographyMethod::SpectralMasking,
                SteganographyMethod::EchoHiding,
                SteganographyMethod::PhaseModulation,
                SteganographyMethod::SpreadSpectrum
            };

            for (SteganographyMethod method : methodsToTry) {
                if (method == _config.method) continue;  // Already tried

                SteganographyMethod originalMethod = _config.method;
                _config.method = method;

                switch (method) {
                    case SteganographyMethod::LSB:
                        extractedData = extractLSBInternal(audioData);
                        break;
                    case SteganographyMethod::SpectralMasking:
                        extractedData = extractSpectralMaskingInternal(audioData);
                        break;
                    case SteganographyMethod::EchoHiding:
                        extractedData = extractEchoHidingInternal(audioData);
                        break;
                    case SteganographyMethod::PhaseModulation:
                        extractedData = extractPhaseModulationInternal(audioData);
                        break;
                    case SteganographyMethod::SpreadSpectrum:
                        extractedData = extractSpreadSpectrumInternal(audioData);
                        break;
                    default:
                        break;
                }

                if (!extractedData.isEmpty()) {
                    qDebug() << "Data found using method:" << static_cast<int>(method);
                    break;
                }

                _config.method = originalMethod;  // Restore original method
            }
        }

        // Recover embedded data
        QByteArray recoveredData = recoverEmbeddedData(extractedData);

        // Update statistics
        qint64 operationTime = startTime.msecsTo(QDateTime::currentDateTime());
        bool success = !recoveredData.isEmpty();

        updatePerformanceMetrics(success, operationTime, "extraction");

        if (success) {
            _metrics.bytesExtracted += recoveredData.size();
            _metrics.successfulExtractions++;

            qDebug() << "Successfully extracted" << recoveredData.size() << "bytes"
                     << "Time:" << operationTime << "ms";
        }

        return recoveredData;

    } catch (const std::exception& e) {
        qCritical() << "Extraction exception:" << e.what();
        updatePerformanceMetrics(false, startTime.msecsTo(QDateTime::currentDateTime()), "extraction");
        return QByteArray();
    }
}

bool GNASteganographyEngine::detectSteganography(const QByteArray& audioData) {
    if (!_initialized || audioData.isEmpty()) {
        return false;
    }

    // Perform comprehensive steganography analysis
    SteganographyAnalysis analysis = analyzeAudioForSteganography(audioData);
    return analysis.dataDetected && analysis.confidence > 0.7;
}

SteganographyAnalysis GNASteganographyEngine::analyzeAudioForSteganography(const QByteArray& audioData) {
    SteganographyAnalysis analysis;
    analysis.analysisTime = QDateTime::currentDateTime();
    QDateTime startTime = analysis.analysisTime;

    try {
        // Statistical tests
        double chiSquare = performChiSquareTestInternal(audioData);
        double ksTest = performKSTestInternal(audioData);
        double entropy = calculateEntropy(audioData);
        double autocorr = calculateAutocorrelation(audioData);

        // Quality assessment
        analysis.audioQualityScore = calculatePerceptualQuality(audioData, audioData);

        // Detection logic
        analysis.dataDetected = (chiSquare > _chiSquareThreshold) ||
                               (ksTest > _ksTestThreshold) ||
                               (entropy > _entropyThreshold) ||
                               (autocorr < 0.8);

        if (analysis.dataDetected) {
            // Estimate method used
            if (chiSquare > 0.1) {
                analysis.detectedMethod = SteganographyMethod::LSB;
                analysis.confidence = qMin(1.0, chiSquare * 2.0);
            } else if (entropy > 7.9) {
                analysis.detectedMethod = SteganographyMethod::SpectralMasking;
                analysis.confidence = qMin(1.0, (entropy - 7.8) * 5.0);
            } else if (autocorr < 0.7) {
                analysis.detectedMethod = SteganographyMethod::EchoHiding;
                analysis.confidence = qMin(1.0, (0.8 - autocorr) * 5.0);
            } else {
                analysis.detectedMethod = SteganographyMethod::PhaseModulation;
                analysis.confidence = 0.5;
            }

            // Estimate payload size
            analysis.estimatedPayloadSize = static_cast<int>(audioData.size() * 0.1 * analysis.confidence);

            analysis.detectionIndicators.append("Statistical anomaly detected");
            analysis.analysisDetails = QString("Chi-square: %1, KS-test: %2, Entropy: %3, Autocorr: %4")
                                     .arg(chiSquare).arg(ksTest).arg(entropy).arg(autocorr);
        } else {
            analysis.confidence = 0.0;
            analysis.analysisDetails = "No steganographic content detected";
        }

        analysis.statisticalSignificance = std::max({chiSquare, ksTest, entropy - 7.8, 0.8 - autocorr});

    } catch (const std::exception& e) {
        qWarning() << "Analysis exception:" << e.what();
        analysis.dataDetected = false;
        analysis.confidence = 0.0;
        analysis.analysisDetails = QString("Analysis failed: %1").arg(e.what());
    }

    analysis.analysisTimeMs = startTime.msecsTo(QDateTime::currentDateTime());
    return analysis;
}

EmbeddingCapacity GNASteganographyEngine::estimateEmbeddingCapacity(const QByteArray& audioData) {
    EmbeddingCapacity capacity;

    if (audioData.isEmpty()) {
        return capacity;
    }

    int sampleCount = audioData.size() / sizeof(qint16);

    // LSB capacity: 1 bit per sample typically
    capacity.maxBytesLSB = sampleCount / 8;

    // Spectral masking: depends on frequency content
    capacity.maxBytesSpectral = static_cast<int>(sampleCount * 0.05 / 8);  // 5% of samples

    // Echo hiding: limited by audio length and echo parameters
    capacity.maxBytesEcho = static_cast<int>(sampleCount * 0.01 / 8);  // 1% of samples

    // Phase modulation: depends on FFT bin count
    capacity.maxBytesPhase = static_cast<int>(sampleCount * 0.03 / 8);  // 3% of samples

    // Recommended capacity (conservative estimate)
    capacity.recommendedBytes = std::min({capacity.maxBytesLSB, capacity.maxBytesSpectral,
                                     capacity.maxBytesEcho, capacity.maxBytesPhase}) / 2;

    // Quality impact estimate
    capacity.qualityImpactEstimate = qMin(1.0, double(capacity.recommendedBytes) / audioData.size());

    // Optimal method recommendation
    if (capacity.maxBytesLSB >= capacity.recommendedBytes * 2) {
        capacity.optimalMethod = "LSB";
    } else if (capacity.maxBytesSpectral >= capacity.recommendedBytes) {
        capacity.optimalMethod = "SpectralMasking";
    } else {
        capacity.optimalMethod = "EchoHiding";
    }

    return capacity;
}

double GNASteganographyEngine::calculateAudioQualityScore(const QByteArray& original, const QByteArray& modified) {
    if (original.size() != modified.size()) {
        return 0.0;
    }

    // Calculate multiple quality metrics
    double snr = calculateSNR(original, modified);
    double psnr = calculatePSNR(original, modified);
    double perceptualQuality = calculatePerceptualQuality(original, modified);
    double spectralDistortion = calculateSpectralDistortion(original, modified);

    // Weighted combination of quality metrics
    double qualityScore = (snr / 60.0) * 0.3 +         // SNR contribution (normalized to 60dB max)
                         (psnr / 80.0) * 0.3 +          // PSNR contribution (normalized to 80dB max)
                         perceptualQuality * 0.2 +       // Perceptual quality
                         (1.0 - spectralDistortion) * 0.2; // Inverse spectral distortion

    return qBound(0.0, qualityScore, 1.0);
}

// LSB Implementation
QByteArray GNASteganographyEngine::embedLSBInternal(const QByteArray& audioData, const QByteArray& data) {
    if (audioData.size() < data.size() * 8 * sizeof(qint16)) {
        qWarning() << "Audio too short for LSB embedding";
        return QByteArray();
    }

    QByteArray result = audioData;
    qint16* samples = reinterpret_cast<qint16*>(result.data());
    int sampleCount = result.size() / sizeof(qint16);

    int bitIndex = 0;
    int bitsPerSample = _lsbParams.bitsPerSample;

    for (int byteIndex = 0; byteIndex < data.size() && bitIndex < sampleCount; byteIndex++) {
        quint8 dataByte = static_cast<quint8>(data[byteIndex]);

        for (int bit = 0; bit < 8 && bitIndex < sampleCount; bit += bitsPerSample) {
            // Extract bits to embed
            quint8 bitsToEmbed = (dataByte >> bit) & ((1 << bitsPerSample) - 1);

            // Clear LSBs and set new bits
            samples[bitIndex] = (samples[bitIndex] & ~((1 << bitsPerSample) - 1)) | bitsToEmbed;
            bitIndex++;
        }
    }

    return result;
}

QByteArray GNASteganographyEngine::extractLSBInternal(const QByteArray& audioData) {
    const qint16* samples = reinterpret_cast<const qint16*>(audioData.constData());
    int sampleCount = audioData.size() / sizeof(qint16);

    QByteArray extractedData;
    int bitsPerSample = _lsbParams.bitsPerSample;
    int bitIndex = 0;
    quint8 currentByte = 0;
    int bitsInCurrentByte = 0;

    // First, try to extract header to determine data size
    int headerBits = HEADER_SIZE * 8;
    QByteArray header;

    for (int i = 0; i < headerBits && bitIndex < sampleCount; i += bitsPerSample) {
        quint8 extractedBits = samples[bitIndex] & ((1 << bitsPerSample) - 1);
        currentByte |= (extractedBits << bitsInCurrentByte);
        bitsInCurrentByte += bitsPerSample;

        if (bitsInCurrentByte >= 8) {
            header.append(static_cast<char>(currentByte));
            currentByte = 0;
            bitsInCurrentByte = 0;
        }

        bitIndex++;
    }

    if (header.size() < HEADER_SIZE) {
        return QByteArray();
    }

    // Parse header to get actual data size
    QDataStream headerStream(header);
    quint32 dataSize;
    headerStream >> dataSize;

    if (dataSize > MAX_PAYLOAD_BYTES) {
        return QByteArray();
    }

    // Extract actual data
    extractedData.reserve(dataSize);
    currentByte = 0;
    bitsInCurrentByte = 0;

    int dataBits = dataSize * 8;
    for (int i = 0; i < dataBits && bitIndex < sampleCount; i += bitsPerSample) {
        quint8 extractedBits = samples[bitIndex] & ((1 << bitsPerSample) - 1);
        currentByte |= (extractedBits << bitsInCurrentByte);
        bitsInCurrentByte += bitsPerSample;

        if (bitsInCurrentByte >= 8) {
            extractedData.append(static_cast<char>(currentByte));
            currentByte = 0;
            bitsInCurrentByte = 0;
        }

        bitIndex++;
    }

    return extractedData.left(dataSize);
}

QByteArray GNASteganographyEngine::adaptiveLSBEmbedding(const QByteArray& audioData, const QByteArray& data) {
    // Analyze audio content to determine optimal LSB parameters
    QList<double> features = extractAudioFeatures(audioData);

    // Adjust parameters based on audio content
    double complexity = features.isEmpty() ? 0.5 : features.first();

    if (complexity > 0.8) {
        _lsbParams.bitsPerSample = 2;  // More aggressive embedding for complex audio
    } else if (complexity > 0.5) {
        _lsbParams.bitsPerSample = 1;  // Standard embedding
    } else {
        _lsbParams.bitsPerSample = 1;  // Conservative embedding for simple audio
    }

    return embedLSBInternal(audioData, data);
}

// Spectral Masking Implementation (Simplified)
QByteArray GNASteganographyEngine::embedSpectralMaskingInternal(const QByteArray& audioData, const QByteArray& data) {
    // This is a simplified implementation
    // Real spectral masking would require proper FFT and psychoacoustic modeling
    qDebug() << "Spectral masking embedding (simplified implementation)";

    // For now, fall back to LSB with reduced embedding strength
    double originalStrength = _config.embeddingStrength;
    _config.embeddingStrength *= 0.5;  // Reduce strength for spectral masking

    QByteArray result = embedLSBInternal(audioData, data);

    _config.embeddingStrength = originalStrength;  // Restore original strength
    return result;
}

QByteArray GNASteganographyEngine::extractSpectralMaskingInternal(const QByteArray& audioData) {
    qDebug() << "Spectral masking extraction (simplified implementation)";
    return extractLSBInternal(audioData);
}

// Echo Hiding Implementation (Simplified)
QByteArray GNASteganographyEngine::embedEchoHidingInternal(const QByteArray& audioData, const QByteArray& data) {
    qDebug() << "Echo hiding embedding (simplified implementation)";

    QByteArray result = audioData;

    // Add subtle echo based on data bits
    for (int i = 0; i < data.size() && i < 100; i++) {  // Limit to first 100 bytes
        quint8 dataByte = static_cast<quint8>(data[i]);

        for (int bit = 0; bit < 8; bit++) {
            bool bitValue = (dataByte & (1 << bit)) != 0;
            double echoDelay = bitValue ? _echoParams.delayMs : _echoParams.delayMs * 0.5;

            // Add echo at specific positions (simplified)
            int echoPosition = (i * 8 + bit) * 1000;  // Spread echoes throughout audio
            if (echoPosition < result.size() - 1000) {
                result = addEcho(result.mid(echoPosition, 1000), echoDelay, _echoParams.amplitudeRatio);
            }
        }
    }

    return result;
}

QByteArray GNASteganographyEngine::extractEchoHidingInternal(const QByteArray& audioData) {
    qDebug() << "Echo hiding extraction (simplified implementation)";
    // Simplified extraction - would require proper echo detection
    return QByteArray("ECHO_EXTRACTED_DATA");
}

QByteArray GNASteganographyEngine::addEcho(const QByteArray& audioData, double delay, double amplitude) {
    if (audioData.isEmpty()) return audioData;

    QByteArray result = audioData;
    qint16* samples = reinterpret_cast<qint16*>(result.data());
    int sampleCount = result.size() / sizeof(qint16);

    int delaySamples = static_cast<int>(delay * _audioFormat.sampleRate() / 1000.0);

    for (int i = delaySamples; i < sampleCount; i++) {
        double original = samples[i];
        double echo = samples[i - delaySamples] * amplitude;
        samples[i] = static_cast<qint16>(qBound(-32768.0, original + echo, 32767.0));
    }

    return result;
}

// Phase Modulation Implementation (Simplified)
QByteArray GNASteganographyEngine::embedPhaseModulationInternal(const QByteArray& audioData, const QByteArray& data) {
    qDebug() << "Phase modulation embedding (simplified implementation)";
    // Complex phase modulation would require proper FFT implementation
    // For now, use a simplified approach similar to LSB
    return embedLSBInternal(audioData, data);
}

QByteArray GNASteganographyEngine::extractPhaseModulationInternal(const QByteArray& audioData) {
    qDebug() << "Phase modulation extraction (simplified implementation)";
    return extractLSBInternal(audioData);
}

// Spread Spectrum Implementation (Simplified)
QByteArray GNASteganographyEngine::embedSpreadSpectrumInternal(const QByteArray& audioData, const QByteArray& data) {
    qDebug() << "Spread spectrum embedding (simplified implementation)";

    // Generate pseudo-random sequence
    QByteArray pseudoSequence = generatePseudoRandomSequence(_spreadParams.sequenceLength,
                                                            _spreadParams.pseudoRandomSeed);

    // Use sequence to spread data (simplified approach)
    QByteArray spreadData;
    for (int i = 0; i < data.size(); i++) {
        quint8 dataByte = static_cast<quint8>(data[i]);
        quint8 sequenceByte = static_cast<quint8>(pseudoSequence[i % pseudoSequence.size()]);
        spreadData.append(static_cast<char>(dataByte ^ sequenceByte));
    }

    return embedLSBInternal(audioData, spreadData);
}

QByteArray GNASteganographyEngine::extractSpreadSpectrumInternal(const QByteArray& audioData) {
    qDebug() << "Spread spectrum extraction (simplified implementation)";

    QByteArray spreadData = extractLSBInternal(audioData);
    if (spreadData.isEmpty()) return QByteArray();

    // Despread using same pseudo-random sequence
    QByteArray pseudoSequence = generatePseudoRandomSequence(_spreadParams.sequenceLength,
                                                            _spreadParams.pseudoRandomSeed);

    QByteArray originalData;
    for (int i = 0; i < spreadData.size(); i++) {
        quint8 spreadByte = static_cast<quint8>(spreadData[i]);
        quint8 sequenceByte = static_cast<quint8>(pseudoSequence[i % pseudoSequence.size()]);
        originalData.append(static_cast<char>(spreadByte ^ sequenceByte));
    }

    return originalData;
}

QByteArray GNASteganographyEngine::generatePseudoRandomSequence(int length, const QString& seed) {
    QByteArray sequence;
    sequence.reserve(length);

    // Simple linear congruential generator
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(seed.toUtf8());
    QByteArray seedHash = hash.result();

    quint32 state = qFromBigEndian<quint32>(reinterpret_cast<const uchar*>(seedHash.constData()));

    for (int i = 0; i < length; i++) {
        state = (state * 1103515245 + 12345) & 0x7fffffff;  // LCG parameters
        sequence.append(static_cast<char>(state & 0xff));
    }

    return sequence;
}

// Data preparation and recovery
QByteArray GNASteganographyEngine::prepareDataForEmbedding(const QByteArray& data) {
    QByteArray prepared = data;

    // Compress if enabled
    if (_config.compressionMethod == "zlib") {
        prepared = compressData(prepared);
    }

    // Encrypt if key is set
    if (!_config.encryptionKey.isEmpty()) {
        prepared = encryptData(prepared);
    }

    // Add error correction if enabled
    if (_config.errorCorrection) {
        prepared = addErrorCorrection(prepared);
    }

    // Add header
    prepared = addSteganographyHeader(prepared);

    return prepared;
}

QByteArray GNASteganographyEngine::recoverEmbeddedData(const QByteArray& extractedData) {
    if (extractedData.isEmpty()) return QByteArray();

    QByteArray recovered = extractedData;

    // Remove header
    recovered = removeSteganographyHeader(recovered);
    if (recovered.isEmpty()) return QByteArray();

    // Remove error correction if enabled
    if (_config.errorCorrection) {
        recovered = removeErrorCorrection(recovered);
        if (recovered.isEmpty()) return QByteArray();
    }

    // Decrypt if key is set
    if (!_config.encryptionKey.isEmpty()) {
        recovered = decryptData(recovered);
        if (recovered.isEmpty()) return QByteArray();
    }

    // Decompress if enabled
    if (_config.compressionMethod == "zlib") {
        recovered = decompressData(recovered);
    }

    return recovered;
}

QByteArray GNASteganographyEngine::addSteganographyHeader(const QByteArray& data) {
    QByteArray header;
    QDataStream stream(&header, QIODevice::WriteOnly);

    // Header format: [size:4][method:4][checksum:8]
    stream << static_cast<quint32>(data.size());
    stream << static_cast<quint32>(_config.method);

    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(data);
    QByteArray checksum = hash.result().left(8);
    header.append(checksum);

    return header + data;
}

QByteArray GNASteganographyEngine::removeSteganographyHeader(const QByteArray& data) {
    if (data.size() < HEADER_SIZE) return QByteArray();

    QDataStream stream(data.left(HEADER_SIZE));
    quint32 size, method;
    stream >> size >> method;

    if (size > MAX_PAYLOAD_BYTES || size > static_cast<quint32>(data.size() - HEADER_SIZE)) {
        return QByteArray();
    }

    // Verify checksum
    QByteArray payload = data.mid(HEADER_SIZE, size);
    QByteArray storedChecksum = data.mid(8, 8);

    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(payload);
    QByteArray calculatedChecksum = hash.result().left(8);

    if (storedChecksum != calculatedChecksum) {
        qWarning() << "Header checksum verification failed";
        return QByteArray();
    }

    return payload;
}

// Simplified implementations for encryption, compression, and error correction
QByteArray GNASteganographyEngine::encryptData(const QByteArray& data) {
    if (_config.encryptionKey.isEmpty()) return data;

    // Simple XOR encryption (for demonstration)
    QByteArray encrypted = data;
    QByteArray key = _config.encryptionKey.toUtf8();

    for (int i = 0; i < encrypted.size(); i++) {
        encrypted[i] = encrypted[i] ^ key[i % key.size()];
    }

    return encrypted;
}

QByteArray GNASteganographyEngine::decryptData(const QByteArray& encryptedData) {
    return encryptData(encryptedData);  // XOR decryption is same as encryption
}

QByteArray GNASteganographyEngine::compressData(const QByteArray& data) {
    // Placeholder for compression
    return data;
}

QByteArray GNASteganographyEngine::decompressData(const QByteArray& compressedData) {
    // Placeholder for decompression
    return compressedData;
}

QByteArray GNASteganographyEngine::addErrorCorrection(const QByteArray& data) {
    // Simple triple redundancy
    QByteArray corrected;
    corrected.reserve(data.size() * 3);

    for (char byte : data) {
        corrected.append(byte);
        corrected.append(byte);
        corrected.append(byte);
    }

    return corrected;
}

QByteArray GNASteganographyEngine::removeErrorCorrection(const QByteArray& data) {
    if (data.size() % 3 != 0) return data;

    QByteArray corrected;
    corrected.reserve(data.size() / 3);

    for (int i = 0; i < data.size(); i += 3) {
        char a = data[i];
        char b = data[i + 1];
        char c = data[i + 2];

        // Majority voting
        char result = (a == b) ? a : ((a == c) ? a : b);
        corrected.append(result);
    }

    return corrected;
}

// Quality assessment methods
double GNASteganographyEngine::calculateSNR(const QByteArray& original, const QByteArray& modified) {
    if (original.size() != modified.size() || original.isEmpty()) {
        return 0.0;
    }

    const qint16* origSamples = reinterpret_cast<const qint16*>(original.constData());
    const qint16* modSamples = reinterpret_cast<const qint16*>(modified.constData());
    int sampleCount = original.size() / sizeof(qint16);

    double signalPower = 0.0;
    double noisePower = 0.0;

    for (int i = 0; i < sampleCount; i++) {
        double origSample = origSamples[i] / 32768.0;
        double modSample = modSamples[i] / 32768.0;
        double noise = modSample - origSample;

        signalPower += origSample * origSample;
        noisePower += noise * noise;
    }

    if (noisePower == 0.0) return 100.0;  // Perfect match

    double snr = 10.0 * std::log10(signalPower / noisePower);
    return qMax(0.0, snr);
}

double GNASteganographyEngine::calculatePSNR(const QByteArray& original, const QByteArray& modified) {
    if (original.size() != modified.size() || original.isEmpty()) {
        return 0.0;
    }

    const qint16* origSamples = reinterpret_cast<const qint16*>(original.constData());
    const qint16* modSamples = reinterpret_cast<const qint16*>(modified.constData());
    int sampleCount = original.size() / sizeof(qint16);

    double mse = 0.0;

    for (int i = 0; i < sampleCount; i++) {
        double diff = origSamples[i] - modSamples[i];
        mse += diff * diff;
    }

    mse /= sampleCount;

    if (mse == 0.0) return 100.0;  // Perfect match

    double maxVal = 32767.0;
    double psnr = 20.0 * std::log10(maxVal / std::sqrt(mse));
    return qMax(0.0, psnr);
}

double GNASteganographyEngine::calculatePerceptualQuality(const QByteArray& original, const QByteArray& modified) {
    // Simplified perceptual quality measure
    double snr = calculateSNR(original, modified);
    return qBound(0.0, snr / 50.0, 1.0);  // Normalize to 0-1 range
}

double GNASteganographyEngine::calculateSpectralDistortion(const QByteArray& original, const QByteArray& modified) {
    // Simplified spectral distortion measure
    double snr = calculateSNR(original, modified);
    return qBound(0.0, 1.0 - (snr / 60.0), 1.0);  // Higher SNR = lower distortion
}

// Statistical analysis implementation
double GNASteganographyEngine::performChiSquareTestInternal(const QByteArray& audioData) {
    if (audioData.size() < 1000) return 0.0;

    // Simple chi-square test on LSBs
    QList<int> lsbCounts(256, 0);
    const qint16* samples = reinterpret_cast<const qint16*>(audioData.constData());
    int sampleCount = audioData.size() / sizeof(qint16);

    for (int i = 0; i < sampleCount; i++) {
        quint8 lsb = samples[i] & 0xff;
        lsbCounts[lsb]++;
    }

    // Calculate chi-square statistic
    double expected = double(sampleCount) / 256.0;
    double chiSquare = 0.0;

    for (int count : lsbCounts) {
        double diff = count - expected;
        chiSquare += (diff * diff) / expected;
    }

    // Normalize and return p-value approximation
    return qMin(1.0, chiSquare / sampleCount);
}

double GNASteganographyEngine::performKSTestInternal(const QByteArray& audioData) {
    // Simplified Kolmogorov-Smirnov test
    return 0.01;  // Placeholder implementation
}

double GNASteganographyEngine::calculateEntropy(const QByteArray& audioData) {
    if (audioData.isEmpty()) return 0.0;

    QList<int> byteCounts(256, 0);

    for (char byte : audioData) {
        byteCounts[static_cast<quint8>(byte)]++;
    }

    double entropy = 0.0;
    double totalBytes = audioData.size();

    for (int count : byteCounts) {
        if (count > 0) {
            double probability = count / totalBytes;
            entropy -= probability * std::log2(probability);
        }
    }

    return entropy;
}

double GNASteganographyEngine::calculateAutocorrelation(const QByteArray& audioData) {
    if (audioData.size() < 100) return 1.0;

    const qint16* samples = reinterpret_cast<const qint16*>(audioData.constData());
    int sampleCount = qMin(1000, audioData.size() / static_cast<int>(sizeof(qint16)));

    double correlation = 0.0;
    int lag = 1;

    for (int i = 0; i < sampleCount - lag; i++) {
        correlation += (samples[i] * samples[i + lag]);
    }

    return qBound(0.0, correlation / (sampleCount - lag) / 32768.0 / 32768.0, 1.0);
}

// Hardware and optimization methods
bool GNASteganographyEngine::initializeGNAHardware() {
    if (!_capabilities.available) return false;

    _gnaHardwareAvailable = true;
    _hardwareProfile = _capabilities.deviceName;

    qDebug() << "GNA hardware initialized for steganography. Profile:" << _hardwareProfile;
    return true;
}

void GNASteganographyEngine::updatePerformanceMetrics(bool success, qint64 operationTime, const QString& operation) {
    if (operation == "embedding") {
        _metrics.averageEmbeddingTime = (_metrics.averageEmbeddingTime * _metrics.totalEmbeddings + operationTime)
                                      / (_metrics.totalEmbeddings + 1);
    } else if (operation == "extraction") {
        _metrics.averageExtractionTime = (_metrics.averageExtractionTime * _metrics.totalExtractions + operationTime)
                                       / (_metrics.totalExtractions + 1);
    }

    _metrics.lastUpdate = QDateTime::currentDateTime();
}

SteganographyMethod GNASteganographyEngine::selectOptimalMethod(const QByteArray& audioData, int payloadSize) {
    EmbeddingCapacity capacity = estimateEmbeddingCapacity(audioData);

    if (payloadSize <= capacity.maxBytesLSB && capacity.maxBytesLSB > 0) {
        return SteganographyMethod::LSB;
    } else if (payloadSize <= capacity.maxBytesSpectral) {
        return SteganographyMethod::SpectralMasking;
    } else if (payloadSize <= capacity.maxBytesEcho) {
        return SteganographyMethod::EchoHiding;
    } else if (payloadSize <= capacity.maxBytesPhase) {
        return SteganographyMethod::PhaseModulation;
    } else {
        return SteganographyMethod::SpreadSpectrum;
    }
}

QList<double> GNASteganographyEngine::extractAudioFeatures(const QByteArray& audioData) {
    QList<double> features;

    if (audioData.isEmpty()) return features;

    const qint16* samples = reinterpret_cast<const qint16*>(audioData.constData());
    int sampleCount = audioData.size() / sizeof(qint16);

    // Calculate basic features
    double mean = 0.0;
    double variance = 0.0;
    double energy = 0.0;

    for (int i = 0; i < sampleCount; i++) {
        double sample = samples[i] / 32768.0;
        mean += sample;
        energy += sample * sample;
    }

    mean /= sampleCount;

    for (int i = 0; i < sampleCount; i++) {
        double sample = samples[i] / 32768.0;
        variance += (sample - mean) * (sample - mean);
    }

    variance /= sampleCount;
    energy /= sampleCount;

    features.append(energy);        // Audio energy
    features.append(variance);      // Audio variance
    features.append(mean);          // Audio mean

    return features;
}

// Initialization methods
void GNASteganographyEngine::initializeSteganographyMethods() {
    qDebug() << "Initializing steganography methods";

    // Initialize embedding patterns
    _lsbParams.embeddingPattern = {0, 1, 2, 3, 4, 5, 6, 7};  // Standard bit order
    _spectralParams.embeddingBins = {10, 15, 20, 25, 30};    // Frequency bins for embedding
    _phaseParams.phaseIndices = {1, 3, 5, 7, 9};             // Phase indices for embedding
}

void GNASteganographyEngine::initializePsychoacousticModel() {
    qDebug() << "Initializing psychoacoustic model";

    // Initialize critical band frequencies (simplified)
    _criticalBandFrequencies = {50, 150, 250, 350, 450, 570, 700, 840, 1000, 1170,
                               1370, 1600, 1850, 2150, 2500, 2900, 3400, 4000, 4800, 5800};

    // Initialize masking thresholds
    _maskingThresholds.fill(PSYCHOACOUSTIC_THRESHOLD, _criticalBandFrequencies.size());
}

void GNASteganographyEngine::initializeStatisticalTests() {
    qDebug() << "Initializing statistical tests";

    _chiSquareThreshold = 0.05;
    _ksTestThreshold = 0.05;
    _entropyThreshold = 7.8;
}

void GNASteganographyEngine::loadQualityMetrics() {
    qDebug() << "Loading quality metrics";
    // Quality metrics already initialized in constructor
}

// Public interface methods
bool GNASteganographyEngine::performSelfTest() {
    qDebug() << "Performing GNA Steganography Engine self-test";

    // Test data
    QByteArray testAudio(8192, 0);  // 4096 16-bit samples
    QByteArray testData = "STEGANOGRAPHY_TEST_DATA_123456789";

    // Fill with test audio data
    qint16* samples = reinterpret_cast<qint16*>(testAudio.data());
    for (int i = 0; i < 4096; i++) {
        samples[i] = static_cast<qint16>(1000.0 * std::sin(2.0 * M_PI * 440.0 * i / 48000.0));
    }

    // Test embedding and extraction
    QByteArray embedded = embedData(testAudio, testData);
    if (embedded.isEmpty()) {
        qWarning() << "Self-test failed: Embedding failed";
        return false;
    }

    QByteArray extracted = extractData(embedded);
    if (extracted != testData) {
        qWarning() << "Self-test failed: Extraction mismatch";
        qWarning() << "Expected:" << testData;
        qWarning() << "Got:" << extracted;
        return false;
    }

    // Test quality metrics
    double snr = calculateSNR(testAudio, embedded);
    if (snr < 20.0) {  // Minimum acceptable SNR
        qWarning() << "Self-test failed: Poor SNR:" << snr << "dB";
        return false;
    }

    qDebug() << "GNA Steganography Engine self-test passed. SNR:" << snr << "dB";
    return true;
}

QVariantMap GNASteganographyEngine::getEngineStatistics() const {
    QVariantMap stats;

    stats["initialized"] = _initialized;
    stats["hardware_accelerated"] = _hardwareAccelerated;
    stats["current_method"] = static_cast<int>(_config.method);
    stats["embedding_strength"] = _config.embeddingStrength;
    stats["target_snr"] = _config.targetSNR;
    stats["max_payload_size"] = _config.maxPayloadSize;

    // Performance metrics
    stats["total_embeddings"] = static_cast<qint64>(_metrics.totalEmbeddings);
    stats["successful_embeddings"] = static_cast<qint64>(_metrics.successfulEmbeddings);
    stats["total_extractions"] = static_cast<qint64>(_metrics.totalExtractions);
    stats["successful_extractions"] = static_cast<qint64>(_metrics.successfulExtractions);
    stats["bytes_embedded"] = static_cast<qint64>(_metrics.bytesEmbedded);
    stats["bytes_extracted"] = static_cast<qint64>(_metrics.bytesExtracted);
    stats["average_embedding_time"] = _metrics.averageEmbeddingTime;
    stats["average_extraction_time"] = _metrics.averageExtractionTime;
    stats["average_snr"] = _metrics.averageSNR;
    stats["average_quality_score"] = _metrics.averageQualityScore;

    return stats;
}

// Configuration methods
void GNASteganographyEngine::setConfiguration(const SteganographyConfig& config) {
    _config = config;
    qDebug() << "Steganography configuration updated:"
             << "Method:" << static_cast<int>(config.method)
             << "Strength:" << config.embeddingStrength
             << "Target SNR:" << config.targetSNR << "dB";
}

void GNASteganographyEngine::setMethod(SteganographyMethod method) {
    _config.method = method;
    qDebug() << "Steganography method changed to:" << static_cast<int>(method);
}

void GNASteganographyEngine::setEncryptionKey(const QString& key) {
    _config.encryptionKey = key;
    qDebug() << "Encryption key updated. Length:" << key.length();
}

void GNASteganographyEngine::clearEncryptionKey() {
    _config.encryptionKey.clear();
    qDebug() << "Encryption key cleared";
}

void GNASteganographyEngine::enableHardwareAcceleration() {
    if (_capabilities.available) {
        _hardwareAccelerated = initializeGNAHardware();
        qDebug() << "Hardware acceleration" << (_hardwareAccelerated ? "enabled" : "failed");
    }
}

void GNASteganographyEngine::disableHardwareAcceleration() {
    _hardwareAccelerated = false;
    qDebug() << "Hardware acceleration disabled";
}

void GNASteganographyEngine::resetMetrics() {
    _metrics = SteganographyMetrics();
    _metrics.metricsStartTime = QDateTime::currentDateTime();
    qDebug() << "Performance metrics reset";
}

// Additional public interface methods for LSB, Spectral, etc.
QByteArray GNASteganographyEngine::embedLSB(const QByteArray& audioData, const QByteArray& hiddenData) {
    SteganographyMethod originalMethod = _config.method;
    _config.method = SteganographyMethod::LSB;
    QByteArray result = embedData(audioData, hiddenData);
    _config.method = originalMethod;
    return result;
}

QByteArray GNASteganographyEngine::embedSpectralMasking(const QByteArray& audioData, const QByteArray& hiddenData) {
    SteganographyMethod originalMethod = _config.method;
    _config.method = SteganographyMethod::SpectralMasking;
    QByteArray result = embedData(audioData, hiddenData);
    _config.method = originalMethod;
    return result;
}

QByteArray GNASteganographyEngine::embedEchoHiding(const QByteArray& audioData, const QByteArray& hiddenData) {
    SteganographyMethod originalMethod = _config.method;
    _config.method = SteganographyMethod::EchoHiding;
    QByteArray result = embedData(audioData, hiddenData);
    _config.method = originalMethod;
    return result;
}

QByteArray GNASteganographyEngine::embedPhaseModulation(const QByteArray& audioData, const QByteArray& hiddenData) {
    SteganographyMethod originalMethod = _config.method;
    _config.method = SteganographyMethod::PhaseModulation;
    QByteArray result = embedData(audioData, hiddenData);
    _config.method = originalMethod;
    return result;
}

QByteArray GNASteganographyEngine::embedSpreadSpectrum(const QByteArray& audioData, const QByteArray& hiddenData) {
    SteganographyMethod originalMethod = _config.method;
    _config.method = SteganographyMethod::SpreadSpectrum;
    QByteArray result = embedData(audioData, hiddenData);
    _config.method = originalMethod;
    return result;
}

QByteArray GNASteganographyEngine::extractLSB(const QByteArray& audioData) {
    SteganographyMethod originalMethod = _config.method;
    _config.method = SteganographyMethod::LSB;
    QByteArray result = extractData(audioData);
    _config.method = originalMethod;
    return result;
}

QByteArray GNASteganographyEngine::extractSpectralMasking(const QByteArray& audioData) {
    SteganographyMethod originalMethod = _config.method;
    _config.method = SteganographyMethod::SpectralMasking;
    QByteArray result = extractData(audioData);
    _config.method = originalMethod;
    return result;
}

QByteArray GNASteganographyEngine::extractEchoHiding(const QByteArray& audioData) {
    SteganographyMethod originalMethod = _config.method;
    _config.method = SteganographyMethod::EchoHiding;
    QByteArray result = extractData(audioData);
    _config.method = originalMethod;
    return result;
}

QByteArray GNASteganographyEngine::extractPhaseModulation(const QByteArray& audioData) {
    SteganographyMethod originalMethod = _config.method;
    _config.method = SteganographyMethod::PhaseModulation;
    QByteArray result = extractData(audioData);
    _config.method = originalMethod;
    return result;
}

QByteArray GNASteganographyEngine::extractSpreadSpectrum(const QByteArray& audioData) {
    SteganographyMethod originalMethod = _config.method;
    _config.method = SteganographyMethod::SpreadSpectrum;
    QByteArray result = extractData(audioData);
    _config.method = originalMethod;
    return result;
}

} // namespace GNAEngines
} // namespace Security