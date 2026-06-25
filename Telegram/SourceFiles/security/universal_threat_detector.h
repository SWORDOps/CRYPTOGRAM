/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#pragma once

#include "../../lib_base/bytes.h"
#include "../../lib_base/expected.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QTimer>
#include <QtCore/QThread>
#include <QtCore/QMutex>
#include <QtCore/QJsonObject>
#include <memory>
#include <vector>
#include <map>

namespace Security {

// AI analysis result types
enum class AIAnalysisResult {
    Safe,
    Suspicious,
    Malicious,
    Unknown,
    ProcessingError
};

// Threat severity levels
enum class ThreatSeverity {
    Info = 1,
    Low = 3,
    Medium = 5,
    High = 7,
    Critical = 9,
    Emergency = 10
};

// Analysis confidence levels
enum class AnalysisConfidence {
    VeryLow = 1,
    Low = 3,
    Medium = 5,
    High = 7,
    VeryHigh = 9,
    Certain = 10
};

// AI processing tiers based on available hardware
enum class AIProcessingTier {
    Tier1_NPU_Accelerated,      // NPU with full AI models
    Tier2_GPU_Accelerated,      // GPU with medium AI models
    Tier3_CPU_Optimized,        // CPU with lightweight models
    Tier4_Pattern_Only          // Pattern matching only, no AI
};

// Threat analysis result structure
struct ThreatAnalysis {
    QString contentId;              // Unique identifier for analyzed content
    AIAnalysisResult result;        // Overall analysis result
    ThreatSeverity severity;        // Threat severity level
    AnalysisConfidence confidence;  // Confidence in the analysis

    // Analysis details
    QString description;            // Human-readable description
    QStringList detectedPatterns;   // Specific patterns detected
    QStringList suspiciousElements; // Elements that raised suspicion

    // Scoring
    double threatScore = 0.0;       // 0-1, higher = more threatening
    double malwareScore = 0.0;      // 0-1, malware probability
    double phishingScore = 0.0;     // 0-1, phishing probability
    double socialEngScore = 0.0;    // 0-1, social engineering probability

    // Metadata
    QDateTime analysisTime;
    double processingTimeMs = 0.0;  // Time taken for analysis
    AIProcessingTier tierUsed;      // Which processing tier was used
    QString modelVersion;           // AI model version used
    QJsonObject rawResults;         // Raw AI model output

    // Recommendations
    QStringList recommendations;    // Recommended actions
    bool blockContent = false;      // Should content be blocked
    bool quarantine = false;        // Should content be quarantined
    bool requireHumanReview = false; // Requires human verification
};

// AI model information
struct AIModelInfo {
    QString name;
    QString version;
    QString format;                 // ONNX, OpenVINO IR, etc.
    QString path;
    size_t sizeBytes = 0;
    bool loaded = false;
    bool optimized = false;
    QStringList inputFormats;       // Supported input types
    QStringList outputFormats;      // Output types
    double accuracy = 0.0;          // Model accuracy (0-1)
    QString description;
    QDateTime lastUpdated;
};

// Processing statistics
struct ProcessingStatistics {
    int totalAnalyses = 0;
    int safeDetections = 0;
    int threatDetections = 0;
    int errorCount = 0;
    double averageProcessingTime = 0.0; // ms
    double peakProcessingTime = 0.0;    // ms
    QDateTime lastAnalysis;
    QMap<AIProcessingTier, int> tierUsage;
    QMap<ThreatSeverity, int> severityCount;
};

// Content analysis request
struct AnalysisRequest {
    QString requestId;
    QString content;
    QString contentType;            // text, file, url, etc.
    QString source;                 // Where content came from
    QString context;                // Additional context
    QVariantMap metadata;           // Request-specific metadata
    AIProcessingTier preferredTier = AIProcessingTier::Tier1_NPU_Accelerated;
    bool priorityRequest = false;
    QDateTime requestTime;
};

// Main universal threat detector
class UniversalThreatDetector : public QObject {
    Q_OBJECT

public:
    explicit UniversalThreatDetector(QObject *parent = nullptr);
    ~UniversalThreatDetector();

    // Initialization and configuration
    void initialize();
    bool isInitialized() const;
    void setEnabled(bool enabled);
    bool isEnabled() const;

    // AI processing tier management
    void setProcessingTier(AIProcessingTier tier);
    AIProcessingTier getCurrentProcessingTier() const;
    QVector<AIProcessingTier> getAvailableTiers() const;
    bool isProcessingTierAvailable(AIProcessingTier tier) const;

    // Content analysis methods
    ThreatAnalysis analyzeText(const QString &text, const QString &context = QString());
    ThreatAnalysis analyzeFile(const QString &filePath);
    ThreatAnalysis analyzeUrl(const QString &url);
    ThreatAnalysis analyzeBinaryData(const QByteArray &data, const QString &contentType);

    // Asynchronous analysis
    QString requestAnalysis(const AnalysisRequest &request);
    void cancelAnalysis(const QString &requestId);
    QStringList getPendingAnalyses() const;
    int getQueueSize() const;

    // AI model management
    QVector<AIModelInfo> getAvailableModels() const;
    AIModelInfo getCurrentModel() const;
    bool loadModel(const QString &modelName);
    void unloadModel();
    bool isModelLoaded() const;
    void optimizeModel();

    // Real-time threat detection
    void enableRealTimeDetection(bool enabled);
    bool isRealTimeDetectionEnabled() const;
    void setRealTimeThreshold(double threshold); // 0-1, lower = more sensitive
    double getRealTimeThreshold() const;

    // Pattern-based fallback detection
    bool detectSuspiciousPatterns(const QString &content, QStringList &patterns);
    bool detectMalwareSignatures(const QByteArray &data, QStringList &signatures);
    bool detectPhishingIndicators(const QString &content, QStringList &indicators);
    bool detectSocialEngineering(const QString &text, QStringList &techniques);

    // Threat database management
    void updateThreatDatabase();
    QDateTime getLastDatabaseUpdate() const;
    int getThreatDatabaseVersion() const;
    void enableAutomaticUpdates(bool enabled);
    bool isAutomaticUpdatesEnabled() const;

    // Performance monitoring and statistics
    ProcessingStatistics getStatistics() const;
    void resetStatistics();
    double getCurrentCPUUsage() const;
    double getCurrentMemoryUsage() const;
    double getAverageLatency() const;

    // Configuration and tuning
    void setAnalysisTimeout(int timeoutMs);
    int getAnalysisTimeout() const;
    void setMaxConcurrentAnalyses(int maxConcurrent);
    int getMaxConcurrentAnalyses() const;
    void setMemoryLimit(size_t limitMB);
    size_t getMemoryLimit() const;

    // Hardware optimization
    void optimizeForHardware();
    void enableHardwareAcceleration(bool enabled);
    bool isHardwareAccelerationEnabled() const;
    QString getHardwareStatus() const;

    // Whitelist and exceptions
    void addToWhitelist(const QString &pattern);
    void removeFromWhitelist(const QString &pattern);
    QStringList getWhitelist() const;
    bool isWhitelisted(const QString &content) const;

    // False positive handling
    void reportFalsePositive(const QString &contentId);
    void reportMissedThreat(const QString &content, ThreatSeverity severity);
    int getFalsePositiveCount() const;
    void retrainOnFeedback();

signals:
    void threatDetected(const ThreatAnalysis &analysis);
    void analysisComplete(const QString &requestId, const ThreatAnalysis &analysis);
    void analysisError(const QString &requestId, const QString &error);
    void modelLoaded(const QString &modelName);
    void modelLoadError(const QString &modelName, const QString &error);
    void processingTierChanged(AIProcessingTier newTier, AIProcessingTier oldTier);
    void statisticsUpdated(const ProcessingStatistics &stats);
    void threatDatabaseUpdated(int newVersion);

private slots:
    void onAnalysisWorkerFinished();
    void onModelLoadFinished();
    void onDatabaseUpdateFinished();
    void onStatisticsTimer();
    void processAnalysisQueue();

private:
    // AI processing implementations
    ThreatAnalysis analyzeWithNPU(const QString &content, const QString &context);
    ThreatAnalysis analyzeWithGPU(const QString &content, const QString &context);
    ThreatAnalysis analyzeWithCPU(const QString &content, const QString &context);
    ThreatAnalysis analyzeWithPatterns(const QString &content, const QString &context);

    // Model management
    bool loadNPUModel(const QString &modelPath);
    bool loadGPUModel(const QString &modelPath);
    bool loadCPUModel(const QString &modelPath);
    void unloadCurrentModel();
    bool validateModel(const QString &modelPath);

    // Content preprocessing
    QString preprocessText(const QString &text);
    QByteArray preprocessBinaryData(const QByteArray &data);
    QJsonObject createModelInput(const QString &content, const QString &context);

    // Result processing
    ThreatAnalysis processModelOutput(const QJsonObject &output, const AnalysisRequest &request);
    ThreatSeverity calculateThreatSeverity(double threatScore);
    AnalysisConfidence calculateConfidence(const QJsonObject &output);
    QStringList extractDetectedPatterns(const QJsonObject &output);

    // Pattern-based detection implementations
    QStringList detectKeywordPatterns(const QString &content);
    QStringList detectRegexPatterns(const QString &content);
    QStringList detectStatisticalAnomalies(const QString &content);
    QStringList detectBehavioralPatterns(const QString &content);

    // Hardware detection and optimization
    bool detectNPUCapability();
    bool detectGPUCapability();
    void optimizeForCPU();
    void optimizeMemoryUsage();
    void optimizeProcessingPipeline();

    // Database operations
    bool loadThreatDatabase();
    void saveThreatDatabase();
    bool downloadDatabaseUpdate();
    void parseThreatDatabase(const QByteArray &data);

    // Performance monitoring
    void updateStatistics(const ThreatAnalysis &analysis);
    void monitorResourceUsage();
    void optimizePerformance();

    // Queue management
    void addToQueue(const AnalysisRequest &request);
    AnalysisRequest getNextRequest();
    void clearQueue();
    void prioritizeRequest(const QString &requestId);

    // Error handling and fallbacks
    ThreatAnalysis handleAnalysisError(const AnalysisRequest &request, const QString &error);
    void fallbackToLowerTier();
    bool recoverFromError();

    // State management
    bool _initialized = false;
    bool _enabled = false;
    AIProcessingTier _currentTier = AIProcessingTier::Tier4_Pattern_Only;
    mutable QMutex _queueMutex;
    mutable QMutex _statsMutex;

    // AI components
    struct AIEngine;
    std::unique_ptr<AIEngine> _aiEngine;
    AIModelInfo _currentModel;
    bool _modelLoaded = false;

    // Analysis queue
    QVector<AnalysisRequest> _analysisQueue;
    QMap<QString, AnalysisRequest> _activeRequests;
    std::unique_ptr<QThread> _analysisThread;
    int _maxConcurrentAnalyses = 4;

    // Statistics and monitoring
    ProcessingStatistics _statistics;
    std::unique_ptr<QTimer> _statisticsTimer;
    std::unique_ptr<QTimer> _queueTimer;

    // Configuration
    int _analysisTimeoutMs = 10000; // 10 seconds
    size_t _memoryLimitMB = 1024;   // 1 GB
    double _realTimeThreshold = 0.5;
    bool _realTimeDetectionEnabled = true;
    bool _automaticUpdatesEnabled = true;

    // Threat database
    QMap<QString, QVariant> _threatDatabase;
    QDateTime _lastDatabaseUpdate;
    int _threatDatabaseVersion = 0;

    // Whitelist and feedback
    QStringList _whitelist;
    QMap<QString, bool> _feedbackData; // contentId -> isThreat
    int _falsePositiveCount = 0;

    // Hardware status
    bool _hardwareAcceleration = true;
    QString _hardwareStatus;

    // Helper methods
    void setupDefaultConfiguration();
    void validateConfiguration();
    QString generateRequestId() const;
    bool hasValidLicense() const;
    void loadConfiguration();
    void saveConfiguration();
    void cleanupResources();
    QString formatAnalysisResult(const ThreatAnalysis &analysis);
};

// Utility functions for threat detection
namespace ThreatDetectorUtils {
    QString aiAnalysisResultToString(AIAnalysisResult result);
    QString threatSeverityToString(ThreatSeverity severity);
    QString analysisConfidenceToString(AnalysisConfidence confidence);
    QString aiProcessingTierToString(AIProcessingTier tier);
    QColor getThreatSeverityColor(ThreatSeverity severity);
    QString getThreatSeverityIcon(ThreatSeverity severity);
    bool isHighRiskAnalysis(const ThreatAnalysis &analysis);
    QString formatThreatAnalysis(const ThreatAnalysis &analysis);
    QString formatProcessingStatistics(const ProcessingStatistics &stats);
    double calculateOverallThreatScore(const ThreatAnalysis &analysis);
    QStringList getRecommendedActions(const ThreatAnalysis &analysis);
}

} // namespace Security