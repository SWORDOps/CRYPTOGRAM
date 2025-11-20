/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "data/data_report.h"
#include "media/audio/media_audio.h"
#include "media/audio/media_audio_track.h"

#include <QtCore/QObject>
#include <QtCore/QProcess>
#include <QtCore/QDir>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>

// HMAC-based security token for voice modification
#include "mtproto/mtproto_auth_key.h"

// Forward declarations
namespace ChatHelpers {
class Show;
} // namespace ChatHelpers

namespace Data {

enum class VoiceSecurityMode {
    Disabled,         // No voice security
    AnonymizeLight,   // Basic voice anonymization
    AnonymizeHeavy,   // Strong voice anonymization
    FullyGenerated    // Replace with AI-generated voice
};

enum class VoiceProcessorType {
    None,
    OpenVINO,   // Intel's Neural Processing acceleration
    Ollama,     // Local LLM for voice processing
    CPU,        // Fallback to CPU processing
    Hybrid      // Use both OpenVINO and Ollama together
};

struct VoiceSecuritySettings {
    bool enabled = false;
    VoiceSecurityMode mode = VoiceSecurityMode::AnonymizeLight;
    VoiceProcessorType processor = VoiceProcessorType::None;
    float pitchShift = 0.0f;  // -1.0 to 1.0
    float timbreChange = 0.0f; // -1.0 to 1.0
    int formantShift = 0;     // -5 to 5
    bool removeBackground = false;
    bool addNoiseLayer = false;
    int noiseLevel = 5;       // 1-10
    int npuPriority = 0;
    int batchSize = 1;
    int npuPrecision = 1;
    int bufferSize = 1024;
    int overlapSize = 256;
    
    // Advanced settings
    bool usePresetCombination = true;  // Use preset combinations instead of individual settings
    bool applyFilters = false;  // Apply additional sound filters
    int filterStrength = 3;    // 1-10
    bool randomizeParameters = false;  // Slightly randomize parameters each time
    float randomizationAmount = 0.2f;  // 0.1-1.0
    
    // Custom voice model settings (for FullyGenerated mode)
    QString voiceModelPath;
    QString customPrompt;
    
    // Auto-switching settings
    bool autoSwitchWhenRecording = true;  // Automatically enable when recording voice messages
    bool autoApplyToReceived = false;     // Auto-anonymize received voice messages before playback
};

// Class for detecting available hardware acceleration
class VoiceSecurityHardwareCheck : public QObject {
    Q_OBJECT
    
public:
    VoiceSecurityHardwareCheck();
    ~VoiceSecurityHardwareCheck();
    
    // Check if OpenVINO NPU is available
    bool hasOpenVINOSupport() const;
    
    // Check if NPU hardware is available
    bool hasNpuSupport() const;
    
    // Check if Ollama is installed
    bool hasOllamaInstalled() const;
    
    // Check for installation paths
    bool checkOllamaInstallation();
    bool checkOpenVINOInstallation();
    
    // Return available processor types
    std::vector<VoiceProcessorType> availableProcessors() const;
    
    // Start processing on most efficient available processor
    VoiceProcessorType recommendedProcessor() const;
    
    // Signal when detection is complete
    rpl::producer<> detectionComplete() const;
    
private:
    void detectHardware();
    void detectOllama();
    
    bool _openvinoAvailable = false;
    bool _ollamaAvailable = false;
    bool _npuAvailable = false;
    QString _ollamaPath;
    QString _openvinoPath;
    
    rpl::event_stream<> _detectionComplete;
    rpl::lifetime _lifetime;
};

// Core class for voice anonymization and security
class VoiceSecurityManager : public QObject {
    Q_OBJECT
    
public:
    explicit VoiceSecurityManager(not_null<::Media::Audio::Instance*> audioInstance);
    ~VoiceSecurityManager();
    
    // Check if hardware acceleration is available
    bool hasHardwareAcceleration() const;
    
    // Get/set settings
    const VoiceSecuritySettings &settings() const;
    void updateSettings(const VoiceSecuritySettings &settings);
    
    // Process voice data
    QByteArray processVoiceData(const QByteArray &voiceData);
    
    // Process in real-time during recording
    void startRealTimeProcessing();
    void stopRealTimeProcessing();
    
    // Apply security to an existing voice message
    void processExistingVoiceMessage(not_null<DocumentData*> voiceMessage);
    
    // Create a cryptographic verification token for processed voice
    // This helps prove the voice was processed through our security system
    QByteArray createVerificationToken(const QByteArray &processedData) const;
    
    // Verify if voice message has been processed with security features
    bool isSecureVoiceMessage(not_null<DocumentData*> document) const;
    
    // Hardware/software detection
    rpl::producer<std::vector<VoiceProcessorType>> availableProcessors() const;
    
    // Settings changed signal
    rpl::producer<VoiceSecuritySettings> settingsChanged() const;
    
    // Processing state signals
    rpl::producer<float> processingProgress() const;
    
    // Performance metrics
    float getLastProcessingTime() const { return _lastProcessingTime; }
    float getAverageProcessingTime() const { return _averageProcessingTime; }
    float getMinProcessingTime() const { return _minProcessingTime; }
    float getMaxProcessingTime() const { return _maxProcessingTime; }
    int getTotalProcessingCalls() const { return _totalProcessingCalls; }
    
    // Voice testing methods
    
    // Start recording a voice sample for testing
    void startTestRecording();
    
    // Stop test recording and return both original and processed samples
    std::pair<QByteArray, QByteArray> stopTestRecording();
    
    // Play the original test sample
    void playOriginalTestSample();
    
    // Play the processed test sample
    void playProcessedTestSample();
    
    // Process a specific voice message for preview
    void previewVoiceMessageWithSecurity(not_null<DocumentData*> document);
    
    // Check if both OpenVINO and Ollama are available for hybrid mode
    bool canUseHybridMode() const;
    
    // Get current test samples (for UI display)
    QByteArray getOriginalTestSample() const;
    QByteArray getProcessedTestSample() const;
    
    // Signals for test recording
    rpl::producer<bool> testRecordingActive() const;
    rpl::producer<int> testRecordingLevel() const; // Audio level for visualization
    
    // Check if a processor is available
    bool isProcessorAvailable(VoiceProcessorType type) const;
    
private:
    // OpenVINO integration
    QByteArray processWithOpenVINO(const QByteArray &data);
    void initializeOpenVINO();
    QString createOpenVINOConfigFile();
    
    // Ollama integration for neural voice processing
    QByteArray processWithOllama(const QByteArray &data);
    void initializeOllama();
    QString sendOllamaRequest(const QString &prompt, const QByteArray &audioData);
    
    // Hybrid processing (both OpenVINO and Ollama)
    QByteArray processWithHybrid(const QByteArray &data);
    
    // CPU fallback processing
    QByteArray processWithCPU(const QByteArray &data);
    
    // Performance tracking
    void updatePerformanceStats(float elapsedMs);
    
    // Voice security implementation methods
    QByteArray applyPitchShift(const QByteArray &data, float shift);
    QByteArray applyFormantShift(const QByteArray &data, int shift);
    QByteArray applyTimbreChange(const QByteArray &data, float change);
    QByteArray removeBackgroundNoise(const QByteArray &data);
    QByteArray addNoise(const QByteArray &data, int level);
    QByteArray applyFilters(const QByteArray &data, int strength);
    QByteArray randomizeParameters(const QByteArray &data, float amount);
    
    // Generate voice with AI model
    QByteArray generateVoice(const QByteArray &sourceData, const QString &prompt);
    
    // Hardware detection helper
    std::unique_ptr<VoiceSecurityHardwareCheck> _hardwareCheck;
    
    // Settings
    VoiceSecuritySettings _settings;
    
    // Audio instance reference
    const not_null<::Media::Audio::Instance*> _audioInstance;
    
    // Network manager for API calls
    std::unique_ptr<QNetworkAccessManager> _networkManager;
    
    // Event streams
    rpl::event_stream<VoiceSecuritySettings> _settingsChanged;
    rpl::event_stream<std::vector<VoiceProcessorType>> _availableProcessorsChanged;
    rpl::event_stream<float> _processingProgress;
    rpl::event_stream<bool> _testRecordingActiveChanged;
    rpl::event_stream<int> _testRecordingLevel;
    
    // Performance metrics
    float _lastProcessingTime = 0.0f;
    float _averageProcessingTime = 0.0f;
    float _minProcessingTime = -1.0f;
    float _maxProcessingTime = 0.0f;
    int _totalProcessingCalls = 0;
    
    // OpenVINO configuration
    QString _openvinoCommand;
    QString _openvinoModelPath;
    
    // Processes for external tools
    std::unique_ptr<QProcess> _ollamaProcess;
    
    // Runtime state
    bool _realTimeProcessingActive = false;
    bool _testRecordingActive = false;
    
    // Test samples
    QByteArray _originalTestSample;
    QByteArray _processedTestSample;
    std::unique_ptr<::Media::Audio::Track> _originalTrack;
    std::unique_ptr<::Media::Audio::Track> _processedTrack;
    
    rpl::lifetime _lifetime;
};

} // namespace Data 
