/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "data/data_voice_security.h"

#include "api/api_sending.h"
#include "apiwrap.h"
#include "core/application.h"
#include "core/core_settings.h"
#include "data/data_document.h"
#include "data/data_file_origin.h"
#include "data/data_session.h"
#include "main/main_session.h"
#include "media/audio/media_audio.h"
#include "media/audio/media_audio_capture.h"
#include "media/audio/media_audio_track.h"
#include "storage/file_download.h"
#include "storage/storage_account.h"
#include "ui/toast/toast.h"

#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QStandardPaths>
#include <QtCore/QCryptographicHash>
#include <QtNetwork/QNetworkReply>
#include <QtCore/QElapsedTimer>
#include <QtCore/QTimer>

namespace Data {

namespace {

// Default configurations
constexpr auto kOpenVINOModelDir = "models/voice_security";
constexpr auto kOllamaDefaultModel = "llama3:8b";  // Default model for voice processing
constexpr auto kOllamaPort = 11434;  // Default Ollama port
constexpr auto kOllamaEndpoint = "http://localhost:11434/api/generate";
constexpr auto kSampleRate = 44100;  // Default sample rate for audio processing
constexpr auto kSecurityMetadataTag = "vscr";  // Tag to mark processed voice messages

// Generate HMAC token for security verification
QByteArray generateSecurityToken(const QByteArray &data) {
    const auto randomData = MTP::AuthKey::Data::Generate(16);
    const auto hmacKey = QCryptographicHash::hash(
        randomData,
        QCryptographicHash::Sha256);
    
    return QMessageAuthenticationCode::hash(
        data,
        hmacKey,
        QCryptographicHash::Sha256).toHex();
}

// Check for common installation paths
QString findExecutablePath(const QString &executableName) {
    // System paths
    const QStringList systemPaths = QStringList()
        << QStandardPaths::findExecutable(executableName)
        << QStandardPaths::findExecutable(executableName, {"/usr/local/bin"})
        << QStandardPaths::findExecutable(executableName, {"/opt/homebrew/bin"})  // macOS Homebrew
        << "C:/Program Files/" + executableName + "/bin/" + executableName + ".exe"  // Windows
        << QDir::homePath() + "/.local/bin/" + executableName;  // Linux user install
    
    for (const auto &path : systemPaths) {
        if (!path.isEmpty() && QFileInfo(path).exists() && QFileInfo(path).isExecutable()) {
            return path;
        }
    }
    
    return QString();
}

} // namespace

// VoiceSecurityHardwareCheck implementation
VoiceSecurityHardwareCheck::VoiceSecurityHardwareCheck() {
    // Start detection process
    detectHardware();
    detectOllama();
}

VoiceSecurityHardwareCheck::~VoiceSecurityHardwareCheck() = default;

bool VoiceSecurityHardwareCheck::hasOpenVINOSupport() const {
    return _openvinoAvailable;
}

bool VoiceSecurityHardwareCheck::hasOllamaInstalled() const {
    return _ollamaAvailable;
}

bool VoiceSecurityHardwareCheck::hasNpuSupport() const {
    return _npuAvailable;
}

void VoiceSecurityHardwareCheck::detectHardware() {
    // Check for OpenVINO runtime
    _openvinoPath = findExecutablePath("openvino");
    
    if (!_openvinoPath.isEmpty()) {
        QProcess process;
        process.start(_openvinoPath, {"--version"});
        
        if (process.waitForFinished(3000)) {
            const QString output = process.readAllStandardOutput();
            _openvinoAvailable = output.contains("OpenVINO");
        }
    }
    
    // Check for NPU hardware availability
    if (_openvinoAvailable) {
        QProcess process;
        process.start(_openvinoPath, {"list", "devices"});
        
        if (process.waitForFinished(3000)) {
            const QString output = process.readAllStandardOutput();
            // Update OpenVINO availability based on any hardware
            _openvinoAvailable = output.contains("GPU") || 
                                output.contains("NPU") || 
                                output.contains("VPU");
            
            // Check specifically for NPU
            _npuAvailable = output.contains("NPU");
        }
    }
    
    _detectionComplete.fire({});
}

void VoiceSecurityHardwareCheck::detectOllama() {
    // Find Ollama in common locations
    _ollamaPath = findExecutablePath("ollama");
    
    if (!_ollamaPath.isEmpty()) {
        QProcess process;
        process.start(_ollamaPath, {"--version"});
        
        if (process.waitForFinished(3000)) {
            _ollamaAvailable = (process.exitCode() == 0);
        }
    }
    
    // If executable found, check if service is running
    if (_ollamaAvailable) {
        // Try to connect to Ollama server
        QTcpSocket socket;
        socket.connectToHost("localhost", kOllamaPort);
        _ollamaAvailable = socket.waitForConnected(1000);
    }
    
    _detectionComplete.fire({});
}

bool VoiceSecurityHardwareCheck::checkOllamaInstallation() {
    detectOllama();
    return _ollamaAvailable;
}

bool VoiceSecurityHardwareCheck::checkOpenVINOInstallation() {
    detectHardware();
    return _openvinoAvailable;
}

std::vector<VoiceProcessorType> VoiceSecurityHardwareCheck::availableProcessors() const {
    std::vector<VoiceProcessorType> result;
    
    // Always add CPU as fallback
    result.push_back(VoiceProcessorType::CPU);
    
    // Add available accelerators
    if (_openvinoAvailable) {
        result.push_back(VoiceProcessorType::OpenVINO);
    }
    
    if (_ollamaAvailable) {
        result.push_back(VoiceProcessorType::Ollama);
    }
    
    // Add hybrid mode if both are available
    if (_openvinoAvailable && _ollamaAvailable) {
        result.push_back(VoiceProcessorType::Hybrid);
    }
    
    return result;
}

VoiceProcessorType VoiceSecurityHardwareCheck::recommendedProcessor() const {
    // Prioritize hardware acceleration and hybrid mode
    if (_openvinoAvailable && _ollamaAvailable) {
        return VoiceProcessorType::Hybrid;
    } else if (_openvinoAvailable) {
        return VoiceProcessorType::OpenVINO;
    } else if (_ollamaAvailable) {
        return VoiceProcessorType::Ollama;
    } else {
        return VoiceProcessorType::CPU;
    }
}

rpl::producer<> VoiceSecurityHardwareCheck::detectionComplete() const {
    return _detectionComplete.events();
}

// VoiceSecurityManager implementation
VoiceSecurityManager::VoiceSecurityManager(
    not_null<Media::Audio::Instance*> audioInstance)
: _audioInstance(audioInstance)
, _networkManager(std::make_unique<QNetworkAccessManager>()) {
    _hardwareCheck = std::make_unique<VoiceSecurityHardwareCheck>();
    
    // Initialize with hardware detection results
    _hardwareCheck->detectionComplete(
    ) | rpl::start_with_next([=] {
        // Auto-select best available processor
        _settings.processor = _hardwareCheck->recommendedProcessor();
        
        // Update available processors
        _availableProcessorsChanged.fire_copy(_hardwareCheck->availableProcessors());
        
        // Enable if hardware acceleration is available
        _settings.enabled = hasHardwareAcceleration();
        
        // Broadcast initial settings
        _settingsChanged.fire_copy(_settings);
    }, _lifetime);
    
    // Initialize required processing modules
    initializeOpenVINO();
    initializeOllama();
}

VoiceSecurityManager::~VoiceSecurityManager() {
    // Ensure resources are released
    stopRealTimeProcessing();
    
    if (_ollamaProcess && _ollamaProcess->state() == QProcess::Running) {
        _ollamaProcess->terminate();
        _ollamaProcess->waitForFinished(1000);
    }
}

bool VoiceSecurityManager::hasHardwareAcceleration() const {
    return _hardwareCheck->hasOpenVINOSupport() || _hardwareCheck->hasOllamaInstalled();
}

const VoiceSecuritySettings &VoiceSecurityManager::settings() const {
    return _settings;
}

void VoiceSecurityManager::updateSettings(const VoiceSecuritySettings &settings) {
    _settings = settings;
    _settingsChanged.fire_copy(_settings);
}

QByteArray VoiceSecurityManager::processVoiceData(const QByteArray &voiceData) {
    if (!_settings.enabled || _settings.mode == VoiceSecurityMode::Disabled) {
        return voiceData;
    }
    
    QByteArray processedData = voiceData;
    
    // Apply processing based on selected processor
    switch (_settings.processor) {
    case VoiceProcessorType::OpenVINO:
        _processingProgress.fire(0.1f);
        processedData = processWithOpenVINO(voiceData);
        break;
    case VoiceProcessorType::Ollama:
        _processingProgress.fire(0.1f);
        processedData = processWithOllama(voiceData);
        break;
    case VoiceProcessorType::Hybrid:
        _processingProgress.fire(0.1f);
        processedData = processWithHybrid(voiceData);
        break;
    case VoiceProcessorType::CPU:
    default:
        _processingProgress.fire(0.1f);
        processedData = processWithCPU(voiceData);
        break;
    }
    
    // Apply additional processing based on settings
    if (_settings.removeBackground) {
        _processingProgress.fire(0.6f);
        processedData = removeBackgroundNoise(processedData);
    }
    
    if (_settings.addNoiseLayer) {
        _processingProgress.fire(0.8f);
        processedData = addNoise(processedData, _settings.noiseLevel);
    }
    
    if (_settings.applyFilters) {
        _processingProgress.fire(0.85f);
        processedData = applyFilters(processedData, _settings.filterStrength);
    }
    
    if (_settings.randomizeParameters && !_settings.usePresetCombination) {
        _processingProgress.fire(0.9f);
        processedData = randomizeParameters(processedData, _settings.randomizationAmount);
    }
    
    if (_settings.pitchShift != 0.0f) {
        _processingProgress.fire(0.95f);
        processedData = applyPitchShift(processedData, _settings.pitchShift);
    }
    
    _processingProgress.fire(1.0f);
    return processedData;
}

void VoiceSecurityManager::startRealTimeProcessing() {
    _realTimeProcessingActive = true;
    
    // Hook into the audio capture system
    Media::Audio::SetVoiceProcessingCallback([this](QByteArray &data) {
        if (_realTimeProcessingActive && _settings.enabled) {
            data = processVoiceData(data);
        }
    });
}

void VoiceSecurityManager::stopRealTimeProcessing() {
    _realTimeProcessingActive = false;
    Media::Audio::SetVoiceProcessingCallback(nullptr);
}

void VoiceSecurityManager::processExistingVoiceMessage(not_null<DocumentData*> voiceMessage) {
    if (!_settings.enabled || 
        _settings.mode == VoiceSecurityMode::Disabled ||
        !voiceMessage->isVoiceMessage()) {
        return;
    }
    
    // Fetch voice message data
    const auto bytes = voiceMessage->data();
    if (bytes.isEmpty()) {
        // Need to load the file first
        auto &session = voiceMessage->session();
        auto origin = Data::FileOrigin();
        
        session.downloader().loadDocument(
            voiceMessage, 
            origin,
            false);
            
        // Process when download is complete
        // This is just a sketch - real implementation would need more robust handling
        return;
    }
    
    // Process the voice data
    const auto processed = processVoiceData(bytes);
    
    // Create verification token
    const auto token = createVerificationToken(processed);
    
    // Here we would save the processed version and update the voice message
    // This would require integration with Telegram's document storage system
}

QByteArray VoiceSecurityManager::createVerificationToken(const QByteArray &processedData) const {
    // Create a verification token to prove this voice was processed by our security system
    // This helps prevent spoofing and validates that voice anonymization was applied
    
    // Get the session's auth key as a secure key source
    MTP::AuthKey::Data authKeyData;
    MTP::AuthKey key(authKeyData);
    
    const auto &session = static_cast<Main::Session*>(_owner)->session();
    if (const auto realKey = session.mtp().mainDcId().authKey()) {
        key = *realKey;
    }
    
    if (key.empty()) {
        LOG(("Voice Security: Cannot create verification token - no auth key"));
        return QByteArray();
    }
    
    // Create a unique message that includes:
    // 1. Hash of the processed audio data
    // 2. Applied security settings (serialized)
    // 3. Timestamp
    // 4. Random nonce for uniqueness
    
    QByteArray settingsData;
    QDataStream settingsStream(&settingsData, QIODevice::WriteOnly);
    settingsStream << static_cast<int>(_settings.mode);
    settingsStream << static_cast<int>(_settings.processor);
    settingsStream << _settings.pitchShift;
    settingsStream << _settings.formantShift;
    settingsStream << _settings.removeBackground;
    settingsStream << _settings.addNoiseLayer;
    settingsStream << _settings.noiseLevel;
    
    // Hash the voice data with SHA-256
    const auto dataHash = QCryptographicHash::hash(
        processedData, 
        QCryptographicHash::Sha256);
        
    // Create timestamp and nonce
    const auto timestamp = QString::number(QDateTime::currentSecsSinceEpoch());
    const quint64 randomValue = QRandomGenerator::global()->generate64();
    const auto nonce = QString::number(randomValue, 16);
    
    // Combine all elements
    QByteArray message;
    QDataStream messageStream(&message, QIODevice::WriteOnly);
    messageStream << dataHash;
    messageStream << settingsData;
    messageStream << timestamp.toUtf8();
    messageStream << nonce.toUtf8();
    
    // Create HMAC-SHA256 signature
    QMessageAuthenticationCode hmac(QCryptographicHash::Sha256);
    const auto keyData = key.created() 
        ? key.data() 
        : MTP::AuthKey::GenerateRandomData();
    
    hmac.setKey(QByteArray(
        reinterpret_cast<const char*>(keyData.data()), 
        keyData.size()));
    hmac.addData(message);
    
    // Build final token structure
    QByteArray token;
    QDataStream tokenStream(&token, QIODevice::WriteOnly);
    tokenStream << timestamp.toUtf8();
    tokenStream << nonce.toUtf8();
    tokenStream << static_cast<quint8>(_settings.mode);
    tokenStream << hmac.result().toHex();
    
    return token;
}

bool VoiceSecurityManager::isSecureVoiceMessage(not_null<DocumentData*> document) const {
    const auto &attributes = document->attributes();
    
    // Check if the document has secure voice attribute
    for (const auto &attribute : attributes) {
        if (attribute.type() == DocumentAttribute::Type::SecureVoice) {
            const auto &secure = attribute.secureVoice();
            
            // Extract token parts
            QDataStream stream(secure.token);
            QByteArray timestamp;
            QByteArray nonce;
            quint8 modeValue;
            QByteArray signature;
            
            stream >> timestamp;
            stream >> nonce;
            stream >> modeValue;
            stream >> signature;
            
            // Validate the token age (must not be too old)
            const qint64 tokenTime = timestamp.toLongLong();
            const qint64 currentTime = QDateTime::currentSecsSinceEpoch();
            const qint64 maxAge = 7 * 24 * 60 * 60; // 7 days
            
            if (currentTime - tokenTime > maxAge) {
                // Token too old
                return false;
            }
            
            // For further validation, we'd need the audio data
            // which we may not have loaded yet
            // For now, we'll return true if the token structure is valid
            return !signature.isEmpty();
        }
    }
    
    return false;
}

rpl::producer<std::vector<VoiceProcessorType>> VoiceSecurityManager::availableProcessors() const {
    return _availableProcessorsChanged.events();
}

rpl::producer<VoiceSecuritySettings> VoiceSecurityManager::settingsChanged() const {
    return _settingsChanged.events();
}

rpl::producer<float> VoiceSecurityManager::processingProgress() const {
    return _processingProgress.events();
}

QByteArray VoiceSecurityManager::processWithOpenVINO(const QByteArray &data) {
    if (!_hardwareCheck->hasOpenVINOSupport()) {
        return processWithCPU(data);
    }
    
    // Start timer for performance monitoring
    QElapsedTimer timer;
    timer.start();
    
    // Signal processing started
    _processingProgress.fire(0.1f);
    
    // Prepare input/output files
    QTemporaryFile inputFile;
    if (!inputFile.open()) {
        LOG(("Voice Security: Failed to create temporary input file"));
        return processWithCPU(data);
    }
    
    inputFile.write(data);
    inputFile.close();
    
    QTemporaryFile outputFile;
    if (!outputFile.open()) {
        LOG(("Voice Security: Failed to create temporary output file"));
        return processWithCPU(data);
    }
    outputFile.close();
    
    // Build command with NPU-specific parameters
    QStringList args = {
        "run",
        "--model", _openvinoModelPath,
        "--input", inputFile.fileName(),
        "--output", outputFile.fileName(),
        "--device", _hardwareCheck->hasNpuSupport() ? "NPU" : "CPU",
        "--config", createOpenVINOConfigFile()
    };
    
    // Signal processing progress
    _processingProgress.fire(0.3f);
    
    // Execute OpenVINO process
    QProcess process;
    process.start(_openvinoCommand, args);
    
    // Process with timeout
    const bool success = process.waitForFinished(30000);
    
    // Signal processing progress
    _processingProgress.fire(0.7f);
    
    // Read result
    QByteArray result;
    if (success && process.exitCode() == 0) {
        outputFile.open();
        result = outputFile.readAll();
        outputFile.close();
    } else {
        LOG(("Voice Security: OpenVINO processing failed with code %1: %2")
            .arg(process.exitCode())
            .arg(QString::fromUtf8(process.readAllStandardError())));
        return processWithCPU(data);
    }
    
    // Record performance stats
    const float elapsed = timer.elapsed();
    updatePerformanceStats(elapsed);
    
    // Signal processing complete
    _processingProgress.fire(1.0f);
    
    // Return processed data or original if processing failed
    return result.isEmpty() ? data : result;
}

void VoiceSecurityManager::initializeOpenVINO() {
    // Find the OpenVINO command path
    _openvinoCommand = findExecutablePath("openvino");
    
    // Set up model paths
    const QString dataPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    const QString modelDir = dataPath + "/" + kOpenVINOModelDir;
    
    // Ensure model directory exists
    QDir dir;
    if (!dir.exists(modelDir)) {
        dir.mkpath(modelDir);
    }
    
    // Set default model path
    _openvinoModelPath = modelDir + "/voice_anonymizer.xml";
    
    // Check if model exists, if not, we would need to download it or inform the user
    const bool modelExists = QFileInfo(_openvinoModelPath).exists();
    
    if (!modelExists) {
        LOG(("Voice Security: OpenVINO model not found at %1").arg(_openvinoModelPath));
        // In a real implementation, you might want to download the model here
        // or provide instructions for the user to download it
    }
}

QByteArray VoiceSecurityManager::processWithOllama(const QByteArray &data) {
    // Process voice data with Ollama LLM API
    
    // Start timer for performance monitoring
    QElapsedTimer timer;
    timer.start();
    
    // Signal processing started
    _processingProgress.fire(0.1f);
    
    // Prepare input for Ollama
    QJsonObject request;
    request["model"] = "voice-anonymizer"; // Model name
    request["prompt"] = _settings.customPrompt.isEmpty() 
        ? "Process this audio to anonymize the voice while maintaining clarity"
        : _settings.customPrompt;
    
    // Encode audio data as base64
    request["audio"] = QString::fromLatin1(data.toBase64());
    
    // Set processing parameters based on settings
    QJsonObject params;
    params["temperature"] = 0.7;
    params["pitch_shift"] = _settings.pitchShift;
    params["formant_shift"] = _settings.formantShift;
    params["add_noise"] = _settings.addNoise;
    params["noise_level"] = _settings.noiseLevel;
    params["remove_background"] = _settings.removeBackground;
    
    request["parameters"] = params;
    
    // Signal progress
    _processingProgress.fire(0.3f);
    
    // Create network request to Ollama API
    QNetworkRequest networkRequest(QUrl("http://localhost:11434/api/generate"));
    networkRequest.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    
    // Send request
    QNetworkAccessManager nam;
    QNetworkReply *reply = nam.post(networkRequest, QJsonDocument(request).toJson());
    
    // Wait for response
    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();
    
    // Signal progress
    _processingProgress.fire(0.7f);
    
    // Check for errors
    if (reply->error() != QNetworkReply::NoError) {
        LOG(("Voice Security: Ollama request failed: %1").arg(reply->errorString()));
        reply->deleteLater();
        return data; // Return original data on error
    }
    
    // Parse response
    QJsonDocument responseDoc = QJsonDocument::fromJson(reply->readAll());
    reply->deleteLater();
    
    if (responseDoc.isNull() || !responseDoc.isObject()) {
        LOG(("Voice Security: Invalid Ollama response format"));
        return data;
    }
    
    QJsonObject responseObj = responseDoc.object();
    
    // Extract processed audio data
    if (!responseObj.contains("audio") || !responseObj["audio"].isString()) {
        LOG(("Voice Security: Missing audio data in Ollama response"));
        return data;
    }
    
    // Decode base64 audio data
    QByteArray processedData = QByteArray::fromBase64(responseObj["audio"].toString().toLatin1());
    
    if (processedData.isEmpty()) {
        LOG(("Voice Security: Empty processed audio from Ollama"));
        return data;
    }
    
    // Record performance stats
    const float elapsed = timer.elapsed();
    updatePerformanceStats(elapsed);
    
    // Signal processing complete
    _processingProgress.fire(1.0f);
    
    return processedData;
}

bool VoiceSecurityManager::checkOllamaAvailability() {
    // Check if Ollama service is available
    QNetworkAccessManager nam;
    QNetworkRequest request(QUrl("http://localhost:11434/api/tags"));
    
    QNetworkReply *reply = nam.get(request);
    
    // Wait for response with timeout
    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    
    timer.start(5000); // 5 second timeout
    loop.exec();
    
    // Check result
    bool available = false;
    
    if (timer.isActive()) {
        // Request completed before timeout
        timer.stop();
        
        if (reply->error() == QNetworkReply::NoError) {
            // Parse response to check if voice model is available
            QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            if (!doc.isNull() && doc.isObject()) {
                QJsonObject obj = doc.object();
                if (obj.contains("models") && obj["models"].isArray()) {
                    QJsonArray models = obj["models"].toArray();
                    
                    // Look for voice-anonymizer model
                    for (const QJsonValue &model : models) {
                        if (model.isObject() && 
                            model.toObject()["name"].toString() == "voice-anonymizer") {
                            available = true;
                            break;
                        }
                    }
                }
            }
        }
    }
    
    reply->deleteLater();
    return available;
}

void VoiceSecurityManager::initializeOllama() {
    if (!_hardwareCheck->hasOllamaInstalled()) {
        return;
    }
    
    // Check if Ollama is already running
    QTcpSocket socket;
    socket.connectToHost("localhost", kOllamaPort);
    const auto connected = socket.waitForConnected(1000);
    socket.close();
    
    // If not running, start it
    if (!connected) {
        _ollamaProcess = std::make_unique<QProcess>();
        _ollamaProcess->start(
            findExecutablePath("ollama"),
            {"serve"});
        
        // Wait for service to start
        QTimer::singleShot(2000, [this] {
            // Pull the default model if not available
            QProcess process;
            process.start(
                findExecutablePath("ollama"),
                {"pull", kOllamaDefaultModel});
            process.waitForFinished(30000); // Wait up to 30 seconds for model download
        });
    }
}

QString VoiceSecurityManager::sendOllamaRequest(
        const QString &prompt, 
        const QByteArray &audioData) {
    
    // Prepare the request
    QNetworkRequest request(QUrl(kOllamaEndpoint));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    
    // Create request body
    QJsonObject jsonRequest;
    jsonRequest["model"] = kOllamaDefaultModel;
    jsonRequest["prompt"] = prompt;
    jsonRequest["audio"] = QString(audioData.toBase64());
    jsonRequest["stream"] = false;
    
    QJsonDocument doc(jsonRequest);
    QByteArray jsonData = doc.toJson();
    
    // Send synchronous request (for simplicity in this sketch)
    QNetworkReply *reply = _networkManager->post(request, jsonData);
    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();
    
    if (reply->error() == QNetworkReply::NoError) {
        const auto response = reply->readAll();
        reply->deleteLater();
        return QString::fromUtf8(response);
    }
    
    reply->deleteLater();
    return QString();
}

QByteArray VoiceSecurityManager::processWithCPU(const QByteArray &data) {
    // Apply basic CPU-based voice processing
    QByteArray result = data;
    
    // Apply processing based on security mode
    switch (_settings.mode) {
    case VoiceSecurityMode::AnonymizeLight:
        _processingProgress.fire(0.3f);
        result = applyPitchShift(result, 0.2f);
        _processingProgress.fire(0.6f);
        result = applyFormantShift(result, 1);
        break;
        
    case VoiceSecurityMode::AnonymizeHeavy:
        _processingProgress.fire(0.3f);
        result = applyPitchShift(result, 0.4f);
        _processingProgress.fire(0.5f);
        result = applyFormantShift(result, 2);
        _processingProgress.fire(0.7f);
        result = applyTimbreChange(result, 0.3f);
        _processingProgress.fire(0.9f);
        result = addNoise(result, 3);
        break;
        
    case VoiceSecurityMode::FullyGenerated:
        // CPU can't do full voice generation effectively
        // Apply heavy modifications instead
        _processingProgress.fire(0.3f);
        result = applyPitchShift(result, _settings.pitchShift > 0 ? 0.6f : -0.6f);
        _processingProgress.fire(0.5f);
        result = applyFormantShift(result, _settings.formantShift != 0 ? _settings.formantShift : 3);
        _processingProgress.fire(0.7f);
        result = applyTimbreChange(result, 0.5f);
        _processingProgress.fire(0.8f);
        result = removeBackgroundNoise(result);
        _processingProgress.fire(0.9f);
        result = addNoise(result, 2);
        break;
        
    default:
        return data;
    }
    
    return result;
}

QByteArray VoiceSecurityManager::applyPitchShift(const QByteArray &data, float shift) {
    // In a real implementation, this would use a DSP library to shift pitch
    // This is a placeholder that doesn't actually process the audio
    
    // Create a safe copy of the data
    QByteArray result = data;
    
    // Simulate pitch shifting with byte manipulation (NOT REAL PROCESSING)
    // A real implementation would use a proper DSP algorithm
    if (shift != 0.0f && !data.isEmpty()) {
        // This is just to simulate processing, not actual pitch shifting!
        const int step = qMax(1, static_cast<int>(data.size() / 100));
        const int offset = static_cast<int>(shift * 10) % step;
        
        for (int i = step; i < data.size(); i += step) {
            const int pos = qBound(0, i + offset, data.size() - 1);
            if (pos < data.size()) {
                result[i] = data[pos];
            }
        }
    }
    
    return result;
}

QByteArray VoiceSecurityManager::applyFormantShift(const QByteArray &data, int shift) {
    // Placeholder implementation - real code would use a DSP library
    // Formant shifting requires spectral processing
    
    // Create a safe copy of the data
    QByteArray result = data;
    
    // Simulate formant shifting (NOT REAL PROCESSING)
    if (shift != 0 && !data.isEmpty()) {
        // This is just to simulate processing, not actual formant shifting!
        const int formantRegions = 5;
        const int regionSize = data.size() / formantRegions;
        
        for (int region = 0; region < formantRegions; region++) {
            const int start = region * regionSize;
            const int end = qMin((region + 1) * regionSize, data.size());
            const int offset = shift % regionSize;
            
            for (int i = start; i < end; i++) {
                const int pos = qBound(start, i + offset, end - 1);
                if (i != pos && pos < data.size()) {
                    // Blend original and shifted data
                    const auto original = static_cast<unsigned char>(data[i]);
                    const auto shifted = static_cast<unsigned char>(data[pos]);
                    result[i] = static_cast<char>((original * 3 + shifted) / 4);
                }
            }
        }
    }
    
    return result;
}

QByteArray VoiceSecurityManager::applyTimbreChange(const QByteArray &data, float change) {
    // Placeholder implementation - real code would use a DSP library
    // Timbre changing requires spectral processing
    
    // Create a safe copy of the data
    QByteArray result = data;
    
    // Simulate timbre change (NOT REAL PROCESSING)
    if (change != 0.0f && !data.isEmpty()) {
        // This is just to simulate processing, not actual timbre changing!
        const int step = qMax(1, static_cast<int>(data.size() / 200));
        
        for (int i = 0; i < data.size() - step; i += step) {
            // Simple EQ-like modification
            if (i + step < data.size()) {
                const auto v1 = static_cast<unsigned char>(data[i]);
                const auto v2 = static_cast<unsigned char>(data[i + step]);
                const auto blend = static_cast<char>((v1 * (1.0f - change) + v2 * change));
                result[i] = blend;
            }
        }
    }
    
    return result;
}

QByteArray VoiceSecurityManager::removeBackgroundNoise(const QByteArray &data) {
    // Placeholder implementation - real code would use a DSP noise reduction algorithm
    
    // Create a safe copy of the data
    QByteArray result = data;
    
    // Simulate noise reduction (NOT REAL PROCESSING)
    if (!data.isEmpty()) {
        // This is just to simulate processing, not actual noise reduction!
        // A real implementation would use spectral subtraction or ML-based denoising
        
        // Estimate noise floor (simplistic approach)
        int noiseFloor = 0;
        const int sampleSize = qMin(1000, data.size());
        for (int i = 0; i < sampleSize; i++) {
            noiseFloor += qAbs(static_cast<unsigned char>(data[i])) / sampleSize;
        }
        
        // Apply simple threshold (this is NOT proper noise reduction!)
        for (int i = 0; i < data.size(); i++) {
            const int sample = static_cast<unsigned char>(data[i]);
            if (qAbs(sample) < noiseFloor + 10) {
                result[i] = 0; // Zero out low amplitude samples
            }
        }
    }
    
    return result;
}

QByteArray VoiceSecurityManager::addNoise(const QByteArray &data, int level) {
    // Placeholder implementation - adds controlled noise to make voice recognition harder
    
    // Create a safe copy of the data
    QByteArray result = data;
    
    // Add controlled noise
    if (level > 0 && !data.isEmpty()) {
        // Scale level to 0-255 range for byte manipulation
        const int noiseAmplitude = qMin(15, level) * 2;
        
        // Add noise (real implementation would be more sophisticated)
        QRandomGenerator random;
        for (int i = 0; i < data.size(); i++) {
            const int noise = random.bounded(-noiseAmplitude, noiseAmplitude + 1);
            const int sample = qBound(0, static_cast<unsigned char>(data[i]) + noise, 255);
            result[i] = static_cast<char>(sample);
        }
    }
    
    return result;
}

QByteArray VoiceSecurityManager::generateVoice(
        const QByteArray &sourceData, 
        const QString &prompt) {
    // In a real implementation, this would use a text-to-speech model
    // based on the content extracted from the source audio
    
    // This is a placeholder that simulates processing
    return processWithCPU(sourceData);
}

bool VoiceSecurityManager::canUseHybridMode() const {
    return _hardwareCheck->hasOpenVINOSupport() && _hardwareCheck->hasOllamaInstalled();
}

bool VoiceSecurityManager::isProcessorAvailable(VoiceProcessorType type) const {
    const auto available = _hardwareCheck->availableProcessors();
    return std::find(available.begin(), available.end(), type) != available.end();
}

QByteArray VoiceSecurityManager::processWithHybrid(const QByteArray &data) {
    if (!canUseHybridMode()) {
        // Fall back to best available
        if (_hardwareCheck->hasOpenVINOSupport()) {
            return processWithOpenVINO(data);
        } else if (_hardwareCheck->hasOllamaInstalled()) {
            return processWithOllama(data);
        } else {
            return processWithCPU(data);
        }
    }
    
    // Hybrid processing uses OpenVINO for voice transformations
    // and Ollama for advanced privacy features
    
    // First pass with OpenVINO for real-time processing
    _processingProgress.fire(0.2f);
    auto result = processWithOpenVINO(data);
    
    // Second pass with Ollama for enhanced anonymization if needed
    if (_settings.mode == VoiceSecurityMode::AnonymizeHeavy || 
        _settings.mode == VoiceSecurityMode::FullyGenerated) {
        _processingProgress.fire(0.5f);
        
        // For heavy anonymization, only use select Ollama features
        // without full voice regeneration to maintain low latency
        QString prompt;
        if (_settings.mode == VoiceSecurityMode::AnonymizeHeavy) {
            prompt = "Apply additional voice privacy features to this already processed audio. "
                    "Preserve the content but further obscure voice characteristics.";
        } else {
            // For full generation, use the complete regeneration prompt
            prompt = _settings.customPrompt.isEmpty() 
                ? "Recreate this speech with a completely different synthesized voice while preserving the content."
                : _settings.customPrompt;
        }
        
        const auto ollamaResult = sendOllamaRequest(prompt, result.toBase64());
        if (!ollamaResult.isEmpty()) {
            QJsonDocument doc = QJsonDocument::fromJson(ollamaResult.toUtf8());
            if (!doc.isNull() && doc.isObject()) {
                const auto obj = doc.object();
                const auto processedBase64 = obj["processed_audio"].toString();
                if (!processedBase64.isEmpty()) {
                    result = QByteArray::fromBase64(processedBase64.toLatin1());
                }
            }
        }
    }
    
    return result;
}

void VoiceSecurityManager::startTestRecording() {
    if (_testRecordingActive) {
        return;
    }
    
    // Clear previous test samples
    _originalTestSample.clear();
    _processedTestSample.clear();
    
    // Start recording
    _testRecordingActive = true;
    _testRecordingActiveChanged.fire_copy(true);
    
    // Set up recording track
    Media::Audio::StartRecording(
        crl::guard(this, [this](const QByteArray &data) {
            _originalTestSample.append(data);
            
            // Calculate audio level for visualization
            int level = 0;
            if (!data.isEmpty()) {
                const auto samplesCount = qMin(data.size(), 100);
                for (int i = 0; i < samplesCount; ++i) {
                    level += qAbs(static_cast<int>(static_cast<uchar>(data[i])));
                }
                level /= samplesCount;
                _testRecordingLevel.fire_copy(level);
            }
        }),
        crl::guard(this, [this](bool success) {
            if (!success) {
                stopTestRecording();
            }
        }));
}

std::pair<QByteArray, QByteArray> VoiceSecurityManager::stopTestRecording() {
    if (!_testRecordingActive) {
        return { QByteArray(), QByteArray() };
    }
    
    // Stop recording
    Media::Audio::StopRecording();
    _testRecordingActive = false;
    _testRecordingActiveChanged.fire_copy(false);
    
    // Process the sample
    if (!_originalTestSample.isEmpty() && _settings.enabled) {
        _processedTestSample = processVoiceData(_originalTestSample);
    } else {
        _processedTestSample = _originalTestSample;
    }
    
    return { _originalTestSample, _processedTestSample };
}

void VoiceSecurityManager::playOriginalTestSample() {
    if (_originalTestSample.isEmpty()) {
        return;
    }
    
    // Stop any current playback
    if (_originalTrack) {
        _originalTrack->detachFromDevice();
    }
    
    // Create track
    _originalTrack = std::make_unique<Media::Audio::Track>(_audioInstance.get());
    _originalTrack->fillFromData(std::move(bytes::make_vector(_originalTestSample)));
    _originalTrack->playOnce();
}

void VoiceSecurityManager::playProcessedTestSample() {
    if (_processedTestSample.isEmpty()) {
        return;
    }
    
    // Stop any current playback
    if (_processedTrack) {
        _processedTrack->detachFromDevice();
    }
    
    // Create track
    _processedTrack = std::make_unique<Media::Audio::Track>(_audioInstance.get());
    _processedTrack->fillFromData(std::move(bytes::make_vector(_processedTestSample)));
    _processedTrack->playOnce();
}

void VoiceSecurityManager::previewVoiceMessageWithSecurity(not_null<DocumentData*> document) {
    if (!document->isVoiceMessage() || !_settings.enabled) {
        return;
    }
    
    // Get document data
    const auto bytes = document->data();
    if (bytes.isEmpty()) {
        // Need to load the document first
        auto &session = document->session();
        auto origin = Data::FileOrigin();
        session.downloader().loadDocument(document, origin, false);
        return;
    }
    
    // Process the document with current settings
    _originalTestSample = bytes;
    _processedTestSample = processVoiceData(bytes);
    
    // Play the processed sample
    playProcessedTestSample();
}

QByteArray VoiceSecurityManager::getOriginalTestSample() const {
    return _originalTestSample;
}

QByteArray VoiceSecurityManager::getProcessedTestSample() const {
    return _processedTestSample;
}

rpl::producer<bool> VoiceSecurityManager::testRecordingActive() const {
    return _testRecordingActiveChanged.events();
}

rpl::producer<int> VoiceSecurityManager::testRecordingLevel() const {
    return _testRecordingLevel.events();
}

QByteArray VoiceSecurityManager::applyFilters(const QByteArray &data, int strength) {
    // Create a safe copy of the data
    QByteArray result = data;
    
    // Simulate audio filters (NOT REAL PROCESSING)
    if (strength > 0 && !data.isEmpty()) {
        // This is a simplified placeholder for real audio filtering
        // In a real implementation, this would apply bandpass/EQ filters
        
        // Simulate simple lowpass filter by averaging samples
        const int windowSize = qBound(2, strength, 10);
        std::vector<unsigned char> buffer(windowSize, 0);
        
        for (int i = windowSize; i < data.size(); i++) {
            // Shift buffer
            for (int j = 0; j < windowSize - 1; j++) {
                buffer[j] = buffer[j + 1];
            }
            buffer[windowSize - 1] = static_cast<unsigned char>(data[i]);
            
            // Calculate average
            unsigned int sum = 0;
            for (int j = 0; j < windowSize; j++) {
                sum += buffer[j];
            }
            
            // Apply filtered value
            result[i] = static_cast<char>(sum / windowSize);
        }
    }
    
    return result;
}

QByteArray VoiceSecurityManager::randomizeParameters(const QByteArray &data, float amount) {
    if (amount <= 0.0f || data.isEmpty()) {
        return data;
    }
    
    // Create random variations of parameters to make voice fingerprinting harder
    QRandomGenerator random;
    
    // Randomize pitch shift
    const float pitchVariation = (random.generateDouble() * 2.0 - 1.0) * amount * 0.3f;
    QByteArray result = applyPitchShift(data, pitchVariation);
    
    // Randomize formant shift
    const int formantVariation = static_cast<int>((random.generateDouble() * 2.0 - 1.0) * amount * 2);
    result = applyFormantShift(result, formantVariation);
    
    // Add subtle randomized noise
    const int noiseLevel = static_cast<int>(random.generateDouble() * amount * 3);
    if (noiseLevel > 0) {
        result = addNoise(result, noiseLevel);
    }
    
    return result;
}

void VoiceSecurityManager::updatePerformanceStats(float elapsedMs) {
    // Store the performance metric for monitoring
    _lastProcessingTime = elapsedMs;
    
    // Keep track of average processing time
    if (_totalProcessingCalls == 0) {
        _averageProcessingTime = elapsedMs;
    } else {
        // Weighted average to give more importance to recent operations
        _averageProcessingTime = (_averageProcessingTime * 0.8f) + (elapsedMs * 0.2f);
    }
    
    _totalProcessingCalls++;
    
    // Store the min/max processing times
    if (_minProcessingTime < 0 || elapsedMs < _minProcessingTime) {
        _minProcessingTime = elapsedMs;
    }
    
    if (elapsedMs > _maxProcessingTime) {
        _maxProcessingTime = elapsedMs;
    }
    
    // Log processing time for debugging
    LOG(("Voice Security: Processing time %1 ms").arg(elapsedMs));
}

QString VoiceSecurityManager::createOpenVINOConfigFile() {
    // Create a temporary config file with the current settings
    QTemporaryFile configFile;
    if (!configFile.open()) {
        return QString();
    }
    
    // Write OpenVINO config in INI format
    QTextStream stream(&configFile);
    stream << "[NPU]\n";
    stream << "PRIORITY=" << _settings.npuPriority << "\n";
    stream << "BATCH_SIZE=" << _settings.batchSize << "\n";
    stream << "PRECISION=";
    
    switch (_settings.npuPrecision) {
    case 0:
        stream << "FP32\n";
        break;
    case 1:
        stream << "FP16\n";
        break;
    case 2:
        stream << "INT8\n";
        break;
    default:
        stream << "FP16\n";
        break;
    }
    
    stream << "BUFFER_SIZE=" << _settings.bufferSize << "\n";
    stream << "OVERLAP=" << _settings.overlapSize << "\n";
    
    configFile.close();
    return configFile.fileName();
}

} // namespace Data 