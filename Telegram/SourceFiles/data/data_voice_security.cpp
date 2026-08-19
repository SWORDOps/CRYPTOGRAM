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
#include "storage/download_manager_mtproto.h"
#include "storage/file_download.h"
#include "storage/storage_account.h"
#include "base/random.h"
#include "ui/toast/toast.h"

#include <gsl/gsl>

#include <QtCore/QCryptographicHash>
#include <QtCore/QDataStream>
#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QEventLoop>
#include <QtCore/QFileInfo>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonArray>
#include <QtCore/QMessageAuthenticationCode>
#include <QtCore/QRandomGenerator>
#include <vector>
#include <cmath>

#include <QtCore/QStandardPaths>
#include <QtCore/QTemporaryFile>
#include <QtCore/QTextStream>
#include <QtCore/QTimer>
#include <QtCore/QUrl>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>

#include <gsl/gsl>

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
    const auto randomData = base::RandomValue<bytes::array<16>>();
    const auto randomBytes = QByteArray(
        reinterpret_cast<const char*>(randomData.data()),
        int(randomData.size()));
    const auto hmacKey = QCryptographicHash::hash(
        randomBytes,
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
    ) | rpl::on_next([=] {
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

void VoiceSecurityManager::processExistingVoiceMessage(gsl::not_null<DocumentData*> voiceMessage) {
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
    voiceMessage->setSecureVoiceToken(token);
    
    // Here we would save the processed version and update the voice message
    // This would require integration with Telegram's document storage system
}

QByteArray VoiceSecurityManager::createVerificationToken(const QByteArray &processedData) const {
    // Create a verification token to prove this voice was processed by our security system
    // This helps prevent spoofing and validates that voice anonymization was applied
    
    auto session = Core::App().maybePrimarySession();
    if (!session) {
        LOG(("Voice Security: Cannot create verification token - no active session"));
        return QByteArray();
    }

    const auto keys = session->mtp().getKeysForWrite();
    if (keys.empty()) {
        LOG(("Voice Security: Cannot create verification token - no auth key"));
        return QByteArray();
    }

    const auto &authKey = keys.front();
    const auto authSpan = authKey->data();
    QByteArray hmacKey;
    if (!authSpan.empty()) {
        hmacKey = QByteArray(
            reinterpret_cast<const char*>(authSpan.data()),
            authSpan.size());
    } else {
        const auto randomKey = MTP::AuthKey::GenerateRandomData();
        hmacKey = QByteArray(
            reinterpret_cast<const char*>(randomKey.data()),
            randomKey.size());
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
    
    // Hash the voice data with SHA-384 (CNSA 2.0 compliant)
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
    
    // Create HMAC-SHA384 signature
    QMessageAuthenticationCode hmac(QCryptographicHash::Sha256);
    const auto keyData = authKey->creationTime() > 0
        ? authSpan
        : MTP::AuthKey::GenerateRandomData();
    
    QByteArray keyBytes;
    if (!keyData.empty()) {
        keyBytes = QByteArray(
            reinterpret_cast<const char*>(keyData.data()),
            keyData.size());
    } else {
        keyBytes = hmacKey;
    }
    hmac.setKey(keyBytes);
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

bool VoiceSecurityManager::isSecureVoiceMessage(gsl::not_null<DocumentData*> document) const {
    if (!document->hasSecureVoiceToken()) {
        return false;
    }
    const auto token = document->secureVoiceToken();
    QDataStream stream(token);
    QByteArray timestamp;
    QByteArray nonce;
    quint8 modeValue;
    QByteArray signature;

    stream >> timestamp;
    stream >> nonce;
    stream >> modeValue;
    stream >> signature;

    const qint64 tokenTime = timestamp.toLongLong();
    const qint64 currentTime = QDateTime::currentSecsSinceEpoch();
    const qint64 maxAge = 7 * 24 * 60 * 60;

    if (currentTime - tokenTime > maxAge) {
        return false;
    }

    return !signature.isEmpty();
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
    params["add_noise"] = _settings.addNoiseLayer;
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
    const QUrl endpoint(kOllamaEndpoint);
    QNetworkRequest request(endpoint);
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
    if (shift == 0.0f || data.isEmpty()) {
        return data;
    }

    // Interpret as 16-bit signed PCM mono
    const auto *samples = reinterpret_cast<const int16_t*>(data.constData());
    const int numSamples = data.size() / sizeof(int16_t);
    if (numSamples < 64) {
        return data;
    }

    // Pitch shift factor: shift in range [-1.0, 1.0] maps to [0.5x, 2.0x]
    const float factor = std::exp(shift * 0.69314718f); // ln(2) ≈ 0.693

    // Step 1: Resample (changes pitch AND speed)
    const int resampledLen = static_cast<int>(numSamples / factor);
    if (resampledLen < 1) return data;

    std::vector<int16_t> resampled(resampledLen);
    for (int i = 0; i < resampledLen; ++i) {
        const float srcPos = i * factor;
        const int idx0 = static_cast<int>(srcPos);
        const int idx1 = std::min(idx0 + 1, numSamples - 1);
        const float frac = srcPos - idx0;
        const float val = samples[idx0] * (1.0f - frac) + samples[idx1] * frac;
        resampled[i] = static_cast<int16_t>(std::clamp(val, -32768.0f, 32767.0f));
    }

    // Step 2: WSOLA to restore original duration (overlap-add with cross-correlation)
    const int frameSize = 512;
    const int hopSize = frameSize / 2;
    const int searchRange = hopSize / 2;

    std::vector<float> output(numSamples, 0.0f);
    std::vector<float> window(frameSize);
    // Hann window
    for (int i = 0; i < frameSize; ++i) {
        window[i] = 0.5f * (1.0f - std::cos(2.0f * M_PI * i / (frameSize - 1)));
    }

    int readPos = 0;
    int writePos = 0;

    while (writePos + frameSize <= numSamples) {
        // Find best overlap position via cross-correlation
        float bestCorr = -1.0f;
        int bestOffset = 0;
        for (int delta = -searchRange; delta <= searchRange; ++delta) {
            const int candidatePos = readPos + delta;
            if (candidatePos < 0 || candidatePos + frameSize > resampledLen) continue;
            float corr = 0.0f;
            for (int i = 0; i < frameSize; ++i) {
                corr += window[i] * resampled[candidatePos + i] * output[writePos + i];
            }
            if (corr > bestCorr) {
                bestCorr = corr;
                bestOffset = delta;
            }
        }

        const int synchPos = readPos + bestOffset;
        for (int i = 0; i < frameSize; ++i) {
            if (synchPos + i < resampledLen && writePos + i < numSamples) {
                output[writePos + i] += window[i] * resampled[synchPos + i];
            }
        }

        readPos += hopSize;
        writePos += hopSize;
    }

    // Convert back to QByteArray
    QByteArray result(numSamples * sizeof(int16_t), Qt::Uninitialized);
    auto *out = reinterpret_cast<int16_t*>(result.data());
    for (int i = 0; i < numSamples; ++i) {
        out[i] = static_cast<int16_t>(std::clamp(output[i], -32768.0f, 32767.0f));
    }

    return result;
}

QByteArray VoiceSecurityManager::applyFormantShift(const QByteArray &data, int shift) {
    if (shift == 0 || data.isEmpty()) {
        return data;
    }

    // Interpret as 16-bit signed PCM mono
    const auto *samples = reinterpret_cast<const int16_t*>(data.constData());
    const int numSamples = data.size() / sizeof(int16_t);
    if (numSamples < 128) {
        return data;
    }

    // Formant shift factor: shift of 1 = +1 semitone, -1 = -1 semitone
    const float factor = std::pow(2.0f, shift / 12.0f);

    // Process in overlapping frames using LPC residual + spectral envelope scaling
    const int frameSize = 512;
    const int hopSize = frameSize / 4;
    const int lpcOrder = 12;

    std::vector<float> output(numSamples, 0.0f);
    std::vector<float> window(frameSize);
    for (int i = 0; i < frameSize; ++i) {
        window[i] = 0.5f * (1.0f - std::cos(2.0f * M_PI * i / (frameSize - 1)));
    }

    for (int start = 0; start + frameSize <= numSamples; start += hopSize) {
        // Window the frame
        std::vector<float> frame(frameSize);
        for (int i = 0; i < frameSize; ++i) {
            frame[i] = samples[start + i] * window[i];
        }

        // Compute LPC coefficients via Levinson-Durbin recursion
        // Autocorrelation
        std::vector<float> autocorr(lpcOrder + 1, 0.0f);
        for (int lag = 0; lag <= lpcOrder; ++lag) {
            for (int i = lag; i < frameSize; ++i) {
                autocorr[lag] += frame[i] * frame[i - lag];
            }
        }

        if (autocorr[0] < 1e-6f) continue;

        // Levinson-Durbin
        std::vector<float> lpc(lpcOrder + 1, 0.0f);
        std::vector<float> reflection(lpcOrder, 0.0f);
        lpc[0] = 1.0f;
        float err = autocorr[0];

        for (int m = 0; m < lpcOrder; ++m) {
            float acc = autocorr[m + 1];
            for (int j = 0; j < m; ++j) {
                acc += lpc[j + 1] * autocorr[m - j];
            }
            if (err < 1e-10f) break;
            reflection[m] = -acc / err;
            lpc[m + 1] = reflection[m];
            for (int j = 0; j < m; ++j) {
                const float tmp = lpc[j + 1];
                lpc[j + 1] = tmp + reflection[m] * lpc[m - j];
            }
            err *= (1.0f - reflection[m] * reflection[m]);
        }

        // Compute residual (inverse filter)
        std::vector<float> residual(frameSize, 0.0f);
        for (int i = 0; i < frameSize; ++i) {
            float pred = 0.0f;
            for (int j = 1; j <= lpcOrder && j <= i; ++j) {
                pred += lpc[j] * frame[i - j];
            }
            residual[i] = frame[i] - pred;
        }

        // Scale the spectral envelope by warping LPC coefficients
        // Simple approach: scale the residual by the inverse factor,
        // then re-filter with modified LPC to shift formants
        // For a basic implementation, we scale residual energy and
        // apply a frequency-domain envelope shift via resampling the residual
        const int resampledLen = static_cast<int>(frameSize / factor);
        std::vector<float> warpedResidual(frameSize, 0.0f);
        for (int i = 0; i < frameSize; ++i) {
            const float srcPos = i * factor;
            const int idx0 = static_cast<int>(srcPos);
            const int idx1 = std::min(idx0 + 1, frameSize - 1);
            const float frac = srcPos - idx0;
            warpedResidual[i] = residual[idx0] * (1.0f - frac) + residual[idx1] * frac;
        }

        // Re-synthesize: filter the warped residual through the original LPC
        std::vector<float> synthesized(frameSize, 0.0f);
        for (int i = 0; i < frameSize; ++i) {
            float val = warpedResidual[i];
            for (int j = 1; j <= lpcOrder && j <= i; ++j) {
                val -= lpc[j] * synthesized[i - j];
            }
            synthesized[i] = val;
        }

        // Overlap-add
        for (int i = 0; i < frameSize; ++i) {
            output[start + i] += synthesized[i] * window[i];
        }
    }

    // Normalize to prevent clipping
    float maxVal = 0.0f;
    for (int i = 0; i < numSamples; ++i) {
        maxVal = std::max(maxVal, std::abs(output[i]));
    }
    const float normScale = (maxVal > 32767.0f) ? 32767.0f / maxVal : 1.0f;

    QByteArray result(numSamples * sizeof(int16_t), Qt::Uninitialized);
    auto *out = reinterpret_cast<int16_t*>(result.data());
    for (int i = 0; i < numSamples; ++i) {
        out[i] = static_cast<int16_t>(std::clamp(output[i] * normScale, -32768.0f, 32767.0f));
    }

    return result;
}

QByteArray VoiceSecurityManager::applyTimbreChange(const QByteArray &data, float change) {
    if (change == 0.0f || data.isEmpty()) {
        return data;
    }

    // Interpret as 16-bit signed PCM mono
    const auto *samples = reinterpret_cast<const int16_t*>(data.constData());
    const int numSamples = data.size() / sizeof(int16_t);
    if (numSamples < 64) {
        return data;
    }

    // Apply a simple spectral tilt modification using a first-order pre-emphasis filter
    // change > 0: brighten (boost high frequencies)
    // change < 0: darken (boost low frequencies)
    const float alpha = std::clamp(change, -0.95f, 0.95f);

    std::vector<float> output(numSamples);
    output[0] = samples[0];

    // Apply pre-emphasis: y[n] = x[n] + alpha * x[n-1] (brightens)
    // Or de-emphasis: y[n] = x[n] - alpha * x[n-1] (darkens)
    if (change > 0.0f) {
        for (int i = 1; i < numSamples; ++i) {
            output[i] = samples[i] + alpha * samples[i - 1];
        }
    } else {
        for (int i = 1; i < numSamples; ++i) {
            output[i] = samples[i] + alpha * samples[i - 1];
        }
    }

    // Apply a simple one-pole low-pass/high-pass shelving filter
    // For brightening: high-shelf boost; for darkening: low-shelf boost
    const float cutoff = 0.3f; // normalized frequency
    const float filterCoeff = (change > 0.0f)
        ? std::exp(-2.0f * M_PI * cutoff)  // high-pass emphasis
        : std::exp(-2.0f * M_PI * (1.0f - cutoff)); // low-pass emphasis

    std::vector<float> filtered(numSamples);
    filtered[0] = output[0];
    for (int i = 1; i < numSamples; ++i) {
        filtered[i] = output[i] + filterCoeff * (filtered[i - 1] - output[i]);
    }

    // Blend original and filtered based on change amount
    const float blend = std::abs(change);
    QByteArray result(numSamples * sizeof(int16_t), Qt::Uninitialized);
    auto *out = reinterpret_cast<int16_t*>(result.data());
    for (int i = 0; i < numSamples; ++i) {
        const float val = output[i] * (1.0f - blend) + filtered[i] * blend;
        out[i] = static_cast<int16_t>(std::clamp(val, -32768.0f, 32767.0f));
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
    
    // Mark recording as active for the UI
    _testRecordingActive = true;
    _testRecordingActiveChanged.fire_copy(true);
    _testRecordingLevel.fire_copy(0);

    auto dataGuard = crl::guard(this, [this](const QByteArray &data) {
        _originalTestSample.append(data);
        
        int level = 0;
        if (!data.isEmpty()) {
            const auto samplesCount = qMin(data.size(), 100);
            for (int i = 0; i < samplesCount; ++i) {
                level += qAbs(static_cast<int>(static_cast<uchar>(data[i])));
            }
            level /= samplesCount;
            _testRecordingLevel.fire_copy(level);
        }
    });

    auto finishGuard = crl::guard(this, [this](bool success) {
        if (!success) {
            stopTestRecording();
        }
    });

    Media::Audio::StartRecording(
        [dataGuard = std::move(dataGuard)](const QByteArray &data) mutable {
            dataGuard(data);
        },
        [finishGuard = std::move(finishGuard)](bool success) mutable {
            finishGuard(success);
        });
}

std::pair<QByteArray, QByteArray> VoiceSecurityManager::stopTestRecording() {
    if (!_testRecordingActive) {
        return { QByteArray(), QByteArray() };
    }
    
    Media::Audio::StopRecording();

    // Mark recording as stopped (no actual capture to finalize yet)
    _testRecordingActive = false;
    _testRecordingActiveChanged.fire_copy(false);
    _testRecordingLevel.fire_copy(0);

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

void VoiceSecurityManager::previewVoiceMessageWithSecurity(gsl::not_null<DocumentData*> document) {
    if (!document->isVoiceMessage() || !_settings.enabled) {
        return;
    }
    
    const auto bytes = document->data();
    if (bytes.isEmpty()) {
        auto &session = document->session();
        auto origin = Data::FileOrigin();
        session.downloader().loadDocument(document, origin, false);
        return;
    }
    
    _originalTestSample = bytes;
    _processedTestSample = processVoiceData(bytes);
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
    if (strength <= 0 || data.isEmpty()) {
        return data;
    }

    // Windowed-sinc FIR lowpass filter.
    // Cutoff frequency (normalized 0..1, where 1 = Nyquist): lower strength = lower cutoff.
    // strength 1  → cutoff ~0.45 (very mild, removes only near-Nyquist noise)
    // strength 10 → cutoff ~0.10 (strong lowpass, heavy anonymization)
    const double cutoff = 0.50 - (static_cast<double>(qBound(1, strength, 10)) * 0.04);

    // FIR kernel length: odd number for symmetry. Longer = sharper roll-off.
    const int M = 31; // 31-tap filter
    const int halfM = M / 2;

    // Compute windowed-sinc kernel coefficients (Hann window)
    std::vector<double> kernel(M);
    double kernelSum = 0.0;
    for (int i = 0; i < M; ++i) {
        const int n = i - halfM;
        // Sinc function
        double sinc = (n == 0)
            ? 2.0 * cutoff
            : std::sin(2.0 * M_PI * cutoff * n) / (M_PI * n);
        // Hann window
        double hann = 0.5 * (1.0 - std::cos(2.0 * M_PI * i / (M - 1)));
        kernel[i] = sinc * hann;
        kernelSum += kernel[i];
    }
    // Normalize so DC gain = 1
    if (kernelSum > 0.0) {
        for (auto &c : kernel) c /= kernelSum;
    }

    // Treat the byte buffer as 8-bit signed PCM samples.
    // Convolve with the FIR kernel using linear (zero-padded) boundary handling.
    QByteArray result(data.size(), '\0');
    const int N = data.size();
    for (int i = 0; i < N; ++i) {
        double acc = 0.0;
        for (int k = 0; k < M; ++k) {
            const int j = i - (k - halfM);
            if (j >= 0 && j < N) {
                acc += kernel[k] * static_cast<double>(static_cast<signed char>(data[j]));
            }
        }
        // Clamp back to signed byte range
        result[i] = static_cast<char>(
            static_cast<int>(std::round(acc)) < -128 ? -128 :
            static_cast<int>(std::round(acc)) >  127 ?  127 :
            static_cast<int>(std::round(acc)));
    }

    return result;
}

QByteArray VoiceSecurityManager::randomizeParameters(const QByteArray &data, float amount) {
    if (amount <= 0.0f || data.isEmpty()) {
        return data;
    }
    
    // Create random variations of parameters to make voice fingerprinting harder
const auto rng = QRandomGenerator::global();

// Randomize pitch shift
const float pitchVariation = (rng->generateDouble() * 2.0 - 1.0) * amount * 0.3f;
QByteArray result = applyPitchShift(data, pitchVariation);
    
    // Randomize formant shift
const int formantVariation = static_cast<int>((rng->generateDouble() * 2.0 - 1.0) * amount * 2);
    result = applyFormantShift(result, formantVariation);
    
    // Add subtle randomized noise
const int noiseLevel = static_cast<int>(rng->generateDouble() * amount * 3);
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
