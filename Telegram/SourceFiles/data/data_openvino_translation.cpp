/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#include "data/data_openvino_translation.h"

#include "base/random.h"
#include "base/unixtime.h"

#include <QtCore/QFile>
#include <QtCore/QDir>
#include <QtCore/QStandardPaths>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonArray>
#include <QtCore/QRegularExpression>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>

namespace Data {
namespace {

// Model download URLs (using Hugging Face for open-source models)
constexpr auto kModelBaseUrl = "https://huggingface.co/intel/";

// Cyrillic detection regex
const QRegularExpression kCyrillicRegex(u"[\\u0400-\\u04FF]"_q);

// Chinese detection regex (Simplified + Traditional)
const QRegularExpression kChineseRegex(u"[\\u4E00-\\u9FFF\\u3400-\\u4DBF]"_q);

// Cache directory
QString translationCachePath() {
	auto path = QStandardPaths::writableLocation(QStandardPaths::CacheLocation);
	QDir dir(path);
	if (!dir.exists("translation_cache")) {
		dir.mkdir("translation_cache");
	}
	return path + "/translation_cache/";
}

// Models directory
QString modelsPath() {
	auto path = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
	QDir dir(path);
	if (!dir.exists("translation_models")) {
		dir.mkdir("translation_models");
	}
	return path + "/translation_models/";
}

} // namespace

class OpenVINOTranslation::OpenVINOTranslationPrivate {
public:
	// Model registry
	QMap<TranslationModel, ModelInfo> modelRegistry;

	// Loaded models
	QMap<TranslationModel, QVariant> loadedModels;  // Placeholder for OpenVINO model objects

	// Hardware capabilities
	QList<OpenVINOCapability> hardwareCapabilities;

	// Translation cache
	QMap<QString, QString> translationCache;  // Key: hash(text+model), Value: translation

	// Network manager for model downloads
	QNetworkAccessManager *networkManager = nullptr;

	// Current downloads
	QMap<TranslationModel, QNetworkReply*> activeDownloads;

	void initializeModelRegistry() {
		// Russian models
		modelRegistry[TranslationModel::EnglishToRussian_Small] = {
			TranslationModel::EnglishToRussian_Small,
			"English → Russian (Small)",
			"Fast translation model, ~100MB, good for real-time chat",
			TranslationLanguage::English,
			TranslationLanguage::RussianCyrillic,
			modelsPath() + "en-ru-small",
			100 * 1024 * 1024,  // 100MB
			false,
			false,
			"1.0",
			kModelBaseUrl + "opus-mt-en-ru/resolve/main/",
			QDateTime()
		};

		modelRegistry[TranslationModel::EnglishToRussian_Base] = {
			TranslationModel::EnglishToRussian_Base,
			"English → Russian (Base)",
			"Balanced translation model, ~300MB, recommended",
			TranslationLanguage::English,
			TranslationLanguage::RussianCyrillic,
			modelsPath() + "en-ru-base",
			300 * 1024 * 1024,
			false,
			false,
			"1.0",
			kModelBaseUrl + "opus-mt-en-ru-base/resolve/main/",
			QDateTime()
		};

		modelRegistry[TranslationModel::RussianToEnglish_Base] = {
			TranslationModel::RussianToEnglish_Base,
			"Russian → English (Base)",
			"Balanced translation model, ~300MB, recommended",
			TranslationLanguage::RussianCyrillic,
			TranslationLanguage::English,
			modelsPath() + "ru-en-base",
			300 * 1024 * 1024,
			false,
			false,
			"1.0",
			kModelBaseUrl + "opus-mt-ru-en-base/resolve/main/",
			QDateTime()
		};

		// Chinese models
		modelRegistry[TranslationModel::EnglishToChinese_Small] = {
			TranslationModel::EnglishToChinese_Small,
			"English → Chinese (Small)",
			"Fast translation model, ~100MB, Simplified Chinese",
			TranslationLanguage::English,
			TranslationLanguage::ChineseMandarin,
			modelsPath() + "en-zh-small",
			100 * 1024 * 1024,
			false,
			false,
			"1.0",
			kModelBaseUrl + "opus-mt-en-zh/resolve/main/",
			QDateTime()
		};

		modelRegistry[TranslationModel::EnglishToChinese_Base] = {
			TranslationModel::EnglishToChinese_Base,
			"English → Chinese (Base)",
			"Balanced translation model, ~300MB, Simplified Chinese",
			TranslationLanguage::English,
			TranslationLanguage::ChineseMandarin,
			modelsPath() + "en-zh-base",
			300 * 1024 * 1024,
			false,
			false,
			"1.0",
			kModelBaseUrl + "opus-mt-en-zh-base/resolve/main/",
			QDateTime()
		};

		modelRegistry[TranslationModel::ChineseToEnglish_Base] = {
			TranslationModel::ChineseToEnglish_Base,
			"Chinese → English (Base)",
			"Balanced translation model, ~300MB, Simplified Chinese",
			TranslationLanguage::ChineseMandarin,
			TranslationLanguage::English,
			modelsPath() + "zh-en-base",
			300 * 1024 * 1024,
			false,
			false,
			"1.0",
			kModelBaseUrl + "opus-mt-zh-en-base/resolve/main/",
			QDateTime()
		};

		// Bidirectional models (more efficient)
		modelRegistry[TranslationModel::EnglishRussianBidirectional] = {
			TranslationModel::EnglishRussianBidirectional,
			"English ↔ Russian (Bidirectional)",
			"Efficient bidirectional model, ~400MB",
			TranslationLanguage::Auto,
			TranslationLanguage::Auto,
			modelsPath() + "en-ru-bidir",
			400 * 1024 * 1024,
			false,
			true,
			"1.0",
			kModelBaseUrl + "opus-mt-en-ru-bidir/resolve/main/",
			QDateTime()
		};

		modelRegistry[TranslationModel::EnglishChineseBidirectional] = {
			TranslationModel::EnglishChineseBidirectional,
			"English ↔ Chinese (Bidirectional)",
			"Efficient bidirectional model, ~400MB, Simplified Chinese",
			TranslationLanguage::Auto,
			TranslationLanguage::Auto,
			modelsPath() + "en-zh-bidir",
			400 * 1024 * 1024,
			false,
			true,
			"1.0",
			kModelBaseUrl + "opus-mt-en-zh-bidir/resolve/main/",
			QDateTime()
		};

		// Check which models are already downloaded
		for (auto &model : modelRegistry) {
			QDir modelDir(model.modelPath);
			model.isDownloaded = modelDir.exists() &&
				QFile::exists(model.modelPath + "/model.xml") &&
				QFile::exists(model.modelPath + "/model.bin");
		}
	}
};

OpenVINOTranslation::OpenVINOTranslation(QObject *parent)
: QObject(parent)
, d(std::make_unique<OpenVINOTranslationPrivate>()) {
	d->networkManager = new QNetworkAccessManager(this);
	d->initializeModelRegistry();
}

OpenVINOTranslation::~OpenVINOTranslation() {
	shutdown();
}

bool OpenVINOTranslation::initialize() {
	if (_initialized) {
		return true;
	}

	// Detect hardware capabilities
	detectHardwareCapabilities();

	// Check if OpenVINO is available
	// In production, this would check for libopenvino.so / openvino.dll
	// For now, we'll assume it's available if we have CPU
	if (d->hardwareCapabilities.isEmpty()) {
		LOG(("OpenVINO Translation: No hardware detected"));
		return false;
	}

	_initialized = true;
	LOG(("OpenVINO Translation: Initialized successfully"));

	return true;
}

bool OpenVINOTranslation::isInitialized() const {
	return _initialized;
}

void OpenVINOTranslation::shutdown() {
	if (!_initialized) {
		return;
	}

	// Unload all models
	for (auto model : d->loadedModels.keys()) {
		unloadModel(model);
	}

	// Cancel active downloads
	for (auto reply : d->activeDownloads.values()) {
		reply->abort();
		reply->deleteLater();
	}
	d->activeDownloads.clear();

	_initialized = false;
}

QList<OpenVINOCapability> OpenVINOTranslation::detectHardwareCapabilities() {
	d->hardwareCapabilities.clear();

	// CPU is always available
	OpenVINOCapability cpuCap;
	cpuCap.device = OpenVINODevice::CPU;
	cpuCap.deviceName = "CPU";
	cpuCap.available = true;
	cpuCap.tested = true;
	cpuCap.performanceFactor = 1.0;
	cpuCap.supportedPrecisions = {"FP32", "FP16", "INT8"};
	cpuCap.availableMemoryMB = 4096;  // Placeholder
	cpuCap.supportsNPU = false;
	cpuCap.supportsGPU = false;
	d->hardwareCapabilities.append(cpuCap);

	// TODO: Detect GPU availability
	// In production, use OpenVINO's device enumeration API
	// For now, we'll add a placeholder GPU entry
	OpenVINOCapability gpuCap;
	gpuCap.device = OpenVINODevice::GPU;
	gpuCap.deviceName = "Integrated GPU";
	gpuCap.available = false;  // Detect in production
	gpuCap.tested = false;
	gpuCap.performanceFactor = 2.0;
	gpuCap.supportedPrecisions = {"FP16"};
	gpuCap.availableMemoryMB = 2048;
	gpuCap.supportsNPU = false;
	gpuCap.supportsGPU = true;
	d->hardwareCapabilities.append(gpuCap);

	// TODO: Detect NPU availability (Intel GNA/VPU)
	OpenVINOCapability npuCap;
	npuCap.device = OpenVINODevice::NPU;
	npuCap.deviceName = "Neural Processing Unit";
	npuCap.available = false;  // Detect in production
	npuCap.tested = false;
	npuCap.performanceFactor = 3.0;
	npuCap.supportedPrecisions = {"INT8"};
	npuCap.availableMemoryMB = 512;
	npuCap.supportsNPU = true;
	npuCap.supportsGPU = false;
	d->hardwareCapabilities.append(npuCap);

	emit hardwareCapabilitiesChanged();
	return d->hardwareCapabilities;
}

bool OpenVINOTranslation::isOpenVINOAvailable() const {
	// In production, check for OpenVINO runtime libraries
	// For now, return true if we have CPU capability
	return !d->hardwareCapabilities.isEmpty();
}

bool OpenVINOTranslation::isDeviceAvailable(OpenVINODevice device) const {
	for (const auto &cap : d->hardwareCapabilities) {
		if (cap.device == device && cap.available) {
			return true;
		}
	}
	return false;
}

OpenVINODevice OpenVINOTranslation::selectOptimalDevice(TranslationModel model) const {
	// Priority: NPU > GPU > CPU for best performance/power
	if (isDeviceAvailable(OpenVINODevice::NPU)) {
		return OpenVINODevice::NPU;
	}
	if (isDeviceAvailable(OpenVINODevice::GPU)) {
		return OpenVINODevice::GPU;
	}
	return OpenVINODevice::CPU;
}

base::expected<TranslationResult, QString> OpenVINOTranslation::translate(
	const QString &text,
	TranslationLanguage targetLanguage,
	TranslationLanguage sourceLanguage) {

	if (!_initialized) {
		return base::make_unexpected("Translation engine not initialized");
	}

	if (text.isEmpty()) {
		return base::make_unexpected("Empty text");
	}

	// Auto-detect source language if needed
	if (sourceLanguage == TranslationLanguage::Auto) {
		sourceLanguage = detectLanguage(text);
	}

	// Select best model for this language pair
	auto quality = _qualityPreference;
	auto model = selectBestModel(sourceLanguage, targetLanguage, quality);

	// Translate using selected model
	return translateWithModel(text, model, _preferredDevice);
}

base::expected<TranslationResult, QString> OpenVINOTranslation::translateWithModel(
	const QString &text,
	TranslationModel model,
	OpenVINODevice device) {

	TranslationResult result;
	result.timestamp = QDateTime::currentDateTime();

	// Check cache first
	if (_cacheEnabled) {
		auto cached = getCachedTranslation(text, model);
		if (!cached.isEmpty()) {
			result.translatedText = cached;
			result.usedModel = model;
			result.usedDevice = device;
			result.success = true;
			result.inferenceTimeMs = 0.0;
			result.confidenceScore = 1.0;
			_metrics.cachedTranslations++;
			_metrics.totalTranslations++;
			return result;
		}
	}

	// Ensure model is loaded
	if (!isModelLoaded(model)) {
		if (!loadModel(model)) {
			return base::make_unexpected("Failed to load model");
		}
	}

	// Run inference
	auto startTime = QDateTime::currentMSecsSinceEpoch();
	auto translated = runInference(text, model, device);
	auto endTime = QDateTime::currentMSecsSinceEpoch();

	if (translated.isEmpty()) {
		return base::make_unexpected("Translation failed");
	}

	result.translatedText = translated;
	result.usedModel = model;
	result.usedDevice = device;
	result.success = true;
	result.inferenceTimeMs = endTime - startTime;
	result.confidenceScore = 0.95;  // Placeholder

	// Update metrics
	_metrics.totalTranslations++;
	_metrics.totalCharactersTranslated += text.length();
	_metrics.lastTranslation = result.timestamp;
	_metrics.averageInferenceTimeMs =
		(_metrics.averageInferenceTimeMs * (_metrics.totalTranslations - 1) + result.inferenceTimeMs) /
		_metrics.totalTranslations;

	// Update language-specific counters
	auto modelInfo = d->modelRegistry[model];
	if (modelInfo.sourceLanguage == TranslationLanguage::RussianCyrillic ||
		modelInfo.targetLanguage == TranslationLanguage::RussianCyrillic) {
		_metrics.russianTranslations++;
	}
	if (modelInfo.sourceLanguage == TranslationLanguage::ChineseMandarin ||
		modelInfo.targetLanguage == TranslationLanguage::ChineseMandarin) {
		_metrics.chineseTranslations++;
	}

	// Add to cache
	if (_cacheEnabled) {
		addToCache(text, translated, model);
	}

	emit translationCompleted(result);
	return result;
}

TranslationLanguage OpenVINOTranslation::detectLanguage(const QString &text) {
	if (text.isEmpty()) {
		return TranslationLanguage::English;
	}

	// Check for Cyrillic characters
	if (kCyrillicRegex.match(text).hasMatch()) {
		return TranslationLanguage::RussianCyrillic;
	}

	// Check for Chinese characters
	if (kChineseRegex.match(text).hasMatch()) {
		return TranslationLanguage::ChineseMandarin;
	}

	// Default to English
	return TranslationLanguage::English;
}

bool OpenVINOTranslation::isCyrillic(const QString &text) {
	return kCyrillicRegex.match(text).hasMatch();
}

bool OpenVINOTranslation::isChinese(const QString &text) {
	return kChineseRegex.match(text).hasMatch();
}

QList<ModelInfo> OpenVINOTranslation::getAvailableModels() const {
	return d->modelRegistry.values();
}

QList<ModelInfo> OpenVINOTranslation::getDownloadedModels() const {
	QList<ModelInfo> downloaded;
	for (const auto &model : d->modelRegistry.values()) {
		if (model.isDownloaded) {
			downloaded.append(model);
		}
	}
	return downloaded;
}

ModelInfo OpenVINOTranslation::getModelInfo(TranslationModel model) const {
	return d->modelRegistry.value(model);
}

bool OpenVINOTranslation::isModelDownloaded(TranslationModel model) const {
	return d->modelRegistry.value(model).isDownloaded;
}

TranslationModel OpenVINOTranslation::selectBestModel(
	TranslationLanguage source,
	TranslationLanguage target,
	TranslationQuality quality) const {

	// Russian translation
	if ((source == TranslationLanguage::English && target == TranslationLanguage::RussianCyrillic) ||
		(source == TranslationLanguage::RussianCyrillic && target == TranslationLanguage::English)) {

		// Check if bidirectional model is downloaded
		if (isModelDownloaded(TranslationModel::EnglishRussianBidirectional)) {
			return TranslationModel::EnglishRussianBidirectional;
		}

		// Select based on direction and quality
		if (source == TranslationLanguage::English) {
			switch (quality) {
				case TranslationQuality::Fast:
					return TranslationModel::EnglishToRussian_Small;
				case TranslationQuality::Balanced:
					return TranslationModel::EnglishToRussian_Base;
				case TranslationQuality::Best:
					return TranslationModel::EnglishToRussian_Large;
			}
		} else {
			return TranslationModel::RussianToEnglish_Base;
		}
	}

	// Chinese translation
	if ((source == TranslationLanguage::English && target == TranslationLanguage::ChineseMandarin) ||
		(source == TranslationLanguage::ChineseMandarin && target == TranslationLanguage::English)) {

		// Check if bidirectional model is downloaded
		if (isModelDownloaded(TranslationModel::EnglishChineseBidirectional)) {
			return TranslationModel::EnglishChineseBidirectional;
		}

		// Select based on direction and quality
		if (source == TranslationLanguage::English) {
			switch (quality) {
				case TranslationQuality::Fast:
					return TranslationModel::EnglishToChinese_Small;
				case TranslationQuality::Balanced:
					return TranslationModel::EnglishToChinese_Base;
				case TranslationQuality::Best:
					return TranslationModel::EnglishToChinese_Large;
			}
		} else {
			return TranslationModel::ChineseToEnglish_Base;
		}
	}

	// Default
	return TranslationModel::EnglishToRussian_Base;
}

bool OpenVINOTranslation::loadModel(TranslationModel model) {
	// Placeholder: In production, load OpenVINO model
	// For now, just mark as loaded
	d->loadedModels[model] = QVariant();
	return true;
}

bool OpenVINOTranslation::unloadModel(TranslationModel model) {
	d->loadedModels.remove(model);
	return true;
}

bool OpenVINOTranslation::isModelLoaded(TranslationModel model) const {
	return d->loadedModels.contains(model);
}

QString OpenVINOTranslation::runInference(
	const QString &text,
	TranslationModel model,
	OpenVINODevice device) {

	// Placeholder: In production, run actual OpenVINO inference
	// For now, return mock translation with language markers
	auto modelInfo = d->modelRegistry[model];

	if (modelInfo.targetLanguage == TranslationLanguage::RussianCyrillic) {
		return "[RU] " + text;  // Mock Cyrillic translation
	} else if (modelInfo.targetLanguage == TranslationLanguage::ChineseMandarin) {
		return "[ZH] " + text;  // Mock Chinese translation
	} else {
		return "[EN] " + text;  // Mock English translation
	}
}

QString OpenVINOTranslation::getCachedTranslation(const QString &text, TranslationModel model) {
	auto key = QString::number(qHash(text)) + "_" + QString::number(static_cast<int>(model));
	return d->translationCache.value(key);
}

void OpenVINOTranslation::addToCache(const QString &text, const QString &translation, TranslationModel model) {
	auto key = QString::number(qHash(text)) + "_" + QString::number(static_cast<int>(model));
	d->translationCache[key] = translation;

	// Limit cache size
	if (getCacheSize() > _maxCacheSize) {
		optimizeCache();
	}
}

void OpenVINOTranslation::setPreferredDevice(OpenVINODevice device) {
	_preferredDevice = device;
}

OpenVINODevice OpenVINOTranslation::getPreferredDevice() const {
	return _preferredDevice;
}

void OpenVINOTranslation::setQualityPreference(TranslationQuality quality) {
	_qualityPreference = quality;
}

TranslationQuality OpenVINOTranslation::getQualityPreference() const {
	return _qualityPreference;
}

OpenVINOTranslation::TranslationMetrics OpenVINOTranslation::getMetrics() const {
	return _metrics;
}

void OpenVINOTranslation::resetMetrics() {
	_metrics = TranslationMetrics();
}

void OpenVINOTranslation::clearTranslationCache() {
	d->translationCache.clear();
}

quint64 OpenVINOTranslation::getCacheSize() const {
	// Rough estimate: 100 bytes per entry
	return d->translationCache.size() * 100;
}

void OpenVINOTranslation::optimizeCache() {
	// Remove oldest 25% of cache entries
	auto toRemove = d->translationCache.size() / 4;
	auto keys = d->translationCache.keys();
	for (int i = 0; i < toRemove && i < keys.size(); ++i) {
		d->translationCache.remove(keys[i]);
	}
}

// Helper functions
QString translationLanguageToString(TranslationLanguage language) {
	switch (language) {
		case TranslationLanguage::English: return "English";
		case TranslationLanguage::RussianCyrillic: return "Russian (Cyrillic)";
		case TranslationLanguage::ChineseMandarin: return "Chinese (Mandarin)";
		case TranslationLanguage::Auto: return "Auto-detect";
	}
	return "Unknown";
}

QString translationModelToString(TranslationModel model) {
	switch (model) {
		case TranslationModel::EnglishToRussian_Small: return "EN→RU (Small)";
		case TranslationModel::EnglishToRussian_Base: return "EN→RU (Base)";
		case TranslationModel::EnglishToRussian_Large: return "EN→RU (Large)";
		case TranslationModel::RussianToEnglish_Base: return "RU→EN (Base)";
		case TranslationModel::EnglishToChinese_Small: return "EN→ZH (Small)";
		case TranslationModel::EnglishToChinese_Base: return "EN→ZH (Base)";
		case TranslationModel::EnglishChineseBidirectional: return "EN↔ZH (Bidir)";
		case TranslationModel::EnglishRussianBidirectional: return "EN↔RU (Bidir)";
		default: return "Unknown";
	}
}

QString openvinoDeviceToString(OpenVINODevice device) {
	switch (device) {
		case OpenVINODevice::CPU: return "CPU";
		case OpenVINODevice::GPU: return "GPU";
		case OpenVINODevice::NPU: return "NPU";
		case OpenVINODevice::AUTO: return "Auto";
		case OpenVINODevice::MultiDevice: return "Multi-Device";
	}
	return "Unknown";
}

} // namespace Data
