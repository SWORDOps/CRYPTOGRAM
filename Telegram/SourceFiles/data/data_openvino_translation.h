/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#pragma once

#include "base/bytes.h"
#include "base/expected.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QDateTime>
#include <memory>
#include <vector>

namespace Data {

// Translation languages supported
enum class TranslationLanguage {
	English,
	RussianCyrillic,
	ChineseMandarin,  // Simplified Chinese (most common)
	Auto              // Auto-detect source language
};

// OpenVINO acceleration targets
enum class OpenVINODevice {
	CPU,              // CPU inference
	GPU,              // Integrated/discrete GPU
	NPU,              // Neural Processing Unit (Intel GNA/VPU)
	AUTO,             // Auto-select best device
	MultiDevice       // Use multiple devices
};

// Translation model types
enum class TranslationModel {
	// Russian models
	EnglishToRussian_Small,       // ~100MB, fast, good quality
	EnglishToRussian_Base,        // ~300MB, balanced
	EnglishToRussian_Large,       // ~600MB, best quality
	RussianToEnglish_Small,
	RussianToEnglish_Base,
	RussianToEnglish_Large,

	// Chinese models
	EnglishToChinese_Small,       // ~100MB, Simplified Chinese
	EnglishToChinese_Base,        // ~300MB
	EnglishToChinese_Large,       // ~600MB
	ChineseToEnglish_Small,
	ChineseToEnglish_Base,
	ChineseToEnglish_Large,

	// Bidirectional models (more efficient)
	EnglishRussianBidirectional,  // ~400MB
	EnglishChineseBidirectional   // ~400MB
};

// Translation quality settings
enum class TranslationQuality {
	Fast,            // Lower quality, fast inference
	Balanced,        // Good quality, moderate speed
	Best             // Best quality, slower inference
};

// Translation result
struct TranslationResult {
	QString translatedText;
	TranslationLanguage detectedSourceLanguage;
	TranslationLanguage targetLanguage;
	TranslationModel usedModel;
	OpenVINODevice usedDevice;
	double confidenceScore;      // 0.0 - 1.0
	double inferenceTimeMs;
	QDateTime timestamp;
	bool success;
	QString errorMessage;
};

// Model information
struct ModelInfo {
	TranslationModel model;
	QString name;
	QString description;
	TranslationLanguage sourceLanguage;
	TranslationLanguage targetLanguage;
	QString modelPath;           // Path to .xml/.bin files
	quint64 sizeBytes;
	bool isDownloaded;
	bool isBidirectional;
	QString version;
	QString downloadUrl;
	QDateTime lastUsed;
};

// Hardware capability info
struct OpenVINOCapability {
	OpenVINODevice device;
	QString deviceName;
	bool available;
	bool tested;
	double performanceFactor;    // Relative to CPU baseline
	QStringList supportedPrecisions;  // FP32, FP16, INT8
	quint64 availableMemoryMB;
	QString driverVersion;
	bool supportsNPU;
	bool supportsGPU;
};

// OpenVINO Translation Engine
class OpenVINOTranslation : public QObject {
	Q_OBJECT

public:
	explicit OpenVINOTranslation(QObject *parent = nullptr);
	~OpenVINOTranslation();

	// Initialization
	bool initialize();
	bool isInitialized() const;
	void shutdown();

	// Hardware detection
	QList<OpenVINOCapability> detectHardwareCapabilities();
	bool isOpenVINOAvailable() const;
	bool isDeviceAvailable(OpenVINODevice device) const;
	OpenVINODevice selectOptimalDevice(TranslationModel model) const;

	// Translation operations
	base::expected<TranslationResult, QString> translate(
		const QString &text,
		TranslationLanguage targetLanguage,
		TranslationLanguage sourceLanguage = TranslationLanguage::Auto);

	base::expected<TranslationResult, QString> translateWithModel(
		const QString &text,
		TranslationModel model,
		OpenVINODevice device = OpenVINODevice::AUTO);

	// Batch translation for efficiency
	base::expected<QList<TranslationResult>, QString> translateBatch(
		const QStringList &texts,
		TranslationLanguage targetLanguage,
		TranslationLanguage sourceLanguage = TranslationLanguage::Auto);

	// Language detection
	TranslationLanguage detectLanguage(const QString &text);
	bool isCyrillic(const QString &text);
	bool isChinese(const QString &text);

	// Model management
	QList<ModelInfo> getAvailableModels() const;
	QList<ModelInfo> getDownloadedModels() const;
	ModelInfo getModelInfo(TranslationModel model) const;
	bool isModelDownloaded(TranslationModel model) const;

	base::expected<bool, QString> downloadModel(
		TranslationModel model,
		std::function<void(quint64, quint64)> progressCallback = nullptr);

	bool deleteModel(TranslationModel model);
	TranslationModel selectBestModel(
		TranslationLanguage source,
		TranslationLanguage target,
		TranslationQuality quality) const;

	// Configuration
	void setPreferredDevice(OpenVINODevice device);
	OpenVINODevice getPreferredDevice() const;

	void setQualityPreference(TranslationQuality quality);
	TranslationQuality getQualityPreference() const;

	void setCacheEnabled(bool enabled);
	bool isCacheEnabled() const;

	void setMaxCacheSize(quint64 sizeBytes);
	quint64 getMaxCacheSize() const;

	// Performance monitoring
	struct TranslationMetrics {
		quint64 totalTranslations = 0;
		quint64 cachedTranslations = 0;
		quint64 russianTranslations = 0;
		quint64 chineseTranslations = 0;

		double averageInferenceTimeMs = 0.0;
		double cacheHitRate = 0.0;

		OpenVINODevice mostUsedDevice = OpenVINODevice::CPU;
		TranslationModel mostUsedModel;

		QDateTime lastTranslation;
		quint64 totalCharactersTranslated = 0;
	};

	TranslationMetrics getMetrics() const;
	void resetMetrics();

	// Cache management
	void clearTranslationCache();
	quint64 getCacheSize() const;
	void optimizeCache();


private:
	class OpenVINOTranslationPrivate;
	std::unique_ptr<OpenVINOTranslationPrivate> d;

	// Model loading
	bool loadModel(TranslationModel model);
	bool unloadModel(TranslationModel model);
	bool isModelLoaded(TranslationModel model) const;

	// Inference
	QString runInference(
		const QString &text,
		TranslationModel model,
		OpenVINODevice device);

	// Text preprocessing
	QString preprocessText(const QString &text, TranslationLanguage language);
	QString postprocessText(const QString &text, TranslationLanguage language);
	QStringList tokenize(const QString &text, TranslationLanguage language);
	QString detokenize(const QStringList &tokens, TranslationLanguage language);

	// Cache operations
	QString getCachedTranslation(const QString &text, TranslationModel model);

	// Performance optimization

	// State
	bool _initialized = false;
	OpenVINODevice _preferredDevice = OpenVINODevice::AUTO;
	TranslationQuality _qualityPreference = TranslationQuality::Balanced;
	bool _cacheEnabled = true;
	quint64 _maxCacheSize = 100 * 1024 * 1024;  // 100MB default
	mutable TranslationMetrics _metrics;
};

// Helper functions
QString translationLanguageToString(TranslationLanguage language);
TranslationLanguage stringToTranslationLanguage(const QString &str);
QString translationModelToString(TranslationModel model);
QString openvinoDeviceToString(OpenVINODevice device);

} // namespace Data
