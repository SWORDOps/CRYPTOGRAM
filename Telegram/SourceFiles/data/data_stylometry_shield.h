/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#pragma once

#include "base/bytes.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtCore/QDateTime>
#include <QtCore/QMutex>

namespace Data {

class Session;

enum class StylometryMode {
	RulesOnly = 0,      // Fast rule-based anonymization (default)
	ModelAssisted = 1,  // OpenVINO model-assisted anonymization
};

enum class StylometryStrength {
	Light = 0,   // Minimal changes, preserve meaning closely
	Medium = 1,  // Moderate obfuscation
	Heavy = 2,   // Aggressive style modification
};

struct StylometryStatistics {
	qint64 textsProcessed = 0;
	qint64 totalProcessingMs = 0;
	double avgProcessingTimeMs = 0.0;
	double avgPatternReduction = 0.0;  // 0.0-1.0, how much style fingerprint was reduced
	QDateTime lastProcessed;
};

struct StylometryAnalysis {
	QString originalText;
	QString anonymizedText;
	double patternReduction = 0.0;  // 0.0-1.0
	QStringList changesApplied;
	qint64 processingTimeMs = 0;
};

class StylometryShield : public QObject {
	Q_OBJECT

public:
	explicit StylometryShield(Session *session);
	~StylometryShield();

	// Main entry point — anonymize text
	StylometryAnalysis anonymize(const QString &text);
	QString anonymizeText(const QString &text);

	// Configuration
	void setEnabled(bool enabled);
	bool isEnabled() const { return _enabled; }

	void setMode(StylometryMode mode);
	StylometryMode mode() const { return _mode; }

	void setStrength(StylometryStrength strength);
	StylometryStrength strength() const { return _strength; }

	// Model management (for ModelAssisted mode)
	bool isModelAvailable() const;
	QString modelPath() const;
	void setModelPath(const QString &path);
	bool loadModel();
	void unloadModel();

	// Statistics
	StylometryStatistics statistics() const;
	void resetStatistics();

	// Analysis utilities
	static double calculateStyleFingerprint(const QString &text);
	static QStringList extractStyleFeatures(const QString &text);

Q_SIGNALS:
	void textAnonymized(const StylometryAnalysis &analysis);
	void modelLoaded(bool success);
	void modelUnloaded();

private:
	// Rule-based anonymization engine
	QString applyRuleBasedAnonymization(const QString &text, QStringList &changes);
	QString applySynonymSubstitution(const QString &text, QStringList &changes);
	QString applySentenceRestructuring(const QString &text, QStringList &changes);
	QString applyPunctuationVariation(const QString &text, QStringList &changes);
	QString applyFillerWordAdjustment(const QString &text, QStringList &changes);
	QString applyVocabularyNormalization(const QString &text, QStringList &changes);
	QString applyCapitalizationVariation(const QString &text, QStringList &changes);

	// Model-assisted anonymization (OpenVINO)
	QString applyModelAnonymization(const QString &text, QStringList &changes);

	// Helper methods
	QString pickSynonym(const QString &word) const;
	QStringList splitSentences(const QString &text) const;
	QString mergeSentences(const QStringList &sentences) const;
	double calculateReduction(const QString &original, const QString &anonymized) const;
	int randomInt(int min, int max) const;

	Session *_session = nullptr;
	bool _enabled = false;
	StylometryMode _mode = StylometryMode::RulesOnly;
	StylometryStrength _strength = StylometryStrength::Medium;

	// Model state
	QString _modelPath;
	bool _modelLoaded = false;

	// Statistics
	mutable QMutex _statsMutex;
	StylometryStatistics _statistics;
};

} // namespace Data
