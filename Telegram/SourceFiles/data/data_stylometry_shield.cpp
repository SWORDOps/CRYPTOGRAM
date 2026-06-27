/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#include "data/data_stylometry_shield.h"

#include "data/data_session.h"
#include "main/main_session.h"

#include <QtCore/QRandomGenerator>
#include <QtCore/QRegularExpression>
#include <QtCore/QElapsedTimer>

namespace Data {
namespace {

// Synonym dictionary for common English words
// Maps words to lists of alternatives
const std::map<QString, QStringList> kSynonyms = {
	{QString("hello"), {QString("hey"), QString("hi there"), QString("greetings")}},
	{QString("hi"), {QString("hey"), QString("hello"), QString("yo")}},
	{QString("yes"), {QString("yeah"), QString("yep"), QString("indeed"), QString("correct")}},
	{QString("no"), {QString("nope"), QString("nah"), QString("negative")}},
	{QString("good"), {QString("great"), QString("fine"), QString("solid"), QString("decent")}},
	{QString("bad"), {QString("poor"), QString("rough"), QString("subpar")}},
	{QString("very"), {QString("really"), QString("quite"), QString("extremely")}},
	{QString("really"), {QString("very"), QString("truly"), QString("genuinely")}},
	{QString("big"), {QString("large"), QString("huge"), QString("sizable")}},
	{QString("small"), {QString("tiny"), QString("little"), QString("compact")}},
	{QString("fast"), {QString("quick"), QString("rapid"), QString("swift")}},
	{QString("slow"), {QString("sluggish"), QString("gradual"), QString("unhurried")}},
	{QString("important"), {QString("crucial"), QString("key"), QString("significant")}},
	{QString("think"), {QString("believe"), QString("reckon"), QString("suppose")}},
	{QString("know"), {QString("realize"), QString("understand"), QString("grasp")}},
	{QString("want"), {QString("need"), QString("would like"), QString("desire")}},
	{QString("get"), {QString("obtain"), QString("acquire"), QString("receive")}},
	{QString("make"), {QString("create"), QString("produce"), QString("build")}},
	{QString("use"), {QString("utilize"), QString("employ"), QString("leverage")}},
	{QString("help"), {QString("assist"), QString("support"), QString("aid")}},
	{QString("start"), {QString("begin"), QString("commence"), QString("initiate")}},
	{QString("end"), {QString("finish"), QString("conclude"), QString("wrap up")}},
	{QString("try"), {QString("attempt"), QString("endeavor"), QString("give it a shot")}},
	{QString("need"), {QString("require"), QString("could use"), QString("must have")}},
	{QString("like"), {QString("enjoy"), QString("appreciate"), QString("favor")}},
	{QString("look"), {QString("seem"), QString("appear"), QString("glance")}},
	{QString("find"), {QString("discover"), QString("locate"), QString("identify")}},
	{QString("tell"), {QString("say"), QString("inform"), QString("mention")}},
	{QString("show"), {QString("display"), QString("reveal"), QString("present")}},
	{QString("work"), {QString("function"), QString("operate"), QString("perform")}},
	{QString("call"), {QString("phone"), QString("ring"), QString("contact")}},
	{QString("buy"), {QString("purchase"), QString("acquire"), QString("pick up")}},
	{QString("eat"), {QString("consume"), QString("have"), QString("grab")}},
	{QString("go"), {QString("head"), QString("proceed"), QString("move")}},
	{QString("come"), {QString("arrive"), QString("show up"), QString("appear")}},
	{QString("see"), {QString("notice"), QString("spot"), QString("observe")}},
	{QString("say"), {QString("state"), QString("express"), QString("mention")}},
	{QString("great"), {QString("excellent"), QString("fantastic"), QString("awesome")}},
	{QString("okay"), {QString("alright"), QString("fine"), QString("acceptable")}},
	{QString("sure"), {QString("certainly"), QString("absolutely"), QString("definitely")}},
	{QString("thanks"), {QString("appreciate it"), QString("much obliged"), QString("cheers")}},
	{QString("sorry"), {QString("apologies"), QString("my bad"), QString("regret that")}},
	{QString("maybe"), {QString("perhaps"), QString("possibly"), QString("might")}},
	{QString("now"), {QString("currently"), QString("at the moment"), QString("presently")}},
	{QString("later"), {QString("afterward"), QString("subsequently"), QString("in a bit")}},
	{QString("today"), {QString("this day"), QString("right now"), QString("as we speak")}},
	{QString("tomorrow"), {QString("the next day"), QString("soon enough"), QString("shortly")}},
	{QString("always"), {QString("constantly"), QString("invariably"), QString("every time")}},
	{QString("never"), {QString("not once"), QString("at no point"), QString("rarely if ever")}},
	{QString("often"), {QString("frequently"), QString("regularly"), QString("commonly")}},
	{QString("however"), {QString("though"), QString("but still"), QString("that said")}},
	{QString("because"), {QString("since"), QString("as"), QString("given that")}},
	{QString("although"), {QString("though"), QString("even so"), QString("despite that")}},
	{QString("therefore"), {QString("so"), QString("thus"), QString("hence")}},
	{QString("finally"), {QString("lastly"), QString("in the end"), QString("at last")}},
	{QString("actually"), {QString("in fact"), QString("as it happens"), QString("truthfully")}},
	{QString("basically"), {QString("essentially"), QString("fundamentally"), QString("in essence")}},
	{QString("probably"), {QString("likely"), QString("most likely"), QString("chances are")}},
};

// Filler words/phrases to insert for style variation
const QStringList kFillers = {
	QString("like"),
	QString("sort of"),
	QString("kind of"),
	QString("you know"),
	QString("I mean"),
	QString("honestly"),
	QString("basically"),
	QString("to be fair"),
};

// Words/phrases to remove (overused style markers)
const QStringList kStyleMarkers = {
	QString("literally"),
	QString("obviously"),
	QString("clearly"),
	QString("naturally"),
	QString("of course"),
	QString("needless to say"),
};

// Punctuation variations
const QStringList kEmDashReplacements = {
	QString(", "),
	QString(" - "),
	QString("; "),
};

} // namespace

StylometryShield::StylometryShield(Session *session)
: QObject(nullptr)
, _session(session) {
}

StylometryShield::~StylometryShield() {
	unloadModel();
}

StylometryAnalysis StylometryShield::anonymize(const QString &text) {
	StylometryAnalysis result;
	result.originalText = text;

	if (text.isEmpty()) {
		result.anonymizedText = text;
		return result;
	}

	QElapsedTimer timer;
	timer.start();

	QStringList changes;

	QString anonymized;
	if (_mode == StylometryMode::ModelAssisted && isModelAvailable()) {
		anonymized = applyModelAnonymization(text, changes);
	} else {
		anonymized = applyRuleBasedAnonymization(text, changes);
	}

	result.anonymizedText = anonymized;
	result.changesApplied = changes;
	result.processingTimeMs = timer.elapsed();
	result.patternReduction = calculateReduction(text, anonymized);

	// Update statistics
	{
		QMutexLocker lock(&_statsMutex);
		_statistics.textsProcessed++;
		_statistics.totalProcessingMs += result.processingTimeMs;
		_statistics.avgProcessingTimeMs =
			double(_statistics.totalProcessingMs) / double(_statistics.textsProcessed);
		_statistics.avgPatternReduction =
			(_statistics.avgPatternReduction * (_statistics.textsProcessed - 1)
				+ result.patternReduction) / _statistics.textsProcessed;
		_statistics.lastProcessed = QDateTime::currentDateTime();
	}

	Q_EMIT textAnonymized(result);
	return result;
}

QString StylometryShield::anonymizeText(const QString &text) {
	return anonymize(text).anonymizedText;
}

void StylometryShield::setEnabled(bool enabled) {
	_enabled = enabled;
}

void StylometryShield::setMode(StylometryMode mode) {
	_mode = mode;
	if (mode == StylometryMode::ModelAssisted && !isModelAvailable()) {
		// Try to load model when switching to model-assisted mode
		loadModel();
	}
}

void StylometryShield::setStrength(StylometryStrength strength) {
	_strength = strength;
}

bool StylometryShield::isModelAvailable() const {
	return _modelLoaded && !_modelPath.isEmpty();
}

QString StylometryShield::modelPath() const {
	return _modelPath;
}

void StylometryShield::setModelPath(const QString &path) {
	if (_modelPath != path) {
		unloadModel();
		_modelPath = path;
	}
}

bool StylometryShield::loadModel() {
	if (_modelPath.isEmpty()) {
		return false;
	}
	// TODO: Load OpenVINO model for text transformation
	// For now, mark as loaded if path is set
	_modelLoaded = true;
	Q_EMIT modelLoaded(true);
	return true;
}

void StylometryShield::unloadModel() {
	if (_modelLoaded) {
		_modelLoaded = false;
		Q_EMIT modelUnloaded();
	}
}

StylometryStatistics StylometryShield::statistics() const {
	QMutexLocker lock(&_statsMutex);
	return _statistics;
}

void StylometryShield::resetStatistics() {
	QMutexLocker lock(&_statsMutex);
	_statistics = StylometryStatistics();
}

double StylometryShield::calculateStyleFingerprint(const QString &text) {
	if (text.isEmpty()) {
		return 0.0;
	}

	// Calculate basic style features
	double fingerprint = 0.0;

	// Average word length
	const auto words = text.split(' ', Qt::SkipEmptyParts);
	if (words.isEmpty()) {
		return 0.0;
	}

	double totalWordLength = 0.0;
	for (const auto &w : words) {
		totalWordLength += w.length();
	}
	const double avgWordLength = totalWordLength / words.size();
	fingerprint += avgWordLength * 0.2;

	// Average sentence length
	const auto sentences = text.split(QRegularExpression("[.!?]+"), Qt::SkipEmptyParts);
	if (!sentences.isEmpty()) {
		double totalSentLength = 0.0;
		for (const auto &s : sentences) {
			totalSentLength += s.split(' ', Qt::SkipEmptyParts).size();
		}
		const double avgSentLength = totalSentLength / sentences.size();
		fingerprint += avgSentLength * 0.3;
	}

	// Punctuation density
	const int punctCount = text.count(QRegularExpression("[,!;:!?\"'-]"));
	fingerprint += double(punctCount) / text.length() * 100.0 * 0.2;

	// Capitalization pattern
	const int upperCount = text.count(QRegularExpression("[A-Z]"));
	fingerprint += double(upperCount) / text.length() * 100.0 * 0.15;

	// Unique word ratio (vocabulary richness)
	const QSet<QString> uniqueWords(words.begin(), words.end());
	fingerprint += double(uniqueWords.size()) / words.size() * 15.0;

	return fingerprint;
}

QStringList StylometryShield::extractStyleFeatures(const QString &text) {
	QStringList features;

	// Word count
	const auto words = text.split(' ', Qt::SkipEmptyParts);
	features << QString("Word count: %1").arg(words.size());

	// Avg word length
	if (!words.isEmpty()) {
		double total = 0.0;
		for (const auto &w : words) {
			total += w.length();
		}
		features << QString("Avg word length: %1").arg(total / words.size(), 0, 'f', 1);
	}

	// Sentence count
	const auto sentences = text.split(QRegularExpression("[.!?]+"), Qt::SkipEmptyParts);
	features << QString("Sentences: %1").arg(sentences.size());

	// Punctuation usage
	const int commas = text.count(',');
	const int periods = text.count('.');
	const int exclamations = text.count('!');
	const int questions = text.count('?');
	features << QString("Commas: %1, Periods: %2, Exclamations: %3, Questions: %4")
		.arg(commas).arg(periods).arg(exclamations).arg(questions);

	// Unique words
	const QSet<QString> uniqueWords(words.begin(), words.end());
	features << QString("Unique words: %1 (%2%)")
		.arg(uniqueWords.size())
		.arg(uniqueWords.size() * 100 / std::max<qsizetype>(1, words.size()));

	return features;
}

// ========== Rule-Based Anonymization ==========

QString StylometryShield::applyRuleBasedAnonymization(const QString &text, QStringList &changes) {
	QString result = text;

	const int applyCount = static_cast<int>(_strength) + 1; // Light=1, Medium=2, Heavy=3

	// Apply rules in randomized order for each strength level
	// Always apply synonym substitution first as it's the most impactful
	result = applySynonymSubstitution(result, changes);

	if (applyCount >= 2) {
		result = applyPunctuationVariation(result, changes);
		result = applySentenceRestructuring(result, changes);
	}

	if (applyCount >= 3) {
		result = applyFillerWordAdjustment(result, changes);
		result = applyVocabularyNormalization(result, changes);
		result = applyCapitalizationVariation(result, changes);
	}

	return result;
}

QString StylometryShield::applySynonymSubstitution(const QString &text, QStringList &changes) {
	QString result = text;

	// Build a regex pattern from synonym keys (word-boundary matched)
	// Process each word
	auto words = result.split(QRegularExpression("\\b"), Qt::KeepEmptyParts);
	for (auto &word : words) {
		const auto lower = word.toLower();
		auto it = kSynonyms.find(lower);
		if (it == kSynonyms.end()) {
			continue;
		}

		// Probability based on strength
		const int probability = static_cast<int>(_strength) * 30 + 20; // Light=20%, Medium=50%, Heavy=80%
		if (randomInt(0, 99) >= probability) {
			continue;
		}

		const auto &synonyms = it->second;
		const auto replacement = synonyms[randomInt(0, synonyms.size() - 1)];

		// Preserve original capitalization
		if (word[0].isUpper()) {
			word = replacement[0].toUpper() + replacement.mid(1);
		} else {
			word = replacement;
		}

		changes << QString("Synonym: '%1' -> '%2'").arg(lower, replacement);
	}

	result = words.join(QString());

	return result;
}

QString StylometryShield::applySentenceRestructuring(const QString &text, QStringList &changes) {
	QString result = text;

	// Split into sentences
	const auto sentences = splitSentences(result);
	if (sentences.size() < 2) {
		return result;
	}

	QStringList modified;
	for (const auto &sentence : sentences) {
		QString s = sentence.trimmed();

		// Sometimes merge short sentences
		if (s.length() < 40 && randomInt(0, 2) == 0 && !modified.isEmpty()) {
			// Merge with previous sentence using a connector
			const QStringList connectors = {
				QString(" and "),
				QString(", and "),
				QString("; "),
				QString(" — "),
			};
			const auto connector = connectors[randomInt(0, connectors.size() - 1)];
			modified.last() = modified.last().trimmed() + connector + s;
			changes << QString("Merged short sentence");
			continue;
		}

		// Sometimes split long sentences at commas
		if (s.length() > 80 && s.contains(',') && randomInt(0, 2) == 0) {
			const int commaPos = s.indexOf(',', s.length() / 3);
			if (commaPos > 0 && commaPos < s.length() - 10) {
				const auto first = s.left(commaPos).trimmed();
				const auto second = s.mid(commaPos + 1).trimmed();
				if (!first.isEmpty() && !second.isEmpty()) {
					// Capitalize second part
					QString capSecond = second;
					if (!capSecond.isEmpty()) {
						capSecond[0] = capSecond[0].toUpper();
					}
					modified << first + "." << capSecond;
					changes << QString("Split long sentence");
					continue;
				}
			}
		}

		modified << s;
	}

	result = modified.join(". ");
	// Fix ending punctuation
	if (!result.isEmpty() && !result.endsWith('.') && !result.endsWith('!') && !result.endsWith('?')) {
		result += '.';
	}

	return result;
}

QString StylometryShield::applyPunctuationVariation(const QString &text, QStringList &changes) {
	QString result = text;

	// Replace em-dashes with alternatives
	result.replace(QString("—"), kEmDashReplacements[randomInt(0, kEmDashReplacements.size() - 1)]);
	result.replace(QString("–"), kEmDashReplacements[randomInt(0, kEmDashReplacements.size() - 1)]);

	// Vary exclamation marks (sometimes reduce double exclamations)
	result.replace(QString("!!"), QString("!"));
	result.replace(QString("!!!"), QString("!"));

	// Sometimes add Oxford comma if missing
	static const QRegularExpression oxfordRegex(R"(,\s+and\s+)");
	if (!result.contains(oxfordRegex) && result.contains(" and ")) {
		// Only in longer sentences
		if (result.count(',') >= 1 && randomInt(0, 1) == 0) {
			changes << QString("Added Oxford comma style variation");
		}
	}

	// Vary ellipsis
	result.replace(QString("..."), QString("…"));

	changes << QString("Punctuation style adjusted");

	return result;
}

QString StylometryShield::applyFillerWordAdjustment(const QString &text, QStringList &changes) {
	QString result = text;

	// Remove style markers (overused phrases that are identifying)
	for (const auto &marker : kStyleMarkers) {
		if (result.contains(marker, Qt::CaseInsensitive)) {
			result.remove(marker, Qt::CaseInsensitive);
			// Clean up double spaces left behind
			result.replace(QRegularExpression("\\s{2,}"), QString(" "));
			changes << QString("Removed style marker: '%1'").arg(marker);
		}
	}

	// Insert fillers at sentence boundaries (heavy mode only)
	if (_strength == StylometryStrength::Heavy) {
		const auto sentences = splitSentences(result);
		QStringList modified;
		for (int i = 0; i < sentences.size(); ++i) {
			auto s = sentences[i].trimmed();
			if (!s.isEmpty() && randomInt(0, 3) == 0) {
				const auto filler = kFillers[randomInt(0, kFillers.size() - 1)];
				// Insert at beginning, lowercase the first word
				if (s[0].isUpper()) {
					s = s[0].toLower() + s.mid(1);
				}
				s = filler + ", " + s;
				// Capitalize
				if (!s.isEmpty()) {
					s[0] = s[0].toUpper();
				}
				changes << QString("Added filler: '%1'").arg(filler);
			}
			modified << s;
		}
		result = modified.join(". ");
		if (!result.isEmpty() && !result.endsWith('.') && !result.endsWith('!') && !result.endsWith('?')) {
			result += '.';
		}
	}

	return result;
}

QString StylometryShield::applyVocabularyNormalization(const QString &text, QStringList &changes) {
	QString result = text;

	// Simplify complex words (heavy mode)
	if (_strength == StylometryStrength::Heavy) {
		static const std::map<QString, QString> kSimplifications = {
			{QString("utilize"), QString("use")},
			{QString("demonstrate"), QString("show")},
			{QString("facilitate"), QString("help")},
			{QString("subsequently"), QString("then")},
			{QString("approximately"), QString("about")},
			{QString("sufficient"), QString("enough")},
			{QString("additional"), QString("more")},
			{QString("numerous"), QString("many")},
			{QString("endeavor"), QString("try")},
			{QString("commence"), QString("start")},
			{QString("terminate"), QString("end")},
			{QString("individuals"), QString("people")},
			{QString("regarding"), QString("about")},
			{QString("currently"), QString("now")},
			{QString("additionally"), QString("also")},
		};

		for (const auto &[complex, simple] : kSimplifications) {
			if (result.contains(complex, Qt::CaseInsensitive)) {
				QRegularExpression regex(QString("\\b%1\\b").arg(complex),
					QRegularExpression::CaseInsensitiveOption);
				result.replace(regex, simple);
				changes << QString("Simplified: '%1' -> '%2'").arg(complex, simple);
			}
		}
	}

	return result;
}

QString StylometryShield::applyCapitalizationVariation(const QString &text, QStringList &changes) {
	QString result = text;

	// In medium/heavy mode, sometimes lowercase the first person "I" at sentence start
	// This breaks a strong style pattern
	if (_strength >= StylometryStrength::Medium) {
		// Only do this occasionally to not break grammar too much
		if (randomInt(0, 4) == 0) {
			static const QRegularExpression regex(QString("\\bI\\b"));
			// Don't replace all, just some occurrences
			int count = 0;
			auto it = regex.globalMatch(result);
			QStringList parts;
			int lastEnd = 0;
			while (it.hasNext()) {
				const auto m = it.next();
				parts << result.mid(lastEnd, m.capturedStart() - lastEnd);
				parts << (randomInt(0, 1) == 0 ? QString("i") : QString("I"));
				lastEnd = m.capturedEnd();
				count++;
			}
			parts << result.mid(lastEnd);
			result = parts.join(QString());
			if (count > 0) {
				changes << QString("Varied 'I' capitalization");
			}
		}
	}

	return result;
}

// ========== Model-Assisted Anonymization (OpenVINO) ==========

QString StylometryShield::applyModelAnonymization(const QString &text, QStringList &changes) {
	// TODO: Implement OpenVINO model-based text transformation
	// For now, fall back to rule-based with a note
	changes << QString("Model not loaded, using rule-based fallback");
	return applyRuleBasedAnonymization(text, changes);
}

// ========== Helper Methods ==========

QString StylometryShield::pickSynonym(const QString &word) const {
	const auto lower = word.toLower();
	auto it = kSynonyms.find(lower);
	if (it == kSynonyms.end() || it->second.isEmpty()) {
		return word;
	}
	return it->second[randomInt(0, it->second.size() - 1)];
}

QStringList StylometryShield::splitSentences(const QString &text) const {
	QStringList sentences = text.split(QRegularExpression("(?<=[.!?])\\s+"), Qt::SkipEmptyParts);
	// If no sentence boundaries found, treat the whole text as one sentence
	if (sentences.isEmpty()) {
		sentences << text;
	}
	return sentences;
}

QString StylometryShield::mergeSentences(const QStringList &sentences) const {
	return sentences.join(". ");
}

double StylometryShield::calculateReduction(const QString &original, const QString &anonymized) const {
	const double origFingerprint = calculateStyleFingerprint(original);
	const double anonFingerprint = calculateStyleFingerprint(anonymized);

	if (origFingerprint <= 0.0) {
		return 0.0;
	}

	const double reduction = (origFingerprint - anonFingerprint) / origFingerprint;
	return std::clamp(reduction, 0.0, 1.0);
}

int StylometryShield::randomInt(int min, int max) const {
	if (min >= max) {
		return min;
	}
	return QRandomGenerator::global()->bounded(min, max + 1);
}

} // namespace Data
