/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "core/utils.h"

#include "base/qthelp_url.h"
#include "platform/platform_specific.h"

extern "C" {
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
} // extern "C"

#ifdef Q_OS_WIN
#elif defined Q_OS_MAC
#include <mach/mach_time.h>
#else
#include <time.h>
#endif

uint64 _SharedMemoryLocation[4] = { 0x00, 0x01, 0x02, 0x03 };

// Base types compile-time check
static_assert(sizeof(char) == 1, "Basic types size check failed");
static_assert(sizeof(uchar) == 1, "Basic types size check failed");
static_assert(sizeof(int16) == 2, "Basic types size check failed");
static_assert(sizeof(uint16) == 2, "Basic types size check failed");
static_assert(sizeof(int32) == 4, "Basic types size check failed");
static_assert(sizeof(uint32) == 4, "Basic types size check failed");
static_assert(sizeof(int64) == 8, "Basic types size check failed");
static_assert(sizeof(uint64) == 8, "Basic types size check failed");
static_assert(sizeof(float32) == 4, "Basic types size check failed");
static_assert(sizeof(float64) == 8, "Basic types size check failed");
static_assert(sizeof(mtpPrime) == 4, "Basic types size check failed");
static_assert(sizeof(MTPint) == 4, "Basic types size check failed");
static_assert(sizeof(MTPlong) == 8, "Basic types size check failed");
static_assert(sizeof(MTPint128) == 16, "Basic types size check failed");
static_assert(sizeof(MTPint256) == 32, "Basic types size check failed");
static_assert(sizeof(MTPdouble) == 8, "Basic types size check failed");

static_assert(sizeof(int) >= 4, "Basic types size check failed");

// Precise timing functions / rand init

namespace ThirdParty {

	void start() {
		Platform::ThirdParty::start();

		if (!RAND_status()) { // should be always inited in all modern OS
			const auto FeedSeed = [](auto value) {
				RAND_seed(&value, sizeof(value));
			};
#ifdef Q_OS_WIN
			LARGE_INTEGER li;
			QueryPerformanceFrequency(&li);
			FeedSeed(li.QuadPart);
			QueryPerformanceCounter(&li);
			FeedSeed(li.QuadPart);
#elif defined Q_OS_MAC
			mach_timebase_info_data_t tb = { 0 };
			mach_timebase_info(&tb);
			FeedSeed(tb);
			FeedSeed(mach_absolute_time());
#else
			timespec ts = { 0 };
			clock_gettime(CLOCK_MONOTONIC, &ts);
			FeedSeed(ts);
#endif
			if (!RAND_status()) {
				LOG(("MTP Error: Could not init OpenSSL rand, RAND_status() is 0..."));
			}
		}
	}

	void finish() {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		EVP_default_properties_enable_fips(nullptr, 0);
#else
		FIPS_mode_set(0);
#endif
		CONF_modules_unload(1);
	}
}

int32 *hashSha1(const void *data, uint32 len, void *dest) {
	return (int32*)SHA1((const uchar*)data, (size_t)len, (uchar*)dest);
}

int32 *hashSha256(const void *data, uint32 len, void *dest) {
	return (int32*)SHA256((const uchar*)data, (size_t)len, (uchar*)dest);
}

HashSha256::HashSha256(const void *input, uint32 length) : _finalized(false) {
	_ctx = EVP_MD_CTX_new();
	init();
	if (input && length > 0) feed(input, length);
}

void HashSha256::init() {
	EVP_DigestInit_ex((EVP_MD_CTX*)_ctx, EVP_sha256(), nullptr);
}

void HashSha256::feed(const void *input, uint32 length) {
	if (_finalized) return;
	EVP_DigestUpdate((EVP_MD_CTX*)_ctx, input, length);
}

void HashSha256::finalize() {
	if (!_finalized) {
		unsigned int len = 0;
		EVP_DigestFinal_ex((EVP_MD_CTX*)_ctx, _digest, &len);
		_finalized = true;
		EVP_MD_CTX_free((EVP_MD_CTX*)_ctx);
		_ctx = nullptr;
	}
}

int32 *HashSha256::result() {
	if (!_finalized) finalize();
	return (int32*)_digest;
}

// md5 hash, replaced with SHA-384 truncated for CNSA 2.0 compliance

namespace {
}

HashLegacy::HashLegacy(const void *input, uint32 length) : _finalized(false) {
	_ctx = EVP_MD_CTX_new();
	init();
	if (input && length > 0) feed(input, length);
}

HashLegacy::~HashLegacy() {
	if (_ctx) {
		EVP_MD_CTX_free((EVP_MD_CTX*)_ctx);
		_ctx = nullptr;
	}
}

void HashLegacy::feed(const void *input, uint32 length) {
	if (_finalized) return;
	EVP_DigestUpdate((EVP_MD_CTX*)_ctx, input, length);
}

int32 *HashLegacy::result() {
	if (!_finalized) finalize();
	return (int32*)_digest;
}

void HashLegacy::init() {
	EVP_DigestInit_ex((EVP_MD_CTX*)_ctx, EVP_md5(), nullptr);
}

void HashLegacy::finalize() {
	if (!_finalized) {
		unsigned int len = 0;
		EVP_DigestFinal_ex((EVP_MD_CTX*)_ctx, _digest, &len);
		_finalized = true;
	}
}

int32 *hashLegacy(const void *data, uint32 len, void *dest) {
	HashLegacy legacy(data, len);
	memcpy(dest, legacy.result(), 16);

	return (int32*)dest;
}

char *hashLegacyHex(const int32 *hashlegacy, void *dest) {
	char *legacyTo = (char*)dest;
	const uchar *res = (const uchar*)hashlegacy;

	for (int i = 0; i < 16; ++i) {
		uchar ch(res[i]), high = (ch >> 4) & 0x0F, low = ch & 0x0F;
		legacyTo[i * 2 + 0] = high + ((high > 0x09) ? ('a' - 0x0A) : '0');
		legacyTo[i * 2 + 1] = low + ((low > 0x09) ? ('a' - 0x0A) : '0');
	}

	return legacyTo;
}

namespace {
	QMap<QString, QString> fastRusEng;
	QHash<QChar, QString> fastLetterRusEng;
	QMap<uint32, QString> fastDoubleLetterRusEng;
	QHash<QChar, QChar> fastRusKeyboardSwitch;
	QHash<QChar, QChar> fastUkrKeyboardSwitch;
}

QString translitLetterRusEng(QChar letter, QChar next, int32 &toSkip) {
	if (fastDoubleLetterRusEng.isEmpty()) {
		fastDoubleLetterRusEng.insert((QString::fromUtf8("Ы").at(0).unicode() << 16) | QString::fromUtf8("й").at(0).unicode(), u"Y"_q);
		fastDoubleLetterRusEng.insert((QString::fromUtf8("и").at(0).unicode() << 16) | QString::fromUtf8("я").at(0).unicode(), u"ia"_q);
		fastDoubleLetterRusEng.insert((QString::fromUtf8("и").at(0).unicode() << 16) | QString::fromUtf8("й").at(0).unicode(), u"y"_q);
		fastDoubleLetterRusEng.insert((QString::fromUtf8("к").at(0).unicode() << 16) | QString::fromUtf8("с").at(0).unicode(), u"x"_q);
		fastDoubleLetterRusEng.insert((QString::fromUtf8("ы").at(0).unicode() << 16) | QString::fromUtf8("й").at(0).unicode(), u"y"_q);
		fastDoubleLetterRusEng.insert((QString::fromUtf8("ь").at(0).unicode() << 16) | QString::fromUtf8("е").at(0).unicode(), u"ye"_q);
	}
	QMap<uint32, QString>::const_iterator i = fastDoubleLetterRusEng.constFind((letter.unicode() << 16) | next.unicode());
	if (i != fastDoubleLetterRusEng.cend()) {
		toSkip = 2;
		return i.value();
	}

	toSkip = 1;
	if (fastLetterRusEng.isEmpty()) {
		fastLetterRusEng.insert(QString::fromUtf8("А").at(0), u"A"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Б").at(0), u"B"_q);
		fastLetterRusEng.insert(QString::fromUtf8("В").at(0), u"V"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Г").at(0), u"G"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Ґ").at(0), u"G"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Д").at(0), u"D"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Е").at(0), u"E"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Є").at(0), u"Ye"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Ё").at(0), u"Yo"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Ж").at(0), u"Zh"_q);
		fastLetterRusEng.insert(QString::fromUtf8("З").at(0), u"Z"_q);
		fastLetterRusEng.insert(QString::fromUtf8("И").at(0), u"I"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Ї").at(0), u"Yi"_q);
		fastLetterRusEng.insert(QString::fromUtf8("І").at(0), u"I"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Й").at(0), u"J"_q);
		fastLetterRusEng.insert(QString::fromUtf8("К").at(0), u"K"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Л").at(0), u"L"_q);
		fastLetterRusEng.insert(QString::fromUtf8("М").at(0), u"M"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Н").at(0), u"N"_q);
		fastLetterRusEng.insert(QString::fromUtf8("О").at(0), u"O"_q);
		fastLetterRusEng.insert(QString::fromUtf8("П").at(0), u"P"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Р").at(0), u"R"_q);
		fastLetterRusEng.insert(QString::fromUtf8("С").at(0), u"S"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Т").at(0), u"T"_q);
		fastLetterRusEng.insert(QString::fromUtf8("У").at(0), u"U"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Ў").at(0), u"W"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Ф").at(0), u"F"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Х").at(0), u"Kh"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Ц").at(0), u"Ts"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Ч").at(0), u"Ch"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Ш").at(0), u"Sh"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Щ").at(0), u"Sch"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Э").at(0), u"E"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Ю").at(0), u"Yu"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Я").at(0), u"Ya"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Ў").at(0), u"W"_q);
		fastLetterRusEng.insert(QString::fromUtf8("а").at(0), u"a"_q);
		fastLetterRusEng.insert(QString::fromUtf8("б").at(0), u"b"_q);
		fastLetterRusEng.insert(QString::fromUtf8("в").at(0), u"v"_q);
		fastLetterRusEng.insert(QString::fromUtf8("г").at(0), u"g"_q);
		fastLetterRusEng.insert(QString::fromUtf8("ґ").at(0), u"g"_q);
		fastLetterRusEng.insert(QString::fromUtf8("д").at(0), u"d"_q);
		fastLetterRusEng.insert(QString::fromUtf8("е").at(0), u"e"_q);
		fastLetterRusEng.insert(QString::fromUtf8("є").at(0), u"ye"_q);
		fastLetterRusEng.insert(QString::fromUtf8("ё").at(0), u"yo"_q);
		fastLetterRusEng.insert(QString::fromUtf8("ж").at(0), u"zh"_q);
		fastLetterRusEng.insert(QString::fromUtf8("з").at(0), u"z"_q);
		fastLetterRusEng.insert(QString::fromUtf8("й").at(0), u"y"_q);
		fastLetterRusEng.insert(QString::fromUtf8("ї").at(0), u"yi"_q);
		fastLetterRusEng.insert(QString::fromUtf8("і").at(0), u"i"_q);
		fastLetterRusEng.insert(QString::fromUtf8("л").at(0), u"l"_q);
		fastLetterRusEng.insert(QString::fromUtf8("м").at(0), u"m"_q);
		fastLetterRusEng.insert(QString::fromUtf8("н").at(0), u"n"_q);
		fastLetterRusEng.insert(QString::fromUtf8("о").at(0), u"o"_q);
		fastLetterRusEng.insert(QString::fromUtf8("п").at(0), u"p"_q);
		fastLetterRusEng.insert(QString::fromUtf8("р").at(0), u"r"_q);
		fastLetterRusEng.insert(QString::fromUtf8("с").at(0), u"s"_q);
		fastLetterRusEng.insert(QString::fromUtf8("т").at(0), u"t"_q);
		fastLetterRusEng.insert(QString::fromUtf8("у").at(0), u"u"_q);
		fastLetterRusEng.insert(QString::fromUtf8("ў").at(0), u"w"_q);
		fastLetterRusEng.insert(QString::fromUtf8("ф").at(0), u"f"_q);
		fastLetterRusEng.insert(QString::fromUtf8("х").at(0), u"kh"_q);
		fastLetterRusEng.insert(QString::fromUtf8("ц").at(0), u"ts"_q);
		fastLetterRusEng.insert(QString::fromUtf8("ч").at(0), u"ch"_q);
		fastLetterRusEng.insert(QString::fromUtf8("ш").at(0), u"sh"_q);
		fastLetterRusEng.insert(QString::fromUtf8("щ").at(0), u"sch"_q);
		fastLetterRusEng.insert(QString::fromUtf8("ъ").at(0), QString());
		fastLetterRusEng.insert(QString::fromUtf8("э").at(0), u"e"_q);
		fastLetterRusEng.insert(QString::fromUtf8("ю").at(0), u"yu"_q);
		fastLetterRusEng.insert(QString::fromUtf8("я").at(0), u"ya"_q);
		fastLetterRusEng.insert(QString::fromUtf8("ў").at(0), u"w"_q);
		fastLetterRusEng.insert(QString::fromUtf8("Ы").at(0), u"Y"_q);
		fastLetterRusEng.insert(QString::fromUtf8("и").at(0), u"i"_q);
		fastLetterRusEng.insert(QString::fromUtf8("к").at(0), u"k"_q);
		fastLetterRusEng.insert(QString::fromUtf8("ы").at(0), u"y"_q);
		fastLetterRusEng.insert(QString::fromUtf8("ь").at(0), QString());
	}
	QHash<QChar, QString>::const_iterator j = fastLetterRusEng.constFind(letter);
	if (j != fastLetterRusEng.cend()) {
		return j.value();
	}
	return QString(1, letter);
}

QString translitRusEng(const QString &rus) {
	if (fastRusEng.isEmpty()) {
		fastRusEng.insert(QString::fromUtf8("Александр"), u"Alexander"_q);
		fastRusEng.insert(QString::fromUtf8("александр"), u"alexander"_q);
		fastRusEng.insert(QString::fromUtf8("Филипп"), u"Philip"_q);
		fastRusEng.insert(QString::fromUtf8("филипп"), u"philip"_q);
		fastRusEng.insert(QString::fromUtf8("Пётр"), u"Petr"_q);
		fastRusEng.insert(QString::fromUtf8("пётр"), u"petr"_q);
		fastRusEng.insert(QString::fromUtf8("Гай"), u"Gai"_q);
		fastRusEng.insert(QString::fromUtf8("гай"), u"gai"_q);
		fastRusEng.insert(QString::fromUtf8("Ильин"), u"Ilyin"_q);
		fastRusEng.insert(QString::fromUtf8("ильин"), u"ilyin"_q);
	}
	QMap<QString, QString>::const_iterator i = fastRusEng.constFind(rus);
	if (i != fastRusEng.cend()) {
		return i.value();
	}

	QString result;
	result.reserve(rus.size() * 2);

	int32 toSkip = 0;
	for (QString::const_iterator i = rus.cbegin(), e = rus.cend(); i != e; i += toSkip) {
		result += translitLetterRusEng(*i, (i + 1 == e) ? ' ' : *(i + 1), toSkip);
	}
	return result;
}

QString engAlphabet = "qwertyuiop[]asdfghjkl;'zxcvbnm,.";
QString engAlphabetUpper = engAlphabet.toUpper();

void initializeKeyboardSwitch() {
	if (fastRusKeyboardSwitch.isEmpty()) {
		QString rusAlphabet = "йцукенгшщзхъфывапролджэячсмитьбю";
		QString rusAlphabetUpper = rusAlphabet.toUpper();
		for (int i = 0; i < rusAlphabet.size(); ++i) {
			fastRusKeyboardSwitch.insert(engAlphabetUpper[i], rusAlphabetUpper[i]);
			fastRusKeyboardSwitch.insert(engAlphabet[i], rusAlphabet[i]);
			fastRusKeyboardSwitch.insert(rusAlphabetUpper[i], engAlphabetUpper[i]);
			fastRusKeyboardSwitch.insert(rusAlphabet[i], engAlphabet[i]);
		}
	}
	if (fastUkrKeyboardSwitch.isEmpty()) {
		QString ukrAlphabet = "йцукенгшщзхїфівапролджєячсмитьбю";
		QString ukrAlphabetUpper = ukrAlphabet.toUpper();
		for (int i = 0; i < ukrAlphabet.size(); ++i) {
			fastUkrKeyboardSwitch.insert(engAlphabetUpper[i], ukrAlphabetUpper[i]);
			fastUkrKeyboardSwitch.insert(engAlphabet[i], ukrAlphabet[i]);
			fastUkrKeyboardSwitch.insert(ukrAlphabetUpper[i], engAlphabetUpper[i]);
			fastUkrKeyboardSwitch.insert(ukrAlphabet[i], engAlphabet[i]);
		}
	}
}

QString switchKeyboardLayout(const QString& from, QHash<QChar, QChar>& keyboardSwitch) {
	QString result;
	result.reserve(from.size());
	for (QString::const_iterator i = from.cbegin(), e = from.cend(); i != e; ++i) {
		QHash<QChar, QChar>::const_iterator j = keyboardSwitch.constFind(*i);
		if (j == keyboardSwitch.cend()) {
			result += *i;
		} else {
			result += j.value();
		}
	}
	return result;
}

QString rusKeyboardLayoutSwitch(const QString& from) {
	initializeKeyboardSwitch();
	QString rus = switchKeyboardLayout(from, fastRusKeyboardSwitch);
	QString ukr = switchKeyboardLayout(from, fastUkrKeyboardSwitch);
	return rus == ukr ? rus : rus + ' ' + ukr;
}
