/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "base/flags.h"
#include "base/algorithm.h"
#include "base/bytes.h"

#include <crl/crl_time.h>
#include <QtCore/QReadWriteLock>
#include <QtCore/QRegularExpression>
#include <QtCore/QMimeData>
#include <QtNetwork/QNetworkProxy>
#include <cmath>
#include <set>
#include <filesystem>

#define qsl(s) QStringLiteral(s)

namespace base {

template <typename Value, typename From, typename Till>
inline bool in_range(Value &&value, From &&from, Till &&till) {
	return (value >= from) && (value < till);
}

inline bool CanReadDirectory(const QString &path) {
#ifndef Q_OS_MAC // directory_iterator since 10.15
	std::error_code error;
	std::filesystem::directory_iterator(path.toStdString(), error);
	return !error;
#else
	Unexpected("Not implemented.");
#endif
}

} // namespace base

static const int32 ScrollMax = INT_MAX;

extern uint64 _SharedMemoryLocation[];
template <typename T, unsigned int N>
T *SharedMemoryLocation() {
	static_assert(N < 4, "Only 4 shared memory locations!");
	return reinterpret_cast<T*>(_SharedMemoryLocation + N);
}

inline void mylocaltime(struct tm * _Tm, const time_t * _Time) {
#ifdef Q_OS_WIN
	localtime_s(_Tm, _Time);
#else
	localtime_r(_Time, _Tm);
#endif
}

namespace ThirdParty {

void start();
void finish();

} // namespace ThirdParty

const static uint32 _legacy_block_size = 64;
class HashLegacy {
public:

	HashLegacy(const void *input = 0, uint32 length = 0);
	~HashLegacy();
	void feed(const void *input, uint32 length);
	int32 *result();

private:

	void init();
	void finalize();

	bool _finalized;
	void *_ctx;
	uchar _digest[32]; // Buffer for SHA-256, truncated to 16 bytes for legacy compat

};

class HashSha256 {
public:
	HashSha256(const void *input = 0, uint32 length = 0);
	void feed(const void *input, uint32 length);
	int32 *result();

private:
	void init();
	void finalize();

	bool _finalized;
	void *_ctx; // EVP_MD_CTX*
	uchar _digest[32];
};

int32 *hashSha1(const void *data, uint32 len, void *dest); // dest - ptr to 20 bytes, returns (int32*)dest
inline std::array<char, 20> hashSha1(const void *data, int size) {
	auto result = std::array<char, 20>();
	hashSha1(data, size, result.data());
	return result;
}

int32 *hashSha256(const void *data, uint32 len, void *dest); // dest - ptr to 32 bytes, returns (int32*)dest
inline std::array<char, 32> hashSha256(const void *data, int size) {
	auto result = std::array<char, 32>();
	hashSha256(data, size, result.data());
	return result;
}

// hashSha384 removed - use hashSha256 instead

int32 *hashLegacy(const void *data, uint32 len, void *dest); // dest = ptr to 16 bytes, returns (int32*)dest
inline std::array<char, 16> hashLegacy(const void *data, int size) {
	auto result = std::array<char, 16>();
	hashLegacy(data, size, result.data());
	return result;
}

char *hashLegacyHex(const int32 *hashlegacy, void *dest); // dest = ptr to 32 bytes, returns (char*)dest
inline char *hashLegacyHex(const void *data, uint32 len, void *dest) { // dest = ptr to 32 bytes, returns (char*)dest
	return hashLegacyHex(HashLegacy(data, len).result(), dest);
}
inline std::array<char, 32> hashLegacyHex(const void *data, int size) {
	auto result = std::array<char, 32>();
	hashLegacyHex(data, size, result.data());
	return result;
}

QString translitRusEng(const QString &rus);
QString rusKeyboardLayoutSwitch(const QString &from);

inline int rowscount(int fullCount, int countPerRow) {
	return (fullCount + countPerRow - 1) / countPerRow;
}
inline int floorclamp(int value, int step, int lowest, int highest) {
	return std::clamp(value / step, lowest, highest);
}
inline int floorclamp(float64 value, int step, int lowest, int highest) {
	return std::clamp(
		static_cast<int>(std::floor(value / step)),
		lowest,
		highest);
}
inline int ceilclamp(int value, int step, int lowest, int highest) {
	return std::clamp((value + step - 1) / step, lowest, highest);
}
inline int ceilclamp(float64 value, int32 step, int32 lowest, int32 highest) {
	return std::clamp(
		static_cast<int>(std::ceil(value / step)),
		lowest,
		highest);
}
