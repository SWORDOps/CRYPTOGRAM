/*
This file is part of CRYPTOGRAM Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/CRYPTOGRAM/blob/main/LEGAL
*/
#include "data/data_signal_transport.h"

#include <QtCore/QByteArray>
#include <QtCore/QDataStream>
#include <QtCore/QIODevice>
#include <QtCore/QString>

namespace Data {
namespace {

// Zero-width Unicode characters used as an invisible base-4 alphabet.
// All four render as nothing in every Telegram client and font.
//   U+200B  ZERO WIDTH SPACE              = 0b00
//   U+200C  ZERO WIDTH NON-JOINER         = 0b01
//   U+200D  ZERO WIDTH JOINER             = 0b10
//   U+FEFF  ZERO WIDTH NO-BREAK SPACE     = 0b11
constexpr char32_t kZW[4] = { 0x200B, 0x200C, 0x200D, 0xFEFF };

// Encode raw bytes → invisible QString (base-4, 4 chars per byte).
[[nodiscard]] QString zwEncode(const QByteArray &data) {
	QString out;
	out.reserve(data.size() * 4);
	for (unsigned char byte : data) {
		out += QChar(static_cast<uint16_t>(kZW[(byte >> 6) & 0x3]));
		out += QChar(static_cast<uint16_t>(kZW[(byte >> 4) & 0x3]));
		out += QChar(static_cast<uint16_t>(kZW[(byte >> 2) & 0x3]));
		out += QChar(static_cast<uint16_t>(kZW[(byte >> 0) & 0x3]));
	}
	return out;
}

// Decode invisible QString → raw bytes.  Returns empty on invalid input.
[[nodiscard]] QByteArray zwDecode(const QString &text) {
	if (text.size() % 4 != 0) {
		return {};
	}
	QByteArray out;
	out.reserve(text.size() / 4);
	for (int i = 0; i < text.size(); i += 4) {
		uint8_t byte = 0;
		for (int j = 0; j < 4; ++j) {
			const uint16_t cp = text[i + j].unicode();
			int bits = -1;
			for (int k = 0; k < 4; ++k) {
				if (cp == static_cast<uint16_t>(kZW[k])) {
					bits = k;
					break;
				}
			}
			if (bits < 0) return {}; // unexpected codepoint
			byte = (byte << 2) | static_cast<uint8_t>(bits);
		}
		out += static_cast<char>(byte);
	}
	return out;
}

// Minimum valid serialised payload (see encodeKeyBundle).
// version(1) + bitmap(1) + regId(8) + identityKey(32) + signedPreKey(32) +
// signature(64) = 138 bytes (without oneTimePreKey).
constexpr int kMinPayloadBytes = 138;

// Minimum valid MLS key package payload:
// version(1) + payloadType(1) + mlsVersion(2) + ciphersuite(2) +
// initKey(32) + credPublicKey(32) + signature(64) = 134 bytes.
constexpr int kMinMLSKeyPackageBytes = 134;

// Minimum valid MLS welcome payload:
// version(1) + payloadType(1) + mlsVersion(2) + ciphersuite(2) +
// encryptedGroupSecrets(variable, min 1) + encryptedGroupInfo(variable, min 1) = 8 bytes.
constexpr int kMinMLSWelcomeBytes = 8;

} // namespace

// ---------------------------------------------------------------------------
// Serialisation
// ---------------------------------------------------------------------------

QByteArray SignalProtocolTransport::encodeKeyBundle(
		const SignalProtocol::KeyBundle &bundle) {
	if (bundle.identityKey.size() != 32
		|| bundle.signedPreKey.size() != 32
		|| bundle.signature.size() != 64) {
		return {};
	}

	const bool hasOtp = (bundle.oneTimePreKey.size() == 32);

	QByteArray raw;
	raw.reserve(kMinPayloadBytes + (hasOtp ? 32 : 0));

	QDataStream out(&raw, QIODevice::WriteOnly);
	out.setByteOrder(QDataStream::LittleEndian);

	out << static_cast<quint8>(kTransportVersion);
	out << static_cast<quint8>(hasOtp ? 0x01 : 0x00);
	out << static_cast<quint64>(bundle.deviceId.registrationId);

	out.writeRawData(
		reinterpret_cast<const char *>(bundle.identityKey.data()), 32);
	out.writeRawData(
		reinterpret_cast<const char *>(bundle.signedPreKey.data()), 32);
	out.writeRawData(
		reinterpret_cast<const char *>(bundle.signature.data()), 64);
	if (hasOtp) {
		out.writeRawData(
			reinterpret_cast<const char *>(bundle.oneTimePreKey.data()), 32);
	}

	return (out.status() == QDataStream::Ok) ? raw : QByteArray{};
}

std::optional<SignalProtocol::KeyBundle>
SignalProtocolTransport::decodeKeyBundle(const QByteArray &raw) {
	if (raw.size() < kMinPayloadBytes) {
		return std::nullopt;
	}

	QDataStream in(raw);
	in.setByteOrder(QDataStream::LittleEndian);

	quint8 version = 0, bitmap = 0;
	quint64 regId = 0;
	in >> version >> bitmap >> regId;

	if (version != kTransportVersion) return std::nullopt;

	const bool hasOtp = (bitmap & 0x01) != 0;

	auto readKey = [&](int size) -> bytes::vector {
		bytes::vector key(size);
		if (in.readRawData(
				reinterpret_cast<char *>(key.data()), size) != size) {
			key.clear();
		}
		return key;
	};

	SignalProtocol::KeyBundle bundle;
	bundle.deviceId.registrationId = regId;
	bundle.identityKey   = readKey(32);
	bundle.signedPreKey  = readKey(32);
	bundle.signature     = readKey(64);
	if (hasOtp) bundle.oneTimePreKey = readKey(32);

	if (in.status() != QDataStream::Ok
		|| bundle.identityKey.empty()
		|| bundle.signedPreKey.empty()
		|| bundle.signature.empty()) {
		return std::nullopt;
	}
	return bundle;
}

// ---------------------------------------------------------------------------
// Entity helpers
// ---------------------------------------------------------------------------

bool SignalProtocolTransport::isCryptogramEntity(uint32 entityType) {
	return entityType == kCryptogramEntityType;
}

std::vector<SignalProtocol::KeyBundle>
SignalProtocolTransport::extractAndStripBundles(
		QVector<MTPMessageEntity> &entities,
		const QString &messageText) {
	std::vector<SignalProtocol::KeyBundle> result;

	auto it = entities.begin();
	while (it != entities.end()) {
		const auto &entity = *it;
		if (entity.type() == mtpc_messageEntityUnknown) {
			const auto &data = entity.c_messageEntityUnknown();
			const int off = data.voffset().v;
			const int len = data.vlength().v;

			// Validate range
			if (off < 0 || len <= 0 || (off + len) > messageText.size()) {
				++it;
				continue;
			}

			// The payload is invisible ZW chars in the message text.
			// Confirm all chars in range are from our ZW alphabet.
			const auto fragment = messageText.mid(off, len);
			bool allZW = true;
			for (const auto &ch : fragment) {
				const uint16_t cp = ch.unicode();
				if (cp != 0x200B && cp != 0x200C
						&& cp != 0x200D && cp != 0xFEFF) {
					allZW = false;
					break;
				}
			}
			if (!allZW) {
				++it;
				continue;
			}

			// Decode ZW chars → raw bytes → KeyBundle
			const auto raw = zwDecode(fragment);
			if (auto bundle = decodeKeyBundle(raw)) {
				result.push_back(std::move(*bundle));
				it = entities.erase(it);
				continue;
			}
		}
		++it;
	}
	return result;
}

// ---------------------------------------------------------------------------
// Outgoing builder
// ---------------------------------------------------------------------------

// Fills |outMessageText| with the invisible ZW-encoded payload and returns
// the entity covering those characters.
// The caller MUST set the message text to |outMessageText| (which will look
// completely blank to stock clients) and append the returned entity.
MTPMessageEntity SignalProtocolTransport::buildOutgoingEntity(
		const SignalProtocol::KeyBundle &bundle,
		QString &outMessageText) {
	const auto raw = encodeKeyBundle(bundle);
	const auto zwText = zwEncode(raw);
	const int length = zwText.size();
	outMessageText = zwText;
	// messageEntityUnknown(offset=0, length=len(ZW payload))
	return MTP_messageEntityUnknown(MTP_int(0), MTP_int(length));
}

// ---------------------------------------------------------------------------
// MLS Key Package Serialisation
// ---------------------------------------------------------------------------
//
// Wire format (binary, before base64 + ZW encoding):
//   [1 byte]  kTransportVersion (0x01)
//   [1 byte]  kPayloadTypeMLSKeyPackage (0x02)
//   [2 bytes] MLS protocol version (little-endian uint16)
//   [2 bytes] ciphersuite (little-endian uint16)
//   [32 bytes] initKey (HPKE public key)
//   [32 bytes] credentialPublicKey (signature public key)
//   [4 bytes] credential length (little-endian uint32)
//   [N bytes] credential data
//   [64 bytes] signature
//   [8 bytes] creationTime (ms since epoch, little-endian int64)
//   [8 bytes] expirationTime (ms since epoch, little-endian int64)

QByteArray SignalProtocolTransport::encodeMLSKeyPackage(
		const MLSKeyPackage &package) {
	if (package.initKey.size() != 32
		|| package.credentialPublicKey.size() != 32
		|| package.signature.size() != 64) {
		return {};
	}

	QByteArray out;
	out.reserve(kMaxMLSKeyPackageBytes);

	// Write little-endian helpers
	auto writeU16 = [&out](uint16_t v) {
		out.append(static_cast<char>(v & 0xFF));
		out.append(static_cast<char>((v >> 8) & 0xFF));
	};
	auto writeU32 = [&out](uint32_t v) {
		for (int i = 0; i < 4; ++i) {
			out.append(static_cast<char>((v >> (i * 8)) & 0xFF));
		}
	};
	auto writeI64 = [&out](qint64 v) {
		for (int i = 0; i < 8; ++i) {
			out.append(static_cast<char>((v >> (i * 8)) & 0xFF));
		}
	};
	auto writeBytes = [&out](const bytes::vector &src) {
		const auto *ptr = reinterpret_cast<const char*>(src.data());
		out.append(ptr, src.size());
	};

	out.append(static_cast<char>(kTransportVersion));
	out.append(static_cast<char>(kPayloadTypeMLSKeyPackage));
	writeU16(package.version);
	writeU16(static_cast<uint16_t>(package.ciphersuite));
	writeBytes(package.initKey);
	writeBytes(package.credentialPublicKey);

	// Credential (variable length)
	const auto credLen = static_cast<uint32_t>(package.credential.size());
	if (credLen > 128) return {}; // Sanity limit
	writeU32(credLen);
	if (credLen > 0) {
		writeBytes(package.credential);
	}

	writeBytes(package.signature);
	writeI64(package.creationTime.toMSecsSinceEpoch());
	writeI64(package.expirationTime.toMSecsSinceEpoch());

	return out;
}

std::optional<MLSKeyPackage>
SignalProtocolTransport::decodeMLSKeyPackage(const QByteArray &payload) {
	if (payload.size() < kMinMLSKeyPackageBytes) {
		return std::nullopt;
	}

	const auto *p = payload.constData();
	int pos = 0;

	auto readU16 = [&p, &pos]() -> uint16_t {
		uint16_t v = static_cast<uint8_t>(p[pos]);
		v |= static_cast<uint16_t>(static_cast<uint8_t>(p[pos + 1])) << 8;
		pos += 2;
		return v;
	};
	auto readU32 = [&p, &pos]() -> uint32_t {
		uint32_t v = 0;
		for (int i = 0; i < 4; ++i) {
			v |= static_cast<uint32_t>(static_cast<uint8_t>(p[pos + i])) << (i * 8);
		}
		pos += 4;
		return v;
	};
	auto readI64 = [&p, &pos]() -> qint64 {
		qint64 v = 0;
		for (int i = 0; i < 8; ++i) {
			v |= static_cast<qint64>(static_cast<uint8_t>(p[pos + i])) << (i * 8);
		}
		pos += 8;
		return v;
	};
	auto readBytes = [&p, &pos](int n) -> bytes::vector {
		bytes::vector v(n);
		std::memcpy(v.data(), p + pos, n);
		pos += n;
		return v;
	};

	// Version
	const auto ver = static_cast<uint8_t>(p[pos++]);
	if (ver != kTransportVersion) return std::nullopt;

	// Payload type
	const auto ptype = static_cast<uint8_t>(p[pos++]);
	if (ptype != kPayloadTypeMLSKeyPackage) return std::nullopt;

	MLSKeyPackage package;
	package.version = readU16();
	package.ciphersuite = static_cast<MLSCiphersuite>(readU16());
	package.initKey = readBytes(32);
	package.credentialPublicKey = readBytes(32);

	const auto credLen = readU32();
	if (credLen > 128) return std::nullopt;
	if (credLen > 0) {
		package.credential = readBytes(credLen);
	}

	package.signature = readBytes(64);
	package.creationTime = QDateTime::fromMSecsSinceEpoch(readI64());
	package.expirationTime = QDateTime::fromMSecsSinceEpoch(readI64());

	return package;
}

std::vector<MLSKeyPackage>
SignalProtocolTransport::extractAndStripMLSKeyPackages(
		QVector<MTPMessageEntity> &entities,
		const QString &messageText) {
	std::vector<MLSKeyPackage> result;

	auto it = entities.begin();
	while (it != entities.end()) {
		if (it->type() == mtpc_messageEntityUnknown) {
			const auto &data = it->c_messageEntityUnknown();
			const int off = data.voffset().v;
			const int len = data.vlength().v;

			if (off < 0 || len <= 0 || (off + len) > messageText.size()) {
				++it;
				continue;
			}

			const auto fragment = messageText.mid(off, len);
			bool allZW = true;
			for (const auto &ch : fragment) {
				const uint16_t cp = ch.unicode();
				if (cp != 0x200B && cp != 0x200C
						&& cp != 0x200D && cp != 0xFEFF) {
					allZW = false;
					break;
				}
			}
			if (!allZW) {
				++it;
				continue;
			}

			const auto raw = zwDecode(fragment);
			if (auto pkg = decodeMLSKeyPackage(raw)) {
				result.push_back(std::move(*pkg));
				it = entities.erase(it);
				continue;
			}
		}
		++it;
	}
	return result;
}

MTPMessageEntity SignalProtocolTransport::buildOutgoingMLSKeyPackage(
		const MLSKeyPackage &package,
		QString &outMessageText) {
	const auto raw = encodeMLSKeyPackage(package);
	const auto zwText = zwEncode(raw);
	const int length = zwText.size();
	outMessageText = zwText;
	return MTP_messageEntityUnknown(MTP_int(0), MTP_int(length));
}

// ---------------------------------------------------------------------------
// MLS Welcome Serialisation
// ---------------------------------------------------------------------------
//
// Wire format:
//   [1 byte]  kTransportVersion (0x01)
//   [1 byte]  kPayloadTypeMLSWelcome (0x03)
//   [2 bytes] MLS protocol version (little-endian uint16)
//   [2 bytes] ciphersuite (little-endian uint16)
//   [4 bytes] encryptedGroupSecrets length
//   [N bytes] encryptedGroupSecrets data
//   [4 bytes] encryptedGroupInfo length
//   [M bytes] encryptedGroupInfo data

QByteArray SignalProtocolTransport::encodeMLSWelcome(const MLSWelcome &welcome) {
	QByteArray out;
	out.reserve(64 + welcome.encryptedGroupSecrets.size()
		+ welcome.encryptedGroupInfo.size());

	auto writeU16 = [&out](uint16_t v) {
		out.append(static_cast<char>(v & 0xFF));
		out.append(static_cast<char>((v >> 8) & 0xFF));
	};
	auto writeU32 = [&out](uint32_t v) {
		for (int i = 0; i < 4; ++i) {
			out.append(static_cast<char>((v >> (i * 8)) & 0xFF));
		}
	};
	auto writeBytes = [&out](const bytes::vector &src) {
		const auto *ptr = reinterpret_cast<const char*>(src.data());
		out.append(ptr, src.size());
	};

	out.append(static_cast<char>(kTransportVersion));
	out.append(static_cast<char>(kPayloadTypeMLSWelcome));
	writeU16(welcome.version);
	writeU16(static_cast<uint16_t>(welcome.ciphersuite));

	const auto secretsLen = static_cast<uint32_t>(welcome.encryptedGroupSecrets.size());
	writeU32(secretsLen);
	if (secretsLen > 0) writeBytes(welcome.encryptedGroupSecrets);

	const auto infoLen = static_cast<uint32_t>(welcome.encryptedGroupInfo.size());
	writeU32(infoLen);
	if (infoLen > 0) writeBytes(welcome.encryptedGroupInfo);

	return out;
}

std::optional<MLSWelcome>
SignalProtocolTransport::decodeMLSWelcome(const QByteArray &payload) {
	if (payload.size() < kMinMLSWelcomeBytes) {
		return std::nullopt;
	}

	const auto *p = payload.constData();
	int pos = 0;

	auto readU16 = [&p, &pos]() -> uint16_t {
		uint16_t v = static_cast<uint8_t>(p[pos]);
		v |= static_cast<uint16_t>(static_cast<uint8_t>(p[pos + 1])) << 8;
		pos += 2;
		return v;
	};
	auto readU32 = [&p, &pos]() -> uint32_t {
		uint32_t v = 0;
		for (int i = 0; i < 4; ++i) {
			v |= static_cast<uint32_t>(static_cast<uint8_t>(p[pos + i])) << (i * 8);
		}
		pos += 4;
		return v;
	};
	auto readBytes = [&p, &pos](int n) -> bytes::vector {
		bytes::vector v(n);
		std::memcpy(v.data(), p + pos, n);
		pos += n;
		return v;
	};

	const auto ver = static_cast<uint8_t>(p[pos++]);
	if (ver != kTransportVersion) return std::nullopt;

	const auto ptype = static_cast<uint8_t>(p[pos++]);
	if (ptype != kPayloadTypeMLSWelcome) return std::nullopt;

	MLSWelcome welcome;
	welcome.version = readU16();
	welcome.ciphersuite = static_cast<MLSCiphersuite>(readU16());

	const auto secretsLen = readU32();
	if (pos + secretsLen > payload.size()) return std::nullopt;
	if (secretsLen > 0) welcome.encryptedGroupSecrets = readBytes(secretsLen);

	const auto infoLen = readU32();
	if (pos + infoLen > payload.size()) return std::nullopt;
	if (infoLen > 0) welcome.encryptedGroupInfo = readBytes(infoLen);

	welcome.timestamp = QDateTime::currentDateTime();

	return welcome;
}

MTPMessageEntity SignalProtocolTransport::buildOutgoingMLSWelcome(
		const MLSWelcome &welcome,
		QString &outMessageText) {
	const auto raw = encodeMLSWelcome(welcome);
	const auto zwText = zwEncode(raw);
	const int length = zwText.size();
	outMessageText = zwText;
	return MTP_messageEntityUnknown(MTP_int(0), MTP_int(length));
}

// Public wrappers for the anonymous-namespace ZW helpers.
QString SignalProtocolTransport::bytesToZeroWidth(const QByteArray &bytes) {
	return zwEncode(bytes);
}

QByteArray SignalProtocolTransport::zeroWidthToBytes(const QString &zwText) {
	return zwDecode(zwText);
}

} // namespace Data
