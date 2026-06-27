/*
This file is part of CRYPTOGRAM Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/CRYPTOGRAM/blob/main/LEGAL
*/
#pragma once

#include "data/data_signal_protocol.h"
#include "data/data_mls_protocol.h"
#include "base/bytes.h"

#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <vector>


namespace Data {

// Sentinel entity type used to carry CRYPTOGRAM key-exchange payloads.
// Chosen well outside Telegram's reserved range so stock clients treat it
// as messageEntityUnknown and silently ignore it.
constexpr uint32 kCryptogramEntityType = 0x43524B45; // 'C','R','K','E'

// Version byte embedded in every payload for forward compatibility.
constexpr uint8 kTransportVersion = 0x01;

// Maximum serialised KeyBundle size (bytes) before base64 encoding.
// Identity(32) + SignedPreKey(32) + OneTimePreKey(32) + Signature(64) +
// deviceId(8) + registrationId(8) + overhead ≈ 256 bytes.
constexpr int kMaxKeyBundleBytes = 512;

// Payload type byte distinguishes Signal key bundles from MLS payloads.
constexpr uint8 kPayloadTypeKeyBundle = 0x01;
constexpr uint8 kPayloadTypeMLSKeyPackage = 0x02;
constexpr uint8 kPayloadTypeMLSWelcome = 0x03;
constexpr uint8 kPayloadTypeMLSCommit = 0x04;

// Maximum serialised MLSKeyPackage size (bytes).
// version(2) + ciphersuite(2) + initKey(32) + credPublicKey(32) +
// credential(variable, max 128) + signature(64) + timestamps(16) ≈ 300 bytes.
constexpr int kMaxMLSKeyPackageBytes = 512;

// SignalProtocolTransport
// ─────────────────────────────────────────────────────────────────────────
// Serialises a SignalProtocol::KeyBundle into a messageEntityUnknown-
// compatible TL entity, and deserialises incoming entities back.
//
// Wire format (binary, before base64):
//   [1 byte]  kTransportVersion
//   [1 byte]  field bitmap  (bit 0 = oneTimePreKey present)
//   [8 bytes] registrationId (little-endian uint64)
//   [32 bytes] identityKey
//   [32 bytes] signedPreKey
//   [64 bytes] signature
//   [32 bytes] oneTimePreKey  (only if bit 0 of bitmap is set)
//
// The binary blob is base64url-encoded and stored in the *message text*
// at the offset/length described by the entity, so stock clients that
// render the message still just see an empty string (we set the message
// text to a zero-width space and point the entity at offset 0, length 1).
// ─────────────────────────────────────────────────────────────────────────
class SignalProtocolTransport final {
public:
	// Encode a KeyBundle into a raw TL entity bytes block (not yet wrapped
	// in MTPMessageEntity). Returns empty on failure.
	[[nodiscard]] static QByteArray encodeKeyBundle(
		const SignalProtocol::KeyBundle &bundle);

	// Decode a raw entity payload back into a KeyBundle.
	// Returns std::nullopt if the payload is malformed or wrong version.
	[[nodiscard]] static std::optional<SignalProtocol::KeyBundle>
		decodeKeyBundle(const QByteArray &payload);

	// Check whether an entity carries a CRYPTOGRAM key-exchange payload.
	// entity_type should be the raw constructor number from the TL object.
	[[nodiscard]] static bool isCryptogramEntity(uint32 entityType);

	// Extract all CRYPTOGRAM key-exchange entities from an MTP message,
	// decode them, and return the list. Returns empty if none found.
	// Also strips the recognised entities from |entities| in-place so the
	// UI renderer never sees them.
	[[nodiscard]] static std::vector<SignalProtocol::KeyBundle>
		extractAndStripBundles(
			QVector<MTPMessageEntity> &entities,
			const QString &messageText);

	// Build the entity + invisible message text for an outgoing key exchange.
	// |outMessageText| is set to the zero-width-encoded payload — pass it as
	// the message body. Stock clients see a completely blank message.
	// The returned entity should be appended to the outgoing entities list.
	[[nodiscard]] static MTPMessageEntity buildOutgoingEntity(
		const SignalProtocol::KeyBundle &bundle,
		QString &outMessageText);

	// ── MLS Key Package transport ─────────────────────────────────────────
	// Encode an MLSKeyPackage into raw bytes for ZW transport.
	[[nodiscard]] static QByteArray encodeMLSKeyPackage(
		const MLSKeyPackage &package);

	// Decode raw bytes back into an MLSKeyPackage.
	[[nodiscard]] static std::optional<MLSKeyPackage>
		decodeMLSKeyPackage(const QByteArray &payload);

	// Extract all MLS key packages from message entities.
	// Also strips the recognised entities in-place.
	[[nodiscard]] static std::vector<MLSKeyPackage>
		extractAndStripMLSKeyPackages(
			QVector<MTPMessageEntity> &entities,
			const QString &messageText);

	// Build outgoing entity + ZW text for an MLS key package.
	[[nodiscard]] static MTPMessageEntity buildOutgoingMLSKeyPackage(
		const MLSKeyPackage &package,
		QString &outMessageText);

	// ── MLS Welcome message transport ─────────────────────────────────────
	// Encode an MLSWelcome into raw bytes for ZW transport.
	[[nodiscard]] static QByteArray encodeMLSWelcome(
		const MLSWelcome &welcome);

	// Decode raw bytes back into an MLSWelcome.
	[[nodiscard]] static std::optional<MLSWelcome>
		decodeMLSWelcome(const QByteArray &payload);

	// Build outgoing entity + ZW text for an MLS Welcome.
	[[nodiscard]] static MTPMessageEntity buildOutgoingMLSWelcome(
		const MLSWelcome &welcome,
		QString &outMessageText);

	// Public helpers for encoding/decoding raw bytes to/from ZW QString.
	// Used by apiwrap/data_session for MLS ciphertext transport.
	[[nodiscard]] static QString bytesToZeroWidth(const QByteArray &bytes);
	[[nodiscard]] static QByteArray zeroWidthToBytes(const QString &zwText);

private:
	SignalProtocolTransport() = delete;
};

} // namespace Data
