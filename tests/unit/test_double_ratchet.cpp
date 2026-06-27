/*
CRYPTOGRAM Signal Protocol Tests
Tests the Signal Protocol transport layer, key bundle encoding/decoding,
and cryptographic primitive wiring.
*/

#include <catch2/catch_test_macros.hpp>

#include "data/data_signal_transport.h"
#include "data/data_signal_protocol.h"
#include "data/data_mls_protocol.h"
#include "base/random.h"
#include "base/bytes.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace Data;

// Helper: generate a random key of the given size.
static bytes::vector randomKey(int size) {
	bytes::vector key(size);
	RAND_bytes(reinterpret_cast<unsigned char*>(key.data()), size);
	return key;
}

// Helper: build a valid KeyBundle with random keys.
static SignalProtocol::KeyBundle makeBundle() {
	SignalProtocol::KeyBundle bundle;
	bundle.identityKey = randomKey(32);
	bundle.signedPreKey = randomKey(32);
	bundle.signature = randomKey(64);
	bundle.oneTimePreKey = randomKey(32);
	bundle.deviceId.registrationId = 0x1234567890ABCDEF;
	return bundle;
}

// ─── Key Bundle Encoding / Decoding ────────────────────────────────────────────

TEST_CASE("KeyBundle encode/decode round-trip", "[signal][transport][unit]") {
	auto bundle = makeBundle();

	auto encoded = SignalProtocolTransport::encodeKeyBundle(bundle);
	REQUIRE(!encoded.isEmpty());

	auto decoded = SignalProtocolTransport::decodeKeyBundle(encoded);
	REQUIRE(decoded.has_value());

	REQUIRE(decoded->identityKey == bundle.identityKey);
	REQUIRE(decoded->signedPreKey == bundle.signedPreKey);
	REQUIRE(decoded->signature == bundle.signature);
	REQUIRE(decoded->oneTimePreKey == bundle.oneTimePreKey);
	REQUIRE(decoded->deviceId.registrationId == bundle.deviceId.registrationId);
}

TEST_CASE("KeyBundle encode rejects invalid sizes", "[signal][transport][unit]") {
	SignalProtocol::KeyBundle bundle;
	bundle.identityKey = randomKey(16);  // Wrong size
	bundle.signedPreKey = randomKey(32);
	bundle.signature = randomKey(64);

	auto encoded = SignalProtocolTransport::encodeKeyBundle(bundle);
	REQUIRE(encoded.isEmpty());
}

TEST_CASE("KeyBundle decode rejects wrong version", "[signal][transport][unit]") {
	auto bundle = makeBundle();
	auto encoded = SignalProtocolTransport::encodeKeyBundle(bundle);
	REQUIRE(!encoded.isEmpty());

	// Corrupt the version byte
	auto corrupted = encoded;
	corrupted[0] = 0x02;  // Unsupported version

	auto decoded = SignalProtocolTransport::decodeKeyBundle(corrupted);
	REQUIRE(!decoded.has_value());
}

TEST_CASE("KeyBundle without oneTimePreKey", "[signal][transport][unit]") {
	SignalProtocol::KeyBundle bundle;
	bundle.identityKey = randomKey(32);
	bundle.signedPreKey = randomKey(32);
	bundle.signature = randomKey(64);
	bundle.oneTimePreKey.clear();  // No OTP
	bundle.deviceId.registrationId = 42;

	auto encoded = SignalProtocolTransport::encodeKeyBundle(bundle);
	REQUIRE(!encoded.isEmpty());

	auto decoded = SignalProtocolTransport::decodeKeyBundle(encoded);
	REQUIRE(decoded.has_value());
	REQUIRE(decoded->oneTimePreKey.empty());
	REQUIRE(decoded->identityKey == bundle.identityKey);
}

// ─── Zero-Width Entity Transport ───────────────────────────────────────────────

TEST_CASE("buildOutgoingEntity produces invisible text", "[signal][transport][unit]") {
	auto bundle = makeBundle();

	QString zwText;
	auto entity = SignalProtocolTransport::buildOutgoingEntity(bundle, zwText);

	// The entity should cover the entire ZW payload
	REQUIRE(entity.type() == mtpc_messageEntityUnknown);
	REQUIRE(entity.c_messageEntityUnknown().voffset().v == 0);
	REQUIRE(entity.c_messageEntityUnknown().vlength().v == zwText.size());

	// All characters in the ZW text should be zero-width
	for (const auto &ch : zwText) {
		const auto cp = ch.unicode();
		REQUIRE((cp == 0x200B || cp == 0x200C || cp == 0x200D || cp == 0xFEFF));
	}
}

TEST_CASE("extractAndStripBundles round-trip", "[signal][transport][unit]") {
	auto bundle = makeBundle();

	QString zwText;
	SignalProtocolTransport::buildOutgoingEntity(bundle, zwText);

	// Simulate an incoming message with the ZW payload
	QVector<MTPMessageEntity> entities;
	entities.push_back(MTP_messageEntityUnknown(MTP_int(0), MTP_int(zwText.size())));

	auto extracted = SignalProtocolTransport::extractAndStripBundles(entities, zwText);

	REQUIRE(extracted.size() == 1);
	REQUIRE(extracted[0].identityKey == bundle.identityKey);
	REQUIRE(extracted[0].signedPreKey == bundle.signedPreKey);
	REQUIRE(extracted[0].signature == bundle.signature);
	REQUIRE(extracted[0].oneTimePreKey == bundle.oneTimePreKey);

	// The entity should have been stripped
	REQUIRE(entities.isEmpty());
}

TEST_CASE("extractAndStripBundles ignores non-ZW entities", "[signal][transport][unit]") {
	QString text = "Hello world";
	QVector<MTPMessageEntity> entities;
	entities.push_back(MTP_messageEntityBold(MTP_int(0), MTP_int(5)));

	auto extracted = SignalProtocolTransport::extractAndStripBundles(entities, text);
	REQUIRE(extracted.empty());
	REQUIRE(entities.size() == 1);  // Bold entity should remain
}

TEST_CASE("isCryptogramEntity", "[signal][transport][unit]") {
	REQUIRE(SignalProtocolTransport::isCryptogramEntity(0x43524B45));
	REQUIRE(!SignalProtocolTransport::isCryptogramEntity(0x12345678));
}

// ─── AES-GCM Encryption / Decryption ───────────────────────────────────────────

TEST_CASE("AES-GCM encrypt/decrypt round-trip", "[signal][crypto][unit]") {
	// Test AES-256-GCM encryption directly via OpenSSL
	auto key = randomKey(32);
	auto iv = randomKey(12);
	auto plaintext = std::string("Test message for AES-GCM");

	// Encrypt
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	REQUIRE(ctx != nullptr);

	REQUIRE(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1);
	REQUIRE(EVP_CIPHER_CTX_set_key_length(ctx, 32) == 1);
	REQUIRE(EVP_EncryptInit_ex(ctx, nullptr, nullptr,
		reinterpret_cast<const unsigned char*>(key.data()),
		reinterpret_cast<const unsigned char*>(iv.data())) == 1);

	std::vector<unsigned char> ciphertext(plaintext.size());
	int len = 0;
	REQUIRE(EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
		reinterpret_cast<const unsigned char*>(plaintext.data()),
		static_cast<int>(plaintext.size())) == 1);
	int totalLen = len;

	REQUIRE(EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) == 1);
	totalLen += len;

	std::vector<unsigned char> tag(16);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
	EVP_CIPHER_CTX_free(ctx);

	// Decrypt
	ctx = EVP_CIPHER_CTX_new();
	REQUIRE(ctx != nullptr);

	REQUIRE(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1);
	REQUIRE(EVP_DecryptInit_ex(ctx, nullptr, nullptr,
		reinterpret_cast<const unsigned char*>(key.data()),
		reinterpret_cast<const unsigned char*>(iv.data())) == 1);

	std::vector<unsigned char> decrypted(plaintext.size());
	REQUIRE(EVP_DecryptUpdate(ctx, decrypted.data(), &len,
		ciphertext.data(), totalLen) == 1);

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data());
	int ret = EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len);
	EVP_CIPHER_CTX_free(ctx);

	REQUIRE(ret == 1);

	std::string result(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
	REQUIRE(result == plaintext);
}

TEST_CASE("AES-GCM detects tampered ciphertext", "[signal][crypto][unit]") {
	auto key = randomKey(32);
	auto iv = randomKey(12);
	auto plaintext = std::string("Tamper test");

	// Encrypt
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
	EVP_EncryptInit_ex(ctx, nullptr, nullptr,
		reinterpret_cast<const unsigned char*>(key.data()),
		reinterpret_cast<const unsigned char*>(iv.data()));

	std::vector<unsigned char> ciphertext(plaintext.size());
	int len = 0;
	EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
		reinterpret_cast<const unsigned char*>(plaintext.data()),
		static_cast<int>(plaintext.size()));
	int totalLen = len;
	EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
	totalLen += len;

	std::vector<unsigned char> tag(16);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
	EVP_CIPHER_CTX_free(ctx);

	// Tamper with ciphertext
	ciphertext[0] ^= 0x01;

	// Decrypt should fail
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
	EVP_DecryptInit_ex(ctx, nullptr, nullptr,
		reinterpret_cast<const unsigned char*>(key.data()),
		reinterpret_cast<const unsigned char*>(iv.data()));

	std::vector<unsigned char> decrypted(plaintext.size());
	EVP_DecryptUpdate(ctx, decrypted.data(), &len,
		ciphertext.data(), totalLen);

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data());
	int ret = EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len);
	EVP_CIPHER_CTX_free(ctx);

	REQUIRE(ret == 0);  // Should fail
}

// ─── HKDF / KDF_RK ─────────────────────────────────────────────────────────────

TEST_CASE("HKDF produces different keys for different info strings", "[signal][crypto][unit]") {
	auto ikm = randomKey(32);
	auto salt = randomKey(32);

	// Derive two keys with different info strings
	auto key1 = bytes::vector(32);
	auto key2 = bytes::vector(32);

	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
	REQUIRE(pctx != nullptr);

	EVP_PKEY_derive_init(pctx);
	EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
	EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size());
	EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm.size());
	EVP_PKEY_CTX_add1_hkdf_info(pctx,
		reinterpret_cast<const unsigned char*>("CryptogramKDF_RK"), 16);
	EVP_PKEY_derive(pctx, key1.data(), nullptr);
	size_t outLen = 32;
	EVP_PKEY_derive(pctx, key1.data(), &outLen);
	EVP_PKEY_CTX_free(pctx);

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
	EVP_PKEY_derive_init(pctx);
	EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
	EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size());
	EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm.size());
	EVP_PKEY_CTX_add1_hkdf_info(pctx,
		reinterpret_cast<const unsigned char*>("CryptogramX3DH"), 15);
	EVP_PKEY_derive(pctx, key2.data(), nullptr);
	outLen = 32;
	EVP_PKEY_derive(pctx, key2.data(), &outLen);
	EVP_PKEY_CTX_free(pctx);

	REQUIRE(key1 != key2);
}

// ─── Key Bundle with Init Params Simulation ────────────────────────────────────

TEST_CASE("KeyBundle fields can be base64-encoded for init params", "[signal][init_params][unit]") {
	auto bundle = makeBundle();

	auto toB64 = [](const bytes::vector &key) {
		return QByteArray(
			reinterpret_cast<const char*>(key.data()),
			key.size()).toBase64().toStdString();
	};

	auto ik = toB64(bundle.identityKey);
	auto spk = toB64(bundle.signedPreKey);
	auto sig = toB64(bundle.signature);
	auto opk = toB64(bundle.oneTimePreKey);

	REQUIRE(!ik.empty());
	REQUIRE(!spk.empty());
	REQUIRE(!sig.empty());
	REQUIRE(!opk.empty());

	// Verify round-trip
	auto fromB64 = [](const std::string &b64) {
		return bytes::make_vector(QByteArray::fromBase64(QByteArray::fromStdString(b64)));
	};

	REQUIRE(fromB64(ik) == bundle.identityKey);
	REQUIRE(fromB64(spk) == bundle.signedPreKey);
	REQUIRE(fromB64(sig) == bundle.signature);
	REQUIRE(fromB64(opk) == bundle.oneTimePreKey);
}

// =========================================================================
// MLS Key Package Transport Tests
// =========================================================================

TEST_CASE("MLS KeyPackage encode/decode round-trip", "[mls][transport]") {
	MLSKeyPackage pkg;
	pkg.version = kMLSProtocolVersion;
	pkg.ciphersuite = MLSCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
	pkg.initKey = randomKey(32);
	pkg.credentialPublicKey = randomKey(32);
	pkg.credential = randomKey(48);
	pkg.signature = randomKey(64);
	pkg.creationTime = QDateTime::currentDateTime();
	pkg.expirationTime = pkg.creationTime.addDays(90);

	const auto encoded = SignalProtocolTransport::encodeMLSKeyPackage(pkg);
	REQUIRE(!encoded.isEmpty());

	const auto decoded = SignalProtocolTransport::decodeMLSKeyPackage(encoded);
	REQUIRE(decoded.has_value());

	REQUIRE(decoded->version == pkg.version);
	REQUIRE(decoded->ciphersuite == pkg.ciphersuite);
	REQUIRE(decoded->initKey == pkg.initKey);
	REQUIRE(decoded->credentialPublicKey == pkg.credentialPublicKey);
	REQUIRE(decoded->credential == pkg.credential);
	REQUIRE(decoded->signature == pkg.signature);
	REQUIRE(decoded->creationTime.toMSecsSinceEpoch() == pkg.creationTime.toMSecsSinceEpoch());
	REQUIRE(decoded->expirationTime.toMSecsSinceEpoch() == pkg.expirationTime.toMSecsSinceEpoch());
}

TEST_CASE("MLS KeyPackage encode rejects invalid key sizes", "[mls][transport]") {
	MLSKeyPackage pkg;
	pkg.initKey = randomKey(31); // Wrong size
	pkg.credentialPublicKey = randomKey(32);
	pkg.signature = randomKey(64);

	const auto encoded = SignalProtocolTransport::encodeMLSKeyPackage(pkg);
	REQUIRE(encoded.isEmpty());
}

TEST_CASE("MLS KeyPackage decode rejects wrong payload type", "[mls][transport]") {
	MLSKeyPackage pkg;
	pkg.version = kMLSProtocolVersion;
	pkg.ciphersuite = MLSCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
	pkg.initKey = randomKey(32);
	pkg.credentialPublicKey = randomKey(32);
	pkg.credential = randomKey(16);
	pkg.signature = randomKey(64);
	pkg.creationTime = QDateTime::currentDateTime();
	pkg.expirationTime = pkg.creationTime.addDays(90);

	auto encoded = SignalProtocolTransport::encodeMLSKeyPackage(pkg);
	REQUIRE(!encoded.isEmpty());

	// Corrupt the payload type byte (index 1)
	encoded[1] = static_cast<char>(0x01); // Key bundle type, not MLS

	const auto decoded = SignalProtocolTransport::decodeMLSKeyPackage(encoded);
	REQUIRE(!decoded.has_value());
}

TEST_CASE("MLS KeyPackage ZW round-trip via buildOutgoingMLSKeyPackage", "[mls][transport]") {
	MLSKeyPackage pkg;
	pkg.version = kMLSProtocolVersion;
	pkg.ciphersuite = MLSCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
	pkg.initKey = randomKey(32);
	pkg.credentialPublicKey = randomKey(32);
	pkg.credential = randomKey(32);
	pkg.signature = randomKey(64);
	pkg.creationTime = QDateTime::currentDateTime();
	pkg.expirationTime = pkg.creationTime.addDays(90);

	QString zwText;
	auto entity = SignalProtocolTransport::buildOutgoingMLSKeyPackage(pkg, zwText);

	REQUIRE(!zwText.isEmpty());
	REQUIRE(entity.type() == mtpc_messageEntityUnknown);

	// All characters should be zero-width
	for (const auto &ch : zwText) {
		const auto cp = ch.unicode();
		REQUIRE((cp == 0x200B || cp == 0x200C || cp == 0x200D || cp == 0xFEFF));
	}

	// Decode back
	const auto rawBytes = SignalProtocolTransport::zeroWidthToBytes(zwText);
	REQUIRE(!rawBytes.isEmpty());

	const auto decoded = SignalProtocolTransport::decodeMLSKeyPackage(rawBytes);
	REQUIRE(decoded.has_value());
	REQUIRE(decoded->initKey == pkg.initKey);
	REQUIRE(decoded->credentialPublicKey == pkg.credentialPublicKey);
}

// =========================================================================
// MLS Welcome Transport Tests
// =========================================================================

TEST_CASE("MLS Welcome encode/decode round-trip", "[mls][transport]") {
	MLSWelcome welcome;
	welcome.version = kMLSProtocolVersion;
	welcome.ciphersuite = MLSCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
	welcome.encryptedGroupSecrets = randomKey(64);
	welcome.encryptedGroupInfo = randomKey(128);

	const auto encoded = SignalProtocolTransport::encodeMLSWelcome(welcome);
	REQUIRE(!encoded.isEmpty());

	const auto decoded = SignalProtocolTransport::decodeMLSWelcome(encoded);
	REQUIRE(decoded.has_value());

	REQUIRE(decoded->version == welcome.version);
	REQUIRE(decoded->ciphersuite == welcome.ciphersuite);
	REQUIRE(decoded->encryptedGroupSecrets == welcome.encryptedGroupSecrets);
	REQUIRE(decoded->encryptedGroupInfo == welcome.encryptedGroupInfo);
}

TEST_CASE("MLS Welcome with empty payloads", "[mls][transport]") {
	MLSWelcome welcome;
	welcome.version = kMLSProtocolVersion;
	welcome.ciphersuite = MLSCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

	const auto encoded = SignalProtocolTransport::encodeMLSWelcome(welcome);
	REQUIRE(!encoded.isEmpty());

	const auto decoded = SignalProtocolTransport::decodeMLSWelcome(encoded);
	REQUIRE(decoded.has_value());
	REQUIRE(decoded->encryptedGroupSecrets.empty());
	REQUIRE(decoded->encryptedGroupInfo.empty());
}

TEST_CASE("MLS Welcome ZW round-trip", "[mls][transport]") {
	MLSWelcome welcome;
	welcome.version = kMLSProtocolVersion;
	welcome.ciphersuite = MLSCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
	welcome.encryptedGroupSecrets = randomKey(48);
	welcome.encryptedGroupInfo = randomKey(96);

	QString zwText;
	auto entity = SignalProtocolTransport::buildOutgoingMLSWelcome(welcome, zwText);

	REQUIRE(!zwText.isEmpty());
	REQUIRE(entity.type() == mtpc_messageEntityUnknown);

	// Decode back
	const auto rawBytes = SignalProtocolTransport::zeroWidthToBytes(zwText);
	REQUIRE(!rawBytes.isEmpty());

	const auto decoded = SignalProtocolTransport::decodeMLSWelcome(rawBytes);
	REQUIRE(decoded.has_value());
	REQUIRE(decoded->encryptedGroupSecrets == welcome.encryptedGroupSecrets);
	REQUIRE(decoded->encryptedGroupInfo == welcome.encryptedGroupInfo);
}

// =========================================================================
// ZW Helper Tests
// =========================================================================

TEST_CASE("bytesToZeroWidth / zeroWidthToBytes round-trip", "[mls][transport]") {
	const QByteArray testData("Hello, MLS World! \x00\xFF\x42", 20);
	const auto zw = SignalProtocolTransport::bytesToZeroWidth(testData);
	REQUIRE(zw.size() == testData.size() * 4);

	const auto decoded = SignalProtocolTransport::zeroWidthToBytes(zw);
	REQUIRE(decoded == testData);
}

TEST_CASE("zeroWidthToBytes rejects invalid input", "[mls][transport]") {
	// Odd length string
	REQUIRE(SignalProtocolTransport::zeroWidthToBytes(QString("abc")).isEmpty());

	// Non-ZW characters
	REQUIRE(SignalProtocolTransport::zeroWidthToBytes(QString("hello")).isEmpty());
}
