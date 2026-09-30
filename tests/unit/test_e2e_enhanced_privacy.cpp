// Real round trips through the production EnhancedPrivacyCrypto unit
// (data/enhanced_privacy_crypto.cpp, compiled directly into this binary):
// PBKDF2-HMAC-SHA-256 known-answer vectors, "CR2:" envelope structure,
// tamper/wrong-key rejections and legacy-envelope compatibility.

#include <catch2/catch_test_macros.hpp>

#include "data/enhanced_privacy_crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <QtCore/QByteArray>
#include <QtCore/QCryptographicHash>
#include <QtCore/QString>

using namespace EnhancedPrivacyCrypto;

namespace {

// The unit's public constants (kSaltSize, kPbkdf2Iterations) are used
// directly; the internal 12-byte IV and 16-byte tag sizes are re-declared.
constexpr int kIvSize = 12;
constexpr int kTagSize = 16;
const QString kPrefix = QStringLiteral("CR2:");

// Reference AES-256-GCM decryption used by the tests to probe envelope
// fields. The encrypt path is never reimplemented here.
QByteArray referenceDecrypt(
		const QByteArray &key,
		const QByteArray &iv,
		const QByteArray &ciphertext,
		const QByteArray &tag) {
	QByteArray plaintext(ciphertext.size(), 0);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	REQUIRE(ctx != nullptr);
	REQUIRE(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1);
	REQUIRE(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) == 1);
	REQUIRE(EVP_DecryptInit_ex(ctx, nullptr, nullptr,
		reinterpret_cast<const unsigned char*>(key.constData()),
		reinterpret_cast<const unsigned char*>(iv.constData())) == 1);
	int len = 0;
	if (!ciphertext.isEmpty()) {
		REQUIRE(EVP_DecryptUpdate(ctx,
			reinterpret_cast<unsigned char*>(plaintext.data()),
			&len,
			reinterpret_cast<const unsigned char*>(ciphertext.constData()),
			ciphertext.size()) == 1);
	}
	const auto plaintextLen = len;
	REQUIRE(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(),
		const_cast<char*>(tag.constData())) == 1);
	REQUIRE(EVP_DecryptFinal_ex(ctx,
		reinterpret_cast<unsigned char*>(plaintext.data()) + plaintextLen,
		&len) == 1); // Fails on tag mismatch
	EVP_CIPHER_CTX_free(ctx);
	plaintext.resize(plaintextLen + len);
	return plaintext;
}

// Reimplementation of the OLD (pre-"CR2:") algorithm, kept here on purpose:
// the compatibility contract is that DecryptString still recovers payloads
// persisted by older builds.
QString makeLegacyEnvelope(const QString &plaintext, const QString &passphrase) {
	const auto key = QCryptographicHash::hash(
		passphrase.toUtf8(),
		QCryptographicHash::Sha256
	).left(32);

	QByteArray iv(kIvSize, 0);
	REQUIRE(RAND_bytes(reinterpret_cast<unsigned char*>(iv.data()), kIvSize) == 1);

	const auto data = plaintext.toUtf8();
	QByteArray ciphertext(data.size(), 0);
	unsigned char tag[kTagSize] = {0};

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	REQUIRE(ctx != nullptr);
	REQUIRE(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1);
	REQUIRE(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kIvSize, nullptr) == 1);
	REQUIRE(EVP_EncryptInit_ex(ctx, nullptr, nullptr,
		reinterpret_cast<const unsigned char*>(key.constData()),
		reinterpret_cast<const unsigned char*>(iv.constData())) == 1);
	int len = 0;
	REQUIRE(EVP_EncryptUpdate(ctx,
		reinterpret_cast<unsigned char*>(ciphertext.data()),
		&len,
		reinterpret_cast<const unsigned char*>(data.constData()),
		data.size()) == 1);
	const auto ciphertextLen = len;
	REQUIRE(EVP_EncryptFinal_ex(ctx,
		reinterpret_cast<unsigned char*>(ciphertext.data()) + ciphertextLen,
		&len) == 1);
	REQUIRE(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagSize, tag) == 1);
	EVP_CIPHER_CTX_free(ctx);
	ciphertext.resize(ciphertextLen + len);

	const auto envelope = iv + ciphertext + QByteArray(
		reinterpret_cast<const char*>(tag), kTagSize);
	return QString::fromLatin1(envelope.toBase64());
}

QString cr2Envelope(const QByteArray &payload) {
	return kPrefix + QString::fromLatin1(payload.toBase64());
}

} // namespace

TEST_CASE("EnhancedPrivacyCrypto PBKDF2 known-answer vectors", "[enhanced_privacy][kdf]") {
	const auto password = QStringLiteral("password");
	const auto salt = QByteArray("salt"); // No null terminator, per the vectors

	SECTION("single iteration") {
		const auto key = DeriveKey(password, salt, 1);
		REQUIRE(key.size() == 32);
		REQUIRE(key.toHex() == QByteArray(
			"120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"));
	}

	SECTION("4096 iterations") {
		const auto key = DeriveKey(password, salt, 4096);
		REQUIRE(key.size() == 32);
		REQUIRE(key.toHex() == QByteArray(
			"c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"));
	}

	SECTION("production work factor yields 32 bytes") {
		REQUIRE(DeriveKey(password, salt, kPbkdf2Iterations).size() == 32);
	}
}

TEST_CASE("EnhancedPrivacyCrypto string roundtrip", "[enhanced_privacy][roundtrip]") {
	const auto passphrase = QStringLiteral("correct horse battery staple");

	SECTION("ASCII") {
		const auto text = QStringLiteral("The quick brown fox jumps over the lazy dog");
		REQUIRE(DecryptString(EncryptString(text, passphrase), passphrase) == text);
	}

	SECTION("empty string") {
		const auto envelope = EncryptString(QString(), passphrase);
		REQUIRE_FALSE(envelope.isEmpty()); // Still a well-formed envelope
		REQUIRE(envelope.startsWith(kPrefix));
		REQUIRE(DecryptString(envelope, passphrase).isEmpty());
	}

	SECTION("unicode with RTL text and emoji") {
		const auto text = QStringLiteral("שלום, مرحبا — 暗号 🚀🔒");
		REQUIRE(DecryptString(EncryptString(text, passphrase), passphrase) == text);
	}

	SECTION("large ~100 KB payload") {
		const auto text = QString("abcdefghijklmnopqrstuvwxyz0123456789").repeated(3000);
		REQUIRE(text.size() >= 100 * 1024);
		REQUIRE(DecryptString(EncryptString(text, passphrase), passphrase) == text);
	}
}

TEST_CASE("EnhancedPrivacyCrypto CR2 envelope structure", "[enhanced_privacy][envelope]") {
	const auto passphrase = QStringLiteral("envelope-probe-passphrase");
	const auto plaintext = QStringLiteral("structure probe payload");

	const auto envelope = EncryptString(plaintext, passphrase);

	SECTION("versioned prefix present") {
		REQUIRE(envelope.startsWith(kPrefix));
	}

	SECTION("random salt and IV make encryptions differ") {
		const auto second = EncryptString(plaintext, passphrase);
		REQUIRE(second != envelope);
		REQUIRE(DecryptString(second, passphrase) == plaintext);
	}

	SECTION("field layout: salt || iv || ciphertext || tag") {
		const auto payload = QByteArray::fromBase64(
			envelope.mid(kPrefix.size()).toLatin1());
		REQUIRE(payload.size() >= kSaltSize + kIvSize + kTagSize);

		// Extract the salt exactly where the format documents it, re-derive
		// the key from it and decrypt the remaining fields.
		const auto salt = payload.left(kSaltSize);
		const auto iv = payload.mid(kSaltSize, kIvSize);
		const auto tag = payload.right(kTagSize);
		const auto ciphertext = payload.mid(
			kSaltSize + kIvSize,
			payload.size() - kSaltSize - kIvSize - kTagSize);

		const auto key = DeriveKey(passphrase, salt, kPbkdf2Iterations);
		REQUIRE(key.size() == 32);
		REQUIRE(referenceDecrypt(key, iv, ciphertext, tag) == plaintext.toUtf8());
	}
}

TEST_CASE("EnhancedPrivacyCrypto legacy envelope compatibility", "[enhanced_privacy][legacy]") {
	const auto passphrase = QStringLiteral("old-build-passphrase");
	const auto plaintext = QStringLiteral("payload persisted by an older build");

	// Old format built with the old algorithm: unsalted single-round
	// SHA-256 key over base64(iv || ciphertext || tag).
	const auto legacy = makeLegacyEnvelope(plaintext, passphrase);
	REQUIRE_FALSE(legacy.startsWith(kPrefix));
	REQUIRE(DecryptString(legacy, passphrase) == plaintext);

	// The old minimum-length guard (IV + tag + at least 1 byte) is
	// preserved for legacy inputs.
	const auto tooShort = QString::fromLatin1(
		(QByteArray(kIvSize, 0) + QByteArray(kTagSize, 0)).toBase64());
	REQUIRE(DecryptString(tooShort, passphrase).isEmpty());
}

TEST_CASE("EnhancedPrivacyCrypto failure handling", "[enhanced_privacy][negative]") {
	const auto passphrase = QStringLiteral("right-passphrase");
	const auto plaintext = QStringLiteral("secret payload");
	const auto envelope = EncryptString(plaintext, passphrase);
	REQUIRE_FALSE(envelope.isEmpty());

	SECTION("wrong passphrase on CR2 envelope") {
		REQUIRE(DecryptString(envelope, QStringLiteral("wrong-passphrase")).isEmpty());
	}

	SECTION("tampered ciphertext byte") {
		auto payload = QByteArray::fromBase64(envelope.mid(kPrefix.size()).toLatin1());
		REQUIRE(payload.size() > kSaltSize + kIvSize + kTagSize);
		payload[kSaltSize + kIvSize] = char(payload[kSaltSize + kIvSize] ^ 0x01);
		REQUIRE(DecryptString(cr2Envelope(payload), passphrase).isEmpty());
	}

	SECTION("tampered tag byte") {
		auto payload = QByteArray::fromBase64(envelope.mid(kPrefix.size()).toLatin1());
		payload[payload.size() - 1] = char(payload[payload.size() - 1] ^ 0x80);
		REQUIRE(DecryptString(cr2Envelope(payload), passphrase).isEmpty());
	}

	SECTION("tampered salt byte") {
		auto payload = QByteArray::fromBase64(envelope.mid(kPrefix.size()).toLatin1());
		payload[0] = char(payload[0] ^ 0x01); // Different salt, different key
		REQUIRE(DecryptString(cr2Envelope(payload), passphrase).isEmpty());
	}

	SECTION("garbage input") {
		REQUIRE(DecryptString(QStringLiteral("not an envelope"), passphrase).isEmpty());
		REQUIRE(DecryptString(kPrefix + QStringLiteral("!!!!"), passphrase).isEmpty());
		REQUIRE(DecryptString(QString(), passphrase).isEmpty());
	}

	SECTION("truncated CR2 payload") {
		const auto payload = QByteArray::fromBase64(
			envelope.mid(kPrefix.size()).toLatin1());
		const auto truncated = payload.left(kSaltSize + kIvSize + kTagSize - 1);
		REQUIRE(DecryptString(cr2Envelope(truncated), passphrase).isEmpty());
	}

	SECTION("legacy wrong passphrase") {
		const auto legacy = makeLegacyEnvelope(plaintext, passphrase);
		REQUIRE(DecryptString(legacy, QStringLiteral("wrong-passphrase")).isEmpty());
	}
}
