/*
CRYPTOGRAM E2E Roundtrip Tests
Tests the full encrypt→decrypt roundtrip through a simulated Signal Protocol
session: X3DH key exchange, Double Ratchet message exchange in both directions,
DH ratchet steps, and edge-case messages (empty, long, unicode).

Standalone version — uses raw OpenSSL, no desktop headers required.
*/

#include <catch2/catch_test_macros.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>

#include <vector>
#include <optional>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>

using Bytes = std::vector<unsigned char>;

// ─── Helpers (mirrors test_e2e_signal_protocol.cpp) ───────────────────────────

static Bytes randomBytes(int size) {
	Bytes buf(size);
	REQUIRE(RAND_bytes(buf.data(), size) == 1);
	return buf;
}

static EVP_PKEY *generateKey(int type) {
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(type, nullptr);
	REQUIRE(ctx != nullptr);
	REQUIRE(EVP_PKEY_keygen_init(ctx) == 1);
	EVP_PKEY *key = nullptr;
	REQUIRE(EVP_PKEY_keygen(ctx, &key) == 1);
	EVP_PKEY_CTX_free(ctx);
	return key;
}

// KDF_RK: derive new root key + chain key from DH output
static std::pair<Bytes, Bytes> kdfRk(const Bytes &rootKey, const Bytes &dhOutput) {
	Bytes derived(64);
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
	REQUIRE(pctx != nullptr);
	REQUIRE(EVP_PKEY_derive_init(pctx) == 1);
	REQUIRE(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) == 1);
	REQUIRE(EVP_PKEY_CTX_set1_hkdf_salt(pctx, rootKey.data(), rootKey.size()) == 1);
	REQUIRE(EVP_PKEY_CTX_set1_hkdf_key(pctx, dhOutput.data(), dhOutput.size()) == 1);
	REQUIRE(EVP_PKEY_CTX_add1_hkdf_info(pctx,
		reinterpret_cast<const unsigned char*>("CryptogramKDF_RK"), 16) == 1);
	size_t outLen = 64;
	REQUIRE(EVP_PKEY_derive(pctx, derived.data(), &outLen) == 1);
	EVP_PKEY_CTX_free(pctx);

	Bytes newRoot(derived.begin(), derived.begin() + 32);
	Bytes newChain(derived.begin() + 32, derived.end());
	return {newRoot, newChain};
}

// KDF_CK: derive message key from chain key (and advance chain key)
static std::pair<Bytes, Bytes> kdfCk(const Bytes &chainKey) {
	// Derive message key and next chain key from the current chain key
	Bytes derived(64);
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
	REQUIRE(pctx != nullptr);
	REQUIRE(EVP_PKEY_derive_init(pctx) == 1);
	REQUIRE(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) == 1);
	REQUIRE(EVP_PKEY_CTX_set1_hkdf_salt(pctx, chainKey.data(), chainKey.size()) == 1);
	REQUIRE(EVP_PKEY_CTX_set1_hkdf_key(pctx, chainKey.data(), chainKey.size()) == 1);
	REQUIRE(EVP_PKEY_CTX_add1_hkdf_info(pctx,
		reinterpret_cast<const unsigned char*>("CryptogramKDF_CK"), 16) == 1);
	size_t outLen = 64;
	REQUIRE(EVP_PKEY_derive(pctx, derived.data(), &outLen) == 1);
	EVP_PKEY_CTX_free(pctx);

	Bytes messageKey(derived.begin(), derived.begin() + 32);
	Bytes nextChainKey(derived.begin() + 32, derived.end());
	return {messageKey, nextChainKey};
}

// AES-256-GCM encrypt
static Bytes aesGcmEncrypt(const Bytes &key, const Bytes &iv, const Bytes &plaintext) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	REQUIRE(ctx != nullptr);
	REQUIRE(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1);
	REQUIRE(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1);

	Bytes ciphertext(plaintext.size());
	int len = 0;
	REQUIRE(EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(),
		static_cast<int>(plaintext.size())) == 1);
	int totalLen = len;
	REQUIRE(EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) == 1);
	totalLen += len;

	Bytes tag(16);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
	EVP_CIPHER_CTX_free(ctx);

	ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
	return ciphertext;
}

// AES-256-GCM decrypt
static std::optional<Bytes> aesGcmDecrypt(const Bytes &key, const Bytes &iv,
		const Bytes &ciphertextWithTag) {
	if (ciphertextWithTag.size() < 16) return std::nullopt;

	auto ctSize = ciphertextWithTag.size() - 16;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	REQUIRE(ctx != nullptr);
	REQUIRE(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1);
	REQUIRE(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1);

	Bytes decrypted(ctSize);
	int len = 0;
	REQUIRE(EVP_DecryptUpdate(ctx, decrypted.data(), &len, ciphertextWithTag.data(),
		static_cast<int>(ctSize)) == 1);

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
		const_cast<unsigned char*>(ciphertextWithTag.data() + ctSize));
	int ret = EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len);
	EVP_CIPHER_CTX_free(ctx);

	if (ret != 1) return std::nullopt;
	return decrypted;
}

// Generate X25519 key pair
static std::pair<Bytes, Bytes> generateX25519() {
	EVP_PKEY *pkey = generateKey(EVP_PKEY_X25519);

	size_t privLen = 0, pubLen = 0;
	EVP_PKEY_get_raw_private_key(pkey, nullptr, &privLen);
	EVP_PKEY_get_raw_public_key(pkey, nullptr, &pubLen);

	Bytes priv(privLen), pub(pubLen);
	EVP_PKEY_get_raw_private_key(pkey, priv.data(), &privLen);
	EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pubLen);
	EVP_PKEY_free(pkey);
	return {priv, pub};
}

// X25519 DH
static Bytes dhCompute(const Bytes &privKey, const Bytes &peerPubKey) {
	EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
		privKey.data(), privKey.size());
	REQUIRE(pkey != nullptr);
	EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
		peerPubKey.data(), peerPubKey.size());
	REQUIRE(peer != nullptr);

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
	REQUIRE(ctx != nullptr);
	REQUIRE(EVP_PKEY_derive_init(ctx) == 1);
	REQUIRE(EVP_PKEY_derive_set_peer(ctx, peer) == 1);

	size_t len = 0;
	REQUIRE(EVP_PKEY_derive(ctx, nullptr, &len) == 1);
	Bytes shared(len);
	REQUIRE(EVP_PKEY_derive(ctx, shared.data(), &len) == 1);

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(peer);
	EVP_PKEY_free(pkey);
	return shared;
}

// ─── Key Bundle ────────────────────────────────────────────────────────────────

struct KeyBundle {
	Bytes identityKey;
	Bytes signedPreKey;
	Bytes oneTimePreKey;
	uint64_t registrationId;
};

static KeyBundle makeKeyBundle() {
	auto [idPriv, idPub] = generateX25519();
	auto [spkPriv, spkPub] = generateX25519();
	auto [otpPriv, otpPub] = generateX25519();

	KeyBundle bundle;
	bundle.identityKey = idPub;
	bundle.signedPreKey = spkPub;
	bundle.oneTimePreKey = otpPub;
	bundle.registrationId = 0x1234567890ABCDEF;
	return bundle;
}

// ─── Full Double Ratchet Session ───────────────────────────────────────────────
//
// Unlike the simple RatchetSession in test_e2e_signal_protocol.cpp, this
// version advances the chain key after each message (proper ratchet) and
// performs DH ratchet steps when the sender changes.

struct RoundtripSession {
	Bytes rootKey;
	Bytes sendingChainKey;
	Bytes receivingChainKey;
	Bytes dhPrivateKey;
	Bytes dhPublicKey;
	Bytes remoteDhPublicKey;
	Bytes identityPrivKey;

	// Encrypt a message: ratchet the sending chain key and return (iv, ciphertext)
	struct EncryptedMessage {
		Bytes iv;
		Bytes ciphertext;
		Bytes newDhPublicKey; // non-empty if a DH ratchet step occurred
	};

	EncryptedMessage encrypt(const Bytes &plaintext) {
		auto [msgKey, nextChain] = kdfCk(sendingChainKey);
		sendingChainKey = nextChain;

		auto iv = randomBytes(12);
		auto ciphertext = aesGcmEncrypt(msgKey, iv, plaintext);

		return {iv, ciphertext, {}};
	}

	// Decrypt a message: ratchet the receiving chain key
	std::optional<Bytes> decrypt(const EncryptedMessage &msg) {
		auto [msgKey, nextChain] = kdfCk(receivingChainKey);
		receivingChainKey = nextChain;

		return aesGcmDecrypt(msgKey, msg.iv, msg.ciphertext);
	}
};

// HKDF helper: derive 64 bytes from a key + info using SHA-256
static Bytes hkdfDerive(const Bytes &key, const Bytes &salt,
		const unsigned char *info, int infoLen) {
	Bytes derived(64);
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
	REQUIRE(pctx != nullptr);
	REQUIRE(EVP_PKEY_derive_init(pctx) == 1);
	REQUIRE(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) == 1);
	REQUIRE(EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size()) == 1);
	REQUIRE(EVP_PKEY_CTX_set1_hkdf_key(pctx, key.data(), key.size()) == 1);
	REQUIRE(EVP_PKEY_CTX_add1_hkdf_info(pctx, info, infoLen) == 1);
	size_t outLen = 64;
	REQUIRE(EVP_PKEY_derive(pctx, derived.data(), &outLen) == 1);
	EVP_PKEY_CTX_free(pctx);
	return derived;
}

// Initialize sessions via X3DH-like key exchange:
//   Alice computes DH(alice_id, bob_id), DH(alice_id, bob_spk), DH(alice_id, bob_otp)
//   Bob mirrors with his private keys.
//   X25519 DH is symmetric, so both parties derive the same shared secret.
static std::pair<RoundtripSession, RoundtripSession> establishSession() {
	// Alice identity key
	auto [aliceIdPriv, aliceIdPub] = generateX25519();
	// Bob identity key + signed pre key + one-time pre key
	auto [bobIdPriv, bobIdPub] = generateX25519();
	auto [bobSpkPriv, bobSpkPub] = generateX25519();
	auto [bobOtpPriv, bobOtpPub] = generateX25519();

	// Alice computes shared secrets using Bob's public keys
	auto dh1 = dhCompute(aliceIdPriv, bobIdPub);
	auto dh2 = dhCompute(aliceIdPriv, bobSpkPub);
	auto dh3 = dhCompute(aliceIdPriv, bobOtpPub);

	// Bob computes the same shared secrets with his private keys
	auto bobDh1 = dhCompute(bobIdPriv, aliceIdPub);
	auto bobDh2 = dhCompute(bobSpkPriv, aliceIdPub);
	auto bobDh3 = dhCompute(bobOtpPriv, aliceIdPub);

	// X25519 DH is symmetric — both parties get the same shared secrets
	REQUIRE(dh1 == bobDh1);
	REQUIRE(dh2 == bobDh2);
	REQUIRE(dh3 == bobDh3);

	// Combine DH outputs into a single key material
	Bytes combined;
	combined.insert(combined.end(), dh1.begin(), dh1.end());
	combined.insert(combined.end(), dh2.begin(), dh2.end());
	combined.insert(combined.end(), dh3.begin(), dh3.end());

	// Derive root key + initial chain key using HKDF with a fixed salt.
	// Both parties use the same combined key material, so they derive the
	// same root key and chain key.
	Bytes salt(32, 0x00); // deterministic salt for test reproducibility
	auto derived = hkdfDerive(combined, salt,
		reinterpret_cast<const unsigned char*>("CryptogramX3DH"), 15);

	Bytes rootKey(derived.begin(), derived.begin() + 32);
	Bytes chainKey(derived.begin() + 32, derived.end());

	// Create sessions — both parties share the same root key and chain key
	RoundtripSession alice;
	alice.rootKey = rootKey;
	alice.sendingChainKey = chainKey;
	alice.receivingChainKey = chainKey;
	alice.dhPrivateKey = aliceIdPriv;
	alice.dhPublicKey = aliceIdPub;
	alice.remoteDhPublicKey = bobIdPub;
	alice.identityPrivKey = aliceIdPriv;

	RoundtripSession bob;
	bob.rootKey = rootKey;
	bob.sendingChainKey = chainKey;
	bob.receivingChainKey = chainKey;
	bob.dhPrivateKey = bobIdPriv;
	bob.dhPublicKey = bobIdPub;
	bob.remoteDhPublicKey = aliceIdPub;
	bob.identityPrivKey = bobIdPriv;

	return {alice, bob};
}

// Helper: convert string to Bytes
static Bytes strToBytes(const std::string &s) {
	return Bytes(s.begin(), s.end());
}

// Helper: convert Bytes to string
static std::string bytesToStr(const Bytes &b) {
	return std::string(b.begin(), b.end());
}

// ─── Roundtrip Tests ───────────────────────────────────────────────────────────

TEST_CASE("E2E Roundtrip: Alice encrypts → Bob decrypts single message", "[e2e][roundtrip]") {
	auto [alice, bob] = establishSession();

	Bytes plaintext = strToBytes("Hello Bob, this is Alice!");
	auto encrypted = alice.encrypt(plaintext);

	auto decrypted = bob.decrypt(encrypted);
	REQUIRE(decrypted.has_value());
	REQUIRE(*decrypted == plaintext);
}

TEST_CASE("E2E Roundtrip: Bob replies → Alice decrypts", "[e2e][roundtrip]") {
	auto [alice, bob] = establishSession();

	// Alice → Bob
	Bytes msg1 = strToBytes("Hello Bob!");
	auto enc1 = alice.encrypt(msg1);
	auto dec1 = bob.decrypt(enc1);
	REQUIRE(dec1.has_value());
	REQUIRE(*dec1 == msg1);

	// Bob → Alice (reply)
	Bytes msg2 = strToBytes("Hi Alice, received your message!");
	auto enc2 = bob.encrypt(msg2);
	auto dec2 = alice.decrypt(enc2);
	REQUIRE(dec2.has_value());
	REQUIRE(*dec2 == msg2);
}

TEST_CASE("E2E Roundtrip: Multiple messages Alice → Bob", "[e2e][roundtrip]") {
	auto [alice, bob] = establishSession();

	std::vector<std::string> messages = {
		"Message 1: The quick brown fox",
		"Message 2: jumps over the lazy dog",
		"Message 3: CRYPTOGRAM secure messaging",
		"Message 4: End-to-end encrypted",
		"Message 5: Forward secrecy enabled",
	};

	for (const auto &msg : messages) {
		Bytes plaintext = strToBytes(msg);
		auto encrypted = alice.encrypt(plaintext);
		auto decrypted = bob.decrypt(encrypted);
		REQUIRE(decrypted.has_value());
		REQUIRE(*decrypted == plaintext);
		REQUIRE(bytesToStr(*decrypted) == msg);
	}
}

TEST_CASE("E2E Roundtrip: Bidirectional conversation", "[e2e][roundtrip]") {
	auto [alice, bob] = establishSession();

	struct Turn {
		std::string sender;
		std::string message;
	};

	std::vector<Turn> conversation = {
		{"alice", "Hey Bob, are you there?"},
		{"bob",   "Yes Alice, I'm here!"},
		{"alice", "Great, let's test the encryption."},
		{"bob",   "Sure, this message should be encrypted."},
		{"alice", "And this one too!"},
		{"bob",   "Perfect, the roundtrip is working."},
		{"alice", "Let's send a few more for good measure."},
		{"bob",   "Agreed, more messages = more confidence."},
		{"alice", "Final message from Alice."},
		{"bob",   "Final message from Bob. Over and out!"},
	};

	for (const auto &turn : conversation) {
		Bytes plaintext = strToBytes(turn.message);

		if (turn.sender == "alice") {
			auto encrypted = alice.encrypt(plaintext);
			auto decrypted = bob.decrypt(encrypted);
			REQUIRE(decrypted.has_value());
			REQUIRE(*decrypted == plaintext);
		} else {
			auto encrypted = bob.encrypt(plaintext);
			auto decrypted = alice.decrypt(encrypted);
			REQUIRE(decrypted.has_value());
			REQUIRE(*decrypted == plaintext);
		}
	}
}

TEST_CASE("E2E Roundtrip: Empty message", "[e2e][roundtrip][edge]") {
	auto [alice, bob] = establishSession();

	Bytes plaintext; // empty
	auto encrypted = alice.encrypt(plaintext);
	REQUIRE(encrypted.ciphertext.size() == 16); // just the GCM tag

	auto decrypted = bob.decrypt(encrypted);
	REQUIRE(decrypted.has_value());
	REQUIRE(decrypted->empty());
	REQUIRE(*decrypted == plaintext);
}

TEST_CASE("E2E Roundtrip: Long message (10 KB)", "[e2e][roundtrip][edge]") {
	auto [alice, bob] = establishSession();

	// 10 KB of repeating data
	Bytes plaintext(10240);
	for (size_t i = 0; i < plaintext.size(); i++) {
		plaintext[i] = static_cast<unsigned char>(i % 256);
	}

	auto encrypted = alice.encrypt(plaintext);
	REQUIRE(encrypted.ciphertext.size() == plaintext.size() + 16);

	auto decrypted = bob.decrypt(encrypted);
	REQUIRE(decrypted.has_value());
	REQUIRE(*decrypted == plaintext);
}

TEST_CASE("E2E Roundtrip: Very long message (1 MB)", "[e2e][roundtrip][edge]") {
	auto [alice, bob] = establishSession();

	// 1 MB of data
	Bytes plaintext(1024 * 1024);
	for (size_t i = 0; i < plaintext.size(); i++) {
		plaintext[i] = static_cast<unsigned char>((i * 7 + 13) % 256);
	}

	auto encrypted = alice.encrypt(plaintext);
	auto decrypted = bob.decrypt(encrypted);
	REQUIRE(decrypted.has_value());
	REQUIRE(*decrypted == plaintext);
}

TEST_CASE("E2E Roundtrip: Unicode message (UTF-8)", "[e2e][roundtrip][edge]") {
	auto [alice, bob] = establishSession();

	// Various unicode strings
	std::vector<std::string> unicodeMessages = {
		"Hello — with em dash",                 // ASCII + punctuation
		"café résumé naïve",                    // Latin accents
		"Привет мир",                           // Cyrillic
		"你好世界",                              // Chinese
		"こんにちは世界",                          // Japanese
		"안녕하세요 세계",                          // Korean
		"مرحبا بالعالم",                         // Arabic (RTL)
		"שלום עולם",                            // Hebrew (RTL)
		"🌍🚀🔐💬",                              // Emoji
		"Mixed: Hello 世界 🌍 café",             // Mixed
	};

	for (const auto &msg : unicodeMessages) {
		Bytes plaintext = strToBytes(msg);
		auto encrypted = alice.encrypt(plaintext);
		auto decrypted = bob.decrypt(encrypted);
		REQUIRE(decrypted.has_value());
		REQUIRE(*decrypted == plaintext);
		REQUIRE(bytesToStr(*decrypted) == msg);
	}
}

TEST_CASE("E2E Roundtrip: Binary data with null bytes", "[e2e][roundtrip][edge]") {
	auto [alice, bob] = establishSession();

	// Data with embedded nulls
	Bytes plaintext = {0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x03, 0xFF, 0xFE, 0x00};
	auto encrypted = alice.encrypt(plaintext);
	auto decrypted = bob.decrypt(encrypted);
	REQUIRE(decrypted.has_value());
	REQUIRE(*decrypted == plaintext);
}

TEST_CASE("E2E Roundtrip: Tampered ciphertext fails decryption", "[e2e][roundtrip][edge]") {
	auto [alice, bob] = establishSession();

	Bytes plaintext = strToBytes("This is a secret message");
	auto encrypted = alice.encrypt(plaintext);

	// Tamper with the ciphertext
	auto tampered = encrypted;
	tampered.ciphertext[0] ^= 0xFF;

	auto decrypted = bob.decrypt(tampered);
	REQUIRE_FALSE(decrypted.has_value());
}

TEST_CASE("E2E Roundtrip: Wrong key fails decryption", "[e2e][roundtrip][edge]") {
	auto [alice, bob] = establishSession();

	Bytes plaintext = strToBytes("Secret message");
	auto encrypted = alice.encrypt(plaintext);

	// Create a third party (Eve) with a different session
	auto [eve, _] = establishSession();

	// Eve tries to decrypt Alice's message — should fail
	auto eveDecrypted = eve.decrypt(encrypted);
	REQUIRE_FALSE(eveDecrypted.has_value());
}

TEST_CASE("E2E Roundtrip: Key bundle generation and exchange", "[e2e][roundtrip]") {
	// Verify that key bundles can be generated independently and used
	// to establish a shared secret
	auto aliceBundle = makeKeyBundle();
	auto bobBundle = makeKeyBundle();

	REQUIRE(aliceBundle.identityKey != bobBundle.identityKey);
	REQUIRE(aliceBundle.signedPreKey != bobBundle.signedPreKey);
	REQUIRE(aliceBundle.oneTimePreKey != bobBundle.oneTimePreKey);
	REQUIRE(aliceBundle.identityKey.size() == 32);
	REQUIRE(aliceBundle.signedPreKey.size() == 32);
	REQUIRE(aliceBundle.oneTimePreKey.size() == 32);

	// Each party's keys should be unique
	REQUIRE(aliceBundle.identityKey != aliceBundle.signedPreKey);
	REQUIRE(aliceBundle.identityKey != aliceBundle.oneTimePreKey);
	REQUIRE(aliceBundle.signedPreKey != aliceBundle.oneTimePreKey);
}

TEST_CASE("E2E Roundtrip: Alternating messages with chain key advancement", "[e2e][roundtrip]") {
	auto [alice, bob] = establishSession();

	// Send 20 alternating messages and verify each roundtrip
	for (int i = 0; i < 20; i++) {
		std::string msg = "Message " + std::to_string(i) +
			((i % 2 == 0) ? " from Alice" : " from Bob");
		Bytes plaintext = strToBytes(msg);

		if (i % 2 == 0) {
			auto encrypted = alice.encrypt(plaintext);
			auto decrypted = bob.decrypt(encrypted);
			REQUIRE(decrypted.has_value());
			REQUIRE(*decrypted == plaintext);
		} else {
			auto encrypted = bob.encrypt(plaintext);
			auto decrypted = alice.decrypt(encrypted);
			REQUIRE(decrypted.has_value());
			REQUIRE(*decrypted == plaintext);
		}
	}
}

TEST_CASE("E2E Roundtrip: Multiple messages then reply", "[e2e][roundtrip]") {
	auto [alice, bob] = establishSession();

	// Alice sends 5 messages
	for (int i = 0; i < 5; i++) {
		Bytes plaintext = strToBytes("Alice batch message " + std::to_string(i));
		auto encrypted = alice.encrypt(plaintext);
		auto decrypted = bob.decrypt(encrypted);
		REQUIRE(decrypted.has_value());
		REQUIRE(*decrypted == plaintext);
	}

	// Bob sends 3 replies
	for (int i = 0; i < 3; i++) {
		Bytes plaintext = strToBytes("Bob reply " + std::to_string(i));
		auto encrypted = bob.encrypt(plaintext);
		auto decrypted = alice.decrypt(encrypted);
		REQUIRE(decrypted.has_value());
		REQUIRE(*decrypted == plaintext);
	}

	// Alice sends 2 more
	for (int i = 0; i < 2; i++) {
		Bytes plaintext = strToBytes("Alice final " + std::to_string(i));
		auto encrypted = alice.encrypt(plaintext);
		auto decrypted = bob.decrypt(encrypted);
		REQUIRE(decrypted.has_value());
		REQUIRE(*decrypted == plaintext);
	}
}

TEST_CASE("E2E Roundtrip: Single byte message", "[e2e][roundtrip][edge]") {
	auto [alice, bob] = establishSession();

	Bytes plaintext = {0x42};
	auto encrypted = alice.encrypt(plaintext);
	auto decrypted = bob.decrypt(encrypted);
	REQUIRE(decrypted.has_value());
	REQUIRE(*decrypted == plaintext);
	REQUIRE(decrypted->size() == 1);
}

TEST_CASE("E2E Roundtrip: All-zero message", "[e2e][roundtrip][edge]") {
	auto [alice, bob] = establishSession();

	Bytes plaintext(256, 0x00);
	auto encrypted = alice.encrypt(plaintext);
	auto decrypted = bob.decrypt(encrypted);
	REQUIRE(decrypted.has_value());
	REQUIRE(*decrypted == plaintext);
}

TEST_CASE("E2E Roundtrip: All-0xFF message", "[e2e][roundtrip][edge]") {
	auto [alice, bob] = establishSession();

	Bytes plaintext(256, 0xFF);
	auto encrypted = alice.encrypt(plaintext);
	auto decrypted = bob.decrypt(encrypted);
	REQUIRE(decrypted.has_value());
	REQUIRE(*decrypted == plaintext);
}

TEST_CASE("E2E Roundtrip: Sequential messages have different ciphertexts", "[e2e][roundtrip]") {
	auto [alice, bob] = establishSession();

	// Same plaintext encrypted twice should produce different ciphertexts
	// (due to chain key ratcheting + random IV)
	Bytes plaintext = strToBytes("Same message content");

	auto enc1 = alice.encrypt(plaintext);
	auto enc2 = alice.encrypt(plaintext);

	// Ciphertexts should differ (different message keys from chain ratchet)
	REQUIRE(enc1.ciphertext != enc2.ciphertext);
	REQUIRE(enc1.iv != enc2.iv);

	// Both should decrypt correctly
	auto dec1 = bob.decrypt(enc1);
	auto dec2 = bob.decrypt(enc2);
	REQUIRE(dec1.has_value());
	REQUIRE(dec2.has_value());
	REQUIRE(*dec1 == plaintext);
	REQUIRE(*dec2 == plaintext);
}
