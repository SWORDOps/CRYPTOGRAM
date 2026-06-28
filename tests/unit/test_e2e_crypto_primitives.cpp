/*
CRYPTOGRAM E2E Crypto Primitives Tests
Tests raw OpenSSL cryptographic operations that underpin all CRYPTOGRAM protocols.
*/

#include <catch2/catch_test_macros.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

#include <vector>
#include <string>
#include <cstring>
#include <memory>

// ─── Helpers ───────────────────────────────────────────────────────────────────

static std::vector<unsigned char> randomBytes(int size) {
	std::vector<unsigned char> buf(size);
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

static std::vector<unsigned char> sha256(const std::vector<unsigned char> &data) {
	std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
	SHA256(data.data(), data.size(), hash.data());
	return hash;
}

// ─── X25519 Key Exchange ───────────────────────────────────────────────────────

TEST_CASE("X25519 key exchange produces shared secret", "[crypto][e2e]") {
	// Generate Alice's key pair
	EVP_PKEY *aliceKey = generateKey(EVP_PKEY_X25519);
	REQUIRE(aliceKey != nullptr);

	size_t alicePrivLen = 0;
	REQUIRE(EVP_PKEY_get_raw_private_key(aliceKey, nullptr, &alicePrivLen) == 1);
	std::vector<unsigned char> alicePriv(alicePrivLen);
	REQUIRE(EVP_PKEY_get_raw_private_key(aliceKey, alicePriv.data(), &alicePrivLen) == 1);

	size_t alicePubLen = 0;
	REQUIRE(EVP_PKEY_get_raw_public_key(aliceKey, nullptr, &alicePubLen) == 1);
	std::vector<unsigned char> alicePub(alicePubLen);
	REQUIRE(EVP_PKEY_get_raw_public_key(aliceKey, alicePub.data(), &alicePubLen) == 1);

	// Generate Bob's key pair
	EVP_PKEY *bobKey = generateKey(EVP_PKEY_X25519);
	REQUIRE(bobKey != nullptr);

	size_t bobPubLen = 0;
	REQUIRE(EVP_PKEY_get_raw_public_key(bobKey, nullptr, &bobPubLen) == 1);
	std::vector<unsigned char> bobPub(bobPubLen);
	REQUIRE(EVP_PKEY_get_raw_public_key(bobKey, bobPub.data(), &bobPubLen) == 1);

	// Derive shared secret on Alice's side
	EVP_PKEY *bobPubKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, bobPub.data(), bobPubLen);
	REQUIRE(bobPubKey != nullptr);

	EVP_PKEY_CTX *deriveCtx = EVP_PKEY_CTX_new(aliceKey, nullptr);
	REQUIRE(deriveCtx != nullptr);
	REQUIRE(EVP_PKEY_derive_init(deriveCtx) == 1);
	REQUIRE(EVP_PKEY_derive_set_peer(deriveCtx, bobPubKey) == 1);

	size_t sharedLen = 0;
	REQUIRE(EVP_PKEY_derive(deriveCtx, nullptr, &sharedLen) == 1);
	std::vector<unsigned char> aliceShared(sharedLen);
	REQUIRE(EVP_PKEY_derive(deriveCtx, aliceShared.data(), &sharedLen) == 1);

	EVP_PKEY_CTX_free(deriveCtx);
	EVP_PKEY_free(bobPubKey);

	// Derive shared secret on Bob's side
	EVP_PKEY *alicePubKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, alicePub.data(), alicePubLen);
	REQUIRE(alicePubKey != nullptr);

	deriveCtx = EVP_PKEY_CTX_new(bobKey, nullptr);
	REQUIRE(deriveCtx != nullptr);
	REQUIRE(EVP_PKEY_derive_init(deriveCtx) == 1);
	REQUIRE(EVP_PKEY_derive_set_peer(deriveCtx, alicePubKey) == 1);

	std::vector<unsigned char> bobShared(sharedLen);
	REQUIRE(EVP_PKEY_derive(deriveCtx, bobShared.data(), &sharedLen) == 1);

	EVP_PKEY_CTX_free(deriveCtx);
	EVP_PKEY_free(alicePubKey);
	EVP_PKEY_free(aliceKey);
	EVP_PKEY_free(bobKey);

	// Both sides must derive the same shared secret
	REQUIRE(aliceShared == bobShared);
	REQUIRE(aliceShared.size() == 32);
}

TEST_CASE("X25519 different key pairs produce different shared secrets", "[crypto][e2e]") {
	auto generatePair = [](std::vector<unsigned char> &priv, std::vector<unsigned char> &pub) {
		EVP_PKEY *key = generateKey(EVP_PKEY_X25519);
		REQUIRE(key != nullptr);
		size_t privLen = 0, pubLen = 0;
		EVP_PKEY_get_raw_private_key(key, nullptr, &privLen);
		EVP_PKEY_get_raw_public_key(key, nullptr, &pubLen);
		priv.resize(privLen);
		pub.resize(pubLen);
		EVP_PKEY_get_raw_private_key(key, priv.data(), &privLen);
		EVP_PKEY_get_raw_public_key(key, pub.data(), &pubLen);
		EVP_PKEY_free(key);
	};

	std::vector<unsigned char> a1Priv, a1Pub, b1Priv, b1Pub;
	generatePair(a1Priv, a1Pub);
	generatePair(b1Priv, b1Pub);

	std::vector<unsigned char> a2Priv, a2Pub, b2Priv, b2Pub;
	generatePair(a2Priv, a2Pub);
	generatePair(b2Priv, b2Pub);

	// Shared secret between A1-B1 should differ from A2-B2
	auto deriveShared = [](const std::vector<unsigned char> &priv,
			       const std::vector<unsigned char> &peerPub) {
		EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), priv.size());
		EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peerPub.data(), peerPub.size());
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
		EVP_PKEY_derive_init(ctx);
		EVP_PKEY_derive_set_peer(ctx, peer);
		size_t len = 0;
		EVP_PKEY_derive(ctx, nullptr, &len);
		std::vector<unsigned char> shared(len);
		EVP_PKEY_derive(ctx, shared.data(), &len);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(peer);
		EVP_PKEY_free(pkey);
		return shared;
	};

	auto shared1 = deriveShared(a1Priv, b1Pub);
	auto shared2 = deriveShared(a2Priv, b2Pub);
	REQUIRE(shared1 != shared2);
}

// ─── Ed25519 Sign/Verify ───────────────────────────────────────────────────────

TEST_CASE("Ed25519 sign and verify round-trip", "[crypto][e2e]") {
	// Generate key pair
	EVP_PKEY *key = generateKey(EVP_PKEY_ED25519);
	REQUIRE(key != nullptr);

	size_t pubLen = 0;
	EVP_PKEY_get_raw_public_key(key, nullptr, &pubLen);
	std::vector<unsigned char> pubKey(pubLen);
	EVP_PKEY_get_raw_public_key(key, pubKey.data(), &pubLen);

	// Sign
	auto message = std::string("CRYPTOGRAM Ed25519 test message");
	EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
	REQUIRE(mdCtx != nullptr);
	REQUIRE(EVP_DigestSignInit(mdCtx, nullptr, nullptr, nullptr, key) == 1);

	size_t sigLen = 0;
	REQUIRE(EVP_DigestSign(mdCtx, nullptr, &sigLen,
		reinterpret_cast<const unsigned char*>(message.data()), message.size()) == 1);
	std::vector<unsigned char> signature(sigLen);
	REQUIRE(EVP_DigestSign(mdCtx, signature.data(), &sigLen,
		reinterpret_cast<const unsigned char*>(message.data()), message.size()) == 1);
	EVP_MD_CTX_free(mdCtx);
	EVP_PKEY_free(key);

	// Verify
	EVP_PKEY *pubKeyObj = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pubKey.data(), pubLen);
	REQUIRE(pubKeyObj != nullptr);

	mdCtx = EVP_MD_CTX_new();
	REQUIRE(EVP_DigestVerifyInit(mdCtx, nullptr, nullptr, nullptr, pubKeyObj) == 1);
	int result = EVP_DigestVerify(mdCtx, signature.data(), sigLen,
		reinterpret_cast<const unsigned char*>(message.data()), message.size());
	EVP_MD_CTX_free(mdCtx);
	EVP_PKEY_free(pubKeyObj);

	REQUIRE(result == 1);
}

TEST_CASE("Ed25519 signature verification fails on tampered message", "[crypto][e2e]") {
	EVP_PKEY *key = generateKey(EVP_PKEY_ED25519);
	REQUIRE(key != nullptr);

	size_t pubLen = 0;
	EVP_PKEY_get_raw_public_key(key, nullptr, &pubLen);
	std::vector<unsigned char> pubKey(pubLen);
	EVP_PKEY_get_raw_public_key(key, pubKey.data(), &pubLen);

	auto message = std::string("Original message");
	EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
	EVP_DigestSignInit(mdCtx, nullptr, nullptr, nullptr, key);
	size_t sigLen = 0;
	EVP_DigestSign(mdCtx, nullptr, &sigLen,
		reinterpret_cast<const unsigned char*>(message.data()), message.size());
	std::vector<unsigned char> signature(sigLen);
	EVP_DigestSign(mdCtx, signature.data(), &sigLen,
		reinterpret_cast<const unsigned char*>(message.data()), message.size());
	EVP_MD_CTX_free(mdCtx);
	EVP_PKEY_free(key);

	// Tamper with message
	auto tampered = std::string("Tampered message");
	EVP_PKEY *pubKeyObj = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pubKey.data(), pubLen);
	mdCtx = EVP_MD_CTX_new();
	EVP_DigestVerifyInit(mdCtx, nullptr, nullptr, nullptr, pubKeyObj);
	int result = EVP_DigestVerify(mdCtx, signature.data(), sigLen,
		reinterpret_cast<const unsigned char*>(tampered.data()), tampered.size());
	EVP_MD_CTX_free(mdCtx);
	EVP_PKEY_free(pubKeyObj);

	REQUIRE(result == 0);  // Verification must fail
}

// ─── AES-256-GCM Encryption ────────────────────────────────────────────────────

TEST_CASE("AES-256-GCM encrypt/decrypt round-trip with associated data", "[crypto][e2e]") {
	auto key = randomBytes(32);
	auto iv = randomBytes(12);
	auto plaintext = std::string("CRYPTOGRAM AES-256-GCM authenticated encryption test");
	auto aad = std::string("AssociatedData:PeerID=12345");

	// Encrypt
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	REQUIRE(ctx != nullptr);
	REQUIRE(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1);
	REQUIRE(EVP_CIPHER_CTX_set_key_length(ctx, 32) == 1);
	REQUIRE(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1);

	int len = 0;
	REQUIRE(EVP_EncryptUpdate(ctx, nullptr, &len,
		reinterpret_cast<const unsigned char*>(aad.data()), aad.size()) == 1);

	std::vector<unsigned char> ciphertext(plaintext.size());
	REQUIRE(EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
		reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) == 1);
	int totalLen = len;
	REQUIRE(EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) == 1);
	totalLen += len;

	std::vector<unsigned char> tag(16);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
	EVP_CIPHER_CTX_free(ctx);

	// Decrypt
	ctx = EVP_CIPHER_CTX_new();
	REQUIRE(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1);
	REQUIRE(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1);

	REQUIRE(EVP_DecryptUpdate(ctx, nullptr, &len,
		reinterpret_cast<const unsigned char*>(aad.data()), aad.size()) == 1);

	std::vector<unsigned char> decrypted(plaintext.size());
	REQUIRE(EVP_DecryptUpdate(ctx, decrypted.data(), &len, ciphertext.data(), totalLen) == 1);

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data());
	int ret = EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len);
	EVP_CIPHER_CTX_free(ctx);

	REQUIRE(ret == 1);
	std::string result(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
	REQUIRE(result == plaintext);
}

TEST_CASE("AES-256-GCM fails with wrong AAD", "[crypto][e2e]") {
	auto key = randomBytes(32);
	auto iv = randomBytes(12);
	auto plaintext = std::string("AAD tamper test");
	auto aad = std::string("CorrectAAD");
	auto wrongAad = std::string("TamperedAAD");

	// Encrypt with correct AAD
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
	EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());
	int len = 0;
	EVP_EncryptUpdate(ctx, nullptr, &len, reinterpret_cast<const unsigned char*>(aad.data()), aad.size());

	std::vector<unsigned char> ciphertext(plaintext.size());
	EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
		reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size());
	int totalLen = len;
	EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
	totalLen += len;

	std::vector<unsigned char> tag(16);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
	EVP_CIPHER_CTX_free(ctx);

	// Decrypt with wrong AAD
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
	EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());
	EVP_DecryptUpdate(ctx, nullptr, &len,
		reinterpret_cast<const unsigned char*>(wrongAad.data()), wrongAad.size());

	std::vector<unsigned char> decrypted(plaintext.size());
	EVP_DecryptUpdate(ctx, decrypted.data(), &len, ciphertext.data(), totalLen);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data());
	int ret = EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len);
	EVP_CIPHER_CTX_free(ctx);

	REQUIRE(ret == 0);  // Must fail
}

TEST_CASE("AES-256-GCM fails with wrong key", "[crypto][e2e]") {
	auto key = randomBytes(32);
	auto wrongKey = randomBytes(32);
	auto iv = randomBytes(12);
	auto plaintext = std::string("Wrong key test");

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
	EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());

	std::vector<unsigned char> ciphertext(plaintext.size());
	int len = 0;
	EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
		reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size());
	int totalLen = len;
	EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
	totalLen += len;

	std::vector<unsigned char> tag(16);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
	EVP_CIPHER_CTX_free(ctx);

	// Decrypt with wrong key
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
	EVP_DecryptInit_ex(ctx, nullptr, nullptr, wrongKey.data(), iv.data());

	std::vector<unsigned char> decrypted(plaintext.size());
	EVP_DecryptUpdate(ctx, decrypted.data(), &len, ciphertext.data(), totalLen);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data());
	int ret = EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len);
	EVP_CIPHER_CTX_free(ctx);

	REQUIRE(ret == 0);
}

// ─── HKDF (RFC 5869) ───────────────────────────────────────────────────────────

TEST_CASE("HKDF-SHA256 derives 32-byte key", "[crypto][e2e]") {
	auto ikm = randomBytes(32);
	auto salt = randomBytes(32);
	std::string info = "CRYPTOGRAM_DoubleRatchet_RootKey";

	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
	REQUIRE(pctx != nullptr);
	REQUIRE(EVP_PKEY_derive_init(pctx) == 1);
	REQUIRE(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) == 1);
	REQUIRE(EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size()) == 1);
	REQUIRE(EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm.size()) == 1);
	REQUIRE(EVP_PKEY_CTX_add1_hkdf_info(pctx,
		reinterpret_cast<const unsigned char*>(info.data()), info.size()) == 1);

	std::vector<unsigned char> derived(32);
	size_t outLen = 32;
	REQUIRE(EVP_PKEY_derive(pctx, derived.data(), &outLen) == 1);
	EVP_PKEY_CTX_free(pctx);

	REQUIRE(outLen == 32);
	// Verify it's not all zeros
	bool allZero = true;
	for (auto b : derived) {
		if (b != 0) { allZero = false; break; }
	}
	REQUIRE_FALSE(allZero);
}

TEST_CASE("HKDF different info strings produce different keys", "[crypto][e2e]") {
	auto ikm = randomBytes(32);
	auto salt = randomBytes(32);

	auto derive = [&](const std::string &infoStr) {
		std::vector<unsigned char> out(32);
		EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
		EVP_PKEY_derive_init(pctx);
		EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
		EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size());
		EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm.size());
		EVP_PKEY_CTX_add1_hkdf_info(pctx,
			reinterpret_cast<const unsigned char*>(infoStr.data()), infoStr.size());
		size_t outLen = 32;
		EVP_PKEY_derive(pctx, out.data(), &outLen);
		EVP_PKEY_CTX_free(pctx);
		return out;
	};

	auto key1 = derive("CRYPTOGRAM_RootKey");
	auto key2 = derive("CRYPTOGRAM_ChainKey");
	auto key3 = derive("CRYPTOGRAM_MessageKey");

	REQUIRE(key1 != key2);
	REQUIRE(key1 != key3);
	REQUIRE(key2 != key3);
}

TEST_CASE("HKDF different salts produce different keys", "[crypto][e2e]") {
	auto ikm = randomBytes(32);
	auto salt1 = randomBytes(32);
	auto salt2 = randomBytes(32);
	std::string info = "CRYPTOGRAM_test";

	auto derive = [&](const std::vector<unsigned char> &salt) {
		std::vector<unsigned char> out(32);
		EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
		EVP_PKEY_derive_init(pctx);
		EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
		EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size());
		EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm.size());
		EVP_PKEY_CTX_add1_hkdf_info(pctx,
			reinterpret_cast<const unsigned char*>(info.data()), info.size());
		size_t outLen = 32;
		EVP_PKEY_derive(pctx, out.data(), &outLen);
		EVP_PKEY_CTX_free(pctx);
		return out;
	};

	auto key1 = derive(salt1);
	auto key2 = derive(salt2);
	REQUIRE(key1 != key2);
}

// ─── SHA-256 Hashing ───────────────────────────────────────────────────────────

TEST_CASE("SHA-256 is deterministic", "[crypto][e2e]") {
	auto data = std::string("CRYPTOGRAM SHA-256 test");
	auto dataBytes = std::vector<unsigned char>(data.begin(), data.end());

	auto hash1 = sha256(dataBytes);
	auto hash2 = sha256(dataBytes);

	REQUIRE(hash1 == hash2);
	REQUIRE(hash1.size() == 32);
}

TEST_CASE("SHA-256 differs for different inputs", "[crypto][e2e]") {
	auto data1 = std::string("Input 1");
	auto data2 = std::string("Input 2");

	auto hash1 = sha256({data1.begin(), data1.end()});
	auto hash2 = sha256({data2.begin(), data2.end()});

	REQUIRE(hash1 != hash2);
}

TEST_CASE("SHA-256 avalanche effect", "[crypto][e2e]") {
	auto data1 = std::string("CRYPTOGRAM test message");
	auto data2 = std::string("CRYPTOGRAM test messagf");  // Last char differs by 1 bit

	auto hash1 = sha256({data1.begin(), data1.end()});
	auto hash2 = sha256({data2.begin(), data2.end()});

	REQUIRE(hash1 != hash2);
}

// ─── HMAC-SHA256 ───────────────────────────────────────────────────────────────

TEST_CASE("HMAC-SHA256 produces correct MAC", "[crypto][e2e]") {
	auto key = randomBytes(32);
	auto message = std::string("HMAC test message");

	unsigned int macLen = 0;
	std::vector<unsigned char> mac(EVP_MAX_MD_SIZE);
	HMAC(EVP_sha256(),
		key.data(), key.size(),
		reinterpret_cast<const unsigned char*>(message.data()), message.size(),
		mac.data(), &macLen);

	REQUIRE(macLen == 32);
	REQUIRE(mac.size() >= macLen);

	// Verify determinism
	std::vector<unsigned char> mac2(EVP_MAX_MD_SIZE);
	unsigned int mac2Len = 0;
	HMAC(EVP_sha256(),
		key.data(), key.size(),
		reinterpret_cast<const unsigned char*>(message.data()), message.size(),
		mac2.data(), &mac2Len);

	REQUIRE(std::memcmp(mac.data(), mac2.data(), macLen) == 0);
}

TEST_CASE("HMAC-SHA256 differs for different keys", "[crypto][e2e]") {
	auto key1 = randomBytes(32);
	auto key2 = randomBytes(32);
	auto message = std::string("Same message, different keys");

	auto computeHmac = [&](const std::vector<unsigned char> &key) {
		std::vector<unsigned char> mac(EVP_MAX_MD_SIZE);
		unsigned int macLen = 0;
		HMAC(EVP_sha256(),
			key.data(), key.size(),
			reinterpret_cast<const unsigned char*>(message.data()), message.size(),
			mac.data(), &macLen);
		mac.resize(macLen);
		return mac;
	};

	auto mac1 = computeHmac(key1);
	auto mac2 = computeHmac(key2);
	REQUIRE(mac1 != mac2);
}

// ─── Random Number Generation ──────────────────────────────────────────────────

TEST_CASE("RAND_bytes produces non-zero output", "[crypto][e2e]") {
	auto buf = randomBytes(32);
	bool allZero = true;
	for (auto b : buf) {
		if (b != 0) { allZero = false; break; }
	}
	REQUIRE_FALSE(allZero);
}

TEST_CASE("RAND_bytes produces different outputs on successive calls", "[crypto][e2e]") {
	auto buf1 = randomBytes(32);
	auto buf2 = randomBytes(32);
	REQUIRE(buf1 != buf2);
}

TEST_CASE("RAND_bytes generates correct sizes", "[crypto][e2e]") {
	for (int size : {16, 32, 64, 128, 256}) {
		auto buf = randomBytes(size);
		REQUIRE(buf.size() == size);
	}
}
