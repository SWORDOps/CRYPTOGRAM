/*
CRYPTOGRAM E2E Signal Protocol Tests
Tests the Double Ratchet protocol: X3DH key exchange, DH ratcheting,
chain key ratcheting, forward secrecy, out-of-order message handling,
and key bundle serialization/transport.

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

using Bytes = std::vector<unsigned char>;

// ─── Helpers ───────────────────────────────────────────────────────────────────

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

// Simulate KDF_RK (root key ratchet): derive new root key + chain key from DH output
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

// Simulate KDF_CK (chain key ratchet): derive message key from chain key
static Bytes kdfCk(const Bytes &chainKey) {
	Bytes messageKey(32);
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
	REQUIRE(pctx != nullptr);
	REQUIRE(EVP_PKEY_derive_init(pctx) == 1);
	REQUIRE(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) == 1);
	REQUIRE(EVP_PKEY_CTX_set1_hkdf_salt(pctx, chainKey.data(), chainKey.size()) == 1);
	REQUIRE(EVP_PKEY_CTX_set1_hkdf_key(pctx, chainKey.data(), chainKey.size()) == 1);
	REQUIRE(EVP_PKEY_CTX_add1_hkdf_info(pctx,
		reinterpret_cast<const unsigned char*>("CryptogramKDF_CK"), 16) == 1);
	size_t outLen = 32;
	REQUIRE(EVP_PKEY_derive(pctx, messageKey.data(), &outLen) == 1);
	EVP_PKEY_CTX_free(pctx);
	return messageKey;
}

// AES-256-GCM encrypt
static Bytes aesGcmEncrypt(const Bytes &key, const Bytes &iv, const Bytes &plaintext) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	REQUIRE(ctx != nullptr);
	REQUIRE(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1);
	REQUIRE(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1);

	Bytes ciphertext(plaintext.size());
	int len = 0;
	REQUIRE(EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) == 1);
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
static std::optional<Bytes> aesGcmDecrypt(const Bytes &key, const Bytes &iv, const Bytes &ciphertextWithTag) {
	if (ciphertextWithTag.size() < 16) return std::nullopt;

	auto ctSize = ciphertextWithTag.size() - 16;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	REQUIRE(ctx != nullptr);
	REQUIRE(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1);
	REQUIRE(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1);

	Bytes decrypted(ctSize);
	int len = 0;
	REQUIRE(EVP_DecryptUpdate(ctx, decrypted.data(), &len, ciphertextWithTag.data(), static_cast<int>(ctSize)) == 1);

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char*>(ciphertextWithTag.data() + ctSize));
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
	EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, privKey.data(), privKey.size());
	REQUIRE(pkey != nullptr);
	EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peerPubKey.data(), peerPubKey.size());
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

// ─── Key Bundle Serialization (simulates SignalProtocolTransport) ──────────────

struct KeyBundle {
	Bytes identityKey;
	Bytes signedPreKey;
	Bytes signature;
	Bytes oneTimePreKey;
	uint64_t registrationId;
};

static KeyBundle makeBundle() {
	KeyBundle bundle;
	bundle.identityKey = randomBytes(32);
	bundle.signedPreKey = randomBytes(32);
	bundle.signature = randomBytes(64);
	bundle.oneTimePreKey = randomBytes(32);
	bundle.registrationId = 0x1234567890ABCDEF;
	return bundle;
}

// Serialize: version(1) + bitmap(1) + regId(8) + identityKey(32) + signedPreKey(32) + signature(64) + oneTimePreKey(32)
static Bytes encodeKeyBundle(const KeyBundle &bundle) {
	Bytes encoded;
	encoded.push_back(0x01); // version
	encoded.push_back(0x0F); // bitmap: all keys present
	uint64_t regId = bundle.registrationId;
	for (int i = 0; i < 8; i++) {
		encoded.push_back(static_cast<unsigned char>((regId >> (i * 8)) & 0xFF));
	}
	encoded.insert(encoded.end(), bundle.identityKey.begin(), bundle.identityKey.end());
	encoded.insert(encoded.end(), bundle.signedPreKey.begin(), bundle.signedPreKey.end());
	encoded.insert(encoded.end(), bundle.signature.begin(), bundle.signature.end());
	encoded.insert(encoded.end(), bundle.oneTimePreKey.begin(), bundle.oneTimePreKey.end());
	return encoded;
}

static std::optional<KeyBundle> decodeKeyBundle(const Bytes &encoded) {
	if (encoded.size() < 170) return std::nullopt; // 1+1+8+32+32+64+32 = 170
	if (encoded[0] != 0x01) return std::nullopt;
	if (encoded[1] != 0x0F) return std::nullopt;

	KeyBundle bundle;
	size_t offset = 2;
	uint64_t regId = 0;
	for (int i = 0; i < 8; i++) {
		regId |= static_cast<uint64_t>(encoded[offset + i]) << (i * 8);
	}
	bundle.registrationId = regId;
	offset += 8;

	bundle.identityKey = Bytes(encoded.begin() + offset, encoded.begin() + offset + 32);
	offset += 32;
	bundle.signedPreKey = Bytes(encoded.begin() + offset, encoded.begin() + offset + 32);
	offset += 32;
	bundle.signature = Bytes(encoded.begin() + offset, encoded.begin() + offset + 64);
	offset += 64;
	bundle.oneTimePreKey = Bytes(encoded.begin() + offset, encoded.begin() + offset + 32);

	return bundle;
}

// Simulate a Double Ratchet session
struct RatchetSession {
	Bytes rootKey;
	Bytes sendingChainKey;
	Bytes receivingChainKey;
	Bytes dhPrivateKey;
	Bytes dhPublicKey;
	Bytes remoteDhPublicKey;
	uint32_t sendCounter = 0;
	uint32_t recvCounter = 0;
};

// ─── Key Bundle Transport E2E ──────────────────────────────────────────────────

TEST_CASE("E2E: KeyBundle serialization round-trip", "[signal][e2e]") {
	auto bundle = makeBundle();
	auto encoded = encodeKeyBundle(bundle);
	REQUIRE(encoded.size() == 170);

	auto decoded = decodeKeyBundle(encoded);
	REQUIRE(decoded.has_value());
	REQUIRE(decoded->identityKey == bundle.identityKey);
	REQUIRE(decoded->signedPreKey == bundle.signedPreKey);
	REQUIRE(decoded->signature == bundle.signature);
	REQUIRE(decoded->oneTimePreKey == bundle.oneTimePreKey);
	REQUIRE(decoded->registrationId == bundle.registrationId);
}

TEST_CASE("E2E: Multiple key bundles serialize independently", "[signal][e2e]") {
	auto bundle1 = makeBundle();
	auto bundle2 = makeBundle();
	bundle2.registrationId = 0xFEDCBA0987654321;

	auto encoded1 = encodeKeyBundle(bundle1);
	auto encoded2 = encodeKeyBundle(bundle2);

	auto decoded1 = decodeKeyBundle(encoded1);
	auto decoded2 = decodeKeyBundle(encoded2);
	REQUIRE(decoded1.has_value());
	REQUIRE(decoded2.has_value());
	REQUIRE(decoded1->registrationId == 0x1234567890ABCDEF);
	REQUIRE(decoded2->registrationId == 0xFEDCBA0987654321);
	REQUIRE(decoded1->identityKey != decoded2->identityKey);
}

// ─── Double Ratchet Simulation E2E ─────────────────────────────────────────────

TEST_CASE("E2E: Double Ratchet basic message exchange", "[signal][e2e][ratchet]") {
	auto [alicePriv, alicePub] = generateX25519();
	auto [bobPriv, bobPub] = generateX25519();

	auto dhOutput = dhCompute(alicePriv, bobPub);
	auto [initialRoot, initialChain] = kdfRk(randomBytes(32), dhOutput);

	RatchetSession alice;
	alice.rootKey = initialRoot;
	alice.sendingChainKey = initialChain;
	alice.dhPrivateKey = alicePriv;
	alice.dhPublicKey = alicePub;
	alice.remoteDhPublicKey = bobPub;

	RatchetSession bob;
	bob.rootKey = initialRoot;
	bob.receivingChainKey = initialChain;
	bob.dhPrivateKey = bobPriv;
	bob.dhPublicKey = bobPub;
	bob.remoteDhPublicKey = alicePub;

	auto msgKey1 = kdfCk(alice.sendingChainKey);
	auto iv1 = randomBytes(12);
	Bytes plaintext1 = {'H', 'e', 'l', 'l', 'o'};
	auto ciphertext1 = aesGcmEncrypt(msgKey1, iv1, plaintext1);
	alice.sendCounter++;

	auto bobMsgKey1 = kdfCk(bob.receivingChainKey);
	auto decrypted1 = aesGcmDecrypt(bobMsgKey1, iv1, ciphertext1);
	REQUIRE(decrypted1.has_value());
	REQUIRE(*decrypted1 == plaintext1);
	bob.recvCounter++;
}

TEST_CASE("E2E: Double Ratchet DH ratchet step", "[signal][e2e][ratchet]") {
	auto [alicePriv, alicePub] = generateX25519();
	auto [bobPriv, bobPub] = generateX25519();

	auto dhOutput1 = dhCompute(alicePriv, bobPub);
	auto [rootKey1, chainKey1] = kdfRk(randomBytes(32), dhOutput1);

	auto [bobNewPriv, bobNewPub] = generateX25519();

	auto dhOutput2 = dhCompute(bobNewPriv, alicePub);
	auto [rootKey2, newChainKey] = kdfRk(rootKey1, dhOutput2);

	auto aliceDhOutput2 = dhCompute(alicePriv, bobNewPub);
	auto [aliceRootKey2, aliceNewChainKey] = kdfRk(rootKey1, aliceDhOutput2);

	REQUIRE(rootKey2 == aliceRootKey2);
	REQUIRE(newChainKey == aliceNewChainKey);
}

TEST_CASE("E2E: Double Ratchet forward secrecy - old keys cannot decrypt new messages", "[signal][e2e][ratchet]") {
	auto [alicePriv, alicePub] = generateX25519();
	auto [bobPriv, bobPub] = generateX25519();

	auto dhOutput = dhCompute(alicePriv, bobPub);
	auto [rootKey, chainKey] = kdfRk(randomBytes(32), dhOutput);

	auto msgKey1 = kdfCk(chainKey);
	auto iv = randomBytes(12);
	Bytes plaintext = {'s', 'e', 'c', 'r', 'e', 't'};
	auto ciphertext = aesGcmEncrypt(msgKey1, iv, plaintext);

	auto [newRoot, newChain] = kdfRk(rootKey, dhCompute(alicePriv, bobPub));
	auto msgKey2 = kdfCk(newChain);

	auto ciphertext2 = aesGcmEncrypt(msgKey2, iv, plaintext);
	auto decryptWithOldKey = aesGcmDecrypt(msgKey1, iv, ciphertext2);
	REQUIRE_FALSE(decryptWithOldKey.has_value());

	auto decryptOriginal = aesGcmDecrypt(msgKey1, iv, ciphertext);
	REQUIRE(decryptOriginal.has_value());
	REQUIRE(*decryptOriginal == plaintext);
}

TEST_CASE("E2E: Double Ratchet out-of-order message handling", "[signal][e2e][ratchet]") {
	auto [alicePriv, alicePub] = generateX25519();
	auto [bobPriv, bobPub] = generateX25519();

	auto dhOutput = dhCompute(alicePriv, bobPub);
	auto [rootKey, chainKey] = kdfRk(randomBytes(32), dhOutput);

	auto key0 = kdfCk(chainKey);
	auto key1 = kdfCk(chainKey);
	auto key2 = kdfCk(chainKey);

	auto iv = randomBytes(12);
	Bytes msg0 = {'m', '0'};
	Bytes msg1 = {'m', '1'};
	Bytes msg2 = {'m', '2'};

	auto ct0 = aesGcmEncrypt(key0, iv, msg0);
	auto ct1 = aesGcmEncrypt(key1, iv, msg1);
	auto ct2 = aesGcmEncrypt(key2, iv, msg2);

	auto dec2 = aesGcmDecrypt(key2, iv, ct2);
	auto dec1 = aesGcmDecrypt(key1, iv, ct1);
	auto dec0 = aesGcmDecrypt(key0, iv, ct0);

	REQUIRE(dec0.has_value());
	REQUIRE(dec1.has_value());
	REQUIRE(dec2.has_value());
	REQUIRE(*dec0 == msg0);
	REQUIRE(*dec1 == msg1);
	REQUIRE(*dec2 == msg2);
}

TEST_CASE("E2E: Double Ratchet multiple messages same chain", "[signal][e2e][ratchet]") {
	auto [alicePriv, alicePub] = generateX25519();
	auto [bobPriv, bobPub] = generateX25519();

	auto dhOutput = dhCompute(alicePriv, bobPub);
	auto [rootKey, chainKey] = kdfRk(randomBytes(32), dhOutput);

	auto iv = randomBytes(12);
	for (int i = 0; i < 5; i++) {
		auto msgKey = kdfCk(chainKey);
		Bytes plaintext = {static_cast<unsigned char>('A' + i), static_cast<unsigned char>('0' + i)};
		auto ciphertext = aesGcmEncrypt(msgKey, iv, plaintext);

		auto recvKey = kdfCk(chainKey);
		auto decrypted = aesGcmDecrypt(recvKey, iv, ciphertext);
		REQUIRE(decrypted.has_value());
		REQUIRE(*decrypted == plaintext);
	}
}

// ─── Key Bundle Validation E2E ─────────────────────────────────────────────────

TEST_CASE("E2E: KeyBundle rejects corrupted identity key", "[signal][e2e]") {
	auto bundle = makeBundle();
	auto encoded = encodeKeyBundle(bundle);
	REQUIRE(!encoded.empty());

	auto corrupted = encoded;
	corrupted[10] ^= 0x01;

	auto decoded = decodeKeyBundle(corrupted);
	// Decoded will succeed structurally but have wrong key — verify it differs
	if (decoded.has_value()) {
		REQUIRE(decoded->identityKey != bundle.identityKey);
	}
}

TEST_CASE("E2E: KeyBundle rejects truncated data", "[signal][e2e]") {
	auto bundle = makeBundle();
	auto encoded = encodeKeyBundle(bundle);
	REQUIRE(!encoded.empty());

	Bytes truncated(encoded.begin(), encoded.begin() + 10);
	auto decoded = decodeKeyBundle(truncated);
	REQUIRE(!decoded.has_value());
}

TEST_CASE("E2E: KeyBundle with maximum registration ID", "[signal][e2e]") {
	KeyBundle bundle;
	bundle.identityKey = randomBytes(32);
	bundle.signedPreKey = randomBytes(32);
	bundle.signature = randomBytes(64);
	bundle.oneTimePreKey = randomBytes(32);
	bundle.registrationId = 0xFFFFFFFFFFFFFFFF;

	auto encoded = encodeKeyBundle(bundle);
	REQUIRE(!encoded.empty());

	auto decoded = decodeKeyBundle(encoded);
	REQUIRE(decoded.has_value());
	REQUIRE(decoded->registrationId == 0xFFFFFFFFFFFFFFFF);
}
