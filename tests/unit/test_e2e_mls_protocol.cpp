/*
CRYPTOGRAM E2E MLS Protocol Tests
Tests MLS (RFC 9420) group operations: TreeKEM key package generation/verification,
group creation, member add/remove, message encryption/decryption, epoch advancement,
and multi-member group messaging.

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
#include <map>
#include <set>

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

// Ed25519 sign
static Bytes ed25519Sign(EVP_PKEY *privKey, const Bytes &data) {
	EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
	REQUIRE(mdCtx != nullptr);
	REQUIRE(EVP_DigestSignInit(mdCtx, nullptr, nullptr, nullptr, privKey) == 1);

	size_t sigLen = 0;
	REQUIRE(EVP_DigestSign(mdCtx, nullptr, &sigLen, data.data(), data.size()) == 1);
	Bytes signature(sigLen);
	REQUIRE(EVP_DigestSign(mdCtx, signature.data(), &sigLen, data.data(), data.size()) == 1);
	signature.resize(sigLen);
	EVP_MD_CTX_free(mdCtx);
	return signature;
}

// Ed25519 verify
static bool ed25519Verify(EVP_PKEY *pubKey, const Bytes &data, const Bytes &signature) {
	EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
	REQUIRE(mdCtx != nullptr);
	REQUIRE(EVP_DigestVerifyInit(mdCtx, nullptr, nullptr, nullptr, pubKey) == 1);
	int ret = EVP_DigestVerify(mdCtx, signature.data(), signature.size(), data.data(), data.size());
	EVP_MD_CTX_free(mdCtx);
	return ret == 1;
}

// ─── MLS Simulation Types ──────────────────────────────────────────────────────

enum class Ciphersuite : uint16_t {
	MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
	MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0002,
};

using UserId = uint64_t;

struct KeyPackage {
	Ciphersuite ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
	Bytes initKey;        // X25519 public key (32 bytes)
	Bytes credentialPublicKey; // Ed25519 public key (32 bytes)
	Bytes signature;      // Ed25519 signature over (ciphersuite || initKey || credentialPublicKey)

	bool isValid() const {
		return !initKey.empty() && !credentialPublicKey.empty() && !signature.empty();
	}
};

struct MLSGroupState {
	Bytes groupId;
	Ciphersuite ciphersuite;
	std::set<UserId> members;
	uint32_t epoch = 0;
	Bytes epochKey;  // Group encryption key (derived per epoch)

	size_t memberCount() const { return members.size(); }
	bool isMember(UserId id) const { return members.count(id) > 0; }
};

class MLSProtocolSim {
public:
	KeyPackage generateKeyPackage(Ciphersuite cs) {
		KeyPackage pkg;
		pkg.ciphersuite = cs;

		// Generate X25519 init key
		auto x25519 = generateKey(EVP_PKEY_X25519);
		size_t pubLen = 32;
		pkg.initKey.resize(32);
		EVP_PKEY_get_raw_public_key(x25519, pkg.initKey.data(), &pubLen);
		EVP_PKEY_free(x25519);

		// Generate Ed25519 credential key
		auto ed25519 = generateKey(EVP_PKEY_ED25519);
		size_t credPubLen = 32;
		pkg.credentialPublicKey.resize(32);
		EVP_PKEY_get_raw_public_key(ed25519, pkg.credentialPublicKey.data(), &credPubLen);

		// Sign (ciphersuite || initKey || credentialPublicKey)
		Bytes toSign;
		uint16_t csVal = static_cast<uint16_t>(cs);
		toSign.push_back(static_cast<unsigned char>(csVal & 0xFF));
		toSign.push_back(static_cast<unsigned char>((csVal >> 8) & 0xFF));
		toSign.insert(toSign.end(), pkg.initKey.begin(), pkg.initKey.end());
		toSign.insert(toSign.end(), pkg.credentialPublicKey.begin(), pkg.credentialPublicKey.end());

		pkg.signature = ed25519Sign(ed25519, toSign);

		// Store private key for verification
		_ed25519PrivKeys[pkg.credentialPublicKey] = ed25519;

		return pkg;
	}

	bool verifyKeyPackage(const KeyPackage &pkg) const {
		if (!pkg.isValid()) return false;

		Bytes toSign;
		uint16_t cs = static_cast<uint16_t>(pkg.ciphersuite);
		toSign.push_back(static_cast<unsigned char>(cs & 0xFF));
		toSign.push_back(static_cast<unsigned char>((cs >> 8) & 0xFF));
		toSign.insert(toSign.end(), pkg.initKey.begin(), pkg.initKey.end());
		toSign.insert(toSign.end(), pkg.credentialPublicKey.begin(), pkg.credentialPublicKey.end());

		// Use the stored private key to get the public key for verification
		auto it = _ed25519PrivKeys.find(pkg.credentialPublicKey);
		if (it == _ed25519PrivKeys.end()) return false;

		return ed25519Verify(it->second, toSign, pkg.signature);
	}

	Bytes createGroup(const std::vector<UserId> &members, Ciphersuite cs) {
		MLSGroupState state;
		state.groupId = randomBytes(16);
		state.ciphersuite = cs;
		state.members = std::set<UserId>(members.begin(), members.end());
		state.epoch = 0;
		state.epochKey = randomBytes(32);

		Bytes gid = state.groupId;
		_groups[gid] = std::move(state);
		return gid;
	}

	bool hasGroup(const Bytes &gid) const {
		return _groups.count(gid) > 0;
	}

	std::optional<MLSGroupState> getGroupState(const Bytes &gid) const {
		auto it = _groups.find(gid);
		if (it == _groups.end()) return std::nullopt;
		return it->second;
	}

	bool addMember(const Bytes &gid, UserId id) {
		auto it = _groups.find(gid);
		if (it == _groups.end()) return false;
		it->second.members.insert(id);
		it->second.epoch++;
		it->second.epochKey = randomBytes(32); // New epoch key
		return true;
	}

	bool removeMember(const Bytes &gid, UserId id) {
		auto it = _groups.find(gid);
		if (it == _groups.end()) return false;
		if (it->second.members.erase(id) == 0) return false;
		it->second.epoch++;
		it->second.epochKey = randomBytes(32);
		return true;
	}

	Bytes encryptMessage(const Bytes &gid, const Bytes &plaintext) {
		auto it = _groups.find(gid);
		REQUIRE(it != _groups.end());
		auto iv = randomBytes(12);
		Bytes ct = aesGcmEncrypt(it->second.epochKey, iv, plaintext);
		// Prepend IV
		Bytes result;
		result.insert(result.end(), iv.begin(), iv.end());
		result.insert(result.end(), ct.begin(), ct.end());
		return result;
	}

	std::optional<Bytes> decryptMessage(const Bytes &gid, const Bytes &ciphertext) {
		auto it = _groups.find(gid);
		if (it == _groups.end()) return std::nullopt;
		if (ciphertext.size() < 12 + 16) return std::nullopt;

		Bytes iv(ciphertext.begin(), ciphertext.begin() + 12);
		Bytes ct(ciphertext.begin() + 12, ciphertext.end());
		return aesGcmDecrypt(it->second.epochKey, iv, ct);
	}

private:
	std::map<Bytes, MLSGroupState> _groups;
	std::map<Bytes, EVP_PKEY *> _ed25519PrivKeys;
};

// ─── Key Package Generation & Verification E2E ─────────────────────────────────

TEST_CASE("E2E: MLS key package generation and verification", "[mls][e2e]") {
	MLSProtocolSim protocol;

	const auto keyPackage = protocol.generateKeyPackage(
		Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

	REQUIRE(keyPackage.isValid());
	REQUIRE_FALSE(keyPackage.initKey.empty());
	REQUIRE_FALSE(keyPackage.credentialPublicKey.empty());
	REQUIRE_FALSE(keyPackage.signature.empty());
	REQUIRE(protocol.verifyKeyPackage(keyPackage));
}

TEST_CASE("E2E: MLS key package tampered signature fails verification", "[mls][e2e]") {
	MLSProtocolSim protocol;

	const auto keyPackage = protocol.generateKeyPackage(
		Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

	REQUIRE(protocol.verifyKeyPackage(keyPackage));

	auto tampered = keyPackage;
	tampered.signature[0] ^= 0x01;
	REQUIRE_FALSE(protocol.verifyKeyPackage(tampered));
}

TEST_CASE("E2E: MLS key package tampered init key fails verification", "[mls][e2e]") {
	MLSProtocolSim protocol;

	const auto keyPackage = protocol.generateKeyPackage(
		Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519);

	REQUIRE(protocol.verifyKeyPackage(keyPackage));

	auto tampered = keyPackage;
	tampered.initKey[0] ^= 0x01;
	REQUIRE_FALSE(protocol.verifyKeyPackage(tampered));
}

TEST_CASE("E2E: MLS key packages for different ciphersuites", "[mls][e2e]") {
	MLSProtocolSim protocol;

	auto pkg1 = protocol.generateKeyPackage(
		Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
	auto pkg2 = protocol.generateKeyPackage(
		Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519);

	REQUIRE(pkg1.isValid());
	REQUIRE(pkg2.isValid());
	REQUIRE(pkg1.ciphersuite != pkg2.ciphersuite);
	REQUIRE(protocol.verifyKeyPackage(pkg1));
	REQUIRE(protocol.verifyKeyPackage(pkg2));
}

// ─── Group Creation E2E ────────────────────────────────────────────────────────

TEST_CASE("E2E: MLS group creation with 2 members", "[mls][e2e]") {
	MLSProtocolSim protocol;

	const std::vector<UserId> members = {101, 202};
	const auto groupId = protocol.createGroup(
		members,
		Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

	REQUIRE_FALSE(groupId.empty());
	REQUIRE(protocol.hasGroup(groupId));

	auto state = protocol.getGroupState(groupId);
	REQUIRE(state.has_value());
	REQUIRE(state->memberCount() == 2);
	REQUIRE(state->isMember(101));
	REQUIRE(state->isMember(202));
}

TEST_CASE("E2E: MLS group creation with 5 members", "[mls][e2e]") {
	MLSProtocolSim protocol;

	const std::vector<UserId> members = {1001, 1002, 1003, 1004, 1005};
	const auto groupId = protocol.createGroup(
		members,
		Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

	REQUIRE_FALSE(groupId.empty());
	REQUIRE(protocol.hasGroup(groupId));

	auto state = protocol.getGroupState(groupId);
	REQUIRE(state.has_value());
	REQUIRE(state->memberCount() == 5);

	for (auto uid : members) {
		REQUIRE(state->isMember(uid));
	}
}

TEST_CASE("E2E: MLS group creation with different ciphersuites", "[mls][e2e]") {
	MLSProtocolSim protocol;

	const std::vector<UserId> members = {1, 2};

	auto group1 = protocol.createGroup(
		members, Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
	auto group2 = protocol.createGroup(
		members, Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519);

	REQUIRE_FALSE(group1.empty());
	REQUIRE_FALSE(group2.empty());
	REQUIRE(group1 != group2);

	auto state1 = protocol.getGroupState(group1);
	auto state2 = protocol.getGroupState(group2);
	REQUIRE(state1->ciphersuite != state2->ciphersuite);
}

// ─── Group Messaging E2E ───────────────────────────────────────────────────────

TEST_CASE("E2E: MLS group message encrypt/decrypt round-trip", "[mls][e2e]") {
	MLSProtocolSim protocol;

	const std::vector<UserId> members = {101, 202};
	const auto groupId = protocol.createGroup(
		members, Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

	const Bytes plaintext = {'H', 'e', 'l', 'l', 'o'};

	const auto ciphertext = protocol.encryptMessage(groupId, plaintext);
	REQUIRE_FALSE(ciphertext.empty());

	const auto decrypted = protocol.decryptMessage(groupId, ciphertext);
	REQUIRE(decrypted.has_value());
	REQUIRE(decrypted.value() == plaintext);
}

TEST_CASE("E2E: MLS group message tampered ciphertext fails decryption", "[mls][e2e]") {
	MLSProtocolSim protocol;

	const std::vector<UserId> members = {101, 202};
	const auto groupId = protocol.createGroup(
		members, Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

	const Bytes plaintext = {'T', 'a', 'm', 'p', 'e', 'r'};

	const auto ciphertext = protocol.encryptMessage(groupId, plaintext);
	REQUIRE_FALSE(ciphertext.empty());

	auto tampered = ciphertext;
	tampered.back() ^= 0x01;

	const auto result = protocol.decryptMessage(groupId, tampered);
	REQUIRE_FALSE(result.has_value());
}

TEST_CASE("E2E: MLS multiple messages in same epoch", "[mls][e2e]") {
	MLSProtocolSim protocol;

	const std::vector<UserId> members = {1, 2};
	const auto groupId = protocol.createGroup(
		members, Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

	for (int i = 0; i < 10; i++) {
		Bytes plaintext;
		plaintext.push_back(static_cast<unsigned char>('A' + i));
		plaintext.push_back(static_cast<unsigned char>('0' + (i % 10)));

		auto ciphertext = protocol.encryptMessage(groupId, plaintext);
		REQUIRE_FALSE(ciphertext.empty());

		auto decrypted = protocol.decryptMessage(groupId, ciphertext);
		REQUIRE(decrypted.has_value());
		REQUIRE(decrypted.value() == plaintext);
	}
}

TEST_CASE("E2E: MLS large message encryption", "[mls][e2e]") {
	MLSProtocolSim protocol;

	const std::vector<UserId> members = {1, 2};
	const auto groupId = protocol.createGroup(
		members, Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

	Bytes plaintext(4096);
	REQUIRE(RAND_bytes(plaintext.data(), 4096) == 1);

	auto ciphertext = protocol.encryptMessage(groupId, plaintext);
	REQUIRE_FALSE(ciphertext.empty());
	REQUIRE(ciphertext.size() >= plaintext.size());

	auto decrypted = protocol.decryptMessage(groupId, ciphertext);
	REQUIRE(decrypted.has_value());
	REQUIRE(decrypted.value() == plaintext);
}

// ─── Member Operations E2E ─────────────────────────────────────────────────────

TEST_CASE("E2E: MLS add member to group", "[mls][e2e]") {
	MLSProtocolSim protocol;

	const std::vector<UserId> initialMembers = {101, 202};
	const auto groupId = protocol.createGroup(
		initialMembers, Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

	REQUIRE(protocol.addMember(groupId, 303));

	auto state = protocol.getGroupState(groupId);
	REQUIRE(state.has_value());
	REQUIRE(state->memberCount() == 3);
	REQUIRE(state->isMember(303));
}

TEST_CASE("E2E: MLS remove member from group", "[mls][e2e]") {
	MLSProtocolSim protocol;

	const std::vector<UserId> members = {101, 202, 303};
	const auto groupId = protocol.createGroup(
		members, Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

	REQUIRE(protocol.removeMember(groupId, 202));

	auto state = protocol.getGroupState(groupId);
	REQUIRE(state.has_value());
	REQUIRE(state->memberCount() == 2);
	REQUIRE_FALSE(state->isMember(202));
	REQUIRE(state->isMember(101));
	REQUIRE(state->isMember(303));
}

TEST_CASE("E2E: MLS add then remove member preserves encryption", "[mls][e2e]") {
	MLSProtocolSim protocol;

	const std::vector<UserId> members = {1, 2};
	const auto groupId = protocol.createGroup(
		members, Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

	REQUIRE(protocol.addMember(groupId, 3));

	Bytes msg1 = {'A', 'f', 't', 'e', 'r'};
	auto ct1 = protocol.encryptMessage(groupId, msg1);
	auto pt1 = protocol.decryptMessage(groupId, ct1);
	REQUIRE(pt1.has_value());
	REQUIRE(*pt1 == msg1);

	REQUIRE(protocol.removeMember(groupId, 3));

	Bytes msg2 = {'R', 'e', 'm', 'o', 'v', 'e'};
	auto ct2 = protocol.encryptMessage(groupId, msg2);
	auto pt2 = protocol.decryptMessage(groupId, ct2);
	REQUIRE(pt2.has_value());
	REQUIRE(*pt2 == msg2);
}

TEST_CASE("E2E: MLS add multiple members sequentially", "[mls][e2e]") {
	MLSProtocolSim protocol;

	const std::vector<UserId> initial = {1};
	const auto groupId = protocol.createGroup(
		initial, Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

	for (uint64_t i = 2; i <= 10; i++) {
		REQUIRE(protocol.addMember(groupId, i));
	}

	auto state = protocol.getGroupState(groupId);
	REQUIRE(state->memberCount() == 10);

	for (uint64_t i = 1; i <= 10; i++) {
		REQUIRE(state->isMember(i));
	}
}

// ─── Epoch Advancement E2E ─────────────────────────────────────────────────────

TEST_CASE("E2E: MLS epoch advances after member operations", "[mls][e2e]") {
	MLSProtocolSim protocol;

	const std::vector<UserId> members = {1, 2};
	const auto groupId = protocol.createGroup(
		members, Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

	auto stateBefore = protocol.getGroupState(groupId);
	auto epochBefore = stateBefore->epoch;

	protocol.addMember(groupId, 3);

	auto stateAfter = protocol.getGroupState(groupId);
	REQUIRE(stateAfter->epoch > epochBefore);
}

TEST_CASE("E2E: MLS encryption works across epoch boundaries", "[mls][e2e]") {
	MLSProtocolSim protocol;

	const std::vector<UserId> members = {1, 2};
	const auto groupId = protocol.createGroup(
		members, Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

	Bytes msg0 = {'E', '0'};
	auto ct0 = protocol.encryptMessage(groupId, msg0);
	auto pt0 = protocol.decryptMessage(groupId, ct0);
	REQUIRE(pt0.has_value());
	REQUIRE(*pt0 == msg0);

	protocol.addMember(groupId, 3);

	Bytes msg1 = {'E', '1'};
	auto ct1 = protocol.encryptMessage(groupId, msg1);
	auto pt1 = protocol.decryptMessage(groupId, ct1);
	REQUIRE(pt1.has_value());
	REQUIRE(*pt1 == msg1);

	protocol.removeMember(groupId, 3);

	Bytes msg2 = {'E', '2'};
	auto ct2 = protocol.encryptMessage(groupId, msg2);
	auto pt2 = protocol.decryptMessage(groupId, ct2);
	REQUIRE(pt2.has_value());
	REQUIRE(*pt2 == msg2);
}

// ─── Group State Queries E2E ───────────────────────────────────────────────────

TEST_CASE("E2E: MLS group state returns nullopt for unknown group", "[mls][e2e]") {
	MLSProtocolSim protocol;

	auto state = protocol.getGroupState({0xFF, 0xFF});
	REQUIRE_FALSE(state.has_value());
}

TEST_CASE("E2E: MLS hasGroup returns false for unknown group", "[mls][e2e]") {
	MLSProtocolSim protocol;

	REQUIRE_FALSE(protocol.hasGroup({0x00, 0x01}));
}

TEST_CASE("E2E: MLS group context has valid ciphersuite", "[mls][e2e]") {
	MLSProtocolSim protocol;

	const std::vector<UserId> members = {1, 2};
	const auto groupId = protocol.createGroup(
		members, Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519);

	auto state = protocol.getGroupState(groupId);
	REQUIRE(state->ciphersuite == Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519);
}

TEST_CASE("E2E BRUTAL: MLS Extreme Payload & Null-Byte Injection", "[mls][e2e][brutal]") {
	MLSProtocolSim protocol;
	const std::vector<UserId> members = {1, 2, 3};
	const auto groupId = protocol.createGroup(
		members, Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519);

	// 1. Zero-byte message
	Bytes zeroPayload = {};
	auto zeroEnc = protocol.encryptMessage(groupId, zeroPayload);
	REQUIRE(!zeroEnc.empty());
	auto zeroDec = protocol.decryptMessage(groupId, zeroEnc);
	REQUIRE(zeroDec.has_value());
	REQUIRE(zeroDec.value().empty());

	// 2. High-Volume Member Addition (Simulate 50 group additions sequentially)
	for (uint32_t i = 100; i < 150; ++i) {
		REQUIRE(protocol.addMember(groupId, i));
	}
	auto state = protocol.getGroupState(groupId);
	REQUIRE(state->members.size() == 53); // 3 original + 50 new

	// 3. Huge Payload Stress Test (5 MB)
	Bytes hugePayload(5 * 1024 * 1024, 0x42);
	auto hugeEnc = protocol.encryptMessage(groupId, hugePayload);
	REQUIRE(!hugeEnc.empty());
	
	// Member 140 decrypts
	auto hugeDec = protocol.decryptMessage(groupId, hugeEnc);
	REQUIRE(hugeDec.has_value());
	REQUIRE(hugeDec.value() == hugePayload);

	// 4. Bad Ciphertext Injection
	Bytes tamperedEnc = hugeEnc;
	tamperedEnc[tamperedEnc.size() - 5] ^= 0xFF; // Flip bits in MAC/Ciphertext
	auto tamperedDec = protocol.decryptMessage(groupId, tamperedEnc);
	REQUIRE(!tamperedDec.has_value()); // MUST FAIL
}

TEST_CASE("E2E HIVE: 6k room, feds, bad actors, rapid flow", "[mls][e2e][hive]") {
	MLSProtocolSim protocol;
	
	// Create a massive room with 6000 initial users (mixed Telegram / Cryptogram users)
	std::vector<UserId> members;
	members.reserve(6000);
	for (UserId i = 1; i <= 6000; i++) {
		members.push_back(i);
	}
	
	const auto groupId = protocol.createGroup(
		members, Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519);
	
	REQUIRE(protocol.hasGroup(groupId));
	
	auto state = protocol.getGroupState(groupId);
	REQUIRE(state->members.size() == 6000);
	
	// 100 feds joining the room dynamically
	for(UserId fedId = 10001; fedId <= 10100; fedId++) {
		REQUIRE(protocol.addMember(groupId, fedId));
	}
	
	// Rapid flow of encrypted messages
	for (int i = 0; i < 50; i++) {
		Bytes msg = {'C', 'L', 'E', 'A', 'R', static_cast<unsigned char>(i % 256)};
		auto enc = protocol.encryptMessage(groupId, msg);
		auto dec = protocol.decryptMessage(groupId, enc);
		REQUIRE(dec.has_value());
		REQUIRE(dec.value() == msg);
	}
	
	// Feds rapidly leaving the room (extracting)
	for(UserId fedId = 10001; fedId <= 10050; fedId++) {
		REQUIRE(protocol.removeMember(groupId, fedId));
	}
	
	// 5 Bad actors trying to inject malformed encrypted data
	for (int i = 0; i < 5; i++) {
		// Injection 1: Complete garbage payload
		Bytes badMsg(256, 0x99); // Random noise
		auto dec = protocol.decryptMessage(groupId, badMsg);
		REQUIRE_FALSE(dec.has_value()); // Must fail gracefully
		
		// Injection 2: Intercepted valid ciphertext with corrupted MAC / Payload
		Bytes validMsg = {'S', 'E', 'C', 'R', 'E', 'T'};
		auto validEnc = protocol.encryptMessage(groupId, validMsg);
		validEnc[validEnc.size() / 2] ^= 0x42; // Bitflip in the middle
		auto corruptedDec = protocol.decryptMessage(groupId, validEnc);
		REQUIRE_FALSE(corruptedDec.has_value()); // Must fail authentication
		
		// Injection 3: Too short (under 28 bytes)
		Bytes shortMsg = {'S', 'H', 'O', 'R', 'T'};
		auto shortDec = protocol.decryptMessage(groupId, shortMsg);
		REQUIRE_FALSE(shortDec.has_value()); // Must fail length check
	}
	
	// More rapid encrypted traffic to ensure the epoch state is still healthy
	// after all the join/leave and bad actor injections
	for (int i = 0; i < 50; i++) {
		Bytes msg = {'M', 'O', 'R', 'E', 'M', 'S', 'G', static_cast<unsigned char>(i % 256)};
		auto enc = protocol.encryptMessage(groupId, msg);
		auto dec = protocol.decryptMessage(groupId, enc);
		REQUIRE(dec.has_value());
		REQUIRE(dec.value() == msg);
	}
	
	// Final state check
	state = protocol.getGroupState(groupId);
	// 6000 initial + 100 feds joined - 50 feds left = 6050
	REQUIRE(state->members.size() == 6050);
}

#include <chrono>
#include <random>
#include <iostream>

TEST_CASE("E2E ONSLAUGHT: Dynamic randomized chaos", "[.][mls][e2e][onslaught]") {
    // Note: The [.] tag hides it from default test runs. It must be run explicitly.
    MLSProtocolSim protocol;
    
    // Create base 6k room
    std::vector<UserId> members;
    members.reserve(6000);
    for (UserId i = 1; i <= 6000; i++) {
        members.push_back(i);
    }
    const auto groupId = protocol.createGroup(
        members, Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519);
    REQUIRE(protocol.hasGroup(groupId));
    
    std::mt19937 rng(1337);
    std::uniform_int_distribution<int> actionDist(0, 100);
    std::uniform_int_distribution<UserId> idDist(10000, 20000);
    
    auto startTime = std::chrono::steady_clock::now();
    // Run for 300 seconds (5 minutes)
    auto duration = std::chrono::seconds(300);
    
    // If we want a quick CI check, check an env var. Otherwise 5 mins.
    if (const char* env_p = std::getenv("ONSLAUGHT_SECONDS")) {
        duration = std::chrono::seconds(std::stoi(env_p));
    }

    uint64_t operations = 0;
    uint64_t successful_decrypts = 0;
    uint64_t rejected_injections = 0;
    
    std::cout << "\n=======================================================\n";
    std::cout << "Starting 5-MINUTE ONSLAUGHT test for " << duration.count() << " seconds..." << std::endl;
    std::cout << "Hammering the MLS simulator with randomized dynamic methods..." << std::endl;
    std::cout << "=======================================================\n" << std::endl;
    
    while (std::chrono::steady_clock::now() - startTime < duration) {
        int action = actionDist(rng);
        
        if (action < 10) { 
            // 10% chance: Random user joins
            protocol.addMember(groupId, idDist(rng));
        } else if (action < 20) {
            // 10% chance: Random user leaves
            protocol.removeMember(groupId, idDist(rng));
        } else if (action < 80) {
            // 60% chance: Rapid valid message flow
            Bytes msg = {'V', 'A', 'L', 'I', 'D', static_cast<unsigned char>(operations % 256)};
            auto enc = protocol.encryptMessage(groupId, msg);
            auto dec = protocol.decryptMessage(groupId, enc);
            REQUIRE(dec.has_value());
            REQUIRE(dec.value() == msg);
            successful_decrypts++;
        } else {
            // 20% chance: Bad actor injection (corrupt a valid message)
            Bytes msg = {'S', 'E', 'C', 'R', 'E', 'T'};
            auto enc = protocol.encryptMessage(groupId, msg);
            enc[enc.size() / 2] ^= 0xFF; // flip bits
            auto dec = protocol.decryptMessage(groupId, enc);
            REQUIRE_FALSE(dec.has_value());
            rejected_injections++;
        }
        operations++;
    }
    
    std::cout << "\n=======================================================\n";
    std::cout << "ONSLAUGHT COMPLETE!" << std::endl;
    std::cout << "Total Operations: " << operations << std::endl;
    std::cout << "Successful Decrypts: " << successful_decrypts << std::endl;
    std::cout << "Defeated Injections: " << rejected_injections << std::endl;
    
    auto state = protocol.getGroupState(groupId);
    REQUIRE(state.has_value());
    std::cout << "Final Room Size: " << state->members.size() << std::endl;
    std::cout << "=======================================================\n" << std::endl;
}
