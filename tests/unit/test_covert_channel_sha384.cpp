// Conformance for the covert-channel packet-authentication chain
// (data_covert_channel.cpp after the CNSA 2.0 alignment):
//   - UNIFORM, level-gated chains. Quantum security level >= 3 (CNSA 2.0
//     tier) upgrades the WHOLE chain to SHA-384: HKDF-SHA384 with a
//     48-byte derived key and HMAC-SHA-384 over a 128-byte block, producing
//     a 48-byte tag. Levels 1-2 keep the legacy uniform SHA-256 chain:
//     HKDF-SHA256, 32-byte key, 64-byte block, 32-byte tag. The digests
//     are never mixed inside one chain.
//   - HKDF is EXTRACT_AND_EXPAND from the 32-byte random session key with
//     info "CovertChannel-PacketMAC". The digest parameter is ALWAYS set —
//     omitting it silently yields zero-filled output on OpenSSL 3.x.
//   - Packet MAC input = seq(4, LE) || total(4, LE) || payload, mirroring
//     the memcpy-based serialization in CovertChannel::createPacket
//     (native little-endian on the platforms this project targets).
//   - The wire tag length equals the chain digest size (32 or 48 bytes),
//     mirroring CovertChannel::signatureSize.

#include <catch2/catch_test_macros.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<unsigned char>;

constexpr auto kInfoLabel = "CovertChannel-PacketMAC";

struct ChainParams {
	const char *digestName; // OpenSSL name for EVP_KDF "digest" param
	const EVP_MD *(*md)();  // matching EVP digest getter
	size_t derivedKeySize;  // HKDF output length L
	size_t hmacBlockSize;   // RFC 2104 block: 64 (SHA-256) / 128 (SHA-384)
	size_t tagSize;         // HMAC output length on the wire
};

// Mirrors CovertChannel::useCnsa20Chain / derivePacketSigningKey gating:
// level >= 3 selects the SHA-384 chain, everything below stays SHA-256.
ChainParams chainParamsForLevel(int level) {
	if (level >= 3) {
		return { "SHA384", &EVP_sha384, 48, 128, 48 };
	}
	return { "SHA256", &EVP_sha256, 32, 64, 32 };
}

Bytes hkdfDerive(
		const Bytes &ikm,
		const std::string &info,
		const ChainParams &params) {
	EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
	REQUIRE(kdf != nullptr);
	EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
	EVP_KDF_free(kdf);
	REQUIRE(ctx != nullptr);

	int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
	OSSL_PARAM params5[5];
	params5[0] = OSSL_PARAM_construct_int("mode", &mode);
	// The digest MUST be set even in EXTRACT_AND_EXPAND mode — omitting it
	// silently produces zero-filled output on OpenSSL 3.x.
	params5[1] = OSSL_PARAM_construct_utf8_string(
		"digest",
		const_cast<char *>(params.digestName),
		0);
	params5[2] = OSSL_PARAM_construct_octet_string(
		"key",
		const_cast<void *>(static_cast<const void *>(ikm.data())),
		ikm.size());
	params5[3] = OSSL_PARAM_construct_octet_string(
		"info",
		const_cast<void *>(static_cast<const void *>(info.data())),
		info.size());
	params5[4] = OSSL_PARAM_construct_end();

	Bytes out(params.derivedKeySize);
	const int rc = EVP_KDF_derive(ctx, out.data(), out.size(), params5);
	EVP_KDF_CTX_free(ctx);
	REQUIRE(rc == 1);
	return out;
}

// Plain one-shot hash (NOT HMAC) — used for the RFC 2104 inner/outer
// hashing, exactly like QCryptographicHash::hash in computeHMAC.
Bytes plainHash(const Bytes &input, const ChainParams &params) {
	unsigned int len = 0;
	Bytes digest(EVP_MAX_MD_SIZE);
	REQUIRE(EVP_Digest(
		input.data(),
		input.size(),
		digest.data(),
		&len,
		params.md(),
		nullptr) == 1);
	digest.resize(len);
	return digest;
}

// The manual full RFC 2104 construction used by data_covert_channel.cpp:
// H((K ^ opad) || H((K ^ ipad) || m)) with the chain's block size.
Bytes hmacManual(
		const Bytes &key,
		const Bytes &data,
		const ChainParams &params) {
	const size_t blockSize = params.hmacBlockSize;
	Bytes k = key;
	if (k.size() > blockSize) {
		k = plainHash(k, params); // RFC 2104: long keys are hashed first
	}
	k.resize(blockSize, 0x00);

	Bytes ipad(blockSize, 0x36);
	Bytes opad(blockSize, 0x5c);
	for (size_t i = 0; i < blockSize; ++i) {
		ipad[i] ^= k[i];
		opad[i] ^= k[i];
	}

	Bytes innerInput = ipad;
	innerInput.insert(innerInput.end(), data.begin(), data.end());
	const Bytes inner = plainHash(innerInput, params);

	Bytes outerInput = opad;
	outerInput.insert(outerInput.end(), inner.begin(), inner.end());
	return plainHash(outerInput, params);
}

// OpenSSL's own HMAC — the cross-check that the manual construction and
// its block-size handling are correct.
Bytes hmacOneShot(
		const Bytes &key,
		const Bytes &data,
		const ChainParams &params) {
	unsigned int len = 0;
	Bytes out(EVP_MAX_MD_SIZE);
	REQUIRE(HMAC(
		params.md(),
		key.data(),
		int(key.size()),
		data.data(),
		data.size(),
		out.data(),
		&len) != nullptr);
	out.resize(len);
	return out;
}

// Mirrors CovertChannel::createPacket: seq || total || payload signed.
Bytes packetMacInput(
		uint32_t sequence,
		uint32_t total,
		const Bytes &payload) {
	Bytes out;
	out.reserve(8 + payload.size());
	const auto appendU32 = [&](uint32_t v) {
		out.push_back(uint8_t(v & 0xff));
		out.push_back(uint8_t((v >> 8) & 0xff));
		out.push_back(uint8_t((v >> 16) & 0xff));
		out.push_back(uint8_t((v >> 24) & 0xff));
	};
	appendU32(sequence);
	appendU32(total);
	out.insert(out.end(), payload.begin(), payload.end());
	return out;
}

Bytes signPacket(
		const Bytes &key,
		uint32_t sequence,
		uint32_t total,
		const Bytes &payload,
		const ChainParams &params) {
	return hmacManual(
		key,
		packetMacInput(sequence, total, payload),
		params);
}

bool verifyPacket(
		const Bytes &key,
		uint32_t sequence,
		uint32_t total,
		const Bytes &payload,
		const Bytes &tag,
		const ChainParams &params) {
	const auto expected = signPacket(key, sequence, total, payload, params);
	if (expected.size() != tag.size()) {
		return false;
	}
	uint8_t diff = 0;
	for (size_t i = 0; i < expected.size(); ++i) {
		diff |= expected[i] ^ tag[i];
	}
	return diff == 0;
}

Bytes randomSessionKey() {
	Bytes key(32);
	REQUIRE(RAND_bytes(key.data(), int(key.size())) == 1);
	return key;
}

} // namespace

TEST_CASE("Covert channel SHA-384 packet-authentication chain", "[covert][sha384]") {
	const auto sessionKey = randomSessionKey();
	const Bytes payload = {
		'C', 'o', 'v', 'e', 'r', 't', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e',
	};

	SECTION("level gating selects the uniform chains") {
		const auto l1 = chainParamsForLevel(1);
		const auto l2 = chainParamsForLevel(2);
		const auto l3 = chainParamsForLevel(3);
		const auto l5 = chainParamsForLevel(5);

		REQUIRE(std::string(l1.digestName) == "SHA256");
		REQUIRE(l1.derivedKeySize == 32);
		REQUIRE(l1.hmacBlockSize == 64);
		REQUIRE(l1.tagSize == 32);

		REQUIRE(std::string(l2.digestName) == "SHA256");
		REQUIRE(l2.derivedKeySize == 32);

		REQUIRE(std::string(l3.digestName) == "SHA384");
		REQUIRE(l3.derivedKeySize == 48);
		REQUIRE(l3.hmacBlockSize == 128);
		REQUIRE(l3.tagSize == 48);

		REQUIRE(std::string(l5.digestName) == "SHA384");
		REQUIRE(l5.derivedKeySize == 48);
	}

	SECTION("CNSA 2.0 tier derives a 48-byte deterministic HKDF-SHA384 key") {
		const auto params = chainParamsForLevel(3);
		const auto key = hkdfDerive(sessionKey, kInfoLabel, params);
		REQUIRE(key.size() == 48);
		REQUIRE(std::any_of(
			key.begin(),
			key.end(),
			[](unsigned char c) { return c != 0; }));
		REQUIRE(key == hkdfDerive(sessionKey, kInfoLabel, params));
	}

	SECTION("HKDF digest parameter is honored (no zero-filled output)") {
		const auto params = chainParamsForLevel(3);
		const auto key = hkdfDerive(sessionKey, kInfoLabel, params);
		// Regression guard: a missing "digest" param on OpenSSL 3.x yields
		// all-zero HKDF output — this exact bug bit deriveKey before.
		REQUIRE(std::any_of(
			key.begin(),
			key.end(),
			[](unsigned char c) { return c != 0; }));
		// The info label is load-bearing: a different label derives a
		// different key.
		REQUIRE(key != hkdfDerive(sessionKey, "Other-Label", params));
	}

	SECTION("sign + verify roundtrip at the CNSA 2.0 tier") {
		const auto params = chainParamsForLevel(3);
		const auto key = hkdfDerive(sessionKey, kInfoLabel, params);
		REQUIRE(key.size() == 48);

		const auto tag = signPacket(key, 7, 3, payload, params);
		REQUIRE(tag.size() == 48);
		REQUIRE(verifyPacket(key, 7, 3, payload, tag, params));
	}

	SECTION("tampered packets fail verification at the CNSA 2.0 tier") {
		const auto params = chainParamsForLevel(3);
		const auto key = hkdfDerive(sessionKey, kInfoLabel, params);
		const auto tag = signPacket(key, 7, 3, payload, params);
		REQUIRE(tag.size() == 48);

		// Tampered payload
		auto badPayload = payload;
		badPayload[0] ^= 0x01;
		REQUIRE_FALSE(verifyPacket(key, 7, 3, badPayload, tag, params));

		// Tampered tag
		auto badTag = tag;
		badTag[0] ^= 0x01;
		REQUIRE_FALSE(verifyPacket(key, 7, 3, payload, badTag, params));

		// Wrong sequence number
		REQUIRE_FALSE(verifyPacket(key, 6, 3, payload, tag, params));

		// Wrong total
		REQUIRE_FALSE(verifyPacket(key, 7, 2, payload, tag, params));
	}

	SECTION("legacy tier (level < 3) keeps the SHA-256 chain self-consistent") {
		for (const int level : { 1, 2 }) {
			const auto params = chainParamsForLevel(level);
			REQUIRE(std::string(params.digestName) == "SHA256");

			const auto key = hkdfDerive(sessionKey, kInfoLabel, params);
			REQUIRE(key.size() == 32);

			const auto tag = signPacket(key, 0, 1, payload, params);
			REQUIRE(tag.size() == 32);
			REQUIRE(verifyPacket(key, 0, 1, payload, tag, params));
			REQUIRE_FALSE(verifyPacket(key, 1, 1, payload, tag, params));
			REQUIRE_FALSE(verifyPacket(key, 0, 1, { 'x' }, tag, params));
		}
	}

	SECTION("chains are uniform — SHA-256 and SHA-384 never mix") {
		const auto sha384 = chainParamsForLevel(3);
		const auto sha256 = chainParamsForLevel(1);

		const auto key384 = hkdfDerive(sessionKey, kInfoLabel, sha384);
		const auto key256 = hkdfDerive(sessionKey, kInfoLabel, sha256);
		REQUIRE(key384.size() == 48);
		REQUIRE(key256.size() == 32);
		// Different digests derive different keys from the same session key.
		REQUIRE(key384 != key256);

		// A legacy tag never verifies under the CNSA 2.0 tier and vice
		// versa — the tier split is deliberate and detectable.
		const auto tag256 = signPacket(key256, 0, 1, payload, sha256);
		REQUIRE_FALSE(
			verifyPacket(key384, 0, 1, payload, tag256, sha384));
		const auto tag384 = signPacket(key384, 0, 1, payload, sha384);
		REQUIRE_FALSE(
			verifyPacket(key256, 0, 1, payload, tag384, sha256));
	}

	SECTION("manual RFC 2104 construction matches OpenSSL HMAC (both digests)") {
		const Bytes data = packetMacInput(9, 4, payload);
		for (const int level : { 1, 3 }) {
			const auto params = chainParamsForLevel(level);
			const auto key = hkdfDerive(sessionKey, kInfoLabel, params);
			REQUIRE(hmacManual(key, data, params)
				== hmacOneShot(key, data, params));

			// Exercise the key-longer-than-block path (hashed first):
			// 96 > 64 for SHA-256 and 144 > 128 for SHA-384.
			Bytes longKey = key;
			longKey.insert(longKey.end(), key.begin(), key.end());
			longKey.insert(longKey.end(), key.begin(), key.end());
			REQUIRE(longKey.size() > params.hmacBlockSize);
			REQUIRE(hmacManual(longKey, data, params)
				== hmacOneShot(longKey, data, params));
		}
	}
}
