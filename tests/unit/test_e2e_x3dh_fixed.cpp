// Cross-side conformance for the FIXED X3DH + Double Ratchet spec
// (data_signal_protocol.cpp after the identity-leg fix):
//   - DH1/DH3 use a dedicated X25519 identity (NOT the Ed25519 bundle
//     identity, whose seed is not the X25519 scalar matching its public —
//     the pre-fix construction provably produced non-agreeing secrets).
//   - HKDF is EXPAND-ONLY with the input as PRK (desktop deriveKey).
//   - Infos: "CryptogramX3DH", "CryptogramKDF_RK", "WhisperMessageKeys",
//     "WhisperMessageKey".
//   - KDF_RK(RK, dhOut) = expand(PRK=RK||dhOut, info="CryptogramKDF_RK", 64)
//     → [0:32] new root, [32:64] chain.
//   - Chain ratchet = HMAC-SHA256(chain, 0x01).
//   - Message key = expand(chain, "WhisperMessageKey", 32).
//   - AAD = u32be(counter) || senderDHPub.
//   - Symmetric chain-init: expand(RK', "WhisperMessageKeys", 32) is
//     Alice's RECEIVING chain and Bob's SENDING chain.

#include <catch2/catch_test_macros.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <cstring>
#include <stdexcept>
#include <vector>

namespace {

using Bytes = std::vector<unsigned char>;

Bytes x25519PublicFromPrivate(const Bytes &priv) {
	EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
		EVP_PKEY_X25519, nullptr, priv.data(), priv.size());
	REQUIRE(pkey != nullptr);
	Bytes pub(32);
	size_t len = 32;
	REQUIRE(EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len) == 1);
	EVP_PKEY_free(pkey);
	return pub;
}

std::pair<Bytes, Bytes> generateX25519() {
	EVP_PKEY *pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
	REQUIRE(pkey != nullptr);
	Bytes priv(32), pub(32);
	size_t privLen = 32, pubLen = 32;
	REQUIRE(EVP_PKEY_get_raw_private_key(pkey, priv.data(), &privLen) == 1);
	REQUIRE(EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pubLen) == 1);
	EVP_PKEY_free(pkey);
	return {priv, pub};
}

Bytes dhCompute(const Bytes &priv, const Bytes &pub) {
	EVP_PKEY *a = EVP_PKEY_new_raw_private_key(
		EVP_PKEY_X25519, nullptr, priv.data(), priv.size());
	EVP_PKEY *b = EVP_PKEY_new_raw_public_key(
		EVP_PKEY_X25519, nullptr, pub.data(), pub.size());
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(a, nullptr);
	REQUIRE(ctx != nullptr);
	Bytes out(32);
	size_t len = 32;
	REQUIRE(EVP_PKEY_derive_init(ctx) == 1);
	REQUIRE(EVP_PKEY_derive_set_peer(ctx, b) == 1);
	REQUIRE(EVP_PKEY_derive(ctx, out.data(), &len) == 1);
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(a);
	EVP_PKEY_free(b);
	return out;
}

// Desktop deriveKey(): HKDF EXPAND-ONLY, input used directly as PRK.
Bytes hkdfExpandOnly(const Bytes &prk, const std::string &info, size_t len) {
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
	REQUIRE(pctx != nullptr);
	REQUIRE(EVP_PKEY_derive_init(pctx) > 0);
	REQUIRE(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) > 0);
	REQUIRE(EVP_PKEY_CTX_set_hkdf_mode(
		pctx, EVP_KDF_HKDF_MODE_EXPAND_ONLY) > 0);
	REQUIRE(EVP_PKEY_CTX_set1_hkdf_key(
		pctx, prk.data(), int(prk.size())) > 0);
	REQUIRE(EVP_PKEY_CTX_add1_hkdf_info(
		pctx, reinterpret_cast<const unsigned char *>(info.data()),
		int(info.size())) > 0);
	Bytes out(len);
	size_t outLen = len;
	REQUIRE(EVP_PKEY_derive(pctx, out.data(), &outLen) > 0);
	EVP_PKEY_CTX_free(pctx);
	out.resize(outLen);
	return out;
}

Bytes hmacSha256(const Bytes &key, const Bytes &data) {
	Bytes out(EVP_MAX_MD_SIZE);
	unsigned int outLen = 0;
	REQUIRE(HMAC(
		EVP_sha256(),
		key.data(), int(key.size()),
		data.data(), data.size(),
		out.data(), &outLen) != nullptr);
	out.resize(outLen);
	return out;
}

struct KdfRkResult {
	Bytes rootKey;
	Bytes chainKey;
};

KdfRkResult kdfRk(const Bytes &rootKey, const Bytes &dhOutput) {
	Bytes combined = rootKey;
	combined.insert(combined.end(), dhOutput.begin(), dhOutput.end());
	auto derived = hkdfExpandOnly(combined, "CryptogramKDF_RK", 64);
	REQUIRE(derived.size() == 64);
	return {
		Bytes(derived.begin(), derived.begin() + 32),
		Bytes(derived.begin() + 32, derived.end()),
	};
}

Bytes ratchetChainKey(const Bytes &chainKey) {
	return hmacSha256(chainKey, {0x01});
}

Bytes messageKey(const Bytes &chainKey) {
	return hkdfExpandOnly(chainKey, "WhisperMessageKey", 32);
}

Bytes aesGcmEncrypt(
		const Bytes &key,
		const Bytes &iv,
		const Bytes &plaintext,
		const Bytes &aad) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	REQUIRE(ctx != nullptr);
	REQUIRE(EVP_EncryptInit_ex(
		ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) == 1);
	int aadLen = 0;
	REQUIRE(EVP_EncryptUpdate(
		ctx, nullptr, &aadLen, aad.data(), int(aad.size())) == 1);
	Bytes out(plaintext.size() + 16);
	int len = 0;
	REQUIRE(EVP_EncryptUpdate(
		ctx, out.data(), &len, plaintext.data(), int(plaintext.size())) == 1);
	int total = len;
	REQUIRE(EVP_EncryptFinal_ex(ctx, out.data() + total, &len) == 1);
	total += len;
	REQUIRE(EVP_CIPHER_CTX_ctrl(
		ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + total) == 1);
	EVP_CIPHER_CTX_free(ctx);
	out.resize(size_t(total) + 16);
	return out;
}

Bytes aesGcmDecrypt(
		const Bytes &key,
		const Bytes &iv,
		const Bytes &ciphertextWithTag,
		const Bytes &aad) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	REQUIRE(ctx != nullptr);
	REQUIRE(EVP_DecryptInit_ex(
		ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) == 1);
	int dLen = 0;
	REQUIRE(EVP_DecryptUpdate(
		ctx, nullptr, &dLen, aad.data(), int(aad.size())) == 1);
	const auto ctLen = ciphertextWithTag.size() - 16;
	Bytes plaintext(ctLen);
	int updateLen = 0;
	if (ctLen > 0) {
		REQUIRE(EVP_DecryptUpdate(
			ctx, plaintext.data(), &updateLen,
			ciphertextWithTag.data(), int(ctLen)) == 1);
	}
	REQUIRE(EVP_CIPHER_CTX_ctrl(
		ctx, EVP_CTRL_GCM_SET_TAG, 16,
		const_cast<unsigned char *>(
			ciphertextWithTag.data() + ctLen)) == 1);
	int finalLen = 0;
	if (EVP_DecryptFinal_ex(
			ctx, plaintext.data() + updateLen, &finalLen) != 1) {
		// Authentication failure must be observable to callers (the
		// tamper test relies on it throwing).
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("aes-gcm authentication failed");
	}
	EVP_CIPHER_CTX_free(ctx);
	// Final overwrites len with its own (zero for GCM) output length —
	// resize to update+final, NOT to the post-Final value.
	plaintext.resize(size_t(updateLen + finalLen));
	return plaintext;
}

Bytes aadFor(uint32_t counter, const Bytes &senderDhPub) {
	Bytes aad = {
		static_cast<unsigned char>((counter >> 24) & 0xFF),
		static_cast<unsigned char>((counter >> 16) & 0xFF),
		static_cast<unsigned char>((counter >> 8) & 0xFF),
		static_cast<unsigned char>(counter & 0xFF),
	};
	aad.insert(aad.end(), senderDhPub.begin(), senderDhPub.end());
	return aad;
}

template <size_t N>
Bytes strTo(const char (&s)[N]) {
	return Bytes(s, s + N - 1);
}

struct Side {
	Bytes rootKey;
	Bytes sendingChainKey;
	Bytes receivingChainKey;
	Bytes dhSendingPrivate;
	Bytes dhSendingPublic;
	Bytes dhRemotePublic;
	uint32_t sendingCounter = 0;
	uint32_t receivingCounter = 0;

	Bytes encrypt(const Bytes &plaintext) {
		auto key = messageKey(sendingChainKey);
		sendingChainKey = ratchetChainKey(sendingChainKey);
		Bytes iv(12);
		REQUIRE(RAND_bytes(iv.data(), 12) == 1);
		const auto aad = aadFor(sendingCounter, dhSendingPublic);
		auto ct = aesGcmEncrypt(key, iv, plaintext, aad);
		++sendingCounter;
		// Wire envelope: counter || dhPub || iv || ct||tag
		Bytes wire = aad;
		wire.insert(wire.end(), iv.begin(), iv.end());
		wire.insert(wire.end(), ct.begin(), ct.end());
		return wire;
	}

	Bytes decrypt(const Bytes &wire) {
		const uint32_t counter = (uint32_t(wire[0]) << 24)
			| (uint32_t(wire[1]) << 16)
			| (uint32_t(wire[2]) << 8)
			| uint32_t(wire[3]);
		Bytes senderDhPub(wire.begin() + 4, wire.begin() + 36);

		// DH ratchet on remote key change (mirrors desktop decryptMessage).
		if (senderDhPub != dhRemotePublic) {
			auto [newPriv, newPub] = generateX25519();
			dhSendingPrivate = newPriv;
			dhSendingPublic = newPub;
			dhRemotePublic = senderDhPub;
			auto dh1 = dhCompute(dhSendingPrivate, dhRemotePublic);
			auto rk1 = kdfRk(rootKey, dh1);
			rootKey = rk1.rootKey;
			receivingChainKey = rk1.chainKey;
			auto dh2 = dhCompute(dhSendingPrivate, dhRemotePublic);
			auto rk2 = kdfRk(rootKey, dh2);
			rootKey = rk2.rootKey;
			sendingChainKey = rk2.chainKey;
			sendingCounter = 0;
			receivingCounter = 0;
		}

		REQUIRE(counter == receivingCounter);
		auto key = messageKey(receivingChainKey);
		receivingChainKey = ratchetChainKey(receivingChainKey);
		++receivingCounter;

		Bytes iv(wire.begin() + 36, wire.begin() + 48);
		Bytes ct(wire.begin() + 48, wire.end());
		return aesGcmDecrypt(key, iv, ct, aadFor(counter, senderDhPub));
	}
};

// The fixed X3DH: separate X25519 identity for DH legs; both sides derive
// identical root/chains. Returns fully-established Alice and Bob sides.
std::pair<Side, Side> establish() {
	auto [xidAPriv, xidAPub] = generateX25519();   // Alice X25519 identity
	auto [ekAPriv, ekAPub] = generateX25519();     // Alice ephemeral
	auto [xidBPriv, xidBPub] = generateX25519();   // Bob X25519 identity
	auto [spkBPriv, spkBPub] = generateX25519();   // Bob signed pre-key
	auto [opkBPriv, opkBPub] = generateX25519();   // Bob one-time pre-key

	// Alice (initiator)
	Bytes dh1 = dhCompute(xidAPriv, spkBPub);
	Bytes dh2 = dhCompute(ekAPriv, spkBPub);
	Bytes dh3 = dhCompute(xidAPriv, opkBPub);
	Bytes dh4 = dhCompute(ekAPriv, opkBPub);
	Bytes combined;
	combined.insert(combined.end(), dh1.begin(), dh1.end());
	combined.insert(combined.end(), dh2.begin(), dh2.end());
	combined.insert(combined.end(), dh3.begin(), dh3.end());
	combined.insert(combined.end(), dh4.begin(), dh4.end());
	auto rk0 = hkdfExpandOnly(combined, "CryptogramX3DH", 32);
	auto rkA = kdfRk(rk0, dh4);

	// Bob (resolver)
	Bytes bdh1 = dhCompute(spkBPriv, xidAPub);
	Bytes bdh2 = dhCompute(spkBPriv, ekAPub);
	Bytes bdh3 = dhCompute(opkBPriv, xidAPub);
	Bytes bdh4 = dhCompute(opkBPriv, ekAPub);
	Bytes bcombined;
	bcombined.insert(bcombined.end(), bdh1.begin(), bdh1.end());
	bcombined.insert(bcombined.end(), bdh2.begin(), bdh2.end());
	bcombined.insert(bcombined.end(), bdh3.begin(), bdh3.end());
	bcombined.insert(bcombined.end(), bdh4.begin(), bdh4.end());
	auto brk0 = hkdfExpandOnly(bcombined, "CryptogramX3DH", 32);
	auto rkB = kdfRk(brk0, bdh4);

	// The previously-broken agreement: roots must be identical.
	REQUIRE(rkA.rootKey == rkB.rootKey);

	// Symmetric chain-init
	auto chainInit = hkdfExpandOnly(rkA.rootKey, "WhisperMessageKeys", 32);

	Side alice;
	alice.rootKey = rkA.rootKey;
	alice.sendingChainKey = rkA.chainKey;
	alice.receivingChainKey = chainInit;
	alice.dhSendingPrivate = ekAPriv;
	alice.dhSendingPublic = ekAPub;
	alice.dhRemotePublic = spkBPub;

	Side bob;
	bob.rootKey = rkB.rootKey;
	bob.sendingChainKey = chainInit;
	bob.receivingChainKey = rkB.chainKey;
	bob.dhSendingPrivate = spkBPriv;
	bob.dhSendingPublic = spkBPub;
	bob.dhRemotePublic = ekAPub;

	return {alice, bob};
}

} // namespace

TEST_CASE("X3DH fixed spec: cross-side root agreement", "[e2e][x3dh]") {
	auto [alice, bob] = establish();
	REQUIRE(alice.rootKey == bob.rootKey);
	// Chain assignment: Alice sends on rkA.chainKey, Bob receives on it.
	REQUIRE(alice.sendingChainKey == bob.receivingChainKey);
	// Chain-init: Bob sends on it, Alice receives on it.
	REQUIRE(bob.sendingChainKey != Bytes(32, 0));
	REQUIRE(bob.sendingChainKey.size() == 32);
}

TEST_CASE("X3DH fixed spec: Alice→Bob then Bob→Alice roundtrips", "[e2e][x3dh]") {
	auto [alice, bob] = establish();
	REQUIRE(alice.rootKey == bob.rootKey);
	REQUIRE(alice.sendingChainKey == bob.receivingChainKey);

	auto m1 = alice.encrypt(strTo("first message from alice"));
	REQUIRE(bob.decrypt(m1) == strTo("first message from alice"));

	auto m2 = bob.encrypt(strTo("reply from bob"));
	REQUIRE(alice.decrypt(m2) == strTo("reply from bob"));

	auto m3 = alice.encrypt(strTo("second alice message"));
	REQUIRE(bob.decrypt(m3) == strTo("second alice message"));

	auto m4 = bob.encrypt(strTo("second bob message"));
	REQUIRE(alice.decrypt(m4) == strTo("second bob message"));
}

TEST_CASE("X3DH fixed spec: long message and tamper rejection", "[e2e][x3dh]") {
	auto [alice, bob] = establish();

	Bytes big(10240);
	for (size_t i = 0; i != big.size(); ++i) {
		big[i] = static_cast<unsigned char>(i & 0xFF);
	}
	auto wire = alice.encrypt(big);
	REQUIRE(bob.decrypt(wire) == big);

	// Replay guard fires first on a re-decrypt (ratchet counters), so
	// tamper rejection needs a fresh session.
	auto [alice2, bob2] = establish();
	auto wire2 = alice2.encrypt(big);
	wire2[wire2.size() - 20] ^= 0x80;
	REQUIRE_THROWS(bob2.decrypt(wire2));
}
TEST_CASE("X3DH fixed spec: debug wire", "[e2e][x3dh][.debug]") {
	auto [alice, bob] = establish();
	const bool rootEq = (alice.rootKey == bob.rootKey);
	const bool chainEq = (alice.sendingChainKey == bob.receivingChainKey);
	REQUIRE(rootEq);
	REQUIRE(chainEq);
	auto plaintext = strTo("first message from alice");
	auto wire = alice.encrypt(plaintext);
	REQUIRE(wire.size() == 4 + 32 + 12 + plaintext.size() + 16);
	REQUIRE(bob.dhRemotePublic == alice.dhSendingPublic);
	REQUIRE(bob.receivingCounter == 0);
	auto result = bob.decrypt(wire);
	REQUIRE(result.size() == plaintext.size());
	REQUIRE(result == plaintext);
}
