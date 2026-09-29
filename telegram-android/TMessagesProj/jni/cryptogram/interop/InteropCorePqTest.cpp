/*
 * CRYPTOGRAM Android — host test for the post-quantum (ML-KEM / PQE1) layer.
 *
 * HOST-ONLY: compiled directly with
 *   g++ -std=c++17 -I <jni>/cryptogram -lcrypto InteropCorePqTest.cpp
 *       InteropCore.cpp KemKeyStore.cpp
 * It is deliberately NOT part of any CMake target (the Android build must not
 * pick up its main()). Exercises the OpenSSL backend (provider-native ML-KEM
 * EVP keys) of InteropCore plus the KemKeyStore container; the BoringSSL
 * backend compiles against the same header contract and shares every
 * backend-independent code path (DER helpers, PQE1 framing, AES-GCM, store).
 *
 * Checks (PATH_1_ANDROID_MLKEM_PARITY gates 1 and 2):
 *   - ML-KEM-1024 identity generation + SPKI DER roundtrip (i2d_PUBKEY /
 *     d2i_PUBKEY) and the hand-built SPKI builder/parser cross-check
 *   - full Alice->Bob wrap/unwrap through importPeerKemRaw
 *   - envelope framing (magic, u32 LE encapsulated length, field order)
 *   - tamper rejection (encapsulated / iv / tag / ciphertext flips)
 *   - wrong private key -> different shared secret, unwrap failure
 *   - encrypted persistence roundtrip (KemKeyStore) incl. wrong password
 *   - key-bundle 0x02 advertisement roundtrip (encode/decode)
 *   - RFC 5869 A.1 known-answer check for the expand-only HKDF helper
 *
 * This file is part of CRYPTOGRAM Android
 * Licensed under GNU GPL v. 2 or later.
 */

#include "interop/InteropCore.h"
#include "interop/KemKeyStore.h"

#include <sys/stat.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

int gChecks = 0;
int gFailures = 0;

void check(bool condition, const char *label) {
    ++gChecks;
    if (condition) {
        std::printf("  [PASS] %s\n", label);
    } else {
        ++gFailures;
        std::printf("  [FAIL] %s\n", label);
    }
}

std::string hex(const interop::ByteVector &data) {
    static const char *digits = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (const auto byte : data) {
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 0x0F]);
    }
    return out;
}

} // namespace

int main() {
    std::printf("== InteropCore PQ (ML-KEM / PQE1) host test ==\n");

    // -------------------------------------------------------------------
    // 1. Identity generation
    // -------------------------------------------------------------------
    std::printf("[1] ML-KEM-1024 identity generation\n");
    const auto bob = interop::generateKemIdentity();
    check(bob.rawPublicKey.size() == interop::kMlKem1024PublicKeySize,
          "raw public key is 1568 bytes");
    check(!bob.publicKeyDer.empty(), "SPKI DER export succeeds");
    check(!bob.privateKeyBlob.empty(), "persist-capable private export succeeds");
    check(bob.publicKeyDer.size() > interop::kMlKem1024PublicKeySize,
          "SPKI DER larger than the raw key (DER framing present)");

    // -------------------------------------------------------------------
    // 2. Gate: SPKI DER roundtrip (OpenSSL i2d_PUBKEY / d2i_PUBKEY happens
    //    inside the backend; cross-checked here against the pure helpers)
    // -------------------------------------------------------------------
    std::printf("[2] SPKI DER roundtrip + pure DER helper cross-check\n");
    int parameterSet = 0;
    interop::ByteVector parsedRaw;
    check(interop::parseMlKemSpkiDer(bob.publicKeyDer, parameterSet, parsedRaw),
          "parseMlKemSpkiDer accepts the generated SPKI");
    check(parameterSet == interop::kMlKemParam1024, "SPKI parameter set is ML-KEM-1024");
    check(parsedRaw == bob.rawPublicKey, "parsed raw key matches the generated key");

    const auto rebuilt = interop::buildMlKemSpkiDer(interop::kMlKemParam1024, bob.rawPublicKey);
    check(rebuilt == bob.publicKeyDer,
          "hand-built SPKI is byte-identical to OpenSSL i2d_PUBKEY output");
    check(interop::buildMlKemSpkiDer(768, bob.rawPublicKey).empty(),
          "builder rejects a raw key that does not match the parameter set");
    auto truncated = bob.publicKeyDer;
    truncated.pop_back();
    check(!interop::parseMlKemSpkiDer(truncated, parameterSet, parsedRaw),
          "parser rejects a truncated SPKI");

    // -------------------------------------------------------------------
    // 3. Alice imports Bob's raw public and wraps; Bob unwraps
    // -------------------------------------------------------------------
    std::printf("[3] Alice->Bob PQE1 roundtrip via importPeerKemRaw\n");
    const auto alice = interop::generateKemIdentity();
    check(!alice.publicKeyDer.empty(), "second identity generation succeeds");

    const auto bobSpkiImported = interop::importPeerKemRaw(bob.rawPublicKey);
    check(bobSpkiImported == bob.publicKeyDer,
          "importPeerKemRaw raw->SPKI matches the generated SPKI");

    const interop::ByteVector message = {'P', 'Q', ' ', 'p', 'a', 'r', 'i', 't', 'y'};
    const auto encapsulation =
        interop::kemEncapsulate(bobSpkiImported);
    check(encapsulation.sharedSecret.size() == interop::kMlKemSharedSecretSize,
          "encapsulation shared secret is 32 bytes");
    check(encapsulation.ciphertext.size() == interop::kMlKem1024CiphertextSize,
          "encapsulation ciphertext is 1568 bytes");

    const auto direct = interop::kemDecapsulate(bob.privateKeyBlob, encapsulation.ciphertext);
    check(direct == encapsulation.sharedSecret,
          "decapsulation reproduces the shared secret");

    const auto wrapped = interop::wrapPqe1(bobSpkiImported, message);
    check(!wrapped.empty(), "wrapPqe1 succeeds");
    check(interop::isPqe1Envelope(wrapped), "PQE1 magic gate accepts the envelope");

    // -------------------------------------------------------------------
    // 4. Envelope framing — FROZEN desktop layout
    // -------------------------------------------------------------------
    std::printf("[4] PQE1 envelope framing\n");
    check(wrapped[0] == 'P' && wrapped[1] == 'Q' && wrapped[2] == 'E' && wrapped[3] == '1',
          "magic is \"PQE1\"");
    const uint32_t encapLen = static_cast<uint32_t>(wrapped[4])
        | (static_cast<uint32_t>(wrapped[5]) << 8)
        | (static_cast<uint32_t>(wrapped[6]) << 16)
        | (static_cast<uint32_t>(wrapped[7]) << 24);
    check(encapLen == interop::kMlKem1024CiphertextSize,
          "encapsulated length field (u32 little-endian) is 1568");
    check(wrapped.size() == 8 + encapLen + 12 + 16 + message.size(),
          "total envelope size matches the frozen layout");
    const auto unwrapped = interop::unwrapPqe1(bob.privateKeyBlob, wrapped);
    check(unwrapped == message, "unwrap reproduces the plaintext byte-for-byte");

    // -------------------------------------------------------------------
    // 5. Tamper rejection
    // -------------------------------------------------------------------
    std::printf("[5] Tamper rejection\n");
    const size_t encapStart = 8;
    const size_t ivStart = encapStart + encapLen;
    const size_t tagStart = ivStart + 12;
    const size_t ciphertextStart = tagStart + 16;
    auto tamperAndUnwrap = [&](size_t offset) {
        auto tampered = wrapped;
        tampered[offset] ^= 0x01;
        return interop::unwrapPqe1(bob.privateKeyBlob, tampered);
    };
    check(tamperAndUnwrap(encapStart).empty(),
          "flipped encapsulated-secret byte is rejected");
    check(tamperAndUnwrap(ivStart).empty(), "flipped IV byte is rejected");
    check(tamperAndUnwrap(tagStart).empty(), "flipped auth-tag byte is rejected");
    check(tamperAndUnwrap(ciphertextStart).empty(), "flipped ciphertext byte is rejected");
    check(interop::unwrapPqe1(bob.privateKeyBlob, message).empty(),
          "non-PQE1 payload is rejected");

    // -------------------------------------------------------------------
    // 6. Wrong private key
    // -------------------------------------------------------------------
    std::printf("[6] Wrong-key behaviour\n");
    const auto eve = interop::generateKemIdentity();
    const auto eveSecret =
        interop::kemDecapsulate(eve.privateKeyBlob, encapsulation.ciphertext);
    check(eveSecret.empty() || eveSecret != encapsulation.sharedSecret,
          "wrong private key never reproduces the shared secret");
    check(interop::unwrapPqe1(eve.privateKeyBlob, wrapped).empty(),
          "wrong private key fails the unwrap (GCM authentication)");

    // -------------------------------------------------------------------
    // 7. Encrypted persistence (KemKeyStore, desktop PBKDF2 parameters)
    // -------------------------------------------------------------------
    std::printf("[7] KemKeyStore encrypted persistence roundtrip\n");
    // The store creates the conventioned subdirectory only; the base
    // (filesDir on Android) always exists, so the test provides it.
    const std::string baseDir = "/tmp/cryptogram_pq_test";
    if (::mkdir(baseDir.c_str(), 0700) != 0 && errno != EEXIST) {
        std::printf("  [SKIP] cannot create test base directory\n");
    }
    const std::string storePath = baseDir + "/cryptogram/interop/pq_identity";
    const auto dir = interop::interopStoragePath(baseDir);
    check(dir == baseDir + "/cryptogram/interop",
          "interopStoragePath resolves <base>/cryptogram/interop");
    check(!dir.empty(), "interopStoragePath creates the directory");

    const std::string password = "test-wrapping-password";
    check(interop::saveKemIdentity(storePath, password, bob),
          "saveKemIdentity writes the store");
    interop::KemKeyPair restored;
    check(interop::loadKemIdentity(storePath, password, restored),
          "loadKemIdentity reads the store back");
    check(restored.privateKeyBlob == bob.privateKeyBlob,
          "private blob survives the store roundtrip");
    check(restored.publicKeyDer == bob.publicKeyDer,
          "SPKI DER survives the store roundtrip");
    check(interop::unwrapPqe1(restored.privateKeyBlob, wrapped) == message,
          "restored identity decrypts envelopes written before the save");
    check(!interop::loadKemIdentity(storePath, "wrong-password", restored),
          "wrong password is rejected");
    interop::KemKeyPair ignored;
    check(!interop::loadKemIdentity("/tmp/cryptogram_pq_test/missing", password, ignored),
          "missing store is rejected");

    // -------------------------------------------------------------------
    // 8. Key-bundle advertisement (bitmap 0x02)
    // -------------------------------------------------------------------
    std::printf("[8] Key-bundle 0x02 advertisement\n");
    interop::LocalIdentity aliceLocal;
    check(interop::generateLocalIdentity(aliceLocal), "local identity generation");
    auto bundle = interop::localKeyBundle(aliceLocal);
    bundle.quantumKemPublicKey = alice.publicKeyDer;
    const auto encoded = interop::encodeKeyBundle(bundle);
    check(!encoded.empty(), "encodeKeyBundle accepts a bundle with a KEM key");
    check((encoded[1] & interop::kBundleFlagQuantumKem) != 0, "bitmap advertises 0x02");
    interop::KeyBundle decoded;
    check(interop::decodeKeyBundle(encoded, decoded), "bundle decodes");
    check(decoded.quantumKemPublicKey == alice.publicKeyDer,
          "KEM public key survives the bundle roundtrip");

    // -------------------------------------------------------------------
    // 9. RFC 5869 A.1 known-answer check (expand-only HKDF helper)
    // -------------------------------------------------------------------
    std::printf("[9] HKDF-SHA256 expand-only known-answer (RFC 5869 A.1)\n");
    // PRK of Test Case 1 (the helper takes the PRK directly; expand-only).
    const std::string prkHex =
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5";
    const std::string infoHex = "f0f1f2f3f4f5f6f7f8f9";
    const std::string okmHex =
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865";
    auto fromHex = [](const std::string &value) {
        interop::ByteVector out;
        for (size_t i = 0; i + 1 < value.size(); i += 2) {
            out.push_back(
                static_cast<uint8_t>(std::stoul(value.substr(i, 2), nullptr, 16)));
        }
        return out;
    };
    const auto infoBytes = fromHex(infoHex);
    const std::string info(infoBytes.begin(), infoBytes.end());
    const auto okm = interop::hkdfExpandSha256(fromHex(prkHex), info, 42);
    check(hex(okm) == okmHex, "OKM matches RFC 5869 A.1");

    std::printf("\n== %d checks, %d failures ==\n", gChecks, gFailures);
    return gFailures == 0 ? 0 : 1;
}
