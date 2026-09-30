// Cross-side conformance for RATCHETED QUANTUM SESSIONS (envelope version 2)
// — the shared desktop (data_signal_protocol.cpp) / Android
// (InteropCore.{h,cpp}) spec:
//
// Establishment. ONE real KEM encapsulation against the peer's static KEM
//   public derives the quantum session:
//     qRoot = HKDF-EXPAND(PRK = ss,    info = "CryptogramQX3DH",    32)
//     initiator ("Alice"): qSend = expand(qRoot, "CryptogramQChainA", 32),
//                          qRecv = expand(qRoot, "CryptogramQChainB", 32)
//   (the resolver "Bob" swaps the A/B labels).
// Lockstep. One quantum message key per classic message:
//     qMessageKey = expand(PRK = qChain, info = "CryptogramQMessage",   32)
//     qChain      = expand(PRK = qChain, info = "CryptogramQChainStep", 32)
//   The quantum AEAD (AES-256-GCM) uses the SAME 12-byte IV and the SAME
//   AAD (u32be counter || senderDhPub) as the classic layer; the classic
//   ratchet encrypts the whole quantum-protected payload. Receive order:
//   classic decrypt first, quantum unwrap second; skipped quantum keys are
//   stored out-of-order exactly like the classic skippedMessageKeys.
// Transport. The kemCiphertext is transported ONCE — in the v2 envelope
//   metadata (hasQuantumInit) of the first quantum-protected message — and
//   subsequent messages carry NO new encapsulation. A fresh init on receive
//   re-establishes the session (restart recovery; replays fail closed).
// Envelope v2 (QDataStream Qt_5_15, all integers big-endian):
//   qint32 version(=2) | quint32 counter | QByteArray iv
//   | QByteArray senderPublicKey | qint32 timestamp
//   | bool hasCacChallenge [nonce] | bool hasCacResponse [sig, certChain]
//   | bool hasQuantumInit [QByteArray kemCiphertext,
//                          QByteArray kemEmitterPublic]
//   | QByteArray ciphertext
//   Legacy envelopes start at the counter; receivers route on the leading
//   int and fall back to the legacy parser when the v2 layout does not fit
//   (a legacy counter == 2 misroutes into the v2 parser but is structurally
//   rejected there because the legacy IV length prefix is random).
//
// KEM backend: real ML-KEM-1024 when the host OpenSSL provides it (>= 3.5),
// otherwise a KEM-shaped X25519 construction (encapsulate: fresh (epriv,
// epub), ss = X25519(epriv, pk), ct = epub; decapsulate: ss =
// X25519(priv, epub)) with the identical interface, so the protocol logic
// is fully exercised on any CI OpenSSL.

#include <catch2/catch_test_macros.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<unsigned char>;

// ---------------------------------------------------------------------------
// KEM abstraction (real ML-KEM-1024 when available, X25519-KEM otherwise)
// ---------------------------------------------------------------------------

struct KemKeyPair {
    Bytes privateKey; // decapsulate key
    Bytes publicKey;  // encapsulate key
};

struct KemEncapsulation {
    Bytes sharedSecret; // always 32 bytes
    Bytes ciphertext;
};

bool mlKemAvailable() {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-KEM-1024");
    if (!pkey) return false;
    EVP_PKEY_free(pkey);
    return true;
}

int kemKeyType() {
    return mlKemAvailable() ? NID_ML_KEM_1024 : EVP_PKEY_X25519;
}

KemKeyPair generateKemKeyPair() {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(
        nullptr, nullptr, mlKemAvailable() ? "ML-KEM-1024" : "X25519");
    REQUIRE(pkey != nullptr);
    KemKeyPair out;
    size_t pubLen = 0;
    REQUIRE(EVP_PKEY_get_raw_public_key(pkey, nullptr, &pubLen) == 1);
    out.publicKey.resize(pubLen);
    REQUIRE(EVP_PKEY_get_raw_public_key(
        pkey, out.publicKey.data(), &pubLen) == 1);
    // Private side travels as PKCS#8 DER: provider-native ML-KEM keys
    // REJECT EVP_PKEY_new_raw_private_key on host OpenSSL 3.x (returns
    // nullptr), while d2i_AutoPrivateKey works — the same reconstruction
    // the production InteropCore uses.
    PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(pkey);
    REQUIRE(p8 != nullptr);
    unsigned char *der = nullptr;
    const int derLen = i2d_PKCS8_PRIV_KEY_INFO(p8, &der);
    PKCS8_PRIV_KEY_INFO_free(p8);
    EVP_PKEY_free(pkey);
    REQUIRE(derLen > 0);
    out.privateKey.assign(der, der + derLen);
    OPENSSL_free(der);
    return out;
}

// X25519 DH (the classic legs and the KEM-shaped fallback); ML-KEM
// itself never uses this — it has its own encapsulate/decapsulate.
Bytes kemShared(const Bytes &priv, const Bytes &pub) {
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

KemEncapsulation kemEncapsulate(const Bytes &peerPublic) {
    if (mlKemAvailable()) {
        EVP_PKEY *pub = EVP_PKEY_new_raw_public_key(
            NID_ML_KEM_1024, nullptr,
            peerPublic.data(), peerPublic.size());
        REQUIRE(pub != nullptr);
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub, nullptr);
        REQUIRE(ctx != nullptr);
        REQUIRE(EVP_PKEY_encapsulate_init(ctx, nullptr) == 1);
        KemEncapsulation out;
        // Parameter order mirrors the production QuantumGuard call:
        // (wrapped key = ciphertext) first, (generated secret) second.
        size_t ctLen = 0, ssLen = 0;
        REQUIRE(EVP_PKEY_encapsulate(ctx, nullptr, &ctLen, nullptr, &ssLen) == 1);
        out.ciphertext.resize(ctLen);
        out.sharedSecret.resize(ssLen);
        REQUIRE(EVP_PKEY_encapsulate(
            ctx,
            out.ciphertext.data(), &ctLen,
            out.sharedSecret.data(), &ssLen) == 1);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub);
        return out;
    }

    // X25519-KEM fallback: ephemeral key, ss = DH(epriv, pk), ct = epub.
    EVP_PKEY *eph = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
    REQUIRE(eph != nullptr);
    Bytes epriv(32), epub(32);
    size_t len = 32;
    REQUIRE(EVP_PKEY_get_raw_private_key(eph, epriv.data(), &len) == 1);
    len = 32;
    REQUIRE(EVP_PKEY_get_raw_public_key(eph, epub.data(), &len) == 1);
    EVP_PKEY_free(eph);
    KemEncapsulation out;
    out.sharedSecret = kemShared(epriv, peerPublic);
    out.ciphertext = epub;
    return out;
}

Bytes kemDecapsulate(const Bytes &privateKey, const Bytes &ciphertext) {
    // Reconstruct via PKCS#8 DER + d2i_AutoPrivateKey (raw private import
    // is rejected for provider-native ML-KEM keys on host OpenSSL 3.x).
    const auto *der = reinterpret_cast<const unsigned char *>(
        privateKey.data());
    EVP_PKEY *priv = d2i_AutoPrivateKey(nullptr, &der, int(privateKey.size()));
    if (priv != nullptr && EVP_PKEY_get_base_id(priv) == EVP_PKEY_X25519) {
        // X25519-KEM fallback: ciphertext embeds the ephemeral public.
        EVP_PKEY_free(priv);
        Bytes rawPriv(32);
        Bytes epriv(ciphertext.begin(), ciphertext.begin() + 32);
        {
            const auto *eder = reinterpret_cast<const unsigned char *>(
                privateKey.data());
            EVP_PKEY *xp = d2i_AutoPrivateKey(nullptr, &eder, int(privateKey.size()));
            REQUIRE(xp != nullptr);
            size_t l = 32;
            REQUIRE(EVP_PKEY_get_raw_private_key(xp, rawPriv.data(), &l) == 1);
            EVP_PKEY_free(xp);
        }
        return kemShared(rawPriv, epriv);
    }
    if (priv == nullptr) {
        return {};
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, nullptr);
    REQUIRE(ctx != nullptr);
    REQUIRE(EVP_PKEY_decapsulate_init(ctx, nullptr) == 1);
    Bytes out(32);
    size_t len = 32;
    // FIPS 203 implicit rejection: a corrupted ciphertext still returns
    // rc == 1 with a PSEUDO-RANDOM secret — never Alice's secret.
    const int rc = EVP_PKEY_decapsulate(
        ctx, out.data(), &len, ciphertext.data(), ciphertext.size());
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv);
    if (rc != 1) return {}; // mirror prod: decapsulation failure = empty
    return out;
}

// ---------------------------------------------------------------------------
// Primitives (desktop deriveKey / calculateHMAC mirrors)
// ---------------------------------------------------------------------------

Bytes hkdfExpandOnly(const Bytes &prk, const std::string &info, size_t len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    REQUIRE(pctx != nullptr);
    REQUIRE(EVP_PKEY_derive_init(pctx) > 0);
    // NEVER omit the digest (desktop commit 9b66cd02f8): OpenSSL 3.x
    // silently yields zero-filled output without it.
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
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + updateLen, &finalLen) != 1) {
        // Authentication failure must be observable (tamper tests).
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("aes-gcm authentication failed");
    }
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(size_t(updateLen + finalLen));
    return plaintext;
}

// Quantum key schedule (labels MUST match the desktop / Android constants).
constexpr const char *kInfoQuantumRoot = "CryptogramQX3DH";
constexpr const char *kInfoQuantumChainA = "CryptogramQChainA";
constexpr const char *kInfoQuantumChainB = "CryptogramQChainB";
constexpr const char *kInfoQuantumMessage = "CryptogramQMessage";
constexpr const char *kInfoQuantumChainStep = "CryptogramQChainStep";

Bytes quantumChainStep(const Bytes &chain) {
    return hkdfExpandOnly(chain, kInfoQuantumChainStep, 32);
}

Bytes quantumMessageKey(const Bytes &chain) {
    return hkdfExpandOnly(chain, kInfoQuantumMessage, 32);
}

// ---------------------------------------------------------------------------
// Classic layer (fixed X3DH + Double Ratchet mirror, see
// test_e2e_x3dh_fixed.cpp) with counter skip-ahead, as desktop decryptMessage.
// ---------------------------------------------------------------------------

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
    return kemShared(priv, pub); // X25519 leg (same construction)
}

struct KdfRkResult {
    Bytes rootKey;
    Bytes chainKey;
};

KdfRkResult kdfRk(const Bytes &rootKey, const Bytes &dhOutput) {
    Bytes combined = rootKey;
    combined.insert(combined.end(), dhOutput.begin(), dhOutput.end());
    auto derived = hkdfExpandOnly(combined, "CryptogramKDF_RK", 64);
    return {
        Bytes(derived.begin(), derived.begin() + 32),
        Bytes(derived.begin() + 32, derived.end()),
    };
}

Bytes ratchetChainKey(const Bytes &chainKey) {
    return hmacSha256(chainKey, {0x01});
}

Bytes classicMessageKey(const Bytes &chainKey) {
    return hkdfExpandOnly(chainKey, "WhisperMessageKey", 32);
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

// Quantum session state (desktop QuantumSessionSnapshot / Android
// QuantumSessionState mirror).
struct QuantumSession {
    Bytes rootKey;
    Bytes sendChainKey;
    Bytes recvChainKey;
    uint32_t sendCounter = 0;
    uint32_t recvCounter = 0;

    struct SkippedKey {
        uint32_t messageNumber = 0;
        Bytes key;
    };
    std::vector<SkippedKey> skippedKeys;
};

// One protocol side: classic session + quantum session.
struct Side {
    // classic
    Bytes classicSendChain;
    Bytes classicRecvChain;
    Bytes dhSendPrivate;
    Bytes dhSendPublic;
    Bytes dhRemotePublic;
    uint32_t sendingCounter = 0;
    uint32_t receivingCounter = 0;
    std::vector<QuantumSession::SkippedKey> classicSkipped;

    // quantum
    QuantumSession quantum;
    bool quantumActive = false;

    // static KEM identity (transport / decapsulation) and the pending
    // first-message transport (the kemCiphertext is sent ONCE per session)
    KemKeyPair kem;
    Bytes pendingKemCiphertext;

    // A message as handed to the wire (envelope fields before ZW framing).
    struct Message {
        uint32_t counter = 0;
        Bytes iv;
        Bytes senderPub;
        uint32_t timestamp = 0;
        Bytes classicCiphertext; // classic layer output (whole payload)
        Bytes quantumCiphertext; // inner quantum payload (tamper tests)
        bool hasQuantumInit = false;
        Bytes kemCiphertext;
        Bytes kemEmitterPublic;
    };
};

// Quantum establishment (initiator): ONE real KEM encapsulation against the
// peer's static KEM public. Returns the encapsulation ciphertext for
// transport in the first quantum-protected message's metadata.
Bytes quantumEstablishInitiator(Side &initiator, const KemKeyPair &peerKem) {
    auto enc = kemEncapsulate(peerKem.publicKey);
    REQUIRE(enc.sharedSecret.size() == 32);
    REQUIRE(!enc.ciphertext.empty());

    const auto qRoot = hkdfExpandOnly(enc.sharedSecret, kInfoQuantumRoot, 32);
    initiator.quantum.rootKey = qRoot;
    // Initiator labels: send on ChainA, receive on ChainB.
    initiator.quantum.sendChainKey = hkdfExpandOnly(qRoot, kInfoQuantumChainA, 32);
    initiator.quantum.recvChainKey = hkdfExpandOnly(qRoot, kInfoQuantumChainB, 32);
    initiator.quantumActive = true;
    return enc.ciphertext;
}

// Quantum establishment (resolver): decapsulate the transported ciphertext
// with OUR static KEM private; same shared secret, labels swapped.
void quantumAcceptInit(Side &resolver, const KemKeyPair &ownKem, const Bytes &kemCiphertext) {
    auto ss = kemDecapsulate(ownKem.privateKey, kemCiphertext);
    REQUIRE(ss.size() == 32);
    const auto qRoot = hkdfExpandOnly(ss, kInfoQuantumRoot, 32);
    resolver.quantum.rootKey = qRoot;
    resolver.quantum.recvChainKey = hkdfExpandOnly(qRoot, kInfoQuantumChainA, 32);
    resolver.quantum.sendChainKey = hkdfExpandOnly(qRoot, kInfoQuantumChainB, 32);
    resolver.quantumActive = true;
}

// Full quantum-protected send (desktop encryptQuantumSessionMessage): the
// classic layer is prepared FIRST (chain advance, counter, iv, aad), the
// quantum layer encrypts the plaintext under the SAME iv + aad, then the
// classic layer encrypts the whole quantum-protected payload.
Side::Message quantumSend(Side &side, const std::string &text, bool withInit) {
    REQUIRE(side.quantumActive);
    if (withInit) {
        REQUIRE(!side.pendingKemCiphertext.empty());
    }

    Side::Message msg;

    // Classic prep (desktop beginClassicEncryption).
    Bytes classicKey = classicMessageKey(side.classicSendChain);
    side.classicSendChain = ratchetChainKey(side.classicSendChain);
    msg.counter = side.sendingCounter++;
    msg.senderPub = side.dhSendPublic;
    msg.timestamp = 123456; // fixed shape; the timestamp feeds no KDF
    msg.iv.resize(12);
    REQUIRE(RAND_bytes(msg.iv.data(), 12) == 1);
    const auto aad = aadFor(msg.counter, msg.senderPub);

    // Quantum wrap (same iv + aad; one message key per classic message).
    Bytes quantumKey = quantumMessageKey(side.quantum.sendChainKey);
    msg.quantumCiphertext = aesGcmEncrypt(
        quantumKey, msg.iv, Bytes(text.begin(), text.end()), aad);
    side.quantum.sendChainKey = quantumChainStep(side.quantum.sendChainKey);
    side.quantum.sendCounter++;

    // Classic layer encrypts the whole quantum-protected payload.
    msg.classicCiphertext = aesGcmEncrypt(
        classicKey, msg.iv, msg.quantumCiphertext, aad);

    if (withInit) {
        msg.hasQuantumInit = true;
        msg.kemCiphertext = side.pendingKemCiphertext;
        msg.kemEmitterPublic = side.kem.publicKey;
        side.pendingKemCiphertext.clear(); // transported ONCE
    }
    return msg;
}

// Classic decrypt with counter skip-ahead (desktop decryptMessage).
Bytes classicDecrypt(Side &side, const Side::Message &msg) {
    const auto aad = aadFor(msg.counter, msg.senderPub);
    Bytes classicKey;
    if (msg.counter == side.receivingCounter) {
        classicKey = classicMessageKey(side.classicRecvChain);
        side.classicRecvChain = ratchetChainKey(side.classicRecvChain);
        side.receivingCounter++;
    } else if (msg.counter > side.receivingCounter) {
        REQUIRE(msg.counter - side.receivingCounter <= 2000);
        auto currentChain = side.classicRecvChain;
        auto currentCounter = side.receivingCounter;
        while (currentCounter < msg.counter) {
            QuantumSession::SkippedKey skip;
            skip.messageNumber = currentCounter;
            skip.key = classicMessageKey(currentChain);
            side.classicSkipped.push_back(std::move(skip));
            currentChain = ratchetChainKey(currentChain);
            currentCounter++;
        }
        classicKey = classicMessageKey(currentChain);
        side.classicRecvChain = ratchetChainKey(currentChain);
        side.receivingCounter = currentCounter + 1;
    } else {
        const auto it = std::find_if(
            side.classicSkipped.begin(),
            side.classicSkipped.end(),
            [&](const QuantumSession::SkippedKey &key) {
                return key.messageNumber == msg.counter;
            });
        REQUIRE(it != side.classicSkipped.end());
        classicKey = it->key;
        side.classicSkipped.erase(it);
    }
    return aesGcmDecrypt(classicKey, msg.iv, msg.classicCiphertext, aad);
}

// Quantum unwrap AFTER classic decryption (desktop
// quantumUnwrapSessionPayload): expected / skip-ahead / skipped-store
// derivation, then AES-GCM with the SAME iv + aad. Throws (auth failure) on
// tamper or chain mismatch — the prod path drops the message instead.
Bytes quantumReceive(Side &side, const Side::Message &msg) {
    REQUIRE(side.quantumActive);
    QuantumSession next = side.quantum;
    const auto aad = aadFor(msg.counter, msg.senderPub);
    Bytes messageKey;
    if (msg.counter == next.recvCounter) {
        messageKey = quantumMessageKey(next.recvChainKey);
        next.recvChainKey = quantumChainStep(next.recvChainKey);
        next.recvCounter++;
    } else if (msg.counter > next.recvCounter) {
        REQUIRE(msg.counter - next.recvCounter <= 2000);
        auto currentChain = next.recvChainKey;
        auto currentCounter = next.recvCounter;
        while (currentCounter < msg.counter) {
            QuantumSession::SkippedKey skip;
            skip.messageNumber = currentCounter;
            skip.key = quantumMessageKey(currentChain);
            next.skippedKeys.push_back(std::move(skip));
            currentChain = quantumChainStep(currentChain);
            currentCounter++;
        }
        messageKey = quantumMessageKey(currentChain);
        next.recvChainKey = quantumChainStep(currentChain);
        next.recvCounter = currentCounter + 1;
    } else {
        const auto it = std::find_if(
            next.skippedKeys.begin(),
            next.skippedKeys.end(),
            [&](const QuantumSession::SkippedKey &key) {
                return key.messageNumber == msg.counter;
            });
        if (it == next.skippedKeys.end()) return {};
        messageKey = it->key;
        next.skippedKeys.erase(it);
    }
    auto plaintext = aesGcmDecrypt(messageKey, msg.iv, msg.quantumCiphertext, aad);
    side.quantum = next; // commit only on success
    return plaintext;
}

// ---------------------------------------------------------------------------
// Envelope v2 / legacy framing (QDataStream Qt_5_15 emulation: integers
// big-endian, QByteArray = u32 BE length + bytes, bool = one byte)
// ---------------------------------------------------------------------------

constexpr uint32_t kEnvelopeVersion = 2;

void pushU32(Bytes &out, uint32_t value) {
    out.push_back(static_cast<unsigned char>((value >> 24) & 0xFF));
    out.push_back(static_cast<unsigned char>((value >> 16) & 0xFF));
    out.push_back(static_cast<unsigned char>((value >> 8) & 0xFF));
    out.push_back(static_cast<unsigned char>(value & 0xFF));
}

void pushU8(Bytes &out, unsigned char value) {
    out.push_back(value);
}

void pushByteArray(Bytes &out, const Bytes &value) {
    pushU32(out, static_cast<uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

struct Reader {
    const Bytes &data;
    size_t pos = 0;

    bool u32(uint32_t &out) {
        if (pos + 4 > data.size()) return false;
        out = (uint32_t(data[pos]) << 24) | (uint32_t(data[pos + 1]) << 16)
            | (uint32_t(data[pos + 2]) << 8) | uint32_t(data[pos + 3]);
        pos += 4;
        return true;
    }
    bool byte(unsigned char &out) {
        if (pos + 1 > data.size()) return false;
        out = data[pos++];
        return true;
    }
    bool bytes(Bytes &out) {
        uint32_t len = 0;
        if (!u32(len)) return false;
        if (len > data.size() - pos) return false;
        out.assign(data.begin() + pos, data.begin() + pos + len);
        pos += len;
        return true;
    }
};

struct Envelope {
    // routing
    int version = 0; // 0 = legacy, 2 = v2
    // classic fields
    uint32_t counter = 0;
    Bytes iv;
    Bytes senderPub;
    uint32_t timestamp = 0;
    // quantum init (v2 only)
    bool hasQuantumInit = false;
    Bytes kemCiphertext;
    Bytes kemEmitterPublic;
    // payload
    Bytes ciphertext;
};

Bytes wrapEnvelopeV2(const Side::Message &msg) {
    Bytes out;
    pushU32(out, kEnvelopeVersion); // qint32 routing prefix, FIRST
    pushU32(out, msg.counter);
    pushByteArray(out, msg.iv);
    pushByteArray(out, msg.senderPub);
    pushU32(out, msg.timestamp);
    pushU8(out, 0); // hasCacChallenge = false
    pushU8(out, 0); // hasCacResponse = false
    pushU8(out, msg.hasQuantumInit ? 1 : 0);
    if (msg.hasQuantumInit) {
        pushByteArray(out, msg.kemCiphertext);
        pushByteArray(out, msg.kemEmitterPublic);
    }
    pushByteArray(out, msg.classicCiphertext);
    return out;
}

Bytes wrapEnvelopeLegacy(uint32_t counter, const Bytes &iv, const Bytes &senderPub, const Bytes &ciphertext) {
    Bytes out;
    pushU32(out, counter); // NO routing prefix: the counter is first
    pushByteArray(out, iv);
    pushByteArray(out, senderPub);
    pushU32(out, 123456);
    pushU8(out, 0); // hasCacChallenge = false
    pushU8(out, 0); // hasCacResponse = false
    pushByteArray(out, ciphertext);
    return out;
}

// Desktop/Android routing: version 2 first, structural failure falls back to
// the legacy parser (which fails loudly on real truncation).
std::optional<Envelope> unwrapEnvelope(const Bytes &blob) {
    Reader probe{blob};
    uint32_t version = 0;
    if (probe.u32(version) && version == kEnvelopeVersion) {
        Reader r{blob};
        Envelope env;
        uint32_t version2 = 0;
        unsigned char flag = 0;
        if (r.u32(version2) && version2 == kEnvelopeVersion
            && r.u32(env.counter)
            && r.bytes(env.iv)
            && r.bytes(env.senderPub)
            && r.u32(env.timestamp)
            && r.byte(flag)) {
            // hasCacChallenge
            bool ok = true;
            if (flag != 0) {
                Bytes nonce;
                ok = r.bytes(nonce);
            }
            if (ok) ok = r.byte(flag);
            // hasCacResponse
            if (ok && flag != 0) {
                Bytes sig, chain;
                ok = r.bytes(sig) && r.bytes(chain);
            }
            if (ok) ok = r.byte(flag);
            // hasQuantumInit
            if (ok) {
                env.hasQuantumInit = (flag != 0);
                if (env.hasQuantumInit) {
                    ok = r.bytes(env.kemCiphertext)
                        && r.bytes(env.kemEmitterPublic)
                        && !env.kemCiphertext.empty()
                        && !env.kemEmitterPublic.empty();
                }
            }
            if (ok) ok = r.bytes(env.ciphertext);
            if (ok) {
                env.version = 2;
                return env;
            }
        }
        // v2 structural failure: fall through to the legacy parser.
    }

    Reader r{blob};
    Envelope env;
    unsigned char flag = 0;
    if (!r.u32(env.counter)
        || !r.bytes(env.iv)
        || !r.bytes(env.senderPub)
        || !r.u32(env.timestamp)
        || !r.byte(flag)) {
        return std::nullopt;
    }
    if (flag != 0) {
        Bytes nonce;
        if (!r.bytes(nonce)) return std::nullopt;
    }
    if (!r.byte(flag)) return std::nullopt;
    if (flag != 0) {
        Bytes sig, chain;
        if (!r.bytes(sig) || !r.bytes(chain)) return std::nullopt;
    }
    if (!r.bytes(env.ciphertext)) return std::nullopt;
    env.version = 0;
    return env;
}

// A fully-established quantum conversation (Alice initiated).
struct Fixture {
    Side alice;
    Side bob;
    KemKeyPair bobKem;

    static Fixture create() {
        Fixture fx;
        auto [xidAPriv, xidAPub] = generateX25519();
        auto [ekAPriv, ekAPub] = generateX25519();
        auto [xidBPriv, xidBPub] = generateX25519();
        auto [spkBPriv, spkBPub] = generateX25519();
        auto [opkBPriv, opkBPub] = generateX25519();

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
        auto chainInit = hkdfExpandOnly(rkA.rootKey, "WhisperMessageKeys", 32);

        fx.alice.classicSendChain = rkA.chainKey;
        fx.alice.classicRecvChain = chainInit;
        fx.alice.dhSendPrivate = ekAPriv;
        fx.alice.dhSendPublic = ekAPub;
        fx.alice.dhRemotePublic = spkBPub;
        fx.alice.kem = generateKemKeyPair();

        fx.bob.classicSendChain = chainInit;
        fx.bob.classicRecvChain = rkA.chainKey;
        fx.bob.dhSendPrivate = spkBPriv;
        fx.bob.dhSendPublic = spkBPub;
        fx.bob.dhRemotePublic = ekAPub;
        fx.bobKem = generateKemKeyPair();
        // Bob's static KEM identity lives on his Side too (tamper tests
        // decapsulate through Side::kem directly).
        fx.bob.kem = fx.bobKem;

        // Alice establishes the quantum session toward Bob; the returned
        // encapsulation ciphertext rides in her first message's metadata.
        fx.alice.pendingKemCiphertext = quantumEstablishInitiator(
            fx.alice, fx.bobKem);
        return fx;
    }

    // Bob resolves Alice's init transport (first v2 message).
    void bobAcceptFirstInit(const Side::Message &first) {
        REQUIRE(first.hasQuantumInit);
        quantumAcceptInit(bob, bobKem, first.kemCiphertext);
    }
};

} // namespace

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST_CASE("Quantum session: root and chain agreement", "[e2e][quantum-session]") {
    auto fx = Fixture::create();
    // Bob resolves Alice's transported init (pure key agreement — no
    // message needed, counters stay at zero).
    quantumAcceptInit(fx.bob, fx.bobKem, fx.alice.pendingKemCiphertext);
    REQUIRE(fx.alice.quantum.rootKey == fx.bob.quantum.rootKey);
    // Chain assignment: Alice sends on ChainA, Bob receives on it.
    REQUIRE(fx.alice.quantum.sendChainKey == fx.bob.quantum.recvChainKey);
    // Bob sends on ChainB, Alice receives on it.
    REQUIRE(fx.bob.quantum.sendChainKey == fx.alice.quantum.recvChainKey);
    // The two directions use distinct chain material.
    REQUIRE(fx.alice.quantum.sendChainKey != fx.alice.quantum.recvChainKey);
    // Counters start at zero.
    REQUIRE(fx.alice.quantum.sendCounter == 0);
    REQUIRE(fx.bob.quantum.recvCounter == 0);
}

TEST_CASE("Quantum session: first message transports the KEM ciphertext once (v2)", "[e2e][quantum-session]") {
    auto fx = Fixture::create();

    const Bytes text{'f', 'i', 'r', 's', 't'};
    const auto msg = quantumSend(fx.alice, "first", true);
    const auto blob = wrapEnvelopeV2(msg);

    // v2 layout: routing prefix + quantum init fields present, exactly once.
    auto parsed = unwrapEnvelope(blob);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->version == 2);
    REQUIRE(parsed->hasQuantumInit);
    REQUIRE(parsed->kemCiphertext == msg.kemCiphertext);
    REQUIRE(parsed->kemEmitterPublic == fx.alice.kem.publicKey);
    if (mlKemAvailable()) {
        REQUIRE(parsed->kemCiphertext.size() == 1568); // ML-KEM-1024 ct
    }

    // Bob: classic decrypt first...
    REQUIRE(classicDecrypt(fx.bob, msg).size() > 0);
    // ...resolve the init, quantum-unwrap second.
    fx.bobAcceptFirstInit(msg);
    REQUIRE(quantumReceive(fx.bob, msg) == text);
    REQUIRE(fx.bob.quantum.recvCounter == 1);
}

TEST_CASE("Quantum session: full conversation, NO new encapsulation", "[e2e][quantum-session]") {
    auto fx = Fixture::create();

    const auto m1 = quantumSend(fx.alice, "hello bob", true);
    fx.bobAcceptFirstInit(m1);
    REQUIRE(classicDecrypt(fx.bob, m1).size() > 0);
    REQUIRE(quantumReceive(fx.bob, m1).size() > 0);

    // Subsequent messages carry NO init fields (no new encapsulation).
    const auto m2 = quantumSend(fx.alice, "second message", false);
    REQUIRE(!m2.hasQuantumInit);
    REQUIRE(m2.kemCiphertext.empty());
    REQUIRE(m2.kemEmitterPublic.empty());
    auto parsed2 = unwrapEnvelope(wrapEnvelopeV2(m2));
    REQUIRE(parsed2.has_value());
    REQUIRE(parsed2->version == 2);
    REQUIRE(!parsed2->hasQuantumInit);
    REQUIRE(classicDecrypt(fx.bob, m2).size() > 0);
    REQUIRE(quantumReceive(fx.bob, m2).size() > 0);

    // Bob replies on HIS chain (still no encapsulation either side).
    const auto r1 = quantumSend(fx.bob, "reply from bob", false);
    REQUIRE(!r1.hasQuantumInit);
    REQUIRE(classicDecrypt(fx.alice, r1).size() > 0);
    REQUIRE(quantumReceive(fx.alice, r1).size() > 0);

    // Interleaved conversation.
    const auto m3 = quantumSend(fx.alice, "alice again", false);
    const auto r2 = quantumSend(fx.bob, "bob again", false);
    REQUIRE(quantumReceive(fx.bob, m3).size() > 0);
    REQUIRE(quantumReceive(fx.alice, r2).size() > 0);

    // Lockstep: exactly one quantum message key per classic message.
    REQUIRE(fx.alice.quantum.sendCounter == 3);
    REQUIRE(fx.bob.quantum.recvCounter == 3); // m1, m2, m3
    REQUIRE(fx.bob.quantum.sendCounter == 2);
    REQUIRE(fx.alice.quantum.recvCounter == 2); // r1, r2
    // Chain states agree per direction.
    REQUIRE(fx.alice.quantum.sendChainKey == fx.bob.quantum.recvChainKey);
    REQUIRE(fx.bob.quantum.sendChainKey == fx.alice.quantum.recvChainKey);
}

TEST_CASE("Quantum session: out-of-order delivery uses skipped quantum keys", "[e2e][quantum-session]") {
    auto fx = Fixture::create();

    const auto m1 = quantumSend(fx.alice, "m1", true);
    fx.bobAcceptFirstInit(m1);
    REQUIRE(classicDecrypt(fx.bob, m1).size() > 0);
    REQUIRE(quantumReceive(fx.bob, m1).size() > 0);

    const auto m2 = quantumSend(fx.alice, "m2", false);
    const auto m3 = quantumSend(fx.alice, "m3", false);

    // Deliver m3 first: both layers skip ahead and store the m2 keys.
    REQUIRE(classicDecrypt(fx.bob, m3).size() > 0);
    REQUIRE(quantumReceive(fx.bob, m3).size() > 0);
    REQUIRE(fx.bob.quantum.skippedKeys.size() == 1);
    REQUIRE(fx.bob.quantum.skippedKeys.front().messageNumber == m2.counter);
    // Then m2 from the skipped stores.
    REQUIRE(classicDecrypt(fx.bob, m2).size() > 0);
    REQUIRE(quantumReceive(fx.bob, m2).size() > 0);
    REQUIRE(fx.bob.quantum.skippedKeys.empty());
    REQUIRE(fx.bob.quantum.recvCounter == 3);
    REQUIRE(fx.bob.quantum.recvChainKey == fx.alice.quantum.sendChainKey);
}

TEST_CASE("Quantum session: tamper rejection", "[e2e][quantum-session]") {
    auto fx = Fixture::create();
    const auto m1 = quantumSend(fx.alice, "tamper target", true);
    fx.bobAcceptFirstInit(m1);

    // 1. Tampered classic ciphertext: the classic layer rejects.
    {
        auto bad = m1;
        bad.classicCiphertext[bad.classicCiphertext.size() - 20] ^= 0x80;
        REQUIRE_THROWS(classicDecrypt(fx.bob, bad));
    }

    // 2. Tampered quantum payload with an intact classic layer: the quantum
    //    AEAD rejects (a receiver cannot be fed a forged inner payload even
    //    when the outer envelope authenticates).
    {
        auto bad = m1;
        bad.quantumCiphertext[0] ^= 0x01;
        Side bobCopy = fx.bob;
        REQUIRE_THROWS(quantumReceive(bobCopy, bad));
        // Rejected receive must not consume chain state.
        REQUIRE(bobCopy.quantum.recvChainKey == fx.bob.quantum.recvChainKey);
        REQUIRE(bobCopy.quantum.recvCounter == fx.bob.quantum.recvCounter);
    }

    // 3. Tampered kemCiphertext: decapsulation never yields Alice's secret
    //    (FIPS 203 implicit rejection), so the resolver derives different
    //    chains and cannot reach the sender's quantum keys.
    {
        auto bad = m1;
        bad.kemCiphertext[0] ^= 0x01;
        Side victim = fx.bob;
        REQUIRE_NOTHROW(quantumAcceptInit(victim, victim.kem, bad.kemCiphertext));
        if (mlKemAvailable()) {
            REQUIRE(victim.quantum.rootKey != fx.alice.quantum.rootKey);
        }
    }
}

TEST_CASE("Quantum session: legacy v1 envelope still parses (classic-only)", "[e2e][quantum-session]") {
    auto fx = Fixture::create();

    // Classic-only message (no quantum layer): legacy field order.
    Side::Message msg;
    msg.counter = fx.alice.sendingCounter++;
    msg.senderPub = fx.alice.dhSendPublic;
    msg.iv.resize(12);
    REQUIRE(RAND_bytes(msg.iv.data(), 12) == 1);
    const auto aad = aadFor(msg.counter, msg.senderPub);
    auto classicKey = classicMessageKey(fx.alice.classicSendChain);
    fx.alice.classicSendChain = ratchetChainKey(fx.alice.classicSendChain);
    const Bytes plaintext{'l', 'e', 'g', 'a', 'c', 'y'};
    msg.classicCiphertext = aesGcmEncrypt(classicKey, msg.iv, plaintext, aad);

    const auto blob = wrapEnvelopeLegacy(
        msg.counter, msg.iv, msg.senderPub, msg.classicCiphertext);
    const auto parsed = unwrapEnvelope(blob);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->version == 0);
    REQUIRE(parsed->counter == msg.counter);
    REQUIRE(parsed->iv == msg.iv);
    REQUIRE(parsed->senderPub == msg.senderPub);
    REQUIRE(!parsed->hasQuantumInit);
    REQUIRE(parsed->ciphertext == msg.classicCiphertext);

    // ...and decrypts through the classic layer only.
    REQUIRE(classicDecrypt(fx.bob, msg) == plaintext);
}

TEST_CASE("Quantum session: legacy counter==2 misroute is structurally rejected", "[e2e][quantum-session]") {
    // A legacy envelope whose FIRST field (the classic counter) is 2 is
    // initially misrouted into the v2 parser; the v2 parse fails structurally
    // (the legacy IV length prefix is the random first four IV bytes — here
    // forced to an impossible length) and the legacy parser handles the blob.
    auto [ekPriv, ekPub] = generateX25519();
    Bytes iv = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    const Bytes plaintext{'c', '2'};
    const auto aad = aadFor(2, ekPub);
    auto classicKey = classicMessageKey(
        hkdfExpandOnly(Bytes(32, 0x11), "WhisperMessageKeys", 32));
    auto ct = aesGcmEncrypt(classicKey, iv, plaintext, aad);

    const auto blob = wrapEnvelopeLegacy(2, iv, ekPub, ct);
    const auto parsed = unwrapEnvelope(blob);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->version == 0);
    REQUIRE(parsed->counter == 2);
    REQUIRE(parsed->iv == iv);
    REQUIRE(parsed->ciphertext == ct);
}

TEST_CASE("Quantum session: fresh init re-establishes (restart recovery)", "[e2e][quantum-session]") {
    auto fx = Fixture::create();
    const auto m1 = quantumSend(fx.alice, "session one", true);
    fx.bobAcceptFirstInit(m1);
    REQUIRE(classicDecrypt(fx.bob, m1).size() > 0);
    REQUIRE(quantumReceive(fx.bob, m1).size() > 0);

    // "Alice restarts": a NEW quantum session replaces the old one and the
    // fresh init is transported again.
    fx.alice.pendingKemCiphertext = quantumEstablishInitiator(fx.alice, fx.bobKem);
    const auto m2 = quantumSend(fx.alice, "session two", true);
    REQUIRE(m2.hasQuantumInit);
    fx.bobAcceptFirstInit(m2); // replace-on-init
    REQUIRE(classicDecrypt(fx.bob, m2).size() > 0);
    REQUIRE(quantumReceive(fx.bob, m2).size() > 0);

    // The new session keeps working (fail-closed only against old sessions).
    const auto m3 = quantumSend(fx.alice, "still session two", false);
    REQUIRE(classicDecrypt(fx.bob, m3).size() > 0);
    REQUIRE(quantumReceive(fx.bob, m3).size() > 0);
}
