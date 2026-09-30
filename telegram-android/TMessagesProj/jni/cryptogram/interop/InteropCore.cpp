/*
 * CRYPTOGRAM Android — JNI-free protocol core implementation.
 *
 * Byte-for-byte port of the desktop protocol in
 * Telegram/SourceFiles/data/data_signal_protocol.cpp (the canonical spec)
 * and Telegram/SourceFiles/data/data_signal_transport.cpp. Function-by-
 * function correspondence is noted in the comments.
 *
 * Uses only the EVP subset shared by OpenSSL and the in-tree BoringSSL, so
 * the same source compiles on the desktop-like host (OpenSSL) and on
 * Android (BoringSSL).
 */

#include "interop/InteropCore.h"

#include <openssl/crypto.h> // CRYPTO_memcmp (constant-time HMAC compare)
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#if defined(OPENSSL_IS_BORINGSSL)
#include <openssl/mem.h> // OPENSSL_cleanse (pulled in transitively on OpenSSL)
#include <openssl/mlkem.h> // low-level ML-KEM (no ML-KEM EVP integration in BoringSSL)
// CBB/CBS for MLKEM*_(de)serialisation. The cryptogram target defines
// BORINGSSL_NO_CXX: this BoringSSL drop's span.h (pulled in by bytestring.h)
// requires C++17 and the target is C++14 — only the C API is used.
#include <openssl/bytestring.h>
#else
#include <openssl/x509.h> // i2d_PUBKEY / d2i_PUBKEY (ML-KEM SPKI, OpenSSL backend)
#endif

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>

#include <sys/stat.h>
#include <sys/types.h>

namespace interop {
namespace {

// AAD: 4-byte BIG-ENDIAN counter || 32-byte sender public key
// (desktop encryptMessage/decryptMessage — NO timestamp). Implementation
// lives below in the interop namespace so it can be exported for the
// quantum-session callers.


ByteVector concatenate3(const ByteVector &a, const ByteVector &b) {
    ByteVector result;
    result.reserve(a.size() + b.size());
    result.insert(result.end(), a.begin(), a.end());
    result.insert(result.end(), b.begin(), b.end());
    return result;
}

void pushU8(ByteVector &out, uint8_t value) {
    out.push_back(value);
}

void pushU32Be(ByteVector &out, uint32_t value) {
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(value & 0xFF));
}

void pushU32Le(ByteVector &out, uint32_t value) {
    for (int shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<uint8_t>((value >> shift) & 0xFF));
    }
}

void pushU16Le(ByteVector &out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
}

void pushU64Le(ByteVector &out, uint64_t value) {
    for (int shift = 0; shift < 64; shift += 8) {
        out.push_back(static_cast<uint8_t>((value >> shift) & 0xFF));
    }
}

// QDataStream QByteArray: quint32 BE length + raw bytes.
void pushQByteArray(ByteVector &out, const ByteVector &value) {
    pushU32Be(out, static_cast<uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

class ByteReader {
public:
    ByteReader(const uint8_t *data, size_t size) : data_(data), size_(size) {
    }

    bool readU8(uint8_t &value) {
        if (pos_ + 1 > size_) return false;
        value = data_[pos_++];
        return true;
    }

    bool readU32Be(uint32_t &value) {
        if (pos_ + 4 > size_) return false;
        value = (static_cast<uint32_t>(data_[pos_]) << 24)
            | (static_cast<uint32_t>(data_[pos_ + 1]) << 16)
            | (static_cast<uint32_t>(data_[pos_ + 2]) << 8)
            | static_cast<uint32_t>(data_[pos_ + 3]);
        pos_ += 4;
        return true;
    }

    bool readU16Le(uint16_t &value) {
        if (pos_ + 2 > size_) return false;
        value = static_cast<uint16_t>(
            static_cast<uint16_t>(data_[pos_])
            | (static_cast<uint16_t>(data_[pos_ + 1]) << 8));
        pos_ += 2;
        return true;
    }

    bool readU64Le(uint64_t &value) {
        if (pos_ + 8 > size_) return false;
        value = 0;
        for (int i = 7; i >= 0; --i) {
            value = (value << 8) | static_cast<uint64_t>(data_[pos_ + i]);
        }
        pos_ += 8;
        return true;
    }

    // QDataStream QByteArray: quint32 BE length + raw bytes.
    bool readByteArray(ByteVector &value) {
        uint32_t len = 0;
        if (!readU32Be(len)) return false;
        if (len > size_ - pos_) return false; // pos_ <= size_ always; overflow-safe
        value.assign(data_ + pos_, data_ + pos_ + len);
        pos_ += len;
        return true;
    }

    bool readRaw(size_t size, ByteVector &value) {
        if (size > size_ - pos_) return false; // pos_ <= size_ always; overflow-safe
        value.assign(data_ + pos_, data_ + pos_ + size);
        pos_ += size;
        return true;
    }

    bool atEnd() const {
        return pos_ >= size_;
    }

private:
    const uint8_t *data_ = nullptr;
    size_t size_ = 0;
    size_t pos_ = 0;
};

} // namespace

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

// AAD: 4-byte BIG-ENDIAN counter || 32-byte sender public key (desktop
// encryptMessage/decryptMessage — NO timestamp). Also used as the quantum
// layer's AAD (desktop encryptQuantumSessionMessage/quantumUnwrapSessionPayload).
ByteVector messageAad(const MessageMetadata &metadata) {
    ByteVector aad;
    aad.reserve(4 + metadata.senderPublicKey.size());
    const uint32_t counter = metadata.messageCounter;
    aad.push_back(static_cast<uint8_t>((counter >> 24) & 0xFF));
    aad.push_back(static_cast<uint8_t>((counter >> 16) & 0xFF));
    aad.push_back(static_cast<uint8_t>((counter >> 8) & 0xFF));
    aad.push_back(static_cast<uint8_t>(counter & 0xFF));
    aad.insert(
        aad.end(),
        metadata.senderPublicKey.begin(),
        metadata.senderPublicKey.end());
    return aad;
}

// OPENSSL_cleanse over the bytes, then clear.
void secureWipe(ByteVector &data) {
    if (!data.empty()) {
        OPENSSL_cleanse(data.data(), data.size());
    }
    data.clear();
}

ByteVector randomVector(size_t size) {
    ByteVector result(size);
    if (size == 0) return result;
    if (RAND_bytes(result.data(), static_cast<int>(size)) != 1) {
        result.clear();
    }
    return result;
}

// desktop SignalProtocol::calculateHMAC
ByteVector hmacSha256(const ByteVector &key, const ByteVector &data) {
    ByteVector output(EVP_MAX_MD_SIZE);
    unsigned int outLen = 0;
    if (!HMAC(
            EVP_sha256(),
            key.empty() ? nullptr : key.data(),
            static_cast<int>(key.size()),
            data.empty() ? nullptr : data.data(),
            data.size(),
            output.data(),
            &outLen)) {
        output.clear();
        return output;
    }
    output.resize(outLen);
    return output;
}

// desktop SignalProtocol::deriveKey: HKDF via EVP_PKEY_CTX in EXPAND_ONLY
// mode with the input used directly as PRK. The digest MUST be set even in
// EXPAND_ONLY mode — OpenSSL 3.x fails ("missing message digest") without
// it and silently yields zero-filled output.
ByteVector hkdfExpandSha256(
        const ByteVector &prk,
        const std::string &info,
        size_t length) {
    ByteVector output(length, 0);

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) return output;

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return output;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return output;
    }

#if defined(OPENSSL_IS_BORINGSSL)
    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return output;
    }
#else
    if (EVP_PKEY_CTX_set_hkdf_mode(pctx, EVP_KDF_HKDF_MODE_EXPAND_ONLY) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return output;
    }
#endif

    if (EVP_PKEY_CTX_set1_hkdf_key(
            pctx,
            prk.empty() ? nullptr : prk.data(),
            static_cast<int>(prk.size())) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return output;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(
            pctx,
            reinterpret_cast<const uint8_t *>(info.data()),
            static_cast<int>(info.size())) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return output;
    }

    size_t outLen = length;
    if (EVP_PKEY_derive(pctx, output.data(), &outLen) <= 0) {
        // Desktop keeps the zero-filled output on derive failure; so do we.
        std::fill(output.begin(), output.end(), static_cast<uint8_t>(0));
    }

    EVP_PKEY_CTX_free(pctx);
    return output;
}

// desktop x25519Generate + x25519PublicFromPrivate combined. EVP keygen is
// used (EVP_PKEY_new_raw_private_key with a null key only works on OpenSSL,
// not BoringSSL).
KeyPair generateDhKeyPair() {
    KeyPair pair;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) return pair;
    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return pair;
    }
    EVP_PKEY_CTX_free(ctx);

    uint8_t priv[kKeySize];
    uint8_t pub[kKeySize];
    // OpenSSL 3.x rejects a zero *len even with a valid buffer — pre-size.
    size_t privLen = kKeySize;
    size_t pubLen = kKeySize;
    const bool ok = EVP_PKEY_get_raw_private_key(pkey, priv, &privLen) == 1
        && privLen == kKeySize
        && EVP_PKEY_get_raw_public_key(pkey, pub, &pubLen) == 1
        && pubLen == kKeySize;
    if (ok) {
        pair.privateKey.assign(priv, priv + kKeySize);
        pair.publicKey.assign(pub, pub + kKeySize);
    }
    EVP_PKEY_free(pkey);
    return pair;
}

// desktop x25519PublicFromPrivate
ByteVector x25519PublicFromPrivate(const ByteVector &privateKey) {
    ByteVector result(kKeySize, 0);
    if (privateKey.size() != kKeySize) return result;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519,
        nullptr,
        privateKey.data(),
        privateKey.size());
    if (!pkey) return result;

    size_t len = kKeySize;
    if (EVP_PKEY_get_raw_public_key(pkey, result.data(), &len) != 1
            || len != kKeySize) {
        std::fill(result.begin(), result.end(), static_cast<uint8_t>(0));
    }
    EVP_PKEY_free(pkey);
    return result;
}

// desktop x25519: zero-filled 32-byte output on failure.
ByteVector x25519(const ByteVector &privateKey, const ByteVector &publicKey) {
    ByteVector result(kKeySize, 0);
    if (privateKey.size() != kKeySize || publicKey.size() != kKeySize) {
        return result;
    }

    EVP_PKEY *privKey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519,
        nullptr,
        privateKey.data(),
        privateKey.size());
    if (!privKey) return result;

    EVP_PKEY *pubKey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519,
        nullptr,
        publicKey.data(),
        publicKey.size());
    if (!pubKey) {
        EVP_PKEY_free(privKey);
        return result;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privKey, nullptr);
    if (ctx
            && EVP_PKEY_derive_init(ctx) > 0
            && EVP_PKEY_derive_set_peer(ctx, pubKey) > 0) {
        size_t outLen = kKeySize;
        if (EVP_PKEY_derive(ctx, result.data(), &outLen) <= 0
                || outLen != kKeySize) {
            std::fill(result.begin(), result.end(), static_cast<uint8_t>(0));
        }
    } else {
        std::fill(result.begin(), result.end(), static_cast<uint8_t>(0));
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(privKey);
    EVP_PKEY_free(pubKey);
    return result;
}

// Raw private key for Ed25519 is the 32-byte seed on both OpenSSL and
// BoringSSL (desktop stores the same EVP raw representation).
KeyPair generateEd25519KeyPair() {
    KeyPair pair;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx) return pair;
    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return pair;
    }
    EVP_PKEY_CTX_free(ctx);

    uint8_t seed[kEd25519SeedSize];
    uint8_t pub[kKeySize];
    // OpenSSL 3.x rejects a zero *len even with a valid buffer — pre-size.
    size_t seedLen = kEd25519SeedSize;
    size_t pubLen = kKeySize;
    const bool ok = EVP_PKEY_get_raw_private_key(pkey, seed, &seedLen) == 1
        && seedLen == kEd25519SeedSize
        && EVP_PKEY_get_raw_public_key(pkey, pub, &pubLen) == 1
        && pubLen == kKeySize;
    if (ok) {
        pair.privateKey.assign(seed, seed + kEd25519SeedSize);
        pair.publicKey.assign(pub, pub + kKeySize);
    }
    EVP_PKEY_free(pkey);
    return pair;
}

// desktop verifyEd25519Signature
bool verifyEd25519Signature(
        const ByteVector &signature,
        const ByteVector &data,
        const ByteVector &publicKey) {
    if (signature.size() != kEd25519SignatureSize) return false;
    if (publicKey.size() != kKeySize) return false;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return false;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519,
        nullptr,
        publicKey.data(),
        publicKey.size());
    if (!pkey) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    bool ok = EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey) == 1;
    if (ok) {
        ok = EVP_DigestVerify(
                 mdctx,
                 signature.data(),
                 signature.size(),
                 data.empty() ? nullptr : data.data(),
                 data.size()) == 1;
    }

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdctx);
    return ok;
}

ByteVector aesGcmEncrypt(
        const ByteVector &key,
        const ByteVector &iv,
        const ByteVector &plaintext,
        const ByteVector &aad) {
    if (key.size() != kAesKeySize || iv.size() != kGcmIvSize) {
        return {};
    }

    ByteVector output(plaintext.size() + kGcmTagSize);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    int outLen = 0;
    int totalLen = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) == 1;
    if (ok && !aad.empty()) {
        ok = EVP_EncryptUpdate(ctx, nullptr, &outLen, aad.data(), static_cast<int>(aad.size())) == 1;
    }
    if (ok && !plaintext.empty()) {
        ok = EVP_EncryptUpdate(
                 ctx,
                 output.data(),
                 &outLen,
                 plaintext.data(),
                 static_cast<int>(plaintext.size())) == 1;
        totalLen = outLen;
    }
    if (ok) {
        ok = EVP_EncryptFinal_ex(ctx, output.data() + totalLen, &outLen) == 1;
        totalLen += outLen;
    }
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(
                 ctx,
                 EVP_CTRL_GCM_GET_TAG,
                 kGcmTagSize,
                 output.data() + totalLen) == 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return {};
    output.resize(static_cast<size_t>(totalLen) + kGcmTagSize);
    return output;
}

ByteVector aesGcmDecrypt(
        const ByteVector &key,
        const ByteVector &iv,
        const ByteVector &ciphertextWithTag,
        const ByteVector &aad) {
    if (key.size() != kAesKeySize
            || iv.size() != kGcmIvSize
            || ciphertextWithTag.size() < kGcmTagSize) {
        return {};
    }
    const size_t ciphertextSize = ciphertextWithTag.size() - kGcmTagSize;

    ByteVector plaintext(ciphertextSize);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    int outLen = 0;
    int totalLen = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) == 1;
    if (ok && !aad.empty()) {
        ok = EVP_DecryptUpdate(ctx, nullptr, &outLen, aad.data(), static_cast<int>(aad.size())) == 1;
    }
    if (ok && ciphertextSize > 0) {
        ok = EVP_DecryptUpdate(
                 ctx,
                 plaintext.data(),
                 &outLen,
                 ciphertextWithTag.data(),
                 static_cast<int>(ciphertextSize)) == 1;
        totalLen = outLen;
    }
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(
                 ctx,
                 EVP_CTRL_GCM_SET_TAG,
                 kGcmTagSize,
                 const_cast<uint8_t *>(ciphertextWithTag.data() + ciphertextSize)) == 1;
    }
    if (ok) {
        ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + totalLen, &outLen) == 1;
        totalLen += outLen;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return {};
    plaintext.resize(static_cast<size_t>(totalLen));
    return plaintext;
}

// ---------------------------------------------------------------------------
// Desktop KDF
// ---------------------------------------------------------------------------

// desktop SignalProtocol::kdfRk
KdfRkResult kdfRk(const ByteVector &rootKey, const ByteVector &dhOutput) {
    ByteVector combined = concatenate3(rootKey, dhOutput);
    const ByteVector derived = hkdfExpandSha256(
        combined,
        kInfoKdfRk,
        kAesKeySize * 2);
    secureWipe(combined);

    KdfRkResult result;
    result.rootKey.assign(derived.begin(), derived.begin() + kAesKeySize);
    result.chainKey.assign(
        derived.begin() + kAesKeySize,
        derived.begin() + (kAesKeySize * 2));
    return result;
}

// desktop SignalProtocol::ratchetChainKey
ByteVector ratchetChainKey(const ByteVector &chainKey) {
    ByteVector input(1, static_cast<uint8_t>(0x01));
    return hmacSha256(chainKey, input);
}

// desktop: deriveKey(chainKey, kInfoMessageKey, kAesKeySize)
ByteVector messageKeyFromChain(const ByteVector &chainKey) {
    return hkdfExpandSha256(chainKey, kInfoMessageKey, kAesKeySize);
}

// ---------------------------------------------------------------------------
// Local identity and key bundle
// ---------------------------------------------------------------------------

bool generateLocalIdentity(LocalIdentity &out) {
    out = LocalIdentity();

    const auto ed = generateEd25519KeyPair();
    const auto xid = generateDhKeyPair();
    const auto spk = generateDhKeyPair();
    const auto opk = generateDhKeyPair();
    const auto regId = randomVector(8);
    if (ed.privateKey.empty()
            || xid.privateKey.empty()
            || spk.privateKey.empty()
            || opk.privateKey.empty()
            || regId.empty()) {
        return false;
    }

    out.ed25519PrivateSeed = ed.privateKey;
    out.ed25519Public = ed.publicKey;
    out.x25519IdentityPrivate = xid.privateKey;
    out.x25519IdentityPublic = xid.publicKey;
    out.signedPreKeyPrivate = spk.privateKey;
    out.signedPreKeyPublic = spk.publicKey;
    out.oneTimePreKeyPrivate = opk.privateKey;
    out.oneTimePreKeyPublic = opk.publicKey;
    out.registrationId = 0;
    for (int i = 7; i >= 0; --i) {
        out.registrationId = (out.registrationId << 8) | static_cast<uint64_t>(regId[i]);
    }
    out.initialized = true;
    return true;
}

KeyBundle localKeyBundle(const LocalIdentity &local) {
    KeyBundle bundle;
    if (!local.initialized) return bundle;

    bundle.registrationId = local.registrationId;
    bundle.identityKey = local.ed25519Public;
    bundle.signedPreKey = local.signedPreKeyPublic;
    bundle.oneTimePreKey = local.oneTimePreKeyPublic;
    bundle.x25519IdentityKey = local.x25519IdentityPublic;

    // Sign the signed pre-key with the Ed25519 identity key.
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_PKEY *pkey = nullptr;
    do {
        if (!mdctx) break;
        pkey = EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519,
            nullptr,
            local.ed25519PrivateSeed.data(),
            local.ed25519PrivateSeed.size());
        if (!pkey) break;
        if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey) != 1) break;
        size_t sigLen = kEd25519SignatureSize;
        bundle.signature.resize(kEd25519SignatureSize);
        if (EVP_DigestSign(
                mdctx,
                bundle.signature.data(),
                &sigLen,
                bundle.signedPreKey.data(),
                bundle.signedPreKey.size()) != 1) {
            bundle.signature.clear();
        } else {
            bundle.signature.resize(sigLen);
        }
    } while (false);
    if (pkey) EVP_PKEY_free(pkey);
    if (mdctx) EVP_MD_CTX_free(mdctx);
    return bundle;
}

// desktop SignalProtocolTransport::encodeKeyBundle (little-endian).
ByteVector encodeKeyBundle(const KeyBundle &bundle) {
    if (bundle.identityKey.size() != kKeySize
            || bundle.signedPreKey.size() != kKeySize
            || bundle.signature.size() != kEd25519SignatureSize) {
        return {};
    }

    const bool hasOtp = (bundle.oneTimePreKey.size() == kKeySize);
    const bool hasPq = !bundle.quantumKemPublicKey.empty();
    const bool hasXid = (bundle.x25519IdentityKey.size() == kKeySize);

    ByteVector raw;
    raw.reserve(
        1 + 1 + 8 + (3 * kKeySize) + kEd25519SignatureSize
        + (hasOtp ? kKeySize : 0)
        + (hasPq ? 2 + bundle.quantumKemPublicKey.size() : 0)
        + (hasXid ? 2 + kKeySize : 0));

    pushU8(raw, kBundleVersion);
    pushU8(
        raw,
        static_cast<uint8_t>(
            (hasOtp ? kBundleFlagOneTimePreKey : 0)
            | (hasPq ? kBundleFlagQuantumKem : 0)
            | (hasXid ? kBundleFlagX25519Identity : 0)));
    pushU64Le(raw, bundle.registrationId);
    raw.insert(raw.end(), bundle.identityKey.begin(), bundle.identityKey.end());
    raw.insert(raw.end(), bundle.signedPreKey.begin(), bundle.signedPreKey.end());
    raw.insert(raw.end(), bundle.signature.begin(), bundle.signature.end());
    if (hasOtp) {
        raw.insert(
            raw.end(),
            bundle.oneTimePreKey.begin(),
            bundle.oneTimePreKey.end());
    }
    if (hasPq) {
        pushU16Le(raw, static_cast<uint16_t>(bundle.quantumKemPublicKey.size()));
        raw.insert(
            raw.end(),
            bundle.quantumKemPublicKey.begin(),
            bundle.quantumKemPublicKey.end());
    }
    if (hasXid) {
        pushU16Le(raw, static_cast<uint16_t>(kKeySize));
        raw.insert(
            raw.end(),
            bundle.x25519IdentityKey.begin(),
            bundle.x25519IdentityKey.end());
    }
    return raw;
}

// desktop SignalProtocolTransport::decodeKeyBundle. Unknown trailing bytes
// are tolerated (the desktop QDataStream reader ignores them too).
bool decodeKeyBundle(const ByteVector &raw, KeyBundle &out) {
    // version(1) + bitmap(1) + regId(8) + identityKey(32) + signedPreKey(32)
    // + signature(64) — without oneTimePreKey (desktop kMinPayloadBytes).
    constexpr size_t kMinPayloadBytes = 138;
    if (raw.size() < kMinPayloadBytes) return false;

    ByteReader reader(raw.data(), raw.size());
    uint8_t version = 0;
    uint8_t bitmap = 0;
    if (!reader.readU8(version) || !reader.readU8(bitmap)) return false;
    if (version != kBundleVersion) return false;

    KeyBundle bundle;
    if (!reader.readU64Le(bundle.registrationId)) return false;
    if (!reader.readRaw(kKeySize, bundle.identityKey)) return false;
    if (!reader.readRaw(kKeySize, bundle.signedPreKey)) return false;
    if (!reader.readRaw(kEd25519SignatureSize, bundle.signature)) return false;
    if ((bitmap & kBundleFlagOneTimePreKey) != 0) {
        // Desktop tolerates a truncated one-time pre-key (the read yields
        // empty and the bundle is treated as having none).
        ByteVector otp;
        if (reader.readRaw(kKeySize, otp)) {
            bundle.oneTimePreKey = std::move(otp);
        }
    }

    // Optional post-quantum extension (0x02): u16le length + DER. Mirrors
    // the desktop exactly, including the skip-on-invalid-length behaviour.
    if ((bitmap & kBundleFlagQuantumKem) != 0 && !reader.atEnd()) {
        uint16_t pqLen = 0;
        if (!reader.readU16Le(pqLen)) return false;
        if (pqLen > 0 && pqLen <= 4096) {
            ByteVector pq;
            if (reader.readRaw(pqLen, pq)) {
                bundle.quantumKemPublicKey = std::move(pq);
            }
        }
    }

    // Optional X3DH-fix extension (0x04): u16le length + 32-byte raw
    // X25519 identity public.
    if ((bitmap & kBundleFlagX25519Identity) != 0 && !reader.atEnd()) {
        uint16_t xidLen = 0;
        if (!reader.readU16Le(xidLen)) return false;
        if (xidLen == kKeySize) {
            ByteVector xid;
            if (reader.readRaw(kKeySize, xid)) {
                bundle.x25519IdentityKey = std::move(xid);
            }
        }
    }

    // Trailing unknown extension bytes are ignored.
    if (bundle.identityKey.empty()
            || bundle.signedPreKey.empty()
            || bundle.signature.empty()) {
        return false;
    }
    out = std::move(bundle);
    return true;
}

// desktop SignalProtocol::verifyKeyBundleSignature
bool verifyKeyBundleSignature(const KeyBundle &bundle) {
    return verifyEd25519Signature(
        bundle.signature,
        bundle.signedPreKey,
        bundle.identityKey);
}

// ---------------------------------------------------------------------------
// X3DH (fixed desktop spec)
// ---------------------------------------------------------------------------

// desktop SignalProtocol::createSession (the fixed version)
bool establishSessionAlice(
        SessionState &outState,
        const LocalIdentity &local,
        const KeyBundle &remoteBundle) {
    outState = SessionState();
    if (!local.initialized) return false;
    if (!verifyKeyBundleSignature(remoteBundle)) return false;
    if (remoteBundle.x25519IdentityKey.size() != kKeySize) return false;
    if (remoteBundle.signedPreKey.size() != kKeySize) return false;

    SessionState state;

    // Alice initiates: her DH sending key is a fresh ephemeral (EK_A).
    const auto ephemeral = generateDhKeyPair();
    if (ephemeral.privateKey.empty()) return false;
    state.dhSendingPrivateKey = ephemeral.privateKey;
    state.dhSendingPublicKey = ephemeral.publicKey;

    state.dhRemotePublicKey = remoteBundle.signedPreKey;
    state.remoteIdentityKey = remoteBundle.identityKey;
    state.remoteX25519IdentityKey = remoteBundle.x25519IdentityKey;

    const auto &xIdentity = local.x25519IdentityPrivate;
    auto dh1 = x25519(xIdentity, remoteBundle.signedPreKey);
    auto dh2 = x25519(state.dhSendingPrivateKey, remoteBundle.signedPreKey);

    ByteVector combined;
    ByteVector dhForChainInit;
    if (remoteBundle.oneTimePreKey.size() == kKeySize) {
        auto dh3 = x25519(xIdentity, remoteBundle.oneTimePreKey);
        const auto dh4 = x25519(state.dhSendingPrivateKey, remoteBundle.oneTimePreKey);
        combined = dh1;
        combined.insert(combined.end(), dh2.begin(), dh2.end());
        combined.insert(combined.end(), dh3.begin(), dh3.end());
        combined.insert(combined.end(), dh4.begin(), dh4.end());
        dhForChainInit = dh4;
        secureWipe(dh3);
    } else {
        combined = dh1;
        combined.insert(combined.end(), dh2.begin(), dh2.end());
        dhForChainInit = dh2;
    }

    state.rootKey = hkdfExpandSha256(combined, kInfoX3DH, kAesKeySize);
    const auto rkResult = kdfRk(state.rootKey, dhForChainInit);
    state.rootKey = rkResult.rootKey;
    state.sendingChainKey = rkResult.chainKey;

    // Symmetric chain-init: Bob derives the SAME 32 bytes from the same
    // root and uses them as his SENDING chain; ours is RECEIVING.
    state.receivingChainKey = hkdfExpandSha256(
        state.rootKey,
        kInfoChainKey,
        kAesKeySize);

    state.sendingMessageCounter = 0;
    state.receivingMessageCounter = 0;
    state.previousSendingChainLength = 0;
    state.pendingRemoteDH = false;

    secureWipe(dh1);
    secureWipe(dh2);
    secureWipe(dhForChainInit);
    secureWipe(combined);

    if (state.rootKey.empty()
            || state.sendingChainKey.empty()
            || state.receivingChainKey.empty()) {
        return false;
    }
    outState = std::move(state);
    return true;
}

// desktop SignalProtocol::createSessionFromInitialMessage
bool establishSessionBob(
        SessionState &outState,
        const LocalIdentity &local,
        const ByteVector &aliceEphemeralPublic,
        const KeyBundle &aliceBundle) {
    outState = SessionState();
    if (!local.initialized) return false;
    if (aliceEphemeralPublic.size() != kKeySize) return false;
    if (aliceBundle.x25519IdentityKey.size() != kKeySize) return false;
    if (local.signedPreKeyPrivate.size() != kKeySize) return false;

    SessionState state;

    // Bob's DH sending key is his signed pre-key (Alice already has it).
    state.dhSendingPrivateKey = local.signedPreKeyPrivate;
    state.dhSendingPublicKey = x25519PublicFromPrivate(local.signedPreKeyPrivate);

    // The remote DH key is Alice's ephemeral key.
    state.dhRemotePublicKey = aliceEphemeralPublic;
    state.remoteIdentityKey = aliceBundle.identityKey;
    state.remoteX25519IdentityKey = aliceBundle.x25519IdentityKey;

    const auto &aliceXIdentity = aliceBundle.x25519IdentityKey;
    auto dh1 = x25519(local.signedPreKeyPrivate, aliceXIdentity);
    auto dh2 = x25519(local.signedPreKeyPrivate, aliceEphemeralPublic);

    ByteVector combined;
    ByteVector dhForChainInit;
    if (local.oneTimePreKeyPrivate.size() == kKeySize) {
        auto dh3 = x25519(local.oneTimePreKeyPrivate, aliceXIdentity);
        const auto dh4 = x25519(local.oneTimePreKeyPrivate, aliceEphemeralPublic);
        combined = dh1;
        combined.insert(combined.end(), dh2.begin(), dh2.end());
        combined.insert(combined.end(), dh3.begin(), dh3.end());
        combined.insert(combined.end(), dh4.begin(), dh4.end());
        dhForChainInit = dh4;
        secureWipe(dh3);
    } else {
        combined = dh1;
        combined.insert(combined.end(), dh2.begin(), dh2.end());
        dhForChainInit = dh2;
    }

    state.rootKey = hkdfExpandSha256(combined, kInfoX3DH, kAesKeySize);
    const auto rkResult = kdfRk(state.rootKey, dhForChainInit);
    state.rootKey = rkResult.rootKey;

    // Bob's receiving chain = Alice's sending chain.
    state.receivingChainKey = rkResult.chainKey;

    // Symmetric chain-init: the SAME 32 bytes Alice uses as her RECEIVING
    // chain become Bob's SENDING chain.
    state.sendingChainKey = hkdfExpandSha256(
        state.rootKey,
        kInfoChainKey,
        kAesKeySize);

    state.sendingMessageCounter = 0;
    state.receivingMessageCounter = 0;
    state.previousSendingChainLength = 0;
    state.pendingRemoteDH = false;

    secureWipe(dh1);
    secureWipe(dh2);
    secureWipe(dhForChainInit);
    secureWipe(combined);

    if (state.rootKey.empty()
            || state.sendingChainKey.empty()
            || state.receivingChainKey.empty()) {
        return false;
    }
    outState = std::move(state);
    return true;
}

// ---------------------------------------------------------------------------
// Envelope (desktop wrapEncryptedText / unwrapEncryptedText)
// ---------------------------------------------------------------------------

// desktop wrapEncryptedText minus the zero-width encoding (the Java layer
// applies any text-level framing). All integers big-endian (QDataStream
// Qt_5_15 default). Envelope VERSION 2: the leading qint32 version routes
// the receiver's parser (desktop parity — legacy envelopes start at the
// classic message counter instead).
ByteVector wrapEnvelope(
        const ByteVector &ciphertext,
        const MessageMetadata &metadata) {
    ByteVector data;
    data.reserve(
        4 + 4 + (4 + metadata.iv.size())
        + (4 + metadata.senderPublicKey.size())
        + 4 + 1 + (metadata.hasCacChallenge
                   ? 4 + metadata.cacChallengeNonce.size() : 0)
        + 1 + (metadata.hasCacResponse
               ? 4 + metadata.cacSignature.size()
               + 4 + metadata.cacCertChainDer.size() : 0)
        + 1 + (metadata.hasQuantumInit
               ? 4 + metadata.quantumKemCiphertext.size()
               + 4 + metadata.quantumKemEmitterPublic.size() : 0)
        + 4 + ciphertext.size());

    pushU32Be(data, kEnvelopeVersion);
    pushU32Be(data, metadata.messageCounter);
    pushQByteArray(data, metadata.iv);
    pushQByteArray(data, metadata.senderPublicKey);
    pushU32Be(data, metadata.timestamp);

    // ZK Phase 1: challenge nonce only — NO identity information.
    pushU8(data, metadata.hasCacChallenge ? 1 : 0);
    if (metadata.hasCacChallenge) {
        pushQByteArray(data, metadata.cacChallengeNonce);
    }

    // ZK Phase 2: hardware signature + full DER cert chain — DN is NEVER
    // serialized.
    pushU8(data, metadata.hasCacResponse ? 1 : 0);
    if (metadata.hasCacResponse) {
        pushQByteArray(data, metadata.cacSignature);
        pushQByteArray(data, metadata.cacCertChainDer);
    }

    // Quantum session init (v2 only): the ML-KEM encapsulation ciphertext is
    // transported ONCE per session, with the sender's static KEM public.
    pushU8(data, metadata.hasQuantumInit ? 1 : 0);
    if (metadata.hasQuantumInit) {
        pushQByteArray(data, metadata.quantumKemCiphertext);
        pushQByteArray(data, metadata.quantumKemEmitterPublic);
    }

    pushQByteArray(data, ciphertext);
    return data;
}

// Legacy field order (envelopes already persisted in-flight): the leading
// int IS the classic message counter.
bool unwrapEnvelopeLegacy(const ByteVector &blob, Envelope &out) {
    ByteReader reader(blob.data(), blob.size());

    Envelope envelope;
    MessageMetadata &metadata = envelope.metadata;

    if (!reader.readU32Be(metadata.messageCounter)) return false;
    if (!reader.readByteArray(metadata.iv)) return false;
    if (!reader.readByteArray(metadata.senderPublicKey)) return false;
    if (!reader.readU32Be(metadata.timestamp)) return false;

    // ZK Phase 1
    uint8_t hasChallenge = 0;
    if (!reader.readU8(hasChallenge)) return false;
    metadata.hasCacChallenge = (hasChallenge != 0);
    if (metadata.hasCacChallenge) {
        if (!reader.readByteArray(metadata.cacChallengeNonce)) return false;
    }

    // ZK Phase 2 — DER cert chain, NO DN
    uint8_t hasResponse = 0;
    if (!reader.readU8(hasResponse)) return false;
    metadata.hasCacResponse = (hasResponse != 0);
    if (metadata.hasCacResponse) {
        if (!reader.readByteArray(metadata.cacSignature)) return false;
        if (!reader.readByteArray(metadata.cacCertChainDer)) return false;
    }

    if (!reader.readByteArray(envelope.ciphertext)) return false;
    out = std::move(envelope);
    return true;
}

// Version 2 field order (desktop UnwrapEncryptedTextV2).
bool unwrapEnvelopeV2(const ByteVector &blob, Envelope &out) {
    ByteReader reader(blob.data(), blob.size());

    Envelope envelope;
    MessageMetadata &metadata = envelope.metadata;

    uint32_t version = 0;
    if (!reader.readU32Be(version)) return false;
    if (version != kEnvelopeVersion) return false;
    metadata.envelopeVersion = static_cast<int32_t>(version);

    if (!reader.readU32Be(metadata.messageCounter)) return false;
    if (!reader.readByteArray(metadata.iv)) return false;
    if (!reader.readByteArray(metadata.senderPublicKey)) return false;
    if (!reader.readU32Be(metadata.timestamp)) return false;

    // ZK Phase 1 (identical to legacy)
    uint8_t hasChallenge = 0;
    if (!reader.readU8(hasChallenge)) return false;
    metadata.hasCacChallenge = (hasChallenge != 0);
    if (metadata.hasCacChallenge) {
        if (!reader.readByteArray(metadata.cacChallengeNonce)) return false;
    }

    // ZK Phase 2 — DER cert chain, NO DN (identical to legacy)
    uint8_t hasResponse = 0;
    if (!reader.readU8(hasResponse)) return false;
    metadata.hasCacResponse = (hasResponse != 0);
    if (metadata.hasCacResponse) {
        if (!reader.readByteArray(metadata.cacSignature)) return false;
        if (!reader.readByteArray(metadata.cacCertChainDer)) return false;
    }

    // Quantum session init (v2 only)
    uint8_t hasQuantumInit = 0;
    if (!reader.readU8(hasQuantumInit)) return false;
    metadata.hasQuantumInit = (hasQuantumInit != 0);
    if (metadata.hasQuantumInit) {
        if (!reader.readByteArray(metadata.quantumKemCiphertext)) return false;
        if (!reader.readByteArray(metadata.quantumKemEmitterPublic)) return false;
        if (metadata.quantumKemCiphertext.empty()
                || metadata.quantumKemEmitterPublic.empty()) {
            return false;
        }
    }

    if (!reader.readByteArray(envelope.ciphertext)) return false;
    out = std::move(envelope);
    return true;
}

// Routes on the leading version int (desktop unwrapEncryptedText): version 2
// → v2 field order; anything else → legacy field order. A legacy message
// whose counter happens to be 2 is structurally rejected by the v2 parser
// (the legacy IV length prefix is the random first four IV bytes) and still
// parses as legacy below.
bool unwrapEnvelope(const ByteVector &blob, Envelope &out) {
    if (blob.size() >= 4) {
        const uint32_t version = (static_cast<uint32_t>(blob[0]) << 24)
            | (static_cast<uint32_t>(blob[1]) << 16)
            | (static_cast<uint32_t>(blob[2]) << 8)
            | static_cast<uint32_t>(blob[3]);
        if (version == kEnvelopeVersion && unwrapEnvelopeV2(blob, out)) {
            return true;
        }
    }
    return unwrapEnvelopeLegacy(blob, out);
}

// ---------------------------------------------------------------------------
// Double ratchet (desktop encryptMessage / decryptMessage)
// ---------------------------------------------------------------------------

// desktop beginClassicEncryption parity: DH-ratchet when pending, derive
// + advance the sending chain, fill the metadata and build the AAD. Returns
// the classic message key (empty on failure); the caller completes the
// encryption with aesGcmEncrypt under the SAME iv + aad — the quantum
// session path reuses this to bind its payload to the exact classic message.
ByteVector beginMessage(
        SessionState &session,
        MessageMetadata &outMetadata,
        ByteVector &outAad) {
    // DH ratchet: if we received a new remote DH key, rotate our DH key
    // pair (desktop encryptMessage — pendingRemoteDH is only ever set
    // externally; the field is kept for byte-level state fidelity).
    if (session.pendingRemoteDH) {
        session.previousSendingChainLength = session.sendingMessageCounter;

        const auto rotated = generateDhKeyPair();
        if (rotated.privateKey.empty()) return {};
        session.dhSendingPrivateKey = rotated.privateKey;
        session.dhSendingPublicKey = rotated.publicKey;

        auto dhOutput = x25519(
            session.dhSendingPrivateKey,
            session.dhRemotePublicKey);
        const auto rkResult = kdfRk(session.rootKey, dhOutput);
        session.rootKey = rkResult.rootKey;
        session.sendingChainKey = rkResult.chainKey;

        session.sendingMessageCounter = 0;
        session.pendingRemoteDH = false;
        secureWipe(dhOutput);
    }

    // Message key from the sending chain, then advance the chain.
    ByteVector messageKey = messageKeyFromChain(session.sendingChainKey);
    session.sendingChainKey = ratchetChainKey(session.sendingChainKey);

    outMetadata.messageCounter = session.sendingMessageCounter++;
    outMetadata.senderPublicKey = session.dhSendingPublicKey;
    outMetadata.timestamp = static_cast<uint32_t>(time(nullptr));
    outMetadata.iv = randomVector(kGcmIvSize);
    if (outMetadata.iv.empty()) {
        secureWipe(messageKey);
        return {};
    }

    outAad = messageAad(outMetadata);
    return messageKey;
}

ByteVector encryptMessage(
        SessionState &session,
        const ByteVector &plaintext,
        MessageMetadata &outMetadata) {
    ByteVector aad;
    ByteVector messageKey = beginMessage(session, outMetadata, aad);
    if (messageKey.empty()) {
        return {};
    }

    ByteVector ciphertext = aesGcmEncrypt(messageKey, outMetadata.iv, plaintext, aad);
    secureWipe(messageKey);
    if (ciphertext.empty()) {
        return {};
    }
    return ciphertext;
}

ByteVector decryptMessage(
        SessionState &session,
        const ByteVector &ciphertextWithTag,
        const MessageMetadata &metadata) {
    // DH ratchet: check if the sender's DH key has changed.
    const bool dhChanged =
        (metadata.senderPublicKey != session.dhRemotePublicKey)
        && !metadata.senderPublicKey.empty()
        && !session.dhRemotePublicKey.empty();

    if (dhChanged) {
        session.previousSendingChainLength = session.receivingMessageCounter;
        session.dhRemotePublicKey = metadata.senderPublicKey;

        const auto rotated = generateDhKeyPair();
        if (rotated.privateKey.empty()) return {};

        // First KDF_RK: new root key + receiving chain key.
        auto dhOutput1 = x25519(rotated.privateKey, session.dhRemotePublicKey);
        const auto rkResult1 = kdfRk(session.rootKey, dhOutput1);
        session.rootKey = rkResult1.rootKey;
        session.receivingChainKey = rkResult1.chainKey;

        // Second KDF_RK: new root key + sending chain key.
        auto dhOutput2 = x25519(rotated.privateKey, session.dhRemotePublicKey);
        const auto rkResult2 = kdfRk(session.rootKey, dhOutput2);
        session.rootKey = rkResult2.rootKey;
        session.sendingChainKey = rkResult2.chainKey;

        session.dhSendingPrivateKey = rotated.privateKey;
        session.dhSendingPublicKey = rotated.publicKey;

        session.receivingMessageCounter = 0;
        session.sendingMessageCounter = 0;

        for (auto &skipped : session.skippedMessageKeys) {
            secureWipe(skipped.key);
        }
        session.skippedMessageKeys.clear();

        secureWipe(dhOutput1);
        secureWipe(dhOutput2);
    }

    ByteVector messageKey;
    if (metadata.messageCounter == session.receivingMessageCounter) {
        // Expected message — derive key from the current chain and advance.
        messageKey = messageKeyFromChain(session.receivingChainKey);
        session.receivingChainKey = ratchetChainKey(session.receivingChainKey);
        session.receivingMessageCounter++;
    } else if (metadata.messageCounter > session.receivingMessageCounter) {
        // Future message — catch up and store the skipped keys.
        if (metadata.messageCounter - session.receivingMessageCounter > kMaxSkipAhead) {
            return {};
        }

        ByteVector currentChainKey = session.receivingChainKey;
        uint32_t currentCounter = session.receivingMessageCounter;
        while (currentCounter < metadata.messageCounter) {
            SessionState::SkippedKey skip;
            skip.messageNumber = currentCounter;
            skip.key = messageKeyFromChain(currentChainKey);
            session.skippedMessageKeys.push_back(std::move(skip));

            if (session.skippedMessageKeys.size() > kMaxSkippedKeys) {
                secureWipe(session.skippedMessageKeys.front().key);
                session.skippedMessageKeys.erase(session.skippedMessageKeys.begin());
            }

            currentChainKey = ratchetChainKey(currentChainKey);
            currentCounter++;
        }

        messageKey = messageKeyFromChain(currentChainKey);
        session.receivingChainKey = ratchetChainKey(currentChainKey);
        session.receivingMessageCounter = currentCounter + 1;
    } else {
        // Old message — check the skipped-key store.
        const auto it = std::find_if(
            session.skippedMessageKeys.begin(),
            session.skippedMessageKeys.end(),
            [&](const SessionState::SkippedKey &key) {
                return key.messageNumber == metadata.messageCounter;
            });
        if (it == session.skippedMessageKeys.end()) {
            return {};
        }
        messageKey = it->key;
        session.skippedMessageKeys.erase(it);
    }

    const ByteVector aad = messageAad(metadata);
    ByteVector plaintext = aesGcmDecrypt(messageKey, metadata.iv, ciphertextWithTag, aad);
    secureWipe(messageKey);
    if (plaintext.empty()) {
        return {};
    }
    return plaintext;
}

// desktop rotateSession (forceRotate path)
bool rotateSession(SessionState &session) {
    if (session.dhRemotePublicKey.empty()) return false;

    const auto rotated = generateDhKeyPair();
    if (rotated.privateKey.empty()) return false;

    session.previousSendingChainLength = session.sendingMessageCounter;

    auto dhResult = x25519(rotated.privateKey, session.dhRemotePublicKey);
    const auto rkResult = kdfRk(session.rootKey, dhResult);
    session.rootKey = rkResult.rootKey;
    session.sendingChainKey = rkResult.chainKey;

    // Desktop derives 64 bytes with kInfoChainKey and takes the SECOND
    // half as the receiving chain key.
    const auto chainKeyData = hkdfExpandSha256(
        session.rootKey,
        kInfoChainKey,
        kAesKeySize * 2);
    if (chainKeyData.size() == kAesKeySize * 2) {
        session.receivingChainKey.assign(
            chainKeyData.begin() + kAesKeySize,
            chainKeyData.begin() + (kAesKeySize * 2));
    }

    session.dhSendingPrivateKey = rotated.privateKey;
    session.dhSendingPublicKey = rotated.publicKey;
    session.sendingMessageCounter = 0;
    session.receivingMessageCounter = 0;

    secureWipe(dhResult);
    return true;
}

// ---------------------------------------------------------------------------
// Post-quantum KEM (ML-KEM, desktop QuantumGuard / PQE1 parity)
//
// Dual backend, chosen at compile time (see InteropCore.h): provider-native
// ML-KEM EVP keys on OpenSSL 3.5+ (host tests), the low-level mlkem.h API on
// the in-tree BoringSSL (Android device builds).
// ---------------------------------------------------------------------------

namespace {

// DER definite-length writer (1 tag byte + up to 2 length bytes — enough for
// every ML-KEM SPKI element).
void derPushTagAndLength(ByteVector &out, uint8_t tag, size_t length) {
    out.push_back(tag);
    if (length < 0x80) {
        out.push_back(static_cast<uint8_t>(length));
    } else if (length <= 0xFF) {
        out.push_back(0x81);
        out.push_back(static_cast<uint8_t>(length));
    } else {
        out.push_back(0x82);
        out.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(length & 0xFF));
    }
}

// DER definite-length reader; pos sits on the length byte and advances past
// it. Limited to 2 length bytes (max 65535) — SPKI sizes only.
bool derReadLength(const ByteVector &der, size_t &pos, size_t &length) {
    if (pos + 1 > der.size()) return false;
    const uint8_t first = der[pos++];
    if (first < 0x80) {
        length = first;
        return true;
    }
    const size_t count = (first & 0x7F);
    if (count > 2 || count > der.size() - pos) return false;
    length = 0;
    for (size_t i = 0; i < count; ++i) {
        length = (length << 8) | der[pos++];
    }
    return true;
}

// DER content bytes of the RFC 9935 ML-KEM algorithm OIDs:
//   2.16.840.1.101.3.4.4.2 (id-ML-KEM-768), 2.16.840.1.101.3.4.4.3
//   (id-ML-KEM-1024) — 0x60 86 48 01 65 03 04 04 0{2,3}.
bool mlKemOidForParameterSet(int parameterSet, ByteVector &out) {
    static const uint8_t kOidPrefix[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04};
    switch (parameterSet) {
    case kMlKemParam768:
        out.assign(kOidPrefix, kOidPrefix + sizeof(kOidPrefix));
        out.push_back(0x02);
        return true;
    case kMlKemParam1024:
        out.assign(kOidPrefix, kOidPrefix + sizeof(kOidPrefix));
        out.push_back(0x03);
        return true;
    default:
        return false;
    }
}

bool mlKemRawSizeForParameterSet(int parameterSet, size_t &size) {
    switch (parameterSet) {
    case kMlKemParam768:
        size = kMlKem768PublicKeySize;
        return true;
    case kMlKemParam1024:
        size = kMlKem1024PublicKeySize;
        return true;
    default:
        return false;
    }
}

} // namespace

ByteVector buildMlKemSpkiDer(int parameterSet, const ByteVector &rawPublicKey) {
    ByteVector oid;
    size_t rawSize = 0;
    if (!mlKemOidForParameterSet(parameterSet, oid)
            || !mlKemRawSizeForParameterSet(parameterSet, rawSize)
            || rawPublicKey.size() != rawSize) {
        return {};
    }

    // AlgorithmIdentifier ::= SEQUENCE { algorithm OID }
    ByteVector algorithmIdentifier;
    derPushTagAndLength(algorithmIdentifier, 0x30, oid.size() + 2);
    derPushTagAndLength(algorithmIdentifier, 0x06, oid.size());
    algorithmIdentifier.insert(algorithmIdentifier.end(), oid.begin(), oid.end());

    // subjectPublicKey ::= BIT STRING — one leading 0x00 (0 unused bits).
    ByteVector bitString;
    derPushTagAndLength(bitString, 0x03, 1 + rawPublicKey.size());
    bitString.push_back(0x00);
    bitString.insert(bitString.end(), rawPublicKey.begin(), rawPublicKey.end());

    ByteVector out;
    derPushTagAndLength(
        out,
        0x30,
        algorithmIdentifier.size() + bitString.size());
    out.insert(out.end(), algorithmIdentifier.begin(), algorithmIdentifier.end());
    out.insert(out.end(), bitString.begin(), bitString.end());
    return out;
}

bool parseMlKemSpkiDer(
        const ByteVector &der,
        int &outParameterSet,
        ByteVector &outRawPublicKey) {
    outParameterSet = 0;
    outRawPublicKey.clear();
    if (der.size() < 2 || der[0] != 0x30) return false;

    size_t pos = 1;
    size_t len = 0;
    if (!derReadLength(der, pos, len) || len != der.size() - pos) {
        return false; // strict: no trailing bytes
    }

    // AlgorithmIdentifier ::= SEQUENCE { OID } — no optional parameters.
    if (pos >= der.size() || der[pos] != 0x30) return false;
    ++pos;
    if (!derReadLength(der, pos, len)) return false;
    const size_t algorithmEnd = pos + len;
    if (algorithmEnd > der.size()) return false;

    if (pos >= algorithmEnd || der[pos] != 0x06) return false;
    ++pos;
    if (!derReadLength(der, pos, len)) return false;
    if (len == 0 || pos + len != algorithmEnd) return false;
    ByteVector oid(der.begin() + pos, der.begin() + pos + len);
    pos = algorithmEnd;

    // subjectPublicKey ::= BIT STRING (0 unused bits).
    if (pos >= der.size() || der[pos] != 0x03) return false;
    ++pos;
    if (!derReadLength(der, pos, len)) return false;
    if (len < 1 || pos + len != der.size() || der[pos] != 0x00) return false;
    ++pos;
    ByteVector raw(der.begin() + pos, der.begin() + pos + (len - 1));

    int parameterSet = 0;
    ByteVector expectedOid;
    if (mlKemOidForParameterSet(kMlKemParam768, expectedOid) && oid == expectedOid) {
        parameterSet = kMlKemParam768;
    } else if (mlKemOidForParameterSet(kMlKemParam1024, expectedOid)
            && oid == expectedOid) {
        parameterSet = kMlKemParam1024;
    } else {
        return false;
    }

    size_t rawSize = 0;
    if (!mlKemRawSizeForParameterSet(parameterSet, rawSize)
            || raw.size() != rawSize) {
        return false;
    }

    outParameterSet = parameterSet;
    outRawPublicKey = std::move(raw);
    return true;
}

#if !defined(OPENSSL_IS_BORINGSSL)
// ---------------------------------------------------------------------------
// OpenSSL 3.5+ backend: provider-native ML-KEM EVP keys (host builds/tests).
// ---------------------------------------------------------------------------

namespace {

// Fills a KemKeyPair from an ML-KEM EVP key, taking ownership of pkey.
// Provider-native ML-KEM keys have no legacy NIDs, so the type check goes
// through EVP_PKEY_get0_type_name — never EVP_PKEY_get_base_id (desktop
// importPeerKemPublicKey convention).
KemKeyPair kemKeyPairFromEvp(EVP_PKEY *pkey) {
    KemKeyPair pair;
    if (!pkey) return pair;
    const auto *typeName = EVP_PKEY_get0_type_name(pkey);
    if (!typeName || std::strncmp(typeName, "ML-KEM", 6) != 0) {
        EVP_PKEY_free(pkey);
        return pair;
    }

    size_t rawLen = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &rawLen) != 1 || rawLen == 0) {
        EVP_PKEY_free(pkey);
        return pair;
    }
    pair.rawPublicKey.resize(rawLen);
    if (EVP_PKEY_get_raw_public_key(pkey, pair.rawPublicKey.data(), &rawLen) != 1) {
        pair.rawPublicKey.clear();
        EVP_PKEY_free(pkey);
        return pair;
    }

    unsigned char *spki = nullptr;
    const int spkiLen = i2d_PUBKEY(pkey, &spki);
    if (spkiLen <= 0 || !spki) {
        OPENSSL_free(spki);
        EVP_PKEY_free(pkey);
        return pair;
    }
    pair.publicKeyDer.assign(spki, spki + spkiLen);
    OPENSSL_free(spki);

    // i2d_PrivateKey yields the PKCS#8 PrivateKeyInfo for ML-KEM — the
    // persist-capable export (desktop QuantumGuard::saveKeys).
    unsigned char *privDer = nullptr;
    const int privLen = i2d_PrivateKey(pkey, &privDer);
    if (privLen <= 0 || !privDer) {
        OPENSSL_free(privDer);
        EVP_PKEY_free(pkey);
        return pair;
    }
    pair.privateKeyBlob.assign(privDer, privDer + privLen);
    OPENSSL_free(privDer);

    EVP_PKEY_free(pkey);
    return pair;
}

EVP_PKEY *kemPrivateFromBlob(const ByteVector &privateKeyBlob) {
    if (privateKeyBlob.empty()) return nullptr;
    const auto *der = privateKeyBlob.data();
    // d2i_AutoPrivateKey handles PKCS#8 (desktop QuantumGuard::loadKeys).
    return d2i_AutoPrivateKey(
        nullptr, &der, static_cast<long>(privateKeyBlob.size()));
}

} // namespace

KemKeyPair generateKemIdentity() {
    // desktop generateQuantumKey: EVP_PKEY_Q_keygen(nullptr, nullptr, algName)
    // with "ML-KEM-1024" (Android advertises the level-4 parameter set).
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-KEM-1024");
    return kemKeyPairFromEvp(pkey);
}

KemKeyPair kemIdentityFromPrivateBlob(const ByteVector &privateKeyBlob) {
    return kemKeyPairFromEvp(kemPrivateFromBlob(privateKeyBlob));
}

ByteVector importPeerKemRaw(const ByteVector &rawPublicKey) {
    // desktop ensureQuantumIdentity: infer the parameter set from the raw
    // size, import raw, export SPKI via i2d_PUBKEY.
    const int nid = rawPublicKey.size() > 1200
        ? NID_ML_KEM_1024
        : (rawPublicKey.size() > 800 ? NID_ML_KEM_768 : NID_ML_KEM_512);
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(
        nid, nullptr, rawPublicKey.data(), rawPublicKey.size());
    if (!pkey) return {};

    unsigned char *spki = nullptr;
    const int spkiLen = i2d_PUBKEY(pkey, &spki);
    EVP_PKEY_free(pkey);
    if (spkiLen <= 0 || !spki) {
        OPENSSL_free(spki);
        return {};
    }
    ByteVector result(spki, spki + spkiLen);
    OPENSSL_free(spki);
    return result;
}

KemEncapsulation kemEncapsulate(const ByteVector &peerPublicKeyDer) {
    KemEncapsulation result;
    if (peerPublicKeyDer.empty()) return result;

    const auto *der = peerPublicKeyDer.data();
    EVP_PKEY *pkey = d2i_PUBKEY(
        nullptr, &der, static_cast<long>(peerPublicKeyDer.size()));
    if (!pkey) return result;
    const auto *typeName = EVP_PKEY_get0_type_name(pkey);
    if (!typeName || std::strncmp(typeName, "ML-KEM", 6) != 0) {
        EVP_PKEY_free(pkey);
        return result;
    }

    // desktop quantumEncapsulate: two-call EVP_PKEY_encapsulate.
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    EVP_PKEY_free(pkey);
    if (!ctx) return result;

    size_t ciphertextLen = 0;
    size_t sharedLen = 0;
    if (EVP_PKEY_encapsulate_init(ctx, nullptr) != 1
            || EVP_PKEY_encapsulate(
                   ctx, nullptr, &ciphertextLen, nullptr, &sharedLen) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return result;
    }
    result.ciphertext.resize(ciphertextLen);
    result.sharedSecret.resize(sharedLen);
    const bool ok = EVP_PKEY_encapsulate(
                        ctx,
                        result.ciphertext.data(),
                        &ciphertextLen,
                        result.sharedSecret.data(),
                        &sharedLen) == 1;
    EVP_PKEY_CTX_free(ctx);
    if (!ok) {
        result.ciphertext.clear();
        secureWipe(result.sharedSecret);
    }
    return result;
}

ByteVector kemDecapsulate(
        const ByteVector &privateKeyBlob,
        const ByteVector &ciphertext) {
    if (ciphertext.empty()) return {};
    EVP_PKEY *pkey = kemPrivateFromBlob(privateKeyBlob);
    if (!pkey) return {};

    // desktop quantumDecapsulate: two-call EVP_PKEY_decapsulate.
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    EVP_PKEY_free(pkey);
    if (!ctx) return {};

    size_t sharedLen = 0;
    if (EVP_PKEY_decapsulate_init(ctx, nullptr) != 1
            || EVP_PKEY_decapsulate(
                   ctx, nullptr, &sharedLen,
                   ciphertext.data(), ciphertext.size()) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    ByteVector sharedSecret(sharedLen);
    const bool ok = EVP_PKEY_decapsulate(
                        ctx,
                        sharedSecret.data(),
                        &sharedLen,
                        ciphertext.data(),
                        ciphertext.size()) == 1;
    EVP_PKEY_CTX_free(ctx);
    if (!ok) return {};
    return sharedSecret;
}

#else // OPENSSL_IS_BORINGSSL
// ---------------------------------------------------------------------------
// BoringSSL backend (Android device builds): the in-tree BoringSSL ships
// ML-KEM only through the low-level openssl/mlkem.h API — no ML-KEM EVP
// integration — so keygen/encap/decap use MLKEM1024_* and SPKI DER is
// built/parsed with the pure helpers above (byte-identical to OpenSSL's
// i2d_PUBKEY output; cross-checked in the host test).
// ---------------------------------------------------------------------------

namespace {

// Android identities are always ML-KEM-1024; the persisted private blob is
// the 64-byte FIPS 203 seed.
bool kem1024PrivateFromSeed(
        const ByteVector &seed,
        MLKEM1024_private_key &out) {
    return seed.size() == kMlKemSeedSize
        && MLKEM1024_private_key_from_seed(&out, seed.data(), seed.size()) == 1;
}

} // namespace

KemKeyPair generateKemIdentity() {
    KemKeyPair pair;

    ByteVector rawPublicKey(kMlKem1024PublicKeySize);
    uint8_t seed[kMlKemSeedSize];
    MLKEM1024_private_key priv;
    MLKEM1024_generate_key(rawPublicKey.data(), seed, &priv);
    OPENSSL_cleanse(&priv, sizeof(priv));

    pair.privateKeyBlob.assign(seed, seed + sizeof(seed));
    OPENSSL_cleanse(seed, sizeof(seed));
    pair.rawPublicKey = std::move(rawPublicKey);
    pair.publicKeyDer = buildMlKemSpkiDer(kMlKemParam1024, pair.rawPublicKey);
    if (pair.publicKeyDer.empty()) {
        secureWipe(pair.privateKeyBlob);
        pair.rawPublicKey.clear();
    }
    return pair;
}

KemKeyPair kemIdentityFromPrivateBlob(const ByteVector &privateKeyBlob) {
    KemKeyPair pair;

    MLKEM1024_private_key priv;
    if (!kem1024PrivateFromSeed(privateKeyBlob, priv)) return pair;

    MLKEM1024_public_key pub;
    MLKEM1024_public_from_private(&pub, &priv);
    OPENSSL_cleanse(&priv, sizeof(priv));

    CBB cbb;
    uint8_t *raw = nullptr;
    size_t rawLen = 0;
    if (!CBB_init(&cbb, 0)
            || !MLKEM1024_marshal_public_key(&cbb, &pub)
            || !CBB_finish(&cbb, &raw, &rawLen)) {
        CBB_cleanup(&cbb);
        return pair;
    }
    pair.privateKeyBlob = privateKeyBlob;
    pair.rawPublicKey.assign(raw, raw + rawLen);
    OPENSSL_free(raw);
    pair.publicKeyDer = buildMlKemSpkiDer(kMlKemParam1024, pair.rawPublicKey);
    return pair;
}

ByteVector importPeerKemRaw(const ByteVector &rawPublicKey) {
    if (rawPublicKey.size() == kMlKem1024PublicKeySize) {
        return buildMlKemSpkiDer(kMlKemParam1024, rawPublicKey);
    }
    if (rawPublicKey.size() == kMlKem768PublicKeySize) {
        return buildMlKemSpkiDer(kMlKemParam768, rawPublicKey);
    }
    // ML-KEM-512 is not available in the in-tree BoringSSL (and desktop only
    // advertises 768/1024 on quantum levels 3+).
    return {};
}

KemEncapsulation kemEncapsulate(const ByteVector &peerPublicKeyDer) {
    KemEncapsulation result;

    int parameterSet = 0;
    ByteVector rawPublicKey;
    if (!parseMlKemSpkiDer(peerPublicKeyDer, parameterSet, rawPublicKey)) {
        return result;
    }

    CBS cbs;
    CBS_init(&cbs, rawPublicKey.data(), rawPublicKey.size());
    if (parameterSet == kMlKemParam1024) {
        MLKEM1024_public_key pub;
        if (MLKEM1024_parse_public_key(&pub, &cbs) != 1) return result;
        result.ciphertext.resize(kMlKem1024CiphertextSize);
        result.sharedSecret.resize(kMlKemSharedSecretSize);
        MLKEM1024_encap(
            result.ciphertext.data(),
            result.sharedSecret.data(),
            &pub);
    } else if (parameterSet == kMlKemParam768) {
        MLKEM768_public_key pub;
        if (MLKEM768_parse_public_key(&pub, &cbs) != 1) return result;
        result.ciphertext.resize(kMlKem768CiphertextSize);
        result.sharedSecret.resize(kMlKemSharedSecretSize);
        MLKEM768_encap(
            result.ciphertext.data(),
            result.sharedSecret.data(),
            &pub);
    }
    return result;
}

ByteVector kemDecapsulate(
        const ByteVector &privateKeyBlob,
        const ByteVector &ciphertext) {
    // The ciphertext length selects the parameter set: a ciphertext can only
    // be decapsulated with the key it was encapsulated against.
    if (ciphertext.size() == kMlKem1024CiphertextSize) {
        MLKEM1024_private_key priv;
        if (!kem1024PrivateFromSeed(privateKeyBlob, priv)) return {};
        ByteVector sharedSecret(kMlKemSharedSecretSize);
        if (MLKEM1024_decap(
                sharedSecret.data(),
                ciphertext.data(),
                ciphertext.size(),
                &priv) != 1) {
            return {};
        }
        return sharedSecret;
    }
    if (ciphertext.size() == kMlKem768CiphertextSize) {
        // Unreachable today (Android only advertises ML-KEM-1024), but a
        // mismatched set must fail cleanly: the same seed derives a different
        // 768 key and the symmetric layer rejects the result.
        MLKEM768_private_key priv;
        if (privateKeyBlob.size() != kMlKemSeedSize
                || MLKEM768_private_key_from_seed(
                       &priv,
                       privateKeyBlob.data(),
                       privateKeyBlob.size()) != 1) {
            return {};
        }
        ByteVector sharedSecret(kMlKemSharedSecretSize);
        if (MLKEM768_decap(
                sharedSecret.data(),
                ciphertext.data(),
                ciphertext.size(),
                &priv) != 1) {
            return {};
        }
        return sharedSecret;
    }
    return {};
}

#endif // OPENSSL_IS_BORINGSSL

ByteVector wrapPqe1(
        const ByteVector &peerPublicKeyDer,
        const ByteVector &plaintext) {
    KemEncapsulation encapsulation = kemEncapsulate(peerPublicKeyDer);
    if (encapsulation.sharedSecret.size() != kMlKemSharedSecretSize
            || encapsulation.ciphertext.empty()) {
        return {};
    }

    const auto iv = randomVector(kGcmIvSize);
    if (iv.empty()) {
        secureWipe(encapsulation.sharedSecret);
        return {};
    }

    // interop AES-GCM returns ciphertext||tag; the desktop envelope keeps
    // them as separate fields.
    const auto ciphertextWithTag = aesGcmEncrypt(
        encapsulation.sharedSecret, iv, plaintext, ByteVector());
    secureWipe(encapsulation.sharedSecret);
    if (ciphertextWithTag.size() < kGcmTagSize) return {};

    // FROZEN desktop layout (quantumWrapPayload):
    //   "PQE1" | u32 LE encapsulated length | encapsulated | iv(12)
    //   | tag(16) | ciphertext
    ByteVector out;
    out.reserve(
        8 + encapsulation.ciphertext.size()
        + kGcmIvSize + kGcmTagSize
        + (ciphertextWithTag.size() - kGcmTagSize));
    const uint8_t magic[] = {'P', 'Q', 'E', '1'};
    out.insert(out.end(), magic, magic + sizeof(magic));
    pushU32Le(out, static_cast<uint32_t>(encapsulation.ciphertext.size()));
    out.insert(
        out.end(),
        encapsulation.ciphertext.begin(),
        encapsulation.ciphertext.end());
    out.insert(out.end(), iv.begin(), iv.end());
    out.insert(out.end(), ciphertextWithTag.end() - kGcmTagSize, ciphertextWithTag.end());
    out.insert(
        out.end(),
        ciphertextWithTag.begin(),
        ciphertextWithTag.end() - kGcmTagSize);
    return out;
}

ByteVector unwrapPqe1(const ByteVector &privateKeyBlob, const ByteVector &blob) {
    constexpr size_t kHeaderSize = 4 + 4 + kGcmIvSize + kGcmTagSize;
    if (blob.size() <= kHeaderSize) return {};
    if (!isPqe1Envelope(blob)) return {};

    // desktop quantumUnwrapPayload: the length field is little-endian.
    const uint32_t encapLen = static_cast<uint32_t>(blob[4])
        | (static_cast<uint32_t>(blob[5]) << 8)
        | (static_cast<uint32_t>(blob[6]) << 16)
        | (static_cast<uint32_t>(blob[7]) << 24);
    if (encapLen == 0 || encapLen > 4096 || blob.size() < kHeaderSize + encapLen) {
        return {};
    }

    size_t pos = 8;
    ByteVector encapsulated(blob.begin() + pos, blob.begin() + pos + encapLen);
    pos += encapLen;
    ByteVector iv(blob.begin() + pos, blob.begin() + pos + kGcmIvSize);
    pos += kGcmIvSize;
    ByteVector tag(blob.begin() + pos, blob.begin() + pos + kGcmTagSize);
    pos += kGcmTagSize;
    ByteVector ciphertext(blob.begin() + pos, blob.end());

    ByteVector sharedSecret = kemDecapsulate(privateKeyBlob, encapsulated);
    if (sharedSecret.size() != kMlKemSharedSecretSize) return {};

    ByteVector ciphertextWithTag = ciphertext;
    ciphertextWithTag.insert(ciphertextWithTag.end(), tag.begin(), tag.end());
    const auto plaintext = aesGcmDecrypt(
        sharedSecret, iv, ciphertextWithTag, ByteVector());
    secureWipe(sharedSecret);
    return plaintext;
}

bool isPqe1Envelope(const ByteVector &data) {
    // desktop processIncomingMessage gate: size > 8 and the "PQE1" magic.
    return data.size() > 8
        && data[0] == static_cast<uint8_t>('P')
        && data[1] == static_cast<uint8_t>('Q')
        && data[2] == static_cast<uint8_t>('E')
        && data[3] == static_cast<uint8_t>('1');
}

// ---------------------------------------------------------------------------
// Ratcheted quantum sessions (desktop parity, see InteropCore.h)
// ---------------------------------------------------------------------------

namespace {

// desktop usableQuantumChain: hkdfExpandSha256 returns zero-filled output on
// some HKDF setup failures (silent in OpenSSL 3.x without the digest — the
// digest is always set here, but defensive); an all-zero chain is never a
// usable session key.
bool usableQuantumChain(const ByteVector &chain) {
    if (chain.size() != kAesKeySize) return false;
    for (const auto byte : chain) {
        if (byte != 0) return true;
    }
    return false;
}

// Chain advance: expand(PRK = qChain, "CryptogramQChainStep", 32).
ByteVector quantumChainStep(const ByteVector &chainKey) {
    return hkdfExpandSha256(chainKey, kInfoQuantumChainStep, kAesKeySize);
}

// Quantum message key: expand(PRK = qChain, "CryptogramQMessage", 32).
ByteVector quantumMessageKeyFromChain(const ByteVector &chainKey) {
    return hkdfExpandSha256(chainKey, kInfoQuantumMessage, kAesKeySize);
}

// Both chains from an agreed root, role-resolved: the INITIATOR sends on
// ChainA and receives on ChainB; the resolver swaps the labels.
void fillQuantumChains(
        QuantumSessionState &out,
        const ByteVector &root,
        bool initiator) {
    out.rootKey = root;
    out.sendChainKey = hkdfExpandSha256(root,
        initiator ? kInfoQuantumChainA : kInfoQuantumChainB, kAesKeySize);
    out.recvChainKey = hkdfExpandSha256(root,
        initiator ? kInfoQuantumChainB : kInfoQuantumChainA, kAesKeySize);
}

} // namespace

bool quantumSessionUsable(const QuantumSessionState &state) {
    return usableQuantumChain(state.rootKey)
        && usableQuantumChain(state.sendChainKey)
        && usableQuantumChain(state.recvChainKey);
}

bool establishQuantumSessionInitiator(
        QuantumSessionState &outState,
        const ByteVector &peerPublicKeyDer,
        ByteVector &outKemCiphertext) {
    outState = QuantumSessionState{};
    outKemCiphertext.clear();

    // REAL ML-KEM encapsulation: fresh shared secret + the ciphertext the
    // peer decapsulates with their static private key.
    auto encapsulation = kemEncapsulate(peerPublicKeyDer);
    if (encapsulation.sharedSecret.size() != kMlKemSharedSecretSize
            || encapsulation.ciphertext.empty()) {
        return false;
    }

    const auto root = hkdfExpandSha256(
        encapsulation.sharedSecret, kInfoQuantumRoot, kAesKeySize);
    secureWipe(encapsulation.sharedSecret);
    if (root.size() != kAesKeySize) return false;

    QuantumSessionState state;
    fillQuantumChains(state, root, true);
    if (!quantumSessionUsable(state)) return false;

    outState = std::move(state);
    outKemCiphertext = encapsulation.ciphertext;
    return true;
}

bool establishQuantumSessionResolver(
        QuantumSessionState &outState,
        const ByteVector &privateKeyBlob,
        const ByteVector &kemCiphertext) {
    outState = QuantumSessionState{};

    ByteVector sharedSecret = kemDecapsulate(privateKeyBlob, kemCiphertext);
    if (sharedSecret.size() != kMlKemSharedSecretSize) return false;

    const auto root = hkdfExpandSha256(
        sharedSecret, kInfoQuantumRoot, kAesKeySize);
    secureWipe(sharedSecret);
    if (root.size() != kAesKeySize) return false;

    QuantumSessionState state;
    fillQuantumChains(state, root, false);
    if (!quantumSessionUsable(state)) return false;

    outState = std::move(state);
    return true;
}

ByteVector quantumSessionWrap(
        QuantumSessionState &state,
        const ByteVector &plaintext,
        const ByteVector &iv,
        const ByteVector &aad) {
    if (!quantumSessionUsable(state) || iv.size() != kGcmIvSize) return {};

    // Derive the message key and advance the chain on a working copy; commit
    // only after the AEAD succeeded (desktop encryptQuantumSessionMessage).
    QuantumSessionState next = state;
    ByteVector messageKey = quantumMessageKeyFromChain(next.sendChainKey);
    next.sendChainKey = quantumChainStep(next.sendChainKey);
    if (messageKey.size() != kAesKeySize
            || next.sendChainKey.size() != kAesKeySize) {
        secureWipe(messageKey);
        return {};
    }

    ByteVector ciphertext = aesGcmEncrypt(messageKey, iv, plaintext, aad);
    secureWipe(messageKey);
    if (ciphertext.empty()) return {};

    next.sendCounter++;
    state = std::move(next);
    return ciphertext;
}

ByteVector quantumSessionUnwrap(
        QuantumSessionState &state,
        const ByteVector &payload,
        const ByteVector &iv,
        const ByteVector &aad,
        uint32_t counter) {
    if (!quantumSessionUsable(state) || iv.size() != kGcmIvSize) return {};

    // Work on a copy; the receive state advances only after a successful
    // unwrap (desktop quantumUnwrapSessionPayload).
    QuantumSessionState next = state;
    ByteVector messageKey;
    if (counter == next.recvCounter) {
        // Expected message — derive the quantum message key and advance.
        messageKey = quantumMessageKeyFromChain(next.recvChainKey);
        next.recvChainKey = quantumChainStep(next.recvChainKey);
        next.recvCounter++;
    } else if (counter > next.recvCounter) {
        // Future message — catch up, storing the skipped quantum keys exactly
        // like the classic layer stores its skipped message keys.
        if (counter - next.recvCounter > kMaxQuantumSkipAhead) return {};
        ByteVector currentChain = next.recvChainKey;
        uint32_t currentCounter = next.recvCounter;
        while (currentCounter < counter) {
            QuantumSessionState::SkippedKey skip;
            skip.messageNumber = currentCounter;
            skip.key = quantumMessageKeyFromChain(currentChain);
            next.skippedMessageKeys.push_back(std::move(skip));

            if (next.skippedMessageKeys.size() > kMaxSkippedKeys) {
                secureWipe(next.skippedMessageKeys.front().key);
                next.skippedMessageKeys.erase(next.skippedMessageKeys.begin());
            }

            currentChain = quantumChainStep(currentChain);
            currentCounter++;
        }
        messageKey = quantumMessageKeyFromChain(currentChain);
        next.recvChainKey = quantumChainStep(currentChain);
        next.recvCounter = currentCounter + 1;
    } else {
        // Old message — check the skipped quantum key store.
        const auto it = std::find_if(
            next.skippedMessageKeys.begin(),
            next.skippedMessageKeys.end(),
            [&](const QuantumSessionState::SkippedKey &key) {
                return key.messageNumber == counter;
            });
        if (it == next.skippedMessageKeys.end()) return {};
        messageKey = it->key;
        next.skippedMessageKeys.erase(it);
    }

    if (messageKey.size() != kAesKeySize) {
        secureWipe(messageKey);
        return {};
    }

    ByteVector plaintext = aesGcmDecrypt(messageKey, iv, payload, aad);
    secureWipe(messageKey);
    if (plaintext.empty()) return {};

    state = std::move(next);
    return plaintext;
}

// ---------------------------------------------------------------------------
// At-rest persistence
// ---------------------------------------------------------------------------

namespace {

// Refuse absurd files up front (a valid identity file is ~1 KB; a session
// file with kMaxSkippedKeys entries stays well under this cap).
constexpr size_t kMaxPersistenceFileSize = 8 * 1024 * 1024;

bool readFileCapped(const std::string &filePath, size_t cap, ByteVector &out) {
    out.clear();
    FILE *file = fopen(filePath.c_str(), "rb");
    if (!file) return false;

    bool ok = true;
    ByteVector data;
    if (fseek(file, 0, SEEK_END) == 0) {
        const long size = ftell(file);
        if (size >= 0 && static_cast<size_t>(size) <= cap) {
            data.resize(static_cast<size_t>(size));
            if (size > 0) {
                rewind(file);
                ok = fread(data.data(), 1, data.size(), file) == data.size();
            }
        } else {
            ok = false;
        }
    } else {
        ok = false;
    }
    fclose(file);

    if (!ok) return false;
    out.swap(data);
    return true;
}

// Write to "<path>.tmp" then rename over the target: a crash mid-write can
// never leave a half-written file in place of a good one.
bool writeFileAtomic(const std::string &filePath, const ByteVector &data) {
    const std::string tmpPath = filePath + ".tmp";
    FILE *file = fopen(tmpPath.c_str(), "wb");
    if (!file) return false;

    const bool wrote = data.empty()
        || fwrite(data.data(), 1, data.size(), file) == data.size();
    const bool closed = (fclose(file) == 0);
    if (!wrote || !closed) {
        remove(tmpPath.c_str());
        return false;
    }
    if (rename(tmpPath.c_str(), filePath.c_str()) != 0) {
        remove(tmpPath.c_str());
        return false;
    }
    return true;
}

// Create every missing directory component of the file's path (progressive
// left-to-right, so EEXIST is the only tolerated "error"). POSIX — fine on
// Linux hosts and Android alike.
bool ensureParentDirectory(const std::string &filePath) {
    for (size_t i = 0; i < filePath.size(); ++i) {
        if (filePath[i] != '/' || i == 0) continue;
        const std::string dir = filePath.substr(0, i);
        if (mkdir(dir.c_str(), 0755) != 0 && errno != EEXIST) return false;
    }
    return true;
}

void jsonEscapeInto(const std::string &value, std::string &out) {
    out.push_back('"');
    for (const char raw : value) {
        const unsigned char c = static_cast<unsigned char>(raw);
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                static const char kHex[] = "0123456789abcdef";
                out += "\\u00";
                out.push_back(kHex[(c >> 4) & 0xF]);
                out.push_back(kHex[c & 0xF]);
            } else {
                out.push_back(raw);
            }
        }
    }
    out.push_back('"');
}

std::string jsonQuote(const std::string &value) {
    std::string out;
    out.reserve(value.size() + 2);
    jsonEscapeInto(value, out);
    return out;
}

std::string base64String(const ByteVector &data) {
    const auto encoded = base64Encode(data);
    return std::string(encoded.begin(), encoded.end());
}

// Minimal strict JSON for the persistence documents: objects, arrays,
// strings (standard escapes), numbers (kept as raw token text so 64-bit
// values survive exactly), true/false, null. Depth-capped.
struct JsonValue {
    enum Type { Null, Boolean, Number, String, Array, Object };
    Type type = Null;
    bool boolean = false;
    std::string numberText;
    std::string stringValue;
    std::vector<JsonValue> array;
    std::vector<std::pair<std::string, JsonValue>> members;

    const JsonValue *find(const char *key) const {
        if (type != Object) return nullptr;
        for (const auto &member : members) {
            if (member.first == key) return &member.second;
        }
        return nullptr;
    }

    bool getString(const char *key, std::string &out) const {
        const JsonValue *value = find(key);
        if (!value || value->type != String) return false;
        out = value->stringValue;
        return true;
    }

    // Exact unsigned parse of the raw number token (no double round-trip —
    // registrationId spans the full uint64 range).
    bool getUint(const char *key, uint64_t &out) const {
        const JsonValue *value = find(key);
        if (!value || value->type != Number) return false;
        const std::string &text = value->numberText;
        if (text.empty() || text.size() > 20) return false;
        for (const char c : text) {
            if (c < '0' || c > '9') return false;
        }
        errno = 0;
        char *end = nullptr;
        const unsigned long long parsed = strtoull(text.c_str(), &end, 10);
        if (errno != 0 || !end || *end != '\0') return false;
        out = static_cast<uint64_t>(parsed);
        return true;
    }

    bool getBool(const char *key, bool &out) const {
        const JsonValue *value = find(key);
        if (!value || value->type != Boolean) return false;
        out = value->boolean;
        return true;
    }
};

class JsonParser {
public:
    explicit JsonParser(const std::string &text)
        : data_(text.data()), size_(text.size()) {
    }

    bool parse(JsonValue &out) {
        skipWhitespace();
        if (!parseValue(out, 0)) return false;
        skipWhitespace();
        return pos_ >= size_; // strict: no trailing content
    }

private:
    static constexpr int kMaxDepth = 32;

    void skipWhitespace() {
        while (pos_ < size_) {
            const char c = data_[pos_];
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') break;
            ++pos_;
        }
    }

    bool consume(char c) {
        if (pos_ < size_ && data_[pos_] == c) {
            ++pos_;
            return true;
        }
        return false;
    }

    bool parseValue(JsonValue &out, int depth) {
        if (depth > kMaxDepth || pos_ >= size_) return false;
        switch (data_[pos_]) {
        case '{': return parseObject(out, depth);
        case '[': return parseArray(out, depth);
        case '"': return parseString(out);
        case 't': return parseLiteral(out, "true", JsonValue::Boolean, true);
        case 'f': return parseLiteral(out, "false", JsonValue::Boolean, false);
        case 'n': return parseNull(out);
        default: return parseNumber(out);
        }
    }

    bool parseLiteral(JsonValue &out, const char *literal, JsonValue::Type type, bool flag) {
        const size_t len = std::strlen(literal);
        if (pos_ + len > size_ || std::memcmp(data_ + pos_, literal, len) != 0) {
            return false;
        }
        pos_ += len;
        out = JsonValue();
        out.type = type;
        out.boolean = flag;
        return true;
    }

    bool parseNull(JsonValue &out) {
        return parseLiteral(out, "null", JsonValue::Null, false);
    }

    bool parseNumber(JsonValue &out) {
        const size_t start = pos_;
        while (pos_ < size_) {
            const char c = data_[pos_];
            if ((c >= '0' && c <= '9') || c == '-' || c == '+'
                    || c == '.' || c == 'e' || c == 'E') {
                ++pos_;
            } else {
                break;
            }
        }
        if (pos_ == start) return false;
        out = JsonValue();
        out.type = JsonValue::Number;
        out.numberText.assign(data_ + start, pos_ - start);
        return true;
    }

    bool parseString(JsonValue &out) {
        if (!consume('"')) return false;
        std::string value;
        while (pos_ < size_) {
            const char c = data_[pos_++];
            if (c == '"') {
                out = JsonValue();
                out.type = JsonValue::String;
                out.stringValue = std::move(value);
                return true;
            }
            if (static_cast<unsigned char>(c) < 0x20) return false;
            if (c != '\\') {
                value.push_back(c);
                continue;
            }
            if (pos_ >= size_) return false;
            const char escape = data_[pos_++];
            switch (escape) {
            case '"': value.push_back('"'); break;
            case '\\': value.push_back('\\'); break;
            case '/': value.push_back('/'); break;
            case 'b': value.push_back('\b'); break;
            case 'f': value.push_back('\f'); break;
            case 'n': value.push_back('\n'); break;
            case 'r': value.push_back('\r'); break;
            case 't': value.push_back('\t'); break;
            case 'u': {
                uint32_t cp = 0;
                if (!readHex4(cp)) return false;
                // Encode as UTF-8. (The persistence documents carry only
                // ASCII payloads; surrogate pairs are not produced.)
                if (cp < 0x80) {
                    value.push_back(static_cast<char>(cp));
                } else if (cp < 0x800) {
                    value.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                    value.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                } else {
                    value.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                    value.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                    value.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                }
                break;
            }
            default: return false;
            }
        }
        return false;
    }

    bool readHex4(uint32_t &out) {
        if (pos_ + 4 > size_) return false;
        uint32_t value = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = data_[pos_++];
            value <<= 4;
            if (c >= '0' && c <= '9') {
                value |= static_cast<uint32_t>(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                value |= static_cast<uint32_t>(c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                value |= static_cast<uint32_t>(c - 'A' + 10);
            } else {
                return false;
            }
        }
        out = value;
        return true;
    }

    bool parseArray(JsonValue &out, int depth) {
        if (!consume('[')) return false;
        out = JsonValue();
        out.type = JsonValue::Array;
        skipWhitespace();
        if (consume(']')) return true;
        while (true) {
            skipWhitespace();
            JsonValue item;
            if (!parseValue(item, depth + 1)) return false;
            out.array.push_back(std::move(item));
            skipWhitespace();
            if (consume(']')) return true;
            if (!consume(',')) return false;
        }
    }

    bool parseObject(JsonValue &out, int depth) {
        if (!consume('{')) return false;
        out = JsonValue();
        out.type = JsonValue::Object;
        skipWhitespace();
        if (consume('}')) return true;
        while (true) {
            skipWhitespace();
            JsonValue key;
            if (!parseString(key)) return false;
            skipWhitespace();
            if (!consume(':')) return false;
            skipWhitespace();
            JsonValue value;
            if (!parseValue(value, depth + 1)) return false;
            out.members.emplace_back(std::move(key.stringValue), std::move(value));
            skipWhitespace();
            if (consume('}')) return true;
            if (!consume(',')) return false;
        }
    }

    const char *data_ = nullptr;
    size_t size_ = 0;
    size_t pos_ = 0;
};

bool jsonParse(const std::string &text, JsonValue &out) {
    JsonParser parser(text);
    return parser.parse(out);
}

// Binds the encrypted private-key bundle to the stored public fields and
// registrationId (the desktop binds nothing; see the header schema note).
ByteVector identityAad(
        const ByteVector &identityPublic,
        const ByteVector &x25519IdentityPublic,
        const ByteVector &signedPreKeyPublic,
        const ByteVector &oneTimePreKeyPublic,
        const std::string &registrationId) {
    const std::string text =
        "cryptogram-identity-v2|" + registrationId
        + "|" + base64String(identityPublic)
        + "|" + base64String(x25519IdentityPublic)
        + "|" + base64String(signedPreKeyPublic)
        + "|" + base64String(oneTimePreKeyPublic);
    return ByteVector(text.begin(), text.end());
}

std::string serializeSessionJson(
        const SessionState &state,
        uint32_t specGeneration) {
    std::string o;
    o.reserve(512 + state.skippedMessageKeys.size() * 96);
    o += "{";
    o += "\"version\":" + std::to_string(kSessionFileFormatVersion) + ",";
    o += "\"specGeneration\":" + std::to_string(specGeneration) + ",";
    o += "\"rootKey\":" + jsonQuote(base64String(state.rootKey)) + ",";
    o += "\"sendingChainKey\":" + jsonQuote(base64String(state.sendingChainKey)) + ",";
    o += "\"receivingChainKey\":" + jsonQuote(base64String(state.receivingChainKey)) + ",";
    o += "\"dhSendingPrivate\":" + jsonQuote(base64String(state.dhSendingPrivateKey)) + ",";
    o += "\"dhSendingPublic\":" + jsonQuote(base64String(state.dhSendingPublicKey)) + ",";
    o += "\"dhRemotePublic\":" + jsonQuote(base64String(state.dhRemotePublicKey)) + ",";
    o += "\"remoteIdentityKey\":" + jsonQuote(base64String(state.remoteIdentityKey)) + ",";
    o += "\"remoteX25519IdentityKey\":" + jsonQuote(base64String(state.remoteX25519IdentityKey)) + ",";
    o += "\"sendingCounter\":" + std::to_string(state.sendingMessageCounter) + ",";
    o += "\"receivingCounter\":" + std::to_string(state.receivingMessageCounter) + ",";
    o += "\"previousChainLength\":" + std::to_string(state.previousSendingChainLength) + ",";
    o += std::string("\"pendingRemoteDH\":") + (state.pendingRemoteDH ? "true" : "false") + ",";
    o += "\"skippedKeys\":[";
    bool first = true;
    for (const auto &skipped : state.skippedMessageKeys) {
        if (!first) o += ",";
        first = false;
        o += "{\"messageNumber\":" + std::to_string(skipped.messageNumber);
        o += ",\"key\":" + jsonQuote(base64String(skipped.key)) + "}";
    }
    o += "]}";
    return o;
}

bool parseFixedKey(const JsonValue &object, const char *key, ByteVector &out) {
    std::string text;
    if (!object.getString(key, text)) return false;
    ByteVector value;
    if (!base64Decode(text, value) || value.size() != kKeySize) return false;
    out = std::move(value);
    return true;
}

bool parseSessionJson(
        const std::string &json,
        SessionState &outState,
        uint32_t &specGenerationOut) {
    JsonValue root;
    if (!jsonParse(json, root) || root.type != JsonValue::Object) return false;

    uint64_t version = 0;
    if (!root.getUint("version", version)
            || version != kSessionFileFormatVersion) {
        return false;
    }
    uint64_t specGeneration = 0;
    if (!root.getUint("specGeneration", specGeneration)
            || specGeneration > 0xFFFFFFFFull) {
        return false;
    }

    SessionState state;
    if (!parseFixedKey(root, "rootKey", state.rootKey)) return false;
    if (!parseFixedKey(root, "sendingChainKey", state.sendingChainKey)) return false;
    if (!parseFixedKey(root, "receivingChainKey", state.receivingChainKey)) return false;
    if (!parseFixedKey(root, "dhSendingPrivate", state.dhSendingPrivateKey)) return false;
    if (!parseFixedKey(root, "dhSendingPublic", state.dhSendingPublicKey)) return false;
    if (!parseFixedKey(root, "dhRemotePublic", state.dhRemotePublicKey)) return false;
    if (!parseFixedKey(root, "remoteIdentityKey", state.remoteIdentityKey)) return false;
    if (!parseFixedKey(root, "remoteX25519IdentityKey", state.remoteX25519IdentityKey)) return false;

    uint64_t counter = 0;
    if (!root.getUint("sendingCounter", counter) || counter > 0xFFFFFFFFull) return false;
    state.sendingMessageCounter = static_cast<uint32_t>(counter);
    if (!root.getUint("receivingCounter", counter) || counter > 0xFFFFFFFFull) return false;
    state.receivingMessageCounter = static_cast<uint32_t>(counter);
    if (!root.getUint("previousChainLength", counter) || counter > 0xFFFFFFFFull) return false;
    state.previousSendingChainLength = static_cast<uint32_t>(counter);

    if (!root.getBool("pendingRemoteDH", state.pendingRemoteDH)) return false;

    const JsonValue *skipped = root.find("skippedKeys");
    if (!skipped || skipped->type != JsonValue::Array) return false;
    for (const auto &entry : skipped->array) {
        if (entry.type != JsonValue::Object) return false;
        SessionState::SkippedKey key;
        if (!entry.getUint("messageNumber", counter) || counter > 0xFFFFFFFFull) return false;
        key.messageNumber = static_cast<uint32_t>(counter);
        if (!parseFixedKey(entry, "key", key.key)) return false;
        state.skippedMessageKeys.push_back(std::move(key));
    }

    specGenerationOut = static_cast<uint32_t>(specGeneration);
    outState = std::move(state);
    return true;
}

bool parseRegistrationId(const std::string &text, uint64_t &out) {
    if (text.empty() || text.size() > 20) return false;
    for (const char c : text) {
        if (c < '0' || c > '9') return false;
    }
    errno = 0;
    char *end = nullptr;
    const unsigned long long parsed = strtoull(text.c_str(), &end, 10);
    if (errno != 0 || !end || *end != '\0') return false;
    out = static_cast<uint64_t>(parsed);
    return true;
}

} // namespace

// Base64 (RFC 4648, standard alphabet with '=' padding).
ByteVector base64Encode(const ByteVector &data) {
    static const char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 3 <= data.size(); i += 3) {
        const uint32_t group = (static_cast<uint32_t>(data[i]) << 16)
            | (static_cast<uint32_t>(data[i + 1]) << 8)
            | static_cast<uint32_t>(data[i + 2]);
        out.push_back(kAlphabet[(group >> 18) & 0x3F]);
        out.push_back(kAlphabet[(group >> 12) & 0x3F]);
        out.push_back(kAlphabet[(group >> 6) & 0x3F]);
        out.push_back(kAlphabet[group & 0x3F]);
    }
    const size_t remaining = data.size() - i;
    if (remaining == 1) {
        const uint32_t group = static_cast<uint32_t>(data[i]) << 16;
        out.push_back(kAlphabet[(group >> 18) & 0x3F]);
        out.push_back(kAlphabet[(group >> 12) & 0x3F]);
        out.push_back('=');
        out.push_back('=');
    } else if (remaining == 2) {
        const uint32_t group = (static_cast<uint32_t>(data[i]) << 16)
            | (static_cast<uint32_t>(data[i + 1]) << 8);
        out.push_back(kAlphabet[(group >> 18) & 0x3F]);
        out.push_back(kAlphabet[(group >> 12) & 0x3F]);
        out.push_back(kAlphabet[(group >> 6) & 0x3F]);
        out.push_back('=');
    }
    return ByteVector(out.begin(), out.end());
}

bool base64Decode(const std::string &text, ByteVector &out) {
    out.clear();
    static const int8_t kReverse[256] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, // + /
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, // 0-9
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,           // A-O
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, // P-Z
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, // a-o
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, // p-z
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    };

    if (text.size() % 4 != 0) return false;
    if (text.empty()) return true; // valid encoding of empty input

    // Padding may only appear as trailing '=' inside the final group.
    size_t padding = 0;
    bool paddingSeen = false;
    for (const char raw : text) {
        const unsigned char c = static_cast<unsigned char>(raw);
        if (c == '=') {
            paddingSeen = true;
            ++padding;
        } else {
            if (paddingSeen) return false; // data after padding
            if (kReverse[c] < 0) return false;
        }
    }
    if (padding > 2) return false;

    out.reserve((text.size() / 4) * 3);
    uint32_t group = 0;
    int groupSize = 0;
    for (const char raw : text) {
        if (raw == '=') break;
        group = (group << 6)
            | static_cast<uint32_t>(kReverse[static_cast<unsigned char>(raw)]);
        if (++groupSize == 4) {
            out.push_back(static_cast<uint8_t>((group >> 16) & 0xFF));
            out.push_back(static_cast<uint8_t>((group >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(group & 0xFF));
            group = 0;
            groupSize = 0;
        }
    }
    if (groupSize == 2) {
        out.push_back(static_cast<uint8_t>((group >> 4) & 0xFF));
    } else if (groupSize == 3) {
        out.push_back(static_cast<uint8_t>((group >> 10) & 0xFF));
        out.push_back(static_cast<uint8_t>((group >> 2) & 0xFF));
    } else if (groupSize != 0) {
        out.clear();
        return false;
    }
    return true;
}

// desktop encryptWithPBKDF2 key derivation (PKCS5_PBKDF2_HMAC is available
// in both OpenSSL and BoringSSL; only the parameter types differ slightly).
ByteVector pbkdf2Sha256(
        const std::string &password,
        const ByteVector &salt,
        uint32_t iterations,
        size_t length) {
    if (length == 0 || length > 0x7FFFFFFF) return {};
    ByteVector output(length, 0);
    const int ok = PKCS5_PBKDF2_HMAC(
        password.c_str(),
        static_cast<int>(password.size()),
        salt.empty() ? nullptr : salt.data(),
        static_cast<int>(salt.size()),
        static_cast<int>(iterations),
        EVP_sha256(),
        static_cast<int>(length),
        output.data());
    if (ok != 1) {
        secureWipe(output);
        return {};
    }
    return output;
}

ByteVector encryptWithPbkdf2(
        const ByteVector &plaintext,
        const std::string &password,
        const ByteVector &aad) {
    if (password.empty()) return {};

    ByteVector salt;
    ByteVector iv;
    {
        salt = randomVector(kPbkdf2SaltSize);
        iv = randomVector(kGcmIvSize);
        if (salt.empty() || iv.empty()) return {};
    }
    auto key = pbkdf2Sha256(password, salt, kPbkdf2Iterations, kAesKeySize);
    if (key.empty()) return {};

    const auto ciphertext = aesGcmEncrypt(key, iv, plaintext, aad);
    secureWipe(key);
    if (ciphertext.empty()) return {};

    // salt(32) || iv(12) || ciphertext||tag — desktop blob layout.
    ByteVector blob;
    blob.reserve(salt.size() + iv.size() + ciphertext.size());
    blob.insert(blob.end(), salt.begin(), salt.end());
    blob.insert(blob.end(), iv.begin(), iv.end());
    blob.insert(blob.end(), ciphertext.begin(), ciphertext.end());
    return blob;
}

bool decryptWithPbkdf2(
        const ByteVector &blob,
        const std::string &password,
        const ByteVector &aad,
        ByteVector &out) {
    out.clear();
    if (password.empty()) return false;
    // Minimum: salt(32) + iv(12) + tag(16) — the desktop's magic 60.
    if (blob.size() < kPbkdf2SaltSize + kGcmIvSize + kGcmTagSize) return false;

    const ByteVector salt(blob.begin(), blob.begin() + kPbkdf2SaltSize);
    const ByteVector iv(blob.begin() + kPbkdf2SaltSize, blob.begin() + kPbkdf2SaltSize + kGcmIvSize);
    const ByteVector ciphertext(blob.begin() + kPbkdf2SaltSize + kGcmIvSize, blob.end());

    auto key = pbkdf2Sha256(password, salt, kPbkdf2Iterations, kAesKeySize);
    if (key.empty()) return false;
    auto plaintext = aesGcmDecrypt(key, iv, ciphertext, aad);
    secureWipe(key);
    if (plaintext.empty()) return false;
    out = std::move(plaintext);
    return true;
}

ByteVector ed25519PublicFromSeed(const ByteVector &seed) {
    ByteVector result(kKeySize, 0);
    if (seed.size() != kEd25519SeedSize) return result;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519,
        nullptr,
        seed.data(),
        seed.size());
    if (!pkey) return result;

    size_t len = kKeySize;
    if (EVP_PKEY_get_raw_public_key(pkey, result.data(), &len) != 1
            || len != kKeySize) {
        std::fill(result.begin(), result.end(), static_cast<uint8_t>(0));
    }
    EVP_PKEY_free(pkey);
    return result;
}

bool saveIdentity(
        const LocalIdentity &identity,
        const std::string &filePath,
        const std::string &password) {
    if (!identity.initialized || filePath.empty() || password.empty()) return false;
    if (identity.ed25519PrivateSeed.size() != kEd25519SeedSize
            || identity.ed25519Public.size() != kKeySize
            || identity.x25519IdentityPrivate.size() != kKeySize
            || identity.x25519IdentityPublic.size() != kKeySize
            || identity.signedPreKeyPrivate.size() != kKeySize
            || identity.signedPreKeyPublic.size() != kKeySize
            || identity.oneTimePreKeyPrivate.size() != kKeySize
            || identity.oneTimePreKeyPublic.size() != kKeySize) {
        return false;
    }

    // Private material wrapped as one blob: seed || xid || spk || opk.
    ByteVector privates;
    privates.reserve(4 * kKeySize);
    privates.insert(privates.end(), identity.ed25519PrivateSeed.begin(), identity.ed25519PrivateSeed.end());
    privates.insert(privates.end(), identity.x25519IdentityPrivate.begin(), identity.x25519IdentityPrivate.end());
    privates.insert(privates.end(), identity.signedPreKeyPrivate.begin(), identity.signedPreKeyPrivate.end());
    privates.insert(privates.end(), identity.oneTimePreKeyPrivate.begin(), identity.oneTimePreKeyPrivate.end());

    const std::string registrationId = std::to_string(identity.registrationId);
    const ByteVector aad = identityAad(
        identity.ed25519Public,
        identity.x25519IdentityPublic,
        identity.signedPreKeyPublic,
        identity.oneTimePreKeyPublic,
        registrationId);
    const auto privateBundle = encryptWithPbkdf2(privates, password, aad);
    secureWipe(privates);
    if (privateBundle.empty()) return false;

    std::string json;
    json.reserve(1024);
    json += "{";
    json += "\"formatVersion\":" + std::to_string(kIdentityFormatVersion) + ",";
    json += "\"keyVersion\":" + std::to_string(kIdentityFormatVersion) + ",";
    json += "\"registrationId\":" + jsonQuote(registrationId) + ",";
    json += "\"identityPublic\":" + jsonQuote(base64String(identity.ed25519Public)) + ",";
    json += "\"x25519IdentityPublic\":" + jsonQuote(base64String(identity.x25519IdentityPublic)) + ",";
    json += "\"signedPreKeyPublic\":" + jsonQuote(base64String(identity.signedPreKeyPublic)) + ",";
    json += "\"oneTimePreKeyPublic\":" + jsonQuote(base64String(identity.oneTimePreKeyPublic)) + ",";
    json += "\"privateBundle\":" + jsonQuote(base64String(privateBundle));
    json += "}";

    if (!ensureParentDirectory(filePath)) return false;
    const ByteVector bytes(json.begin(), json.end());
    return writeFileAtomic(filePath, bytes);
}

bool loadIdentity(
        LocalIdentity &out,
        const std::string &filePath,
        const std::string &password) {
    out = LocalIdentity();
    if (filePath.empty() || password.empty()) return false;

    ByteVector fileBytes;
    if (!readFileCapped(filePath, kMaxPersistenceFileSize, fileBytes)) return false;
    const std::string text(fileBytes.begin(), fileBytes.end());

    JsonValue root;
    if (!jsonParse(text, root) || root.type != JsonValue::Object) return false;

    uint64_t formatVersion = 0;
    if (!root.getUint("formatVersion", formatVersion)
            || formatVersion != kIdentityFormatVersion) {
        return false;
    }
    std::string registrationId;
    if (!root.getString("registrationId", registrationId)) return false;
    uint64_t registrationIdValue = 0;
    if (!parseRegistrationId(registrationId, registrationIdValue)) return false;

    ByteVector identityPublic;
    ByteVector x25519IdentityPublic;
    ByteVector signedPreKeyPublic;
    ByteVector oneTimePreKeyPublic;
    if (!parseFixedKey(root, "identityPublic", identityPublic)) return false;
    if (!parseFixedKey(root, "x25519IdentityPublic", x25519IdentityPublic)) return false;
    if (!parseFixedKey(root, "signedPreKeyPublic", signedPreKeyPublic)) return false;
    if (!parseFixedKey(root, "oneTimePreKeyPublic", oneTimePreKeyPublic)) return false;

    std::string bundleText;
    if (!root.getString("privateBundle", bundleText)) return false;
    ByteVector privateBundle;
    if (!base64Decode(bundleText, privateBundle)) return false;

    // AAD must reproduce the save-time binding exactly — any tampering with
    // the stored publics (or the registrationId) fails the GCM tag check.
    const ByteVector aad = identityAad(
        identityPublic,
        x25519IdentityPublic,
        signedPreKeyPublic,
        oneTimePreKeyPublic,
        registrationId);
    ByteVector privates;
    if (!decryptWithPbkdf2(privateBundle, password, aad, privates)) return false;
    if (privates.size() != 4 * kKeySize) {
        secureWipe(privates);
        return false;
    }

    LocalIdentity candidate;
    candidate.ed25519PrivateSeed.assign(privates.begin(), privates.begin() + kEd25519SeedSize);
    candidate.x25519IdentityPrivate.assign(privates.begin() + kEd25519SeedSize, privates.begin() + 2 * kKeySize);
    candidate.signedPreKeyPrivate.assign(privates.begin() + 2 * kKeySize, privates.begin() + 3 * kKeySize);
    candidate.oneTimePreKeyPrivate.assign(privates.begin() + 3 * kKeySize, privates.end());
    secureWipe(privates);

    candidate.ed25519Public = identityPublic;
    candidate.x25519IdentityPublic = x25519IdentityPublic;
    candidate.signedPreKeyPublic = signedPreKeyPublic;
    candidate.oneTimePreKeyPublic = oneTimePreKeyPublic;
    candidate.registrationId = registrationIdValue;
    candidate.initialized = true;

    // Trust nothing the file asserts without re-deriving it: every public
    // must match its private counterpart and the SPK signature must verify.
    if (ed25519PublicFromSeed(candidate.ed25519PrivateSeed) != candidate.ed25519Public
            || x25519PublicFromPrivate(candidate.x25519IdentityPrivate) != candidate.x25519IdentityPublic
            || x25519PublicFromPrivate(candidate.signedPreKeyPrivate) != candidate.signedPreKeyPublic
            || x25519PublicFromPrivate(candidate.oneTimePreKeyPrivate) != candidate.oneTimePreKeyPublic
            || !verifyKeyBundleSignature(localKeyBundle(candidate))) {
        return false;
    }

    out = std::move(candidate);
    return true;
}

bool readIdentityRegistrationId(
        const std::string &filePath,
        std::string &registrationIdOut) {
    registrationIdOut.clear();
    ByteVector fileBytes;
    if (!readFileCapped(filePath, kMaxPersistenceFileSize, fileBytes)) return false;
    const std::string text(fileBytes.begin(), fileBytes.end());

    JsonValue root;
    if (!jsonParse(text, root) || root.type != JsonValue::Object) return false;
    std::string registrationId;
    if (!root.getString("registrationId", registrationId)) return false;
    uint64_t ignored = 0;
    if (!parseRegistrationId(registrationId, ignored)) return false;
    registrationIdOut = std::move(registrationId);
    return true;
}

bool saveSessionFile(
        const SessionState &state,
        const std::string &filePath,
        const ByteVector &hmacKey,
        uint32_t specGeneration) {
    if (filePath.empty() || hmacKey.size() != kAesKeySize) return false;

    // Compact inner session JSON, HMAC'd raw (desktop session.json parity:
    // sessionData base64 + HMAC over the DECODED bytes).
    const std::string inner = serializeSessionJson(state, specGeneration);
    const ByteVector sessionData(inner.begin(), inner.end());
    const auto mac = hmacSha256(hmacKey, sessionData);
    if (mac.empty()) return false;

    std::string json;
    json.reserve(inner.size() + 256);
    json += "{";
    json += "\"version\":" + std::to_string(kSessionFileFormatVersion) + ",";
    json += "\"sessionData\":" + jsonQuote(base64String(sessionData)) + ",";
    json += "\"hmac\":" + jsonQuote(base64String(mac));
    json += "}";

    if (!ensureParentDirectory(filePath)) return false;
    const ByteVector bytes(json.begin(), json.end());
    return writeFileAtomic(filePath, bytes);
}

bool loadSessionFile(
        SessionState &outState,
        const std::string &filePath,
        const ByteVector &hmacKey,
        uint32_t expectedSpecGeneration) {
    outState = SessionState();
    if (filePath.empty() || hmacKey.size() != kAesKeySize) return false;

    ByteVector fileBytes;
    if (!readFileCapped(filePath, kMaxPersistenceFileSize, fileBytes)) return false;
    const std::string text(fileBytes.begin(), fileBytes.end());

    JsonValue root;
    if (!jsonParse(text, root) || root.type != JsonValue::Object) {
        remove(filePath.c_str());
        return false;
    }

    uint64_t version = 0;
    std::string sessionDataText;
    std::string hmacText;
    if (!root.getUint("version", version)
            || version != kSessionFileFormatVersion
            || !root.getString("sessionData", sessionDataText)
            || !root.getString("hmac", hmacText)) {
        remove(filePath.c_str());
        return false;
    }

    ByteVector sessionData;
    ByteVector storedMac;
    if (!base64Decode(sessionDataText, sessionData) || !base64Decode(hmacText, storedMac)) {
        remove(filePath.c_str());
        return false;
    }

    // Constant-time HMAC verification (desktop calculateHMAC + CRYPTO_memcmp
    // pattern) before any field is trusted.
    const auto calculatedMac = hmacSha256(hmacKey, sessionData);
    if (calculatedMac.empty()
            || storedMac.size() != calculatedMac.size()
            || CRYPTO_memcmp(
                   storedMac.data(),
                   calculatedMac.data(),
                   calculatedMac.size()) != 0) {
        // Tamper attempt or foreign session: DELETE and report a miss so the
        // caller re-establishes. The file is never trusted after a failure.
        remove(filePath.c_str());
        return false;
    }

    const std::string inner(sessionData.begin(), sessionData.end());
    SessionState state;
    uint32_t specGeneration = 0;
    if (!parseSessionJson(inner, state, specGeneration)
            || specGeneration != expectedSpecGeneration) {
        // Wrong-spec sessions from older builds are REPLACED, not trusted.
        remove(filePath.c_str());
        return false;
    }

    outState = std::move(state);
    return true;
}

} // namespace interop
