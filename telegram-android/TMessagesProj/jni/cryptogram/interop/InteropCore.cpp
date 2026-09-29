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
#include <cstring>
#include <ctime>

namespace interop {
namespace {

// AAD: 4-byte BIG-ENDIAN counter || 32-byte sender public key
// (desktop encryptMessage/decryptMessage — NO timestamp).
ByteVector metadataAad(const MessageMetadata &metadata) {
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
// Qt_5_15 default).
ByteVector wrapEnvelope(
        const ByteVector &ciphertext,
        const MessageMetadata &metadata) {
    ByteVector data;
    data.reserve(
        4 + (4 + metadata.iv.size())
        + (4 + metadata.senderPublicKey.size())
        + 4 + 1 + (metadata.hasCacChallenge
                   ? 4 + metadata.cacChallengeNonce.size() : 0)
        + 1 + (metadata.hasCacResponse
               ? 4 + metadata.cacSignature.size()
               + 4 + metadata.cacCertChainDer.size() : 0)
        + 4 + ciphertext.size());

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

    pushQByteArray(data, ciphertext);
    return data;
}

bool unwrapEnvelope(const ByteVector &blob, Envelope &out) {
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

// ---------------------------------------------------------------------------
// Double ratchet (desktop encryptMessage / decryptMessage)
// ---------------------------------------------------------------------------

ByteVector encryptMessage(
        SessionState &session,
        const ByteVector &plaintext,
        MessageMetadata &outMetadata) {
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

    const ByteVector aad = metadataAad(outMetadata);
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

    const ByteVector aad = metadataAad(metadata);
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

} // namespace interop
