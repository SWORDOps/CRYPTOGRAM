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

void secureWipe(ByteVector &data) {
    if (!data.empty()) {
        OPENSSL_cleanse(data.data(), data.size());
    }
    data.clear();
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

} // namespace interop
