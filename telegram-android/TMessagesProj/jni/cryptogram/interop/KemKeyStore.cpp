/*
 * CRYPTOGRAM Android — encrypted persistence for the static ML-KEM identity.
 * See KemKeyStore.h for the container format and threat model.
 *
 * This file is part of CRYPTOGRAM Android
 * Licensed under GNU GPL v. 2 or later.
 */

#include "interop/KemKeyStore.h"

#include <openssl/evp.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>
#include <sys/types.h>

namespace interop {
namespace {

// "QGKA" — Android-local variant of the desktop "QGKS" container. The
// wrapping parameters are shared with the desktop; the inner payload is not
// (the desktop serializes a Qt key store, Android a single KEM identity).
const uint8_t kMagic[4] = {'Q', 'G', 'K', 'A'};
constexpr uint32_t kVersion = 1;

void pushU32Be(ByteVector &out, uint32_t value) {
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(value & 0xFF));
}

bool readU32Be(const ByteVector &data, size_t &pos, uint32_t &value) {
    if (pos + 4 > data.size()) return false;
    value = (static_cast<uint32_t>(data[pos]) << 24)
        | (static_cast<uint32_t>(data[pos + 1]) << 16)
        | (static_cast<uint32_t>(data[pos + 2]) << 8)
        | static_cast<uint32_t>(data[pos + 3]);
    pos += 4;
    return true;
}

bool readBlob(
        const ByteVector &data,
        size_t &pos,
        size_t length,
        ByteVector &out) {
    if (length == 0 || length > data.size() - pos) return false;
    out.assign(data.begin() + pos, data.begin() + pos + length);
    pos += length;
    return true;
}

ByteVector serializeIdentity(const KemKeyPair &identity) {
    ByteVector out;
    out.reserve(
        8 + identity.privateKeyBlob.size() + identity.publicKeyDer.size());
    pushU32Be(out, static_cast<uint32_t>(identity.privateKeyBlob.size()));
    out.insert(
        out.end(),
        identity.privateKeyBlob.begin(),
        identity.privateKeyBlob.end());
    pushU32Be(out, static_cast<uint32_t>(identity.publicKeyDer.size()));
    out.insert(
        out.end(),
        identity.publicKeyDer.begin(),
        identity.publicKeyDer.end());
    return out;
}

bool deserializeIdentity(const ByteVector &plain, KemKeyPair &out) {
    KemKeyPair identity;
    size_t pos = 0;
    uint32_t privateLen = 0;
    uint32_t publicLen = 0;
    if (!readU32Be(plain, pos, privateLen)
            || !readBlob(plain, pos, privateLen, identity.privateKeyBlob)
            || !readU32Be(plain, pos, publicLen)
            || !readBlob(plain, pos, publicLen, identity.publicKeyDer)
            || pos != plain.size()) {
        return false;
    }
    out = std::move(identity);
    return true;
}

bool deriveWrappingKey(
        const std::string &password,
        const ByteVector &salt,
        ByteVector &key) {
    key.resize(kAesKeySize);
    // desktop QuantumGuard: PKCS5_PBKDF2_HMAC(..., 100000, EVP_sha256(), 32).
    return PKCS5_PBKDF2_HMAC(
               password.data(),
               static_cast<int>(password.size()),
               salt.data(),
               static_cast<int>(salt.size()),
               static_cast<int>(kKemKeyStoreIterations),
               EVP_sha256(),
               static_cast<unsigned>(key.size()),
               key.data()) == 1;
}

bool writeFile(const std::string &filePath, const ByteVector &data) {
    std::FILE *file = std::fopen(filePath.c_str(), "wb");
    if (!file) return false;
    bool ok = data.empty()
        || std::fwrite(data.data(), 1, data.size(), file) == data.size();
    ok = ok && std::fflush(file) == 0;
    ok = std::fclose(file) == 0 && ok;
    return ok;
}

bool readFile(const std::string &filePath, ByteVector &out) {
    std::FILE *file = std::fopen(filePath.c_str(), "rb");
    if (!file) return false;
    out.clear();
    uint8_t buffer[4096];
    size_t chunk = 0;
    while ((chunk = std::fread(buffer, 1, sizeof(buffer), file)) > 0) {
        out.insert(out.end(), buffer, buffer + chunk);
    }
    const bool ok = !std::ferror(file) && !out.empty();
    std::fclose(file);
    return ok;
}

} // namespace

std::string interopStoragePath(const std::string &baseDir) {
    if (baseDir.empty()) return {};
    std::string dir = baseDir;
    while (!dir.empty() && dir.back() == '/') {
        dir.pop_back();
    }
    // mkdir -p over the conventioned subpath ("cryptogram/interop"); the
    // base itself (the app files dir) always exists.
    const std::string sub = kInteropStorageSubdir;
    std::string current = dir;
    size_t start = 0;
    while (true) {
        const size_t slash = sub.find('/', start);
        const size_t end = (slash == std::string::npos) ? sub.size() : slash;
        current += "/";
        current.append(sub, start, end - start);
        if (::mkdir(current.c_str(), 0700) != 0 && errno != EEXIST) {
            return {};
        }
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
    return current;
}

bool saveKemIdentity(
        const std::string &filePath,
        const std::string &password,
        const KemKeyPair &identity) {
    if (filePath.empty()
            || password.empty()
            || identity.privateKeyBlob.empty()
            || identity.publicKeyDer.empty()) {
        return false;
    }

    const ByteVector plain = serializeIdentity(identity);
    if (plain.empty()) return false;

    const auto salt = randomVector(kKemKeyStoreSaltSize);
    const auto iv = randomVector(kKemKeyStoreIvSize);
    if (salt.empty() || iv.empty()) return false;

    ByteVector key;
    if (!deriveWrappingKey(password, salt, key)) return false;
    // interop AES-GCM returns ciphertext||tag.
    const auto cipherWithTag = aesGcmEncrypt(key, iv, plain, ByteVector());
    secureWipe(key);
    if (cipherWithTag.size() < kKemKeyStoreTagSize) return false;

    ByteVector out;
    out.reserve(kKemKeyStoreHeaderSize + (cipherWithTag.size() - kKemKeyStoreTagSize));
    out.insert(out.end(), kMagic, kMagic + sizeof(kMagic));
    pushU32Be(out, kVersion);
    out.insert(out.end(), salt.begin(), salt.end());
    out.insert(out.end(), iv.begin(), iv.end());
    out.insert(out.end(), cipherWithTag.end() - kKemKeyStoreTagSize, cipherWithTag.end());
    out.insert(
        out.end(),
        cipherWithTag.begin(),
        cipherWithTag.end() - kKemKeyStoreTagSize);

    const bool ok = writeFile(filePath, out);
    secureWipe(out);
    return ok;
}

bool loadKemIdentity(
        const std::string &filePath,
        const std::string &password,
        KemKeyPair &out) {
    out = KemKeyPair();

    ByteVector data;
    if (!readFile(filePath, data) || data.size() <= kKemKeyStoreHeaderSize) {
        return false;
    }
    if (std::memcmp(data.data(), kMagic, sizeof(kMagic)) != 0) return false;

    size_t pos = 4;
    uint32_t version = 0;
    if (!readU32Be(data, pos, version) || version != kVersion) return false;

    ByteVector salt;
    ByteVector iv;
    ByteVector tag;
    if (!readBlob(data, pos, kKemKeyStoreSaltSize, salt)
            || !readBlob(data, pos, kKemKeyStoreIvSize, iv)
            || !readBlob(data, pos, kKemKeyStoreTagSize, tag)) {
        return false;
    }
    ByteVector cipherWithTag(data.begin() + pos, data.end());
    cipherWithTag.insert(cipherWithTag.end(), tag.begin(), tag.end());

    ByteVector key;
    if (!deriveWrappingKey(password, salt, key)) return false;
    ByteVector plain = aesGcmDecrypt(key, iv, cipherWithTag, ByteVector());
    secureWipe(key);
    if (plain.empty()) return false; // wrong password or corrupt store

    const bool ok = deserializeIdentity(plain, out);
    secureWipe(plain);
    return ok;
}

} // namespace interop
