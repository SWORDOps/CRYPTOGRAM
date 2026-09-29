/*
 * CRYPTOGRAM Android — encrypted persistence for the static ML-KEM identity.
 *
 * JNI-free and host-compilable (plain OpenSSL on the host, in-tree BoringSSL
 * on device — only the portable EVP subset is used). The JNI layer
 * (CryptogramWrapper.cpp) passes the app files directory; this unit owns the
 * file format and the encrypted container.
 *
 * The container mirrors the desktop QuantumGuard::saveKeys/loadKeys parameter
 * choices (PBKDF2-SHA256 with 100000 iterations over a 16-byte random salt,
 * AES-256-GCM with a 12-byte random IV and a 16-byte tag) without the
 * desktop's Qt-serialized inner payload, which has no meaning on Android:
 *
 *   "QGKA" | u32be version = 1 | salt (16) | iv (12) | tag (16) | ciphertext
 *
 * Plaintext payload (Android-local, all integers big-endian):
 *   u32be privateKeyBlob length | privateKeyBlob
 *   u32be publicKeyDer length   | publicKeyDer (SPKI DER)
 *
 * The raw public key is not stored — it is re-derived from the private blob
 * on load (kemIdentityFromPrivateBlob) when needed. Like the desktop, the
 * wrapping password is obfuscation-grade protection AT REST only; the
 * security property that matters is harvest-now-decrypt-later resistance on
 * the wire.
 *
 * This file is part of CRYPTOGRAM Android
 * Licensed under GNU GPL v. 2 or later.
 */

#ifndef CRYPTOGRAM_ANDROID_INTEROP_KEM_KEY_STORE_H
#define CRYPTOGRAM_ANDROID_INTEROP_KEM_KEY_STORE_H

#include <string>

#include "InteropCore.h"

namespace interop {

// Desktop QuantumGuard parameter choices (do not change silently — the
// parameters are part of the at-rest format stability).
static constexpr size_t kKemKeyStoreSaltSize = 16;
static constexpr size_t kKemKeyStoreIvSize = kGcmIvSize;
static constexpr size_t kKemKeyStoreTagSize = kGcmTagSize;
static constexpr size_t kKemKeyStoreIterations = 100000;
// "QGKA"(4) + version(4) + salt(16) + iv(12) + tag(16).
static constexpr size_t kKemKeyStoreHeaderSize = 4 + 4 + 16 + 12 + 16;

// Resolves the conventioned interop storage directory
// "<baseDir>/<kInteropStorageSubdir>" (InteropCore.h), creating any missing
// component of the conventioned subpath. The base itself (the app files dir
// on Android) must exist. Returns an empty string when baseDir is empty or
// the directory cannot be created.
std::string interopStoragePath(const std::string &baseDir);

// Both return false on any failure (missing file, wrong password, corrupt
// container, I/O error). out is left empty on failure.
bool saveKemIdentity(
    const std::string &filePath,
    const std::string &password,
    const KemKeyPair &identity);
bool loadKemIdentity(
    const std::string &filePath,
    const std::string &password,
    KemKeyPair &out);

} // namespace interop

#endif // CRYPTOGRAM_ANDROID_INTEROP_KEM_KEY_STORE_H
