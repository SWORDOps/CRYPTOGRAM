/*
 * CRYPTOGRAM Android JNI bridge.
 */

#include <jni.h>
#include <android/log.h>

#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#define LOG_TAG "CryptogramNative"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

using ByteVector = std::vector<uint8_t>;

constexpr size_t kX25519KeySize = 32;
constexpr size_t kEd25519PublicKeySize = 32;
constexpr size_t kEd25519PrivateKeySize = 64;
constexpr size_t kAes256KeySize = 32;
constexpr size_t kGcmIvSize = 12;
constexpr size_t kGcmTagSize = 16;
constexpr uint8_t kSignalEnvelopeVersion = 1;
constexpr uint8_t kMlsEnvelopeVersion = 1;
constexpr size_t kMaxSkippedKeys = 128;

JavaVM *gJavaVM = nullptr;
std::string gStoragePath;

struct DeviceId {
    std::string identifier;
    uint64_t registrationId = 0;
};

struct KeyBundle {
    DeviceId deviceId;
    ByteVector identityKey;
    ByteVector signedPreKey;
    ByteVector oneTimePreKey;
    ByteVector signature;
};

struct MessageMetadata {
    uint32_t messageCounter = 0;
    ByteVector iv;
    ByteVector senderPublicKey;
    uint32_t timestamp = 0;
};

struct SessionState {
    ByteVector rootKey;
    ByteVector sendingChainKey;
    ByteVector receivingChainKey;
    ByteVector remoteIdentityKey;
    uint32_t sendingCounter = 0;
    uint32_t receivingCounter = 0;
    std::map<uint32_t, ByteVector> skippedReceivingKeys;
};

struct LocalIdentity {
    DeviceId deviceId;
    ByteVector identityPublic;
    std::array<uint8_t, kEd25519PrivateKeySize> identityPrivate{};
    ByteVector signedPreKeyPublic;
    std::array<uint8_t, kX25519KeySize> signedPreKeyPrivate{};
    ByteVector oneTimePreKeyPublic;
    std::array<uint8_t, kX25519KeySize> oneTimePreKeyPrivate{};
    bool initialized = false;
};

struct MlsGroup {
    ByteVector groupId;
    ByteVector epochSecret;
    uint64_t epoch = 0;
};

std::mutex gSignalMutex;
LocalIdentity gIdentity;
std::unordered_map<int64_t, SessionState> gSessions;
std::mutex gMlsMutex;
std::unordered_map<int64_t, MlsGroup> gMlsGroups;
std::mutex gPrivacyMutex;
std::unordered_map<int64_t, bool> gCryptogramUsers;

uint32_t nowSeconds() {
    return static_cast<uint32_t>(time(nullptr));
}

bool randomBytes(uint8_t *data, size_t size) {
    return RAND_bytes(data, size) == 1;
}

ByteVector randomVector(size_t size) {
    ByteVector result(size);
    if (!result.empty() && !randomBytes(result.data(), result.size())) {
        result.clear();
    }
    return result;
}

void pushU8(ByteVector &out, uint8_t value) {
    out.push_back(value);
}

void pushU32(ByteVector &out, uint32_t value) {
    for (int shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<uint8_t>((value >> shift) & 0xFF));
    }
}

void pushU64(ByteVector &out, uint64_t value) {
    for (int shift = 0; shift < 64; shift += 8) {
        out.push_back(static_cast<uint8_t>((value >> shift) & 0xFF));
    }
}

bool readU8(const uint8_t *data, size_t size, size_t &pos, uint8_t &value) {
    if (pos + sizeof(value) > size) return false;
    value = data[pos++];
    return true;
}

bool readU32(const uint8_t *data, size_t size, size_t &pos, uint32_t &value) {
    if (pos + sizeof(value) > size) return false;
    value = 0;
    for (int shift = 0; shift < 32; shift += 8) {
        value |= static_cast<uint32_t>(data[pos++]) << shift;
    }
    return true;
}

bool readU64(const uint8_t *data, size_t size, size_t &pos, uint64_t &value) {
    if (pos + sizeof(value) > size) return false;
    value = 0;
    for (int shift = 0; shift < 64; shift += 8) {
        value |= static_cast<uint64_t>(data[pos++]) << shift;
    }
    return true;
}

void pushVector(ByteVector &out, const ByteVector &value) {
    pushU32(out, static_cast<uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

bool readVector(const uint8_t *data, size_t size, size_t &pos, ByteVector &value) {
    uint32_t len = 0;
    if (!readU32(data, size, pos, len) || pos + len > size) return false;
    value.assign(data + pos, data + pos + len);
    pos += len;
    return true;
}

ByteVector jbyteArrayToVector(JNIEnv *env, jbyteArray array) {
    if (!array) return {};
    const auto len = env->GetArrayLength(array);
    auto *bytes = env->GetByteArrayElements(array, nullptr);
    if (!bytes) return {};
    ByteVector result(reinterpret_cast<uint8_t *>(bytes), reinterpret_cast<uint8_t *>(bytes) + len);
    env->ReleaseByteArrayElements(array, bytes, JNI_ABORT);
    return result;
}

jbyteArray vectorToJByteArray(JNIEnv *env, const ByteVector &data) {
    auto result = env->NewByteArray(static_cast<jsize>(data.size()));
    if (!result) return nullptr;
    if (!data.empty()) {
        env->SetByteArrayRegion(result, 0, static_cast<jsize>(data.size()), reinterpret_cast<const jbyte *>(data.data()));
    }
    return result;
}

ByteVector hkdfSha256(const ByteVector &secret, const std::string &info, size_t outSize, const ByteVector &salt = {}) {
    ByteVector result(outSize);
    const uint8_t *saltData = salt.empty() ? nullptr : salt.data();
    const uint8_t *infoData = reinterpret_cast<const uint8_t *>(info.data());
    if (HKDF(result.data(), result.size(), EVP_sha256(), secret.data(), secret.size(), saltData, salt.size(), infoData, info.size()) != 1) {
        return {};
    }
    return result;
}

ByteVector sha256Concat(const ByteVector &first, const ByteVector &second) {
    SHA256_CTX ctx;
    ByteVector digest(SHA256_DIGEST_LENGTH);
    SHA256_Init(&ctx);
    if (!first.empty()) SHA256_Update(&ctx, first.data(), first.size());
    if (!second.empty()) SHA256_Update(&ctx, second.data(), second.size());
    SHA256_Final(digest.data(), &ctx);
    return digest;
}

std::optional<ByteVector> aesGcmEncrypt(const ByteVector &key, const ByteVector &iv, const ByteVector &plaintext, const ByteVector &aad) {
    if (key.size() != kAes256KeySize || iv.size() != kGcmIvSize) return std::nullopt;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::nullopt;

    ByteVector output(plaintext.size() + kGcmTagSize);
    int outLen = 0;
    int totalLen = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) == 1 &&
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1;
    if (ok && !aad.empty()) {
        ok = EVP_EncryptUpdate(ctx, nullptr, &outLen, aad.data(), static_cast<int>(aad.size())) == 1;
    }
    if (ok && !plaintext.empty()) {
        ok = EVP_EncryptUpdate(ctx, output.data(), &outLen, plaintext.data(), static_cast<int>(plaintext.size())) == 1;
        totalLen = outLen;
    }
    if (ok) {
        ok = EVP_EncryptFinal_ex(ctx, output.data() + totalLen, &outLen) == 1;
        totalLen += outLen;
    }
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kGcmTagSize, output.data() + totalLen) == 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return std::nullopt;
    output.resize(static_cast<size_t>(totalLen) + kGcmTagSize);
    return output;
}

std::optional<ByteVector> aesGcmDecrypt(const ByteVector &key, const ByteVector &iv, const ByteVector &ciphertextWithTag, const ByteVector &aad) {
    if (key.size() != kAes256KeySize || iv.size() != kGcmIvSize || ciphertextWithTag.size() < kGcmTagSize) return std::nullopt;
    const size_t ciphertextSize = ciphertextWithTag.size() - kGcmTagSize;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::nullopt;

    ByteVector plaintext(ciphertextSize);
    int outLen = 0;
    int totalLen = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1;
    if (ok && !aad.empty()) {
        ok = EVP_DecryptUpdate(ctx, nullptr, &outLen, aad.data(), static_cast<int>(aad.size())) == 1;
    }
    if (ok && ciphertextSize > 0) {
        ok = EVP_DecryptUpdate(ctx, plaintext.data(), &outLen, ciphertextWithTag.data(), static_cast<int>(ciphertextSize)) == 1;
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
    if (!ok) return std::nullopt;
    plaintext.resize(static_cast<size_t>(totalLen));
    return plaintext;
}

ByteVector deriveMessageKey(const ByteVector &chainKey, uint32_t counter) {
    ByteVector counterBytes;
    pushU32(counterBytes, counter);
    return hkdfSha256(chainKey, "Cryptogram-Android-DoubleRatchet-Message", kAes256KeySize, counterBytes);
}

ByteVector ratchetChain(const ByteVector &chainKey) {
    return hkdfSha256(chainKey, "Cryptogram-Android-DoubleRatchet-Chain", kAes256KeySize);
}

bool ensureIdentity() {
    if (gIdentity.initialized) return true;

    std::array<uint8_t, kEd25519PublicKeySize> publicKey{};
    ED25519_keypair(publicKey.data(), gIdentity.identityPrivate.data());
    gIdentity.identityPublic.assign(publicKey.begin(), publicKey.end());

    std::array<uint8_t, kX25519KeySize> signedPublic{};
    X25519_keypair(signedPublic.data(), gIdentity.signedPreKeyPrivate.data());
    gIdentity.signedPreKeyPublic.assign(signedPublic.begin(), signedPublic.end());

    std::array<uint8_t, kX25519KeySize> oneTimePublic{};
    X25519_keypair(oneTimePublic.data(), gIdentity.oneTimePreKeyPrivate.data());
    gIdentity.oneTimePreKeyPublic.assign(oneTimePublic.begin(), oneTimePublic.end());

    gIdentity.deviceId.identifier = "android-primary";
    if (!randomBytes(reinterpret_cast<uint8_t *>(&gIdentity.deviceId.registrationId), sizeof(gIdentity.deviceId.registrationId))) {
        return false;
    }
    gIdentity.initialized = true;
    return true;
}

ByteVector signBytes(const ByteVector &data) {
    ByteVector signature(ED25519_SIGNATURE_LEN);
    if (!ensureIdentity()) return {};
    if (!ED25519_sign(signature.data(), data.data(), data.size(), gIdentity.identityPrivate.data())) {
        return {};
    }
    return signature;
}

bool verifySignature(const ByteVector &signature, const ByteVector &data, const ByteVector &publicKey) {
    if (signature.size() != ED25519_SIGNATURE_LEN || publicKey.size() != kEd25519PublicKeySize) return false;
    return ED25519_verify(data.data(), data.size(), signature.data(), publicKey.data()) == 1;
}

KeyBundle localKeyBundle() {
    ensureIdentity();
    KeyBundle bundle;
    bundle.deviceId = gIdentity.deviceId;
    bundle.identityKey = gIdentity.identityPublic;
    bundle.signedPreKey = gIdentity.signedPreKeyPublic;
    bundle.oneTimePreKey = gIdentity.oneTimePreKeyPublic;
    bundle.signature = signBytes(bundle.signedPreKey);
    return bundle;
}

ByteVector serializeKeyBundle(const KeyBundle &bundle) {
    ByteVector result;
    pushU32(result, static_cast<uint32_t>(bundle.deviceId.identifier.size()));
    result.insert(result.end(), bundle.deviceId.identifier.begin(), bundle.deviceId.identifier.end());
    pushU64(result, bundle.deviceId.registrationId);
    pushVector(result, bundle.identityKey);
    pushVector(result, bundle.signedPreKey);
    pushVector(result, bundle.oneTimePreKey);
    pushVector(result, bundle.signature);
    return result;
}

std::optional<KeyBundle> deserializeKeyBundle(const ByteVector &data) {
    KeyBundle bundle;
    size_t pos = 0;
    uint32_t idLen = 0;
    if (!readU32(data.data(), data.size(), pos, idLen) || pos + idLen > data.size()) return std::nullopt;
    bundle.deviceId.identifier.assign(reinterpret_cast<const char *>(data.data() + pos), idLen);
    pos += idLen;
    if (!readU64(data.data(), data.size(), pos, bundle.deviceId.registrationId)) return std::nullopt;
    if (!readVector(data.data(), data.size(), pos, bundle.identityKey)) return std::nullopt;
    if (!readVector(data.data(), data.size(), pos, bundle.signedPreKey)) return std::nullopt;
    if (!readVector(data.data(), data.size(), pos, bundle.oneTimePreKey)) return std::nullopt;
    if (!readVector(data.data(), data.size(), pos, bundle.signature)) return std::nullopt;
    return bundle;
}

bool createSessionFromBundle(int64_t userId, const KeyBundle &remoteBundle) {
    if (!ensureIdentity()) return false;
    if (remoteBundle.signedPreKey.size() != kX25519KeySize ||
        !verifySignature(remoteBundle.signature, remoteBundle.signedPreKey, remoteBundle.identityKey)) {
        return false;
    }

    std::array<uint8_t, kX25519KeySize> sharedSecret{};
    if (!X25519(sharedSecret.data(), gIdentity.signedPreKeyPrivate.data(), remoteBundle.signedPreKey.data())) {
        return false;
    }
    ByteVector shared(sharedSecret.begin(), sharedSecret.end());
    ByteVector root = hkdfSha256(shared, "Cryptogram-Android-X3DH-Root", kAes256KeySize);
    if (root.empty()) return false;

    const bool localFirst = std::lexicographical_compare(
        gIdentity.identityPublic.begin(),
        gIdentity.identityPublic.end(),
        remoteBundle.identityKey.begin(),
        remoteBundle.identityKey.end());

    SessionState state;
    state.rootKey = root;
    state.remoteIdentityKey = remoteBundle.identityKey;
    state.sendingChainKey = hkdfSha256(root, localFirst ? "Cryptogram-Android-Chain-A" : "Cryptogram-Android-Chain-B", kAes256KeySize);
    state.receivingChainKey = hkdfSha256(root, localFirst ? "Cryptogram-Android-Chain-B" : "Cryptogram-Android-Chain-A", kAes256KeySize);
    if (state.sendingChainKey.empty() || state.receivingChainKey.empty()) return false;
    gSessions[userId] = std::move(state);
    gCryptogramUsers[userId] = true;
    return true;
}

ByteVector metadataAad(const MessageMetadata &metadata) {
    ByteVector aad;
    pushU32(aad, metadata.messageCounter);
    pushVector(aad, metadata.senderPublicKey);
    pushU32(aad, metadata.timestamp);
    return aad;
}

ByteVector serializeMetadata(const MessageMetadata &metadata) {
    ByteVector result;
    pushU32(result, metadata.messageCounter);
    pushVector(result, metadata.iv);
    pushVector(result, metadata.senderPublicKey);
    pushU32(result, metadata.timestamp);
    return result;
}

bool deserializeMetadata(const uint8_t *data, size_t size, size_t &pos, MessageMetadata &metadata) {
    return readU32(data, size, pos, metadata.messageCounter) &&
        readVector(data, size, pos, metadata.iv) &&
        readVector(data, size, pos, metadata.senderPublicKey) &&
        readU32(data, size, pos, metadata.timestamp);
}

ByteVector serializeSignalState(int64_t userId) {
    const auto it = gSessions.find(userId);
    std::ostringstream out;
    out << "{\"initialized\": true, \"protocol\": \"Cryptogram Android Double Ratchet\", \"hasSession\": "
        << (it == gSessions.end() ? "false" : "true")
        << ", \"userId\": " << userId << "}";
    const auto text = out.str();
    return ByteVector(text.begin(), text.end());
}

ByteVector mlsSecretForGroup(MlsGroup &group) {
    ByteVector epochBytes;
    pushU64(epochBytes, group.epoch);
    return hkdfSha256(group.epochSecret, "Cryptogram-Android-MLS-Application", kAes256KeySize, epochBytes);
}

bool runDoubleRatchetSelfTest() {
    auto bundle = localKeyBundle();
    return createSessionFromBundle(1, bundle) && gSessions.find(1) != gSessions.end();
}

bool runMlsSelfTest() {
    MlsGroup group;
    group.groupId = randomVector(kAes256KeySize);
    group.epochSecret = randomVector(kAes256KeySize);
    if (group.groupId.empty() || group.epochSecret.empty()) return false;
    auto key = mlsSecretForGroup(group);
    auto iv = randomVector(kGcmIvSize);
    ByteVector plaintext{'m', 'l', 's'};
    ByteVector aad;
    pushU64(aad, group.epoch);
    auto encrypted = aesGcmEncrypt(key, iv, plaintext, aad);
    if (!encrypted.has_value()) return false;
    auto decrypted = aesGcmDecrypt(key, iv, *encrypted, aad);
    return decrypted.has_value() && *decrypted == plaintext;
}

} // namespace

extern "C" {

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeInitializeSession(JNIEnv *, jobject, jlong userId) {
    std::lock_guard<std::mutex> lock(gSignalMutex);
    return createSessionFromBundle(static_cast<int64_t>(userId), localKeyBundle()) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jbyteArray JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeGenerateKeyBundle(JNIEnv *env, jobject) {
    std::lock_guard<std::mutex> lock(gSignalMutex);
    return vectorToJByteArray(env, serializeKeyBundle(localKeyBundle()));
}

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeInitializeWithRemoteBundle(JNIEnv *env, jobject, jlong userId, jbyteArray bundleData) {
    const auto data = jbyteArrayToVector(env, bundleData);
    const auto bundle = deserializeKeyBundle(data);
    if (!bundle.has_value()) return JNI_FALSE;
    std::lock_guard<std::mutex> lock(gSignalMutex);
    return createSessionFromBundle(static_cast<int64_t>(userId), *bundle) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeHasSession(JNIEnv *, jobject, jlong userId) {
    std::lock_guard<std::mutex> lock(gSignalMutex);
    return gSessions.find(static_cast<int64_t>(userId)) != gSessions.end() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jbyteArray JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeEncrypt(JNIEnv *env, jobject, jlong userId, jstring plaintext) {
    if (!plaintext) return nullptr;
    const char *messageText = env->GetStringUTFChars(plaintext, nullptr);
    if (!messageText) return nullptr;

    std::lock_guard<std::mutex> lock(gSignalMutex);
    const auto it = gSessions.find(static_cast<int64_t>(userId));
    if (it == gSessions.end()) {
        env->ReleaseStringUTFChars(plaintext, messageText);
        return nullptr;
    }

    auto &session = it->second;
    MessageMetadata metadata;
    metadata.messageCounter = session.sendingCounter++;
    metadata.iv = randomVector(kGcmIvSize);
    metadata.senderPublicKey = gIdentity.identityPublic;
    metadata.timestamp = nowSeconds();

    ByteVector plainBytes(reinterpret_cast<const uint8_t *>(messageText), reinterpret_cast<const uint8_t *>(messageText) + std::strlen(messageText));
    env->ReleaseStringUTFChars(plaintext, messageText);

    const auto key = deriveMessageKey(session.sendingChainKey, metadata.messageCounter);
    session.sendingChainKey = ratchetChain(session.sendingChainKey);
    const auto ciphertext = aesGcmEncrypt(key, metadata.iv, plainBytes, metadataAad(metadata));
    if (!ciphertext.has_value()) return nullptr;

    const auto metaBytes = serializeMetadata(metadata);
    ByteVector envelope;
    pushU8(envelope, kSignalEnvelopeVersion);
    pushVector(envelope, metaBytes);
    pushVector(envelope, *ciphertext);
    return vectorToJByteArray(env, envelope);
}

JNIEXPORT jstring JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeDecrypt(JNIEnv *env, jobject, jlong userId, jbyteArray ciphertext) {
    const auto envelope = jbyteArrayToVector(env, ciphertext);
    if (envelope.empty()) return nullptr;

    std::lock_guard<std::mutex> lock(gSignalMutex);
    const auto it = gSessions.find(static_cast<int64_t>(userId));
    if (it == gSessions.end()) return nullptr;

    size_t pos = 0;
    uint8_t version = 0;
    ByteVector metaBytes;
    ByteVector payload;
    if (!readU8(envelope.data(), envelope.size(), pos, version) ||
        version != kSignalEnvelopeVersion ||
        !readVector(envelope.data(), envelope.size(), pos, metaBytes) ||
        !readVector(envelope.data(), envelope.size(), pos, payload)) {
        return nullptr;
    }

    MessageMetadata metadata;
    size_t metaPos = 0;
    if (!deserializeMetadata(metaBytes.data(), metaBytes.size(), metaPos, metadata)) return nullptr;

    auto &session = it->second;
    while (session.receivingCounter < metadata.messageCounter) {
        if (session.skippedReceivingKeys.size() >= kMaxSkippedKeys) {
            session.skippedReceivingKeys.erase(session.skippedReceivingKeys.begin());
        }
        session.skippedReceivingKeys[session.receivingCounter] = deriveMessageKey(session.receivingChainKey, session.receivingCounter);
        session.receivingChainKey = ratchetChain(session.receivingChainKey);
        ++session.receivingCounter;
    }

    ByteVector key;
    const auto skipped = session.skippedReceivingKeys.find(metadata.messageCounter);
    if (skipped != session.skippedReceivingKeys.end()) {
        key = skipped->second;
        session.skippedReceivingKeys.erase(skipped);
    } else {
        key = deriveMessageKey(session.receivingChainKey, metadata.messageCounter);
        session.receivingChainKey = ratchetChain(session.receivingChainKey);
        session.receivingCounter = metadata.messageCounter + 1;
    }

    const auto plaintext = aesGcmDecrypt(key, metadata.iv, payload, metadataAad(metadata));
    if (!plaintext.has_value()) return nullptr;
    std::string text(reinterpret_cast<const char *>(plaintext->data()), plaintext->size());
    return env->NewStringUTF(text.c_str());
}

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeRotateSession(JNIEnv *, jobject, jlong userId) {
    std::lock_guard<std::mutex> lock(gSignalMutex);
    const auto it = gSessions.find(static_cast<int64_t>(userId));
    if (it == gSessions.end()) return JNI_FALSE;
    auto dh = randomVector(kAes256KeySize);
    it->second.rootKey = hkdfSha256(it->second.rootKey, "Cryptogram-Android-DoubleRatchet-Rotate", kAes256KeySize, dh);
    it->second.sendingChainKey = hkdfSha256(it->second.rootKey, "Cryptogram-Android-Chain-A", kAes256KeySize);
    it->second.receivingChainKey = hkdfSha256(it->second.rootKey, "Cryptogram-Android-Chain-B", kAes256KeySize);
    it->second.sendingCounter = 0;
    it->second.receivingCounter = 0;
    it->second.skippedReceivingKeys.clear();
    return JNI_TRUE;
}

JNIEXPORT jstring JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeGetFingerprint(JNIEnv *env, jobject, jlong userId) {
    std::lock_guard<std::mutex> lock(gSignalMutex);
    const auto it = gSessions.find(static_cast<int64_t>(userId));
    if (it == gSessions.end()) return env->NewStringUTF("UNINITIALIZED");
    const auto digest = sha256Concat(gIdentity.identityPublic, it->second.remoteIdentityKey);
    std::ostringstream out;
    for (int i = 0; i < 5; ++i) {
        const uint16_t chunk = static_cast<uint16_t>((digest[i * 2] << 8) | digest[i * 2 + 1]);
        if (i > 0) out << '-';
        out << std::setw(4) << std::setfill('0') << (chunk % 10000);
    }
    return env->NewStringUTF(out.str().c_str());
}

JNIEXPORT jstring JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeGetState(JNIEnv *env, jobject, jlong userId) {
    std::lock_guard<std::mutex> lock(gSignalMutex);
    const auto json = serializeSignalState(static_cast<int64_t>(userId));
    std::string text(json.begin(), json.end());
    return env->NewStringUTF(text.c_str());
}

JNIEXPORT jbyteArray JNICALL
Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeGenerateKeyPackage(JNIEnv *env, jobject) {
    ByteVector package;
    pushVector(package, randomVector(kX25519KeySize));
    pushVector(package, randomVector(kEd25519PublicKeySize));
    pushU32(package, nowSeconds());
    return vectorToJByteArray(env, package);
}

JNIEXPORT jlong JNICALL
Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeProcessWelcome(JNIEnv *env, jobject, jbyteArray welcomeData) {
    const auto welcome = jbyteArrayToVector(env, welcomeData);
    if (welcome.size() < kAes256KeySize) return 0;
    MlsGroup group;
    group.groupId.assign(welcome.begin(), welcome.begin() + kAes256KeySize);
    group.epochSecret = sha256Concat(welcome, randomVector(kAes256KeySize));
    uint64_t handle = 0;
    if (!randomBytes(reinterpret_cast<uint8_t *>(&handle), sizeof(handle)) || handle == 0) return 0;
    std::lock_guard<std::mutex> lock(gMlsMutex);
    gMlsGroups[static_cast<int64_t>(handle)] = std::move(group);
    return static_cast<jlong>(handle);
}

JNIEXPORT jbyteArray JNICALL
Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeCommitGroupChanges(JNIEnv *env, jobject, jlong groupId) {
    std::lock_guard<std::mutex> lock(gMlsMutex);
    const auto it = gMlsGroups.find(static_cast<int64_t>(groupId));
    if (it == gMlsGroups.end()) return nullptr;
    it->second.epochSecret = hkdfSha256(it->second.epochSecret, "Cryptogram-Android-MLS-Commit", kAes256KeySize);
    ++it->second.epoch;
    ByteVector commit;
    pushU64(commit, it->second.epoch);
    pushVector(commit, it->second.epochSecret);
    return vectorToJByteArray(env, commit);
}

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeCreateGroup(JNIEnv *, jobject, jlong groupId, jlongArray memberIds) {
    if (!memberIds) return JNI_FALSE;
    MlsGroup group;
    group.groupId = randomVector(kAes256KeySize);
    group.epochSecret = randomVector(kAes256KeySize);
    if (group.groupId.empty() || group.epochSecret.empty()) return JNI_FALSE;
    std::lock_guard<std::mutex> lock(gMlsMutex);
    gMlsGroups[static_cast<int64_t>(groupId)] = std::move(group);
    return JNI_TRUE;
}

JNIEXPORT jbyteArray JNICALL
Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeEncryptGroupMessage(JNIEnv *env, jobject, jlong groupId, jstring plaintext) {
    if (!plaintext) return nullptr;
    const char *messageText = env->GetStringUTFChars(plaintext, nullptr);
    if (!messageText) return nullptr;

    std::lock_guard<std::mutex> lock(gMlsMutex);
    auto it = gMlsGroups.find(static_cast<int64_t>(groupId));
    if (it == gMlsGroups.end()) {
        env->ReleaseStringUTFChars(plaintext, messageText);
        return nullptr;
    }
    auto key = mlsSecretForGroup(it->second);
    auto iv = randomVector(kGcmIvSize);
    ByteVector plainBytes(reinterpret_cast<const uint8_t *>(messageText), reinterpret_cast<const uint8_t *>(messageText) + std::strlen(messageText));
    env->ReleaseStringUTFChars(plaintext, messageText);
    ByteVector aad;
    pushU64(aad, it->second.epoch);
    auto ciphertext = aesGcmEncrypt(key, iv, plainBytes, aad);
    if (!ciphertext.has_value()) return nullptr;
    ByteVector envelope;
    pushU8(envelope, kMlsEnvelopeVersion);
    pushU64(envelope, it->second.epoch);
    pushVector(envelope, iv);
    pushVector(envelope, *ciphertext);
    return vectorToJByteArray(env, envelope);
}

JNIEXPORT jstring JNICALL
Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeDecryptGroupMessage(JNIEnv *env, jobject, jlong groupId, jbyteArray ciphertext) {
    const auto envelope = jbyteArrayToVector(env, ciphertext);
    if (envelope.empty()) return nullptr;
    std::lock_guard<std::mutex> lock(gMlsMutex);
    auto it = gMlsGroups.find(static_cast<int64_t>(groupId));
    if (it == gMlsGroups.end()) return nullptr;
    size_t pos = 0;
    uint8_t version = 0;
    uint64_t epoch = 0;
    ByteVector iv;
    ByteVector payload;
    if (!readU8(envelope.data(), envelope.size(), pos, version) ||
        version != kMlsEnvelopeVersion ||
        !readU64(envelope.data(), envelope.size(), pos, epoch) ||
        !readVector(envelope.data(), envelope.size(), pos, iv) ||
        !readVector(envelope.data(), envelope.size(), pos, payload) ||
        epoch != it->second.epoch) {
        return nullptr;
    }
    auto key = mlsSecretForGroup(it->second);
    ByteVector aad;
    pushU64(aad, epoch);
    auto plaintext = aesGcmDecrypt(key, iv, payload, aad);
    if (!plaintext.has_value()) return nullptr;
    std::string text(reinterpret_cast<const char *>(plaintext->data()), plaintext->size());
    return env->NewStringUTF(text.c_str());
}

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeAddMember(JNIEnv *, jobject, jlong groupId, jlong) {
    std::lock_guard<std::mutex> lock(gMlsMutex);
    const auto it = gMlsGroups.find(static_cast<int64_t>(groupId));
    if (it == gMlsGroups.end()) return JNI_FALSE;
    it->second.epochSecret = hkdfSha256(it->second.epochSecret, "Cryptogram-Android-MLS-Add", kAes256KeySize);
    ++it->second.epoch;
    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeRemoveMember(JNIEnv *, jobject, jlong groupId, jlong) {
    std::lock_guard<std::mutex> lock(gMlsMutex);
    const auto it = gMlsGroups.find(static_cast<int64_t>(groupId));
    if (it == gMlsGroups.end()) return JNI_FALSE;
    it->second.epochSecret = hkdfSha256(it->second.epochSecret, "Cryptogram-Android-MLS-Remove", kAes256KeySize);
    ++it->second.epoch;
    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_EnhancedPrivacy_nativeIsCryptogramUser(JNIEnv *, jobject, jlong userId) {
    std::lock_guard<std::mutex> lock(gPrivacyMutex);
    return gCryptogramUsers.find(static_cast<int64_t>(userId)) != gCryptogramUsers.end() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_org_telegram_messenger_cryptogram_CryptogramNative_nativeGetVersion(JNIEnv *env, jobject) {
    return env->NewStringUTF("CRYPTOGRAM Android 1.1.0");
}

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_CryptogramNative_nativeCheckDoubleRatchet(JNIEnv *, jobject) {
    std::lock_guard<std::mutex> lock(gSignalMutex);
    return runDoubleRatchetSelfTest() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_CryptogramNative_nativeCheckMLS(JNIEnv *, jobject) {
    return runMlsSelfTest() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_org_telegram_messenger_cryptogram_CryptogramNative_nativeInitializeStorage(JNIEnv *env, jobject, jstring path) {
    if (!path) return;
    const char *pathStr = env->GetStringUTFChars(path, nullptr);
    if (!pathStr) return;
    gStoragePath = pathStr;
    env->ReleaseStringUTFChars(path, pathStr);
}

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *) {
    gJavaVM = vm;
    return JNI_VERSION_1_6;
}

} // extern "C"
