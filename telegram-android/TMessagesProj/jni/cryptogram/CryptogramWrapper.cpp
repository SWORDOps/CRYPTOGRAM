/*
 * CRYPTOGRAM Android JNI bridge.
 *
 * The Double Ratchet protocol core lives in cryptogram/interop/
 * InteropCore.{h,cpp} — a JNI-free, byte-compatible port of the desktop
 * spec (Telegram/SourceFiles/data/data_signal_protocol.cpp and
 * data_signal_transport.cpp). This wrapper keeps the per-user session map
 * and mutexes and delegates all crypto and wire-format work to InteropCore.
 */

#include <jni.h>
#include <android/log.h>

#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "interop/InteropCore.h"
#include "interop/KemKeyStore.h"

#include <cstdint>
#include <cstring>
#include <iomanip>
#include <mutex>
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
constexpr size_t kAes256KeySize = 32;
constexpr size_t kGcmIvSize = 12;
constexpr uint8_t kMlsEnvelopeVersion = 1;

JavaVM *gJavaVM = nullptr;
std::string gStoragePath;

struct MlsGroup {
    ByteVector groupId;
    ByteVector epochSecret;
    uint64_t epoch = 0;
};

std::mutex gSignalMutex;
interop::LocalIdentity gIdentity;
// Static ML-KEM identity (desktop ensureQuantumIdentity parity): generated
// once, persisted under <filesDir>/cryptogram/interop/pq_identity, advertised
// in the local bundle's 0x02 extension. Guarded by gSignalMutex.
interop::KemKeyPair gKemIdentity;
// Obfuscation-grade AT-REST wrapping only (desktop wraps its QuantumGuard
// store with userId + device identifier; Android's identity is app-scoped,
// so a fixed app-local string plays the same role).
const char kPqIdentityPassword[] = "cryptogram-android-pq-identity";
std::unordered_map<int64_t, interop::SessionState> gSessions;
// Remote bundles registered via nativeInitializeWithRemoteBundle. They are
// needed for the Bob-side session establishment at first contact and for
// the stale-session retry in nativeDecrypt. A bundle's quantumKemPublicKey
// (extension 0x02) gates PQE1 wrapping for that peer.
std::unordered_map<int64_t, interop::KeyBundle> gRemoteBundles;
std::mutex gMlsMutex;
std::unordered_map<int64_t, MlsGroup> gMlsGroups;
std::mutex gPrivacyMutex;
std::unordered_map<int64_t, bool> gCryptogramUsers;

uint32_t nowSeconds() {
    return static_cast<uint32_t>(time(nullptr));
}

bool randomBytes(uint8_t *data, size_t size) {
    return RAND_bytes(data, static_cast<int>(size)) == 1;
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

void pushVector(ByteVector &out, const ByteVector &value) {
    pushU32(out, static_cast<uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

bool readU8(const uint8_t *data, size_t size, size_t &pos, uint8_t &value) {
    if (pos + sizeof(value) > size) return false;
    value = data[pos++];
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

bool readVector(const uint8_t *data, size_t size, size_t &pos, ByteVector &value) {
    uint32_t len = 0;
    for (int shift = 0; shift < 32; shift += 8) {
        if (pos + sizeof(uint8_t) > size) return false;
        len |= static_cast<uint32_t>(data[pos++]) << shift;
    }
    if (len > size - pos) return false; // pos <= size always; overflow-safe
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

// Proper UTF-8 encoding of a jstring (GetStringUTFChars yields JNI
// "modified UTF-8", which is NOT UTF-8 for supplementary characters —
// the desktop side decodes real UTF-8).
ByteVector jstringToUtf8Bytes(JNIEnv *env, jstring text) {
    ByteVector result;
    if (!text) return result;
    const jsize length = env->GetStringLength(text);
    if (length <= 0) return result;
    const jchar *chars = env->GetStringChars(text, nullptr);
    if (!chars) return result;

    auto pushCodePoint = [&result](uint32_t cp) {
        if (cp < 0x80) {
            result.push_back(static_cast<uint8_t>(cp));
        } else if (cp < 0x800) {
            result.push_back(static_cast<uint8_t>(0xC0 | (cp >> 6)));
            result.push_back(static_cast<uint8_t>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            result.push_back(static_cast<uint8_t>(0xE0 | (cp >> 12)));
            result.push_back(static_cast<uint8_t>(0x80 | ((cp >> 6) & 0x3F)));
            result.push_back(static_cast<uint8_t>(0x80 | (cp & 0x3F)));
        } else {
            result.push_back(static_cast<uint8_t>(0xF0 | (cp >> 18)));
            result.push_back(static_cast<uint8_t>(0x80 | ((cp >> 12) & 0x3F)));
            result.push_back(static_cast<uint8_t>(0x80 | ((cp >> 6) & 0x3F)));
            result.push_back(static_cast<uint8_t>(0x80 | (cp & 0x3F)));
        }
    };

    for (jsize i = 0; i < length;) {
        uint32_t cp = chars[i];
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < length) {
            const uint32_t low = chars[i + 1];
            if (low >= 0xDC00 && low <= 0xDFFF) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                pushCodePoint(cp);
                i += 2;
                continue;
            }
        }
        pushCodePoint(cp);
        i += 1;
    }
    env->ReleaseStringChars(text, chars);
    return result;
}

// jstring from real UTF-8 bytes (NewStringUTF expects modified UTF-8 and
// corrupts 4-byte sequences; the desktop sends real UTF-8).
jstring utf8BytesToJString(JNIEnv *env, const ByteVector &bytes) {
    std::vector<uint16_t> units;
    units.reserve(bytes.size());
    size_t i = 0;
    while (i < bytes.size()) {
        const uint8_t first = bytes[i];
        uint32_t cp = first;
        size_t advance = 1;
        if ((first & 0xE0) == 0xC0 && i + 1 < bytes.size()) {
            cp = (static_cast<uint32_t>(first & 0x1F) << 6)
                | (bytes[i + 1] & 0x3F);
            advance = 2;
        } else if ((first & 0xF0) == 0xE0 && i + 2 < bytes.size()) {
            cp = (static_cast<uint32_t>(first & 0x0F) << 12)
                | (static_cast<uint32_t>(bytes[i + 1] & 0x3F) << 6)
                | (bytes[i + 2] & 0x3F);
            advance = 3;
        } else if ((first & 0xF8) == 0xF0 && i + 3 < bytes.size()) {
            cp = (static_cast<uint32_t>(first & 0x07) << 18)
                | (static_cast<uint32_t>(bytes[i + 1] & 0x3F) << 12)
                | (static_cast<uint32_t>(bytes[i + 2] & 0x3F) << 6)
                | (bytes[i + 3] & 0x3F);
            advance = 4;
        }
        i += advance;

        if (cp >= 0x10000) {
            cp -= 0x10000;
            units.push_back(static_cast<uint16_t>(0xD800 + (cp >> 10)));
            units.push_back(static_cast<uint16_t>(0xDC00 + (cp & 0x3FF)));
        } else {
            units.push_back(static_cast<uint16_t>(cp));
        }
    }
    return env->NewString(units.data(), static_cast<jsize>(units.size()));
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

bool ensureIdentity() {
    if (gIdentity.initialized) return true;
    return interop::generateLocalIdentity(gIdentity);
}

// Full path of the encrypted KEM identity store; empty when no storage dir
// was passed via nativeInitializeStorage (identity then lives in memory
// only, matching the desktop's tolerance for persistence failures).
std::string pqIdentityPath() {
    const auto dir = interop::interopStoragePath(gStoragePath);
    if (dir.empty()) return {};
    return dir + "/" + interop::kPqIdentityFileName;
}

// Desktop ensureQuantumIdentity semantics: load the persisted static KEM
// identity when present, otherwise generate and persist. Persistence failure
// is non-fatal (desktop logs and keeps the in-memory identity).
bool ensureKemIdentity() {
    if (!gKemIdentity.publicKeyDer.empty()) return true;

    const auto path = pqIdentityPath();
    if (!path.empty()) {
        interop::KemKeyPair stored;
        if (interop::loadKemIdentity(path, kPqIdentityPassword, stored)
                && !stored.privateKeyBlob.empty()
                && !stored.publicKeyDer.empty()) {
            gKemIdentity = std::move(stored);
            LOGD("Loaded persisted ML-KEM identity");
            return true;
        }
    }

    gKemIdentity = interop::generateKemIdentity();
    if (gKemIdentity.publicKeyDer.empty()) {
        LOGE("ML-KEM identity generation failed");
        return false;
    }
    if (!path.empty() && interop::saveKemIdentity(path, kPqIdentityPassword, gKemIdentity)) {
        LOGD("Generated and persisted static ML-KEM identity");
    } else if (!path.empty()) {
        LOGE("ML-KEM identity persistence failed — keeping in-memory identity");
    }
    return true;
}

// Desktop gate semantics: PQ-wrap outgoing payloads ONLY when the peer's
// registered bundle advertised the 0x02 KEM extension.
bool peerKemAdvertised(int64_t userId) {
    const auto it = gRemoteBundles.find(userId);
    return it != gRemoteBundles.end()
        && !it->second.quantumKemPublicKey.empty();
}

ByteVector serializeSignalState(int64_t userId) {
    const auto it = gSessions.find(userId);
    std::ostringstream out;
    out << "{\"initialized\": true, \"protocol\": \"Signal Double Ratchet (desktop-compatible)\", \"hasSession\": "
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

// Full both-sides exercise of the desktop-compatible core:
// bundle serialization -> Alice X3DH -> encrypt -> envelope round-trip ->
// Bob-side establishment -> decrypt -> DH-ratcheted reply -> out-of-order
// delivery with skipped keys.
bool runDoubleRatchetSelfTest() {
    interop::LocalIdentity alice;
    interop::LocalIdentity bob;
    if (!interop::generateLocalIdentity(alice) || !interop::generateLocalIdentity(bob)) {
        return false;
    }

    // Bob advertises his bundle; Alice consumes the serialized form.
    const auto bobBundleRaw = interop::encodeKeyBundle(interop::localKeyBundle(bob));
    interop::KeyBundle bobBundle;
    if (!interop::decodeKeyBundle(bobBundleRaw, bobBundle)
            || !interop::verifyKeyBundleSignature(bobBundle)) {
        return false;
    }

    const auto aliceBundleRaw = interop::encodeKeyBundle(interop::localKeyBundle(alice));
    interop::KeyBundle aliceBundle;
    if (!interop::decodeKeyBundle(aliceBundleRaw, aliceBundle)) {
        return false;
    }

    interop::SessionState aliceSession;
    if (!interop::establishSessionAlice(aliceSession, alice, bobBundle)) {
        return false;
    }

    const ByteVector hello = {'h', 'e', 'l', 'l', 'o'};
    interop::MessageMetadata metadata;
    const auto ciphertext = interop::encryptMessage(aliceSession, hello, metadata);
    if (ciphertext.empty()) {
        return false;
    }

    const auto envelopeRaw = interop::wrapEnvelope(ciphertext, metadata);
    interop::Envelope unwrapped;
    if (!interop::unwrapEnvelope(envelopeRaw, unwrapped)) {
        return false;
    }

    // Bob-side establishment is driven by the sender public key carried in
    // the first message's metadata.
    interop::SessionState bobSession;
    if (!interop::establishSessionBob(bobSession, bob, unwrapped.metadata.senderPublicKey, aliceBundle)) {
        return false;
    }
    const auto plaintext = interop::decryptMessage(bobSession, unwrapped.ciphertext, unwrapped.metadata);
    if (plaintext != hello) {
        return false;
    }

    // Bob replies; Alice's receiving chain must stay in sync.
    const ByteVector reply = {'r', 'e', 'p', 'l', 'y'};
    interop::MessageMetadata replyMetadata;
    const auto replyCiphertext = interop::encryptMessage(bobSession, reply, replyMetadata);
    if (replyCiphertext.empty()) {
        return false;
    }
    const auto replyPlaintext = interop::decryptMessage(aliceSession, replyCiphertext, replyMetadata);
    if (replyPlaintext != reply) {
        return false;
    }

    // Out-of-order delivery: skip-ahead storage, then skipped-key lookup.
    const ByteVector second = {'m', '2'};
    const ByteVector third = {'m', '3'};
    interop::MessageMetadata secondMetadata;
    interop::MessageMetadata thirdMetadata;
    const auto secondCiphertext = interop::encryptMessage(aliceSession, second, secondMetadata);
    const auto thirdCiphertext = interop::encryptMessage(aliceSession, third, thirdMetadata);
    if (secondCiphertext.empty() || thirdCiphertext.empty()) {
        return false;
    }
    const auto thirdPlaintext = interop::decryptMessage(bobSession, thirdCiphertext, thirdMetadata);
    if (thirdPlaintext != third) {
        return false;
    }
    const auto secondPlaintext = interop::decryptMessage(bobSession, secondCiphertext, secondMetadata);
    if (secondPlaintext != second) {
        return false;
    }

    return true;
}

// Full both-sides exercise of the post-quantum layer: KEM identity
// generation, persistence-blob restore, PQE1 wrap/unwrap, tamper rejection
// and wrong-key rejection (desktop quantumWrap/quantumUnwrap parity).
bool runPqSelfTest() {
    const auto alice = interop::generateKemIdentity();
    const auto bob = interop::generateKemIdentity();
    if (alice.publicKeyDer.empty() || bob.publicKeyDer.empty()) {
        return false;
    }

    // The persisted-private-restore path (what loadKemIdentity hands back).
    const auto bobRestored = interop::kemIdentityFromPrivateBlob(bob.privateKeyBlob);
    if (bobRestored.publicKeyDer != bob.publicKeyDer) {
        return false;
    }

    const ByteVector message = {'p', 'q', ' ', 'o', 'k'};
    const auto wrapped = interop::wrapPqe1(bob.publicKeyDer, message);
    if (wrapped.empty()
            || !interop::isPqe1Envelope(wrapped)
            || interop::unwrapPqe1(bobRestored.privateKeyBlob, wrapped) != message) {
        return false;
    }

    // Tampered envelope must fail authentication.
    auto tampered = wrapped;
    tampered.back() ^= 0x01;
    if (!interop::unwrapPqe1(bobRestored.privateKeyBlob, tampered).empty()) {
        return false;
    }

    // A wrong private key must never yield the message.
    const auto eve = interop::generateKemIdentity();
    return interop::unwrapPqe1(eve.privateKeyBlob, wrapped).empty();
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
    auto encrypted = interop::aesGcmEncrypt(key, iv, plaintext, aad);
    if (encrypted.empty()) return false;
    auto decrypted = interop::aesGcmDecrypt(key, iv, encrypted, aad);
    return !decrypted.empty() && decrypted == plaintext;
}

} // namespace

extern "C" {

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeInitializeSession(JNIEnv *, jobject, jlong userId) {
    std::lock_guard<std::mutex> lock(gSignalMutex);
    // A real session requires a remote bundle (X3DH); this prepares the
    // local identity so bundles can be generated and first-contact
    // establishment can succeed.
    if (!ensureIdentity()) return JNI_FALSE;
    gCryptogramUsers[static_cast<int64_t>(userId)] = true;
    return JNI_TRUE;
}

JNIEXPORT jbyteArray JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeGenerateKeyBundle(JNIEnv *env, jobject) {
    std::lock_guard<std::mutex> lock(gSignalMutex);
    if (!ensureIdentity()) return nullptr;
    const auto bundle = interop::localKeyBundle(gIdentity);
    // Desktop transport format: version 0x01, one-time pre-key present, the
    // static KEM public key (SPKI DER) in the 0x02 extension (desktop PQ
    // parity), X25519 identity in the 0x04 extension. Like the desktop's
    // ensureQuantumIdentity, an unavailable KEM identity degrades the bundle
    // to classic-only instead of failing.
    interop::KeyBundle fullBundle = bundle;
    if (ensureKemIdentity()) {
        fullBundle.quantumKemPublicKey = gKemIdentity.publicKeyDer;
    } else {
        LOGE("KEM identity unavailable — emitting classic-only bundle");
    }
    const auto raw = interop::encodeKeyBundle(fullBundle);
    if (raw.empty()) return nullptr;
    return vectorToJByteArray(env, raw);
}

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeInitializeWithRemoteBundle(JNIEnv *env, jobject, jlong userId, jbyteArray bundleData) {
    const auto data = jbyteArrayToVector(env, bundleData);
    if (data.empty()) return JNI_FALSE;
    interop::KeyBundle bundle;
    if (!interop::decodeKeyBundle(data, bundle)) return JNI_FALSE;

    std::lock_guard<std::mutex> lock(gSignalMutex);
    if (!ensureIdentity()) return JNI_FALSE;
    if (!interop::verifyKeyBundleSignature(bundle)) return JNI_FALSE;

    // Alice side of the fixed X3DH; requires the bundle's 0x04 X25519
    // identity. Bob-side establishment happens at first decrypt.
    interop::SessionState session;
    if (!interop::establishSessionAlice(session, gIdentity, bundle)) return JNI_FALSE;

    const auto key = static_cast<int64_t>(userId);
    gSessions[key] = std::move(session);
    gRemoteBundles[key] = bundle;
    gCryptogramUsers[key] = true;
    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeHasSession(JNIEnv *, jobject, jlong userId) {
    std::lock_guard<std::mutex> lock(gSignalMutex);
    return gSessions.find(static_cast<int64_t>(userId)) != gSessions.end() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jbyteArray JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeEncrypt(JNIEnv *env, jobject, jlong userId, jstring plaintext) {
    if (!plaintext) return nullptr;

    std::lock_guard<std::mutex> lock(gSignalMutex);
    if (!ensureIdentity()) return nullptr;
    const auto it = gSessions.find(static_cast<int64_t>(userId));
    if (it == gSessions.end()) return nullptr;

    const auto plainBytes = jstringToUtf8Bytes(env, plaintext);
    const auto key = static_cast<int64_t>(userId);

    // Post-quantum inner envelope (desktop processOutgoingMessage): when the
    // peer's registered bundle advertised a KEM key (bitmap 0x02), wrap the
    // PLAINTEXT in the PQE1 envelope BEFORE the ratchet encrypt. On wrap
    // failure the desktop silently falls back to classic-only — so do we.
    ByteVector payload = plainBytes;
    if (peerKemAdvertised(key) && ensureKemIdentity()) {
        auto quantumWrapped = interop::wrapPqe1(
            gRemoteBundles[key].quantumKemPublicKey, plainBytes);
        if (!quantumWrapped.empty()) {
            payload = std::move(quantumWrapped);
        } else {
            LOGE("PQE1 wrap failed — sending classic-only for user %lld",
                 static_cast<long long>(key));
        }
    }

    interop::MessageMetadata metadata;
    const auto ciphertext = interop::encryptMessage(it->second, payload, metadata);
    if (ciphertext.empty()) return nullptr;

    // ZK Phase 1: always attach a fresh challenge nonce. Android never
    // emits a CAC response.
    metadata.hasCacChallenge = true;
    metadata.cacChallengeNonce = interop::randomVector(interop::kCacChallengeNonceSize);
    if (metadata.cacChallengeNonce.empty()) return nullptr;

    // Raw desktop envelope bytes (QDataStream layout); the Java layer
    // applies any text-level framing.
    const auto envelope = interop::wrapEnvelope(ciphertext, metadata);
    if (envelope.empty()) return nullptr;
    return vectorToJByteArray(env, envelope);
}

JNIEXPORT jstring JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeDecrypt(JNIEnv *env, jobject, jlong userId, jbyteArray ciphertext) {
    const auto blob = jbyteArrayToVector(env, ciphertext);
    if (blob.empty()) return nullptr;

    std::lock_guard<std::mutex> lock(gSignalMutex);
    if (!ensureIdentity()) return nullptr;

    interop::Envelope envelope;
    if (!interop::unwrapEnvelope(blob, envelope)) return nullptr;
    if (envelope.metadata.senderPublicKey.size() != interop::kKeySize) return nullptr;

    const auto key = static_cast<int64_t>(userId);
    auto it = gSessions.find(key);
    if (it == gSessions.end()) {
        // First contact with a registered bundle: run the BOB-side
        // establishment using the sender public key from the metadata as
        // Alice's ephemeral.
        const auto bundleIt = gRemoteBundles.find(key);
        if (bundleIt == gRemoteBundles.end()) return nullptr;
        interop::SessionState established;
        if (!interop::establishSessionBob(established, gIdentity, envelope.metadata.senderPublicKey, bundleIt->second)) {
            return nullptr;
        }
        it = gSessions.emplace(key, std::move(established)).first;
        gCryptogramUsers[key] = true;
    }

    auto plaintext = interop::decryptMessage(it->second, envelope.ciphertext, envelope.metadata);
    if (plaintext.empty()) {
        // Stale-session retry: re-establish once from this message's
        // sender key and retry. The existing session is only replaced
        // when the retry succeeds.
        const auto bundleIt = gRemoteBundles.find(key);
        if (bundleIt != gRemoteBundles.end()) {
            interop::SessionState established;
            if (interop::establishSessionBob(established, gIdentity, envelope.metadata.senderPublicKey, bundleIt->second)) {
                auto retried = interop::decryptMessage(established, envelope.ciphertext, envelope.metadata);
                if (!retried.empty()) {
                    gSessions[key] = std::move(established);
                    gCryptogramUsers[key] = true;
                    plaintext = std::move(retried);
                }
            }
        }
    }
    if (plaintext.empty()) return nullptr;

    // Post-quantum inner envelope (desktop processIncomingMessage): real
    // ML-KEM decapsulation + AES-256-GCM, stripped AFTER the classic ratchet
    // layer has been removed. An unwrap failure drops the message — the
    // desktop does the same rather than showing a mixed-classical payload.
    if (interop::isPqe1Envelope(plaintext)) {
        if (!ensureKemIdentity()) return nullptr;
        auto unwrappedPq = interop::unwrapPqe1(gKemIdentity.privateKeyBlob, plaintext);
        if (unwrappedPq.empty()) {
            LOGE("PQE1 unwrap failed — dropping message from user %lld",
                 static_cast<long long>(key));
            return nullptr;
        }
        plaintext = std::move(unwrappedPq);
    }

    return utf8BytesToJString(env, plaintext);
}

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeRotateSession(JNIEnv *, jobject, jlong userId) {
    std::lock_guard<std::mutex> lock(gSignalMutex);
    const auto it = gSessions.find(static_cast<int64_t>(userId));
    if (it == gSessions.end()) return JNI_FALSE;
    return interop::rotateSession(it->second) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeGetFingerprint(JNIEnv *env, jobject, jlong userId) {
    std::lock_guard<std::mutex> lock(gSignalMutex);
    const auto it = gSessions.find(static_cast<int64_t>(userId));
    if (it == gSessions.end() || !ensureIdentity()) return env->NewStringUTF("UNINITIALIZED");
    const auto digest = sha256Concat(gIdentity.ed25519Public, it->second.remoteIdentityKey);
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
    auto ciphertext = interop::aesGcmEncrypt(key, iv, plainBytes, aad);
    if (ciphertext.empty()) return nullptr;
    ByteVector envelope;
    pushU8(envelope, kMlsEnvelopeVersion);
    pushU64(envelope, it->second.epoch);
    pushVector(envelope, iv);
    pushVector(envelope, ciphertext);
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
    auto plaintext = interop::aesGcmDecrypt(key, iv, payload, aad);
    if (plaintext.empty()) return nullptr;
    std::string text(reinterpret_cast<const char *>(plaintext.data()), plaintext.size());
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
    // The PQ self-test rides the Double Ratchet check: the post-quantum
    // layer is part of the same 1:1 message pipeline.
    return (runDoubleRatchetSelfTest() && runPqSelfTest()) ? JNI_TRUE : JNI_FALSE;
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
