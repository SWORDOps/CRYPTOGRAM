/**
 * CRYPTOGRAM JNI Wrapper
 * Bridges native CRYPTOGRAM functionality to Android Java/Kotlin.
 */

#include "cryptogram/data/data_mls_protocol.h"
#include "cryptogram/data/data_enhanced_privacy.h"
#include "desktop_shims.h"

#include <jni.h>
#include <android/log.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#define LOG_TAG "CryptogramNative"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

using namespace Data;

namespace {

JavaVM* gJavaVM = nullptr;
jmethodID gGenerateIdentityKeyMethod = nullptr;
jmethodID gGeneratePreKeyMethod = nullptr;
jmethodID gGenerateOneTimeKeyMethod = nullptr;
jmethodID gSignMessageMethod = nullptr;

std::mutex gSignalMutex;
std::unique_ptr<SignalProtocol> gSignalProtocol;
std::unique_ptr<Session> gDummySession;

std::mutex gMlsMutex;
std::unordered_map<int64_t, MLSGroupId> gMlsGroups;

JNIEnv* getJNIEnv() {
    JNIEnv* env = nullptr;
    if (gJavaVM->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        gJavaVM->AttachCurrentThread(&env, nullptr);
    }
    return env;
}

bytes::vector jbyteArrayToVector(JNIEnv* env, jbyteArray array) {
    if (!array) return {};
    jsize len = env->GetArrayLength(array);
    jbyte* bytes = env->GetByteArrayElements(array, nullptr);
    bytes::vector result(reinterpret_cast<uint8_t*>(bytes), reinterpret_cast<uint8_t*>(bytes) + len);
    env->ReleaseByteArrayElements(array, bytes, JNI_ABORT);
    return result;
}

bool ensureSignalProtocol() {
    if (!gSignalProtocol) {
        if (!gDummySession) {
            gDummySession = std::make_unique<Session>();
        }
        gSignalProtocol = std::make_unique<SignalProtocol>(gDummySession.get());
        gSignalProtocol->setEnabled(true);
    }
    return gSignalProtocol != nullptr;
}

not_null<PeerData*> peerForUserId(int64_t userId) {
    return PeerData::from(
        gDummySession.get(),
        PeerId(static_cast<uint64>(userId)));
}

std::string buildSessionFingerprint(not_null<PeerData*> peer) {
    auto state = gSignalProtocol->getSession(peer);
    bytes::vector material;
    material.insert(material.end(), state.rootKey.begin(), state.rootKey.end());
    material.insert(material.end(), state.dhSendingPublicKey.begin(), state.dhSendingPublicKey.end());
    material.insert(material.end(), state.dhRemotePublicKey.begin(), state.dhRemotePublicKey.end());

    const auto append32 = [&](uint32_t value) {
        material.push_back(static_cast<uint8_t>(value & 0xFF));
        material.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        material.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        material.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    };
    append32(state.sendingMessageCounter);
    append32(state.receivingMessageCounter);

    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    if (!material.empty()) {
        SHA256(material.data(), material.size(), digest);
    } else {
        SHA256(reinterpret_cast<const uint8_t*>("empty"), 5, digest);
    }

    std::ostringstream out;
    for (int i = 0; i < 5; ++i) {
        const uint16_t chunk = static_cast<uint16_t>((digest[i * 2] << 8) | digest[i * 2 + 1]);
        if (i > 0) out << '-';
        out << std::setw(4) << std::setfill('0') << (chunk % 10000);
    }
    return out.str();
}

bool ensureMlsProtocol() {
    auto *protocol = GetMLSProtocol();
    if (!protocol) {
        InitializeMLSProtocol();
        protocol = GetMLSProtocol();
    }
    return protocol != nullptr;
}

// Serialization helpers
bytes::vector serializeKeyBundle(const SignalProtocol::KeyBundle &bundle) {
    bytes::vector result;
    // Simple binary format: [ID_LEN][ID][REG_ID][KEY_LEN][KEY][SPK_LEN][SPK][OTP_LEN][OTP][SIG_LEN][SIG]
    auto push_vec = [&](const bytes::vector &v) {
        uint32_t len = static_cast<uint32_t>(v.size());
        result.insert(result.end(), reinterpret_cast<uint8_t*>(&len), reinterpret_cast<uint8_t*>(&len) + 4);
        result.insert(result.end(), v.begin(), v.end());
    };

    uint32_t idLen = static_cast<uint32_t>(bundle.deviceId.identifier.length());
    result.insert(result.end(), reinterpret_cast<uint8_t*>(&idLen), reinterpret_cast<uint8_t*>(&idLen) + 4);
    result.insert(result.end(), bundle.deviceId.identifier.begin(), bundle.deviceId.identifier.end());
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&bundle.deviceId.registrationId), reinterpret_cast<const uint8_t*>(&bundle.deviceId.registrationId) + 8);

    push_vec(bundle.identityKey);
    push_vec(bundle.signedPreKey);
    push_vec(bundle.oneTimePreKey);
    push_vec(bundle.signature);
    return result;
}

SignalProtocol::KeyBundle deserializeKeyBundle(const uint8_t *data, size_t size) {
    SignalProtocol::KeyBundle bundle;
    size_t pos = 0;
    auto read_vec = [&](bytes::vector &v) {
        if (pos + 4 > size) return;
        uint32_t len;
        std::memcpy(&len, data + pos, 4);
        pos += 4;
        if (pos + len > size) return;
        v.assign(data + pos, data + pos + len);
        pos += len;
    };

    if (pos + 4 > size) return bundle;
    uint32_t idLen;
    std::memcpy(&idLen, data + pos, 4);
    pos += 4;
    if (pos + idLen > size) return bundle;
    bundle.deviceId.identifier = std::string(reinterpret_cast<const char*>(data + pos), idLen);
    pos += idLen;

    if (pos + 8 > size) return bundle;
    std::memcpy(&bundle.deviceId.registrationId, data + pos, 8);
    pos += 8;

    read_vec(bundle.identityKey);
    read_vec(bundle.signedPreKey);
    read_vec(bundle.oneTimePreKey);
    read_vec(bundle.signature);
    return bundle;
}

bytes::vector serializeMetadata(const SignalProtocol::MessageMetadata &metadata) {
    bytes::vector result;
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&metadata.messageCounter), reinterpret_cast<const uint8_t*>(&metadata.messageCounter) + 4);

    uint32_t ivLen = static_cast<uint32_t>(metadata.iv.size());
    result.insert(result.end(), reinterpret_cast<uint8_t*>(&ivLen), reinterpret_cast<uint8_t*>(&ivLen) + 4);
    result.insert(result.end(), metadata.iv.begin(), metadata.iv.end());

    uint32_t keyLen = static_cast<uint32_t>(metadata.senderPublicKey.size());
    result.insert(result.end(), reinterpret_cast<uint8_t*>(&keyLen), reinterpret_cast<uint8_t*>(&keyLen) + 4);
    result.insert(result.end(), metadata.senderPublicKey.begin(), metadata.senderPublicKey.end());

    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&metadata.timestamp), reinterpret_cast<const uint8_t*>(&metadata.timestamp) + 4);
    return result;
}

bool deserializeMetadata(const uint8_t *data, size_t size, SignalProtocol::MessageMetadata &metadata, size_t &pos) {
    if (pos + 4 > size) return false;
    std::memcpy(&metadata.messageCounter, data + pos, 4);
    pos += 4;

    if (pos + 4 > size) return false;
    uint32_t ivLen;
    std::memcpy(&ivLen, data + pos, 4);
    pos += 4;
    if (pos + ivLen > size) return false;
    metadata.iv.assign(data + pos, data + pos + ivLen);
    pos += ivLen;

    if (pos + 4 > size) return false;
    uint32_t keyLen;
    std::memcpy(&keyLen, data + pos, 4);
    pos += 4;
    if (pos + keyLen > size) return false;
    metadata.senderPublicKey.assign(data + pos, data + pos + keyLen);
    pos += keyLen;

    if (pos + 4 > size) return false;
    std::memcpy(&metadata.timestamp, data + pos, 4);
    pos += 4;
    return true;
}

std::string buildSignalStateJson(int64_t userId) {
    if (!gSignalProtocol) return "{\"initialized\": false}";

    const auto peer = peerForUserId(userId);
    std::ostringstream out;
    out << "{\"userId\": " << userId
        << ", \"initialized\": " << (gSignalProtocol->isEnabled() ? "true" : "false")
        << ", \"protocol\": \"SpyGram Signal Protocol (Double Ratchet)\""
        << ", \"hasSession\": " << (gSignalProtocol->hasSession(peer) ? "true" : "false")
        << "}";
    return out.str();
}

// Serialization helpers for MLS
bytes::vector serializeKeyPackage(const MLSKeyPackage &kp) {
    bytes::vector result;
    auto push_vec = [&](const bytes::vector &v) {
        uint32_t len = static_cast<uint32_t>(v.size());
        result.insert(result.end(), reinterpret_cast<uint8_t*>(&len), reinterpret_cast<uint8_t*>(&len) + 4);
        result.insert(result.end(), v.begin(), v.end());
    };

    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&kp.version), reinterpret_cast<const uint8_t*>(&kp.version) + 2);
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&kp.ciphersuite), reinterpret_cast<const uint8_t*>(&kp.ciphersuite) + 2);

    push_vec(kp.initKey);
    push_vec(kp.credentialPublicKey);
    push_vec(kp.credential);
    push_vec(kp.signature);

    int64_t creation = kp.creationTime.toMSecsSinceEpoch();
    int64_t expiration = kp.expirationTime.toMSecsSinceEpoch();
    result.insert(result.end(), reinterpret_cast<uint8_t*>(&creation), reinterpret_cast<uint8_t*>(&creation) + 8);
    result.insert(result.end(), reinterpret_cast<uint8_t*>(&expiration), reinterpret_cast<uint8_t*>(&expiration) + 8);

    return result;
}

MLSKeyPackage deserializeKeyPackage(const uint8_t *data, size_t size, size_t &pos) {
    MLSKeyPackage kp;
    auto read_vec = [&](bytes::vector &v) {
        if (pos + 4 > size) return;
        uint32_t len;
        std::memcpy(&len, data + pos, 4);
        pos += 4;
        if (pos + len > size) return;
        v.assign(data + pos, data + pos + len);
        pos += len;
    };

    if (pos + 2 > size) return kp;
    std::memcpy(&kp.version, data + pos, 2);
    pos += 2;

    if (pos + 2 > size) return kp;
    std::memcpy(&kp.ciphersuite, data + pos, 2);
    pos += 2;

    read_vec(kp.initKey);
    read_vec(kp.credentialPublicKey);
    read_vec(kp.credential);
    read_vec(kp.signature);

    if (pos + 8 > size) return kp;
    int64_t creation;
    std::memcpy(&creation, data + pos, 8);
    pos += 8;
    kp.creationTime = QDateTime::fromMSecsSinceEpoch(creation);

    if (pos + 8 > size) return kp;
    int64_t expiration;
    std::memcpy(&expiration, data + pos, 8);
    pos += 8;
    kp.expirationTime = QDateTime::fromMSecsSinceEpoch(expiration);

    return kp;
}

bytes::vector serializeWelcome(const MLSWelcome &welcome) {
    bytes::vector result;
    auto push_vec = [&](const bytes::vector &v) {
        uint32_t len = static_cast<uint32_t>(v.size());
        result.insert(result.end(), reinterpret_cast<uint8_t*>(&len), reinterpret_cast<uint8_t*>(&len) + 4);
        result.insert(result.end(), v.begin(), v.end());
    };

    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&welcome.version), reinterpret_cast<const uint8_t*>(&welcome.version) + 2);
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&welcome.ciphersuite), reinterpret_cast<const uint8_t*>(&welcome.ciphersuite) + 2);

    push_vec(welcome.encryptedGroupSecrets);
    push_vec(welcome.encryptedGroupInfo);

    int64_t timestamp = welcome.timestamp.toMSecsSinceEpoch();
    result.insert(result.end(), reinterpret_cast<uint8_t*>(&timestamp), reinterpret_cast<uint8_t*>(&timestamp) + 8);

    return result;
}

MLSWelcome deserializeWelcome(const uint8_t *data, size_t size) {
    MLSWelcome welcome;
    size_t pos = 0;
    auto read_vec = [&](bytes::vector &v) {
        if (pos + 4 > size) return;
        uint32_t len;
        std::memcpy(&len, data + pos, 4);
        pos += 4;
        if (pos + len > size) return;
        v.assign(data + pos, data + pos + len);
        pos += len;
    };

    if (pos + 2 > size) return welcome;
    std::memcpy(&welcome.version, data + pos, 2);
    pos += 2;

    if (pos + 2 > size) return welcome;
    std::memcpy(&welcome.ciphersuite, data + pos, 2);
    pos += 2;

    read_vec(welcome.encryptedGroupSecrets);
    read_vec(welcome.encryptedGroupInfo);

    if (pos + 8 > size) return welcome;
    int64_t timestamp;
    std::memcpy(&timestamp, data + pos, 8);
    pos += 8;
    welcome.timestamp = QDateTime::fromMSecsSinceEpoch(timestamp);

    return welcome;
}

bytes::vector serializeProposal(const MLSProposal &proposal) {
    bytes::vector result;
    result.push_back(static_cast<uint8>(proposal.type));
    
    uint64 proposer = proposal.proposer.valueOf();
    result.insert(result.end(), reinterpret_cast<uint8_t*>(&proposer), reinterpret_cast<uint8_t*>(&proposer) + 8);
    const uint8 targetPresent = proposal.targetUser.has_value() ? 1 : 0;
    result.push_back(targetPresent);
    if (targetPresent) {
        uint64 target = proposal.targetUser->valueOf();
        result.insert(result.end(), reinterpret_cast<uint8_t*>(&target), reinterpret_cast<uint8_t*>(&target) + 8);
    }

    auto push_vec = [&](const bytes::vector &v) {
        uint32_t len = static_cast<uint32_t>(v.size());
        result.insert(result.end(), reinterpret_cast<uint8_t*>(&len), reinterpret_cast<uint8_t*>(&len) + 4);
        result.insert(result.end(), v.begin(), v.end());
    };

    if (proposal.type == MLSProposalType::Add && proposal.addKeyPackage.has_value()) {
        auto pkgBytes = serializeKeyPackage(proposal.addKeyPackage.value());
        push_vec(pkgBytes);
    } else if (proposal.type == MLSProposalType::Remove && proposal.removeLeaf.has_value()) {
        uint32_t leaf = proposal.removeLeaf.value();
        result.insert(result.end(), reinterpret_cast<uint8_t*>(&leaf), reinterpret_cast<uint8_t*>(&leaf) + 4);
    } else if (proposal.type == MLSProposalType::Update) {
        push_vec(proposal.updateKey);
    }

    int64_t timestamp = proposal.timestamp.toMSecsSinceEpoch();
    result.insert(result.end(), reinterpret_cast<uint8_t*>(&timestamp), reinterpret_cast<uint8_t*>(&timestamp) + 8);

    return result;
}

bytes::vector serializeCommit(const MLSCommit &commit) {
    bytes::vector result;
    uint32_t proposalCount = static_cast<uint32_t>(commit.proposals.size());
    result.insert(result.end(), reinterpret_cast<uint8_t*>(&proposalCount), reinterpret_cast<uint8_t*>(&proposalCount) + 4);
    for (const auto &p : commit.proposals) {
        auto pBytes = serializeProposal(p);
        uint32_t pLen = static_cast<uint32_t>(pBytes.size());
        result.insert(result.end(), reinterpret_cast<uint8_t*>(&pLen), reinterpret_cast<uint8_t*>(&pLen) + 4);
        result.insert(result.end(), pBytes.begin(), pBytes.end());
    }

    auto push_vec = [&](const bytes::vector &v) {
        uint32_t len = static_cast<uint32_t>(v.size());
        result.insert(result.end(), reinterpret_cast<uint8_t*>(&len), reinterpret_cast<uint8_t*>(&len) + 4);
        result.insert(result.end(), v.begin(), v.end());
    };

    push_vec(commit.path);
    
    uint64 sender = commit.sender.valueOf();
    result.insert(result.end(), reinterpret_cast<uint8_t*>(&sender), reinterpret_cast<uint8_t*>(&sender) + 8);

    int64_t timestamp = commit.timestamp.toMSecsSinceEpoch();
    result.insert(result.end(), reinterpret_cast<uint8_t*>(&timestamp), reinterpret_cast<uint8_t*>(&timestamp) + 8);

    return result;
}

jbyteArray groupIdToJByteArray(JNIEnv *env, const MLSGroupId &groupId) {
    jbyteArray result = env->NewByteArray(static_cast<jsize>(groupId.size()));
    env->SetByteArrayRegion(result, 0, static_cast<jsize>(groupId.size()), reinterpret_cast<const jbyte*>(groupId.data()));
    return result;
}

MLSGroupId jbyteArrayToGroupId(JNIEnv *env, jbyteArray array) {
    if (!array) return {};
    const auto len = env->GetArrayLength(array);
    auto *bytes = env->GetByteArrayElements(array, nullptr);
    if (!bytes) return {};
    MLSGroupId result(reinterpret_cast<const uint8_t*>(bytes), reinterpret_cast<const uint8_t*>(bytes) + len);
    env->ReleaseByteArrayElements(array, bytes, JNI_ABORT);
    return result;
}

bool runDoubleRatchetSelfTest() {
    LOGD("Running Double Ratchet self-test...");
    if (!ensureSignalProtocol()) return false;
    return gSignalProtocol->isEnabled();
}

bool runMlsSelfTest() {
    if (!ensureMlsProtocol()) return false;

    constexpr auto kMessage = "cryptogram-mls-selftest";
    QVector<UserId> members;
    members.push_back(UserId(static_cast<uint64>(101)));
    members.push_back(UserId(static_cast<uint64>(202)));

    std::lock_guard<std::mutex> lock(gMlsMutex);
    auto *protocol = GetMLSProtocol();
    if (!protocol) return false;

    const auto groupId = protocol->createGroup(
        members,
        MLSCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    if (groupId.empty() || !protocol->hasGroup(groupId)) return false;

    bytes::vector plaintext;
    plaintext.insert(plaintext.end(), kMessage, kMessage + std::strlen(kMessage));

    const auto ciphertext = protocol->encryptMessage(groupId, plaintext);
    if (ciphertext.empty()) return false;

    const auto decrypted = protocol->decryptMessage(groupId, ciphertext);
    if (!decrypted.has_value() || decrypted.value() != plaintext) return false;

    return true;
}

} // namespace

extern "C" {

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeInitializeSession(
    JNIEnv *, jobject, jlong userId) {
    LOGD("Initializing Signal session for user %lld", (long long)userId);
    try {
        std::lock_guard<std::mutex> lock(gSignalMutex);
        if (!ensureSignalProtocol()) return JNI_FALSE;
        EnhancedPrivacy::RegisterCryptogramUser(UserId(static_cast<uint64>(userId)));
        return JNI_TRUE;
    } catch (const std::exception &e) {
        LOGE("Failed to initialize session: %s", e.what());
        return JNI_FALSE;
    }
}

JNIEXPORT jbyteArray JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeGenerateKeyBundle(
    JNIEnv *env, jobject) {
    try {
        std::lock_guard<std::mutex> lock(gSignalMutex);
        if (!ensureSignalProtocol()) return nullptr;

        auto bundle = gSignalProtocol->generateLocalKeyBundle();
        auto serialized = serializeKeyBundle(bundle);

        jbyteArray result = env->NewByteArray(static_cast<jsize>(serialized.size()));
        env->SetByteArrayRegion(result, 0, static_cast<jsize>(serialized.size()), reinterpret_cast<const jbyte*>(serialized.data()));
        return result;
    } catch (const std::exception &e) {
        LOGE("Failed to generate key bundle: %s", e.what());
        return nullptr;
    }
}

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeInitializeWithRemoteBundle(
    JNIEnv *env, jobject, jlong userId, jbyteArray bundleData) {
    if (!bundleData) return JNI_FALSE;
    const auto len = env->GetArrayLength(bundleData);
    auto *bytes = env->GetByteArrayElements(bundleData, nullptr);
    if (!bytes) return JNI_FALSE;

    try {
        auto bundle = deserializeKeyBundle(reinterpret_cast<const uint8_t*>(bytes), static_cast<size_t>(len));
        env->ReleaseByteArrayElements(bundleData, bytes, JNI_ABORT);

        std::lock_guard<std::mutex> lock(gSignalMutex);
        if (!ensureSignalProtocol()) return JNI_FALSE;

        const auto peer = peerForUserId(static_cast<int64_t>(userId));
        gSignalProtocol->createSession(peer, bundle);
        EnhancedPrivacy::RegisterCryptogramUser(UserId(static_cast<uint64>(userId)));
        return JNI_TRUE;
    } catch (const std::exception &e) {
        env->ReleaseByteArrayElements(bundleData, bytes, JNI_ABORT);
        LOGE("Failed to initialize with remote bundle: %s", e.what());
        return JNI_FALSE;
    }
}

JNIEXPORT jbyteArray JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeEncrypt(
    JNIEnv *env, jobject, jlong userId, jstring plaintext) {
    if (!plaintext) return nullptr;
    const char *messageText = env->GetStringUTFChars(plaintext, nullptr);
    if (!messageText) return nullptr;

    try {
        std::lock_guard<std::mutex> lock(gSignalMutex);
        if (!ensureSignalProtocol()) {
            env->ReleaseStringUTFChars(plaintext, messageText);
            return nullptr;
        }

        bytes::const_span plaintextBytes;
        plaintextBytes.insert(plaintextBytes.end(), messageText, messageText + std::strlen(messageText));

        const auto peer = peerForUserId(static_cast<int64_t>(userId));
        SignalProtocol::MessageMetadata metadata;
        auto ciphertext = gSignalProtocol->encryptMessage(plaintextBytes, peer, metadata);
        env->ReleaseStringUTFChars(plaintext, messageText);

        if (ciphertext.empty()) return nullptr;

        // Pack into envelope: [VERSION(1)][META_LEN(4)][META][PAYLOAD_LEN(4)][PAYLOAD]
        auto metaBytes = serializeMetadata(metadata);
        uint32_t metaLen = static_cast<uint32_t>(metaBytes.size());
        uint32_t payloadLen = static_cast<uint32_t>(ciphertext.size());

        bytes::vector envelope;
        envelope.push_back(1); // Version
        envelope.insert(envelope.end(), reinterpret_cast<uint8_t*>(&metaLen), reinterpret_cast<uint8_t*>(&metaLen) + 4);
        envelope.insert(envelope.end(), metaBytes.begin(), metaBytes.end());
        envelope.insert(envelope.end(), reinterpret_cast<uint8_t*>(&payloadLen), reinterpret_cast<uint8_t*>(&payloadLen) + 4);
        envelope.insert(envelope.end(), ciphertext.begin(), ciphertext.end());

        jbyteArray result = env->NewByteArray(static_cast<jsize>(envelope.size()));
        env->SetByteArrayRegion(result, 0, static_cast<jsize>(envelope.size()), reinterpret_cast<const jbyte*>(envelope.data()));
        return result;
    } catch (const std::exception &e) {
        env->ReleaseStringUTFChars(plaintext, messageText);
        LOGE("Encryption failed: %s", e.what());
        return nullptr;
    }
}

JNIEXPORT jstring JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeDecrypt(
    JNIEnv *env, jobject, jlong userId, jbyteArray ciphertext) {
    if (!ciphertext) return nullptr;
    const auto len = env->GetArrayLength(ciphertext);
    auto *bytes = env->GetByteArrayElements(ciphertext, nullptr);
    if (!bytes) return nullptr;

    try {
        std::lock_guard<std::mutex> lock(gSignalMutex);
        if (!ensureSignalProtocol()) {
            env->ReleaseByteArrayElements(ciphertext, bytes, JNI_ABORT);
            return nullptr;
        }

        const uint8_t *data = reinterpret_cast<const uint8_t*>(bytes);
        if (len < 1 || data[0] != 1) {
            env->ReleaseByteArrayElements(ciphertext, bytes, JNI_ABORT);
            return nullptr;
        }

        size_t pos = 1;
        uint32_t metaLen;
        std::memcpy(&metaLen, data + pos, 4);
        pos += 4;

        SignalProtocol::MessageMetadata metadata;
        if (!deserializeMetadata(data, static_cast<size_t>(len), metadata, pos)) {
            env->ReleaseByteArrayElements(ciphertext, bytes, JNI_ABORT);
            return nullptr;
        }

        uint32_t payloadLen;
        std::memcpy(&payloadLen, data + pos, 4);
        pos += 4;
        if (pos + payloadLen > static_cast<size_t>(len)) {
            env->ReleaseByteArrayElements(ciphertext, bytes, JNI_ABORT);
            return nullptr;
        }

        bytes::const_span ciphertextBytes;
        ciphertextBytes.insert(ciphertextBytes.end(), data + pos, data + pos + payloadLen);

        const auto peer = peerForUserId(static_cast<int64_t>(userId));
        auto plaintext = gSignalProtocol->decryptMessage(ciphertextBytes, peer, metadata);
        env->ReleaseByteArrayElements(ciphertext, bytes, JNI_ABORT);

        if (plaintext.empty()) return nullptr;
        std::string plaintextStr(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
        return env->NewStringUTF(plaintextStr.c_str());
    } catch (const std::exception &e) {
        env->ReleaseByteArrayElements(ciphertext, bytes, JNI_ABORT);
        LOGE("Decryption failed: %s", e.what());
        return nullptr;
    }
}

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeRotateSession(
    JNIEnv *, jobject, jlong userId) {
    try {
        std::lock_guard<std::mutex> lock(gSignalMutex);
        if (!ensureSignalProtocol()) return JNI_FALSE;
        const auto peer = peerForUserId(static_cast<int64_t>(userId));
        if (!gSignalProtocol->hasSession(peer)) return JNI_FALSE;
        gSignalProtocol->rotateSession(peer, true);
        return JNI_TRUE;
    } catch (const std::exception &e) {
        LOGE("Failed to rotate session: %s", e.what());
        return JNI_FALSE;
    }
}

JNIEXPORT jstring JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeGetFingerprint(
    JNIEnv *env, jobject, jlong userId) {
    try {
        std::lock_guard<std::mutex> lock(gSignalMutex);
        if (!ensureSignalProtocol()) return nullptr;
        const auto peer = peerForUserId(static_cast<int64_t>(userId));
        if (!gSignalProtocol->hasSession(peer)) {
            return env->NewStringUTF("UNINITIALIZED");
        }
        const auto fingerprint = buildSessionFingerprint(peer);
        return env->NewStringUTF(fingerprint.c_str());
    } catch (const std::exception &e) {
        LOGE("Failed to get fingerprint: %s", e.what());
        return nullptr;
    }
}

JNIEXPORT jstring JNICALL
Java_org_telegram_messenger_cryptogram_DoubleRatchet_nativeGetState(
    JNIEnv *env, jobject, jlong userId) {
    try {
        std::lock_guard<std::mutex> lock(gSignalMutex);
        const auto stateJson = buildSignalStateJson(userId);
        return env->NewStringUTF(stateJson.c_str());
    } catch (const std::exception &e) {
        LOGE("Failed to get state: %s", e.what());
        return nullptr;
    }
}

// MLS JNI Implementations
JNIEXPORT jbyteArray JNICALL
Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeGenerateKeyPackage(
    JNIEnv *env, jobject) {
    if (!ensureMlsProtocol()) return nullptr;
    try {
        std::lock_guard<std::mutex> lock(gMlsMutex);
        auto kp = GetMLSProtocol()->generateKeyPackage(MLSCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
        auto serialized = serializeKeyPackage(kp);

        jbyteArray result = env->NewByteArray(static_cast<jsize>(serialized.size()));
        env->SetByteArrayRegion(result, 0, static_cast<jsize>(serialized.size()), reinterpret_cast<const jbyte*>(serialized.data()));
        return result;
    } catch (const std::exception &e) {
        LOGE("Failed to generate MLS key package: %s", e.what());
        return nullptr;
    }
}

JNIEXPORT jlong JNICALL
Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeProcessWelcome(
    JNIEnv *env, jobject, jbyteArray welcomeData) {
    if (!ensureMlsProtocol() || !welcomeData) return 0;
    try {
        const auto len = env->GetArrayLength(welcomeData);
        auto *bytes = env->GetByteArrayElements(welcomeData, nullptr);
        if (!bytes) return 0;

        auto welcome = deserializeWelcome(reinterpret_cast<const uint8_t*>(bytes), static_cast<size_t>(len));
        env->ReleaseByteArrayElements(welcomeData, bytes, JNI_ABORT);

        std::lock_guard<std::mutex> lock(gMlsMutex);
        auto groupId = GetMLSProtocol()->processWelcome(welcome);

        // Generate a handle for the group
        int64_t handle;
        RAND_bytes(reinterpret_cast<uint8_t*>(&handle), sizeof(handle));
        gMlsGroups[handle] = groupId;
        
        return handle;
    } catch (const std::exception &e) {
        LOGE("Failed to process MLS welcome: %s", e.what());
        return 0;
    }
}

JNIEXPORT jbyteArray JNICALL
Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeCommitGroupChanges(
    JNIEnv *env, jobject, jlong groupIdHandle) {
    if (!ensureMlsProtocol()) return nullptr;
    try {
        std::lock_guard<std::mutex> lock(gMlsMutex);
        const auto it = gMlsGroups.find(groupIdHandle);
        if (it == gMlsGroups.end()) return nullptr;

        auto commit = GetMLSProtocol()->commitGroupChanges(it->second);
        if (!commit.has_value()) return nullptr;

        auto serialized = serializeCommit(commit.value());
        jbyteArray result = env->NewByteArray(static_cast<jsize>(serialized.size()));
        env->SetByteArrayRegion(result, 0, static_cast<jsize>(serialized.size()), reinterpret_cast<const jbyte*>(serialized.data()));
        return result;
    } catch (const std::exception &e) {
        LOGE("Failed to commit MLS group changes: %s", e.what());
        return nullptr;
    }
}

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeCreateGroup(
    JNIEnv *env, jobject, jlong groupId, jlongArray memberIds) {
    if (!memberIds || !ensureMlsProtocol()) return JNI_FALSE;
    const auto memberCount = env->GetArrayLength(memberIds);
    auto *members = env->GetLongArrayElements(memberIds, nullptr);
    if (!members) return JNI_FALSE;

    try {
        QVector<UserId> initialMembers;
        for (jsize i = 0; i < memberCount; ++i) initialMembers.push_back(UserId(static_cast<uint64>(members[i])));
        std::lock_guard<std::mutex> lock(gMlsMutex);
        gMlsGroups[groupId] = GetMLSProtocol()->createGroup(initialMembers);
        env->ReleaseLongArrayElements(memberIds, members, JNI_ABORT);
        return JNI_TRUE;
    } catch (const std::exception &e) {
        env->ReleaseLongArrayElements(memberIds, members, JNI_ABORT);
        LOGE("Failed to create MLS group: %s", e.what());
        return JNI_FALSE;
    }
}

JNIEXPORT jbyteArray JNICALL
Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeEncryptGroupMessage(
    JNIEnv *env, jobject, jlong groupId, jstring plaintext) {
    if (!plaintext || !ensureMlsProtocol()) return nullptr;
    const char *messageText = env->GetStringUTFChars(plaintext, nullptr);
    if (!messageText) return nullptr;

    try {
        std::lock_guard<std::mutex> lock(gMlsMutex);
        const auto it = gMlsGroups.find(groupId);
        if (it == gMlsGroups.end() || !GetMLSProtocol()->hasGroup(it->second)) {
            env->ReleaseStringUTFChars(plaintext, messageText);
            return nullptr;
        }

        bytes::vector plaintextBytes(reinterpret_cast<const uint8_t*>(messageText), reinterpret_cast<const uint8_t*>(messageText) + std::strlen(messageText));
        auto ciphertext = GetMLSProtocol()->encryptMessage(it->second, plaintextBytes);
        env->ReleaseStringUTFChars(plaintext, messageText);
        if (ciphertext.empty()) return nullptr;

        jbyteArray result = env->NewByteArray(static_cast<jsize>(ciphertext.size()));
        env->SetByteArrayRegion(result, 0, static_cast<jsize>(ciphertext.size()), reinterpret_cast<const jbyte*>(ciphertext.data()));
        return result;
    } catch (const std::exception &e) {
        env->ReleaseStringUTFChars(plaintext, messageText);
        LOGE("Group encryption failed: %s", e.what());
        return nullptr;
    }
}

JNIEXPORT jstring JNICALL
Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeDecryptGroupMessage(
    JNIEnv *env, jobject, jlong groupId, jbyteArray ciphertext) {
    if (!ciphertext || !ensureMlsProtocol()) return nullptr;
    const auto len = env->GetArrayLength(ciphertext);
    auto *bytes = env->GetByteArrayElements(ciphertext, nullptr);
    if (!bytes) return nullptr;

    try {
        std::lock_guard<std::mutex> lock(gMlsMutex);
        const auto it = gMlsGroups.find(groupId);
        if (it == gMlsGroups.end() || !GetMLSProtocol()->hasGroup(it->second)) {
            env->ReleaseByteArrayElements(ciphertext, bytes, JNI_ABORT);
            return nullptr;
        }

        bytes::vector ciphertextVec(reinterpret_cast<const uint8_t*>(bytes), reinterpret_cast<const uint8_t*>(bytes) + len);
        auto plaintext = GetMLSProtocol()->decryptMessage(it->second, ciphertextVec);
        env->ReleaseByteArrayElements(ciphertext, bytes, JNI_ABORT);
        if (!plaintext.has_value()) return nullptr;

        std::string plaintextString(reinterpret_cast<const char*>(plaintext->data()), plaintext->size());
        return env->NewStringUTF(plaintextString.c_str());
    } catch (const std::exception &e) {
        env->ReleaseByteArrayElements(ciphertext, bytes, JNI_ABORT);
        LOGE("Group decryption failed: %s", e.what());
        return nullptr;
    }
}

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeAddMember(
    JNIEnv *, jobject, jlong groupId, jlong userId) {
    if (!ensureMlsProtocol()) return JNI_FALSE;
    try {
        std::lock_guard<std::mutex> lock(gMlsMutex);
        const auto it = gMlsGroups.find(groupId);
        if (it == gMlsGroups.end() || !GetMLSProtocol()->hasGroup(it->second)) return JNI_FALSE;
        return GetMLSProtocol()->addMember(it->second, UserId(static_cast<uint64>(userId))) ? JNI_TRUE : JNI_FALSE;
    } catch (...) { return JNI_FALSE; }
}

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_MLSProtocol_nativeRemoveMember(
    JNIEnv *, jobject, jlong groupId, jlong userId) {
    if (!ensureMlsProtocol()) return JNI_FALSE;
    try {
        std::lock_guard<std::mutex> lock(gMlsMutex);
        const auto it = gMlsGroups.find(groupId);
        if (it == gMlsGroups.end() || !GetMLSProtocol()->hasGroup(it->second)) return JNI_FALSE;
        return GetMLSProtocol()->removeMember(it->second, UserId(static_cast<uint64>(userId))) ? JNI_TRUE : JNI_FALSE;
    } catch (...) { return JNI_FALSE; }
}

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_EnhancedPrivacy_nativeIsCryptogramUser(
    JNIEnv *, jobject, jlong userId) {
    return EnhancedPrivacy::IsCryptogramUser(UserId(static_cast<uint64>(userId))) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_org_telegram_messenger_cryptogram_CryptogramNative_nativeGetVersion(
    JNIEnv *env, jobject) {
    return env->NewStringUTF("CRYPTOGRAM Android 1.1.0-SignalPort");
}

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_CryptogramNative_nativeCheckDoubleRatchet(
    JNIEnv *, jobject) {
    return runDoubleRatchetSelfTest() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_org_telegram_messenger_cryptogram_CryptogramNative_nativeCheckMLS(
    JNIEnv *, jobject) {
    return runMlsSelfTest() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_org_telegram_messenger_cryptogram_CryptogramNative_nativeInitializeStorage(
    JNIEnv *env, jobject, jstring path) {
    if (!path) return;
    const char *pathStr = env->GetStringUTFChars(path, nullptr);
    if (!pathStr) return;
    base::SetGlobalStoragePath(pathStr);
    LOGD("Initialized storage path to: %s", pathStr);
    env->ReleaseStringUTFChars(path, pathStr);
}

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM* vm, void* reserved) {
    gJavaVM = vm;
    JNIEnv* env = nullptr;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}

} // extern "C"
