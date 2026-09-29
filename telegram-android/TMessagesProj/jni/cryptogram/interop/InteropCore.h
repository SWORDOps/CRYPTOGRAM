/*
 * CRYPTOGRAM Android — JNI-free protocol core.
 *
 * Byte-for-byte port of the desktop Signal-style double ratchet:
 *   - Telegram/SourceFiles/data/data_signal_protocol.cpp  (HKDF labels,
 *     X3DH, KDF_RK, chain ratchet, message keys, envelope layout)
 *   - Telegram/SourceFiles/data/data_signal_transport.cpp (key bundle
 *     transport format)
 *
 * This header/translation unit must not include jni.h or android/log.h so
 * the protocol core can be compiled and tested on any host against plain
 * OpenSSL as well as against the in-tree BoringSSL used by the Android
 * build.
 *
 * Only the portable EVP subset is used (no BoringSSL-specific low-level
 * curve25519.h entry points) so both backends compile unchanged.
 */

#ifndef CRYPTOGRAM_ANDROID_INTEROP_INTEROP_CORE_H
#define CRYPTOGRAM_ANDROID_INTEROP_INTEROP_CORE_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace interop {

using ByteVector = std::vector<uint8_t>;

// Sizes (desktop: kDHKeySize / kAesKeySize / kGcmIvSize / kGcmTagSize).
static constexpr size_t kKeySize = 32; // X25519 private/public key size
static constexpr size_t kEd25519SeedSize = 32; // Ed25519 raw private = seed
static constexpr size_t kEd25519SignatureSize = 64;
static constexpr size_t kAesKeySize = 32; // AES-256 key size
static constexpr size_t kGcmIvSize = 12; // AES-GCM IV size
static constexpr size_t kGcmTagSize = 16; // AES-GCM auth tag size
static constexpr size_t kMaxSkippedKeys = 1000; // desktop kMaxSkippedKeys
static constexpr uint32_t kMaxSkipAhead = 2000; // desktop skip-ahead limit
static constexpr size_t kCacChallengeNonceSize = 32;

// Key bundle transport format (desktop data_signal_transport.cpp).
static constexpr uint8_t kBundleVersion = 0x01;
static constexpr uint8_t kBundleFlagOneTimePreKey = 0x01;
static constexpr uint8_t kBundleFlagQuantumKem = 0x02;
static constexpr uint8_t kBundleFlagX25519Identity = 0x04;

// HKDF info labels — MUST match the desktop constants exactly
// (data_signal_protocol.cpp lines 61-65).
static constexpr const char *kInfoRootKey = "WhisperRatchet";
static constexpr const char *kInfoChainKey = "WhisperMessageKeys";
static constexpr const char *kInfoMessageKey = "WhisperMessageKey";
static constexpr const char *kInfoKdfRk = "CryptogramKDF_RK";
static constexpr const char *kInfoX3DH = "CryptogramX3DH";

struct KeyPair {
    ByteVector privateKey;
    ByteVector publicKey;
};

// Peer key bundle (desktop SignalProtocol::KeyBundle, transport-relevant
// fields only).
struct KeyBundle {
    uint64_t registrationId = 0;
    ByteVector identityKey; // Ed25519 public (32) — signs signedPreKey
    ByteVector signedPreKey; // X25519 public (32)
    ByteVector signature; // Ed25519 signature (64) over signedPreKey
    ByteVector oneTimePreKey; // X25519 public (32), optional
    ByteVector quantumKemPublicKey; // optional DER extension (0x02), unused on Android
    ByteVector x25519IdentityKey; // X25519 identity public (32), extension 0x04
};

// Desktop SignalProtocol::MessageMetadata (CAC fields included so the
// desktop envelope parses identically; Android never emits a CAC response).
struct MessageMetadata {
    uint32_t messageCounter = 0;
    ByteVector iv; // 12 bytes, random per message
    ByteVector senderPublicKey; // 32 bytes, current DH sending public
    uint32_t timestamp = 0;
    bool hasCacChallenge = false;
    ByteVector cacChallengeNonce;
    bool hasCacResponse = false;
    ByteVector cacSignature;
    ByteVector cacCertChainDer;
};

// Desktop SignalProtocol::SessionState.
struct SessionState {
    ByteVector rootKey;
    ByteVector sendingChainKey;
    ByteVector receivingChainKey;
    ByteVector dhSendingPrivateKey;
    ByteVector dhSendingPublicKey;
    ByteVector dhRemotePublicKey;
    ByteVector remoteIdentityKey; // peer Ed25519 identity public
    ByteVector remoteX25519IdentityKey; // peer X25519 identity public
    uint32_t sendingMessageCounter = 0;
    uint32_t receivingMessageCounter = 0;
    uint32_t previousSendingChainLength = 0;
    bool pendingRemoteDH = false;

    struct SkippedKey {
        uint32_t messageNumber = 0;
        ByteVector key;
    };
    std::vector<SkippedKey> skippedMessageKeys;
};

// Local long-term identity: Ed25519 identity (bundle identityKey, used for
// signing only) plus the dedicated X25519 identity required for the X3DH
// DH1/DH3 legs (an Ed25519 public is NOT the X25519 public of its seed).
struct LocalIdentity {
    ByteVector ed25519PrivateSeed; // 32 bytes
    ByteVector ed25519Public; // 32 bytes
    ByteVector x25519IdentityPrivate; // 32 bytes
    ByteVector x25519IdentityPublic; // 32 bytes
    ByteVector signedPreKeyPrivate; // 32 bytes
    ByteVector signedPreKeyPublic; // 32 bytes
    ByteVector oneTimePreKeyPrivate; // 32 bytes
    ByteVector oneTimePreKeyPublic; // 32 bytes
    uint64_t registrationId = 0;
    bool initialized = false;
};

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

// RAND_bytes wrapper; empty vector on failure.
ByteVector randomVector(size_t size);

// HMAC-SHA256 (desktop SignalProtocol::calculateHMAC).
ByteVector hmacSha256(const ByteVector &key, const ByteVector &data);

// HKDF-SHA256 in EXPAND_ONLY mode with the input used directly as PRK
// (desktop SignalProtocol::deriveKey). The digest is explicitly set —
// OpenSSL 3.x silently yields zero-filled output without it.
ByteVector hkdfExpandSha256(
    const ByteVector &prk,
    const std::string &info,
    size_t length);

// X25519 helpers (desktop generateDH / x25519PublicFromPrivate / x25519).
// x25519 returns a zero-filled 32-byte vector on failure, like the desktop.
KeyPair generateDhKeyPair();
ByteVector x25519PublicFromPrivate(const ByteVector &privateKey);
ByteVector x25519(const ByteVector &privateKey, const ByteVector &publicKey);

// Ed25519 helpers. The raw private key is the 32-byte seed on both OpenSSL
// and BoringSSL. KeyPair.privateKey is the seed, publicKey the 32-byte
// public key.
KeyPair generateEd25519KeyPair();
bool verifyEd25519Signature(
    const ByteVector &signature,
    const ByteVector &data,
    const ByteVector &publicKey);

// AES-256-GCM; encrypt returns ciphertext||tag, decrypt expects
// ciphertext||tag. Empty result means failure / authentication failure
// (desktop convention: empty bytes::vector on error).
ByteVector aesGcmEncrypt(
    const ByteVector &key,
    const ByteVector &iv,
    const ByteVector &plaintext,
    const ByteVector &aad);
ByteVector aesGcmDecrypt(
    const ByteVector &key,
    const ByteVector &iv,
    const ByteVector &ciphertextWithTag,
    const ByteVector &aad);

// ---------------------------------------------------------------------------
// Desktop KDF
// ---------------------------------------------------------------------------

struct KdfRkResult {
    ByteVector rootKey;
    ByteVector chainKey;
};

// Desktop kdfRk: expand-only HKDF over rootKey||dhOutput with info
// kInfoKdfRk; [0:32] = new root key, [32:64] = chain key.
KdfRkResult kdfRk(const ByteVector &rootKey, const ByteVector &dhOutput);

// HMAC-SHA256(chainKey, 0x01) (desktop ratchetChainKey).
ByteVector ratchetChainKey(const ByteVector &chainKey);

// Message key from a chain key (desktop: deriveKey(chain, kInfoMessageKey, 32)).
ByteVector messageKeyFromChain(const ByteVector &chainKey);

// ---------------------------------------------------------------------------
// Local identity and key bundle
// ---------------------------------------------------------------------------

// Generates the full local identity (Ed25519 identity, X25519 identity,
// signed pre-key, one-time pre-key, random registration id).
bool generateLocalIdentity(LocalIdentity &out);

// Builds the signed key bundle for the local identity (signature over
// signedPreKey made with the Ed25519 identity).
KeyBundle localKeyBundle(const LocalIdentity &local);

// Desktop transport format (data_signal_transport.cpp encodeKeyBundle):
// u8 version=0x01, u8 bitmap, u64 LE registrationId,
// identityKey(32) + signedPreKey(32) + signature(64) raw,
// [oneTimePreKey(32)], then the length-tagged extensions in order
// 0x02 (u16le len + DER) and 0x04 (u16le len=32 + raw). Little-endian.
ByteVector encodeKeyBundle(const KeyBundle &bundle);

// Parses the desktop transport format; tolerates unknown trailing
// extension bytes. Returns false on truncation or bad version.
bool decodeKeyBundle(const ByteVector &raw, KeyBundle &out);

// Ed25519 verify of signature over signedPreKey using identityKey
// (desktop verifyKeyBundleSignature).
bool verifyKeyBundleSignature(const KeyBundle &bundle);

// ---------------------------------------------------------------------------
// X3DH (fixed desktop spec)
// ---------------------------------------------------------------------------

// Alice side (desktop createSession): verifies the remote bundle signature,
// requires the 0x04 X25519 identity, computes
//   DH1 = X25519(XIK_A_priv, SPK_B), DH2 = X25519(EK_A_priv, SPK_B),
//   DH3 = X25519(XIK_A_priv, OPK_B), DH4 = X25519(EK_A_priv, OPK_B)
//   RK0 = expand(PRK=DH1||DH2[||DH3||DH4], kInfoX3DH, 32)
//   KDF_RK(RK0, DH4 or DH2) -> root + Alice SENDING chain
//   receivingChain = expand(PRK=root', kInfoChainKey, 32)
bool establishSessionAlice(
    SessionState &outState,
    const LocalIdentity &local,
    const KeyBundle &remoteBundle);

// Bob side (desktop createSessionFromInitialMessage):
//   DH1 = X25519(SPK_B_priv, XIK_A), DH2 = X25519(SPK_B_priv, EK_A),
//   DH3 = X25519(OPK_B_priv, XIK_A), DH4 = X25519(OPK_B_priv, EK_A)
//   KDF_RK -> root + Bob RECEIVING chain; sending chain = the symmetric
//   chain-init bytes (Alice's receiving chain).
bool establishSessionBob(
    SessionState &outState,
    const LocalIdentity &local,
    const ByteVector &aliceEphemeralPublic,
    const KeyBundle &aliceBundle);

// ---------------------------------------------------------------------------
// Envelope (desktop wrapEncryptedText / unwrapEncryptedText)
// ---------------------------------------------------------------------------

// QDataStream (Qt_5_15, all integers big-endian) layout:
//   quint32 counter | QByteArray iv | QByteArray senderPublicKey
//   | qint32 timestamp | bool hasCacChallenge [nonce] | bool hasCacResponse
//   [signature, certChainDer] | QByteArray ciphertext
// QByteArray = u32 BE length + raw bytes; bool = one byte.
// This is the RAW blob — zero-width encoding is applied by the Java layer.
ByteVector wrapEnvelope(const ByteVector &ciphertext, const MessageMetadata &metadata);

struct Envelope {
    ByteVector ciphertext;
    MessageMetadata metadata;
};

// Returns false on truncation (desktop unwrapEncryptedText failure).
bool unwrapEnvelope(const ByteVector &data, Envelope &out);

// ---------------------------------------------------------------------------
// Double ratchet (desktop encryptMessage / decryptMessage semantics)
// ---------------------------------------------------------------------------

// Performs the DH-ratchet step when session.pendingRemoteDH is set, derives
// the message key from the sending chain, advances the chain and fills
// outMetadata (counter, iv, senderPublicKey, timestamp). Returns
// ciphertext||tag; empty result = failure (desktop convention).
ByteVector encryptMessage(
    SessionState &session,
    const ByteVector &plaintext,
    MessageMetadata &outMetadata);

// DH-ratchets on remote sender-key change (two KDF_RK steps as in the
// desktop), handles counter checks and skipped-key storage, then AES-GCM
// decrypts. Mutates session only on success paths exactly like the desktop.
// Empty result = failure (desktop convention).
ByteVector decryptMessage(
    SessionState &session,
    const ByteVector &ciphertextWithTag,
    const MessageMetadata &metadata);

// Desktop rotateSession semantics: new DH pair, KDF_RK against the remote
// key for root+sending chain, receiving chain from the symmetric chain-init
// expansion; counters reset.
bool rotateSession(SessionState &session);

} // namespace interop

#endif // CRYPTOGRAM_ANDROID_INTEROP_INTEROP_CORE_H
