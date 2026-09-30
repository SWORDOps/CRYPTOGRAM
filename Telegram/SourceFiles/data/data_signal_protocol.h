/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#pragma once

#include "base/bytes.h"
#include "data/data_peer.h"
#include "history/history_item.h"
#include "storage/storage_account.h"
#include "data/data_tsm_interface.h"
#include <openssl/crypto.h>
#include <utility>
#include <memory>
#include <optional>
#include <QDataStream>

class History;

namespace Data {

// Forward declarations
class Session;
class QuantumGuard;

// Signal Protocol integration for Telegram Desktop
class SignalProtocol final {
public:
    // Identifies a specific device for Double Ratchet algorithm
    struct DeviceId {
        QString identifier;
        uint64 registrationId = 0;
    };

    // Double Ratchet session state
    struct SessionState {
        // Root key and chain keys
        bytes::vector rootKey;
        bytes::vector sendingChainKey;
        bytes::vector receivingChainKey;
        
        // Ratchet state
        bytes::vector dhSendingPublicKey;
        bytes::vector dhSendingPrivateKey;
        bytes::vector dhRemotePublicKey;
        
        // Message counters
        uint32 sendingMessageCounter = 0;
        uint32 receivingMessageCounter = 0;
        uint32 previousSendingChainLength = 0;

        // DH ratchet state
        bool pendingRemoteDH = false; // Set when a new remote DH key is seen in decrypt

        // Key history for out-of-order messages
        struct SkippedKey {
            uint32 messageNumber;
            bytes::vector key;
        };
        std::vector<SkippedKey> skippedMessageKeys;
        
        // Session identification
        DeviceId localDevice;
        DeviceId remoteDevice;
        TimeId createdAt = 0;
        TimeId lastUsedAt = 0;
    };

    // Encrypted message metadata
    struct MessageMetadata {
        uint32 messageCounter;
        bytes::vector iv;
        bytes::vector senderPublicKey;
        TimeId timestamp;

        // === Zero-Knowledge Mutual-Gating CAC Protocol ===
        //
        // Phase 1 (Challenge): Sender emits a random 32-byte nonce.
        //   - hasCacChallenge = true, cacChallengeNonce = <32 random bytes>
        //   - NO certificate, NO DN, NO signature is transmitted.
        //   - A snooping client learns NOTHING about the sender's identity.
        //
        // Phase 2 (Response): Recipient with a valid CAC signs the nonce
        //   using their hardware private key and attaches their full
        //   DER-encoded certificate chain (for chain validation).
        //   - hasCacResponse = true, cacSignature = <RSA/EC sig over nonce>
        //   - cacCertChainDer = <full X.509 cert chain, DER-encoded>
        //   - cacUserDN is NOT sent; it is extracted locally from the cert.
        //   - A recipient without a CAC card emits nothing. Silence = no card.
        //
        // Phase 3 (Reveal): Sender verifies the recipient's signed response
        //   against the NATO/Military trust store. Only on SUCCESS does the
        //   sender emit their own Phase 2 response back. Both sides have now
        //   proven possession of a valid hardware card before revealing
        //   either identity. An attacker with no card never reaches Phase 3.

        // Phase 1
        bool hasCacChallenge = false;
        bytes::vector cacChallengeNonce;   // 32 random bytes, no identity info

        // Phase 2
        bool hasCacResponse = false;
        bytes::vector cacSignature;        // hardware signature over the nonce
        bytes::vector cacCertChainDer;     // full DER cert chain for validation
        // cacUserDN is NOT transmitted; extracted locally from cacCertChainDer

        // === Ratcheted quantum session (envelope version 2) ===
        //
        // envelopeVersion routes unwrapEncryptedText: 0 = legacy field order
        // (envelopes already persisted in-flight), 2 = the quantum-session
        // capable layout (leading qint32 version, quantum init fields before
        // the ciphertext). Every NEW envelope writes version 2.
        int envelopeVersion = 0;

        // Set on the FIRST quantum-protected message of a fresh quantum
        // session: carries the ML-KEM encapsulation ciphertext (decapsulated
        // by the receiver with their static KEM private) and the sender's
        // static KEM public (SPKI DER, lets the receiver pick the right key
        // store entry). Both are empty (false) on every subsequent message —
        // the session chains take over.
        bool hasQuantumInit = false;
        bytes::vector quantumKemCiphertext;
        bytes::vector quantumKemEmitterPublic;
    };

    // Encryption key bundle
    struct KeyBundle {
        DeviceId deviceId;
        bytes::vector identityKey;
        bytes::vector signedPreKey;
        bytes::vector oneTimePreKey;
        bytes::vector signature;
        // Optional post-quantum addition (transport v1 extension, 0x02):
        // sender's static ML-KEM public key as SubjectPublicKeyInfo DER.
        // Empty for classic-only peers. Receivers encapsulate against this
        // key; the owner decapsulates with the private half.
        bytes::vector quantumKemPublicKey;
        // Optional X3DH fix extension (transport v1 extension, 0x04): the
        // sender's dedicated X25519 identity PUBLIC key used for the DH1/DH3
        // identity legs. The legacy identityKey field is an Ed25519 public
        // (signature identity) whose seed is NOT the X25519 scalar matching
        // this public — using it for DH produced non-agreeing secrets on
        // the two ends. Empty = legacy peer (session refused, see below).
        bytes::vector x25519IdentityKey;
    };

    SignalProtocol(not_null<Session*> session);
    ~SignalProtocol();


    // Enable/disable Signal Protocol encryption
    void setEnabled(bool enabled);
    [[nodiscard]] bool isEnabled() const;

    // TSM Integration
    void enableTSMIntegration(bool enabled);
    [[nodiscard]] bool isTSMEnabled() const;
    [[nodiscard]] TSMPlatform getTSMPlatform() const;
    [[nodiscard]] TSMCapabilities getTSMCapabilities() const;

    // Key management
    KeyBundle generateLocalKeyBundle();
    void registerRemoteKeyBundle(not_null<PeerData*> peer, const KeyBundle &bundle);
    KeyBundle getKeyBundleForPeer(not_null<PeerData*> peer);

    // Session management
    void createSession(not_null<PeerData*> peer, const KeyBundle &remoteBundle);
    void createSessionFromInitialMessage(
        not_null<PeerData*> peer,
        const bytes::const_span &aliceEphemeralKey,
        const KeyBundle &aliceBundle);
    [[nodiscard]] bool hasSession(not_null<PeerData*> peer) const;
    [[nodiscard]] SessionState getSession(not_null<PeerData*> peer) const;
    void updateSession(not_null<PeerData*> peer, const SessionState &state);
    void rotateSession(not_null<PeerData*> peer, bool forceRotate = false);

    // Cached key bundle for init params
    [[nodiscard]] const KeyBundle &cachedKeyBundle() const;
    void refreshCachedKeyBundle();

    // Message encryption/decryption
    bytes::vector encryptMessage(
        const bytes::const_span &plaintext,
        not_null<PeerData*> peer,
        MessageMetadata &outMetadata);
    
    bytes::vector decryptMessage(
        const bytes::const_span &ciphertext,
        not_null<PeerData*> peer,
        const MessageMetadata &metadata);

    // Wire-up helpers for the message pipeline
    [[nodiscard]] QString wrapEncryptedText(const bytes::vector &ciphertext, const MessageMetadata &metadata);
    [[nodiscard]] std::optional<std::pair<bytes::vector, MessageMetadata>> unwrapEncryptedText(const QString &text);
    
    [[nodiscard]] bool verifyCacMutualAuth(
        const bytes::vector &challengeNonce,
        const bytes::vector &signature,
        const bytes::vector &certChainDer,
        QString &outUserDN);  // DN extracted locally, never transmitted
    [[nodiscard]] TextWithEntities processIncomingMessage(not_null<PeerData*> peer, const TextWithEntities &text);
    [[nodiscard]] TextWithEntities processOutgoingMessage(not_null<PeerData*> peer, const TextWithEntities &text);
    [[nodiscard]] TextWithTags processOutgoingMessage(not_null<PeerData*> peer, const TextWithTags &text);

    // Key exchange via message entities (peer-to-peer)
    // Attaches key bundle to outgoing message text if no session exists.
    // Returns the modified text with ZW payload prepended.
    [[nodiscard]] TextWithEntities attachKeyBundleIfNeeded(
        not_null<PeerData*> peer,
        const TextWithEntities &text);
    // Returns the ZW payload length for the last attached key bundle.
    // Call after attachKeyBundleIfNeeded to know how many leading chars
    // are the key bundle payload (for constructing the MTP entity).
    [[nodiscard]] int lastKeyBundlePayloadLength() const;
    // Extracts key bundles from incoming message entities and initializes session.
    [[nodiscard]] TextWithEntities processIncomingKeyBundle(
        not_null<PeerData*> peer,
        const TextWithEntities &text,
        const QVector<MTPMessageEntity> &entities);



    // History storage management
    void saveEncryptedHistoryLocal(not_null<PeerData*> peer, const HistoryItem *item);
    HistoryItem* loadEncryptedHistoryLocal(not_null<PeerData*> peer, MsgId msgId);
    
    // Key backup & recovery
    bytes::vector backupKeys(const QString &password);
    bool restoreKeys(const bytes::const_span &backup, const QString &password);
    
    // Perfect Forward Secrecy key management
    void scheduleKeyRotation(not_null<PeerData*> peer, TimeId scheduleTime);
    void performScheduledKeyRotations();
    TimeId getKeyRotationInterval() const;
    void setKeyRotationInterval(TimeId interval);

private:
    // Cryptographic primitives
    bytes::vector deriveKey(const bytes::const_span &input, const QString &info, int length);
    bytes::vector calculateHMAC(const bytes::const_span &key, const bytes::const_span &data);
    
    // Double Ratchet operations
    bytes::vector ratchetRootKey(const SessionState &state);
    bytes::vector ratchetChainKey(const bytes::const_span &chainKey);

    // KDF_RK: derive new root key and chain key from DH output
    struct KdfRkResult { bytes::vector rootKey; bytes::vector chainKey; };
    KdfRkResult kdfRk(const bytes::const_span &rootKey, const bytes::const_span &dhOutput);

    // AES-256-GCM encrypt/decrypt (replaces CBC)
    bytes::vector aesGcmEncrypt(
        const bytes::const_span &plaintext,
        const bytes::const_span &key,
        const bytes::const_span &iv,
        const bytes::const_span &aad);
    bytes::vector aesGcmDecrypt(
        const bytes::const_span &ciphertext,
        const bytes::const_span &key,
        const bytes::const_span &iv,
        const bytes::const_span &aad);

    // Secure zeroization
    void secureWipe(bytes::vector &data);
    
    // Session serialization
    QByteArray serializeSession(const SessionState &state);
    SessionState deserializeSession(const QByteArray &data);
    
    // Local storage
    void saveSession(not_null<PeerData*> peer, const SessionState &state);
    SessionState loadSession(not_null<PeerData*> peer);
    void saveEncryptedMessage(not_null<PeerData*> peer, MsgId msgId, const QByteArray &data);
    QByteArray loadEncryptedMessage(not_null<PeerData*> peer, MsgId msgId);
    
    // Key generation
    bytes::vector generateDH();
    bytes::vector generateRandomBytes(int length);

    // Ed25519 signature operations
    bytes::vector signWithIdentityKey(const bytes::const_span &data);
    bool verifyKeyBundleSignature(const KeyBundle &bundle);
    bool verifyEd25519Signature(
        const bytes::const_span &signature,
        const bytes::const_span &data,
        const bytes::const_span &publicKey);
    std::pair<bytes::vector, bytes::vector> generateEd25519KeyPair();

    // Secure key storage
    QByteArray encryptWithPBKDF2(const bytes::const_span &data, const QString &password);
    bytes::vector decryptWithPBKDF2(const QByteArray &encryptedData, const QString &password);
    void saveIdentityKeys();

    // Post-quantum (QuantumGuard ML-KEM) layer. All key material is real:
    // our static KEM keypair persists next to the identity keys, peers
    // advertise their KEM public key inside the key-bundle entity, and the
    // per-message envelope is a genuine ML-KEM encapsulation + AES-256-GCM.
    [[nodiscard]] bool quantumProtectionActive() const;
    void ensureQuantumIdentity();
    [[nodiscard]] QString peerQuantumKeyPath(not_null<PeerData*> peer) const;
    [[nodiscard]] std::optional<bytes::vector> quantumWrapPayload(
        not_null<PeerData*> peer,
        const bytes::const_span &plaintext);
    [[nodiscard]] std::optional<bytes::vector> quantumUnwrapPayload(
        const bytes::const_span &envelope);

    // Ratcheted quantum sessions (envelope version 2). A per-peer session
    // established by ONE real ML-KEM encapsulation supersedes the per-message
    // PQE1 envelopes: chains advance one message key per classic message in
    // lockstep, so subsequent messages carry no new encapsulation.
    [[nodiscard]] bool peerKemKeyAdvertised(not_null<PeerData*> peer) const;
    [[nodiscard]] bool peerQuantumSessionActive(not_null<PeerData*> peer) const;
    // Initiator ("Alice") establishment: encapsulate against the peer's
    // static KEM public, derive the chain pair, and fill the metadata fields
    // that transport the kemCiphertext to the peer (v2 envelope).
    bool establishQuantumSessionInitiator(
        not_null<PeerData*> peer,
        MessageMetadata &outMetadata);
    // Resolver ("Bob") establishment: decapsulate the transported kemCiphertext
    // with our static KEM private and derive the SAME chains (labels swapped).
    bool acceptQuantumSessionInit(
        not_null<PeerData*> peer,
        const bytes::const_span &kemCiphertext);
    // Shared tail of encryptMessage and the quantum send path: DH-ratchet
    // when pending, derive + advance the classic sending chain, fill the
    // metadata (counter/iv/senderPub/timestamp) and build the AAD. Returns
    // the classic message key (empty on failure); `inoutSession` carries the
    // live session copy the caller commits via updateSession on success.
    bytes::vector beginClassicEncryption(
        not_null<PeerData*> peer,
        MessageMetadata &outMetadata,
        bytes::vector &outAad,
        SessionState &inoutSession);
    // Quantum-protected send path (established session): the plaintext is
    // encrypted under the quantum chain key with the SAME iv + AAD as the
    // classic layer, then the classic ratchet encrypts the quantum payload.
    bytes::vector encryptQuantumSessionMessage(
        const bytes::const_span &plaintext,
        not_null<PeerData*> peer,
        MessageMetadata &outMetadata);
    // Quantum unwrap AFTER classic decryption: derive the recv-chain message
    // key for metadata.messageCounter (skipped-key storage mirrors the classic
    // layer) and AES-256-GCM-decrypt with the same iv + AAD.
    [[nodiscard]] std::optional<bytes::vector> quantumUnwrapSessionPayload(
        not_null<PeerData*> peer,
        const bytes::const_span &payload,
        const MessageMetadata &metadata);
    
    // Current state
    bool _enabled = false;
    bool _tsmEnabled = false;
    std::unique_ptr<SignalTSMIntegration> _tsmIntegration;
    TimeId _keyRotationInterval = 60 * 60 * 24 * 7; // 1 week by default
    not_null<Session*> _session;

    // Pending ZK challenges we have issued, keyed by PeerId.
    // When we receive a Phase 2 response, we look up the nonce here to verify.
    // Cleared after successful verification or expiry.
    struct PendingChallenge {
        bytes::vector nonce;   // the 32-byte nonce we sent in Phase 1
        TimeId issuedAt;       // wall-clock time; expire after 5 minutes
    };
    base::flat_map<PeerId, PendingChallenge> _pendingCacChallenges;


    
    // Locally stored data
    struct PeerKeyData {
        KeyBundle remoteBundle;
        std::vector<SessionState> sessions;
    };
    base::flat_map<PeerId, PeerKeyData> _peerKeyData;
    
    // Own identity keys
    DeviceId _localDevice;
    bytes::vector _identityKeyPrivate;
    bytes::vector _identityKeyPublic;

    // Dedicated X25519 identity for the X3DH DH1/DH3 legs (fixed spec).
    // The Ed25519 identity above signs bundles; its seed is not the X25519
    // scalar matching its public, so DH via the Ed25519 pair never agreed
    // across the two session-establishment sides.
    bytes::vector _x25519IdentityPrivate;
    bytes::vector _x25519IdentityPublic;
    void ensureX25519Identity();

    // Post-quantum state (lazy-initialized; KEM private key lives inside
    // _quantumGuard's key store and persists via QuantumGuard::saveKeys).
    std::shared_ptr<QuantumGuard> _quantumGuard;
    QString _quantumKemKeyId;
    bytes::vector _quantumKemPublicKeyDer;
    
    // Scheduled operations
    struct ScheduledKeyRotation {
        PeerId peerId;
        TimeId time;
    };
    std::vector<ScheduledKeyRotation> _scheduledRotations;
    
    // Cached key bundle for init params
    KeyBundle _cachedBundle;
    bool _cachedBundleValid = false;
    int _lastKeyBundlePayloadLength = 0;

    // For synchronization
    base::flat_set<PeerId> _initializingPeers;

    // Truth Gap Mitigation (Secure Memory Enclave)
    struct PendingMessage {
        bytes::vector enclaveEncryptedPlaintext;
        TimeId queuedAt;
    };
    base::flat_map<PeerId, std::vector<PendingMessage>> _truthGapEnclave;
    bytes::vector _enclaveKey;

    void initializeEnclave();
public:
    void enqueueTruthGapMessage(not_null<PeerData*> peer, const bytes::const_span &plaintext);
    std::vector<bytes::vector> flushTruthGapEnclave(not_null<PeerData*> peer);
};

} // namespace Data 