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
#include <openssl/crypto.h>
#include <utility>
#include <memory>

namespace Data {

// Forward declarations
class Session;
class User;
class History;

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
    };

    // Encryption key bundle
    struct KeyBundle {
        DeviceId deviceId;
        bytes::vector identityKey;
        bytes::vector signedPreKey;
        bytes::vector oneTimePreKey;
        bytes::vector signature;
    };

    SignalProtocol(not_null<Session*> session);
    ~SignalProtocol();


    // Enable/disable Signal Protocol encryption
    void setEnabled(bool enabled);
    [[nodiscard]] bool isEnabled() const;

    // Key management
    KeyBundle generateLocalKeyBundle();
    void registerRemoteKeyBundle(not_null<PeerData*> peer, const KeyBundle &bundle);
    KeyBundle getKeyBundleForPeer(not_null<PeerData*> peer);

    // Session management
    void createSession(not_null<PeerData*> peer, const KeyBundle &remoteBundle);
    [[nodiscard]] bool hasSession(not_null<PeerData*> peer) const;
    [[nodiscard]] SessionState getSession(not_null<PeerData*> peer) const;
    void updateSession(not_null<PeerData*> peer, const SessionState &state);
    void rotateSession(not_null<PeerData*> peer, bool forceRotate = false);

    // Message encryption/decryption
    bytes::vector encryptMessage(
        const bytes::const_span &plaintext,
        not_null<PeerData*> peer,
        MessageMetadata &outMetadata);
    
    bytes::vector decryptMessage(
        const bytes::const_span &ciphertext,
        not_null<PeerData*> peer,
        const MessageMetadata &metadata);

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
    
    // Current state
    bool _enabled = false;
    TimeId _keyRotationInterval = 60 * 60 * 24 * 7; // 1 week by default
    not_null<Session*> _session;

    
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
    
    // Scheduled operations
    struct ScheduledKeyRotation {
        PeerId peerId;
        TimeId time;
    };
    std::vector<ScheduledKeyRotation> _scheduledRotations;
    
    // For synchronization
    base::flat_set<PeerId> _initializingPeers;
};

} // namespace Data 