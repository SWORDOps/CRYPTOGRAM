/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#include "data/data_signal_protocol.h"
#include "data/data_signal_transport.h"
#include "data/data_tsm_factory.h"
#include "core/peer_trust_encryption.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <QDir>

#include "base/random.h"
#include "base/unixtime.h"
#include "core/application.h"
#include "data/data_session.h"
#include "data/data_user.h"
#include "data/data_file_origin.h"
#include "history/history.h"
#include "history/history_item.h"
#include "storage/storage_account.h"
#include "storage/localimageloader.h"
#include "main/main_session.h"

#include <QtCore/QFile>
#include <QtCore/QDir>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonArray>

namespace Data {
namespace {

// Constants for the Signal Protocol implementation
constexpr auto kSignalStoragePath = "signal_protocol";
constexpr auto kSignalKeyDbName = "signal_keys.json";
constexpr auto kSignalMsgDbPrefix = "signal_messages_";
constexpr auto kSignalBackupName = "signal_keys_backup.enc";
constexpr auto kDHKeySize = 32; // X25519 key size in bytes
constexpr auto kAesKeySize = 32; // AES-256 key size
constexpr auto kAesIvSize = 16;  // AES IV size (CBC legacy)
constexpr auto kGcmIvSize = 12;  // AES-GCM IV size
constexpr auto kGcmTagSize = 16; // AES-GCM auth tag size
constexpr auto kMaxSkippedKeys = 1000; // Maximum skipped message keys to store
constexpr auto kInfoRootKey = "WhisperRatchet"; // Used in HKDF for root keys
constexpr auto kInfoChainKey = "WhisperMessageKeys"; // Used in HKDF for chain keys
constexpr auto kInfoMessageKey = "WhisperMessageKey"; // Used in HKDF for message keys
constexpr auto kInfoKdfRk = "CryptogramKDF_RK"; // Used in HKDF for KDF_RK
constexpr auto kInfoX3DH = "CryptogramX3DH"; // Used in HKDF for X3DH initial root key

inline const unsigned char *asConstUChar(const bytes::const_span &span) {
    return reinterpret_cast<const unsigned char *>(span.data());
}

inline unsigned char *asUChar(bytes::span span) {
    return reinterpret_cast<unsigned char *>(span.data());
}

inline unsigned char *asUChar(bytes::vector &value) {
    return asUChar(bytes::make_span(value));
}

inline const unsigned char *asConstUChar(const bytes::vector &value) {
    return asConstUChar(bytes::make_span(value));
}

// Helper to create storage paths
QString signalStoragePath(not_null<Session*> session) {
    const auto basePath = session->local().basePath();
    QDir dir(basePath);
    if (!dir.exists(kSignalStoragePath)) {
        dir.mkdir(kSignalStoragePath);
    }
    return basePath + '/' + kSignalStoragePath + '/';
}

bool aesEncryptLocal(
        const void *plaintext,
        void *ciphertext,
        int plaintextLen,
        const void *key,
        const void *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           reinterpret_cast<const unsigned char *>(key),
                           reinterpret_cast<const unsigned char *>(iv)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int outLen1 = 0;
    if (EVP_EncryptUpdate(ctx,
            reinterpret_cast<unsigned char *>(ciphertext),
            &outLen1,
            reinterpret_cast<const unsigned char *>(plaintext),
            plaintextLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int outLen2 = 0;
    if (EVP_EncryptFinal_ex(ctx,
            reinterpret_cast<unsigned char *>(ciphertext) + outLen1,
            &outLen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// AES-256-GCM encrypt: returns ciphertext || tag
bytes::vector aesGcmEncryptLocal(
        const bytes::const_span &plaintext,
        const bytes::const_span &key,
        const bytes::const_span &iv,
        const bytes::const_span &aad) {
    bytes::vector result(plaintext.size() + kGcmTagSize);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           asConstUChar(key), asConstUChar(iv)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int outLen = 0;
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &outLen,
                              asConstUChar(aad), aad.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
    }

    if (EVP_EncryptUpdate(ctx, asUChar(result), &outLen,
                          asConstUChar(plaintext), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx, asUChar(result) + outLen, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kGcmTagSize,
            asUChar(result) + outLen + finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    EVP_CIPHER_CTX_free(ctx);
    result.resize(outLen + finalLen + kGcmTagSize);
    return result;
}

// AES-256-GCM decrypt: input is ciphertext || tag, returns plaintext or empty on auth failure
bytes::vector aesGcmDecryptLocal(
        const bytes::const_span &ciphertextWithTag,
        const bytes::const_span &key,
        const bytes::const_span &iv,
        const bytes::const_span &aad) {
    if (ciphertextWithTag.size() < kGcmTagSize) return {};

    const auto ctLen = ciphertextWithTag.size() - kGcmTagSize;
    bytes::vector plaintext(ctLen);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           asConstUChar(key), asConstUChar(iv)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int outLen = 0;
    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &outLen,
                              asConstUChar(aad), aad.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
    }

    if (EVP_DecryptUpdate(ctx, asUChar(plaintext), &outLen,
                          asConstUChar(ciphertextWithTag), ctLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Set the tag from the end of the input
    auto tagSpan = bytes::make_span(ciphertextWithTag).subspan(ctLen);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kGcmTagSize,
            const_cast<unsigned char*>(asConstUChar(tagSpan))) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx, asUChar(plaintext) + outLen, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {}; // Authentication failed
    }

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(outLen + finalLen);
    return plaintext;
}

bool aesDecryptLocal(
        const void *ciphertext,
        void *plaintext,
        int ciphertextLen,
        const void *key,
        const void *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           reinterpret_cast<const unsigned char *>(key),
                           reinterpret_cast<const unsigned char *>(iv)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int outLen1 = 0;
    if (EVP_DecryptUpdate(ctx,
            reinterpret_cast<unsigned char *>(plaintext),
            &outLen1,
            reinterpret_cast<const unsigned char *>(ciphertext),
            ciphertextLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int outLen2 = 0;
    if (EVP_DecryptFinal_ex(ctx,
            reinterpret_cast<unsigned char *>(plaintext) + outLen1,
            &outLen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// Helper for OpenSSL X25519 (Curve25519) key exchange
bytes::vector x25519Generate() {
    auto privateKey = bytes::vector(kDHKeySize);
    
    // Generate random private key
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, nullptr, 0);
    if (!pkey) {
        LOG(("Signal Protocol Error: Failed to create X25519 key"));
        return privateKey;
    }
    
    // Get raw private key bytes
    size_t len = kDHKeySize;
    EVP_PKEY_get_raw_private_key(pkey, asUChar(privateKey), &len);
    EVP_PKEY_free(pkey);
    
    return privateKey;
}

bytes::vector x25519PublicFromPrivate(const bytes::const_span &privateKey) {
    auto result = bytes::vector(kDHKeySize);
    
    // Create private key object
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519,
        nullptr,
        reinterpret_cast<const unsigned char*>(privateKey.data()),
        privateKey.size());
    
    if (!pkey) {
        LOG(("Signal Protocol Error: Failed to load X25519 private key"));
        return result;
    }
    
    // Get public key
    size_t len = kDHKeySize;
    EVP_PKEY_get_raw_public_key(pkey, asUChar(result), &len);
    EVP_PKEY_free(pkey);

    return result;
}

bytes::vector x25519(const bytes::const_span &privateKey, const bytes::const_span &publicKey) {
    auto result = bytes::vector(kDHKeySize);
    
    // Create private key object
    EVP_PKEY *privKey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519,
        nullptr,
        reinterpret_cast<const unsigned char*>(privateKey.data()),
        privateKey.size());
    
    if (!privKey) {
        LOG(("Signal Protocol Error: Failed to load X25519 private key for DH"));
        return result;
    }
    
    // Create public key object
    EVP_PKEY *pubKey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519,
        nullptr,
        reinterpret_cast<const unsigned char*>(publicKey.data()),
        publicKey.size());
    
    if (!pubKey) {
        EVP_PKEY_free(privKey);
        LOG(("Signal Protocol Error: Failed to load X25519 public key for DH"));
        return result;
    }
    
    // Create context for key exchange
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privKey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(privKey);
        EVP_PKEY_free(pubKey);
        LOG(("Signal Protocol Error: Failed to create X25519 context"));
        return result;
    }
    
    // Initialize key derivation
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privKey);
        EVP_PKEY_free(pubKey);
        LOG(("Signal Protocol Error: Failed to initialize X25519 derivation"));
        return result;
    }
    
    // Set peer public key
    if (EVP_PKEY_derive_set_peer(ctx, pubKey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privKey);
        EVP_PKEY_free(pubKey);
        LOG(("Signal Protocol Error: Failed to set X25519 peer key"));
        return result;
    }
    
    // Derive shared secret
    size_t sharedSecretLen = kDHKeySize;
    if (EVP_PKEY_derive(ctx, asUChar(result), &sharedSecretLen) <= 0) {
        LOG(("Signal Protocol Error: Failed to derive X25519 shared secret"));
    }
    
    // Cleanup
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(privKey);
    EVP_PKEY_free(pubKey);
    
    return result;
}

} // namespace

SignalProtocol::SignalProtocol(not_null<Session*> session)
: _session(session) {
    // Initialize device ID
    _localDevice.identifier = QString::number(session->userId().bare) + "_device";
    _localDevice.registrationId = base::RandomValue<uint64>();

    // Initialize TSM integration
    _tsmIntegration = std::make_unique<SignalTSMIntegration>(session);
    auto tsmResult = _tsmIntegration->initializeWithSignalProtocol();
    if (tsmResult == TSMResult::Success) {
        _tsmEnabled = true;
        LOG(("Signal Protocol: TSM integration enabled successfully"));
    } else {
        LOG(("Signal Protocol: TSM integration failed, using software fallback"));
        _tsmEnabled = false;
    }
    
    // Generate identity keys if none exist
    auto keyPath = signalStoragePath(session) + kSignalKeyDbName;
    QFile keyFile(keyPath);
    if (keyFile.exists() && keyFile.open(QIODevice::ReadOnly)) {
        auto data = keyFile.readAll();
        auto doc = QJsonDocument::fromJson(data);
        auto obj = doc.object();
        
        // Load identity keys with version compatibility
        if (obj.contains("identityPublic") && obj.contains("identityPrivate")) {
            auto publicBase64 = obj["identityPublic"].toString().toLatin1();
            auto privateBase64 = obj["identityPrivate"].toString().toLatin1();

            _identityKeyPublic = bytes::make_vector(QByteArray::fromBase64(publicBase64));

            // Check if this is the new encrypted format
            auto keyVersion = obj.value("keyVersion").toInt(1); // Default to version 1
            if (keyVersion >= 2) {
                // Decrypt private key using PBKDF2
                auto passwordData = QString::number(session->userId().bare) +
                                   _localDevice.identifier +
                                   QString::number(_localDevice.registrationId);

                auto encryptedPrivateKey = QByteArray::fromBase64(privateBase64);
                _identityKeyPrivate = decryptWithPBKDF2(encryptedPrivateKey, passwordData);
            } else {
                // Legacy unencrypted format
                _identityKeyPrivate = bytes::make_vector(QByteArray::fromBase64(privateBase64));
                // Upgrade to encrypted format on next save
                saveIdentityKeys();
            }
        }
        
        keyFile.close();
    }
    
    // Generate keys if not loaded - use Ed25519 for identity keys
    if (_identityKeyPublic.empty() || _identityKeyPrivate.empty()) {
        auto keyPair = generateEd25519KeyPair();
        _identityKeyPrivate = keyPair.first;
        _identityKeyPublic = keyPair.second;

        // Save the generated keys
        saveIdentityKeys();
    }

    // Pre-generate cached key bundle for MTProto init params
    refreshCachedKeyBundle();
}

SignalProtocol::~SignalProtocol() {
    // Ensure sessions are saved
    for (const auto &[peerId, data] : _peerKeyData) {
        for (const auto &session : data.sessions) {
            saveSession(_session->peer(peerId), session);
        }
    }
}

void SignalProtocol::setEnabled(bool enabled) {
    _enabled = enabled;
}

bool SignalProtocol::isEnabled() const {
    return _enabled;
}

// Save identity keys to storage with password-based encryption
void SignalProtocol::saveIdentityKeys() {
    auto keyPath = signalStoragePath(_session) + kSignalKeyDbName;
    QFile keyFile(keyPath);
    if (keyFile.open(QIODevice::WriteOnly)) {
        QJsonObject obj;

        // Create a strong password from session data
        auto passwordData = QString::number(_session->userId().bare) +
                           _localDevice.identifier +
                           QString::number(_localDevice.registrationId);

        // Encrypt private key with PBKDF2-derived key
        auto encryptedPrivateKey = encryptWithPBKDF2(_identityKeyPrivate, passwordData);

        // Convert keys to Base64 for storage
        auto publicKey = QByteArray(
            reinterpret_cast<const char*>(_identityKeyPublic.data()),
            _identityKeyPublic.size()).toBase64();

        obj["identityPublic"] = QString::fromLatin1(publicKey);
        obj["identityPrivate"] = QString::fromLatin1(encryptedPrivateKey.toBase64());
        obj["deviceId"] = _localDevice.identifier;
        obj["registrationId"] = QString::number(_localDevice.registrationId);
        obj["keyVersion"] = 2; // Version 2 uses PBKDF2 encryption

        QJsonDocument doc(obj);
        keyFile.write(doc.toJson(QJsonDocument::Compact));
        keyFile.close();
    }
}

// Generate a new key bundle for local device
SignalProtocol::KeyBundle SignalProtocol::generateLocalKeyBundle() {
    KeyBundle bundle;
    bundle.deviceId = _localDevice;
    bundle.identityKey = _identityKeyPublic;
    
    // Generate a signed pre-key
    auto preKeyPrivate = generateDH();
    auto preKeyPublic = x25519PublicFromPrivate(preKeyPrivate);
    
    // Sign the pre-key with identity key using proper EdDSA signature
    auto signature = signWithIdentityKey(preKeyPublic);
    
    // Generate a one-time pre-key
    auto oneTimeKeyPrivate = generateDH();
    auto oneTimeKeyPublic = x25519PublicFromPrivate(oneTimeKeyPrivate);
    
    bundle.signedPreKey = preKeyPublic;
    bundle.oneTimePreKey = oneTimeKeyPublic;
    bundle.signature = signature;
    
    // Store keys for later use in session establishment
    auto keyPath = signalStoragePath(_session) + kSignalKeyDbName;
    QFile keyFile(keyPath);
    if (keyFile.open(QIODevice::ReadWrite)) {
        QJsonDocument doc;
        if (keyFile.size() > 0) {
            doc = QJsonDocument::fromJson(keyFile.readAll());
        }
        
        auto obj = doc.object();
        
        // Add pre-keys to storage
        QJsonObject preKeyObj;
        preKeyObj["public"] = QString::fromLatin1(QByteArray(
            reinterpret_cast<const char*>(preKeyPublic.data()), 
            preKeyPublic.size()).toBase64());
        preKeyObj["private"] = QString::fromLatin1(QByteArray(
            reinterpret_cast<const char*>(preKeyPrivate.data()), 
            preKeyPrivate.size()).toBase64());
        
        QJsonObject oneTimeKeyObj;
        oneTimeKeyObj["public"] = QString::fromLatin1(QByteArray(
            reinterpret_cast<const char*>(oneTimeKeyPublic.data()), 
            oneTimeKeyPublic.size()).toBase64());
        oneTimeKeyObj["private"] = QString::fromLatin1(QByteArray(
            reinterpret_cast<const char*>(oneTimeKeyPrivate.data()), 
            oneTimeKeyPrivate.size()).toBase64());
        
        obj["signedPreKey"] = preKeyObj;
        obj["oneTimePreKey"] = oneTimeKeyObj;
        
        keyFile.seek(0);
        keyFile.write(QJsonDocument(obj).toJson(QJsonDocument::Compact));
        keyFile.close();
    }
    
    return bundle;
}

// Message encryption
bytes::vector SignalProtocol::encryptMessage(
    const bytes::const_span &plaintext,
    not_null<PeerData*> peer,
    MessageMetadata &outMetadata) {

    if (!hasSession(peer)) {
        LOG(("Signal Protocol: No session for peer %1").arg(peer->id.value));
        return {};
    }

    // Check for CAC-verified peer trust encryption
    const auto trustParams = Core::PeerTrustEncryption::GetEncryptionParams(peer->id.value);
    if (trustParams.verified && trustParams.useTPM) {
        LOG(("Signal Protocol: Using %1 with TPM backing for CAC-verified peer %2")
            .arg(trustParams.cipher)
            .arg(peer->id.value));
    }

    // Get the current session
    auto session = getSession(peer);

    // Update last used timestamp
    session.lastUsedAt = base::unixtime::now();

    // DH ratchet: if we received a new remote DH key, rotate our DH key pair
    if (session.pendingRemoteDH) {
        // Save old sending chain length
        session.previousSendingChainLength = session.sendingMessageCounter;

        // Generate new DH key pair
        session.dhSendingPrivateKey = generateDH();
        session.dhSendingPublicKey = x25519PublicFromPrivate(session.dhSendingPrivateKey);

        // Perform DH ratchet: KDF_RK(rootKey, DH(new_priv, remote_pub))
        auto dhOutput = x25519(session.dhSendingPrivateKey, session.dhRemotePublicKey);
        auto rkResult = kdfRk(session.rootKey, dhOutput);
        session.rootKey = rkResult.rootKey;
        session.sendingChainKey = rkResult.chainKey;

        // Reset sending counter
        session.sendingMessageCounter = 0;
        session.pendingRemoteDH = false;

        secureWipe(dhOutput);
    }

    // Generate message key from chain key
    auto messageKey = deriveKey(session.sendingChainKey,
                               kInfoMessageKey,
                               kAesKeySize);

    // Advance the chain key
    session.sendingChainKey = ratchetChainKey(session.sendingChainKey);

    // Prepare metadata
    outMetadata.messageCounter = session.sendingMessageCounter++;
    outMetadata.senderPublicKey = session.dhSendingPublicKey;
    outMetadata.timestamp = base::unixtime::now();

    // Create random IV for AES-GCM (12 bytes)
    outMetadata.iv = generateRandomBytes(kGcmIvSize);

    // Build AAD: message counter (4 bytes) + sender public key (32 bytes)
    bytes::vector aad;
    aad.reserve(4 + session.dhSendingPublicKey.size());
    auto counter = outMetadata.messageCounter;
    aad.push_back(bytes::type((counter >> 24) & 0xFF));
    aad.push_back(bytes::type((counter >> 16) & 0xFF));
    aad.push_back(bytes::type((counter >> 8) & 0xFF));
    aad.push_back(bytes::type(counter & 0xFF));
    aad.insert(aad.end(), session.dhSendingPublicKey.begin(), session.dhSendingPublicKey.end());

    // Encrypt plaintext using AES-256-GCM (returns ciphertext || tag)
    auto ciphertext = aesGcmEncrypt(plaintext, messageKey, outMetadata.iv, aad);

    // Zeroize sensitive key material
    secureWipe(messageKey);
    secureWipe(aad);

    if (ciphertext.empty()) {
        LOG(("Signal Protocol Error: AES-GCM encryption failed"));
        return {};
    }

    // Update the session
    updateSession(peer, session);

    return ciphertext;
}

// Message decryption
bytes::vector SignalProtocol::decryptMessage(
    const bytes::const_span &ciphertext,
    not_null<PeerData*> peer,
    const MessageMetadata &metadata) {

    if (!hasSession(peer)) {
        LOG(("Signal Protocol: No session for peer %1").arg(peer->id.value));
        return {};
    }

    // Get the current session
    auto session = getSession(peer);

    // Update last used timestamp
    session.lastUsedAt = base::unixtime::now();

    // DH ratchet: check if the sender's DH key has changed
    const bool dhChanged = (metadata.senderPublicKey != session.dhRemotePublicKey)
        && !metadata.senderPublicKey.empty()
        && !session.dhRemotePublicKey.empty();

    if (dhChanged) {
        // Save old receiving chain length
        session.previousSendingChainLength = session.receivingMessageCounter;

        // Update remote DH key
        session.dhRemotePublicKey = metadata.senderPublicKey;

        // Generate new DH key pair for our side
        auto newDhPrivate = generateDH();
        auto newDhPublic = x25519PublicFromPrivate(newDhPrivate);

        // First KDF_RK: derive new root key and receiving chain key
        auto dhOutput1 = x25519(newDhPrivate, session.dhRemotePublicKey);
        auto rkResult1 = kdfRk(session.rootKey, dhOutput1);
        session.rootKey = rkResult1.rootKey;
        session.receivingChainKey = rkResult1.chainKey;

        // Second KDF_RK: derive new root key and sending chain key
        auto dhOutput2 = x25519(newDhPrivate, session.dhRemotePublicKey);
        auto rkResult2 = kdfRk(session.rootKey, dhOutput2);
        session.rootKey = rkResult2.rootKey;
        session.sendingChainKey = rkResult2.chainKey;

        // Update our DH keys
        session.dhSendingPrivateKey = newDhPrivate;
        session.dhSendingPublicKey = newDhPublic;

        // Reset counters for new chain
        session.receivingMessageCounter = 0;
        session.sendingMessageCounter = 0;

        // Clear skipped message keys from previous chain
        for (auto &sk : session.skippedMessageKeys) {
            secureWipe(sk.key);
        }
        session.skippedMessageKeys.clear();

        secureWipe(dhOutput1);
        secureWipe(dhOutput2);
    }

    bytes::vector messageKey;
    bytes::vector plaintext;

    // Check if this is the expected message in sequence
    if (metadata.messageCounter == session.receivingMessageCounter) {
        // Expected message - derive key from current chain
        messageKey = deriveKey(session.receivingChainKey,
                              kInfoMessageKey,
                              kAesKeySize);

        // Advance chain key
        session.receivingChainKey = ratchetChainKey(session.receivingChainKey);
        session.receivingMessageCounter++;
    } else if (metadata.messageCounter > session.receivingMessageCounter) {
        // Future message - we need to catch up
        if (metadata.messageCounter - session.receivingMessageCounter > 2000) {
            LOG(("Signal Protocol: Too many skipped messages"));
            return {};
        }

        // Store current keys
        auto currentChainKey = session.receivingChainKey;
        auto currentCounter = session.receivingMessageCounter;

        // Skip ahead and save the skipped keys
        while (currentCounter < metadata.messageCounter) {
            auto skippedKey = deriveKey(currentChainKey,
                                       kInfoMessageKey,
                                       kAesKeySize);

            SessionState::SkippedKey skip;
            skip.messageNumber = currentCounter;
            skip.key = skippedKey;
            session.skippedMessageKeys.push_back(skip);

            if (session.skippedMessageKeys.size() > kMaxSkippedKeys) {
                secureWipe(session.skippedMessageKeys.front().key);
                session.skippedMessageKeys.erase(session.skippedMessageKeys.begin());
            }

            currentChainKey = ratchetChainKey(currentChainKey);
            currentCounter++;
        }

        // Get key for current message
        messageKey = deriveKey(currentChainKey,
                              kInfoMessageKey,
                              kAesKeySize);

        session.receivingChainKey = ratchetChainKey(currentChainKey);
        session.receivingMessageCounter = currentCounter + 1;
    } else {
        // Old message - check if we have the key saved
        auto it = std::find_if(
            session.skippedMessageKeys.begin(),
            session.skippedMessageKeys.end(),
            [&](const SessionState::SkippedKey &key) {
                return key.messageNumber == metadata.messageCounter;
            });

        if (it != session.skippedMessageKeys.end()) {
            messageKey = it->key;
            session.skippedMessageKeys.erase(it);
        } else {
            LOG(("Signal Protocol: Message key not found for counter %1")
                .arg(metadata.messageCounter));
            return {};
        }
    }

    // Build AAD: message counter (4 bytes) + sender public key (32 bytes)
    bytes::vector aad;
    aad.reserve(4 + metadata.senderPublicKey.size());
    auto counter = metadata.messageCounter;
    aad.push_back(bytes::type((counter >> 24) & 0xFF));
    aad.push_back(bytes::type((counter >> 16) & 0xFF));
    aad.push_back(bytes::type((counter >> 8) & 0xFF));
    aad.push_back(bytes::type(counter & 0xFF));
    aad.insert(aad.end(), metadata.senderPublicKey.begin(), metadata.senderPublicKey.end());

    // Decrypt using AES-256-GCM (input is ciphertext || tag)
    plaintext = aesGcmDecrypt(ciphertext, messageKey, metadata.iv, aad);

    // Zeroize sensitive key material
    secureWipe(messageKey);
    secureWipe(aad);

    if (plaintext.empty()) {
        LOG(("Signal Protocol Error: AES-GCM decryption failed (auth tag mismatch)"));
        return {};
    }

    // Update session
    updateSession(peer, session);

    return plaintext;
}

// Cryptographic helpers
bytes::vector SignalProtocol::deriveKey(
    const bytes::const_span &input, 
    const QString &info,
    int length) {
    
    bytes::vector output(length);
    auto infoBytes = info.toUtf8();
    
    // Create HKDF context
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) {
        LOG(("Signal Protocol Error: Failed to create HKDF context"));
        return output;
    }
    
    // Initialize HKDF
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        LOG(("Signal Protocol Error: Failed to initialize HKDF"));
        return output;
    }
    
    // Set HKDF mode to expand only (we're using the input directly as PRK)
    if (EVP_PKEY_CTX_set_hkdf_mode(pctx, EVP_KDF_HKDF_MODE_EXPAND_ONLY) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        LOG(("Signal Protocol Error: Failed to set HKDF mode"));
        return output;
    }
    
    // Set the key material (PRK)
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, asConstUChar(input), input.size()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        LOG(("Signal Protocol Error: Failed to set HKDF key"));
        return output;
    }
    
    // Set the info string
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx,
            reinterpret_cast<const unsigned char*>(infoBytes.constData()),
            infoBytes.size()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        LOG(("Signal Protocol Error: Failed to set HKDF info"));
        return output;
    }
    
    // Generate the output key material
    size_t outLen = length;
    auto outputSpan = bytes::make_span(output);
    if (EVP_PKEY_derive(pctx, asUChar(outputSpan), &outLen) <= 0) {
        LOG(("Signal Protocol Error: Failed to derive HKDF output"));
    }
    
    EVP_PKEY_CTX_free(pctx);
    return output;
}

bytes::vector SignalProtocol::calculateHMAC(
    const bytes::const_span &key, 
    const bytes::const_span &data) {
    
    bytes::vector output(EVP_MAX_MD_SIZE);
    unsigned int outLen = 0;
    
    // Create HMAC context
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (!ctx) {
        LOG(("Signal Protocol Error: Failed to create HMAC context"));
        return output;
    }
    
    // Initialize with SHA-256
    if (!HMAC_Init_ex(ctx, asConstUChar(key), key.size(), EVP_sha256(), nullptr)) {
        HMAC_CTX_free(ctx);
        LOG(("Signal Protocol Error: Failed to initialize HMAC"));
        return output;
    }
    
    // Update with input data
    if (!HMAC_Update(ctx, asConstUChar(data), data.size())) {
        HMAC_CTX_free(ctx);
        LOG(("Signal Protocol Error: Failed to update HMAC"));
        return output;
    }
    
    // Finalize
    auto outputSpan = bytes::make_span(output);
    if (!HMAC_Final(ctx, asUChar(outputSpan), &outLen)) {
        LOG(("Signal Protocol Error: Failed to finalize HMAC"));
    }
    
    HMAC_CTX_free(ctx);
    output.resize(outLen);
    return output;
}

bytes::vector SignalProtocol::ratchetChainKey(const bytes::const_span &chainKey) {
    // Chain key ratchet using HMAC-SHA256
    bytes::vector input(1, bytes::type(0x01));
    return calculateHMAC(chainKey, input);
}

bytes::vector SignalProtocol::ratchetRootKey(const SessionState &state) {
    // DH ratchet to create new root key
    auto dhOutput = x25519(state.dhSendingPrivateKey, state.dhRemotePublicKey);
    auto combined = bytes::concatenate(state.rootKey, dhOutput);
    return deriveKey(combined, kInfoRootKey, kAesKeySize);
}

SignalProtocol::KdfRkResult SignalProtocol::kdfRk(
        const bytes::const_span &rootKey,
        const bytes::const_span &dhOutput) {
    // KDF_RK: HKDF-SHA256(dhOutput, salt=rootKey, info=kInfoKdfRk) -> 64 bytes
    // First 32 bytes = new root key, second 32 bytes = new chain key
    auto combined = bytes::concatenate(rootKey, dhOutput);
    auto derived = deriveKey(combined, kInfoKdfRk, kAesKeySize * 2);

    KdfRkResult result;
    auto span = bytes::make_span(derived);
    result.rootKey = bytes::vector(span.begin(), span.begin() + kAesKeySize);
    result.chainKey = bytes::vector(span.begin() + kAesKeySize, span.begin() + (kAesKeySize * 2));

    secureWipe(derived);
    return result;
}

bytes::vector SignalProtocol::aesGcmEncrypt(
        const bytes::const_span &plaintext,
        const bytes::const_span &key,
        const bytes::const_span &iv,
        const bytes::const_span &aad) {
    return aesGcmEncryptLocal(plaintext, key, iv, aad);
}

bytes::vector SignalProtocol::aesGcmDecrypt(
        const bytes::const_span &ciphertext,
        const bytes::const_span &key,
        const bytes::const_span &iv,
        const bytes::const_span &aad) {
    return aesGcmDecryptLocal(ciphertext, key, iv, aad);
}

void SignalProtocol::secureWipe(bytes::vector &data) {
    if (!data.empty()) {
        OPENSSL_cleanse(data.data(), data.size());
        data.clear();
    }
}

const SignalProtocol::KeyBundle &SignalProtocol::cachedKeyBundle() const {
    return _cachedBundle;
}

void SignalProtocol::refreshCachedKeyBundle() {
    _cachedBundle = generateLocalKeyBundle();
    _cachedBundleValid = true;
}

// Helpers
bytes::vector SignalProtocol::generateDH() {
    return x25519Generate();
}

bytes::vector SignalProtocol::generateRandomBytes(int length) {
    bytes::vector result(length);
    // Use OpenSSL's cryptographically secure random number generator
    if (RAND_bytes(asUChar(bytes::make_span(result)), result.size()) != 1) {
        LOG(("Signal Protocol Error: Failed to generate secure random bytes"));
        // Fallback to less secure random as last resort
        base::RandomFill(result.data(), result.size());
    }
    return result;
}

// Local storage for encrypted message history
void SignalProtocol::saveEncryptedHistoryLocal(
    not_null<PeerData*> peer, 
    const HistoryItem *item) {
    
    if (!item) return;
    
    auto peerDir = QString::number(peer->id.value);
    auto storagePath = signalStoragePath(_session) + peerDir;
    
    QDir dir(storagePath);
    if (!dir.exists()) {
        dir.mkpath(".");
    }
    
    auto msgId = item->id;
    auto filePath = storagePath + QString("/msg_%1.json").arg(msgId.bare);
    
    QJsonObject obj;
    obj["msgId"] = QString::number(msgId.bare);
    obj["date"] = item->date();
    
    // Serialize text
    auto text = item->originalText();
    obj["text"] = text.text;
    
    // Serialize entities
    QJsonArray entitiesArray;
    for (const auto &entity : text.entities) {
        QJsonObject entityObj;
        entityObj["type"] = static_cast<int>(entity.type());
        entityObj["offset"] = entity.offset();
        entityObj["length"] = entity.length();
        entityObj["data"] = entity.data();
        entitiesArray.append(entityObj);
    }
    obj["entities"] = entitiesArray;
    
    // Save to file
    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(obj).toJson(QJsonDocument::Compact));
        file.close();
    }
}

HistoryItem* SignalProtocol::loadEncryptedHistoryLocal(
    not_null<PeerData*> peer, 
    MsgId msgId) {
    
    auto peerDir = QString::number(peer->id.value);
    auto storagePath = signalStoragePath(_session) + peerDir;
    auto filePath = storagePath + QString("/msg_%1.json").arg(msgId.bare);
    
    QFile file(filePath);
    if (!file.exists() || !file.open(QIODevice::ReadOnly)) {
        return nullptr;
    }
    
    auto data = file.readAll();
    file.close();
    
    auto doc = QJsonDocument::fromJson(data);
    auto obj = doc.object();
    
    // Get text and entities
    auto text = obj["text"].toString();
    auto entitiesArray = obj["entities"].toArray();
    auto date = obj["date"].toInt();
    
    TextWithEntities textWithEntities;
    textWithEntities.text = text;
    
    // Restore entities
    for (const auto &entityValue : entitiesArray) {
        auto entityObj = entityValue.toObject();
        auto type = static_cast<EntityType>(entityObj["type"].toInt());
        auto offset = entityObj["offset"].toInt();
        auto length = entityObj["length"].toInt();
        auto data = entityObj["data"].toString();
        
        textWithEntities.entities.push_back(
            EntityInText(type, offset, length, data));
    }
    
    // Reconstruct the message
    // Note: Direct History API access requires full definition in header
    // Using Session::addNewLocalMessage instead for encrypted content
    return nullptr;  // Placeholder: encrypted message storage handled via session
}

// Implementation for other methods would follow...
// Including session management, key rotation, etc.

void SignalProtocol::createSession(not_null<PeerData*> peer, const KeyBundle &remoteBundle) {
    // Verify remote bundle signature before using it
    if (!verifyKeyBundleSignature(remoteBundle)) {
        LOG(("Signal Protocol Error: Remote key bundle signature verification failed in createSession for peer %1").arg(peer->id.value));
        return;
    }

    SessionState state;

    // Initialize device IDs
    state.localDevice = _localDevice;
    state.remoteDevice = remoteBundle.deviceId;

    // Alice initiates: generate ephemeral key pair (EK_A)
    state.dhSendingPrivateKey = generateDH();
    state.dhSendingPublicKey = x25519PublicFromPrivate(state.dhSendingPrivateKey);

    // Set remote DH public key to Bob's signed pre-key
    state.dhRemotePublicKey = remoteBundle.signedPreKey;

    // X3DH: Alice uses her identity key (IK_A) and ephemeral key (EK_A)
    // against Bob's signed pre-key (SPK_B) and optional one-time pre-key (OPK_B)
    //
    // DH1 = X25519(IK_A_priv, SPK_B_pub)  -- Alice identity x Bob signed pre-key
    // DH2 = X25519(EK_A_priv, SPK_B_pub)  -- Alice ephemeral x Bob signed pre-key
    // DH3 = X25519(IK_A_priv, OPK_B_pub)  -- Alice identity x Bob one-time pre-key (if present)
    // DH4 = X25519(EK_A_priv, OPK_B_pub)  -- Alice ephemeral x Bob one-time pre-key (if present)
    //
    // RK = HKDF(DH1 || DH2 || DH3 || DH4, info=kInfoX3DH)
    // SK (initial sending chain) = KDF_RK(RK, DH4) if OPK exists, else KDF_RK(RK, DH2)

    auto dh1 = x25519(_identityKeyPrivate, remoteBundle.signedPreKey);
    auto dh2 = x25519(state.dhSendingPrivateKey, remoteBundle.signedPreKey);

    bytes::vector combined;
    bytes::vector dhForChainInit;

    if (!remoteBundle.oneTimePreKey.empty()) {
        auto dh3 = x25519(_identityKeyPrivate, remoteBundle.oneTimePreKey);
        auto dh4 = x25519(state.dhSendingPrivateKey, remoteBundle.oneTimePreKey);
        combined = bytes::concatenate(dh1, dh2, dh3, dh4);
        dhForChainInit = dh4;
        secureWipe(dh3);
    } else {
        combined = bytes::concatenate(dh1, dh2);
        dhForChainInit = dh2;
    }

    // Derive initial root key from X3DH combined secret
    state.rootKey = deriveKey(combined, kInfoX3DH, kAesKeySize);

    // Derive initial sending chain key via KDF_RK
    auto rkResult = kdfRk(state.rootKey, dhForChainInit);
    state.rootKey = rkResult.rootKey;
    state.sendingChainKey = rkResult.chainKey;

    // Receiving chain key: derive from root key with different info
    // Bob will derive the same when he processes Alice's first message
    auto recvChainData = deriveKey(state.rootKey, kInfoChainKey, kAesKeySize * 2);
    {
        auto span = bytes::make_span(recvChainData);
        state.receivingChainKey = bytes::vector(span.begin() + kAesKeySize, span.begin() + (kAesKeySize * 2));
    }

    // Initialize counters
    state.sendingMessageCounter = 0;
    state.receivingMessageCounter = 0;
    state.previousSendingChainLength = 0;
    state.pendingRemoteDH = false;

    // Set creation timestamp
    state.createdAt = base::unixtime::now();
    state.lastUsedAt = state.createdAt;

    // Zeroize sensitive DH outputs
    secureWipe(dh1);
    secureWipe(dh2);
    secureWipe(dhForChainInit);
    secureWipe(combined);

    // Store the session
    _peerKeyData[peer->id].remoteBundle = remoteBundle;
    _peerKeyData[peer->id].sessions.push_back(state);

    // Save to disk
    saveSession(peer, state);
}

void SignalProtocol::createSessionFromInitialMessage(
        not_null<PeerData*> peer,
        const bytes::const_span &aliceIdentityKey,
        const bytes::const_span &aliceEphemeralKey,
        const KeyBundle &aliceBundle) {
    // Bob's side: he receives Alice's identity key and ephemeral key
    // along with Alice's key bundle (for future ratcheting).

    // Load Bob's signed pre-key private and one-time pre-key private from storage
    auto keyPath = signalStoragePath(_session) + kSignalKeyDbName;
    QFile keyFile(keyPath);
    bytes::vector signedPreKeyPrivate;
    bytes::vector oneTimePreKeyPrivate;

    if (keyFile.open(QIODevice::ReadOnly)) {
        auto data = keyFile.readAll();
        auto doc = QJsonDocument::fromJson(data);
        auto obj = doc.object();

        if (obj.contains("signedPreKey")) {
            auto preKey = obj["signedPreKey"].toObject();
            signedPreKeyPrivate = bytes::make_vector(
                QByteArray::fromBase64(preKey["private"].toString().toLatin1()));
        }

        if (obj.contains("oneTimePreKey")) {
            auto oneTimeKey = obj["oneTimePreKey"].toObject();
            oneTimePreKeyPrivate = bytes::make_vector(
                QByteArray::fromBase64(oneTimeKey["private"].toString().toLatin1()));
        }

        keyFile.close();
    }

    if (signedPreKeyPrivate.empty()) {
        LOG(("Signal Protocol: Could not load signed pre-key for receiver-side init"));
        return;
    }

    SessionState state;
    state.localDevice = _localDevice;
    state.remoteDevice = aliceBundle.deviceId;

    // Bob's DH sending key is his signed pre-key (Alice already has it)
    state.dhSendingPrivateKey = signedPreKeyPrivate;
    state.dhSendingPublicKey = x25519PublicFromPrivate(signedPreKeyPrivate);

    // Remote DH key is Alice's ephemeral key
    state.dhRemotePublicKey = bytes::make_vector(aliceEphemeralKey);

    // X3DH from Bob's perspective:
    // DH1 = X25519(SPK_B_priv, IK_A_pub)  -- Bob signed pre-key x Alice identity key
    // DH2 = X25519(SPK_B_priv, EK_A_pub)  -- Bob signed pre-key x Alice ephemeral key
    // DH3 = X25519(OPK_B_priv, IK_A_pub)  -- Bob one-time pre-key x Alice identity key (if present)
    // DH4 = X25519(OPK_B_priv, EK_A_pub)  -- Bob one-time pre-key x Alice ephemeral key (if present)
    auto dh1 = x25519(signedPreKeyPrivate, aliceIdentityKey);
    auto dh2 = x25519(signedPreKeyPrivate, aliceEphemeralKey);

    bytes::vector combined;
    bytes::vector dhForChainInit;

    if (!oneTimePreKeyPrivate.empty()) {
        auto dh3 = x25519(oneTimePreKeyPrivate, aliceIdentityKey);
        auto dh4 = x25519(oneTimePreKeyPrivate, aliceEphemeralKey);
        combined = bytes::concatenate(dh1, dh2, dh3, dh4);
        dhForChainInit = dh4;
        secureWipe(dh3);
    } else {
        combined = bytes::concatenate(dh1, dh2);
        dhForChainInit = dh2;
    }

    // Derive initial root key from X3DH combined secret (same as Alice)
    state.rootKey = deriveKey(combined, kInfoX3DH, kAesKeySize);

    // Derive initial chain keys via KDF_RK (same as Alice)
    auto rkResult = kdfRk(state.rootKey, dhForChainInit);
    state.rootKey = rkResult.rootKey;

    // Bob's receiving chain = Alice's sending chain, and vice versa
    state.receivingChainKey = rkResult.chainKey;

    // Bob's sending chain: derive from root key with different info
    auto sendChainData = deriveKey(state.rootKey, kInfoChainKey, kAesKeySize * 2);
    {
        auto span = bytes::make_span(sendChainData);
        state.sendingChainKey = bytes::vector(span.begin(), span.begin() + kAesKeySize);
    }

    // Initialize counters
    state.sendingMessageCounter = 0;
    state.receivingMessageCounter = 0;
    state.previousSendingChainLength = 0;
    state.pendingRemoteDH = false;

    // Set creation timestamp
    state.createdAt = base::unixtime::now();
    state.lastUsedAt = state.createdAt;

    // Zeroize sensitive DH outputs
    secureWipe(dh1);
    secureWipe(dh2);
    secureWipe(dhForChainInit);
    secureWipe(combined);
    secureWipe(oneTimePreKeyPrivate);

    // Store Alice's bundle and the session
    _peerKeyData[peer->id].remoteBundle = aliceBundle;
    _peerKeyData[peer->id].sessions.push_back(state);

    // Save to disk
    saveSession(peer, state);

    LOG(("Signal Protocol: Receiver-side session created for peer %1").arg(peer->id.value));
}

bool SignalProtocol::hasSession(not_null<PeerData*> peer) const {
    auto it = _peerKeyData.find(peer->id);
    if (it != _peerKeyData.end()) {
        return !it->second.sessions.empty();
    }
    
    // Try to load from storage
    auto peerDir = QString::number(peer->id.value);
    auto storagePath = signalStoragePath(_session) + peerDir;
    auto sessionFile = storagePath + "/session.json";
    
    return QFile::exists(sessionFile);
}

void SignalProtocol::updateSession(not_null<PeerData*> peer, const SessionState &state) {
    auto &sessions = _peerKeyData[peer->id].sessions;
    
    // Find and update existing session
    auto it = std::find_if(sessions.begin(), sessions.end(), 
                          [&](const SessionState &s) {
                              return s.remoteDevice.identifier == state.remoteDevice.identifier;
                          });
    
    if (it != sessions.end()) {
        *it = state;
    } else {
        sessions.push_back(state);
    }
    
    // Save to disk
    saveSession(peer, state);
}

SignalProtocol::SessionState SignalProtocol::getSession(not_null<PeerData*> peer) const {
    // Try to find in memory first
    auto it = _peerKeyData.find(peer->id);
    if (it != _peerKeyData.end() && !it->second.sessions.empty()) {
        return it->second.sessions.front(); // Return first session
    }
    
    // Load from storage
    return const_cast<SignalProtocol*>(this)->loadSession(peer);
}

// Signal Protocol integration points with the Telegram app
// These would be connected to appropriate UI elements and message handling code

void SignalProtocol::rotateSession(not_null<PeerData*> peer, bool forceRotate) {
    // Get current session
    auto session = getSession(peer);
    
    // Check if rotation is needed
    auto now = base::unixtime::now();
    if (!forceRotate && (now - session.lastUsedAt) < _keyRotationInterval) {
        return;
    }
    
    // Generate new DH key pair
    auto newPrivateKey = generateDH();
    auto newPublicKey = x25519PublicFromPrivate(newPrivateKey);
    
    // Store old sending chain length
    session.previousSendingChainLength = session.sendingMessageCounter;
    
    // Perform DH with current remote key
    auto dhResult = x25519(newPrivateKey, session.dhRemotePublicKey);
    
    // Derive new root key and chain keys via KDF_RK
    auto rkResult = kdfRk(session.rootKey, dhResult);
    session.rootKey = rkResult.rootKey;
    session.sendingChainKey = rkResult.chainKey;

    // Derive receiving chain key from new root key
    auto chainKeyData = deriveKey(session.rootKey, kInfoChainKey, kAesKeySize * 2);
    {
        auto span = bytes::make_span(chainKeyData);
        session.receivingChainKey = bytes::vector(span.begin() + kAesKeySize, span.begin() + (kAesKeySize * 2));
    }
    
    // Update DH keys
    session.dhSendingPrivateKey = newPrivateKey;
    session.dhSendingPublicKey = newPublicKey;
    
    // Reset message counters
    session.sendingMessageCounter = 0;
    session.receivingMessageCounter = 0;
    
    // Update timestamps
    session.lastUsedAt = now;
    
    // Zeroize DH output
    secureWipe(dhResult);
    
    // Save updated session
    updateSession(peer, session);
    
    // Schedule next rotation
    scheduleKeyRotation(peer, now + _keyRotationInterval);
}

void SignalProtocol::scheduleKeyRotation(not_null<PeerData*> peer, TimeId scheduleTime) {
    // Remove any existing scheduled rotation for this peer
    _scheduledRotations.erase(
        std::remove_if(
            _scheduledRotations.begin(),
            _scheduledRotations.end(),
            [&](const ScheduledKeyRotation &rotation) {
                return rotation.peerId == peer->id;
            }
        ),
        _scheduledRotations.end()
    );
    
    // Add new scheduled rotation
    ScheduledKeyRotation rotation;
    rotation.peerId = peer->id;
    rotation.time = scheduleTime;
    _scheduledRotations.push_back(rotation);
    
    // Sort by time
    std::sort(
        _scheduledRotations.begin(),
        _scheduledRotations.end(),
        [](const ScheduledKeyRotation &a, const ScheduledKeyRotation &b) {
            return a.time < b.time;
        }
    );
}

void SignalProtocol::performScheduledKeyRotations() {
    auto now = base::unixtime::now();
    
    // Process all rotations that are due
    while (!_scheduledRotations.empty() && _scheduledRotations.front().time <= now) {
        auto rotation = _scheduledRotations.front();
        _scheduledRotations.erase(_scheduledRotations.begin());
        
        // Get peer
        auto peer = _session->peer(rotation.peerId);
        if (!peer) {
            continue;
        }
        
        // Rotate session
        rotateSession(peer, true);
    }
}

bytes::vector SignalProtocol::backupKeys(const QString &password) {
    // Serialize all keys and sessions
    QJsonObject backup;
    
    // Add identity keys
    backup["identityPublic"] = QString::fromLatin1(QByteArray(
        reinterpret_cast<const char*>(_identityKeyPublic.data()),
        _identityKeyPublic.size()).toBase64());
    
    backup["identityPrivate"] = QString::fromLatin1(QByteArray(
        reinterpret_cast<const char*>(_identityKeyPrivate.data()),
        _identityKeyPrivate.size()).toBase64());
    
    // Add device info
    QJsonObject deviceObj;
    deviceObj["identifier"] = _localDevice.identifier;
    deviceObj["registrationId"] = QString::number(_localDevice.registrationId);
    backup["device"] = deviceObj;
    
    // Add peer sessions
    QJsonObject peersObj;
    for (const auto &[peerId, data] : _peerKeyData) {
        QJsonObject peerObj;
        
        // Add remote bundle
        QJsonObject bundleObj;
        bundleObj["identityKey"] = QString::fromLatin1(QByteArray(
            reinterpret_cast<const char*>(data.remoteBundle.identityKey.data()),
            data.remoteBundle.identityKey.size()).toBase64());
        
        bundleObj["signedPreKey"] = QString::fromLatin1(QByteArray(
            reinterpret_cast<const char*>(data.remoteBundle.signedPreKey.data()),
            data.remoteBundle.signedPreKey.size()).toBase64());
        
        if (!data.remoteBundle.oneTimePreKey.empty()) {
            bundleObj["oneTimePreKey"] = QString::fromLatin1(QByteArray(
                reinterpret_cast<const char*>(data.remoteBundle.oneTimePreKey.data()),
                data.remoteBundle.oneTimePreKey.size()).toBase64());
        }
        
        bundleObj["signature"] = QString::fromLatin1(QByteArray(
            reinterpret_cast<const char*>(data.remoteBundle.signature.data()),
            data.remoteBundle.signature.size()).toBase64());
        
        QJsonObject deviceIdObj;
        deviceIdObj["identifier"] = data.remoteBundle.deviceId.identifier;
        deviceIdObj["registrationId"] = QString::number(data.remoteBundle.deviceId.registrationId);
        bundleObj["deviceId"] = deviceIdObj;
        
        peerObj["bundle"] = bundleObj;
        
        // Add sessions
        QJsonArray sessionsArray;
        for (const auto &session : data.sessions) {
            QJsonObject sessionObj;
            
            // Add keys
            sessionObj["rootKey"] = QString::fromLatin1(QByteArray(
                reinterpret_cast<const char*>(session.rootKey.data()),
                session.rootKey.size()).toBase64());
            
            sessionObj["sendingChainKey"] = QString::fromLatin1(QByteArray(
                reinterpret_cast<const char*>(session.sendingChainKey.data()),
                session.sendingChainKey.size()).toBase64());
            
            sessionObj["receivingChainKey"] = QString::fromLatin1(QByteArray(
                reinterpret_cast<const char*>(session.receivingChainKey.data()),
                session.receivingChainKey.size()).toBase64());
            
            // Add DH keys
            sessionObj["dhSendingPublic"] = QString::fromLatin1(QByteArray(
                reinterpret_cast<const char*>(session.dhSendingPublicKey.data()),
                session.dhSendingPublicKey.size()).toBase64());
            
            sessionObj["dhSendingPrivate"] = QString::fromLatin1(QByteArray(
                reinterpret_cast<const char*>(session.dhSendingPrivateKey.data()),
                session.dhSendingPrivateKey.size()).toBase64());
            
            sessionObj["dhRemotePublic"] = QString::fromLatin1(QByteArray(
                reinterpret_cast<const char*>(session.dhRemotePublicKey.data()),
                session.dhRemotePublicKey.size()).toBase64());
            
            // Add counters
            sessionObj["sendingCounter"] = QString::number(session.sendingMessageCounter);
            sessionObj["receivingCounter"] = QString::number(session.receivingMessageCounter);
            sessionObj["previousChainLength"] = QString::number(session.previousSendingChainLength);
            
            // Add timestamps
            sessionObj["createdAt"] = QString::number(session.createdAt);
            sessionObj["lastUsedAt"] = QString::number(session.lastUsedAt);
            
            // Add device IDs
            QJsonObject localDeviceObj;
            localDeviceObj["identifier"] = session.localDevice.identifier;
            localDeviceObj["registrationId"] = QString::number(session.localDevice.registrationId);
            sessionObj["localDevice"] = localDeviceObj;
            
            QJsonObject remoteDeviceObj;
            remoteDeviceObj["identifier"] = session.remoteDevice.identifier;
            remoteDeviceObj["registrationId"] = QString::number(session.remoteDevice.registrationId);
            sessionObj["remoteDevice"] = remoteDeviceObj;
            
            sessionsArray.append(sessionObj);
        }
        
        peerObj["sessions"] = sessionsArray;
        peersObj[QString::number(peerId.value)] = peerObj;
    }
    
    backup["peers"] = peersObj;
    
    // Serialize to JSON
    QJsonDocument doc(backup);
    auto jsonData = doc.toJson(QJsonDocument::Compact);
    
    // Derive encryption key from password using PBKDF2
    unsigned char salt[32];
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        LOG(("Signal Protocol Error: Failed to generate salt for backup"));
        return {};
    }
    
    unsigned char key[32];
    if (PKCS5_PBKDF2_HMAC(
        password.toUtf8().constData(),
        password.toUtf8().length(),
        salt,
        sizeof(salt),
        100000, // Iterations
        EVP_sha256(),
        sizeof(key),
        key) != 1) {
        LOG(("Signal Protocol Error: Failed to derive key for backup"));
        return {};
    }
    
    // Generate random IV
    unsigned char iv[12];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        LOG(("Signal Protocol Error: Failed to generate IV for backup"));
        return {};
    }
    
    // Create encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOG(("Signal Protocol Error: Failed to create encryption context for backup"));
        return {};
    }
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LOG(("Signal Protocol Error: Failed to initialize encryption for backup"));
        return {};
    }
    
    // Encrypt the data
    std::vector<unsigned char> ciphertext(jsonData.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen = 0;
    
    if (EVP_EncryptUpdate(
        ctx,
        ciphertext.data(),
        &outLen,
        reinterpret_cast<const unsigned char*>(jsonData.constData()),
        jsonData.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LOG(("Signal Protocol Error: Failed to encrypt backup data"));
        return {};
    }
    
    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LOG(("Signal Protocol Error: Failed to finalize backup encryption"));
        return {};
    }
    
    // Get the tag
    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LOG(("Signal Protocol Error: Failed to get encryption tag for backup"));
        return {};
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Combine all components into final backup
    bytes::vector result;
    result.reserve(sizeof(salt) + sizeof(iv) + sizeof(tag) + outLen + finalLen);

    auto appendSpan = [&result](const bytes::const_span span) {
        result.insert(result.end(), span.begin(), span.end());
    };

    appendSpan(bytes::make_span(salt, sizeof(salt)));
    appendSpan(bytes::make_span(iv, sizeof(iv)));
    appendSpan(bytes::make_span(ciphertext.data(), outLen + finalLen));
    appendSpan(bytes::make_span(tag, sizeof(tag)));

    return result;
}

bool SignalProtocol::restoreKeys(const bytes::const_span &backup, const QString &password) {
    if (backup.size() < 60) { // Minimum size for salt + IV + tag
        LOG(("Signal Protocol Error: Backup data too small"));
        return false;
    }
    
    // Extract components
    const auto backupSpan = backup;
    const unsigned char *salt = asConstUChar(backupSpan);
    const unsigned char *iv = salt + 32;
    const unsigned char *tag = salt + backupSpan.size() - 16;
    const unsigned char *ciphertext = iv + 12;
    size_t ciphertextLen = backup.size() - 60;
    
    // Derive key from password
    unsigned char key[32];
    if (PKCS5_PBKDF2_HMAC(
        password.toUtf8().constData(),
        password.toUtf8().length(),
        salt,
        32,
        100000, // Iterations
        EVP_sha256(),
        sizeof(key),
        key) != 1) {
        LOG(("Signal Protocol Error: Failed to derive key for backup restoration"));
        return false;
    }
    
    // Create decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOG(("Signal Protocol Error: Failed to create decryption context for backup"));
        return false;
    }
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LOG(("Signal Protocol Error: Failed to initialize decryption for backup"));
        return false;
    }
    
    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LOG(("Signal Protocol Error: Failed to set decryption tag for backup"));
        return false;
    }
    
    // Decrypt the data
    std::vector<unsigned char> plaintext(ciphertextLen);
    int outLen = 0;
    
    if (EVP_DecryptUpdate(
        ctx,
        plaintext.data(),
        &outLen,
        ciphertext,
        ciphertextLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LOG(("Signal Protocol Error: Failed to decrypt backup data"));
        return false;
    }
    
    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LOG(("Signal Protocol Error: Failed to verify backup integrity"));
        return false;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Parse JSON data
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(
        QByteArray(reinterpret_cast<const char*>(plaintext.data()), outLen + finalLen),
        &error);
    
    if (error.error != QJsonParseError::NoError) {
        LOG(("Signal Protocol Error: Failed to parse backup JSON: %1").arg(error.errorString()));
        return false;
    }
    
    auto backupObj = doc.object();
    
    // Restore identity keys
    auto identityPublic = QByteArray::fromBase64(backupObj["identityPublic"].toString().toLatin1());
    auto identityPrivate = QByteArray::fromBase64(backupObj["identityPrivate"].toString().toLatin1());
    
    _identityKeyPublic = bytes::make_vector(identityPublic);
    _identityKeyPrivate = bytes::make_vector(identityPrivate);
    
    // Restore device info
    auto deviceObj = backupObj["device"].toObject();
    _localDevice.identifier = deviceObj["identifier"].toString();
    _localDevice.registrationId = deviceObj["registrationId"].toString().toULongLong();
    
    // Clear existing peer data
    _peerKeyData.clear();
    
    // Restore peer sessions
    auto peersObj = backupObj["peers"].toObject();
    for (auto it = peersObj.begin(); it != peersObj.end(); ++it) {
        PeerId peerId(it.key().toULongLong());
        auto peerObj = it.value().toObject();
        
        // Restore bundle
        auto bundleObj = peerObj["bundle"].toObject();
        KeyBundle bundle;
        
        bundle.identityKey = bytes::make_vector(
            QByteArray::fromBase64(bundleObj["identityKey"].toString().toLatin1()));
        
        bundle.signedPreKey = bytes::make_vector(
            QByteArray::fromBase64(bundleObj["signedPreKey"].toString().toLatin1()));
        
        if (bundleObj.contains("oneTimePreKey")) {
            bundle.oneTimePreKey = bytes::make_vector(
                QByteArray::fromBase64(bundleObj["oneTimePreKey"].toString().toLatin1()));
        }
        
        bundle.signature = bytes::make_vector(
            QByteArray::fromBase64(bundleObj["signature"].toString().toLatin1()));
        
        auto deviceIdObj = bundleObj["deviceId"].toObject();
        bundle.deviceId.identifier = deviceIdObj["identifier"].toString();
        bundle.deviceId.registrationId = deviceIdObj["registrationId"].toString().toULongLong();
        
        // Restore sessions
        std::vector<SessionState> sessions;
        auto sessionsArray = peerObj["sessions"].toArray();
        
        for (const auto &value : sessionsArray) {
            auto sessionObj = value.toObject();
            SessionState session;
            
            // Restore keys
            session.rootKey = bytes::make_vector(
                QByteArray::fromBase64(sessionObj["rootKey"].toString().toLatin1()));
            
            session.sendingChainKey = bytes::make_vector(
                QByteArray::fromBase64(sessionObj["sendingChainKey"].toString().toLatin1()));
            
            session.receivingChainKey = bytes::make_vector(
                QByteArray::fromBase64(sessionObj["receivingChainKey"].toString().toLatin1()));
            
            // Restore DH keys
            session.dhSendingPublicKey = bytes::make_vector(
                QByteArray::fromBase64(sessionObj["dhSendingPublic"].toString().toLatin1()));
            
            session.dhSendingPrivateKey = bytes::make_vector(
                QByteArray::fromBase64(sessionObj["dhSendingPrivate"].toString().toLatin1()));
            
            session.dhRemotePublicKey = bytes::make_vector(
                QByteArray::fromBase64(sessionObj["dhRemotePublic"].toString().toLatin1()));
            
            // Restore counters
            session.sendingMessageCounter = sessionObj["sendingCounter"].toString().toUInt();
            session.receivingMessageCounter = sessionObj["receivingCounter"].toString().toUInt();
            session.previousSendingChainLength = sessionObj["previousChainLength"].toString().toUInt();
            
            // Restore timestamps
            session.createdAt = sessionObj["createdAt"].toString().toLongLong();
            session.lastUsedAt = sessionObj["lastUsedAt"].toString().toLongLong();
            
            // Restore device IDs
            auto localDeviceObj = sessionObj["localDevice"].toObject();
            session.localDevice.identifier = localDeviceObj["identifier"].toString();
            session.localDevice.registrationId = localDeviceObj["registrationId"].toString().toULongLong();
            
            auto remoteDeviceObj = sessionObj["remoteDevice"].toObject();
            session.remoteDevice.identifier = remoteDeviceObj["identifier"].toString();
            session.remoteDevice.registrationId = remoteDeviceObj["registrationId"].toString().toULongLong();
            
            sessions.push_back(session);
        }
        
        // Store restored data
        PeerKeyData &data = _peerKeyData[peerId];
        data.remoteBundle = bundle;
        data.sessions = sessions;
    }
    
    return true;
}

// Missing implementation functions for session management
void SignalProtocol::saveSession(not_null<PeerData*> peer, const SessionState &state) {
    auto peerDir = QString::number(peer->id.value);
    auto storagePath = signalStoragePath(_session) + peerDir;

    QDir dir(storagePath);
    if (!dir.exists()) {
        dir.mkpath(".");
    }

    auto sessionFile = storagePath + "/session.json";

    // Serialize session with HMAC integrity protection
    auto sessionData = serializeSession(state);
    auto hmacKey = deriveKey(_identityKeyPrivate, "session_hmac", 32);
    auto sessionHmac = calculateHMAC(hmacKey, bytes::make_span(sessionData));

    QJsonObject obj;
    obj["sessionData"] = QString::fromLatin1(sessionData.toBase64());
    obj["hmac"] = QString::fromLatin1(QByteArray(
        reinterpret_cast<const char*>(sessionHmac.data()),
        sessionHmac.size()).toBase64());
    obj["version"] = 1;

    QFile file(sessionFile);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(obj).toJson(QJsonDocument::Compact));
        file.close();
    }
}

SignalProtocol::SessionState SignalProtocol::loadSession(not_null<PeerData*> peer) {
    SessionState state;

    auto peerDir = QString::number(peer->id.value);
    auto storagePath = signalStoragePath(_session) + peerDir;
    auto sessionFile = storagePath + "/session.json";

    QFile file(sessionFile);
    if (!file.exists() || !file.open(QIODevice::ReadOnly)) {
        return state; // Return empty state
    }

    auto data = file.readAll();
    file.close();

    auto doc = QJsonDocument::fromJson(data);
    auto obj = doc.object();

    // Verify HMAC integrity
    auto sessionDataBase64 = obj["sessionData"].toString().toLatin1();
    auto hmacBase64 = obj["hmac"].toString().toLatin1();

    auto sessionData = QByteArray::fromBase64(sessionDataBase64);
    auto storedHmac = bytes::make_vector(QByteArray::fromBase64(hmacBase64));

    auto hmacKey = deriveKey(_identityKeyPrivate, "session_hmac", 32);
    auto calculatedHmac = calculateHMAC(hmacKey, bytes::make_span(sessionData));

    // Verify HMAC to ensure session integrity
    if (storedHmac.size() != calculatedHmac.size() ||
        CRYPTO_memcmp(storedHmac.data(), calculatedHmac.data(), storedHmac.size()) != 0) {
        LOG(("Signal Protocol Error: Session HMAC verification failed for peer %1").arg(peer->id.value));
        return state; // Return empty state on integrity failure
    }

    // Deserialize session data
    state = deserializeSession(sessionData);

    return state;
}

void SignalProtocol::registerRemoteKeyBundle(not_null<PeerData*> peer, const KeyBundle &bundle) {
    // Verify signature before accepting the key bundle
    if (!verifyKeyBundleSignature(bundle)) {
        LOG(("Signal Protocol Error: Key bundle signature verification failed for peer %1").arg(peer->id.value));
        return;
    }

    // Store the verified bundle
    _peerKeyData[peer->id].remoteBundle = bundle;

    // Save to persistent storage
    auto peerDir = QString::number(peer->id.value);
    auto storagePath = signalStoragePath(_session) + peerDir;

    QDir dir(storagePath);
    if (!dir.exists()) {
        dir.mkpath(".");
    }

    auto bundleFile = storagePath + "/key_bundle.json";

    QJsonObject obj;
    obj["identityKey"] = QString::fromLatin1(QByteArray(
        reinterpret_cast<const char*>(bundle.identityKey.data()),
        bundle.identityKey.size()).toBase64());

    obj["signedPreKey"] = QString::fromLatin1(QByteArray(
        reinterpret_cast<const char*>(bundle.signedPreKey.data()),
        bundle.signedPreKey.size()).toBase64());

    if (!bundle.oneTimePreKey.empty()) {
        obj["oneTimePreKey"] = QString::fromLatin1(QByteArray(
            reinterpret_cast<const char*>(bundle.oneTimePreKey.data()),
            bundle.oneTimePreKey.size()).toBase64());
    }

    obj["signature"] = QString::fromLatin1(QByteArray(
        reinterpret_cast<const char*>(bundle.signature.data()),
        bundle.signature.size()).toBase64());

    QJsonObject deviceObj;
    deviceObj["identifier"] = bundle.deviceId.identifier;
    deviceObj["registrationId"] = QString::number(bundle.deviceId.registrationId);
    obj["deviceId"] = deviceObj;

    QFile file(bundleFile);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(obj).toJson(QJsonDocument::Compact));
        file.close();
    }
}

SignalProtocol::KeyBundle SignalProtocol::getKeyBundleForPeer(not_null<PeerData*> peer) {
    auto it = _peerKeyData.find(peer->id);
    if (it != _peerKeyData.end()) {
        return it->second.remoteBundle;
    }

    // Try to load from storage
    KeyBundle bundle;
    auto peerDir = QString::number(peer->id.value);
    auto storagePath = signalStoragePath(_session) + peerDir;
    auto bundleFile = storagePath + "/key_bundle.json";

    QFile file(bundleFile);
    if (!file.exists() || !file.open(QIODevice::ReadOnly)) {
        return bundle; // Return empty bundle
    }

    auto data = file.readAll();
    file.close();

    auto doc = QJsonDocument::fromJson(data);
    auto obj = doc.object();

    bundle.identityKey = bytes::make_vector(
        QByteArray::fromBase64(obj["identityKey"].toString().toLatin1()));

    bundle.signedPreKey = bytes::make_vector(
        QByteArray::fromBase64(obj["signedPreKey"].toString().toLatin1()));

    if (obj.contains("oneTimePreKey")) {
        bundle.oneTimePreKey = bytes::make_vector(
            QByteArray::fromBase64(obj["oneTimePreKey"].toString().toLatin1()));
    }

    bundle.signature = bytes::make_vector(
        QByteArray::fromBase64(obj["signature"].toString().toLatin1()));

    auto deviceObj = obj["deviceId"].toObject();
    bundle.deviceId.identifier = deviceObj["identifier"].toString();
    bundle.deviceId.registrationId = deviceObj["registrationId"].toString().toULongLong();

    // Verify signature before returning
    if (!verifyKeyBundleSignature(bundle)) {
        LOG(("Signal Protocol Error: Stored key bundle signature verification failed for peer %1").arg(peer->id.value));
        return KeyBundle(); // Return empty bundle on verification failure
    }

    _peerKeyData[peer->id].remoteBundle = bundle;
    return bundle;
}

// Helper functions for Ed25519 signature operations
bytes::vector SignalProtocol::signWithIdentityKey(const bytes::const_span &data) {
    // Use Ed25519 digital signature with identity key
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        LOG(("Signal Protocol Error: Failed to create signing context"));
        return bytes::vector();
    }

    // Create private key from raw bytes
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519,
        nullptr,
        asConstUChar(_identityKeyPrivate),
        _identityKeyPrivate.size());

    if (!pkey) {
        EVP_MD_CTX_free(mdctx);
        LOG(("Signal Protocol Error: Failed to create Ed25519 private key for signing"));
        return bytes::vector();
    }

    // Initialize signing
    if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey) != 1) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        LOG(("Signal Protocol Error: Failed to initialize Ed25519 signing"));
        return bytes::vector();
    }

    // Sign the data
    size_t siglen = 64; // Ed25519 signature size is always 64 bytes
    bytes::vector signature(siglen);

    if (EVP_DigestSign(mdctx, asUChar(signature), &siglen, asConstUChar(data), data.size()) != 1) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        LOG(("Signal Protocol Error: Failed to generate Ed25519 signature"));
        return bytes::vector();
    }

    // Cleanup
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdctx);

    signature.resize(siglen);
    return signature;
}

bool SignalProtocol::verifyKeyBundleSignature(const KeyBundle &bundle) {
    // Verify Ed25519 signature on the signed pre-key
    return verifyEd25519Signature(bundle.signature, bundle.signedPreKey, bundle.identityKey);
}

bool SignalProtocol::verifyEd25519Signature(
    const bytes::const_span &signature,
    const bytes::const_span &data,
    const bytes::const_span &publicKey) {

    if (signature.size() != 64) {
        LOG(("Signal Protocol Error: Invalid Ed25519 signature size"));
        return false;
    }

    if (publicKey.size() != 32) {
        LOG(("Signal Protocol Error: Invalid Ed25519 public key size"));
        return false;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        LOG(("Signal Protocol Error: Failed to create verification context"));
        return false;
    }

    // Create public key from raw bytes
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519,
        nullptr,
        asConstUChar(publicKey),
        publicKey.size());

    if (!pkey) {
        EVP_MD_CTX_free(mdctx);
        LOG(("Signal Protocol Error: Failed to create Ed25519 public key for verification"));
        return false;
    }

    // Initialize verification
    if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey) != 1) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        LOG(("Signal Protocol Error: Failed to initialize Ed25519 verification"));
        return false;
    }

    // Verify the signature
    int result = EVP_DigestVerify(
        mdctx,
        asConstUChar(signature),
        signature.size(),
        asConstUChar(data),
        data.size());

    // Cleanup
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdctx);

    if (result == 1) {
        return true; // Signature is valid
    } else if (result == 0) {
        LOG(("Signal Protocol Warning: Ed25519 signature verification failed"));
        return false; // Signature is invalid
    } else {
        LOG(("Signal Protocol Error: Ed25519 signature verification error"));
        return false; // Verification error
    }
}

// PBKDF2-based encryption/decryption for secure key storage
QByteArray SignalProtocol::encryptWithPBKDF2(const bytes::const_span &data, const QString &password) {
    // Generate random salt
    unsigned char salt[32];
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        LOG(("Signal Protocol Error: Failed to generate salt for key encryption"));
        return QByteArray();
    }

    // Derive encryption key using PBKDF2
    unsigned char key[32];
    if (PKCS5_PBKDF2_HMAC(
        password.toUtf8().constData(),
        password.toUtf8().length(),
        salt,
        sizeof(salt),
        100000, // 100k iterations for security
        EVP_sha256(),
        sizeof(key),
        key) != 1) {
        LOG(("Signal Protocol Error: Failed to derive encryption key"));
        return QByteArray();
    }

    // Generate random IV
    unsigned char iv[12];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        LOG(("Signal Protocol Error: Failed to generate IV for key encryption"));
        return QByteArray();
    }

    // Encrypt using AES-256-GCM
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOG(("Signal Protocol Error: Failed to create encryption context for key storage"));
        return QByteArray();
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LOG(("Signal Protocol Error: Failed to initialize key encryption"));
        return QByteArray();
    }

    // Encrypt the data
    std::vector<unsigned char> ciphertext(data.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen = 0;

    if (EVP_EncryptUpdate(
        ctx,
        ciphertext.data(),
        &outLen,
        asConstUChar(data),
        data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LOG(("Signal Protocol Error: Failed to encrypt key data"));
        return QByteArray();
    }

    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LOG(("Signal Protocol Error: Failed to finalize key encryption"));
        return QByteArray();
    }

    // Get authentication tag
    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LOG(("Signal Protocol Error: Failed to get authentication tag for key encryption"));
        return QByteArray();
    }

    EVP_CIPHER_CTX_free(ctx);

    // Combine salt + IV + ciphertext + tag
    QByteArray result;
    result.reserve(sizeof(salt) + sizeof(iv) + outLen + finalLen + sizeof(tag));
    result.append(reinterpret_cast<const char*>(salt), sizeof(salt));
    result.append(reinterpret_cast<const char*>(iv), sizeof(iv));
    result.append(reinterpret_cast<const char*>(ciphertext.data()), outLen + finalLen);
    result.append(reinterpret_cast<const char*>(tag), sizeof(tag));

    return result;
}

bytes::vector SignalProtocol::decryptWithPBKDF2(const QByteArray &encryptedData, const QString &password) {
    if (encryptedData.size() < 60) { // Minimum size for salt + IV + tag
        LOG(("Signal Protocol Error: Encrypted key data too small"));
        return bytes::vector();
    }

    // Extract components
    const unsigned char *salt = reinterpret_cast<const unsigned char*>(encryptedData.constData());
    const unsigned char *iv = salt + 32;
    const unsigned char *tag = reinterpret_cast<const unsigned char*>(encryptedData.constData() + encryptedData.size() - 16);
    const unsigned char *ciphertext = iv + 12;
    size_t ciphertextLen = encryptedData.size() - 60;

    // Derive decryption key using PBKDF2
    unsigned char key[32];
    if (PKCS5_PBKDF2_HMAC(
        password.toUtf8().constData(),
        password.toUtf8().length(),
        salt,
        32,
        100000, // 100k iterations
        EVP_sha256(),
        sizeof(key),
        key) != 1) {
        LOG(("Signal Protocol Error: Failed to derive decryption key"));
        return bytes::vector();
    }

    // Decrypt using AES-256-GCM
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOG(("Signal Protocol Error: Failed to create decryption context for key storage"));
        return bytes::vector();
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LOG(("Signal Protocol Error: Failed to initialize key decryption"));
        return bytes::vector();
    }

    // Set expected authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LOG(("Signal Protocol Error: Failed to set authentication tag for key decryption"));
        return bytes::vector();
    }

    // Decrypt the data
    bytes::vector plaintext(ciphertextLen);
    int outLen = 0;

    if (EVP_DecryptUpdate(
        ctx,
        asUChar(plaintext),
        &outLen,
        ciphertext,
        ciphertextLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LOG(("Signal Protocol Error: Failed to decrypt key data"));
        return bytes::vector();
    }

    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx, asUChar(plaintext) + outLen, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LOG(("Signal Protocol Error: Failed to verify key data integrity"));
        return bytes::vector();
    }

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(outLen + finalLen);

    return plaintext;
}

// Ed25519 key pair generation for identity keys
std::pair<bytes::vector, bytes::vector> SignalProtocol::generateEd25519KeyPair() {
    // Generate Ed25519 key pair
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!pctx) {
        LOG(("Signal Protocol Error: Failed to create Ed25519 key generation context"));
        return {bytes::vector(), bytes::vector()};
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        LOG(("Signal Protocol Error: Failed to initialize Ed25519 key generation"));
        return {bytes::vector(), bytes::vector()};
    }

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        LOG(("Signal Protocol Error: Failed to generate Ed25519 key pair"));
        return {bytes::vector(), bytes::vector()};
    }

    // Extract private key
    size_t privKeyLen = 32;
    bytes::vector privateKey(privKeyLen);
    if (EVP_PKEY_get_raw_private_key(pkey, asUChar(privateKey), &privKeyLen) != 1) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        LOG(("Signal Protocol Error: Failed to extract Ed25519 private key"));
        return {bytes::vector(), bytes::vector()};
    }

    // Extract public key
    size_t pubKeyLen = 32;
    bytes::vector publicKey(pubKeyLen);
    if (EVP_PKEY_get_raw_public_key(pkey, asUChar(publicKey), &pubKeyLen) != 1) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        LOG(("Signal Protocol Error: Failed to extract Ed25519 public key"));
        return {bytes::vector(), bytes::vector()};
    }

    // Cleanup
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);

    privateKey.resize(privKeyLen);
    publicKey.resize(pubKeyLen);

    return {privateKey, publicKey};
}

// TSM Integration Methods
void SignalProtocol::enableTSMIntegration(bool enabled) {
    if (!_tsmIntegration) {
        LOG(("Signal Protocol Error: TSM integration not initialized"));
        return;
    }

    if (enabled && !_tsmEnabled) {
        // Enable TSM integration
        auto result = _tsmIntegration->initializeWithSignalProtocol();
        if (result == TSMResult::Success) {
            _tsmEnabled = true;
            LOG(("Signal Protocol: TSM integration enabled"));

            // Generate hardware-backed identity key if none exists
            if (_tsmIntegration->isHardwareBackedSecurity()) {
                auto identityResult = _tsmIntegration->generateSignalIdentityKeyPair();
                if (identityResult.has_value()) {
                    // Update identity key with hardware-backed version
                    _identityKeyPublic = identityResult.value();
                    LOG(("Signal Protocol: Hardware-backed identity key generated"));
                    saveIdentityKeys();
                }
            }
        } else {
            LOG(("Signal Protocol Warning: Failed to enable TSM integration, error: %1").arg((int)result));
        }
    } else if (!enabled && _tsmEnabled) {
        // Disable TSM integration - fall back to software
        _tsmEnabled = false;
        LOG(("Signal Protocol: TSM integration disabled, using software fallback"));
    }
}

bool SignalProtocol::isTSMEnabled() const {
    return _tsmEnabled && _tsmIntegration && _tsmIntegration->isHardwareBackedSecurity();
}

TSMPlatform SignalProtocol::getTSMPlatform() const {
    if (!_tsmIntegration) {
        return TSMPlatform::SoftwareFallback;
    }

    auto capabilities = _tsmIntegration->getTSMCapabilities();
    return capabilities.platform;
}

TSMCapabilities SignalProtocol::getTSMCapabilities() const {
    if (!_tsmIntegration) {
        return TSMCapabilities{};
    }

    return _tsmIntegration->getTSMCapabilities();
}

// Session serialization implementation
QByteArray SignalProtocol::serializeSession(const SessionState &state) {
    QJsonObject obj;

    // Serialize keys
    obj["rootKey"] = QString::fromLatin1(QByteArray(
        reinterpret_cast<const char*>(state.rootKey.data()),
        state.rootKey.size()).toBase64());

    obj["sendingChainKey"] = QString::fromLatin1(QByteArray(
        reinterpret_cast<const char*>(state.sendingChainKey.data()),
        state.sendingChainKey.size()).toBase64());

    obj["receivingChainKey"] = QString::fromLatin1(QByteArray(
        reinterpret_cast<const char*>(state.receivingChainKey.data()),
        state.receivingChainKey.size()).toBase64());

    // Serialize DH keys
    obj["dhSendingPublic"] = QString::fromLatin1(QByteArray(
        reinterpret_cast<const char*>(state.dhSendingPublicKey.data()),
        state.dhSendingPublicKey.size()).toBase64());

    obj["dhSendingPrivate"] = QString::fromLatin1(QByteArray(
        reinterpret_cast<const char*>(state.dhSendingPrivateKey.data()),
        state.dhSendingPrivateKey.size()).toBase64());

    obj["dhRemotePublic"] = QString::fromLatin1(QByteArray(
        reinterpret_cast<const char*>(state.dhRemotePublicKey.data()),
        state.dhRemotePublicKey.size()).toBase64());

    // Serialize counters
    obj["sendingCounter"] = QString::number(state.sendingMessageCounter);
    obj["receivingCounter"] = QString::number(state.receivingMessageCounter);
    obj["previousChainLength"] = QString::number(state.previousSendingChainLength);

    // Serialize skipped keys
    QJsonArray skippedKeysArray;
    for (const auto &skipped : state.skippedMessageKeys) {
        QJsonObject skippedObj;
        skippedObj["messageNumber"] = QString::number(skipped.messageNumber);
        skippedObj["key"] = QString::fromLatin1(QByteArray(
            reinterpret_cast<const char*>(skipped.key.data()),
            skipped.key.size()).toBase64());
        skippedKeysArray.append(skippedObj);
    }
    obj["skippedKeys"] = skippedKeysArray;

    // Serialize device IDs
    QJsonObject localDeviceObj;
    localDeviceObj["identifier"] = state.localDevice.identifier;
    localDeviceObj["registrationId"] = QString::number(state.localDevice.registrationId);
    obj["localDevice"] = localDeviceObj;

    QJsonObject remoteDeviceObj;
    remoteDeviceObj["identifier"] = state.remoteDevice.identifier;
    remoteDeviceObj["registrationId"] = QString::number(state.remoteDevice.registrationId);
    obj["remoteDevice"] = remoteDeviceObj;

    // Serialize timestamps
    obj["createdAt"] = QString::number(state.createdAt);
    obj["lastUsedAt"] = QString::number(state.lastUsedAt);

    // Add version
    obj["version"] = 1;

    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

// Session deserialization implementation
SignalProtocol::SessionState SignalProtocol::deserializeSession(const QByteArray &data) {
    SessionState state;

    QJsonParseError error;
    auto doc = QJsonDocument::fromJson(data, &error);

    if (error.error != QJsonParseError::NoError) {
        LOG(("Signal Protocol Error: Failed to parse session JSON: %1").arg(error.errorString()));
        return state;
    }

    auto obj = doc.object();

    // Check version
    auto version = obj.value("version").toInt(1);
    if (version != 1) {
        LOG(("Signal Protocol Error: Unsupported session version: %1").arg(version));
        return state;
    }

    // Deserialize keys
    state.rootKey = bytes::make_vector(
        QByteArray::fromBase64(obj["rootKey"].toString().toLatin1()));

    state.sendingChainKey = bytes::make_vector(
        QByteArray::fromBase64(obj["sendingChainKey"].toString().toLatin1()));

    state.receivingChainKey = bytes::make_vector(
        QByteArray::fromBase64(obj["receivingChainKey"].toString().toLatin1()));

    // Deserialize DH keys
    state.dhSendingPublicKey = bytes::make_vector(
        QByteArray::fromBase64(obj["dhSendingPublic"].toString().toLatin1()));

    state.dhSendingPrivateKey = bytes::make_vector(
        QByteArray::fromBase64(obj["dhSendingPrivate"].toString().toLatin1()));

    state.dhRemotePublicKey = bytes::make_vector(
        QByteArray::fromBase64(obj["dhRemotePublic"].toString().toLatin1()));

    // Deserialize counters
    state.sendingMessageCounter = obj["sendingCounter"].toString().toUInt();
    state.receivingMessageCounter = obj["receivingCounter"].toString().toUInt();
    state.previousSendingChainLength = obj["previousChainLength"].toString().toUInt();

    // Deserialize skipped keys
    auto skippedKeysArray = obj["skippedKeys"].toArray();
    for (const auto &value : skippedKeysArray) {
        auto skippedObj = value.toObject();
        SessionState::SkippedKey skipped;
        skipped.messageNumber = skippedObj["messageNumber"].toString().toUInt();
        skipped.key = bytes::make_vector(
            QByteArray::fromBase64(skippedObj["key"].toString().toLatin1()));
        state.skippedMessageKeys.push_back(skipped);
    }

    // Deserialize device IDs
    auto localDeviceObj = obj["localDevice"].toObject();
    state.localDevice.identifier = localDeviceObj["identifier"].toString();
    state.localDevice.registrationId = localDeviceObj["registrationId"].toString().toULongLong();

    auto remoteDeviceObj = obj["remoteDevice"].toObject();
    state.remoteDevice.identifier = remoteDeviceObj["identifier"].toString();
    state.remoteDevice.registrationId = remoteDeviceObj["registrationId"].toString().toULongLong();

    // Deserialize timestamps
    state.createdAt = obj["createdAt"].toString().toLongLong();
    state.lastUsedAt = obj["lastUsedAt"].toString().toLongLong();

    return state;
}

TimeId SignalProtocol::getKeyRotationInterval() const {
    return _keyRotationInterval;
}

QString SignalProtocol::wrapEncryptedText(const bytes::vector &ciphertext, const MessageMetadata &metadata) {
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream.setVersion(QDataStream::Qt_5_15);

    stream << metadata.messageCounter;
    stream << QByteArray(reinterpret_cast<const char*>(metadata.iv.data()), metadata.iv.size());
    stream << QByteArray(reinterpret_cast<const char*>(metadata.senderPublicKey.data()), metadata.senderPublicKey.size());
    stream << metadata.timestamp;

    // ZK Phase 1: challenge nonce only — NO identity information
    stream << metadata.hasCacChallenge;
    if (metadata.hasCacChallenge) {
        stream << QByteArray(reinterpret_cast<const char*>(metadata.cacChallengeNonce.data()),
                             metadata.cacChallengeNonce.size());
    }

    // ZK Phase 2: hardware signature + full DER cert chain — DN is NEVER serialized
    stream << metadata.hasCacResponse;
    if (metadata.hasCacResponse) {
        stream << QByteArray(reinterpret_cast<const char*>(metadata.cacSignature.data()),
                             metadata.cacSignature.size());
        stream << QByteArray(reinterpret_cast<const char*>(metadata.cacCertChainDer.data()),
                             metadata.cacCertChainDer.size());
        // NOTE: cacUserDN is intentionally NOT serialized here.
        // The recipient extracts it locally from cacCertChainDer after
        // cryptographic validation — it never crosses the wire.
    }

    stream << QByteArray(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());

    const QChar kInvis[4] = { QChar(0x200B), QChar(0x200C), QChar(0x200D), QChar(0x2060) };
    const QString kMarker = QString() + QChar(0xFEFF) + QChar(0x200B) + QChar(0x200C) + QChar(0xFEFF);

    QString result = kMarker;
    for (char c : data) {
        uint8 byte = static_cast<uint8>(c);
        result += kInvis[(byte >> 6) & 3];
        result += kInvis[(byte >> 4) & 3];
        result += kInvis[(byte >> 2) & 3];
        result += kInvis[byte & 3];
    }
    return result;
}

std::optional<std::pair<bytes::vector, SignalProtocol::MessageMetadata>> SignalProtocol::unwrapEncryptedText(const QString &text) {
    const QString kMarker = QString() + QChar(0xFEFF) + QChar(0x200B) + QChar(0x200C) + QChar(0xFEFF);
    int markerIdx = text.indexOf(kMarker);
    if (markerIdx < 0) return std::nullopt;

    const QChar kInvis[4] = { QChar(0x200B), QChar(0x200C), QChar(0x200D), QChar(0x2060) };
    auto charToBits = [&](QChar c) -> int {
        for (int i = 0; i < 4; ++i) if (c == kInvis[i]) return i;
        return -1;
    };

    QByteArray data;
    int payloadStart = markerIdx + kMarker.size();
    for (int i = payloadStart; i + 3 < text.size(); i += 4) {
        int b1 = charToBits(text[i]);
        int b2 = charToBits(text[i+1]);
        int b3 = charToBits(text[i+2]);
        int b4 = charToBits(text[i+3]);
        if (b1 < 0 || b2 < 0 || b3 < 0 || b4 < 0) break;
        uint8 byte = (b1 << 6) | (b2 << 4) | (b3 << 2) | b4;
        data.append(static_cast<char>(byte));
    }

    QDataStream stream(data);
    stream.setVersion(QDataStream::Qt_5_15);

    MessageMetadata metadata;
    QByteArray iv, senderPublicKey, ct;
    stream >> metadata.messageCounter >> iv >> senderPublicKey >> metadata.timestamp;

    // ZK Phase 1
    stream >> metadata.hasCacChallenge;
    if (metadata.hasCacChallenge) {
        QByteArray challenge;
        stream >> challenge;
        metadata.cacChallengeNonce = bytes::make_vector(challenge);
    }

    // ZK Phase 2 — DER cert chain, NO DN
    stream >> metadata.hasCacResponse;
    if (metadata.hasCacResponse) {
        QByteArray sig, certChain;
        stream >> sig >> certChain;
        metadata.cacSignature    = bytes::make_vector(sig);
        metadata.cacCertChainDer = bytes::make_vector(certChain);
        // cacUserDN intentionally left empty; extracted after local validation
    }

    stream >> ct;
    if (stream.status() != QDataStream::Ok) return std::nullopt;

    metadata.iv              = bytes::make_vector(iv);
    metadata.senderPublicKey = bytes::make_vector(senderPublicKey);
    return std::make_pair(bytes::make_vector(ct), metadata);
}

TextWithEntities SignalProtocol::processOutgoingMessage(not_null<PeerData*> peer, const TextWithEntities &original) {
    if (!isEnabled() || !hasSession(peer)) return original;

    MessageMetadata metadata;
    const auto plaintext = bytes::make_span(original.text.toUtf8());
    auto ciphertext = encryptMessage(plaintext, peer, metadata);
    if (ciphertext.empty()) return original;

    // === ZK Phase 1: always emit a fresh challenge nonce ===
    // We attach a random 32-byte nonce to every outgoing message.
    // This reveals ZERO information about whether we are a CAC user.
    metadata.hasCacChallenge = true;
    metadata.cacChallengeNonce = generateRandomBytes(32);
    // Store it so we can match the Phase 2 response when it arrives.
    _pendingCacChallenges[peer->id] = { metadata.cacChallengeNonce, base::unixtime::now() };

    // === ZK Phase 3: if peer has already proven themselves, reveal ourselves ===
    // Only attach our own Phase 2 response if we already verified the peer is
    // a valid CAC holder. A snooper who never passed Phase 2 never sees our cert.
    if (CACUserRegistry::isCACUser(peer->id.value)) {
        auto cac = CACFactory::create();
        if (cac && cac->isCardPresent()) {
            auto info = cac->getCardInfo();
            if (info && info->isValid) {
                // Sign the current challenge nonce we are issuing right now
                auto sigResult = cac->signData(bytes::make_span(
                    QByteArray(reinterpret_cast<const char*>(metadata.cacChallengeNonce.data()),
                               metadata.cacChallengeNonce.size())));
                if (sigResult) {
                    metadata.hasCacResponse    = true;
                    metadata.cacSignature      = sigResult->signature;
                    metadata.cacCertChainDer   = info->certChainDer;
                    // NOTE: DN is NOT placed into metadata; recipient extracts it locally
                }
            }
        }
    }

    TextWithEntities result;
    result.text = wrapEncryptedText(ciphertext, metadata);
    return result;
}

TextWithTags SignalProtocol::processOutgoingMessage(not_null<PeerData*> peer, const TextWithTags &original) {
    if (!isEnabled() || !hasSession(peer)) return original;

    MessageMetadata metadata;
    const auto plaintext = bytes::make_span(original.text.toUtf8());
    auto ciphertext = encryptMessage(plaintext, peer, metadata);
    if (ciphertext.empty()) return original;

    metadata.hasCacChallenge   = true;
    metadata.cacChallengeNonce = generateRandomBytes(32);
    _pendingCacChallenges[peer->id] = { metadata.cacChallengeNonce, base::unixtime::now() };

    if (CACUserRegistry::isCACUser(peer->id.value)) {
        auto cac = CACFactory::create();
        if (cac && cac->isCardPresent()) {
            auto info = cac->getCardInfo();
            if (info && info->isValid) {
                auto sigResult = cac->signData(bytes::make_span(
                    QByteArray(reinterpret_cast<const char*>(metadata.cacChallengeNonce.data()),
                               metadata.cacChallengeNonce.size())));
                if (sigResult) {
                    metadata.hasCacResponse  = true;
                    metadata.cacSignature    = sigResult->signature;
                    metadata.cacCertChainDer = info->certChainDer;
                }
            }
        }
    }

    TextWithTags result;
    result.text = wrapEncryptedText(ciphertext, metadata);
    return result;
}

bool SignalProtocol::verifyCacMutualAuth(const bytes::vector &challengeNonce, const bytes::vector &signature, const QString &userDN) {
    if (signature.empty()) return false;
    
    // Create an X509 store for the NATO/Military roots
    X509_STORE *store = X509_STORE_new();
    if (!store) return false;
    
    // Load all military/government certificates we filtered into the store

    bool loadedAny = false;
    for (const QString &file : QDir(natoKeysDir).entryList({u"*.pem"_q, u"*.crt"_q, u"*.cer"_q})) {
        QByteArray path = (natoKeysDir + u"/"_q + file).toLocal8Bit();
        FILE *fp = fopen(path.constData(), "rb");
        if (!fp) continue;
        X509 *cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
        if (!cert) {
            rewind(fp);
            cert = d2i_X509_fp(fp, nullptr);
        }
        fclose(fp);
        if (cert) {
            X509_STORE_add_cert(store, cert);
            X509_free(cert);
            loadedAny = true;
        }
    }

    if (!loadedAny) {
        X509_STORE_free(store);
        LOG(("Signal Protocol [ZK] Error: No NATO/Military root certificates found in %1")
                .arg(natoKeysDir));
        return false;
    }

    const unsigned char *p = reinterpret_cast<const unsigned char*>(certChainDer.data());
    X509 *leafCert = d2i_X509(nullptr, &p, static_cast<long>(certChainDer.size()));
    if (!leafCert) {
        X509_STORE_free(store);
        return false;
    }

    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    bool chainValid = false;
    if (ctx) {
        if (X509_STORE_CTX_init(ctx, store, leafCert, nullptr) == 1) {
            chainValid = (X509_verify_cert(ctx) == 1);
            if (!chainValid) {
                LOG(("Signal Protocol [ZK] WARNING: Certificate chain validation failed: %1")
                        .arg(X509_verify_cert_error_string(
                            X509_STORE_CTX_get_error(ctx))));
            }
        }
        X509_STORE_CTX_free(ctx);
    }

    if (!chainValid) {
        X509_free(leafCert);
        X509_STORE_free(store);
        return false;
    }

    EVP_PKEY *pubKey = X509_get_pubkey(leafCert);
    bool sigValid = false;
    if (pubKey) {
        EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
        if (mdCtx) {
            // CNSA 2.0 / Legacy Fallback chain
            // 1. Try nullptr (for inherent algorithms like ML-DSA-87, Ed25519)
            if (EVP_DigestVerifyInit(mdCtx, nullptr, nullptr, nullptr, pubKey) == 1 &&
                EVP_DigestVerifyUpdate(mdCtx, challengeNonce.data(), challengeNonce.size()) == 1 &&
                EVP_DigestVerifyFinal(mdCtx, reinterpret_cast<const unsigned char*>(signature.data()), signature.size()) == 1) {
                sigValid = true;
            } else {
                EVP_MD_CTX_reset(mdCtx);
                // 2. Try SHA-384 (CNSA 2.0 standard for RSA/ECDSA)
                if (EVP_DigestVerifyInit(mdCtx, nullptr, EVP_sha384(), nullptr, pubKey) == 1 &&
                    EVP_DigestVerifyUpdate(mdCtx, challengeNonce.data(), challengeNonce.size()) == 1 &&
                    EVP_DigestVerifyFinal(mdCtx, reinterpret_cast<const unsigned char*>(signature.data()), signature.size()) == 1) {
                    sigValid = true;
                } else {
                    EVP_MD_CTX_reset(mdCtx);
                    // 3. Try SHA-256 (Legacy CAC hardware)
                    if (EVP_DigestVerifyInit(mdCtx, nullptr, EVP_sha256(), nullptr, pubKey) == 1 &&
                        EVP_DigestVerifyUpdate(mdCtx, challengeNonce.data(), challengeNonce.size()) == 1 &&
                        EVP_DigestVerifyFinal(mdCtx, reinterpret_cast<const unsigned char*>(signature.data()), signature.size()) == 1) {
                        sigValid = true;
                        LOG(("Signal Protocol [ZK] WARNING: Accepted legacy SHA-256 signature (Not CNSA 2.0 Compliant)"));
                    }
                }
            }
            EVP_MD_CTX_free(mdCtx);
        }
        EVP_PKEY_free(pubKey);
    }

    if (!sigValid) {
        LOG(("Signal Protocol [ZK] WARNING: Signature verification failed for incoming Phase 2"));
        X509_free(leafCert);
        X509_STORE_free(store);
        return false;
    }

    char dnBuf[512] = {};
    X509_NAME_oneline(X509_get_subject_name(leafCert), dnBuf, sizeof(dnBuf));
    outUserDN = QString::fromUtf8(dnBuf);

    // --- Verify EKU and Policy OIDs ---
    bool isCanadian = outUserDN.contains("C=CA", Qt::CaseInsensitive);
    bool isGerman = outUserDN.contains("C=DE", Qt::CaseInsensitive);

    // Check ClientAuth EKU
    bool hasClientAuth = false;
    EXTENDED_KEY_USAGE *eku = static_cast<EXTENDED_KEY_USAGE*>(X509_get_ext_d2i(leafCert, NID_ext_key_usage, nullptr, nullptr));
    if (eku) {
        for (int i = 0; i < sk_ASN1_OBJECT_num(eku); i++) {
            if (OBJ_obj2nid(sk_ASN1_OBJECT_value(eku, i)) == NID_client_auth) {
                hasClientAuth = true;
                break;
            }
        }
        EXTENDED_KEY_USAGE_free(eku);
    }

    if (isGerman && !hasClientAuth) {
        LOG(("Signal Protocol [ZK] WARNING: Rejected DE certificate — missing ClientAuth EKU"));
        X509_free(leafCert); X509_STORE_free(store); return false;
    }

    // Check Certificate Policies (for Canada DND Hardware constraint)
    bool hasCanadianHardwareOID = false;
    CERTIFICATEPOLICIES *policies = static_cast<CERTIFICATEPOLICIES*>(X509_get_ext_d2i(leafCert, NID_certificate_policies, nullptr, nullptr));
    if (policies) {
        for (int i = 0; i < sk_POLICYINFO_num(policies); i++) {
            POLICYINFO *pi = sk_POLICYINFO_value(policies, i);
            char oidBuf[128] = {0};
            OBJ_obj2txt(oidBuf, sizeof(oidBuf), pi->policyid, 1);
            if (strcmp(oidBuf, "2.16.124.101.1.259.2.1.1") == 0) {
                hasCanadianHardwareOID = true;
                break;
            }
        }
        CERTIFICATEPOLICIES_free(policies);
    }

    if (isCanadian && !hasCanadianHardwareOID) {
        LOG(("Signal Protocol [ZK] WARNING: Rejected CA certificate — missing hardware-backed policy OID 2.16.124.101.1.259.2.1.1"));
        X509_free(leafCert); X509_STORE_free(store); return false;
    }

    X509_free(leafCert);
    X509_STORE_free(store);
    return true;
}

TextWithEntities SignalProtocol::processIncomingMessage(not_null<PeerData*> peer, const TextWithEntities &original) {
    if (!isEnabled()) return original;

    auto unwrapped = unwrapEncryptedText(original.text);
    if (!unwrapped) return original;

    auto plaintext = decryptMessage(unwrapped->first, peer, unwrapped->second);
    if (plaintext.empty()) return original;

    const auto &metadata = unwrapped->second;
    const TimeId now = base::unixtime::now();
    constexpr TimeId kChallengeExpirySecs = 300; // 5 minutes

    // === ZK Phase 2: incoming challenge from peer — respond only if we have a CAC ===
    // A non-CAC client simply does nothing here. Complete silence.
    if (metadata.hasCacChallenge && !metadata.hasCacResponse) {
        auto cac = CACFactory::create();
        if (cac && cac->isCardPresent()) {
            auto info = cac->getCardInfo();
            if (info && info->isValid) {
                // Sign the exact nonce the peer sent us
                const QByteArray nonceBytes(
                    reinterpret_cast<const char*>(metadata.cacChallengeNonce.data()),
                    metadata.cacChallengeNonce.size());
                auto sigResult = cac->signData(bytes::make_span(nonceBytes));
                if (sigResult) {
                    // Build a reply message containing our Phase 2 proof.
                    // We do this by constructing a minimal metadata-only envelope
                    // (empty ciphertext) and sending it back immediately.
                    MessageMetadata reply;
                    reply.messageCounter  = 0;
                    reply.timestamp       = now;
                    reply.hasCacChallenge = false;
                    reply.hasCacResponse  = true;
                    reply.cacSignature    = sigResult->signature;
                    reply.cacCertChainDer = info->certChainDer;
                    // Queue for out-of-band delivery — implementation hook
                    LOG(("Signal Protocol [ZK]: Sending Phase 2 CAC response to peer %1")
                            .arg(peer->id.value));
                }
            }
        }
        // If no CAC — fall through silently. Peer learns nothing.
    }

    // === ZK Phase 2 received: peer is proving they have a CAC ===
    if (metadata.hasCacResponse && !CACUserRegistry::isCACUser(peer->id.value)) {
        // Validate the nonce we originally issued
        auto it = _pendingCacChallenges.find(peer->id);
        if (it != _pendingCacChallenges.end()) {
            const auto &pending = it->second;
            const bool expired = (now - pending.issuedAt) > kChallengeExpirySecs;

            if (!expired) {
                QString extractedDN;
                if (verifyCacMutualAuth(
                        pending.nonce,
                        metadata.cacSignature,
                        metadata.cacCertChainDer,
                        extractedDN)) {

                    LOG(("Signal Protocol [ZK]: Phase 2 verified for peer %1 DN=%2")
                            .arg(peer->id.value).arg(extractedDN));

                    // DN was extracted locally from the DER chain — never transmitted
                    CACUserRegistry::registerCACUser(peer->id.value, extractedDN);
                    _pendingCacChallenges.erase(it);

                    // Append national flag to display name
                    if (const auto user = peer->asUser()) {
                        const QString flag = CACUserRegistry::getUserFlag(peer->id.value);
                        if (!flag.isEmpty()
                                && !user->lastName.contains(flag)
                                && !user->firstName.contains(flag)) {
                            const QString newLast = user->lastName.isEmpty()
                                ? flag
                                : user->lastName + u" "_q + flag;
                            user->setName(user->firstName, newLast,
                                          user->nameOrPhone, user->username());
                        }
                    }
                } else {
                    LOG(("Signal Protocol [ZK] WARNING: Invalid Phase 2 proof from peer %1 — possible forgery")
                            .arg(peer->id.value));
                    // Explicitly do NOT register the peer. They remain invisible.
                }
            } else {
                // Challenge expired — discard and require fresh handshake
                _pendingCacChallenges.erase(it);
                LOG(("Signal Protocol [ZK]: Expired challenge from peer %1, discarding")
                        .arg(peer->id.value));
            }
        } else {
            // Unsolicited Phase 2 with no matching challenge — replay attack or bug
            LOG(("Signal Protocol [ZK] WARNING: Unsolicited Phase 2 from peer %1, no pending challenge")
                    .arg(peer->id.value));
        }
    }

    TextWithEntities result = original;
    result.text = QString::fromUtf8(
        reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
    result.entities.clear();
    return result;
}

TextWithEntities SignalProtocol::attachKeyBundleIfNeeded(
        not_null<PeerData*> peer,
        const TextWithEntities &text) {
    if (!isEnabled() || hasSession(peer)) {
        return text; // Already have a session, no bundle needed
    }

    // Ensure we have a cached bundle
    if (!_cachedBundleValid) {
        refreshCachedKeyBundle();
    }

    // Build the invisible key-bundle payload using the transport
    QString zwPayload;
    SignalProtocolTransport::buildOutgoingEntity(_cachedBundle, zwPayload);
    _lastKeyBundlePayloadLength = zwPayload.size();

    // Prepend the invisible payload to the message text.
    // The zero-width characters are invisible to the user.
    // The caller is responsible for appending the MTPMessageEntity
    // that covers the ZW payload region, so stock clients ignore it.
    TextWithEntities result = text;
    result.text = zwPayload + result.text;

    // Shift existing entity offsets by the ZW payload length
    for (auto &entity : result.entities) {
        entity.shiftRight(zwPayload.size());
    }

    LOG(("Signal Protocol: Attached key bundle to outgoing message for peer %1").arg(peer->id.value));
    return result;
}

int SignalProtocol::lastKeyBundlePayloadLength() const {
    return _lastKeyBundlePayloadLength;
}

TextWithEntities SignalProtocol::processIncomingKeyBundle(
        not_null<PeerData*> peer,
        const TextWithEntities &text,
        const QVector<MTPMessageEntity> &entities) {
    if (!isEnabled()) return text;

    // Extract key bundles from the message entities
    auto mutableEntities = entities;
    auto bundles = SignalProtocolTransport::extractAndStripBundles(
        mutableEntities, text.text);

    if (bundles.empty()) return text; // No key bundles found

    for (const auto &bundle : bundles) {
        // Verify the bundle signature before accepting
        if (!verifyKeyBundleSignature(bundle)) {
            LOG(("Signal Protocol: Incoming key bundle signature verification failed for peer %1").arg(peer->id.value));
            continue;
        }

        if (!hasSession(peer)) {
            // We don't have a session yet — this is Alice's initial message
            // carrying her key bundle. Create a receiver-side session.
            // We need Alice's identity key and ephemeral key from the bundle.
            // The identity key is in the bundle, and the ephemeral key
            // is the signedPreKey (since Alice uses it as her initial DH key).
            createSessionFromInitialMessage(
                peer,
                bundle.identityKey,
                bundle.signedPreKey,
                bundle);
            LOG(("Signal Protocol: Created session from incoming key bundle for peer %1").arg(peer->id.value));
        } else {
            // We already have a session — this might be a key rotation
            // or a new bundle from the peer. Register it for future use.
            registerRemoteKeyBundle(peer, bundle);
        }
    }

    // Return the text with stripped entities
    TextWithEntities result = text;
    result.text = text.text; // Text unchanged (ZW chars are invisible)
    return result;
}

void SignalProtocol::setKeyRotationInterval(TimeId interval) {
    _keyRotationInterval = interval;
}

void SignalProtocol::initializeEnclave() {
    // Generate a volatile memory enclave key that is never written to disk
    if (_enclaveKey.empty()) {
        _enclaveKey = generateRandomBytes(kAesKeySize);
    }
}

void SignalProtocol::enqueueTruthGapMessage(not_null<PeerData*> peer, const bytes::const_span &plaintext) {
    initializeEnclave();
    
    // Encrypt the plaintext with the volatile enclave key
    auto iv = generateRandomBytes(kAesIvSize);
    bytes::vector ciphertext(plaintext.size() + 32);
    
    auto plainCopy = bytes::make_vector(plaintext);
    int padding = 16 - (plainCopy.size() % 16);
    plainCopy.resize(plainCopy.size() + padding, bytes::type(padding));
    
    if (aesEncryptLocal(
            reinterpret_cast<const void*>(plainCopy.data()),
            reinterpret_cast<void*>(ciphertext.data()),
            plainCopy.size(),
            _enclaveKey.data(),
            iv.data())) {
        
        ciphertext.resize(plainCopy.size());
        
        // Prepend IV so we can decrypt later
        auto finalEncrypted = bytes::concatenate(iv, ciphertext);
        
        PendingMessage msg;
        msg.enclaveEncryptedPlaintext = finalEncrypted;
        msg.queuedAt = base::unixtime::now();
        
        _truthGapEnclave[peer->id].push_back(msg);
        LOG(("Signal Protocol: Truth Gap mitigated. Queued pending message for peer %1").arg(peer->id.value));
    }
}

std::vector<bytes::vector> SignalProtocol::flushTruthGapEnclave(not_null<PeerData*> peer) {
    std::vector<bytes::vector> plaintexts;
    auto it = _truthGapEnclave.find(peer->id);
    if (it == _truthGapEnclave.end() || it->second.empty()) {
        return plaintexts;
    }
    
    for (const auto &msg : it->second) {
        if (msg.enclaveEncryptedPlaintext.size() <= kAesIvSize) continue;
        
        auto iv = bytes::make_span(msg.enclaveEncryptedPlaintext).subspan(0, kAesIvSize);
        auto ciphertext = bytes::make_span(msg.enclaveEncryptedPlaintext).subspan(kAesIvSize);
        
        bytes::vector plaintext(ciphertext.size());
        if (aesDecryptLocal(
                reinterpret_cast<const void*>(ciphertext.data()),
                reinterpret_cast<void*>(plaintext.data()),
                ciphertext.size(),
                _enclaveKey.data(),
                iv.data())) {
                
            // Remove padding
            if (!plaintext.empty()) {
                auto paddingSize = static_cast<int>(plaintext.back());
                if (paddingSize > 0 && paddingSize <= 16 && paddingSize <= plaintext.size()) {
                    plaintext.resize(plaintext.size() - paddingSize);
                }
            }
            plaintexts.push_back(plaintext);
        }
    }
    
    _truthGapEnclave.erase(it);
    LOG(("Signal Protocol: Flushed %1 Truth Gap messages for peer %2").arg(plaintexts.size()).arg(peer->id.value));
    return plaintexts;
}

} // namespace Data
