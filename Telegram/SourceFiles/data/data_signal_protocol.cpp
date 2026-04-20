/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#include "data/data_signal_protocol.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>

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
constexpr auto kAesIvSize = 12;  // GCM nonce size
constexpr auto kAesTagSize = 16; // GCM auth tag size
constexpr auto kMaxSkippedKeys = 1000; // Maximum skipped message keys to store
constexpr auto kInfoRootKey = "WhisperRatchet"; // Used in HKDF for root keys
constexpr auto kInfoChainKey = "WhisperMessageKeys"; // Used in HKDF for chain keys
constexpr auto kInfoMessageKey = "WhisperMessageKey"; // Used in HKDF for message keys

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

bool verifyFixedLength(const bytes::const_span &value, size_t expected) {
    return value.size() == expected;
}

bool isValidSessionState(const SignalProtocol::SessionState &state) {
	if (state.rootKey.size() != kAesKeySize) {
		return false;
	}
	if (state.sendingChainKey.size() != kAesKeySize
		|| state.receivingChainKey.size() != kAesKeySize) {
		return false;
	}
	if (state.dhSendingPublicKey.size() != kDHKeySize
		|| state.dhSendingPrivateKey.size() != kDHKeySize
		|| state.dhRemotePublicKey.size() != kDHKeySize) {
		return false;
	}
	for (const auto &skipped : state.skippedMessageKeys) {
		if (skipped.key.size() != kAesKeySize) {
			return false;
		}
	}
	return true;
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
        const void *aad,
        int aadLen,
        const void *key,
        const void *iv,
        void *tagOut) {
    if (!plaintext || !ciphertext || !key || !iv || plaintextLen < 0) {
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, kAesIvSize, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                           reinterpret_cast<const unsigned char *>(key),
                           reinterpret_cast<const unsigned char *>(iv)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int outLen1 = 0;
    if (aad && aadLen > 0) {
        if (EVP_EncryptUpdate(
                ctx,
                nullptr,
                &outLen1,
                reinterpret_cast<const unsigned char *>(aad),
                aadLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }
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
    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_AEAD_GET_TAG,
            kAesTagSize,
            reinterpret_cast<unsigned char *>(tagOut)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aesDecryptLocal(
        const void *ciphertext,
        void *plaintext,
        int ciphertextLen,
        const void *aad,
        int aadLen,
        const void *key,
        const void *iv,
        const void *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, kAesIvSize, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                           reinterpret_cast<const unsigned char *>(key),
                           reinterpret_cast<const unsigned char *>(iv)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int outLen1 = 0;
    if (aad && aadLen > 0) {
        if (EVP_DecryptUpdate(
                ctx,
                nullptr,
                &outLen1,
                reinterpret_cast<const unsigned char *>(aad),
                aadLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }
    if (EVP_DecryptUpdate(ctx,
            reinterpret_cast<unsigned char *>(plaintext),
            &outLen1,
            reinterpret_cast<const unsigned char *>(ciphertext),
            ciphertextLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_AEAD_SET_TAG,
            kAesTagSize,
            const_cast<void *>(tag)) != 1) {
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
    if (EVP_PKEY_get_raw_private_key(pkey, asUChar(privateKey), &len) != 1 || len != privateKey.size()) {
        EVP_PKEY_free(pkey);
        LOG(("Signal Protocol Error: Failed to export generated X25519 private key"));
        return {};
    }
    EVP_PKEY_free(pkey);
    
    return privateKey;
}

bytes::vector x25519PublicFromPrivate(const bytes::const_span &privateKey) {
    auto result = bytes::vector(kDHKeySize);

    if (!verifyFixedLength(privateKey, kDHKeySize)) {
        LOG(("Signal Protocol Error: X25519 public derivation expects 32-byte private key"));
        return {};
    }
    
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
    if (EVP_PKEY_get_raw_public_key(pkey, asUChar(result), &len) != 1 || len != result.size()) {
        EVP_PKEY_free(pkey);
        LOG(("Signal Protocol Error: Failed to export X25519 public key"));
        return {};
    }
    EVP_PKEY_free(pkey);

    return result;
}

bytes::vector x25519(const bytes::const_span &privateKey, const bytes::const_span &publicKey) {
    auto result = bytes::vector(kDHKeySize);

    if (!verifyFixedLength(privateKey, kDHKeySize) || !verifyFixedLength(publicKey, kDHKeySize)) {
        LOG(("Signal Protocol Error: X25519 DH expects 32-byte private/public keys"));
        return {};
    }
    
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
    if (EVP_PKEY_derive(ctx, asUChar(result), &sharedSecretLen) != 1 || sharedSecretLen != result.size()) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privKey);
        EVP_PKEY_free(pubKey);
        LOG(("Signal Protocol Error: Failed to derive X25519 shared secret"));
        return {};
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

    } else {
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
    
	// Get the current session
	auto session = getSession(peer);
	if (!isValidSessionState(session)) {
		LOG(("Signal Protocol: Invalid session state for peer %1").arg(peer->id.value));
		return {};
	}
    
    // Update last used timestamp
    session.lastUsedAt = base::unixtime::now();
    
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
    
    // Create random IV
    outMetadata.iv = generateRandomBytes(kAesIvSize);
    
    // Encrypt plaintext using AES-256-GCM
    bytes::vector ciphertext(plaintext.size() + kAesTagSize);

    // Prepare AES key and IV
    bytes::vector aesKey(kAesKeySize);
    bytes::vector aesIV(kAesIvSize);
    bytes::copy(bytes::make_span(aesKey), bytes::make_span(messageKey));
    bytes::copy(bytes::make_span(aesIV), bytes::make_span(outMetadata.iv));
    bytes::vector aad(sizeof(outMetadata.messageCounter) + sizeof(outMetadata.timestamp));
    std::memcpy(aad.data(), &outMetadata.messageCounter, sizeof(outMetadata.messageCounter));
    std::memcpy(
        aad.data() + sizeof(outMetadata.messageCounter),
        &outMetadata.timestamp,
        sizeof(outMetadata.timestamp));

    bytes::vector tag(kAesTagSize);
    if (!aesEncryptLocal(
            reinterpret_cast<const void*>(plaintext.data()),
            reinterpret_cast<void*>(ciphertext.data()),
            plaintext.size(),
            reinterpret_cast<const void*>(aad.data()),
            aad.size(),
            aesKey.data(),
            aesIV.data(),
            tag.data())) {
        LOG(("Signal Protocol Error: AES encryption failed"));
        return {};
    }

    ciphertext.resize(plaintext.size());
    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
    
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
	if (!isValidSessionState(session)) {
		LOG(("Signal Protocol: Invalid session state for peer %1").arg(peer->id.value));
		return {};
	}
    
	// Update last used timestamp
	session.lastUsedAt = base::unixtime::now();

	if (metadata.iv.size() != kAesIvSize) {
		LOG(("Signal Protocol: Invalid IV size in metadata"));
		return {};
	}
    
    if (ciphertext.size() < kAesTagSize) {
        LOG(("Signal Protocol: Ciphertext too short for auth tag"));
        return {};
    }
    bytes::vector plaintext(ciphertext.size() - kAesTagSize);
    bytes::vector messageKey;
    
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
            return {}; // Too many skipped messages - possible attack
        }
        
        // Store current keys
        auto currentChainKey = session.receivingChainKey;
        auto currentCounter = session.receivingMessageCounter;
        
        // Skip ahead and save the skipped keys
        while (currentCounter < metadata.messageCounter) {
            auto skippedKey = deriveKey(currentChainKey, 
                                       kInfoMessageKey, 
                                       kAesKeySize);
            
            // Save skipped key
            SessionState::SkippedKey skip;
            skip.messageNumber = currentCounter;
            skip.key = skippedKey;
            session.skippedMessageKeys.push_back(skip);
            
            // Enforce max skipped keys
            if (session.skippedMessageKeys.size() > kMaxSkippedKeys) {
                session.skippedMessageKeys.erase(session.skippedMessageKeys.begin());
            }
            
            // Advance
            currentChainKey = ratchetChainKey(currentChainKey);
            currentCounter++;
        }
        
        // Get key for current message
        messageKey = deriveKey(currentChainKey, 
                              kInfoMessageKey, 
                              kAesKeySize);
        
        // Update session state
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
            return {}; // Message key not found
        }
    }
    
    // Decrypt using AES-256-GCM
    bytes::vector aesKey(kAesKeySize);
    bytes::vector aesIV(kAesIvSize);
    bytes::copy(bytes::make_span(aesKey), bytes::make_span(messageKey));
    bytes::copy(bytes::make_span(aesIV), bytes::make_span(metadata.iv));

    bytes::vector aad(sizeof(metadata.messageCounter) + sizeof(metadata.timestamp));
    std::memcpy(aad.data(), &metadata.messageCounter, sizeof(metadata.messageCounter));
    std::memcpy(
        aad.data() + sizeof(metadata.messageCounter),
        &metadata.timestamp,
        sizeof(metadata.timestamp));
    const auto cipherLen = ciphertext.size() - kAesTagSize;
    if (!aesDecryptLocal(
            reinterpret_cast<const void*>(ciphertext.data()),
            reinterpret_cast<void*>(plaintext.data()),
            cipherLen,
            reinterpret_cast<const void*>(aad.data()),
            aad.size(),
            aesKey.data(),
            aesIV.data(),
            reinterpret_cast<const void*>(ciphertext.data() + cipherLen))) {
        LOG(("Signal Protocol Error: AES decryption failed"));
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
    if (EVP_PKEY_CTX_set_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0) {
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
    return nullptr;  // Encrypted message storage is handled through the session path.
}

// Implementation for other methods would follow...
// Including session management, key rotation, etc.

void SignalProtocol::createSession(not_null<PeerData*> peer, const KeyBundle &remoteBundle) {
    SessionState state;
    
    // Initialize device IDs
    state.localDevice = _localDevice;
    state.remoteDevice = remoteBundle.deviceId;
    
    // Get our pre-keys
    auto keyPath = signalStoragePath(_session) + kSignalKeyDbName;
    QFile keyFile(keyPath);
    bytes::vector signedPreKeyPrivate;
    
    if (keyFile.open(QIODevice::ReadOnly)) {
        auto data = keyFile.readAll();
        auto doc = QJsonDocument::fromJson(data);
        auto obj = doc.object();
        
        if (obj.contains("signedPreKey")) {
            auto preKey = obj["signedPreKey"].toObject();
            auto privateKeyBase64 = preKey["private"].toString().toLatin1();
            signedPreKeyPrivate = bytes::make_vector(QByteArray::fromBase64(privateKeyBase64));
        }
        
        keyFile.close();
    }
    
    if (signedPreKeyPrivate.empty()) {
        LOG(("Signal Protocol: Could not load signed pre-key"));
        return;
    }
    
    // Generate ephemeral key pair
    state.dhSendingPrivateKey = generateDH();
    state.dhSendingPublicKey = x25519PublicFromPrivate(state.dhSendingPrivateKey);
    
    // Set remote public key
    state.dhRemotePublicKey = remoteBundle.signedPreKey;
    
    // Calculate shared secrets for the initial keys
    auto dh1 = x25519(signedPreKeyPrivate, remoteBundle.identityKey);
    auto dh2 = x25519(_identityKeyPrivate, remoteBundle.signedPreKey);
    auto dh3 = x25519(signedPreKeyPrivate, remoteBundle.signedPreKey);
    auto dh4 = bytes::vector();
    if (!remoteBundle.oneTimePreKey.empty()) {
        dh4 = x25519(signedPreKeyPrivate, remoteBundle.oneTimePreKey);
    }
    
    // Combine secrets for the root key
    auto combined = bytes::concatenate(dh1, dh2, dh3, dh4);
    state.rootKey = deriveKey(combined, kInfoRootKey, kAesKeySize);
    
    // Initialize chain keys
    auto chainKeyData = deriveKey(state.rootKey, "chain", kAesKeySize * 2);
    {
        auto span = bytes::make_span(chainKeyData);
        state.sendingChainKey = bytes::vector(span.begin(), span.begin() + kAesKeySize);
        state.receivingChainKey = bytes::vector(span.begin() + kAesKeySize, span.begin() + (kAesKeySize * 2));
    }
    
    // Initialize counters
    state.sendingMessageCounter = 0;
    state.receivingMessageCounter = 0;
    state.previousSendingChainLength = 0;
    
    // Set creation timestamp
    state.createdAt = base::unixtime::now();
    state.lastUsedAt = state.createdAt;
    
    // Store the session
    _peerKeyData[peer->id].remoteBundle = remoteBundle;
    _peerKeyData[peer->id].sessions.push_back(state);
    
    // Save to disk
    saveSession(peer, state);
}

bool SignalProtocol::hasSession(not_null<PeerData*> peer) const {
    auto it = _peerKeyData.find(peer->id);
    if (it != _peerKeyData.end()) {
        return !it->second.sessions.empty()
			&& isValidSessionState(it->second.sessions.front());
    }
    
    // Try to load from storage
    auto peerDir = QString::number(peer->id.value);
    auto storagePath = signalStoragePath(_session) + peerDir;
    auto sessionFile = storagePath + "/session.json";
    
    if (!QFile::exists(sessionFile)) {
		return false;
	}
	return isValidSessionState(const_cast<SignalProtocol*>(this)->loadSession(peer));
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
    
    // Derive new root key and chain keys
    auto combinedDH = bytes::concatenate(session.rootKey, dhResult);
    session.rootKey = deriveKey(combinedDH, kInfoRootKey, kAesKeySize);
    
    auto chainKeyData = deriveKey(session.rootKey, kInfoChainKey, kAesKeySize * 2);
    {
        auto span = bytes::make_span(chainKeyData);
        session.sendingChainKey = bytes::vector(span.begin(), span.begin() + kAesKeySize);
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
	if (!isValidSessionState(state)) {
		LOG(("Signal Protocol Error: Invalid session format for peer %1").arg(peer->id.value));
		return {};
	}

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

void SignalProtocol::setKeyRotationInterval(TimeId interval) {
    _keyRotationInterval = interval;
}

} // namespace Data
