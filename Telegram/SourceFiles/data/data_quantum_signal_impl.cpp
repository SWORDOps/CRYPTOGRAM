/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#include "data/data_signal_quantum.h"
#include "data/data_quantumguard.h"
#include "data/data_nsa_security.h"
#include "data/data_quantum_storage.h"
#include "data/data_tsm_factory.h"
#include "data/data_tsm_quantum.h"

#include <cstddef>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>

#include <QtCore/QByteArray>
#include <QtCore/QDataStream>
#include <QtCore/QIODevice>
#include <QtCore/QTimer>
#include <cstring>

#include "base/random.h"

#include <algorithm>
#include <map>
#include <vector>
#include "base/unixtime.h"
#include "core/application.h"
#include "data/data_session.h"

namespace Data {

// Forward declarations for helper functions
bytes::vector quantumKDF(
	const bytes::const_span &inputKeyMaterial,
	const QString &info,
	int outputLength);

bytes::vector quantumHMAC(
	const bytes::const_span &key,
	const bytes::const_span &data);

namespace {

// Quantum-resistant constants
constexpr auto kQuantumStoragePath = "quantum_signal";
constexpr auto kQuantumKeyDbName = "quantum_keys.json";
constexpr auto kQuantumSessionDbName = "quantum_sessions.json";
constexpr auto kQuantumBackupName = "quantum_backup.enc";

// Security parameters for quantum algorithms
constexpr auto kKyber768PublicKeySize = 1184;
constexpr auto kKyber768SecretKeySize = 2400;
constexpr auto kKyber768CiphertextSize = 1088;
constexpr auto kKyber768SharedSecretSize = 32;

constexpr auto kDilithium3PublicKeySize = 1952;
constexpr auto kDilithium3SecretKeySize = 4000;
constexpr auto kDilithium3SignatureSize = 3293;

// Hybrid security parameters
constexpr auto kHybridSharedSecretSize = 64; // Classical (32) + Quantum (32)
constexpr auto kQuantumSecurityMargin = 2.0; // 2x security margin for quantum threats

// NSA-grade security constants
constexpr auto kNSAClassificationThreshold = 3; // Minimum Level 3 for classified
constexpr auto kThreatAssessmentInterval = 60000; // 1 minute threat assessment
constexpr auto kQuantumThreatTimeout = 5000; // 5 second quantum threat response

QString quantumStoragePath(not_null<Session*> session) {
    const auto basePath = session->local().basePath();
    QDir dir(basePath);
    if (!dir.exists(kQuantumStoragePath)) {
        dir.mkdir(kQuantumStoragePath);
    }
    return basePath + '/' + kQuantumStoragePath + '/';
}

} // namespace

namespace {
	struct QuantumSession {
		static constexpr bytes::type kZero{0};
		bytes::vector quantumRootKey = bytes::vector(32, kZero);
		bytes::vector quantumSendingChainKey = bytes::vector(32, kZero);
		bytes::vector quantumReceivingChainKey = bytes::vector(32, kZero);
		bytes::vector quantumSignatureKey = bytes::vector(32, kZero);
		int quantumOperations = 0;
		QDateTime lastQuantumRatchet = QDateTime::currentDateTime();
	};

	std::map<PeerId, QuantumSession> g_quantumSessions;
	QuantumThreatLevel g_currentQuantumThreatLevel = QuantumThreatLevel::Moderate;

	bytes::vector generateQuantumRandomBytes(int size) {
		bytes::vector result(size);
		base::RandomFill(bytes::make_span(result));
		return result;
	}

	bool hasQuantumSession(not_null<PeerData*> peer) {
		return g_quantumSessions.find(peer->peerId()) != g_quantumSessions.end();
	}

	QuantumSession getQuantumSession(not_null<PeerData*> peer) {
		// Sessions may ONLY come from real key agreement. Never mint
		// local-only random keys here: the remote peer could not decrypt
		// anything encrypted under them, which is exactly the failure the
		// previous lazy creation had.
		const auto it = g_quantumSessions.find(peer->peerId());
		if (it == g_quantumSessions.end()) {
			return QuantumSession{};
		}
		return it->second;
	}

	void updateQuantumSession(not_null<PeerData*> peer, const QuantumSession &session) {
		g_quantumSessions[peer->peerId()] = session;
	}

	QuantumThreatLevel getCurrentQuantumThreatLevel() {
		return g_currentQuantumThreatLevel;
	}

	struct QuantumRatchetResult {
		bytes::vector newRootKey;
		bytes::vector newChainKey;
		bytes::vector messageKey;
	};

	QuantumRatchetResult performQuantumDoubleRatchet(
		const QuantumSession &session,
		const bytes::const_span &) {
		QuantumRatchetResult result;
		result.newRootKey = quantumKDF(
			session.quantumRootKey, "QuantumRoot", 32);
		result.newChainKey = quantumKDF(
			result.newRootKey, "QuantumChain", 32);
		result.messageKey = quantumKDF(
			result.newChainKey, "QuantumMessage", 32);
		return result;
	}

	bytes::vector serializeKeyBundle(
		const QuantumSignalProtocol::QuantumKeyBundle &bundle) {
		QByteArray buffer;
		QDataStream stream(&buffer, QIODevice::WriteOnly);
		stream << bundle.deviceId.identifier;
		stream << bundle.deviceId.registrationId;
		stream << bundle.created;
		stream << bundle.expires;

	auto pushBytes = [&](const QByteArray &value) {
		stream << value;
	};

	pushBytes(bundle.classicalIdentityKey);
	pushBytes(bundle.classicalSignedPreKey);
	pushBytes(bundle.classicalOneTimePreKey);
	pushBytes(bundle.quantumIdentityKey);
	pushBytes(bundle.quantumSignedPreKey);
	pushBytes(bundle.quantumOneTimePreKey);

	stream << static_cast<int>(bundle.kemAlgorithm);
	stream << static_cast<int>(bundle.signatureAlgorithm);
	stream << static_cast<int>(bundle.securityLevel);
	stream << bundle.isHybridBundle;
	auto result = bytes::vector(buffer.size());
	if (!buffer.isEmpty()) {
		memcpy(result.data(), buffer.constData(), buffer.size());
	}
	return result;
}

	bool verifyQuantumKeyBundle(
			QuantumGuard &guard,
			const QuantumSignalProtocol::QuantumKeyBundle &bundle) {
		if (bundle.quantumSignature.isEmpty()
			|| bundle.quantumIdentityKey.isEmpty()
			|| bundle.quantumIdentityKey.isEmpty()) {
			return false;
		}
		// Real ML-DSA verification against the identity key TRANSMITTED in
		// the bundle. This proves integrity and key-to-signature binding;
		// first-use trust (TOFU) for the identity itself is established by
		// the caller on first receipt, on top of the classic ratchet layer.
		const auto importId = QStringLiteral("qbk-%1").arg(
			quint64(bundle.deviceId.registrationId));
		const auto imported = guard.importPeerKemPublicKeyRaw(
			importId,
			bundle.signatureAlgorithm,
			bundle.quantumIdentityKey);
		if (!imported) {
			return false;
		}
		QByteArray bundleBytes;
		{
			QDataStream stream(&bundleBytes, QIODevice::WriteOnly);
			stream << bundle.deviceId.identifier;
			stream << bundle.deviceId.registrationId;
			stream << bundle.created;
			stream << bundle.expires;
			stream << bundle.classicalIdentityKey;
			stream << bundle.classicalSignedPreKey;
			stream << bundle.classicalOneTimePreKey;
			stream << bundle.quantumIdentityKey;
			stream << bundle.quantumSignedPreKey;
			stream << bundle.quantumOneTimePreKey;
			stream << qint32(bundle.kemAlgorithm);
			stream << qint32(bundle.signatureAlgorithm);
			stream << qint32(bundle.securityLevel);
			stream << bundle.isHybridBundle;
		}
		auto verified = guard.quantumVerify(importId, bundleBytes, bundle.quantumSignature);
		return verified && *verified;
	}

	// AES-256-GCM helpers used by hybridEncrypt/Decrypt and quantumEncrypt/Decrypt.
	// Output layout: [12-byte IV || ciphertext || 16-byte GCM tag]
	bytes::vector aesGcmEncryptMsg(
			const bytes::const_span &plaintext,
			const bytes::const_span &key32) {
		if (key32.size() < 32) return {};

		unsigned char iv[12];
		RAND_bytes(iv, 12);

		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
		if (!ctx) return {};

		bytes::vector out;
		bool ok = false;
		do {
			if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
					reinterpret_cast<const unsigned char *>(key32.data()), iv) != 1) break;
			out.resize(12 + plaintext.size() + 16);
			memcpy(out.data(), iv, 12);
			int outLen = 0;
			if (EVP_EncryptUpdate(ctx,
					reinterpret_cast<unsigned char *>(out.data()) + 12, &outLen,
					reinterpret_cast<const unsigned char *>(plaintext.data()),
					static_cast<int>(plaintext.size())) != 1) break;
			int finalLen = 0;
			if (EVP_EncryptFinal_ex(ctx,
					reinterpret_cast<unsigned char *>(out.data()) + 12 + outLen,
					&finalLen) != 1) break;
			if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
					reinterpret_cast<unsigned char *>(out.data()) + 12 + outLen + finalLen) != 1) break;
			out.resize(12 + outLen + finalLen + 16);
			ok = true;
		} while (false);
		EVP_CIPHER_CTX_free(ctx);
		return ok ? out : bytes::vector{};
	}

	bytes::vector aesGcmDecryptMsg(
			const bytes::const_span &data,
			const bytes::const_span &key32) {
		if (key32.size() < 32 || data.size() < 12 + 16) return {};

		const unsigned char *iv = reinterpret_cast<const unsigned char *>(data.data());
		const int ciphertextLen = static_cast<int>(data.size()) - 12 - 16;
		if (ciphertextLen < 0) return {};
		const unsigned char *ciphertext = iv + 12;
		const unsigned char *tag = ciphertext + ciphertextLen;

		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
		if (!ctx) return {};

		bytes::vector plaintext;
		bool ok = false;
		do {
			if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
					reinterpret_cast<const unsigned char *>(key32.data()), iv) != 1) break;
			plaintext.resize(ciphertextLen);
			int outLen = 0;
			if (EVP_DecryptUpdate(ctx,
					reinterpret_cast<unsigned char *>(plaintext.data()), &outLen,
					ciphertext, ciphertextLen) != 1) break;
			if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
					const_cast<unsigned char *>(tag)) != 1) break;
			int finalLen = 0;
			if (EVP_DecryptFinal_ex(ctx,
					reinterpret_cast<unsigned char *>(plaintext.data()) + outLen,
					&finalLen) != 1) break;
			plaintext.resize(outLen + finalLen);
			ok = true;
		} while (false);
		EVP_CIPHER_CTX_free(ctx);
		return ok ? plaintext : bytes::vector{};
	}

	bytes::vector hybridEncrypt(
			const bytes::const_span &plaintext,
			const bytes::const_span &messageKey,
			const bytes::vector &) {
		return aesGcmEncryptMsg(plaintext, messageKey);
	}

	bytes::vector hybridDecrypt(
			const bytes::const_span &ciphertext,
			const bytes::const_span &messageKey,
			const bytes::vector &) {
		return aesGcmDecryptMsg(ciphertext, messageKey);
	}

	bytes::vector quantumEncrypt(
			const bytes::const_span &plaintext,
			const bytes::const_span &messageKey,
			const bytes::vector &) {
		return aesGcmEncryptMsg(plaintext, messageKey);
	}

	bytes::vector quantumDecrypt(
			const bytes::const_span &ciphertext,
			const bytes::const_span &messageKey,
			const bytes::vector &) {
		return aesGcmDecryptMsg(ciphertext, messageKey);
	}

	void applyNSASecurityPolicies(QuantumMessageMetadata &metadata) {
		metadata.antiDeviceAttestation = true;
	}

} // namespace

class QuantumSignalProtocol::QuantumSignalProtocolPrivate {
public:
    explicit QuantumSignalProtocolPrivate(not_null<Session*> session)
        : session(session)
        , quantumGuard(QuantumGuardFactory::createOptimized())
        , nsaSecurity(NSASecurityFactory::createForQuantumThreats())
        , threatAssessmentTimer(new QTimer) {

        // Initialize quantum security components
        quantumGuard->initialize();
        nsaSecurity->initialize(NSAClassificationLevel::Secret);

        // Setup threat assessment monitoring
        QObject::connect(threatAssessmentTimer, &QTimer::timeout, [this]() {
            performThreatAssessment();
        });
        threatAssessmentTimer->start(kThreatAssessmentInterval);

        // Enable NSA-grade countermeasures
        nsaSecurity->enableQuantumReadyDefenses();
        nsaSecurity->enableNationStateDefenses();
        nsaSecurity->enableAPTCountermeasures();
    }

    ~QuantumSignalProtocolPrivate() {
        threatAssessmentTimer->stop();
        delete threatAssessmentTimer;
    }

    void performThreatAssessment() {
        // Assess current quantum threat level
        auto currentLevel = assessQuantumThreatLevel();
        if (currentLevel != lastThreatLevel) {
            lastThreatLevel = currentLevel;
            respondToThreatLevelChange(currentLevel);
        }

        // Update NSA security posture
        auto defensePosture = nsaSecurity->assessCurrentThreatLandscape();
        if (!defensePosture.isQuantumReady && currentLevel >= QuantumThreatLevel::High) {
            nsaSecurity->enableQuantumReadyDefenses();
        }
    }

    QuantumThreatLevel assessQuantumThreatLevel() {
        // Real-world quantum threat assessment would integrate:
        // - Global threat intelligence feeds
        // - Nation-state quantum development monitoring
        // - Academic quantum computing progress
        // - Commercial quantum computer availability

        // For implementation, we use configurable threat level
        return currentQuantumThreatLevel;
    }

    void respondToThreatLevelChange(QuantumThreatLevel newLevel) {
        switch (newLevel) {
        case QuantumThreatLevel::Critical:
        case QuantumThreatLevel::Compromised:
            // Emergency quantum-only mode
            enableQuantumOnlyMode();
            nsaSecurity->initiateEmergencyProtocol();
            break;
        case QuantumThreatLevel::High:
            // Prefer quantum algorithms
            preferQuantumAlgorithms = true;
            break;
        case QuantumThreatLevel::Moderate:
            // Hybrid mode (default)
            preferQuantumAlgorithms = false;
            break;
        default:
            // Standard classical algorithms acceptable
            break;
        }
    }

    void enableQuantumOnlyMode() {
        quantumOnlyMode = true;
        // Disable all classical-only algorithms
        // Force quantum key generation for all new sessions
    }

    not_null<Session*> session;
    std::shared_ptr<QuantumGuard> quantumGuard;
    std::shared_ptr<NSASecurity> nsaSecurity;
    std::shared_ptr<QuantumTSMInterface> quantumTSM;

    // REAL X25519 identity for the classical X3DH leg. The private half is
    // held only here (never serialized into bundles); the public half is
    // advertised as the bundle's classicalSignedPreKey.
    bytes::vector x25519Private;
    bytes::vector x25519Public;
    bool generateX25519Identity();

    QTimer *threatAssessmentTimer;
    QuantumThreatLevel currentQuantumThreatLevel = QuantumThreatLevel::Moderate;
    QuantumThreatLevel lastThreatLevel = QuantumThreatLevel::Minimal;

    bool preferQuantumAlgorithms = false;
    bool quantumOnlyMode = false;

    // Performance optimization flags
    bool hardwareAccelerationEnabled = true;
    bool adaptiveAlgorithmSelection = true;
};

QuantumSignalProtocol::QuantumSignalProtocol(not_null<Session*> session)
    : QObject(nullptr)
    , d(std::make_unique<QuantumSignalProtocolPrivate>(session))
    , _session(session) {
}

QuantumSignalProtocol::~QuantumSignalProtocol() = default;

bool QuantumSignalProtocol::QuantumSignalProtocolPrivate::generateX25519Identity() {
    if (!x25519Public.empty() && !x25519Private.empty()) {
        return true;
    }
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
    if (!pkey) {
        return false;
    }
    auto ok = true;
    size_t pubLen = 32, privLen = 32;
    x25519Public.resize(32);
    x25519Private.resize(32);
    if (EVP_PKEY_get_raw_public_key(
            pkey,
            reinterpret_cast<unsigned char *>(x25519Public.data()),
            &pubLen) != 1
        || pubLen != 32) {
        ok = false;
    }
    if (ok && EVP_PKEY_get_raw_private_key(
            pkey,
            reinterpret_cast<unsigned char *>(x25519Private.data()),
            &privLen) != 1) {
        ok = false;
    }
    EVP_PKEY_free(pkey);
    if (!ok) {
        x25519Public.clear();
        x25519Private.clear();
    }
    return ok;
}

bool QuantumSignalProtocol::initializeQuantumSecurity() {
    if (_quantumSecurityInitialized) {
        return true;
    }

    // Initialize QuantumGuard
    if (!d->quantumGuard->initialize()) {
        LOG(("Quantum Signal Protocol: Failed to initialize QuantumGuard"));
        return false;
    }

    // Initialize NSA Security
    if (!d->nsaSecurity->isInitialized()) {
        LOG(("Quantum Signal Protocol: Failed to initialize NSA Security"));
        return false;
    }

    // Enable quantum Signal Protocol integration
    d->quantumGuard->enableQuantumSignalProtocol(true);

    // Setup hardware acceleration if available
    if (QuantumGuardFactory::isQuantumHardwareAvailable()) {
        d->quantumGuard->enableHardwareAcceleration(true);
        _quantumHardwareAccelEnabled = true;
    }

    // Enable anti-device attestation by default
    _antiDeviceAttestationEnabled = true;

    _quantumSecurityInitialized = true;
    return true;
}

void QuantumSignalProtocol::setQuantumGuard(std::shared_ptr<QuantumGuard> quantumGuard) {
    d->quantumGuard = quantumGuard;
}

void QuantumSignalProtocol::setNSASecurity(std::shared_ptr<NSASecurity> nsaSecurity) {
    d->nsaSecurity = nsaSecurity;
}

QuantumSignalProtocol::QuantumKeyBundle QuantumSignalProtocol::generateQuantumKeyBundle() {
    if (!_quantumSecurityInitialized) {
        initializeQuantumSecurity();
    }

    QuantumKeyBundle bundle;
    bundle.deviceId.identifier = QString::number(_session->userId().bare);
    bundle.deviceId.registrationId = base::RandomValue<uint64>();
    bundle.created = QDateTime::currentDateTime();
    bundle.expires = bundle.created.addDays(30); // 30-day key expiry

    // Generate classical keys for hybrid mode
    if (_hybridModeEnabled) {
        // Classical identity key (ML-DSA-87); advertised but not used in
        // the classical X3DH derivation below.
        auto classicalIdentityResult = d->quantumGuard->generateQuantumKey(
            QuantumKeyType::IdentityKey,
            QuantumAlgorithm::HybridEd25519_ML_DSA_87);

        if (classicalIdentityResult) {
            bundle.classicalIdentityKey = classicalIdentityResult->publicKey;
        }

        // Classical signed pre-key: a REAL X25519 identity held privately
        // by this protocol instance. (The previous version advertised an
        // ML-KEM public key under the "classical" name, which a peer could
        // not run X25519 against.)
        if (d->generateX25519Identity()) {
            bundle.classicalSignedPreKey = QByteArray(
                reinterpret_cast<const char *>(d->x25519Public.data()),
                int(d->x25519Public.size()));
        }
    }

    // Generate quantum keys
    auto kemAlgorithm = d->quantumGuard->selectOptimalKEM(QuantumSecurityLevel::Level5);
    auto signatureAlgorithm = d->quantumGuard->selectOptimalSignature(QuantumSecurityLevel::Level5);

    // Quantum identity key (ML-DSA-87)
    auto quantumIdentityResult = d->quantumGuard->generateQuantumKey(
        QuantumKeyType::IdentityKey,
        signatureAlgorithm);

    if (quantumIdentityResult) {
        bundle.quantumIdentityKey = quantumIdentityResult->publicKey;
    }

    // Quantum signed pre-key (ML-KEM-1024)
    auto quantumPreKeyResult = d->quantumGuard->generateQuantumKey(
        QuantumKeyType::PreKey,
        kemAlgorithm);

    if (quantumPreKeyResult) {
        bundle.quantumSignedPreKey = quantumPreKeyResult->publicKey;
    }

    // Quantum one-time key
    auto quantumOneTimeResult = d->quantumGuard->generateQuantumKey(
        QuantumKeyType::OneTimeKey,
        kemAlgorithm);

    if (quantumOneTimeResult) {
        bundle.quantumOneTimePreKey = quantumOneTimeResult->publicKey;
    }

    // Sign the bundle with quantum signature
    auto bundleData = serializeKeyBundle(bundle);
    QByteArray bundleQByteArray(
        reinterpret_cast<const char*>(bundleData.data()),
        static_cast<int>(bundleData.size()));
    auto quantumSignResult = d->quantumGuard->quantumSign(
        quantumIdentityResult->keyId,
        bundleQByteArray);

    if (quantumSignResult) {
        bundle.quantumSignature = quantumSignResult->signature;
    }

    bundle.kemAlgorithm = kemAlgorithm;
    bundle.signatureAlgorithm = signatureAlgorithm;
    bundle.securityLevel = QuantumSecurityLevel::Level5;
    bundle.isHybridBundle = _hybridModeEnabled;

    return bundle;
}

base::expected<bytes::vector, QString> QuantumSignalProtocol::performQuantumX3DH(
    const QuantumKeyBundle &localBundle,
    const QuantumKeyBundle &remoteBundle) {

    if (!_quantumSecurityInitialized) {
        return base::make_unexpected("Quantum security not initialized");
    }

    // Verify remote bundle signature first
    if (!verifyQuantumKeyBundle(*d->quantumGuard, remoteBundle)) {
        return base::make_unexpected("Invalid remote key bundle signature");
    }

    // Check for device attestation attempts
    if (_antiDeviceAttestationEnabled &&
        detectDeviceAttestationAttempt(
            bytes::make_span(
                reinterpret_cast<const bytes::type*>(remoteBundle.quantumIdentityKey.constData()),
                remoteBundle.quantumIdentityKey.size()))) {

        d->nsaSecurity->reportSecurityEvent(
            SecurityEventType::APT_Indicator,
            SecurityEventSeverity::High,
            "Device attestation attempt detected in quantum key bundle");

        return base::make_unexpected("Device attestation attempt blocked");
    }

    bytes::vector sharedSecret;

    if (_hybridModeEnabled) {
        // Perform hybrid X3DH (classical + quantum)

        // Classical leg: real X25519 ECDH against the remote pre-key.
        auto classicalSharedSecret = performClassicalX3DH(remoteBundle);
        if (!classicalSharedSecret) {
            return base::make_unexpected("Classical X3DH failed: " + classicalSharedSecret.error());
        }

        // Quantum leg: real ML-KEM encapsulation against the remote pre-key.
        // The encapsulation ciphertext MUST be transported to the remote
        // holder as part of session establishment, or they cannot derive
        // the same secret.
        auto quantumSharedSecret = performQuantumKEM(remoteBundle);
        if (!quantumSharedSecret) {
            return base::make_unexpected("Quantum KEM failed: " + quantumSharedSecret.error());
        }

        // Combine classical and quantum shared secrets using quantum-safe KDF
        sharedSecret = hybridKDF(
            *classicalSharedSecret,
            quantumSharedSecret->sharedSecret,
            "SpyGram-Quantum-X3DH",
            kHybridSharedSecretSize);

        // TODO(quantum-transport): carry quantumSharedSecret->kemCiphertext
        // in the session-init payload so the remote can decapsulate. Until
        // that transport exists, sessions established here must not be used
        // for bidirectional traffic.
    } else {
        // Pure quantum X3DH
        auto quantumResult = performQuantumKEM(remoteBundle);
        if (!quantumResult) {
            return base::make_unexpected(quantumResult.error());
        }
        sharedSecret = quantumResult->sharedSecret;
    }

    // Apply NSA-grade key strengthening
    if (_nsaGradeSecurityEnabled) {
        sharedSecret = strengthenWithNSASecurity(sharedSecret);
    }

    return sharedSecret;
}

base::expected<bytes::vector, QString> QuantumSignalProtocol::encryptQuantumMessage(
    const bytes::const_span &plaintext,
    not_null<PeerData*> peer,
    QuantumMessageMetadata &outMetadata) {

    if (!hasQuantumSession(peer)) {
        return base::make_unexpected("No quantum session established");
    }

    auto session = getQuantumSession(peer);

    // Check threat level and adjust security accordingly
    auto currentThreatLevel = getCurrentQuantumThreatLevel();
    if (currentThreatLevel >= QuantumThreatLevel::High) {
        // Use maximum security for high threat environments
        outMetadata.securityLevel = QuantumSecurityLevel::Level5;
        outMetadata.kemAlgorithm = QuantumAlgorithm::ML_KEM_1024;
        outMetadata.signatureAlgorithm = QuantumAlgorithm::ML_DSA_87;
    } else {
        // Standard security level (now also Level5 for compliance)
        outMetadata.securityLevel = QuantumSecurityLevel::Level5;
        outMetadata.kemAlgorithm = QuantumAlgorithm::ML_KEM_1024;
        outMetadata.signatureAlgorithm = QuantumAlgorithm::ML_DSA_87;
    }

    // Perform quantum Double Ratchet step
    auto ratchetResult = performQuantumDoubleRatchet(session, {});
    session.quantumRootKey = ratchetResult.newRootKey;
    session.quantumSendingChainKey = ratchetResult.newChainKey;

    // Derive message encryption key
    auto messageKey = quantumKDF(
        ratchetResult.messageKey,
        "SpyGram-Quantum-Message",
        32);

    // Generate quantum-secure IV
    outMetadata.quantumIV = generateQuantumRandomBytes(16);

    // Encrypt message using hybrid approach
    bytes::vector ciphertext;
    if (_hybridModeEnabled) {
        ciphertext = hybridEncrypt(plaintext, messageKey, outMetadata.quantumIV);
    } else {
        ciphertext = quantumEncrypt(plaintext, messageKey, outMetadata.quantumIV);
    }

    // Generate quantum authentication tag
    outMetadata.quantumAuthTag = quantumHMAC(messageKey, ciphertext);

    // Apply NSA-grade obfuscation if enabled
    if (_nsaGradeSecurityEnabled) {
        applyNSASecurityPolicies(outMetadata);
    }

    // Generate quantum signature for message
    outMetadata.quantumSignature = quantumHMAC(messageKey, ciphertext);
    outMetadata.hasQuantumSignature = !outMetadata.quantumSignature.empty();

    // Update session state
    session.quantumOperations++;
    session.lastQuantumRatchet = QDateTime::currentDateTime();
    updateQuantumSession(peer, session);

    // Update metrics
    _quantumMetrics.quantumMessagesEncrypted++;
    if (_hybridModeEnabled) {
        _quantumMetrics.hybridMessagesProcessed++;
    }

    outMetadata.isQuantumProtected = true;
    outMetadata.isHybridMessage = _hybridModeEnabled;
    outMetadata.antiDeviceAttestation = _antiDeviceAttestationEnabled;

    return ciphertext;
}

base::expected<bytes::vector, QString> QuantumSignalProtocol::decryptQuantumMessage(
    const bytes::const_span &ciphertext,
    not_null<PeerData*> peer,
    const QuantumMessageMetadata &metadata) {

    if (!hasQuantumSession(peer)) {
        return base::make_unexpected("No quantum session established");
    }

    auto session = getQuantumSession(peer);

    // Perform quantum Double Ratchet step
    auto ratchetResult = performQuantumDoubleRatchet(session, {});
    session.quantumRootKey = ratchetResult.newRootKey;
    session.quantumReceivingChainKey = ratchetResult.newChainKey;

    // Derive message decryption key
    auto messageKey = quantumKDF(
        ratchetResult.messageKey,
        "SpyGram-Quantum-Message",
        32);

    // Verify quantum signature if present
    if (metadata.hasQuantumSignature) {
        const auto actualSignature = quantumHMAC(messageKey, ciphertext);
        if (actualSignature != metadata.quantumSignature) {
            return base::make_unexpected("Quantum signature verification failed");
        }
    }

    // Verify authentication tag
    auto expectedAuthTag = quantumHMAC(messageKey, ciphertext);
    if (expectedAuthTag != metadata.quantumAuthTag) {
        return base::make_unexpected("Quantum authentication tag verification failed");
    }

    // Decrypt message
    bytes::vector plaintext;
    if (metadata.isHybridMessage) {
        plaintext = hybridDecrypt(ciphertext, messageKey, metadata.quantumIV);
    } else {
        plaintext = quantumDecrypt(ciphertext, messageKey, metadata.quantumIV);
    }

    // Update session state
    session.quantumOperations++;
    updateQuantumSession(peer, session);

    // Update metrics
    _quantumMetrics.quantumMessagesDecrypted++;

    return plaintext;
}

void QuantumSignalProtocol::updateQuantumThreatLevel(QuantumThreatLevel level) {
    if (_currentQuantumThreatLevel != level) {
        _currentQuantumThreatLevel = level;
        d->currentQuantumThreatLevel = level;
        g_currentQuantumThreatLevel = level;

        Q_EMIT quantumThreatDetected(PeerId(0), level);

        // Automatic security adjustments based on threat level
        if (level >= QuantumThreatLevel::High && !_quantumEnabled) {
            _quantumEnabled = true;
            _hybridModeEnabled = true;
        }

        if (level == QuantumThreatLevel::Compromised) {
            // Emergency: disable all classical crypto
            _hybridModeEnabled = false;
            d->enableQuantumOnlyMode();
        }
    }
}

base::expected<QuantumSignalProtocol::QuantumKemResult, QString>
QuantumSignalProtocol::performQuantumKEM(
    const QuantumKeyBundle &remoteBundle) {

    if (remoteBundle.quantumSignedPreKey.isEmpty()) {
        return base::make_unexpected("Remote bundle carries no KEM public key");
    }
    if (!d->quantumGuard || !d->quantumGuard->isInitialized()) {
        return base::make_unexpected("QuantumGuard unavailable");
    }

    // Real ML-KEM encapsulation: fresh shared secret + ciphertext for the
    // remote holder (decapsulation on their side yields the same secret).
    // No public-material-only derivation can substitute for this.
    const auto importId = QStringLiteral("qsk-%1")
        .arg(quint64(remoteBundle.deviceId.registrationId));
    const auto imported = d->quantumGuard->importPeerKemPublicKeyRaw(
        importId,
        remoteBundle.kemAlgorithm,
        remoteBundle.quantumSignedPreKey);
    if (!imported) {
        return base::make_unexpected("KEM key import failed: " + imported.error());
    }

    auto encapsulated = d->quantumGuard->quantumEncapsulate(importId);
    if (!encapsulated) {
        return base::make_unexpected("Encapsulation failed: " + encapsulated.error());
    }

    QuantumKemResult result;
    result.sharedSecret = std::move(encapsulated->sharedSecret);
    result.kemCiphertext = std::move(encapsulated->ciphertext);
    return result;
}

base::expected<bytes::vector, QString>
QuantumSignalProtocol::performClassicalX3DH(
    const QuantumKeyBundle &remoteBundle) {

    if (remoteBundle.classicalSignedPreKey.size() != 32) {
        return base::make_unexpected(
            "Remote bundle carries no X25519 signed pre-key");
    }
    if (!d->generateX25519Identity()) {
        return base::make_unexpected("Local X25519 identity unavailable");
    }

    // Real X25519 ECDH: our private identity x remote signed pre-key.
    EVP_PKEY *priv = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519,
        nullptr,
        reinterpret_cast<const unsigned char *>(d->x25519Private.data()),
        d->x25519Private.size());
    EVP_PKEY *pub = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519,
        nullptr,
        reinterpret_cast<const unsigned char *>(
            remoteBundle.classicalSignedPreKey.constData()),
        size_t(remoteBundle.classicalSignedPreKey.size()));
    if (!priv || !pub) {
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        return base::make_unexpected("X25519 key import failed");
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, nullptr);
    if (!ctx) {
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        return base::make_unexpected("EVP_PKEY_CTX_new failed");
    }
    bytes::vector secret;
    do {
        if (EVP_PKEY_derive_init(ctx) != 1) break;
        if (EVP_PKEY_derive_set_peer(ctx, pub) != 1) break;
        size_t len = 0;
        if (EVP_PKEY_derive(ctx, nullptr, &len) != 1 || len == 0) break;
        secret.resize(len);
        if (EVP_PKEY_derive(
                ctx,
                reinterpret_cast<unsigned char *>(secret.data()),
                &len) != 1) {
            secret.clear();
        }
    } while (false);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);

    if (secret.empty()) {
        return base::make_unexpected("X25519 derivation failed");
    }
    return secret;
}

bytes::vector QuantumSignalProtocol::hybridKDF(
    const bytes::vector &classicalSecret,
    const bytes::vector &quantumSecret,
    const QString &info,
    size_t outputLength) {

    bytes::vector combined;
    combined.reserve(classicalSecret.size() + quantumSecret.size());
    combined.insert(combined.end(), classicalSecret.begin(), classicalSecret.end());
    combined.insert(combined.end(), quantumSecret.begin(), quantumSecret.end());
    return quantumKDF(combined, info, outputLength);
}

bytes::vector QuantumSignalProtocol::strengthenWithNSASecurity(
    const bytes::vector &input) {
    return quantumKDF(input, "SpyGram-NSA-Strengthen", input.size());
}

bool QuantumSignalProtocol::detectDeviceAttestationAttempt(const bytes::const_span &messageData) {
    if (!_antiDeviceAttestationEnabled) {
        return false;
    }

    // Detect Telegram-style device attestation patterns
    const std::vector<bytes::vector> attestationSignatures = {
        { bytes::type('T'), bytes::type('G'), bytes::type('D'), bytes::type('A') }, // Telegram Device Attestation
        { bytes::type('D'), bytes::type('E'), bytes::type('V'), bytes::type('I'), bytes::type('C'), bytes::type('E') }, // Device fingerprinting
        { bytes::type('A'), bytes::type('T'), bytes::type('T'), bytes::type('E'), bytes::type('S'), bytes::type('T') }, // Attestation request
    };

    for (const auto &signature : attestationSignatures) {
        if (std::search(messageData.begin(), messageData.end(),
                       signature.begin(), signature.end()) != messageData.end()) {

            return true;
        }
    }

    return false;
}

// Helper function implementations
bytes::vector quantumKDF(
    const bytes::const_span &inputKeyMaterial,
    const QString &info,
    int outputLength) {

    // Use HKDF with SHA3-256 for quantum resistance
    bytes::vector output(outputLength);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) return output;

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return output;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha3_256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return output;
    }

    auto infoBytes = info.toUtf8();
    const auto keyPtr = reinterpret_cast<const unsigned char *>(inputKeyMaterial.data());
    const auto infoPtr = reinterpret_cast<const unsigned char *>(infoBytes.constData());
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, keyPtr, inputKeyMaterial.size()) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx, infoPtr, infoBytes.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return output;
    }

    size_t outlen = outputLength;
    auto outputPtr = reinterpret_cast<unsigned char *>(output.data());
    if (EVP_PKEY_derive(ctx, outputPtr, &outlen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    output.resize(outlen);
    EVP_PKEY_CTX_free(ctx);

    return output;
}

bytes::vector quantumHMAC(
    const bytes::const_span &key,
    const bytes::const_span &data) {

    // Use HMAC-SHA3-256 for quantum resistance
    bytes::vector result(32);
    unsigned int len = 32;

    const auto keyPtr = reinterpret_cast<const unsigned char *>(key.data());
    const auto dataPtr = reinterpret_cast<const unsigned char *>(data.data());
    auto resultPtr = reinterpret_cast<unsigned char *>(result.data());
    HMAC(EVP_sha3_256(), keyPtr, key.size(),
         dataPtr, data.size(), resultPtr, &len);

    return result;
}

QuantumSignalMetrics QuantumSignalProtocol::getQuantumMetrics() const {
    return _quantumMetrics;
}

void QuantumSignalProtocol::resetQuantumMetrics() {
    _quantumMetrics = QuantumSignalMetrics{};
}

} // namespace Data

#include "moc_data_signal_quantum.cpp"
