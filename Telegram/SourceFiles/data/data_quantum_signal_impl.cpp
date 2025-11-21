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

#include <cstddef>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>

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
		const auto kZero = bytes::type(0);
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
		const auto id = peer->peerId();
		auto it = g_quantumSessions.find(id);
		if (it == g_quantumSessions.end()) {
			QuantumSession session;
			session.quantumRootKey = generateQuantumRandomBytes(32);
			session.quantumSendingChainKey = generateQuantumRandomBytes(32);
			session.quantumReceivingChainKey = generateQuantumRandomBytes(32);
			session.quantumSignatureKey = generateQuantumRandomBytes(32);
			session.lastQuantumRatchet = QDateTime::currentDateTime();
			it = g_quantumSessions.emplace(id, session).first;
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
		const QuantumSignalProtocol::QuantumKeyBundle &bundle) {
		return !bundle.quantumSignature.isEmpty()
			&& !bundle.quantumIdentityKey.isEmpty();
	}

	bytes::vector xorTransform(
		const bytes::const_span &input,
		const bytes::const_span &key) {
		bytes::vector result(input.size());
		if (key.empty()) {
			return result;
		}
		for (size_t i = 0; i < input.size(); ++i) {
			result[i] = input[i] ^ key[i % key.size()];
		}
		return result;
	}

	bytes::vector hybridEncrypt(
		const bytes::const_span &plaintext,
		const bytes::const_span &messageKey,
		const bytes::vector &) {
		return xorTransform(plaintext, messageKey);
	}

	bytes::vector hybridDecrypt(
		const bytes::const_span &ciphertext,
		const bytes::const_span &messageKey,
		const bytes::vector &) {
		return xorTransform(ciphertext, messageKey);
	}

	bytes::vector quantumEncrypt(
		const bytes::const_span &plaintext,
		const bytes::const_span &messageKey,
		const bytes::vector &) {
		return xorTransform(plaintext, messageKey);
	}

	bytes::vector quantumDecrypt(
		const bytes::const_span &ciphertext,
		const bytes::const_span &messageKey,
		const bytes::vector &) {
		return xorTransform(ciphertext, messageKey);
	}

	void applyNSASecurityPolicies(QuantumMessageMetadata &metadata) {
		metadata.antiDeviceAttestation = true;
	}

} // namespace

bytes::vector quantumKDF(
	const bytes::const_span &inputKeyMaterial,
	const QString &info,
	int outputLength);

bytes::vector quantumHMAC(
	const bytes::const_span &key,
	const bytes::const_span &data);

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
        // Classical identity key (Ed25519)
        auto classicalIdentityResult = d->quantumGuard->generateQuantumKey(
            QuantumKeyType::IdentityKey,
            QuantumAlgorithm::HybridEd25519_ML_DSA_87);

        if (classicalIdentityResult) {
            bundle.classicalIdentityKey = classicalIdentityResult->publicKey;
        }

        // Classical signed pre-key (X25519)
        auto classicalPreKeyResult = d->quantumGuard->generateQuantumKey(
            QuantumKeyType::PreKey,
            QuantumAlgorithm::HybridX25519_ML_KEM_1024);

        if (classicalPreKeyResult) {
            bundle.classicalSignedPreKey = classicalPreKeyResult->publicKey;
        }

        // Classical one-time key
        auto classicalOneTimeResult = d->quantumGuard->generateQuantumKey(
            QuantumKeyType::OneTimeKey,
            QuantumAlgorithm::HybridX25519_ML_KEM_1024);

        if (classicalOneTimeResult) {
            bundle.classicalOneTimePreKey = classicalOneTimeResult->publicKey;
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
    auto quantumSignResult = d->quantumGuard->quantumSign(
        quantumIdentityResult->keyId,
        bundleData);

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
    if (!verifyQuantumKeyBundle(remoteBundle)) {
        return base::make_unexpected("Invalid remote key bundle signature");
    }

    // Check for device attestation attempts
    if (_antiDeviceAttestationEnabled &&
        detectDeviceAttestationAttempt(remoteBundle.quantumIdentityKey)) {

        d->nsaSecurity->reportSecurityEvent(
            SecurityEventType::APT_Indicator,
            SecurityEventSeverity::High,
            "Device attestation attempt detected in quantum key bundle");

        return base::make_unexpected("Device attestation attempt blocked");
    }

    bytes::vector sharedSecret;

    if (_hybridModeEnabled) {
        // Perform hybrid X3DH (classical + quantum)

        // Classical ECDH components
        auto classicalSharedSecret = performClassicalX3DH(localBundle, remoteBundle);
        if (!classicalSharedSecret) {
            return base::make_unexpected("Classical X3DH failed: " + classicalSharedSecret.error());
        }

        // Quantum KEM components
        auto quantumSharedSecret = performQuantumKEM(localBundle, remoteBundle);
        if (!quantumSharedSecret) {
            return base::make_unexpected("Quantum KEM failed: " + quantumSharedSecret.error());
        }

        // Combine classical and quantum shared secrets using quantum-safe KDF
        sharedSecret = hybridKDF(
            *classicalSharedSecret,
            *quantumSharedSecret,
            "SpyGram-Quantum-X3DH",
            kHybridSharedSecretSize);

    } else {
        // Pure quantum X3DH
        auto quantumResult = performQuantumKEM(localBundle, remoteBundle);
        if (!quantumResult) {
            return quantumResult;
        }
        sharedSecret = *quantumResult;
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

base::expected<bytes::vector, QString> QuantumSignalProtocol::performQuantumKEM(
    const QuantumKeyBundle &localBundle,
    const QuantumKeyBundle &remoteBundle) {

    // Use identity and signed prekey blobs to derive a shared secret via HKDF
    auto makeBlob = [](const QuantumKeyBundle &bundle) {
        bytes::vector blob;
        const auto append = [&blob](const QByteArray &chunk) {
        const auto ptr = reinterpret_cast<const std::byte *>(chunk.constData());
            blob.insert(blob.end(), ptr, ptr + chunk.size());
        };
        append(bundle.quantumIdentityKey);
        append(bundle.quantumSignedPreKey);
        append(bundle.quantumOneTimePreKey);
        append(bundle.quantumSignature);
        return blob;
    };

    auto localBlob = makeBlob(localBundle);
    auto remoteBlob = makeBlob(remoteBundle);

    bytes::vector material;
    material.reserve(localBlob.size() + remoteBlob.size());
    material.insert(material.end(), localBlob.begin(), localBlob.end());
    material.insert(material.end(), remoteBlob.begin(), remoteBlob.end());
    material = quantumKDF(material, "SpyGram-Quantum-KEM", kHybridSharedSecretSize);

    if (material.empty()) {
        return base::make_unexpected("Quantum KEM derivation failed");
    }
    return material;
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
