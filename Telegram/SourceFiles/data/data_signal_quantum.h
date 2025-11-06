/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#pragma once

#include "data/data_signal_protocol.h"
#include "data/data_quantumguard.h"
#include "data/data_tsm_quantum.h"
#include "data/data_nsa_security.h"
#include "base/bytes.h"
#include "base/expected.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QDateTime>
#include <memory>
#include <variant>

namespace Data {

// Quantum-enhanced Signal Protocol
class QuantumSignalProtocol : public QObject {
    Q_OBJECT

public:
    // Quantum X3DH key bundle (post-quantum X3DH)
    struct QuantumKeyBundle {
        DeviceId deviceId;

        // Classical keys (for hybrid mode)
        bytes::vector classicalIdentityKey;
        bytes::vector classicalSignedPreKey;
        bytes::vector classicalOneTimePreKey;
        bytes::vector classicalSignature;

        // Quantum keys
        bytes::vector quantumIdentityKey;
        bytes::vector quantumSignedPreKey;
        bytes::vector quantumOneTimePreKey;
        bytes::vector quantumSignature;

        // Hybrid metadata
        QuantumAlgorithm kemAlgorithm = QuantumAlgorithm::Kyber768;
        QuantumAlgorithm signatureAlgorithm = QuantumAlgorithm::Dilithium3;
        QuantumSecurityLevel securityLevel = QuantumSecurityLevel::Level3;
        bool isHybridBundle = true;
        QDateTime created;
        QDateTime expires;
    };

    // Quantum Double Ratchet session state
    struct QuantumSessionState {
        // Classical Double Ratchet state
        SignalProtocol::SessionState classicalState;

        // Quantum-enhanced state
        bytes::vector quantumRootKey;
        bytes::vector quantumSendingChainKey;
        bytes::vector quantumReceivingChainKey;

        // Quantum ratchet keys
        bytes::vector quantumDHSendingPublicKey;
        bytes::vector quantumDHSendingPrivateKey;
        bytes::vector quantumDHRemotePublicKey;

        // Quantum key encapsulation
        bytes::vector kemSharedSecret;
        bytes::vector kemEncapsulation;
        QuantumAlgorithm kemAlgorithm = QuantumAlgorithm::Kyber768;

        // Quantum signatures
        bytes::vector quantumSignatureKey;
        QuantumAlgorithm signatureAlgorithm = QuantumAlgorithm::Dilithium3;

        // Security metadata
        QuantumSecurityLevel achievedSecurityLevel = QuantumSecurityLevel::Level3;
        QuantumThreatLevel threatAssessment = QuantumThreatLevel::Moderate;
        bool isQuantumReady = false;
        bool isHybridSession = true;

        // NSA-grade security features
        NSAClassificationLevel classificationLevel = NSAClassificationLevel::Secret;
        QStringList activeDefenses;
        bool antiForensicsEnabled = false;

        // Performance monitoring
        uint64 quantumOperations = 0;
        uint64 hybridOperations = 0;
        QDateTime lastQuantumRatchet;
        double averageQuantumLatency = 0.0;
    };

    // Quantum message metadata
    struct QuantumMessageMetadata {
        // Classical metadata
        SignalProtocol::MessageMetadata classicalMetadata;

        // Quantum metadata
        bytes::vector quantumIV;
        bytes::vector quantumAuthTag;
        bytes::vector kemEncapsulation;
        bytes::vector quantumSignature;

        // Algorithm information
        QuantumAlgorithm kemAlgorithm = QuantumAlgorithm::Kyber768;
        QuantumAlgorithm signatureAlgorithm = QuantumAlgorithm::Dilithium3;
        QuantumSecurityLevel securityLevel = QuantumSecurityLevel::Level3;

        // Security flags
        bool isQuantumProtected = true;
        bool isHybridMessage = true;
        bool hasQuantumSignature = true;
        bool antiDeviceAttestation = true;

        // NSA security metadata
        NSAClassificationLevel classification = NSAClassificationLevel::Secret;
        QStringList appliedDefenses;
        bool covertChannel = false;
        QString trafficProfile;
    };

    explicit QuantumSignalProtocol(not_null<Session*> session);
    ~QuantumSignalProtocol();

    // Initialization and configuration
    bool initializeQuantumSecurity();
    void setQuantumGuard(std::shared_ptr<QuantumGuard> quantumGuard);
    void setQuantumTSM(std::shared_ptr<QuantumTSMInterface> quantumTSM);
    void setNSASecurity(std::shared_ptr<NSASecurity> nsaSecurity);

    // Quantum threat assessment
    void updateQuantumThreatLevel(QuantumThreatLevel level);
    QuantumThreatLevel getCurrentQuantumThreatLevel() const;
    bool shouldUseQuantumProtection() const;
    bool shouldUseHybridMode() const;

    // Quantum X3DH key exchange
    QuantumKeyBundle generateQuantumKeyBundle();
    void registerQuantumKeyBundle(not_null<PeerData*> peer, const QuantumKeyBundle &bundle);
    QuantumKeyBundle getQuantumKeyBundleForPeer(not_null<PeerData*> peer);

    // Post-quantum X3DH key agreement
    base::expected<bytes::vector, QString> performQuantumX3DH(
        const QuantumKeyBundle &localBundle,
        const QuantumKeyBundle &remoteBundle);

    // Quantum Double Ratchet session management
    void createQuantumSession(not_null<PeerData*> peer, const QuantumKeyBundle &remoteBundle);
    bool hasQuantumSession(not_null<PeerData*> peer) const;
    QuantumSessionState getQuantumSession(not_null<PeerData*> peer) const;
    void updateQuantumSession(not_null<PeerData*> peer, const QuantumSessionState &state);
    void rotateQuantumSession(not_null<PeerData*> peer, bool forceQuantumRotation = false);

    // Quantum message encryption/decryption
    base::expected<bytes::vector, QString> encryptQuantumMessage(
        const bytes::const_span &plaintext,
        not_null<PeerData*> peer,
        QuantumMessageMetadata &outMetadata);

    base::expected<bytes::vector, QString> decryptQuantumMessage(
        const bytes::const_span &ciphertext,
        not_null<PeerData*> peer,
        const QuantumMessageMetadata &metadata);

    // Hybrid message operations (classical + quantum)
    base::expected<bytes::vector, QString> encryptHybridMessage(
        const bytes::const_span &plaintext,
        not_null<PeerData*> peer,
        QuantumMessageMetadata &outMetadata);

    base::expected<bytes::vector, QString> decryptHybridMessage(
        const bytes::const_span &ciphertext,
        not_null<PeerData*> peer,
        const QuantumMessageMetadata &metadata);

    // Anti-device attestation protection
    bool detectDeviceAttestationAttempt(const bytes::const_span &messageData);
    void enableAntiDeviceAttestation(bool enabled);
    bool isAntiDeviceAttestationEnabled() const;

    // Perfect Forward Secrecy with quantum resistance
    void enableQuantumPerfectForwardSecrecy(bool enabled);
    void scheduleQuantumKeyRotation(not_null<PeerData*> peer, TimeId scheduleTime);
    void performQuantumKeyRotations();
    TimeId getQuantumKeyRotationInterval() const;
    void setQuantumKeyRotationInterval(TimeId interval);

    // Quantum-safe backup and recovery
    base::expected<QByteArray, QString> backupQuantumKeys(const QString &password);
    base::expected<bool, QString> restoreQuantumKeys(
        const QByteArray &backup,
        const QString &password);

    // Migration from classical to quantum
    void enableQuantumMigration(bool enabled);
    bool isQuantumMigrationEnabled() const;
    base::expected<bool, QString> migrateSessionToQuantum(not_null<PeerData*> peer);
    QuantumMigrationStatus getSessionMigrationStatus(not_null<PeerData*> peer) const;

    // NSA-grade security integration
    void enableNSAGradeSecurity(bool enabled);
    bool isNSAGradeSecurityEnabled() const;
    void setClassificationLevel(NSAClassificationLevel level);
    NSAClassificationLevel getCurrentClassificationLevel() const;

    // Advanced countermeasures
    void enableQuantumCountermeasures();
    void enableNationStateCountermeasures();
    void enableAPTCountermeasures();
    void enableCovertMessaging(bool enabled);
    void setTrafficObfuscationProfile(const QString &profileName);

    // Performance monitoring
    struct QuantumSignalMetrics {
        uint64 quantumMessagesEncrypted = 0;
        uint64 quantumMessagesDecrypted = 0;
        uint64 hybridMessagesProcessed = 0;
        uint64 quantumSessionsCreated = 0;
        uint64 quantumKeyRotations = 0;
        uint64 deviceAttestationBlocked = 0;

        double averageQuantumEncryptTime = 0.0;
        double averageQuantumDecryptTime = 0.0;
        double averageHybridOverhead = 0.0;
        double averageKeyRotationTime = 0.0;

        QuantumAlgorithm fastestKEM = QuantumAlgorithm::Kyber768;
        QuantumAlgorithm fastestSignature = QuantumAlgorithm::Dilithium3;

        QDateTime lastQuantumOperation;
        QString lastThreatDetected;
        NSAClassificationLevel highestClassificationUsed = NSAClassificationLevel::Unclassified;
    };

    QuantumSignalMetrics getQuantumMetrics() const;
    void resetQuantumMetrics();

    // Hardware acceleration
    void enableQuantumHardwareAcceleration(bool enabled);
    bool isQuantumHardwareAccelerationEnabled() const;
    QStringList getAvailableQuantumAccelerators() const;

signals:
    void quantumSessionCreated(PeerId peerId, QuantumSecurityLevel level);
    void quantumThreatDetected(PeerId peerId, QuantumThreatLevel level);
    void quantumKeyRotationCompleted(PeerId peerId);
    void deviceAttestationBlocked(PeerId peerId, const QString &reason);
    void quantumMigrationCompleted(PeerId peerId, QuantumMigrationStatus status);
    void nsaSecurityEventDetected(const NSASecurityEvent &event);
    void classificationLevelChanged(NSAClassificationLevel level);
    void quantumHardwareStatusChanged(bool available);

private:
    // Core implementations
    class QuantumSignalProtocolPrivate;
    std::unique_ptr<QuantumSignalProtocolPrivate> d;

    // Quantum cryptographic primitives
    bytes::vector quantumKDF(
        const bytes::const_span &inputKeyMaterial,
        const QString &info,
        int outputLength);

    bytes::vector quantumHMAC(
        const bytes::const_span &key,
        const bytes::const_span &data);

    bytes::vector hybridKDF(
        const bytes::const_span &classicalIKM,
        const bytes::const_span &quantumIKM,
        const QString &info,
        int outputLength);

    // Quantum Double Ratchet operations
    bytes::vector quantumRatchetRootKey(const QuantumSessionState &state);
    bytes::vector quantumRatchetChainKey(const bytes::const_span &chainKey);

    struct QuantumRatchetResult {
        bytes::vector newRootKey;
        bytes::vector newChainKey;
        bytes::vector messageKey;
    };

    QuantumRatchetResult performQuantumDoubleRatchet(
        const QuantumSessionState &state,
        const bytes::const_span &remotePublicKey);

    // Session serialization with quantum data
    QByteArray serializeQuantumSession(const QuantumSessionState &state);
    QuantumSessionState deserializeQuantumSession(const QByteArray &data);

    // Quantum key generation and management
    bytes::vector generateQuantumDH();
    bytes::vector generateQuantumRandomBytes(int length);
    std::pair<bytes::vector, bytes::vector> generateQuantumKeyPair(QuantumAlgorithm algorithm);

    // Anti-device attestation implementation
    bool containsDeviceAttestationData(const bytes::const_span &data);
    bytes::vector obfuscateDeviceAttestationData(const bytes::const_span &data);
    void blockTelegramKeyExchange(const bytes::const_span &suspiciousData);

    // NSA security integration
    void applyNSASecurityPolicies(QuantumMessageMetadata &metadata);
    void enableCovertChannelIfNeeded(const QuantumMessageMetadata &metadata);
    void performTrafficObfuscation(bytes::vector &messageData);

    // Threat detection and response
    void assessQuantumThreat(const QuantumMessageMetadata &metadata);
    void respondToQuantumThreat(QuantumThreatLevel level, not_null<PeerData*> peer);
    void updateThreatIntelligence(const NSASecurityEvent &event);

    // Performance optimization
    void optimizeForQuantumHardware();
    QuantumAlgorithm selectOptimalAlgorithm(QuantumKeyType keyType);
    void cacheQuantumOperations();

    // Migration helpers
    bool canMigrateSession(const SignalProtocol::SessionState &classicalState);
    QuantumSessionState createQuantumFromClassical(
        const SignalProtocol::SessionState &classicalState);

    // Hardware integration
    void detectQuantumHardware();
    void configureQuantumAcceleration();
    bool isQuantumAccelerationAvailable() const;

    // State management
    bool _quantumSecurityInitialized = false;
    bool _quantumEnabled = false;
    bool _hybridModeEnabled = true;
    bool _antiDeviceAttestationEnabled = true;
    bool _quantumMigrationEnabled = false;
    bool _nsaGradeSecurityEnabled = false;
    bool _covertMessagingEnabled = false;
    bool _quantumHardwareAccelEnabled = false;

    QuantumThreatLevel _currentQuantumThreatLevel = QuantumThreatLevel::Moderate;
    NSAClassificationLevel _currentClassificationLevel = NSAClassificationLevel::Secret;
    TimeId _quantumKeyRotationInterval = 60 * 60 * 24 * 3; // 3 days for quantum

    not_null<Session*> _session;
    std::shared_ptr<QuantumGuard> _quantumGuard;
    std::shared_ptr<QuantumTSMInterface> _quantumTSM;
    std::shared_ptr<NSASecurity> _nsaSecurity;

    // Quantum session storage
    base::flat_map<PeerId, QuantumSessionState> _quantumSessions;
    base::flat_map<PeerId, QuantumKeyBundle> _peerQuantumBundles;
    base::flat_map<PeerId, QuantumMigrationStatus> _migrationStatus;

    // Performance metrics
    mutable QuantumSignalMetrics _quantumMetrics;

    // Threat tracking
    base::flat_map<PeerId, QuantumThreatLevel> _peerThreatLevels;
    std::vector<NSASecurityEvent> _recentSecurityEvents;

    // Hardware state
    QStringList _availableQuantumAccelerators;
    bool _quantumHardwareAvailable = false;
};

// Factory for creating quantum-enhanced Signal Protocol
class QuantumSignalProtocolFactory {
public:
    // Create quantum Signal Protocol optimized for threat level
    static std::unique_ptr<QuantumSignalProtocol> createForThreatLevel(
        not_null<Session*> session,
        QuantumThreatLevel threatLevel);

    // Create with specific security requirements
    static std::unique_ptr<QuantumSignalProtocol> createForClassificationLevel(
        not_null<Session*> session,
        NSAClassificationLevel classificationLevel);

    // Create with quantum hardware acceleration
    static std::unique_ptr<QuantumSignalProtocol> createWithQuantumHardware(
        not_null<Session*> session);

    // Migration from classical Signal Protocol
    static std::unique_ptr<QuantumSignalProtocol> migrateFromClassical(
        not_null<Session*> session,
        SignalProtocol *classicalProtocol);

    // Platform optimization
    static std::unique_ptr<QuantumSignalProtocol> createOptimizedForPlatform(
        not_null<Session*> session,
        TSMPlatform platform);
};

} // namespace Data