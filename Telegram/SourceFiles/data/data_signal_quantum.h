/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#pragma once

#include "base/bytes.h"
#include "base/expected.h"
#include "data/data_peer.h"
#include "data/data_quantum_types.h"
#include "data/data_session.h"

#include <QtCore/QByteArray>
#include <QtCore/QDateTime>
#include <QtCore/QObject>
#include <QtCore/QString>
#include <memory>
#include <vector>

namespace Data {

class QuantumGuard;
class NSASecurity;

class QuantumSignal {
public:
	QuantumSignal() = default;
	~QuantumSignal() = default;

	void initialize();
	bool isEnabled() const;
	void setEnabled(bool enabled);
	QString generateSignature(const QByteArray &data);
	bool verifySignature(const QByteArray &data, const QString &signature);

private:
	bool _enabled = false;
	QuantumSignal(const QuantumSignal &other) = delete;
	QuantumSignal &operator=(const QuantumSignal &other) = delete;
};

enum class QuantumThreatLevel {
	Minimal = 0,
	Low,
	Moderate,
	High,
	Compromised,
	Critical,
};

struct QuantumSignalMetrics {
	int quantumMessagesEncrypted = 0;
	int quantumMessagesDecrypted = 0;
	int hybridMessagesProcessed = 0;
};

struct QuantumMessageMetadata {
	bytes::vector quantumIV;
	bytes::vector quantumAuthTag;
	bytes::vector quantumSignature;
	QuantumAlgorithm kemAlgorithm = QuantumAlgorithm::ML_KEM_1024;
	QuantumAlgorithm signatureAlgorithm = QuantumAlgorithm::ML_DSA_87;
	QuantumSecurityLevel securityLevel = QuantumSecurityLevel::Level5;
	bool hasQuantumSignature = false;
	bool isHybridMessage = false;
	bool isQuantumProtected = false;
	bool antiDeviceAttestation = false;
};

class QuantumSignalProtocol final : public QObject {
	Q_OBJECT

public:
	struct QuantumKeyBundle {
		struct DeviceId {
			QString identifier;
			quint64 registrationId = 0;
		};

		DeviceId deviceId;
		QDateTime created;
		QDateTime expires;
		QByteArray classicalIdentityKey;
		QByteArray classicalSignedPreKey;
		QByteArray classicalOneTimePreKey;
		QByteArray quantumIdentityKey;
		QByteArray quantumSignedPreKey;
		QByteArray quantumOneTimePreKey;
		QByteArray quantumSignature;
		QuantumAlgorithm kemAlgorithm = QuantumAlgorithm::ML_KEM_1024;
		QuantumAlgorithm signatureAlgorithm = QuantumAlgorithm::ML_DSA_87;
		QuantumSecurityLevel securityLevel = QuantumSecurityLevel::Level5;
		bool isHybridBundle = false;
	};

	explicit QuantumSignalProtocol(not_null<Session*> session);
	~QuantumSignalProtocol() override;

	bool initializeQuantumSecurity();
	void setQuantumGuard(std::shared_ptr<QuantumGuard> quantumGuard);
	void setNSASecurity(std::shared_ptr<NSASecurity> nsaSecurity);

	QuantumKeyBundle generateQuantumKeyBundle();
	base::expected<bytes::vector, QString> performQuantumX3DH(
		const QuantumKeyBundle &localBundle,
		const QuantumKeyBundle &remoteBundle);
	base::expected<bytes::vector, QString> encryptQuantumMessage(
		const bytes::const_span &plaintext,
		not_null<PeerData*> peer,
		QuantumMessageMetadata &outMetadata);
	base::expected<bytes::vector, QString> decryptQuantumMessage(
		const bytes::const_span &ciphertext,
		not_null<PeerData*> peer,
		const QuantumMessageMetadata &metadata);

	// Result of a REAL ML-KEM encapsulation. The shared secret feeds the
	// session KDF; kemCiphertext MUST be transported to the remote key
	// holder, who decapsulates it to arrive at the same secret.
	struct QuantumKemResult {
		bytes::vector sharedSecret;
		bytes::vector kemCiphertext;
	};

	void updateQuantumThreatLevel(QuantumThreatLevel level);
	bool detectDeviceAttestationAttempt(const bytes::const_span &messageData);

	QuantumSignalMetrics getQuantumMetrics() const;
	void resetQuantumMetrics();

private:
	// Real ML-KEM encapsulation against the REMOTE bundle's KEM public key.
	// The returned kemCiphertext must be transported to the remote holder.
	base::expected<QuantumKemResult, QString> performQuantumKEM(
		const QuantumKeyBundle &remoteBundle);
	bytes::vector hybridKDF(
		const bytes::vector &classicalSecret,
		const bytes::vector &quantumSecret,
		const QString &info,
		size_t outputLength);
	bytes::vector strengthenWithNSASecurity(
		const bytes::vector &input);
	// Real X25519 ECDH between our identity and the remote bundle's
	// signed pre-key (remote key only; our private half lives in the
	// protocol instance, never in the bundle).
	base::expected<bytes::vector, QString> performClassicalX3DH(
		const QuantumKeyBundle &remoteBundle);

Q_SIGNALS:
	void quantumThreatDetected(PeerId peerId, QuantumThreatLevel level);

private:
	class QuantumSignalProtocolPrivate;
	std::unique_ptr<QuantumSignalProtocolPrivate> d;
	Session* _session = nullptr;
	bool _quantumSecurityInitialized = false;
	bool _quantumEnabled = false;
	bool _hybridModeEnabled = true;
	bool _antiDeviceAttestationEnabled = true;
	bool _nsaGradeSecurityEnabled = true;
	bool _quantumHardwareAccelEnabled = false;
	QuantumThreatLevel _currentQuantumThreatLevel = QuantumThreatLevel::Moderate;
	QuantumSignalMetrics _quantumMetrics;
};

// ---------------------------------------------------------------------------
// Ratcheted quantum sessions (per-peer, envelope version 2).
//
// A quantum session is established by ONE real ML-KEM encapsulation against
// the peer's static KEM public and then replaces the per-message PQE1
// envelopes: the two derived chains advance one message key per classic
// message in lockstep. The session state lives in the shared
// g_quantumSessions map in data_quantum_signal_impl.cpp (extended, not
// duplicated); SignalProtocol reaches it through the snapshot bridge below.
//
// Key schedule (HKDF-SHA256 EXPAND-ONLY, input used directly as PRK — the
// desktop deriveKey):
//   qRoot    = expand(PRK = ss,            info = "CryptogramQX3DH",     32)
//   qSend    = expand(PRK = qRoot,         info = "CryptogramQChainA",   32)  // initiator
//   qRecv    = expand(PRK = qRoot,         info = "CryptogramQChainB",   32)  // initiator
// (the resolver swaps the A/B labels: its send chain is ChainB). Per message:
//   qMessageKey = expand(PRK = qChain, info = "CryptogramQMessage",   32)
//   qChain     = expand(PRK = qChain, info = "CryptogramQChainStep", 32)
// ---------------------------------------------------------------------------
struct QuantumSessionSnapshot {
	bytes::vector rootKey;
	bytes::vector sendChainKey;
	bytes::vector recvChainKey;
	quint32 sendCounter = 0;
	quint32 recvCounter = 0;

	// Receive-side out-of-order storage, mirroring the classic layer's
	// skippedMessageKeys (same cap, same semantics).
	struct SkippedKey {
		quint32 messageNumber = 0;
		bytes::vector key;
	};
	std::vector<SkippedKey> skippedKeys;
};

[[nodiscard]] bool peerQuantumSessionExists(PeerId peerId);
[[nodiscard]] QuantumSessionSnapshot loadPeerQuantumSession(PeerId peerId);
void savePeerQuantumSession(PeerId peerId, const QuantumSessionSnapshot &snapshot);
void erasePeerQuantumSession(PeerId peerId);

} // namespace Data
