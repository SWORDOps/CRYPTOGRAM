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

	void updateQuantumThreatLevel(QuantumThreatLevel level);
	bool detectDeviceAttestationAttempt(const bytes::const_span &messageData);

	QuantumSignalMetrics getQuantumMetrics() const;
	void resetQuantumMetrics();

private:
	base::expected<bytes::vector, QString> performQuantumKEM(
		const QuantumKeyBundle &localBundle,
		const QuantumKeyBundle &remoteBundle);
	bytes::vector hybridKDF(
		const bytes::vector &classicalSecret,
		const bytes::vector &quantumSecret,
		const QString &info,
		size_t outputLength);
	bytes::vector strengthenWithNSASecurity(
		const bytes::vector &input);

signals:
	void quantumThreatDetected(PeerId peerId, QuantumThreatLevel level);

private:
	class QuantumSignalProtocolPrivate;
	std::unique_ptr<QuantumSignalProtocolPrivate> d;
	not_null<Session*> _session = nullptr;
	bool _quantumSecurityInitialized = false;
	bool _quantumEnabled = false;
	bool _hybridModeEnabled = true;
	bool _antiDeviceAttestationEnabled = true;
	bool _nsaGradeSecurityEnabled = true;
	bool _quantumHardwareAccelEnabled = false;
	QuantumThreatLevel _currentQuantumThreatLevel = QuantumThreatLevel::Moderate;
	QuantumSignalMetrics _quantumMetrics;
};

} // namespace Data
