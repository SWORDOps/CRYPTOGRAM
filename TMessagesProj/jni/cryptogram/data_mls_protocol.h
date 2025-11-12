/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#pragma once

#include "data/data_peer.h"
#include "base/bytes.h"
#include "base/timer.h"

#include <QtCore/QByteArray>
#include <QtCore/QDateTime>
#include <QtCore/QMap>
#include <QtCore/QSet>
#include <optional>

namespace Data {

// MLS (Message Layer Security) Protocol Implementation
// RFC 9420: https://www.rfc-editor.org/rfc/rfc9420.html
//
// MLS provides efficient group key agreement with forward secrecy and
// post-compromise security. Uses TreeKEM algorithm for scalable group encryption.
//
// Key Features:
// - Forward secrecy: Past messages secure even if current keys compromised
// - Post-compromise security: Self-healing after key compromise
// - Efficient member operations: O(log n) complexity for adds/removes
// - Asynchronous: Members can be offline during group operations
// - Deniability: No cryptographic proof of authorship

// MLS Protocol Version
constexpr uint16 kMLSProtocolVersion = 1;  // MLS 1.0 (RFC 9420)

// MLS Ciphersuites (from RFC 9420 Section 17)
enum class MLSCiphersuite : uint16 {
	// Recommended ciphersuite for most use cases
	MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,

	// High security ciphersuite
	MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,

	// Maximum security (default for CRYPTOGRAM)
	MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0007,
};

// MLS Node Index (TreeKEM tree position)
using MLSNodeIndex = uint32;

// MLS Epoch (group state version)
using MLSEpoch = uint64;

// MLS Group ID
using MLSGroupId = bytes::vector;

// MLS Leaf Index (member position in tree)
using MLSLeafIndex = uint32;

// TreeKEM Node Types
enum class MLSNodeType : uint8 {
	Leaf,        // Leaf node (represents a member)
	Parent,      // Parent node (intermediate key)
};

// MLS Content Type
enum class MLSContentType : uint8 {
	Application = 1,  // Application message
	Proposal = 2,     // Group operation proposal
	Commit = 3,       // Commit proposals to group state
};

// MLS Proposal Types
enum class MLSProposalType : uint8 {
	Add = 1,       // Add new member
	Update = 2,    // Update own leaf key
	Remove = 3,    // Remove member
	PreSharedKey = 4,  // Add pre-shared key
	ReInit = 5,    // Re-initialize group
	ExternalInit = 6,  // External join
	GroupContextExtensions = 7,  // Update group extensions
};

// MLS Key Package
// Contains member's public keys and identity
struct MLSKeyPackage {
	uint16 version = kMLSProtocolVersion;
	MLSCiphersuite ciphersuite = MLSCiphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448;

	bytes::vector initKey;           // HPKE init key (public)
	bytes::vector credentialPublicKey; // Signature public key
	bytes::vector credential;        // Identity credential
	bytes::vector signature;         // Self-signature

	QDateTime creationTime;
	QDateTime expirationTime;

	bool isValid() const {
		return !initKey.empty() &&
		       !credentialPublicKey.empty() &&
		       QDateTime::currentDateTime() < expirationTime;
	}
};

// MLS Ratchet Tree Node
struct MLSTreeNode {
	MLSNodeType type;
	MLSNodeIndex index;

	// For leaf nodes
	std::optional<MLSKeyPackage> keyPackage;
	std::optional<UserId> userId;

	// For parent nodes
	bytes::vector publicKey;
	bytes::vector privateKey;  // Only if we're in the direct path

	// Tree structure
	std::optional<MLSNodeIndex> parent;
	std::optional<MLSNodeIndex> leftChild;
	std::optional<MLSNodeIndex> rightChild;

	bool isBlank() const {
		return publicKey.empty() && !keyPackage.has_value();
	}
};

// MLS Group Context
// Cryptographically bound to group state
struct MLSGroupContext {
	uint16 version = kMLSProtocolVersion;
	MLSCiphersuite ciphersuite;
	MLSGroupId groupId;
	MLSEpoch epoch = 0;
	bytes::vector treeHash;          // Hash of ratchet tree
	bytes::vector confirmedTranscriptHash;
	bytes::vector extensions;        // Group extensions
};

// MLS Proposal
struct MLSProposal {
	MLSProposalType type;
	UserId sender;

	// Proposal-specific data
	std::optional<MLSKeyPackage> addKeyPackage;  // For Add proposals
	std::optional<MLSLeafIndex> removeLeaf;      // For Remove proposals
	bytes::vector updateKey;                     // For Update proposals

	QDateTime timestamp;
};

// MLS Commit
// Commits a set of proposals to the group state
struct MLSCommit {
	std::vector<MLSProposal> proposals;
	bytes::vector path;              // UpdatePath (new key material)
	UserId sender;
	QDateTime timestamp;
};

// MLS Welcome Message
// Sent to new members to initialize their group state
struct MLSWelcome {
	uint16 version = kMLSProtocolVersion;
	MLSCiphersuite ciphersuite;
	bytes::vector encryptedGroupSecrets;
	bytes::vector encryptedGroupInfo;
	QDateTime timestamp;
};

// MLS Group Member
struct MLSGroupMember {
	UserId userId;
	MLSLeafIndex leafIndex;
	MLSKeyPackage keyPackage;
	QDateTime addedAt;
	bool isActive = true;
};

// MLS Group State
// Represents the current state of an MLS group
class MLSGroupState {
public:
	MLSGroupState(const MLSGroupId &groupId, MLSCiphersuite ciphersuite);

	// Group identification
	[[nodiscard]] MLSGroupId groupId() const { return _groupId; }
	[[nodiscard]] MLSEpoch epoch() const { return _epoch; }
	[[nodiscard]] MLSCiphersuite ciphersuite() const { return _ciphersuite; }

	// Member management
	[[nodiscard]] bool isMember(UserId userId) const;
	[[nodiscard]] std::optional<MLSLeafIndex> getLeafIndex(UserId userId) const;
	[[nodiscard]] QVector<MLSGroupMember> members() const;
	[[nodiscard]] int memberCount() const;

	// Tree operations
	[[nodiscard]] const std::vector<MLSTreeNode>& ratchetTree() const { return _ratchetTree; }
	[[nodiscard]] bytes::vector computeTreeHash() const;

	// Epoch management
	void advanceEpoch();

	// Group context
	[[nodiscard]] MLSGroupContext groupContext() const;

	// Key derivation
	[[nodiscard]] bytes::vector deriveApplicationSecret(const QString &label) const;
	[[nodiscard]] bytes::vector deriveEpochSecret() const;

private:
	MLSGroupId _groupId;
	MLSEpoch _epoch = 0;
	MLSCiphersuite _ciphersuite;

	// Ratchet tree (TreeKEM)
	std::vector<MLSTreeNode> _ratchetTree;

	// Members
	QMap<UserId, MLSGroupMember> _members;
	QMap<MLSLeafIndex, UserId> _leafToUser;

	// Cryptographic state
	bytes::vector _epochSecret;
	bytes::vector _confirmationKey;
	bytes::vector _initSecret;

	// Transcript hashes
	bytes::vector _confirmedTranscriptHash;
	bytes::vector _interimTranscriptHash;
};

// MLS Protocol Manager
// Handles MLS operations for group encryption
class MLSProtocol final {
public:
	MLSProtocol();
	~MLSProtocol();

	// Group creation
	MLSGroupId createGroup(
		const QVector<UserId> &initialMembers,
		MLSCiphersuite ciphersuite = MLSCiphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448);

	// Group operations
	bool addMember(const MLSGroupId &groupId, UserId newMember);
	bool removeMember(const MLSGroupId &groupId, UserId memberToRemove);
	bool updateOwnKey(const MLSGroupId &groupId);

	// Message operations
	bytes::vector encryptMessage(
		const MLSGroupId &groupId,
		const bytes::vector &plaintext);

	std::optional<bytes::vector> decryptMessage(
		const MLSGroupId &groupId,
		const bytes::vector &ciphertext);

	// Group state
	std::optional<MLSGroupState> getGroupState(const MLSGroupId &groupId) const;
	bool hasGroup(const MLSGroupId &groupId) const;

	// Key package management
	MLSKeyPackage generateKeyPackage(MLSCiphersuite ciphersuite);
	bool verifyKeyPackage(const MLSKeyPackage &keyPackage);

	// Welcome processing
	MLSGroupId processWelcome(const MLSWelcome &welcome);

	// Commit processing
	bool processCommit(const MLSGroupId &groupId, const MLSCommit &commit);

	// Proposal processing
	bool processProposal(const MLSGroupId &groupId, const MLSProposal &proposal);

private:
	// Group states
	QMap<MLSGroupId, MLSGroupState> _groups;

	// Pending proposals (not yet committed)
	QMap<MLSGroupId, QVector<MLSProposal>> _pendingProposals;

	// Own key packages
	QVector<MLSKeyPackage> _ownKeyPackages;

	// Private keys
	QMap<bytes::vector, bytes::vector> _privateKeys;  // publicKey -> privateKey

	// TreeKEM operations
	void initializeTree(MLSGroupState &state, const QVector<MLSKeyPackage> &keyPackages);
	void updateTreePath(MLSGroupState &state, MLSLeafIndex leafIndex, const bytes::vector &newKey);
	bytes::vector encryptPathSecret(const MLSTreeNode &node, const bytes::vector &secret);

	// Cryptographic operations
	bytes::vector deriveSecret(const bytes::vector &secret, const QString &label);
	bytes::vector hkdfExpand(const bytes::vector &prk, const QString &info, int length);
	bytes::vector hkdfExtract(const bytes::vector &salt, const bytes::vector &ikm);

	// Key generation
	std::pair<bytes::vector, bytes::vector> generateKeyPair(MLSCiphersuite ciphersuite);
	bytes::vector generateEpochSecret();

	// Signature operations
	bytes::vector sign(const bytes::vector &data, const bytes::vector &privateKey);
	bool verify(const bytes::vector &data, const bytes::vector &signature, const bytes::vector &publicKey);
};

// Global MLS instance
MLSProtocol* GetMLSProtocol();
void InitializeMLSProtocol();
void DestroyMLSProtocol();

} // namespace Data
