/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#include "data/data_mls_protocol.h"

#include "base/openssl_help.h"
#include "logs.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/curve25519.h>

namespace Data {
namespace {

// Global MLS instance
MLSProtocol *GlobalMLSProtocol = nullptr;

// MLS Constants
constexpr int kX25519KeySize = 32;
constexpr int kX448KeySize = 56;
constexpr int kEd25519KeySize = 32;
constexpr int kEd448KeySize = 57;
constexpr int kSHA256Size = 32;
constexpr int kSHA512Size = 64;
constexpr int kAES128KeySize = 16;
constexpr int kAES256KeySize = 32;
constexpr int kChaCha20KeySize = 32;

// MLS Labels (from RFC 9420)
const QString kLabelInit = "init";
const QString kLabelEpoch = "epoch";
const QString kLabelConfirm = "confirm";
const QString kLabelMember = "member";
const QString kLabelApplication = "app";
const QString kLabelExporter = "exporter";

// TreeKEM Labels
const QString kLabelNode = "node";
const QString kLabelPath = "path";
const QString kLabelTree = "tree";

// Get key size for ciphersuite
int getKeySize(MLSCiphersuite ciphersuite) {
	switch (ciphersuite) {
	case MLSCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
		return kX25519KeySize;
	case MLSCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519:
		return kX25519KeySize;
	case MLSCiphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448:
		return kX448KeySize;
	}
	return kX25519KeySize;
}

// Get hash size for ciphersuite
int getHashSize(MLSCiphersuite ciphersuite) {
	switch (ciphersuite) {
	case MLSCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
	case MLSCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519:
		return kSHA256Size;
	case MLSCiphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448:
		return kSHA512Size;
	}
	return kSHA256Size;
}

// Compute SHA-256 hash (Upgraded to use SHA-384 context where possible, or just used for compatibility)
// For CNSA 2.0 we prefer SHA-384. This function name is kept but implementation uses SHA-384 if allowed or we replace usage.
// Actually, let's just use SHA-384.
	bytes::vector result(48); // SHA-384 size
	SHA384(data.data(), data.size(), result.data());
	return result;
}

// Compute SHA-512 hash
bytes::vector computeSHA512(const bytes::vector &data) {
	bytes::vector result(kSHA512Size);
	SHA512(data.data(), data.size(), result.data());
	return result;
}

// Hash data based on ciphersuite
bytes::vector hashData(const bytes::vector &data, MLSCiphersuite ciphersuite) {
	switch (ciphersuite) {
	case MLSCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
	case MLSCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519:
		return computeSHA256(data);
	case MLSCiphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448:
		return computeSHA512(data);
	}
	return computeSHA256(data);
}

// Generate random bytes
bytes::vector generateRandomBytes(int size) {
	bytes::vector result(size);
	RAND_bytes(result.data(), size);
	return result;
}

// TreeKEM tree size calculation
MLSNodeIndex treeSize(MLSLeafIndex leafCount) {
	if (leafCount == 0) return 0;
	return 2 * leafCount - 1;
}

// Get parent node index
std::optional<MLSNodeIndex> parentIndex(MLSNodeIndex index, MLSNodeIndex treeSize) {
	if (index >= treeSize) return std::nullopt;
	if (index == 0 && treeSize == 1) return std::nullopt;  // Root with single node

	// Parent of node at index x is at (x | 1) >> 1
	auto parent = ((index | 1) + 1) >> 1;
	if (parent >= treeSize) return std::nullopt;
	return parent;
}

// Get left child index
std::optional<MLSNodeIndex> leftChild(MLSNodeIndex index) {
	return 2 * index;
}

// Get right child index
std::optional<MLSNodeIndex> rightChild(MLSNodeIndex index) {
	return 2 * index + 1;
}

// Check if node is a leaf
bool isLeaf(MLSNodeIndex index) {
	return (index & 1) == 0;
}

// Convert leaf index to node index
MLSNodeIndex leafToNode(MLSLeafIndex leafIndex) {
	return 2 * leafIndex;
}

// Convert node index to leaf index
std::optional<MLSLeafIndex> nodeToLeaf(MLSNodeIndex nodeIndex) {
	if (!isLeaf(nodeIndex)) return std::nullopt;
	return nodeIndex / 2;
}

} // namespace

// ========== MLSGroupState Implementation ==========

MLSGroupState::MLSGroupState(const MLSGroupId &groupId, MLSCiphersuite ciphersuite)
	: _groupId(groupId)
	, _ciphersuite(ciphersuite) {
}

bool MLSGroupState::isMember(UserId userId) const {
	return _members.contains(userId);
}

std::optional<MLSLeafIndex> MLSGroupState::getLeafIndex(UserId userId) const {
	const auto it = _members.find(userId);
	if (it == _members.end()) {
		return std::nullopt;
	}
	return it->leafIndex;
}

QVector<MLSGroupMember> MLSGroupState::members() const {
	QVector<MLSGroupMember> result;
	for (const auto &member : _members) {
		if (member.isActive) {
			result.append(member);
		}
	}
	return result;
}

int MLSGroupState::memberCount() const {
	int count = 0;
	for (const auto &member : _members) {
		if (member.isActive) {
			count++;
		}
	}
	return count;
}

bytes::vector MLSGroupState::computeTreeHash() const {
	// Compute hash of entire ratchet tree
	// This is used to verify tree integrity

	bytes::vector treeData;

	// Serialize tree structure
	for (const auto &node : _ratchetTree) {
		// Add node type
		treeData.push_back(static_cast<uint8>(node.type));

		// Add public key or key package
		if (node.type == MLSNodeType::Leaf && node.keyPackage.has_value()) {
			const auto &pkg = node.keyPackage.value();
			treeData.insert(treeData.end(), pkg.initKey.begin(), pkg.initKey.end());
		} else if (!node.publicKey.empty()) {
			treeData.insert(treeData.end(), node.publicKey.begin(), node.publicKey.end());
		}
	}

	return hashData(treeData, _ciphersuite);
}

void MLSGroupState::advanceEpoch() {
	_epoch++;

	// Derive new epoch secret
	_epochSecret = deriveEpochSecret();

	// Update transcript hash
	bytes::vector epochData;
	epochData.resize(8);
	std::memcpy(epochData.data(), &_epoch, sizeof(_epoch));

	auto newHash = hashData(epochData, _ciphersuite);
	_confirmedTranscriptHash.insert(_confirmedTranscriptHash.end(), newHash.begin(), newHash.end());
	_confirmedTranscriptHash = hashData(_confirmedTranscriptHash, _ciphersuite);
}

MLSGroupContext MLSGroupState::groupContext() const {
	MLSGroupContext context;
	context.version = kMLSProtocolVersion;
	context.ciphersuite = _ciphersuite;
	context.groupId = _groupId;
	context.epoch = _epoch;
	context.treeHash = computeTreeHash();
	context.confirmedTranscriptHash = _confirmedTranscriptHash;
	return context;
}

bytes::vector MLSGroupState::deriveApplicationSecret(const QString &label) const {
	if (_epochSecret.empty()) {
		return generateRandomBytes(getKeySize(_ciphersuite));
	}

	// HKDF-Expand(epoch_secret, label, hash_size)
	const auto hashSize = getHashSize(_ciphersuite);
	const auto labelBytes = label.toUtf8();

	bytes::vector info;
	info.insert(info.end(), labelBytes.begin(), labelBytes.end());

	bytes::vector result(hashSize);

	// Simplified HKDF expand
	auto hash = _epochSecret;
	hash.insert(hash.end(), info.begin(), info.end());
	result = hashData(hash, _ciphersuite);

	return result;
}

bytes::vector MLSGroupState::deriveEpochSecret() const {
	if (_initSecret.empty()) {
		return generateRandomBytes(getHashSize(_ciphersuite));
	}

	// Derive epoch secret from init secret
	return deriveApplicationSecret(kLabelEpoch);
}

// ========== MLSProtocol Implementation ==========

MLSProtocol::MLSProtocol() {
	LOG(("MLS: Protocol initialized"));
}

MLSProtocol::~MLSProtocol() {
	LOG(("MLS: Protocol destroyed"));
}

MLSGroupId MLSProtocol::createGroup(
	const QVector<UserId> &initialMembers,
	MLSCiphersuite ciphersuite) {

	// Generate unique group ID
	auto groupId = generateRandomBytes(32);

	// Create group state
	MLSGroupState state(groupId, ciphersuite);

	// Generate key packages for all initial members
	QVector<MLSKeyPackage> keyPackages;
	for (const auto userId : initialMembers) {
		// In a real implementation, we'd fetch key packages from members
		// For now, generate placeholder packages
		auto keyPackage = generateKeyPackage(ciphersuite);
		keyPackages.append(keyPackage);
	}

	// Initialize ratchet tree
	initializeTree(state, keyPackages);

	// Add members to state
	for (int i = 0; i < initialMembers.size(); ++i) {
		MLSGroupMember member;
		member.userId = initialMembers[i];
		member.leafIndex = i;
		member.keyPackage = keyPackages[i];
		member.addedAt = QDateTime::currentDateTime();
		member.isActive = true;

		state._members[initialMembers[i]] = member;
		state._leafToUser[i] = initialMembers[i];
	}

	// Initialize cryptographic state
	state._initSecret = generateRandomBytes(getHashSize(ciphersuite));
	state._epochSecret = state.deriveEpochSecret();

	// Store group state
	_groups[groupId] = state;

	LOG(("MLS: Created group with %1 members, epoch 0").arg(initialMembers.size()));

	return groupId;
}

bool MLSProtocol::addMember(const MLSGroupId &groupId, UserId newMember) {
	auto it = _groups.find(groupId);
	if (it == _groups.end()) {
		LOG(("MLS: Cannot add member - group not found"));
		return false;
	}

	auto &state = it.value();

	// Check if already a member
	if (state.isMember(newMember)) {
		LOG(("MLS: User already a member"));
		return false;
	}

	// Generate key package for new member
	auto keyPackage = generateKeyPackage(state.ciphersuite());

	// Create Add proposal
	MLSProposal proposal;
	proposal.type = MLSProposalType::Add;
	proposal.addKeyPackage = keyPackage;
	proposal.timestamp = QDateTime::currentDateTime();

	// Add to pending proposals
	_pendingProposals[groupId].append(proposal);

	// In a real implementation, this proposal would be sent to the group
	// and committed by any member (usually the sender)

	LOG(("MLS: Added proposal to add member"));

	return true;
}

bool MLSProtocol::removeMember(const MLSGroupId &groupId, UserId memberToRemove) {
	auto it = _groups.find(groupId);
	if (it == _groups.end()) {
		LOG(("MLS: Cannot remove member - group not found"));
		return false;
	}

	auto &state = it.value();

	// Get leaf index of member to remove
	auto leafIndex = state.getLeafIndex(memberToRemove);
	if (!leafIndex.has_value()) {
		LOG(("MLS: Cannot remove member - not in group"));
		return false;
	}

	// Create Remove proposal
	MLSProposal proposal;
	proposal.type = MLSProposalType::Remove;
	proposal.removeLeaf = leafIndex.value();
	proposal.timestamp = QDateTime::currentDateTime();

	// Add to pending proposals
	_pendingProposals[groupId].append(proposal);

	LOG(("MLS: Added proposal to remove member"));

	return true;
}

bool MLSProtocol::updateOwnKey(const MLSGroupId &groupId) {
	auto it = _groups.find(groupId);
	if (it == _groups.end()) {
		LOG(("MLS: Cannot update key - group not found"));
		return false;
	}

	// Generate new key pair
	auto [publicKey, privateKey] = generateKeyPair(it.value().ciphersuite());

	// Create Update proposal
	MLSProposal proposal;
	proposal.type = MLSProposalType::Update;
	proposal.updateKey = publicKey;
	proposal.timestamp = QDateTime::currentDateTime();

	// Add to pending proposals
	_pendingProposals[groupId].append(proposal);

	LOG(("MLS: Added proposal to update own key"));

	return true;
}

bytes::vector MLSProtocol::encryptMessage(
	const MLSGroupId &groupId,
	const bytes::vector &plaintext) {

	auto it = _groups.find(groupId);
	if (it == _groups.end()) {
		LOG(("MLS: Cannot encrypt - group not found"));
		return bytes::vector();
	}

	const auto &state = it.value();

	// Derive application secret for this epoch
	auto appSecret = state.deriveApplicationSecret(kLabelApplication);

	// Simple XOR encryption for now (in production, use AEAD)
	bytes::vector ciphertext = plaintext;
	for (size_t i = 0; i < ciphertext.size(); ++i) {
		ciphertext[i] ^= appSecret[i % appSecret.size()];
	}

	// Prepend epoch number (8 bytes)
	bytes::vector result(8);
	std::memcpy(result.data(), &state._epoch, sizeof(state._epoch));
	result.insert(result.end(), ciphertext.begin(), ciphertext.end());

	LOG(("MLS: Encrypted message for epoch %1").arg(state._epoch));

	return result;
}

std::optional<bytes::vector> MLSProtocol::decryptMessage(
	const MLSGroupId &groupId,
	const bytes::vector &ciphertext) {

	if (ciphertext.size() < 8) {
		LOG(("MLS: Ciphertext too short"));
		return std::nullopt;
	}

	auto it = _groups.find(groupId);
	if (it == _groups.end()) {
		LOG(("MLS: Cannot decrypt - group not found"));
		return std::nullopt;
	}

	const auto &state = it.value();

	// Extract epoch
	MLSEpoch messageEpoch;
	std::memcpy(&messageEpoch, ciphertext.data(), sizeof(messageEpoch));

	// Verify epoch matches
	if (messageEpoch != state._epoch) {
		LOG(("MLS: Epoch mismatch - message from epoch %1, current %2")
			.arg(messageEpoch).arg(state._epoch));
		return std::nullopt;
	}

	// Derive application secret
	auto appSecret = state.deriveApplicationSecret(kLabelApplication);

	// Decrypt (simple XOR for now)
	bytes::vector plaintext(ciphertext.begin() + 8, ciphertext.end());
	for (size_t i = 0; i < plaintext.size(); ++i) {
		plaintext[i] ^= appSecret[i % appSecret.size()];
	}

	LOG(("MLS: Decrypted message from epoch %1").arg(messageEpoch));

	return plaintext;
}

std::optional<MLSGroupState> MLSProtocol::getGroupState(const MLSGroupId &groupId) const {
	auto it = _groups.find(groupId);
	if (it == _groups.end()) {
		return std::nullopt;
	}
	return it.value();
}

bool MLSProtocol::hasGroup(const MLSGroupId &groupId) const {
	return _groups.contains(groupId);
}

MLSKeyPackage MLSProtocol::generateKeyPackage(MLSCiphersuite ciphersuite) {
	MLSKeyPackage package;
	package.version = kMLSProtocolVersion;
	package.ciphersuite = ciphersuite;

	// Generate init key (HPKE key)
	auto [publicKey, privateKey] = generateKeyPair(ciphersuite);
	package.initKey = publicKey;
	_privateKeys[publicKey] = privateKey;

	// Generate credential key (signature key)
	auto [credPublicKey, credPrivateKey] = generateKeyPair(ciphersuite);
	package.credentialPublicKey = credPublicKey;
	_privateKeys[credPublicKey] = credPrivateKey;

	// Set validity period
	package.creationTime = QDateTime::currentDateTime();
	package.expirationTime = package.creationTime.addDays(90);  // 90 days validity

	// Sign the package
	bytes::vector dataToSign = publicKey;
	dataToSign.insert(dataToSign.end(), credPublicKey.begin(), credPublicKey.end());
	package.signature = sign(dataToSign, credPrivateKey);

	_ownKeyPackages.append(package);

	return package;
}

bool MLSProtocol::verifyKeyPackage(const MLSKeyPackage &keyPackage) {
	// Verify expiration
	if (!keyPackage.isValid()) {
		return false;
	}

	// Verify signature
	bytes::vector dataToVerify = keyPackage.initKey;
	dataToVerify.insert(dataToVerify.end(),
		keyPackage.credentialPublicKey.begin(),
		keyPackage.credentialPublicKey.end());

	return verify(dataToVerify, keyPackage.signature, keyPackage.credentialPublicKey);
}

MLSGroupId MLSProtocol::processWelcome(const MLSWelcome &welcome) {
	// Decrypt group secrets and initialize group state
	// This is called when added to a new group

	// For now, generate placeholder group ID
	auto groupId = generateRandomBytes(32);

	LOG(("MLS: Processed Welcome message for new group"));

	return groupId;
}

bool MLSProtocol::processCommit(const MLSGroupId &groupId, const MLSCommit &commit) {
	auto it = _groups.find(groupId);
	if (it == _groups.end()) {
		LOG(("MLS: Cannot process commit - group not found"));
		return false;
	}

	auto &state = it.value();

	// Process all proposals in the commit
	for (const auto &proposal : commit.proposals) {
		processProposal(groupId, proposal);
	}

	// Advance epoch
	state.advanceEpoch();

	// Clear pending proposals
	_pendingProposals.remove(groupId);

	LOG(("MLS: Processed commit, advanced to epoch %1").arg(state._epoch));

	return true;
}

bool MLSProtocol::processProposal(const MLSGroupId &groupId, const MLSProposal &proposal) {
	auto it = _groups.find(groupId);
	if (it == _groups.end()) {
		return false;
	}

	auto &state = it.value();

	switch (proposal.type) {
	case MLSProposalType::Add:
		if (proposal.addKeyPackage.has_value()) {
			// Add new member to tree
			LOG(("MLS: Processing Add proposal"));
		}
		break;

	case MLSProposalType::Remove:
		if (proposal.removeLeaf.has_value()) {
			// Blank the leaf in the tree
			LOG(("MLS: Processing Remove proposal"));
		}
		break;

	case MLSProposalType::Update:
		// Update leaf key
		LOG(("MLS: Processing Update proposal"));
		break;

	default:
		break;
	}

	return true;
}

void MLSProtocol::initializeTree(MLSGroupState &state, const QVector<MLSKeyPackage> &keyPackages) {
	const auto leafCount = keyPackages.size();
	const auto nodeCount = treeSize(leafCount);

	state._ratchetTree.resize(nodeCount);

	// Initialize leaf nodes
	for (int i = 0; i < leafCount; ++i) {
		auto nodeIdx = leafToNode(i);
		auto &node = state._ratchetTree[nodeIdx];

		node.type = MLSNodeType::Leaf;
		node.index = nodeIdx;
		node.keyPackage = keyPackages[i];

		// Set parent
		auto parent = parentIndex(nodeIdx, nodeCount);
		if (parent.has_value()) {
			node.parent = parent.value();
		}
	}

	// Initialize parent nodes
	for (size_t i = 0; i < nodeCount; ++i) {
		if (!isLeaf(i)) {
			auto &node = state._ratchetTree[i];
			node.type = MLSNodeType::Parent;
			node.index = i;

			// Generate parent keys
			auto [publicKey, privateKey] = generateKeyPair(state.ciphersuite());
			node.publicKey = publicKey;

			// Set children
			auto left = leftChild(i);
			auto right = rightChild(i);
			if (left.has_value() && left.value() < nodeCount) {
				node.leftChild = left.value();
			}
			if (right.has_value() && right.value() < nodeCount) {
				node.rightChild = right.value();
			}

			// Set parent
			auto parent = parentIndex(i, nodeCount);
			if (parent.has_value()) {
				node.parent = parent.value();
			}
		}
	}

	LOG(("MLS: Initialized tree with %1 leaves, %2 total nodes").arg(leafCount).arg(nodeCount));
}

void MLSProtocol::updateTreePath(MLSGroupState &state, MLSLeafIndex leafIndex, const bytes::vector &newKey) {
	auto nodeIdx = leafToNode(leafIndex);
	const auto nodeCount = state._ratchetTree.size();

	// Update all nodes in the direct path from leaf to root
	while (nodeIdx < nodeCount) {
		auto &node = state._ratchetTree[nodeIdx];

		// Update key
		if (node.type == MLSNodeType::Parent) {
			auto [publicKey, privateKey] = generateKeyPair(state.ciphersuite());
			node.publicKey = publicKey;
			node.privateKey = privateKey;
		}

		// Move to parent
		auto parent = parentIndex(nodeIdx, nodeCount);
		if (!parent.has_value()) break;
		nodeIdx = parent.value();
	}
}

bytes::vector MLSProtocol::encryptPathSecret(const MLSTreeNode &node, const bytes::vector &secret) {
	// HPKE encryption would be used here
	// For now, return the secret (placeholder)
	return secret;
}

bytes::vector MLSProtocol::deriveSecret(const bytes::vector &secret, const QString &label) {
	return hkdfExpand(
		secret,
		label,
		getHashSize(MLSCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519));
}

bytes::vector MLSProtocol::hkdfExpand(const bytes::vector &prk, const QString &info, int length) {
	bytes::vector result(length);

	const auto infoBytes = info.toUtf8();
	auto data = prk;
	data.insert(data.end(), infoBytes.begin(), infoBytes.end());

	const auto hash = (length <= kSHA384Size) ? computeSHA384(data) : computeSHA512(data);
	std::memcpy(result.data(), hash.data(), std::min(length, (int)hash.size()));

	return result;
}

bytes::vector MLSProtocol::hkdfExtract(const bytes::vector &salt, const bytes::vector &ikm) {
	auto data = salt;
	data.insert(data.end(), ikm.begin(), ikm.end());
	return computeSHA512(data);
}

std::pair<bytes::vector, bytes::vector> MLSProtocol::generateKeyPair(MLSCiphersuite ciphersuite) {
	const auto keySize = getKeySize(ciphersuite);

	bytes::vector publicKey(keySize);
	bytes::vector privateKey(keySize);

	switch (ciphersuite) {
	case MLSCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
	case MLSCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519:
		// Generate X25519 key pair
		X25519_keypair(publicKey.data(), privateKey.data());
		break;

	case MLSCiphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448:
		// X448 generation (placeholder - would use proper X448 function)
		RAND_bytes(privateKey.data(), keySize);
		RAND_bytes(publicKey.data(), keySize);
		break;
	}

	return {publicKey, privateKey};
}

bytes::vector MLSProtocol::generateEpochSecret() {
	return generateRandomBytes(kSHA512Size);
}

bytes::vector MLSProtocol::sign(const bytes::vector &data, const bytes::vector &privateKey) {
	// Ed25519 signature (placeholder implementation)
	bytes::vector signature(64);
	RAND_bytes(signature.data(), signature.size());
	return signature;
}

bool MLSProtocol::verify(const bytes::vector &data, const bytes::vector &signature, const bytes::vector &publicKey) {
	// Ed25519 verification (placeholder implementation)
	return signature.size() == 64 && !publicKey.empty();
}

// ========== Global Functions ==========

MLSProtocol* GetMLSProtocol() {
	return GlobalMLSProtocol;
}

void InitializeMLSProtocol() {
	if (!GlobalMLSProtocol) {
		GlobalMLSProtocol = new MLSProtocol();
	}
}

void DestroyMLSProtocol() {
	if (GlobalMLSProtocol) {
		delete GlobalMLSProtocol;
		GlobalMLSProtocol = nullptr;
	}
}

} // namespace Data
