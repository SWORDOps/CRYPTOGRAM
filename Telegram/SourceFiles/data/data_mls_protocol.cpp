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
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/curve25519.h>
#include <limits>
#include <algorithm>

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
constexpr int kSHA384Size = 48;
constexpr int kSHA512Size = 64;
constexpr int kAES128KeySize = 16;
constexpr int kAES256KeySize = 32;
constexpr int kChaCha20KeySize = 32;
constexpr int kAeadNonceSize = 12;
constexpr int kAeadTagSize = 16;

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

// Compute SHA-256 hash
bytes::vector computeSHA256(const bytes::vector &data) {
	bytes::vector result(kSHA256Size);
	SHA256(data.data(), data.size(), result.data());
	return result;
}

// Compute SHA-384 hash
bytes::vector computeSHA384(const bytes::vector &data) {
	bytes::vector result(kSHA384Size);
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

const EVP_CIPHER* aeadCipherFor(MLSCiphersuite ciphersuite) {
	switch (ciphersuite) {
	case MLSCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
		return EVP_aes_128_gcm();
	case MLSCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519:
	case MLSCiphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448:
		return EVP_chacha20_poly1305();
	}
	return EVP_chacha20_poly1305();
}

int aeadKeySizeFor(MLSCiphersuite ciphersuite) {
	switch (ciphersuite) {
	case MLSCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
		return kAES128KeySize;
	case MLSCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519:
	case MLSCiphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448:
		return kChaCha20KeySize;
	}
	return kChaCha20KeySize;
}

std::optional<bytes::vector> aeadEncrypt(
	MLSCiphersuite ciphersuite,
	const bytes::vector &key,
	const bytes::vector &nonce,
	const bytes::vector &plaintext,
	const bytes::vector &aad) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return std::nullopt;

	const auto *cipher = aeadCipherFor(ciphersuite);
	if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return std::nullopt;
	}
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce.size(), nullptr) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return std::nullopt;
	}
	if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return std::nullopt;
	}

	int outLen = 0;
	if (!aad.empty()) {
		if (EVP_EncryptUpdate(ctx, nullptr, &outLen, aad.data(), aad.size()) != 1) {
			EVP_CIPHER_CTX_free(ctx);
			return std::nullopt;
		}
	}

	bytes::vector ciphertext(plaintext.size());
	if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outLen, plaintext.data(), plaintext.size()) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return std::nullopt;
	}
	int finalLen = 0;
	if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen, &finalLen) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return std::nullopt;
	}
	ciphertext.resize(outLen + finalLen);

	bytes::vector tag(kAeadTagSize);
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag.size(), tag.data()) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return std::nullopt;
	}
	EVP_CIPHER_CTX_free(ctx);

	bytes::vector out;
	out.reserve(ciphertext.size() + tag.size());
	out.insert(out.end(), ciphertext.begin(), ciphertext.end());
	out.insert(out.end(), tag.begin(), tag.end());
	return out;
}

std::optional<bytes::vector> aeadDecrypt(
	MLSCiphersuite ciphersuite,
	const bytes::vector &key,
	const bytes::vector &nonce,
	const bytes::vector &ciphertextAndTag,
	const bytes::vector &aad) {
	if (ciphertextAndTag.size() < kAeadTagSize) return std::nullopt;
	const auto cipherLen = ciphertextAndTag.size() - kAeadTagSize;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return std::nullopt;

	const auto *cipher = aeadCipherFor(ciphersuite);
	if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return std::nullopt;
	}
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce.size(), nullptr) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return std::nullopt;
	}
	if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return std::nullopt;
	}

	int outLen = 0;
	if (!aad.empty()) {
		if (EVP_DecryptUpdate(ctx, nullptr, &outLen, aad.data(), aad.size()) != 1) {
			EVP_CIPHER_CTX_free(ctx);
			return std::nullopt;
		}
	}

	bytes::vector plaintext(cipherLen);
	if (EVP_DecryptUpdate(
			ctx,
			plaintext.data(),
			&outLen,
			ciphertextAndTag.data(),
			cipherLen) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return std::nullopt;
	}
	if (EVP_CIPHER_CTX_ctrl(
			ctx,
			EVP_CTRL_AEAD_SET_TAG,
			kAeadTagSize,
			const_cast<uint8_t*>(ciphertextAndTag.data() + cipherLen)) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return std::nullopt;
	}

	int finalLen = 0;
	if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen, &finalLen) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return std::nullopt;
	}
	EVP_CIPHER_CTX_free(ctx);
	plaintext.resize(outLen + finalLen);
	return plaintext;
}

// TreeKEM tree size calculation
MLSNodeIndex treeSize(MLSLeafIndex leafCount) {
	if (leafCount == 0) return 0;
	return 2 * leafCount - 1;
}

// Get parent node index
std::optional<MLSNodeIndex> parentIndex(MLSNodeIndex index, MLSNodeIndex treeSize) {
	if (index >= treeSize || index == 0) {
		return std::nullopt;
	}

	// Full binary tree, zero-based array indexing: parent(i) = (i - 1) / 2
	auto parent = (index - 1) / 2;
	if (parent >= treeSize) {
		return std::nullopt;
	}
	return parent;
}

// Get left child index
std::optional<MLSNodeIndex> leftChild(MLSNodeIndex index) {
	if (index > (std::numeric_limits<MLSNodeIndex>::max() - 1) / 2) {
		return std::nullopt;
	}
	return 2 * index;
}

// Get right child index
std::optional<MLSNodeIndex> rightChild(MLSNodeIndex index) {
	if (index > (std::numeric_limits<MLSNodeIndex>::max() - 2) / 2) {
		return std::nullopt;
	}
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
	if (initialMembers.isEmpty()) {
		LOG(("MLS: createGroup rejected - no initial members"));
		return MLSGroupId();
	}

	QSet<UserId> seenMembers;
	QVector<UserId> dedupedMembers;
	dedupedMembers.reserve(initialMembers.size());
	for (const auto memberId : initialMembers) {
		if (seenMembers.contains(memberId)) {
			continue;
		}
		seenMembers.insert(memberId);
		dedupedMembers.append(memberId);
	}

	// Generate unique group ID
	auto groupId = generateRandomBytes(32);

	// Create group state
	MLSGroupState state(groupId, ciphersuite);

	// Generate key packages for all initial members
	QVector<MLSKeyPackage> keyPackages;
	for (const auto userId : dedupedMembers) {
		// Generate local key packages for bootstrap. Production deploys can
		// replace this with distribution/fetch of remote member key packages.
		auto keyPackage = generateKeyPackage(ciphersuite);
		keyPackages.append(keyPackage);
	}

	// Initialize ratchet tree
	initializeTree(state, keyPackages);

	// Add members to state
	for (int i = 0; i < dedupedMembers.size(); ++i) {
		MLSGroupMember member;
		member.userId = dedupedMembers[i];
		member.leafIndex = i;
		member.keyPackage = keyPackages[i];
		member.addedAt = QDateTime::currentDateTime();
		member.isActive = true;

		state._members[dedupedMembers[i]] = member;
		state._leafToUser[i] = dedupedMembers[i];
	}

	// Initialize cryptographic state
	state._initSecret = generateRandomBytes(getHashSize(ciphersuite));
	state._epochSecret = state.deriveEpochSecret();

	// Store group state
	_groups[groupId] = state;

	LOG(("MLS: Created group with %1 members, epoch 0").arg(dedupedMembers.size()));

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
	proposal.newMember = newMember;
	proposal.addKeyPackage = keyPackage;
	proposal.timestamp = QDateTime::currentDateTime();
	proposal.sender = newMember;

	// Add to pending proposals
	_pendingProposals[groupId].append(proposal);
	MLSCommit commit;
	commit.proposals = _pendingProposals[groupId];
	commit.sender = newMember;
	commit.timestamp = QDateTime::currentDateTime();
	const auto result = processCommit(groupId, commit);
	if (!result) {
		_pendingProposals[groupId].clear();
	}
	return result;
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
	proposal.sender = memberToRemove;
	proposal.timestamp = QDateTime::currentDateTime();

	// Add to pending proposals
	_pendingProposals[groupId].append(proposal);
	MLSCommit commit;
	commit.proposals = _pendingProposals[groupId];
	commit.sender = memberToRemove;
	commit.timestamp = QDateTime::currentDateTime();
	const auto result = processCommit(groupId, commit);
	if (!result) {
		_pendingProposals[groupId].clear();
	}
	return result;
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
	proposal.sender = it.value().members().empty()
		? UserId()
		: it.value().members().front().userId;
	proposal.timestamp = QDateTime::currentDateTime();

	if (proposal.sender == UserId()) {
		LOG(("MLS: Cannot update key - no members in group"));
		return false;
	}

	// Add to pending proposals and commit immediately.
	_pendingProposals[groupId].append(proposal);
	MLSCommit commit;
	commit.proposals = _pendingProposals[groupId];
	commit.sender = proposal.sender;
	commit.timestamp = QDateTime::currentDateTime();
	const auto result = processCommit(groupId, commit);
	if (!result) {
		_pendingProposals[groupId].clear();
	}
	return result;
}

bool MLSProtocol::removeGroup(const MLSGroupId &groupId) {
	if (groupId.empty() || !_groups.contains(groupId)) {
		return false;
	}
	_groups.remove(groupId);
	_pendingProposals.remove(groupId);
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

	// Derive per-epoch application key and nonce
	auto appSecret = state.deriveApplicationSecret(kLabelApplication);
	auto key = hkdfExpand(appSecret, "mls-msg-key", aeadKeySizeFor(state.ciphersuite()));
	auto nonce = generateRandomBytes(kAeadNonceSize);
	bytes::vector aad;
	aad.resize(sizeof(state._epoch) + groupId.size());
	std::memcpy(aad.data(), &state._epoch, sizeof(state._epoch));
	if (!groupId.empty()) {
		std::memcpy(aad.data() + sizeof(state._epoch), groupId.data(), groupId.size());
	}
	const auto sealed = aeadEncrypt(state.ciphersuite(), key, nonce, plaintext, aad);
	if (!sealed.has_value()) {
		LOG(("MLS: AEAD encryption failed"));
		return {};
	}

	// Message format: [epoch(8)][nonce(12)][ciphertext|tag]
	bytes::vector result(8 + kAeadNonceSize);
	std::memcpy(result.data(), &state._epoch, sizeof(state._epoch));
	std::memcpy(result.data() + 8, nonce.data(), kAeadNonceSize);
	result.insert(result.end(), sealed->begin(), sealed->end());

	LOG(("MLS: Encrypted message for epoch %1").arg(state._epoch));

	return result;
}

std::optional<bytes::vector> MLSProtocol::decryptMessage(
	const MLSGroupId &groupId,
	const bytes::vector &ciphertext) {

	if (ciphertext.size() < (8 + kAeadNonceSize + kAeadTagSize)) {
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

	// Derive per-epoch application key and decrypt
	auto appSecret = state.deriveApplicationSecret(kLabelApplication);
	auto key = hkdfExpand(appSecret, "mls-msg-key", aeadKeySizeFor(state.ciphersuite()));
	bytes::vector nonce(ciphertext.begin() + 8, ciphertext.begin() + 8 + kAeadNonceSize);
	bytes::vector payload(ciphertext.begin() + 8 + kAeadNonceSize, ciphertext.end());
	bytes::vector aad;
	aad.resize(sizeof(messageEpoch) + groupId.size());
	std::memcpy(aad.data(), &messageEpoch, sizeof(messageEpoch));
	if (!groupId.empty()) {
		std::memcpy(aad.data() + sizeof(messageEpoch), groupId.data(), groupId.size());
	}
	const auto plaintext = aeadDecrypt(state.ciphersuite(), key, nonce, payload, aad);
	if (!plaintext.has_value()) {
		LOG(("MLS: AEAD decryption failed"));
		return std::nullopt;
	}

	LOG(("MLS: Decrypted message from epoch %1").arg(messageEpoch));

	return plaintext.value();
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

	// Generate credential key (signature key) using Ed25519/Ed448.
	const bool useEd448 =
		(ciphersuite == MLSCiphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448);
	const int sigType = useEd448 ? EVP_PKEY_ED448 : EVP_PKEY_ED25519;
	const size_t sigPubLen = useEd448 ? kEd448KeySize : kEd25519KeySize;
	const size_t sigPrivLen = useEd448 ? kEd448KeySize : kEd25519KeySize;

	EVP_PKEY_CTX *sigKeygen = EVP_PKEY_CTX_new_id(sigType, nullptr);
	if (!sigKeygen || EVP_PKEY_keygen_init(sigKeygen) != 1) {
		if (sigKeygen) EVP_PKEY_CTX_free(sigKeygen);
		return package;
	}
	EVP_PKEY *sigPkey = nullptr;
	if (EVP_PKEY_keygen(sigKeygen, &sigPkey) != 1 || !sigPkey) {
		EVP_PKEY_CTX_free(sigKeygen);
		return package;
	}
	EVP_PKEY_CTX_free(sigKeygen);

	bytes::vector credPublicKey(sigPubLen);
	bytes::vector credPrivateKey(sigPrivLen);
	size_t credPublicLenOut = credPublicKey.size();
	size_t credPrivateLenOut = credPrivateKey.size();
	if (EVP_PKEY_get_raw_public_key(sigPkey, credPublicKey.data(), &credPublicLenOut) != 1
		|| EVP_PKEY_get_raw_private_key(sigPkey, credPrivateKey.data(), &credPrivateLenOut) != 1) {
		EVP_PKEY_free(sigPkey);
		return package;
	}
	EVP_PKEY_free(sigPkey);
	credPublicKey.resize(credPublicLenOut);
	credPrivateKey.resize(credPrivateLenOut);
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
	// Derive deterministic group ID from welcome payload to avoid random state.
	bytes::vector seed = welcome.encryptedGroupInfo;
	seed.insert(seed.end(),
		welcome.encryptedGroupSecrets.begin(),
		welcome.encryptedGroupSecrets.end());
	const auto digest = hashData(seed, welcome.ciphersuite);
	MLSGroupId groupId(digest.begin(), digest.begin() + std::min<size_t>(32, digest.size()));
	if (_groups.contains(groupId)) {
		return groupId;
	}

	MLSGroupState state(groupId, welcome.ciphersuite);
	state._initSecret = hkdfExtract({}, welcome.encryptedGroupSecrets);
	state._epochSecret = state.deriveEpochSecret();
	_groups[groupId] = state;

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
		if (!processProposal(groupId, proposal)) {
			LOG(("MLS: Failed to process commit proposal"));
			return false;
		}
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
	return processProposalInternal(state, proposal);
}

bool MLSProtocol::processProposalInternal(MLSGroupState &state, const MLSProposal &proposal) {
	switch (proposal.type) {
	case MLSProposalType::Add: {
		if (!proposal.newMember.has_value() || !proposal.addKeyPackage.has_value()) {
			LOG(("MLS: Rejecting invalid Add proposal"));
			return false;
		}
		if (!verifyKeyPackage(*proposal.addKeyPackage)) {
			LOG(("MLS: Rejecting invalid key package in Add proposal"));
			return false;
		}
		if (state.isMember(*proposal.newMember)) {
			LOG(("MLS: Add proposal for existing member"));
			return false;
		}

		auto member = MLSGroupMember();
		member.userId = *proposal.newMember;
		member.leafIndex = state.memberCount();
		member.keyPackage = *proposal.addKeyPackage;
		member.addedAt = proposal.timestamp.isValid()
			? proposal.timestamp
			: QDateTime::currentDateTime();
		member.isActive = true;
		state._members[member.userId] = member;

		rebuildGroupTreeFromMembers(state);
		LOG(("MLS: Processed Add proposal"));
		return true;
	}
	case MLSProposalType::Remove: {
		std::optional<MLSLeafIndex> targetLeaf = proposal.removeLeaf;
		if (!targetLeaf.has_value() && proposal.sender != UserId() && state.isMember(proposal.sender)) {
			targetLeaf = state.getLeafIndex(proposal.sender);
		}
		if (!targetLeaf.has_value()) {
			LOG(("MLS: Rejecting Remove proposal without leaf or known sender"));
			return false;
		}
		auto userIt = state._leafToUser.find(targetLeaf.value());
		if (userIt == state._leafToUser.end()) {
			LOG(("MLS: Remove proposal for unknown leaf"));
			return false;
		}
		const auto userId = userIt.value();
		if (!state._members.contains(userId)) {
			LOG(("MLS: Remove proposal for unknown member"));
			return false;
		}
		state._members[userId].isActive = false;
		rebuildGroupTreeFromMembers(state);
		LOG(("MLS: Processed Remove proposal"));
		return true;
	}
	case MLSProposalType::Update: {
		if (!state.isMember(proposal.sender) || proposal.updateKey.empty()) {
			LOG(("MLS: Rejecting Update proposal"));
			return false;
		}
		auto member = state._members[proposal.sender];
		if (!member.isActive) {
			LOG(("MLS: Rejecting Update proposal for inactive member"));
			return false;
		}
		member.keyPackage.initKey = proposal.updateKey;
		state._members[proposal.sender] = member;
		rebuildGroupTreeFromMembers(state);
		LOG(("MLS: Processed Update proposal"));
		return true;
	}
	default:
		LOG(("MLS: Unsupported proposal type"));
		return false;
	}
}

bool MLSProtocol::rebuildGroupTreeFromMembers(MLSGroupState &state) {
	QVector<MLSGroupMember> activeMembers;
	for (auto it = state._members.begin(); it != state._members.end(); ++it) {
		if (it->isActive) {
			activeMembers.append(it.value());
		}
	}

	std::sort(
		activeMembers.begin(),
		activeMembers.end(),
		[](const MLSGroupMember &left, const MLSGroupMember &right) {
			return left.userId < right.userId;
		});
	state._members.clear();
	state._leafToUser.clear();

	QVector<MLSKeyPackage> keyPackages;
	keyPackages.reserve(activeMembers.size());
	for (const auto &member : activeMembers) {
		keyPackages.append(member.keyPackage);
	}

	if (keyPackages.isEmpty()) {
		state._ratchetTree.clear();
		return true;
	}

	initializeTree(state, keyPackages);
	for (int i = 0; i < activeMembers.size(); ++i) {
		auto member = activeMembers[i];
		member.leafIndex = static_cast<MLSLeafIndex>(i);
		state._members[member.userId] = member;
		state._leafToUser[member.leafIndex] = member.userId;
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
	if (node.publicKey.empty() || secret.empty()) {
		return {};
	}
	const auto nonce = generateRandomBytes(kAeadNonceSize);
	bytes::vector keySeed = node.publicKey;
	keySeed.insert(keySeed.end(), kLabelPath.toUtf8().begin(), kLabelPath.toUtf8().end());
	const auto keyMaterial = computeSHA256(keySeed);
	bytes::vector key(keyMaterial.begin(), keyMaterial.begin() + kChaCha20KeySize);
	const auto sealed = aeadEncrypt(
		MLSCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
		key,
		nonce,
		secret,
		{});
	if (!sealed.has_value()) return {};
	bytes::vector out = nonce;
	out.insert(out.end(), sealed->begin(), sealed->end());
	return out;
}

bytes::vector MLSProtocol::deriveSecret(const bytes::vector &secret, const QString &label) {
	return hkdfExpand(
		secret,
		label,
		getHashSize(MLSCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519));
}

bytes::vector MLSProtocol::hkdfExpand(const bytes::vector &prk, const QString &info, int length) {
	if (length <= 0) return {};
	const auto infoBytes = info.toUtf8();
	bytes::vector result;
	result.reserve(length);

	bytes::vector t;
	uint8_t counter = 1;
	while (static_cast<int>(result.size()) < length) {
		HMAC_CTX *ctx = HMAC_CTX_new();
		if (!ctx) break;
		HMAC_Init_ex(ctx, prk.data(), prk.size(), EVP_sha512(), nullptr);
		if (!t.empty()) {
			HMAC_Update(ctx, t.data(), t.size());
		}
		if (!infoBytes.empty()) {
			HMAC_Update(ctx, reinterpret_cast<const uint8_t*>(infoBytes.data()), infoBytes.size());
		}
		HMAC_Update(ctx, &counter, 1);
		t.resize(kSHA512Size);
		unsigned int outLen = 0;
		HMAC_Final(ctx, t.data(), &outLen);
		HMAC_CTX_free(ctx);
		t.resize(outLen);
		result.insert(result.end(), t.begin(), t.end());
		++counter;
	}
	result.resize(length);
	return result;
}

bytes::vector MLSProtocol::hkdfExtract(const bytes::vector &salt, const bytes::vector &ikm) {
	unsigned int outLen = kSHA512Size;
	bytes::vector out(kSHA512Size);
	HMAC(
		EVP_sha512(),
		salt.empty() ? nullptr : salt.data(),
		salt.size(),
		ikm.data(),
		ikm.size(),
		out.data(),
		&outLen);
	out.resize(outLen);
	return out;
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
		// Generate X448 key pair through EVP APIs.
		{
			EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X448, nullptr);
			if (!kctx || EVP_PKEY_keygen_init(kctx) != 1) {
				if (kctx) EVP_PKEY_CTX_free(kctx);
				return {publicKey, privateKey};
			}
			EVP_PKEY *pkey = nullptr;
			if (EVP_PKEY_keygen(kctx, &pkey) != 1 || !pkey) {
				EVP_PKEY_CTX_free(kctx);
				return {publicKey, privateKey};
			}
			EVP_PKEY_CTX_free(kctx);
			size_t publen = publicKey.size();
			size_t privlen = privateKey.size();
			if (EVP_PKEY_get_raw_public_key(pkey, publicKey.data(), &publen) != 1
				|| EVP_PKEY_get_raw_private_key(pkey, privateKey.data(), &privlen) != 1) {
				EVP_PKEY_free(pkey);
				return {publicKey, privateKey};
			}
			EVP_PKEY_free(pkey);
			publicKey.resize(publen);
			privateKey.resize(privlen);
		}
		break;
	}

	return {publicKey, privateKey};
}

bytes::vector MLSProtocol::generateEpochSecret() {
	return generateRandomBytes(kSHA512Size);
}

bytes::vector MLSProtocol::sign(const bytes::vector &data, const bytes::vector &privateKey) {
	int pkeyType = 0;
	size_t signatureSize = 0;
	if (privateKey.size() == kEd25519KeySize) {
		pkeyType = EVP_PKEY_ED25519;
		signatureSize = 64;
	} else if (privateKey.size() == kEd448KeySize) {
		pkeyType = EVP_PKEY_ED448;
		signatureSize = 114;
	} else {
		return {};
	}

	EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
		pkeyType,
		nullptr,
		privateKey.data(),
		privateKey.size());
	if (!pkey) return {};

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		EVP_PKEY_free(pkey);
		return {};
	}
	if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) != 1) {
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		return {};
	}

	bytes::vector signature(signatureSize);
	size_t outLen = signature.size();
	if (EVP_DigestSign(ctx, signature.data(), &outLen, data.data(), data.size()) != 1) {
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		return {};
	}
	signature.resize(outLen);
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return signature;
}

bool MLSProtocol::verify(const bytes::vector &data, const bytes::vector &signature, const bytes::vector &publicKey) {
	int pkeyType = 0;
	if (publicKey.size() == kEd25519KeySize) {
		pkeyType = EVP_PKEY_ED25519;
	} else if (publicKey.size() == kEd448KeySize) {
		pkeyType = EVP_PKEY_ED448;
	} else {
		return false;
	}

	EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(
		pkeyType,
		nullptr,
		publicKey.data(),
		publicKey.size());
	if (!pkey) return false;

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		EVP_PKEY_free(pkey);
		return false;
	}
	if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) != 1) {
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		return false;
	}
	const auto ok = EVP_DigestVerify(
		ctx,
		signature.data(),
		signature.size(),
		data.data(),
		data.size()) == 1;
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return ok;
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
