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
constexpr int kGcmIvSize = 12;
constexpr int kGcmTagSize = 16;

std::optional<std::pair<bytes::vector, bytes::vector>> generateRawKeyPair(
	int keyType,
	size_t publicKeySize,
	size_t privateKeySize) {
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(keyType, nullptr);
	if (!pctx) {
		return std::nullopt;
	}

	bool ok = EVP_PKEY_keygen_init(pctx) == 1;
	EVP_PKEY *pkey = nullptr;
	if (ok) {
		ok = EVP_PKEY_keygen(pctx, &pkey) == 1;
	}
	EVP_PKEY_CTX_free(pctx);

	if (!ok || !pkey) {
		if (pkey) {
			EVP_PKEY_free(pkey);
		}
		return std::nullopt;
	}

	bytes::vector publicKey(publicKeySize);
	bytes::vector privateKey(privateKeySize);
	size_t actualPublicKeySize = publicKey.size();
	size_t actualPrivateKeySize = privateKey.size();
	ok =
		EVP_PKEY_get_raw_public_key(pkey, publicKey.data(), &actualPublicKeySize) == 1 &&
		EVP_PKEY_get_raw_private_key(pkey, privateKey.data(), &actualPrivateKeySize) == 1;
	EVP_PKEY_free(pkey);

	if (!ok) {
		return std::nullopt;
	}

	publicKey.resize(actualPublicKeySize);
	privateKey.resize(actualPrivateKeySize);
	return std::make_pair(std::move(publicKey), std::move(privateKey));
}

std::optional<std::pair<bytes::vector, bytes::vector>> generateSignatureKeyPair(
	MLSCiphersuite ciphersuite) {
	switch (ciphersuite) {
	case MLSCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
	case MLSCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519:
		return generateRawKeyPair(EVP_PKEY_ED25519, kEd25519KeySize, kEd25519KeySize);
	case MLSCiphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448:
		return generateRawKeyPair(EVP_PKEY_ED448, kEd448KeySize, kEd448KeySize);
	}
	return std::nullopt;
}

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

const EVP_MD* selectHkdfDigestForLength(int length) {
	return (length > kSHA256Size) ? EVP_sha512() : EVP_sha256();
}

int digestSize(const EVP_MD *md) {
	return EVP_MD_size(md);
}

// Generate random bytes
bytes::vector generateRandomBytes(int size) {
	bytes::vector result(size);
	RAND_bytes(result.data(), size);
	return result;
}

bytes::vector normalizeAeadKey(const bytes::vector &secret) {
	bytes::vector key(kAES256KeySize);
	if (secret.empty()) {
		return key;
	}
	if (secret.size() >= key.size()) {
		std::memcpy(key.data(), secret.data(), key.size());
		return key;
	}
	std::memcpy(key.data(), secret.data(), secret.size());
	auto hash = computeSHA512(secret);
	std::memcpy(key.data() + secret.size(), hash.data(), key.size() - secret.size());
	return key;
}

std::optional<bytes::vector> encryptAesGcm(
	const bytes::vector &key,
	const uint8_t *plaintext,
	size_t plaintextSize,
	const uint8_t *aad,
	size_t aadSize,
	const bytes::vector &iv) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		return std::nullopt;
	}

	bytes::vector ciphertext(plaintextSize + kGcmTagSize);
	bytes::vector tag(kGcmTagSize);
	int outLen = 0;
	int totalLen = 0;
	bool ok =
		EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) == 1 &&
		EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1;

	if (ok && aad && aadSize > 0) {
		ok = EVP_EncryptUpdate(ctx, nullptr, &outLen, aad, static_cast<int>(aadSize)) == 1;
	}
	if (ok) {
		ok = EVP_EncryptUpdate(
			ctx,
			ciphertext.data(),
			&outLen,
			plaintext,
			static_cast<int>(plaintextSize)) == 1;
		totalLen = outLen;
	}
	if (ok) {
		ok = EVP_EncryptFinal_ex(ctx, ciphertext.data() + totalLen, &outLen) == 1;
		totalLen += outLen;
	}
	if (ok) {
		ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kGcmTagSize, tag.data()) == 1;
	}

	EVP_CIPHER_CTX_free(ctx);
	if (!ok) {
		return std::nullopt;
	}

	ciphertext.resize(totalLen);
	bytes::vector result;
	result.reserve(iv.size() + tag.size() + ciphertext.size());
	result.insert(result.end(), iv.begin(), iv.end());
	result.insert(result.end(), tag.begin(), tag.end());
	result.insert(result.end(), ciphertext.begin(), ciphertext.end());
	return result;
}

std::optional<bytes::vector> decryptAesGcm(
	const bytes::vector &key,
	const uint8_t *ciphertext,
	size_t ciphertextSize,
	const uint8_t *aad,
	size_t aadSize) {
	if (ciphertextSize < (kGcmIvSize + kGcmTagSize)) {
		return std::nullopt;
	}

	const auto *iv = ciphertext;
	const auto *tag = ciphertext + kGcmIvSize;
	const auto *payload = ciphertext + kGcmIvSize + kGcmTagSize;
	const auto payloadSize = ciphertextSize - kGcmIvSize - kGcmTagSize;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		return std::nullopt;
	}

	bytes::vector plaintext(payloadSize + kGcmTagSize);
	int outLen = 0;
	int totalLen = 0;
	bool ok =
		EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kGcmIvSize, nullptr) == 1 &&
		EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv) == 1;

	if (ok && aad && aadSize > 0) {
		ok = EVP_DecryptUpdate(ctx, nullptr, &outLen, aad, static_cast<int>(aadSize)) == 1;
	}
	if (ok) {
		ok = EVP_DecryptUpdate(
			ctx,
			plaintext.data(),
			&outLen,
			payload,
			static_cast<int>(payloadSize)) == 1;
		totalLen = outLen;
	}
	if (ok) {
		ok = EVP_CIPHER_CTX_ctrl(
			ctx,
			EVP_CTRL_GCM_SET_TAG,
			kGcmTagSize,
			const_cast<uint8_t*>(tag)) == 1;
	}
	if (ok) {
		ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + totalLen, &outLen) == 1;
		totalLen += outLen;
	}

	EVP_CIPHER_CTX_free(ctx);
	if (!ok) {
		return std::nullopt;
	}

	plaintext.resize(totalLen);
	return plaintext;
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
		// Current repo state generates local key packages for the initial tree.
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
	proposal.proposer = !state._members.isEmpty()
		? state._members.first().userId
		: UserId(0);
	proposal.targetUser = newMember;
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
	proposal.proposer = !state._members.isEmpty()
		? state._members.first().userId
		: UserId(0);
	proposal.targetUser = memberToRemove;
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
	const auto &state = it.value();
	if (state._members.isEmpty()) {
		LOG(("MLS: Cannot update key - no local member"));
		return false;
	}

	// Generate new key pair
	auto [publicKey, privateKey] = generateKeyPair(state.ciphersuite());
	if (publicKey.empty()) {
		LOG(("MLS: Cannot update key - key generation failed"));
		return false;
	}

	// Create Update proposal
	MLSProposal proposal;
	proposal.type = MLSProposalType::Update;
	proposal.proposer = state._members.first().userId;
	proposal.targetUser = state._members.first().userId;
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
	auto appSecret = normalizeAeadKey(state.deriveApplicationSecret(kLabelApplication));
	auto iv = generateRandomBytes(kGcmIvSize);
	const auto *aad = reinterpret_cast<const uint8_t*>(&state._epoch);
	auto ciphertext = encryptAesGcm(
		appSecret,
		plaintext.data(),
		plaintext.size(),
		aad,
		sizeof(state._epoch),
		iv);
	if (!ciphertext.has_value()) {
		LOG(("MLS: AEAD encryption failed"));
		return bytes::vector();
	}

	bytes::vector result(sizeof(state._epoch));
	std::memcpy(result.data(), &state._epoch, sizeof(state._epoch));
	result.insert(result.end(), ciphertext->begin(), ciphertext->end());

	LOG(("MLS: Encrypted message for epoch %1").arg(state._epoch));

	return result;
}

std::optional<bytes::vector> MLSProtocol::decryptMessage(
	const MLSGroupId &groupId,
	const bytes::vector &ciphertext) {

	if (ciphertext.size() < static_cast<int>(sizeof(MLSEpoch) + kGcmIvSize + kGcmTagSize)) {
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

	auto appSecret = normalizeAeadKey(state.deriveApplicationSecret(kLabelApplication));
	const auto *aad = reinterpret_cast<const uint8_t*>(&messageEpoch);
	auto plaintext = decryptAesGcm(
		appSecret,
		ciphertext.data() + sizeof(messageEpoch),
		ciphertext.size() - sizeof(messageEpoch),
		aad,
		sizeof(messageEpoch));
	if (!plaintext.has_value()) {
		LOG(("MLS: AEAD decryption failed"));
		return std::nullopt;
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
	if (publicKey.empty() || privateKey.empty()) {
		LOG(("MLS: Failed to generate init key package material"));
		return package;
	}
	package.initKey = publicKey;
	_privateKeys[publicKey] = privateKey;

	// Generate credential key (signature key)
	bytes::vector credPublicKey;
	bytes::vector credPrivateKey;
	if (const auto credKeyPair = generateSignatureKeyPair(ciphersuite)) {
		credPublicKey = credKeyPair->first;
		credPrivateKey = credKeyPair->second;
	} else {
		LOG(("MLS: Failed to generate credential signing key pair"));
		return package;
	}
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

	auto groupIdSource = !welcome.encryptedGroupInfo.empty()
		? welcome.encryptedGroupInfo
		: welcome.encryptedGroupSecrets;
	auto groupId = hashData(groupIdSource, welcome.ciphersuite);
	if (groupId.empty()) {
		groupId = generateRandomBytes(32);
	}

	// Create new group state from welcome
	MLSGroupState state(groupId, welcome.ciphersuite);
	state._initSecret = !welcome.encryptedGroupSecrets.empty()
		? hkdfExtract(groupId, welcome.encryptedGroupSecrets)
		: generateRandomBytes(getHashSize(welcome.ciphersuite));
	state._epochSecret = state.deriveEpochSecret();
	state._confirmedTranscriptHash = hashData(groupIdSource, welcome.ciphersuite);
	state._interimTranscriptHash = hashData(welcome.encryptedGroupSecrets, welcome.ciphersuite);
	
	_groups[groupId] = state;

	LOG(("MLS: Processed Welcome message for group %1").arg(QString::fromLatin1(groupId.toHex())));

	return groupId;
}

std::optional<MLSCommit> MLSProtocol::commitGroupChanges(const MLSGroupId &groupId) {
	auto it = _groups.find(groupId);
	if (it == _groups.end()) {
		LOG(("MLS: Cannot commit - group not found"));
		return std::nullopt;
	}

	auto &state = it.value();
	auto pendingIt = _pendingProposals.find(groupId);
	if (pendingIt == _pendingProposals.end() || pendingIt.value().isEmpty()) {
		LOG(("MLS: No pending proposals to commit"));
		return std::nullopt;
	}

	MLSCommit commit;
	for (const auto &p : pendingIt.value()) {
		commit.proposals.push_back(p);
	}
	
	// Generate update path (simplified)
	auto [publicKey, privateKey] = generateKeyPair(state.ciphersuite());
	commit.path = publicKey;
	
	commit.sender = !state._members.isEmpty()
		? state._members.first().userId
		: UserId(0);
	commit.timestamp = QDateTime::currentDateTime();

	if (!processCommit(groupId, commit)) {
		LOG(("MLS: Failed to apply local commit"));
		return std::nullopt;
	}

	LOG(("MLS: Created commit for %1 proposals").arg(commit.proposals.size()));

	return commit;
}

bool MLSProtocol::processCommit(const MLSGroupId &groupId, const MLSCommit &commit) {
	auto it = _groups.find(groupId);
	if (it == _groups.end()) {
		LOG(("MLS: Cannot process commit - group not found"));
		return false;
	}

	auto &state = it.value();
	if (commit.sender.valueOf() == 0 || !state.isMember(commit.sender)) {
		LOG(("MLS: Rejecting commit - unauthorized sender"));
		return false;
	}
	const auto senderIt = state._members.find(commit.sender);
	if (senderIt == state._members.end() || !senderIt->isActive) {
		LOG(("MLS: Rejecting commit - inactive sender"));
		return false;
	}
	if (commit.path.empty()) {
		LOG(("MLS: Rejecting commit - missing update path"));
		return false;
	}
	if (!commit.timestamp.isValid()) {
		LOG(("MLS: Rejecting commit - invalid timestamp"));
		return false;
	}

	// Process all proposals in the commit
	for (const auto &proposal : commit.proposals) {
		if (proposal.proposer.valueOf() == 0 || proposal.proposer != commit.sender) {
			LOG(("MLS: Rejecting commit - proposal proposer mismatch"));
			return false;
		}
		if (!processProposal(groupId, proposal)) {
			LOG(("MLS: Rejecting commit - invalid proposal"));
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
	if (!proposal.timestamp.isValid()) {
		LOG(("MLS: Rejecting proposal - invalid timestamp"));
		return false;
	}
	const auto isActiveMember = [&](UserId user) {
		const auto it = state._members.find(user);
		return it != state._members.end() && it->isActive;
	};

	switch (proposal.type) {
	case MLSProposalType::Add:
		if (!proposal.addKeyPackage.has_value()) {
			LOG(("MLS: Rejecting Add proposal - missing key package"));
			return false;
		}
		if (proposal.proposer.valueOf() == 0 || !isActiveMember(proposal.proposer)) {
			LOG(("MLS: Rejecting Add proposal - unauthorized proposer"));
			return false;
		}
		if (!proposal.targetUser.has_value() || proposal.targetUser->valueOf() == 0) {
			LOG(("MLS: Rejecting Add proposal - missing target"));
			return false;
		}
		if (state.isMember(*proposal.targetUser)) {
			LOG(("MLS: Rejecting Add proposal - target already member"));
			return false;
		}
		const auto &kp = proposal.addKeyPackage.value();
		if (!kp.isValid() || !verifyKeyPackage(kp)) {
			LOG(("MLS: Rejecting Add proposal - invalid key package"));
			return false;
		}

		auto nextLeaf = MLSLeafIndex(0);
		for (const auto &[leaf, _] : state._leafToUser) {
			nextLeaf = std::max(nextLeaf, MLSLeafIndex(leaf + 1));
		}

		MLSGroupMember member;
		member.userId = *proposal.targetUser;
		member.leafIndex = nextLeaf;
		member.keyPackage = kp;
		member.addedAt = QDateTime::currentDateTime();
		member.isActive = true;

		state._members[*proposal.targetUser] = member;
		state._leafToUser[nextLeaf] = *proposal.targetUser;

		LOG(("MLS: Processing Add proposal: proposer %1 added user %2 at leaf %3")
			.arg(static_cast<qulonglong>(proposal.proposer.valueOf()))
			.arg(static_cast<qulonglong>(proposal.targetUser->valueOf()))
			.arg(nextLeaf));
		break;

	case MLSProposalType::Remove:
		if (!proposal.removeLeaf.has_value()) {
			LOG(("MLS: Rejecting Remove proposal - missing leaf"));
			return false;
		}
		if (proposal.proposer.valueOf() == 0 || !isActiveMember(proposal.proposer)) {
			LOG(("MLS: Rejecting Remove proposal - unauthorized proposer"));
			return false;
		}
		if (!proposal.targetUser.has_value() || proposal.targetUser->valueOf() == 0) {
			LOG(("MLS: Rejecting Remove proposal - missing target"));
			return false;
		}
		const auto leaf = proposal.removeLeaf.value();
		const auto userIt = state._leafToUser.find(leaf);
		if (userIt == state._leafToUser.end()) {
			LOG(("MLS: Rejecting Remove proposal - leaf not found"));
			return false;
		}
		const auto user = userIt.value();
		if (user != *proposal.targetUser) {
			LOG(("MLS: Rejecting Remove proposal - target/leaf mismatch"));
			return false;
		}
		auto memberIt = state._members.find(user);
		if (memberIt == state._members.end() || !memberIt->isActive) {
			LOG(("MLS: Rejecting Remove proposal - target already inactive"));
			return false;
		}
		memberIt->isActive = false;
		state._leafToUser.remove(leaf);
		LOG(("MLS: Processing Remove proposal: proposer %1 removed leaf %2 user %3")
			.arg(static_cast<qulonglong>(proposal.proposer.valueOf()))
			.arg(leaf)
			.arg(static_cast<qulonglong>(user.valueOf())));
		break;

	case MLSProposalType::Update:
		if (proposal.proposer.valueOf() == 0 || proposal.updateKey.empty()) {
			LOG(("MLS: Rejecting Update proposal - missing proposer/key"));
			return false;
		}
		if (!isActiveMember(proposal.proposer)) {
			LOG(("MLS: Rejecting Update proposal - unauthorized proposer"));
			return false;
		}
		if (proposal.targetUser.has_value() && *proposal.targetUser != proposal.proposer) {
			LOG(("MLS: Rejecting Update proposal - target/proposer mismatch"));
			return false;
		}
		auto leaf = state.getLeafIndex(proposal.proposer);
		if (!leaf.has_value()) {
			LOG(("MLS: Rejecting Update proposal - missing leaf"));
			return false;
		}
		auto memberIt = state._members.find(proposal.proposer);
		if (memberIt != state._members.end()) {
			memberIt->keyPackage.initKey = proposal.updateKey;
		}
		const auto nodeIndex = leafToNode(leaf.value());
		if (nodeIndex < state._ratchetTree.size()
			&& state._ratchetTree[nodeIndex].keyPackage.has_value()) {
			auto kp = state._ratchetTree[nodeIndex].keyPackage.value();
			kp.initKey = proposal.updateKey;
			state._ratchetTree[nodeIndex].keyPackage = kp;
		}
		LOG(("MLS: Processing Update proposal: updated user %1")
			.arg(static_cast<qulonglong>(proposal.proposer.valueOf())));
		break;

	default:
		LOG(("MLS: Rejecting unsupported proposal type"));
		return false;
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
	if (secret.empty() || node.publicKey.empty()) {
		return {};
	}

	auto keyMaterial = computeSHA512(node.publicKey);
	auto key = normalizeAeadKey(keyMaterial);
	auto iv = generateRandomBytes(kGcmIvSize);

	bytes::vector aad(sizeof(node.index) + 1);
	std::memcpy(aad.data(), &node.index, sizeof(node.index));
	aad[sizeof(node.index)] = static_cast<uint8>(node.type);

	auto encrypted = encryptAesGcm(
		key,
		secret.data(),
		secret.size(),
		aad.data(),
		aad.size(),
		iv);
	if (!encrypted.has_value()) {
		LOG(("MLS: Failed to encrypt path secret for node %1").arg(node.index));
		return {};
	}
	return *encrypted;
}

bytes::vector MLSProtocol::deriveSecret(const bytes::vector &secret, const QString &label) {
	return hkdfExpand(
		secret,
		label,
		getHashSize(MLSCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519));
}

bytes::vector MLSProtocol::hkdfExpand(const bytes::vector &prk, const QString &info, int length) {
	if (length <= 0 || prk.empty()) {
		return {};
	}

	bytes::vector result(length);
	const auto infoBytes = info.toUtf8();
	const auto *md = selectHkdfDigestForLength(length);
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
	if (!ctx) {
		return {};
	}

	bool ok =
		EVP_PKEY_derive_init(ctx) > 0 &&
		EVP_PKEY_CTX_set_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) > 0 &&
		EVP_PKEY_CTX_set_hkdf_md(ctx, md) > 0 &&
		EVP_PKEY_CTX_set1_hkdf_key(ctx, prk.data(), static_cast<int>(prk.size())) > 0;
	if (ok && !infoBytes.isEmpty()) {
		ok = EVP_PKEY_CTX_add1_hkdf_info(
			ctx,
			reinterpret_cast<const uint8_t*>(infoBytes.data()),
			infoBytes.size()) > 0;
	}
	size_t outLen = static_cast<size_t>(length);
	if (ok) {
		ok = EVP_PKEY_derive(ctx, result.data(), &outLen) > 0;
	}
	EVP_PKEY_CTX_free(ctx);
	if (!ok) {
		return {};
	}
	result.resize(static_cast<int>(outLen));
	return result;
}

bytes::vector MLSProtocol::hkdfExtract(const bytes::vector &salt, const bytes::vector &ikm) {
	const auto *md = selectHkdfDigestForLength(
		std::max<int>(static_cast<int>(salt.size()), static_cast<int>(ikm.size())));
	const auto outputSize = digestSize(md);
	if (outputSize <= 0 || ikm.empty()) {
		return {};
	}

	bytes::vector prk(outputSize);
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
	if (!ctx) {
		return {};
	}

	bool ok =
		EVP_PKEY_derive_init(ctx) > 0 &&
		EVP_PKEY_CTX_set_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) > 0 &&
		EVP_PKEY_CTX_set_hkdf_md(ctx, md) > 0 &&
		EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm.data(), static_cast<int>(ikm.size())) > 0;
	if (ok && !salt.empty()) {
		ok = EVP_PKEY_CTX_set1_hkdf_salt(
			ctx,
			salt.data(),
			static_cast<int>(salt.size())) > 0;
	}
	size_t outLen = static_cast<size_t>(outputSize);
	if (ok) {
		ok = EVP_PKEY_derive(ctx, prk.data(), &outLen) > 0;
	}
	EVP_PKEY_CTX_free(ctx);
	if (!ok) {
		return {};
	}
	prk.resize(static_cast<int>(outLen));
	return prk;
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
		if (const auto keyPair = generateRawKeyPair(EVP_PKEY_X448, kX448KeySize, kX448KeySize)) {
			publicKey = keyPair->first;
			privateKey = keyPair->second;
		} else {
			LOG(("MLS: Failed to generate X448 key pair"));
			publicKey.clear();
			privateKey.clear();
		}
		break;
	}

	return {publicKey, privateKey};
}

bytes::vector MLSProtocol::generateEpochSecret() {
	return generateRandomBytes(kSHA512Size);
}

bytes::vector MLSProtocol::sign(const bytes::vector &data, const bytes::vector &privateKey) {
	const auto keyType = (privateKey.size() == kEd448KeySize)
		? EVP_PKEY_ED448
		: EVP_PKEY_ED25519;
	EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
		keyType,
		nullptr,
		privateKey.data(),
		privateKey.size());
	if (!pkey) {
		LOG(("MLS: Failed to create signing key"));
		return {};
	}

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		EVP_PKEY_free(pkey);
		return {};
	}

	size_t signatureSize = 0;
	bool ok =
		EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) == 1 &&
		EVP_DigestSign(ctx, nullptr, &signatureSize, data.data(), data.size()) == 1;
	bytes::vector signature(signatureSize);
	if (ok) {
		ok = EVP_DigestSign(
			ctx,
			signature.data(),
			&signatureSize,
			data.data(),
			data.size()) == 1;
	}

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);

	if (!ok) {
		LOG(("MLS: Signature generation failed"));
		return {};
	}

	signature.resize(signatureSize);
	return signature;
}

bool MLSProtocol::verify(const bytes::vector &data, const bytes::vector &signature, const bytes::vector &publicKey) {
	if (publicKey.empty() || signature.empty()) {
		return false;
	}

	const auto keyType = (publicKey.size() == kEd448KeySize)
		? EVP_PKEY_ED448
		: EVP_PKEY_ED25519;
	EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(
		keyType,
		nullptr,
		publicKey.data(),
		publicKey.size());
	if (!pkey) {
		LOG(("MLS: Failed to create verification key"));
		return false;
	}

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		EVP_PKEY_free(pkey);
		return false;
	}

	const auto verifyResult =
		EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1
		? EVP_DigestVerify(
			ctx,
			signature.data(),
			signature.size(),
			data.data(),
			data.size())
		: 0;

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return verifyResult == 1;
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
