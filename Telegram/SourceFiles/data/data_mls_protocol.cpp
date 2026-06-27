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
#include <openssl/hkdf.h>
#include <openssl/core_names.h>

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

// Generate a real X25519 / X448 key pair via EVP_PKEY
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
		EVP_PKEY_get_raw_public_key(pkey, reinterpret_cast<unsigned char*>(publicKey.data()), &actualPublicKeySize) == 1 &&
		EVP_PKEY_get_raw_private_key(pkey, reinterpret_cast<unsigned char*>(privateKey.data()), &actualPrivateKeySize) == 1;
	EVP_PKEY_free(pkey);

	if (!ok) {
		return std::nullopt;
	}

	publicKey.resize(actualPublicKeySize);
	privateKey.resize(actualPrivateKeySize);
	return std::make_pair(std::move(publicKey), std::move(privateKey));
}

// Generate Ed25519 / Ed448 signature key pair
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

// Normalize a secret to a 32-byte AES-256 key
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

// AES-256-GCM encryption (returns iv || tag || ciphertext)
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
		EVP_EncryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data())) == 1;

	if (ok && aad && aadSize > 0) {
		ok = EVP_EncryptUpdate(ctx, nullptr, &outLen, aad, static_cast<int>(aadSize)) == 1;
	}
	if (ok) {
		ok = EVP_EncryptUpdate(
			ctx,
			reinterpret_cast<unsigned char*>(ciphertext.data()),
			&outLen,
			plaintext,
			static_cast<int>(plaintextSize)) == 1;
		totalLen = outLen;
	}
	if (ok) {
		ok = EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()) + totalLen, &outLen) == 1;
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

// AES-256-GCM decryption (input is iv || tag || ciphertext)
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
		EVP_DecryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast<const unsigned char*>(key.data()), iv) == 1;

	if (ok && aad && aadSize > 0) {
		ok = EVP_DecryptUpdate(ctx, nullptr, &outLen, aad, static_cast<int>(aadSize)) == 1;
	}
	if (ok) {
		ok = EVP_DecryptUpdate(
			ctx,
			reinterpret_cast<unsigned char*>(plaintext.data()),
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
		ok = EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plaintext.data()) + totalLen, &outLen) == 1;
		totalLen += outLen;
	}

	EVP_CIPHER_CTX_free(ctx);
	if (!ok) {
		return std::nullopt;
	}

	plaintext.resize(totalLen);
	return plaintext;
}

// Select HKDF digest based on hash size
const EVP_MD *selectHkdfDigestForLength(int length) {
	if (length <= kSHA256Size) {
		return EVP_sha256();
	}
	return EVP_sha512();
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
	bytes::vector result(32); // SHA-256 size
	SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), reinterpret_cast<unsigned char*>(result.data()));
	return result;
}

// Compute SHA-512 hash
bytes::vector computeSHA512(const bytes::vector &data) {
	bytes::vector result(kSHA512Size);
	SHA512(reinterpret_cast<const unsigned char*>(data.data()), data.size(), reinterpret_cast<unsigned char*>(result.data()));
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
	RAND_bytes(reinterpret_cast<unsigned char*>(result.data()), size);
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
		treeData.push_back(static_cast<std::byte>(static_cast<uint8>(node.type)));

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

	bytes::vector result(hashSize);
	const auto *md = selectHkdfDigestForLength(hashSize);
	if (HKDF_expand(
			reinterpret_cast<unsigned char*>(result.data()),
			static_cast<size_t>(hashSize),
			md,
			reinterpret_cast<const unsigned char*>(_epochSecret.data()),
			_epochSecret.size(),
			reinterpret_cast<const unsigned char*>(labelBytes.data()),
			labelBytes.size()) != 1) {
		// Fallback to hash-based derivation if HKDF fails
		auto hash = _epochSecret;
		hash.insert(hash.end(),
			reinterpret_cast<const std::byte*>(labelBytes.data()),
			reinterpret_cast<const std::byte*>(labelBytes.data() + labelBytes.size()));
		result = hashData(hash, _ciphersuite);
	}

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
	auto appSecret = normalizeAeadKey(state.deriveApplicationSecret(kLabelApplication));
	auto iv = generateRandomBytes(kGcmIvSize);
	const auto *aad = reinterpret_cast<const uint8_t*>(&state._epoch);
	auto ciphertext = encryptAesGcm(
		appSecret,
		reinterpret_cast<const uint8_t*>(plaintext.data()),
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
		reinterpret_cast<const uint8_t*>(ciphertext.data()) + sizeof(messageEpoch),
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
	package.expirationTime = package.creationTime.addDays(90);

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
	// Create group state from welcome message
	auto groupId = generateRandomBytes(32);

	MLSGroupState state(groupId, welcome.ciphersuite);

	// Initialize with a placeholder tree (real implementation would decrypt
	// the encrypted group secrets and group info from the welcome)
	state._initSecret = generateRandomBytes(getHashSize(welcome.ciphersuite));
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
			auto leafIdx = state.memberCount();
			MLSGroupMember member;
			member.userId = proposal.sender;
			member.leafIndex = leafIdx;
			member.keyPackage = proposal.addKeyPackage.value();
			member.addedAt = QDateTime::currentDateTime();
			member.isActive = true;

			state._members[proposal.sender] = member;
			state._leafToUser[leafIdx] = proposal.sender;

			LOG(("MLS: Processing Add proposal for leaf %1").arg(leafIdx));
		}
		break;

	case MLSProposalType::Remove:
		if (proposal.removeLeaf.has_value()) {
			// Blank the leaf in the tree
			auto leafIdx = proposal.removeLeaf.value();
			auto userIt = state._leafToUser.find(leafIdx);
			if (userIt != state._leafToUser.end()) {
				auto memberIt = state._members.find(userIt.value());
				if (memberIt != state._members.end()) {
					memberIt->isActive = false;
				}
				state._leafToUser.remove(leafIdx);
			}
			LOG(("MLS: Processing Remove proposal for leaf %1").arg(leafIdx));
		}
		break;

	case MLSProposalType::Update:
		// Update leaf key in tree
		if (!proposal.updateKey.empty()) {
			auto leafIdx = state.getLeafIndex(proposal.sender);
			if (leafIdx.has_value()) {
				updateTreePath(state, leafIdx.value(), proposal.updateKey);
			}
		}
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
		reinterpret_cast<const uint8_t*>(secret.data()),
		secret.size(),
		reinterpret_cast<const uint8_t*>(aad.data()),
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
	if (HKDF_expand(
			reinterpret_cast<unsigned char*>(result.data()),
			static_cast<size_t>(length),
			md,
			reinterpret_cast<const unsigned char*>(prk.data()),
			prk.size(),
			reinterpret_cast<const unsigned char*>(infoBytes.data()),
			infoBytes.size()) != 1) {
		return {};
	}
	return result;
}

bytes::vector MLSProtocol::hkdfExtract(const bytes::vector &salt, const bytes::vector &ikm) {
	const auto *md = selectHkdfDigestForLength(
		static_cast<int>(std::max(salt.size(), ikm.size())));
	bytes::vector result(EVP_MD_size(md));
	if (HKDF_extract(
			reinterpret_cast<unsigned char*>(result.data()),
			nullptr,
			md,
			reinterpret_cast<const unsigned char*>(ikm.data()),
			ikm.size(),
			reinterpret_cast<const unsigned char*>(salt.data()),
			salt.size()) != 1) {
		return computeSHA512(salt.empty() ? ikm : salt);
	}
	return result;
}

std::pair<bytes::vector, bytes::vector> MLSProtocol::generateKeyPair(MLSCiphersuite ciphersuite) {
	const auto keySize = getKeySize(ciphersuite);

	bytes::vector publicKey;
	bytes::vector privateKey;

	switch (ciphersuite) {
	case MLSCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
	case MLSCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519: {
		auto keyPair = generateRawKeyPair(EVP_PKEY_X25519, kX25519KeySize, kX25519KeySize);
		if (keyPair) {
			publicKey = std::move(keyPair->first);
			privateKey = std::move(keyPair->second);
		}
		break;
	}

	case MLSCiphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448: {
		auto keyPair = generateRawKeyPair(EVP_PKEY_X448, kX448KeySize, kX448KeySize);
		if (keyPair) {
			publicKey = std::move(keyPair->first);
			privateKey = std::move(keyPair->second);
		}
		break;
	}
	}

	if (publicKey.empty() || privateKey.empty()) {
		LOG(("MLS: Key pair generation failed for ciphersuite"));
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
		reinterpret_cast<const unsigned char*>(privateKey.data()),
		privateKey.size());
	if (!pkey) {
		LOG(("MLS: Failed to load private key for signing"));
		return {};
	}

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		EVP_PKEY_free(pkey);
		return {};
	}

	size_t sigLen = 0;
	bool ok = EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) == 1;
	if (ok) {
		ok = EVP_DigestSign(
			ctx,
			nullptr,
			&sigLen,
			reinterpret_cast<const unsigned char*>(data.data()),
			data.size()) == 1;
	}
	bytes::vector signature(sigLen);
	if (ok) {
		ok = EVP_DigestSign(
			ctx,
			reinterpret_cast<unsigned char*>(signature.data()),
			&sigLen,
			reinterpret_cast<const unsigned char*>(data.data()),
			data.size()) == 1;
	}

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);

	if (!ok) {
		LOG(("MLS: Signature generation failed"));
		return {};
	}

	signature.resize(sigLen);
	return signature;
}

bool MLSProtocol::verify(const bytes::vector &data, const bytes::vector &signature, const bytes::vector &publicKey) {
	if (signature.empty() || publicKey.empty()) {
		return false;
	}

	const auto keyType = (publicKey.size() == kEd448KeySize)
		? EVP_PKEY_ED448
		: EVP_PKEY_ED25519;
	EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(
		keyType,
		nullptr,
		reinterpret_cast<const unsigned char*>(publicKey.data()),
		publicKey.size());
	if (!pkey) {
		return false;
	}

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		EVP_PKEY_free(pkey);
		return false;
	}

	bool ok = EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1;
	int verifyResult = 0;
	if (ok) {
		verifyResult = EVP_DigestVerify(
			ctx,
			reinterpret_cast<const unsigned char*>(signature.data()),
			signature.size(),
			reinterpret_cast<const unsigned char*>(data.data()),
			data.size());
	}

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
