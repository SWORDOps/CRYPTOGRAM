/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#include "data/data_group_encryption.h"

#include "data/data_enhanced_privacy.h"
#include "data/data_signal_transport.h"
#include "data/data_channel.h"
#include "data/data_chat.h"
#include "data/data_user.h"
#include "logs.h"

namespace Data {
namespace {

// Global instance
GroupEncryption *GlobalGroupEncryption = nullptr;

} // namespace

GroupEncryption::GroupEncryption() {
	// Initialize MLS protocol
	_mlsProtocol = GetMLSProtocol();

	if (!_mlsProtocol) {
		InitializeMLSProtocol();
		_mlsProtocol = GetMLSProtocol();
	}

	LOG(("GroupEncryption: Initialized"));
}

GroupEncryption::~GroupEncryption() {
	LOG(("GroupEncryption: Destroyed"));
}

bool GroupEncryption::createEncryptedGroup(not_null<PeerData*> group) {
	if (!_mlsProtocol) {
		LOG(("GroupEncryption: MLS protocol not available"));
		return false;
	}

	// Check if already encrypted
	if (isEncrypted(group)) {
		LOG(("GroupEncryption: Group already encrypted"));
		return true;
	}

	// Get CRYPTOGRAM members only
	auto members = getCryptogramMembers(group);
	if (members.isEmpty()) {
		LOG(("GroupEncryption: No CRYPTOGRAM members in group"));
		return false;
	}

	// Create MLS group
	auto mlsGroupId = _mlsProtocol->createGroup(
		members,
		MLSCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519);

	// Store mapping
	_groupToMLS[group->id] = mlsGroupId;
	_mlsToGroup[mlsGroupId] = group->id;

	LOG(("GroupEncryption: Created encrypted group with %1 members").arg(members.size()));

	return true;
}

bool GroupEncryption::destroyEncryptedGroup(not_null<PeerData*> group) {
	auto it = _groupToMLS.find(group->id);
	if (it == _groupToMLS.end()) {
		return false;
	}

	auto mlsGroupId = it.value();

	// Remove mappings
	_mlsToGroup.remove(mlsGroupId);
	_groupToMLS.erase(it);

	LOG(("GroupEncryption: Destroyed encrypted group"));

	return true;
}

bool GroupEncryption::isEncrypted(not_null<PeerData*> group) const {
	return _groupToMLS.contains(group->id);
}

bool GroupEncryption::addGroupMember(not_null<PeerData*> group, not_null<UserData*> user) {
	if (!_mlsProtocol) {
		return false;
	}

	auto mlsGroupId = getMLSGroupId(group);
	if (mlsGroupId.empty()) {
		return false;
	}

	// Only add if user is a CRYPTOGRAM user
	if (!EnhancedPrivacy::IsCryptogramUser(peerToUser(user->id))) {
		LOG(("GroupEncryption: Cannot add non-CRYPTOGRAM user to encrypted group"));
		return false;
	}

	return _mlsProtocol->addMember(mlsGroupId, peerToUser(user->id));
}

bool GroupEncryption::removeGroupMember(not_null<PeerData*> group, not_null<UserData*> user) {
	if (!_mlsProtocol) {
		return false;
	}

	auto mlsGroupId = getMLSGroupId(group);
	if (mlsGroupId.empty()) {
		return false;
	}

	return _mlsProtocol->removeMember(mlsGroupId, peerToUser(user->id));
}

QVector<UserId> GroupEncryption::getGroupMembers(not_null<PeerData*> group) const {
	if (!_mlsProtocol) {
		return QVector<UserId>();
	}

	auto mlsGroupId = getMLSGroupId(group);
	if (mlsGroupId.empty()) {
		return QVector<UserId>();
	}

	auto state = _mlsProtocol->getGroupState(mlsGroupId);
	if (!state.has_value()) {
		return QVector<UserId>();
	}

	QVector<UserId> result;
	for (const auto &member : state->members()) {
		result.push_back(member.userId);
	}

	return result;
}

bytes::vector GroupEncryption::encryptGroupMessage(
	not_null<PeerData*> group,
	const QString &plaintext) {

	if (!_mlsProtocol) {
		LOG(("GroupEncryption: MLS protocol not available"));
		return bytes::vector();
	}

	auto mlsGroupId = getMLSGroupId(group);
	if (mlsGroupId.empty()) {
		LOG(("GroupEncryption: Group not encrypted"));
		return bytes::vector();
	}

	// Convert plaintext to bytes
	auto plaintextUtf8 = plaintext.toUtf8();
	bytes::vector plaintextBytes(
		reinterpret_cast<const std::byte*>(plaintextUtf8.data()),
		reinterpret_cast<const std::byte*>(plaintextUtf8.data() + plaintextUtf8.size()));

	// Encrypt with MLS
	auto ciphertext = _mlsProtocol->encryptMessage(mlsGroupId, plaintextBytes);

	LOG(("GroupEncryption: Encrypted group message (%1 bytes)").arg(ciphertext.size()));

	return ciphertext;
}

std::optional<QString> GroupEncryption::decryptGroupMessage(
	not_null<PeerData*> group,
	const bytes::vector &ciphertext) {

	if (!_mlsProtocol) {
		LOG(("GroupEncryption: MLS protocol not available"));
		return std::nullopt;
	}

	auto mlsGroupId = getMLSGroupId(group);
	if (mlsGroupId.empty()) {
		LOG(("GroupEncryption: Group not encrypted"));
		return std::nullopt;
	}

	// Decrypt with MLS
	auto plaintextBytes = _mlsProtocol->decryptMessage(mlsGroupId, ciphertext);
	if (!plaintextBytes.has_value()) {
		LOG(("GroupEncryption: Decryption failed"));
		return std::nullopt;
	}

	// Convert bytes to QString
	QByteArray plaintextArray(
		reinterpret_cast<const char*>(plaintextBytes->data()),
		plaintextBytes->size());

	auto plaintext = QString::fromUtf8(plaintextArray);

	LOG(("GroupEncryption: Decrypted group message"));

	return plaintext;
}

std::optional<MLSGroupState> GroupEncryption::getGroupState(not_null<PeerData*> group) const {
	if (!_mlsProtocol) {
		return std::nullopt;
	}

	auto mlsGroupId = getMLSGroupId(group);
	if (mlsGroupId.empty()) {
		return std::nullopt;
	}

	return _mlsProtocol->getGroupState(mlsGroupId);
}

MLSEpoch GroupEncryption::getCurrentEpoch(not_null<PeerData*> group) const {
	auto state = getGroupState(group);
	if (!state.has_value()) {
		return 0;
	}
	return state->epoch();
}

MLSGroupId GroupEncryption::getMLSGroupId(not_null<PeerData*> group) const {
	auto it = _groupToMLS.find(group->id);
	if (it == _groupToMLS.end()) {
		return MLSGroupId();
	}
	return it.value();
}

QVector<UserId> GroupEncryption::getCryptogramMembers(not_null<PeerData*> group) const {
	QVector<UserId> result;

	// Get all members depending on group type
	if (const auto chat = group->asChat()) {
		// Regular group chat
		for (const auto &participant : chat->participants) {
			if (EnhancedPrivacy::IsCryptogramUser(peerToUser(participant->id))) {
				result.push_back(peerToUser(participant->id));
			}
		}
	} else if (const auto channel = group->asChannel()) {
		// Supergroup or channel
		// In a real implementation, we'd fetch the member list
		// For now, assume we have access to participants
		LOG(("GroupEncryption: Channel/supergroup member detection not yet implemented"));
	}

	return result;
}

// ========== MLS Welcome Transport ==========

QString GroupEncryption::buildOutgoingMLSWelcome(
		not_null<PeerData*> group,
		not_null<UserData*> newMember) {
	if (!_mlsProtocol) {
		return {};
	}

	auto mlsGroupId = getMLSGroupId(group);
	if (mlsGroupId.empty()) {
		return {};
	}

	// Build a Welcome message for the new member
	MLSWelcome welcome;
	welcome.version = kMLSProtocolVersion;
	welcome.ciphersuite = MLSCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
	welcome.timestamp = QDateTime::currentDateTime();

	// In a full implementation, the encrypted group secrets and group info
	// would be encrypted for the new member's key package init key.
	// For now, we generate placeholder encrypted blobs.
	auto state = _mlsProtocol->getGroupState(mlsGroupId);
	if (state.has_value()) {
		auto context = state->groupContext();
		// Serialize group context as the encrypted group info
		welcome.encryptedGroupInfo = context.groupId;
		welcome.encryptedGroupSecrets = state->deriveEpochSecret();
	}

	QString zwText;
	[[maybe_unused]] auto entity = SignalProtocolTransport::buildOutgoingMLSWelcome(welcome, zwText);

	LOG(("GroupEncryption: Built MLS Welcome for user %1 in group %2")
		.arg(newMember->id.value)
		.arg(group->id.value));

	return zwText;
}

bool GroupEncryption::processIncomingMLSWelcome(const MLSWelcome &welcome) {
	if (!_mlsProtocol) {
		return false;
	}

	// Process the welcome through MLS protocol
	auto groupId = _mlsProtocol->processWelcome(welcome);
	if (groupId.empty()) {
		LOG(("GroupEncryption: Failed to process MLS Welcome"));
		return false;
	}

	LOG(("GroupEncryption: Processed MLS Welcome for group"));

	return true;
}

// ========== Global Functions ==========

GroupEncryption* GetGroupEncryption() {
	return GlobalGroupEncryption;
}

void InitializeGroupEncryption() {
	if (!GlobalGroupEncryption) {
		GlobalGroupEncryption = new GroupEncryption();
	}
}

void DestroyGroupEncryption() {
	if (GlobalGroupEncryption) {
		delete GlobalGroupEncryption;
		GlobalGroupEncryption = nullptr;
	}
}

} // namespace Data
