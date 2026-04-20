/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#include "data/data_group_encryption.h"

#include "data/data_enhanced_privacy.h"
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
	if (_mlsProtocol) {
		for (auto it = _groupToMLS.begin(); it != _groupToMLS.end(); ++it) {
			_mlsProtocol->removeGroup(it.value());
		}
	}
	_groupToMLS.clear();
	_mlsToGroup.clear();
	LOG(("GroupEncryption: Destroyed"));
}

bool GroupEncryption::createEncryptedGroup(not_null<PeerData*> group) {
	auto existingGroupId = getMLSGroupId(group);
	if (_mlsProtocol && !existingGroupId.empty() && !_mlsProtocol->hasGroup(existingGroupId)) {
		_groupToMLS.remove(group->id);
		_mlsToGroup.remove(existingGroupId);
		existingGroupId = MLSGroupId();
	}

	if (!_mlsProtocol) {
		LOG(("GroupEncryption: MLS protocol not available"));
		return false;
	}

	// Check if already encrypted
	if (!existingGroupId.empty() && _mlsProtocol->hasGroup(existingGroupId)) {
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
	if (mlsGroupId.empty()) {
		LOG(("GroupEncryption: MLS createGroup returned empty group id"));
		return false;
	}

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
	if (_mlsProtocol) {
		_mlsProtocol->removeGroup(mlsGroupId);
	}

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
	if (!EnhancedPrivacy::IsCryptogramUser(user->id)) {
		LOG(("GroupEncryption: Cannot add non-CRYPTOGRAM user to encrypted group"));
		return false;
	}

	return _mlsProtocol->addMember(mlsGroupId, user->id);
}

bool GroupEncryption::removeGroupMember(not_null<PeerData*> group, not_null<UserData*> user) {
	if (!_mlsProtocol) {
		return false;
	}

	auto mlsGroupId = getMLSGroupId(group);
	if (mlsGroupId.empty()) {
		return false;
	}

	return _mlsProtocol->removeMember(mlsGroupId, user->id);
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
		result.append(member.userId);
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
	if (plaintextBytes->empty()) {
		LOG(("GroupEncryption: Decrypted empty group message"));
		return QString();
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
	auto includeCryptogramUser = [&](UserData *user) {
		if (!user) {
			return;
		}
		const auto userId = user->id;
		if (!EnhancedPrivacy::IsCryptogramUser(userId)) {
			return;
		}
		if (!result.contains(userId)) {
			result.append(userId);
		}
	};

	// Get all members depending on group type
	if (const auto chat = group->asChat()) {
		// Regular group chat
		for (const auto &participant : chat->participants) {
			includeCryptogramUser(participant);
		}
	} else if (const auto channel = group->asChannel()) {
		// Supergroup or channel
		if (!channel->isMegagroup()) {
			LOG(("GroupEncryption: Channel encryption requires megagroup participants"));
			return result;
		}

		const auto mgInfo = channel->mgInfo.get();
		if (!mgInfo) {
			LOG(("GroupEncryption: Missing megagroup info for channel %1")
				.arg(channel->id.value()));
			return result;
		}

		for (const auto &participant : mgInfo->lastParticipants) {
			includeCryptogramUser(participant);
		}
		for (const auto &admin : mgInfo->lastAdmins) {
			includeCryptogramUser(admin.first);
		}
		if (mgInfo->creator) {
			includeCryptogramUser(mgInfo->creator);
		}

		if (result.isEmpty()
			&& channel->amIn()
			&& channel->membersCount() == 1
			&& EnhancedPrivacy::IsCryptogramUser(channel->session().user()->id)) {
			includeCryptogramUser(channel->session().user());
		}
	}

	return result;
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
