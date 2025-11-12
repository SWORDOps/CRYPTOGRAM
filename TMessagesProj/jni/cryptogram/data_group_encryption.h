/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#pragma once

#include "data/data_peer.h"
#include "data/data_mls_protocol.h"
#include "base/weak_ptr.h"

namespace Data {

// Group Encryption Manager
// Bridges MLS protocol with Telegram group chats
//
// Features:
// - Automatic MLS group creation for CRYPTOGRAM groups
// - Member add/remove synchronization
// - Message encryption/decryption for group messages
// - Forward secrecy and post-compromise security
// - Scalable to large groups (O(log n) operations)

class GroupEncryption final : public base::has_weak_ptr {
public:
	GroupEncryption();
	~GroupEncryption();

	// Group management
	bool createEncryptedGroup(not_null<PeerData*> group);
	bool destroyEncryptedGroup(not_null<PeerData*> group);
	bool isEncrypted(not_null<PeerData*> group) const;

	// Member operations
	bool addGroupMember(not_null<PeerData*> group, not_null<UserData*> user);
	bool removeGroupMember(not_null<PeerData*> group, not_null<UserData*> user);
	QVector<UserId> getGroupMembers(not_null<PeerData*> group) const;

	// Message operations
	bytes::vector encryptGroupMessage(
		not_null<PeerData*> group,
		const QString &plaintext);

	std::optional<QString> decryptGroupMessage(
		not_null<PeerData*> group,
		const bytes::vector &ciphertext);

	// Group state
	std::optional<MLSGroupState> getGroupState(not_null<PeerData*> group) const;
	MLSEpoch getCurrentEpoch(not_null<PeerData*> group) const;

	// Status
	bool isReady() const { return _mlsProtocol != nullptr; }
	int totalEncryptedGroups() const { return _groupToMLS.size(); }

private:
	// MLS mapping
	QMap<PeerId, MLSGroupId> _groupToMLS;    // Telegram group -> MLS group
	QMap<MLSGroupId, PeerId> _mlsToGroup;    // MLS group -> Telegram group

	// MLS protocol instance
	MLSProtocol *_mlsProtocol = nullptr;

	// Helper functions
	MLSGroupId getMLSGroupId(not_null<PeerData*> group) const;
	QVector<UserId> getCryptogramMembers(not_null<PeerData*> group) const;
};

// Global group encryption instance
GroupEncryption* GetGroupEncryption();
void InitializeGroupEncryption();
void DestroyGroupEncryption();

} // namespace Data
