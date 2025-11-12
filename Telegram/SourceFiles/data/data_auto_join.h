/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#pragma once

#include "base/weak_ptr.h"

namespace Main {
class Session;
} // namespace Main

namespace Data {

// Auto-join Channel Manager
// Automatically joins configured Telegram channels/groups on startup
//
// Features:
// - Joins multiple channels/groups (CRYPTOGRAM Updates + partner groups)
// - Handles admin approval channels (pending join requests)
// - Checks membership before attempting join
// - Handles invite links (t.me/+ format)
// - Configurable enable/disable

// Channel configuration
struct AutoJoinChannelConfig {
	QString inviteHash;          // Invite hash (e.g., "GkvkFoujMR5kODE9")
	QString name;                // Display name for logging
	bool requiresApproval;       // true if admin approval required
};

class AutoJoinChannel final : public base::has_weak_ptr {
public:
	explicit AutoJoinChannel(not_null<Main::Session*> session);
	~AutoJoinChannel();

	// Trigger auto-join process for all configured channels
	void checkAndJoinAll();

	// Check if auto-join is enabled
	[[nodiscard]] bool isEnabled() const;
	void setEnabled(bool enabled);

	// Get configured channels
	[[nodiscard]] QVector<AutoJoinChannelConfig> getChannels() const;

private:
	const not_null<Main::Session*> _session;

	// Configured channels to auto-join
	static const QVector<AutoJoinChannelConfig> kChannels;

	// Join via invite link
	void joinViaInvite(const AutoJoinChannelConfig &channel);

	// Callback handlers
	void onJoinSuccess(const QString &channelName);
	void onJoinPending(const QString &channelName);
	void onJoinFailed(const QString &channelName, const QString &error);
};

} // namespace Data
