/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#include "data/data_auto_join.h"

#include "apiwrap.h"
#include "main/main_session.h"
#include "data/data_session.h"
#include "data/data_channel.h"
#include "core/application.h"
#include "core/core_settings.h"
#include "logs.h"

namespace Data {

// Configure channels to auto-join
// Add more channels here as needed
const QVector<AutoJoinChannelConfig> AutoJoinChannel::kChannels = {
	{
		// CRYPTOGRAM Updates (admin approval required)
		.inviteHash = "GkvkFoujMR5kODE9",
		.name = "CRYPTOGRAM Updates",
		.requiresApproval = true,
	},
	{
		// Privacy & Security News Channel
		// Public channel for privacy news and security updates
		.inviteHash = "PrivacySecurityNews",
		.name = "Privacy & Security News",
		.requiresApproval = false,
	},
	{
		// CRYPTOGRAM Support Community
		// Public group for user support and discussions
		.inviteHash = "CRYPTOGRAMSupport",
		.name = "CRYPTOGRAM Support",
		.requiresApproval = false,
	},
};

AutoJoinChannel::AutoJoinChannel(not_null<Main::Session*> session)
	: _session(session) {
}

AutoJoinChannel::~AutoJoinChannel() = default;

void AutoJoinChannel::checkAndJoinAll() {
	// Check if auto-join is enabled in settings
	if (!isEnabled()) {
		LOG(("AutoJoin: Disabled in settings"));
		return;
	}

	LOG(("AutoJoin: Starting auto-join for %1 configured channels").arg(kChannels.size()));

	// Attempt to join all configured channels
	for (const auto &channel : kChannels) {
		joinViaInvite(channel);
	}
}

bool AutoJoinChannel::isEnabled() const {
	// Auto-join enabled by default for CRYPTOGRAM
	return Core::App().settings().autoJoinCryptogramChannel();
}

void AutoJoinChannel::setEnabled(bool enabled) {
	Core::App().settings().setAutoJoinCryptogramChannel(enabled);
	Core::App().saveSettingsDelayed();
}

QVector<AutoJoinChannelConfig> AutoJoinChannel::getChannels() const {
	return kChannels;
}

void AutoJoinChannel::joinViaInvite(const AutoJoinChannelConfig &channel) {
	const auto hash = channel.inviteHash;
	const auto name = channel.name;
	const auto requiresApproval = channel.requiresApproval;

	LOG(("AutoJoin: Attempting to join '%1' (hash: %2, approval: %3)")
		.arg(name)
		.arg(hash)
		.arg(requiresApproval ? "required" : "not required"));

	// Use Telegram API to import chat invite
	_session->api().request(MTPmessages_ImportChatInvite(
		MTP_string(hash)
	)).done([=](const MTPUpdates &result) {
		_session->data().processUsers(result.data().vusers());
		_session->data().processChats(result.data().vchats());
		_session->api().applyUpdates(result);

		if (requiresApproval) {
			// For admin approval channels, this might be a pending state
			LOG(("AutoJoin: Join request sent for '%1' (pending admin approval)").arg(name));
			onJoinPending(name);
		} else {
			LOG(("AutoJoin: Successfully joined '%1'").arg(name));
			onJoinSuccess(name);
		}

	}).fail([=](const MTP::Error &error) {
		const auto errorText = error.type();
		LOG(("AutoJoin: Failed to join '%1' - %2").arg(name).arg(errorText));

		// Handle common errors
		if (errorText == u"INVITE_HASH_EXPIRED"_q) {
			LOG(("AutoJoin: Invite link for '%1' has expired").arg(name));
		} else if (errorText == u"CHANNELS_TOO_MUCH"_q) {
			LOG(("AutoJoin: User has joined too many channels (cannot join '%1')").arg(name));
		} else if (errorText == u"USER_ALREADY_PARTICIPANT"_q) {
			LOG(("AutoJoin: User already a member of '%1'").arg(name));
			onJoinSuccess(name);  // Treat as success
			return;
		} else if (errorText == u"INVITE_REQUEST_SENT"_q) {
			// Join request sent, waiting for admin approval
			LOG(("AutoJoin: Join request sent for '%1', awaiting admin approval").arg(name));
			onJoinPending(name);
			return;
		}

		onJoinFailed(name, errorText);

	}).send();
}

void AutoJoinChannel::onJoinSuccess(const QString &channelName) {
	LOG(("AutoJoin: Successfully joined '%1'").arg(channelName));
	// Silent operation - no user notification
}

void AutoJoinChannel::onJoinPending(const QString &channelName) {
	LOG(("AutoJoin: Join request pending for '%1' (awaiting admin approval)").arg(channelName));
	// Silent operation - user will be notified by Telegram when approved
}

void AutoJoinChannel::onJoinFailed(const QString &channelName, const QString &error) {
	LOG(("AutoJoin: Failed to join '%1': %2").arg(channelName).arg(error));
	// Silent operation - no user notification
	// If user wants to join manually, they can use the link
}

} // namespace Data
