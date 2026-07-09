/*
This file is part of CRYPTOGRAM Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LEGAL
*/
#include "data/data_peer_cryptogram_id.h"

#include "data/data_enhanced_privacy.h"
#include "data/data_cac_interface.h"
#include "data/data_user.h"
#include "ui/chat/chat_style.h"
#include "styles/style_dialogs.h"

namespace Data {

bool ShouldShowAsRedName(not_null<PeerData*> peer) {
    // Only show red name if peer is registered as CRYPTOGRAM user
    if (const auto user = peer->asUser()) {
        return EnhancedPrivacy::IsCryptogramUser(peerToUser(user->id));
    }
    return false;
}

bool ShouldShowAsGreenName(not_null<PeerData*> peer) {
    // SECURITY PATCH: The vulnerability of relying on a local UI check has been removed.
    // The "Green Name" is now strictly enforced by the backend Cryptographic Mutual Authentication Handshake.
    // A peer will ONLY exist in the CACUserRegistry if their physical smart card successfully 
    // signed our cryptographic challenge, and we verified it against the NATO/DoD Root CAs.
    if (const auto user = peer->asUser()) {
        return CACUserRegistry::isCACUser(peerToUser(user->id));
    }
    return false;
}

QColor GetPeerNameColor(not_null<PeerData*> peer) {
    // Priority: CAC (green) > CRYPTOGRAM (red) > Normal colors

    // Check if this is a CAC-authenticated user (highest priority)
    if (ShouldShowAsGreenName(peer)) {
        // Return green color (forest green)
        return QColor(34, 139, 34);
    }

    // Check if this is a CRYPTOGRAM user
    if (ShouldShowAsRedName(peer)) {
        // Return red color (crimson)
        return QColor(220, 20, 60);
    }

    // Return normal peer color based on their colorIndex
    // This preserves the standard Telegram color scheme for non-CRYPTOGRAM users
    const auto colorIndex = peer->colorIndex();

    // Use standard Telegram peer colors
    // These are the default peer name colors from Telegram's palette
    static const std::array<QColor, 8> kDefaultPeerColors = {{
        QColor(242, 106, 97),   // Red
        QColor(105, 181, 77),   // Green
        QColor(116, 174, 250),  // Blue
        QColor(236, 161, 86),   // Orange
        QColor(144, 121, 255),  // Purple
        QColor(105, 221, 188),  // Cyan
        QColor(255, 135, 168),  // Pink
        QColor(255, 179, 71),   // Yellow
    }};

    return kDefaultPeerColors[colorIndex % kDefaultPeerColors.size()];
}

style::color GetPeerNameStyleColor(not_null<PeerData*> peer) {
    // Priority: CAC (green) > CRYPTOGRAM (red) > Normal

    // For CAC users, return green color style
    if (ShouldShowAsGreenName(peer)) {
        // Will be overridden in paint code with forest green
        return st::msgFileOutBg;
    }

    // For CRYPTOGRAM users, return red color style
    if (ShouldShowAsRedName(peer)) {
        // Will be overridden in paint code with crimson red
        return st::msgFileOutBg;
    }

    // Return normal dialog name color
    return st::dialogsNameFg;
}

void AutoDetectCryptogramUser(not_null<PeerData*> peer) {
    // Auto-register peer as CRYPTOGRAM user
    // Called when we detect they're using CRYPTOGRAM features (e.g., covert channel, encryption)
    if (const auto user = peer->asUser()) {
        if (!EnhancedPrivacy::IsCryptogramUser(peerToUser(user->id))) {
            EnhancedPrivacy::RegisterCryptogramUser(peerToUser(user->id));
            LOG(("CRYPTOGRAM: Auto-detected CRYPTOGRAM user: %1").arg(user->id.value));
        }
    }
}

void AutoDetectCACUser(not_null<PeerData*> peer, const QString &userDN) {
    // Auto-register peer as CAC-authenticated user
    // Called when we detect they're using CAC card for authentication
    if (const auto user = peer->asUser()) {
        if (!CACUserRegistry::isCACUser(peerToUser(user->id))) {
            CACUserRegistry::registerCACUser(peerToUser(user->id), userDN);
            LOG(("CRYPTOGRAM: Auto-detected CAC user: %1, DN: %2")
                .arg(user->id.value)
                .arg(userDN));
        }
    }
}

} // namespace Data
