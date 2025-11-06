/*
This file is part of CRYPTOGRAM Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LEGAL
*/
#pragma once

#include "data/data_peer.h"
#include "ui/style/style_core.h"

namespace Data {

// CRYPTOGRAM & CAC User Visual Identification
// Displays known users with colored names (only visible to respective user groups)
//
// Color Scheme:
// - RED names: CRYPTOGRAM users (encryption, covert channels) - visible to CRYPTOGRAM users
// - GREEN names: CAC-authenticated users (military/government smart cards) - visible ONLY to CAC card owners
// - Normal colors: Regular Telegram users
//
// Privacy-preserving visibility rules:
// - Green names (CAC users): Only visible when you have a CAC card present on your device
// - Red names (CRYPTOGRAM users): Only visible to other CRYPTOGRAM users
// - Non-CRYPTOGRAM/CAC users see normal Telegram colors only
//
// This helps users identify:
// - Who supports encryption (red)
// - Who has CAC authentication (green)
// - Who to use covert channels with (red)
// - Who has hardware-backed security (green)

// Get the color for a peer's name
// Returns green for CAC users, red for CRYPTOGRAM users, normal color otherwise
[[nodiscard]] QColor GetPeerNameColor(not_null<PeerData*> peer);

// Get the style color for a peer's name (for style system)
[[nodiscard]] style::color GetPeerNameStyleColor(not_null<PeerData*> peer);

// Check if peer should be displayed with red name (CRYPTOGRAM user)
[[nodiscard]] bool ShouldShowAsRedName(not_null<PeerData*> peer);

// Check if peer should be displayed with green name (CAC user)
[[nodiscard]] bool ShouldShowAsGreenName(not_null<PeerData*> peer);

// Auto-register CRYPTOGRAM user when they send encrypted message
void AutoDetectCryptogramUser(not_null<PeerData*> peer);

// Auto-register CAC user when they present CAC certificate
void AutoDetectCACUser(not_null<PeerData*> peer, const QString &userDN);

// Constants
namespace {
    // Red color for CRYPTOGRAM users (visible only to CRYPTOGRAM users)
    constexpr auto kCryptogramUserColor = QColor(220, 20, 60); // Crimson red
    constexpr auto kCryptogramUserColorHex = "#DC143C";

    // Green color for CAC users (visible only to CAC/CRYPTOGRAM users)
    constexpr auto kCACUserColor = QColor(34, 139, 34); // Forest green
    constexpr auto kCACUserColorHex = "#228B22";
}

} // namespace Data
