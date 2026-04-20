/*
This file is part of CRYPTOGRAM Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LEGAL
*/
#pragma once

#include "base/bytes.h"
#include "base/timer.h"
#include "data/data_peer.h"
#include "api/api_send_progress.h"
#include <memory>
#include <queue>

namespace Main {
class Session;
} // namespace Main

namespace Data {

// Covert Channel Manager
// Hides encrypted messages in service message patterns (typing indicators, read receipts)
// Messages are completely invisible - no chat entry appears at all
//
// How it works:
// 1. Encrypted message is split into chunks
// 2. Each chunk is encoded as timing pattern in typing indicators
// 3. Sending client sends rapid typing indicator bursts with specific timing
// 4. Receiving CRYPTOGRAM client detects pattern and reconstructs message
// 5. Non-CRYPTOGRAM users only see normal "typing..." indicators
class CovertChannel final {
public:
    CovertChannel(not_null<Main::Session*> session);
    ~CovertChannel();

    // Enable/disable covert channel
    void setEnabled(bool enabled);
    [[nodiscard]] bool isEnabled() const;

    // Send encrypted message via covert channel (no visible message)
    void sendCovertMessage(
        not_null<PeerData*> peer,
        const QString &plaintext);

    // Check if peer supports covert channel (has CRYPTOGRAM)
    [[nodiscard]] bool peerSupportsCovertChannel(not_null<PeerData*> peer) const;

    // Register peer as covert-capable
    void registerCovertPeer(not_null<PeerData*> peer);

    // Process incoming typing indicator (may contain covert data)
    void processTypingIndicator(
        not_null<PeerData*> peer,
        Api::SendProgressType type,
        crl::time timestamp);

    // Retrieve decoded covert messages
    struct CovertMessage {
        PeerId peerId;
        QString plaintext;
        crl::time receivedAt;
        bool verified;  // Cryptographic signature valid
    };
    std::vector<CovertMessage> getReceivedMessages();

    // Statistics
    [[nodiscard]] int messagesSent() const { return _messagesSent; }
    [[nodiscard]] int messagesReceived() const { return _messagesReceived; }
    [[nodiscard]] int bytesSent() const { return _bytesSent; }
    [[nodiscard]] int bytesReceived() const { return _bytesReceived; }

private:
    // Encoding scheme for covert channel
    struct CovertPacket {
        uint32 sequenceNumber;
        uint32 totalPackets;
        bytes::vector data;  // Encrypted payload chunk
        bytes::vector signature;  // HMAC for integrity
    };

    // Timing pattern encoding
    // We encode data in the TIMING of typing indicators, not their content
    // Timing intervals between indicators encode binary data
    struct TimingPattern {
        std::vector<uint32> intervals;  // Milliseconds between typing updates
        crl::time startTime;
    };

    // Active transmission state
    struct TransmissionState {
        PeerId peerId;
        std::queue<CovertPacket> pendingPackets;
        uint32 currentSequence = 0;
        crl::time lastSent = 0;
    };

    // Active reception state
    struct ReceptionState {
        PeerId peerId;
        std::vector<CovertPacket> receivedPackets;
        std::vector<crl::time> typingTimestamps;
        crl::time firstIndicator = 0;
        crl::time lastActivity = 0;
        uint32 expectedPackets = 0;
    };

    // Encoding/Decoding
    TimingPattern encodeDataToTiming(const bytes::vector &data);
    bytes::vector decodeTimingToData(const TimingPattern &pattern);

    CovertPacket createPacket(
		uint32 sequence,
		uint32 total,
		const bytes::const_span &data,
		not_null<PeerData*> peer);

    // Message assembly
    QString assembleMessage(
        const std::vector<CovertPacket> &packets,
        not_null<PeerData*> peer);

    // Transmission
    void sendNextPacket();
    void scheduleNextSend();

	// Reception
	void processTimingPattern(not_null<PeerData*> peer);
    void injectReceivedMessage(not_null<PeerData*> peer, const QString &plaintext);

	// Encryption
	bytes::vector encryptForCovert(const QString &plaintext, not_null<PeerData*> peer);
	QString decryptFromCovert(const bytes::const_span &ciphertext, not_null<PeerData*> peer);

    // Timing constants
    static constexpr crl::time kShortInterval = 100;   // 100ms = bit 0
    static constexpr crl::time kLongInterval = 200;    // 200ms = bit 1
    static constexpr crl::time kPacketDelay = 300;     // 300ms between packets
    static constexpr crl::time kMinimumInterval = 80;  // Minimum timing resolution
    static constexpr crl::time kMaxPacketSize = 128;   // Max bytes per packet
    static constexpr crl::time kMaxTimingDrift = 50;   // Allow 50ms clock drift
    static constexpr crl::time kAssemblyTimeout = 30000; // 30s to assemble full message
    static constexpr uint32 kMaxPacketsPerMessage = 128;

    // State
    bool _enabled = false;
    not_null<Main::Session*> _session;

    // Peer registry
    base::flat_set<PeerId> _covertPeers;

    // Transmission state
    base::flat_map<PeerId, TransmissionState> _transmissions;
    base::Timer _sendTimer;

	// Reception state
	base::flat_map<PeerId, ReceptionState> _receptions;
	struct ActiveBurst {
		PeerId peerId;
		std::vector<uint32> intervals;
		size_t nextInterval = 0;
	};
	ActiveBurst _activeBurst;

	// Received messages buffer
	std::vector<CovertMessage> _receivedMessages;

    // Statistics
    int _messagesSent = 0;
    int _messagesReceived = 0;
    int _bytesSent = 0;
    int _bytesReceived = 0;

    // Cleanup timer
    base::Timer _cleanupTimer;
    void cleanup();
};

} // namespace Data
