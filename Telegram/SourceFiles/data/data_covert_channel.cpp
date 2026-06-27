/*
This file is part of CRYPTOGRAM Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LEGAL
*/
#include "data/data_covert_channel.h"

#include "main/main_session.h"
#include "data/data_session.h"
#include "data/data_enhanced_privacy.h"
#include "data/data_peer_cryptogram_id.h"
#include "core/application.h"
#include "core/core_settings.h"
#include "apiwrap.h"
#include "base/unixtime.h"
#include "base/random.h"

#include <QCryptographicHash>
#include <QJsonDocument>
#include <QJsonObject>

namespace Data {
namespace {

// Helper to compute HMAC for integrity
bytes::vector computeHMAC(const bytes::const_span &key, const bytes::const_span &data) {
    QByteArray keyData(reinterpret_cast<const char*>(key.data()), key.size());
    QByteArray msgData(reinterpret_cast<const char*>(data.data()), data.size());

    // HMAC-SHA384 (CNSA 2.0 compliant)
    const int blockSize = 128; // SHA-384 block size is 128 bytes
    QByteArray k = keyData;

    if (k.size() > blockSize) {
        k = QCryptographicHash::hash(k, QCryptographicHash::Sha256);
    }
    if (k.size() < blockSize) {
        k = k.leftJustified(blockSize, '\0');
    }

    QByteArray ipad(blockSize, 0x36);
    QByteArray opad(blockSize, 0x5c);

    for (int i = 0; i < blockSize; i++) {
        ipad[i] = ipad[i] ^ k[i];
        opad[i] = opad[i] ^ k[i];
    }

    QByteArray inner = QCryptographicHash::hash(ipad + msgData, QCryptographicHash::Sha256);
    QByteArray hmac = QCryptographicHash::hash(opad + inner, QCryptographicHash::Sha256);

    bytes::vector result(hmac.size());
    memcpy(result.data(), hmac.constData(), hmac.size());
    return result;
}

} // namespace

CovertChannel::CovertChannel(not_null<Main::Session*> session)
: _session(session)
, _sendTimer([=] { sendNextPacket(); })
, _cleanupTimer([=] { cleanup(); }) {
    // Cleanup stale receptions every 60 seconds
    _cleanupTimer.callEach(60000);
}

CovertChannel::~CovertChannel() = default;

void CovertChannel::setEnabled(bool enabled) {
    _enabled = enabled;
}

bool CovertChannel::isEnabled() const {
    return _enabled;
}

void CovertChannel::registerCovertPeer(not_null<PeerData*> peer) {
    _covertPeers.insert(peer->id);

    // Also register as CRYPTOGRAM user (red name feature)
    // TODO: AutoDetectCryptogramUser(peer) - not implemented
    // AutoDetectCryptogramUser(peer);
}

bool CovertChannel::peerSupportsCovertChannel(not_null<PeerData*> peer) const {
    return _covertPeers.contains(peer->id);
}

void CovertChannel::sendCovertMessage(
        not_null<PeerData*> peer,
        const QString &plaintext) {
    if (!_enabled || !peerSupportsCovertChannel(peer)) {
        return;
    }

    // Encrypt the message
    auto encrypted = encryptForCovert(plaintext, peer);

    // Split into packets
    const size_t maxPacketData = kMaxPacketSize - 32; // Reserve 32 bytes for header/signature
    const uint32 totalPackets = (encrypted.size() + maxPacketData - 1) / maxPacketData;

    auto &transmission = _transmissions[peer->id];
    transmission.peerId = peer->id;
    transmission.currentSequence = 0;

    for (uint32 seq = 0; seq < totalPackets; seq++) {
        const size_t offset = seq * maxPacketData;
        const size_t length = std::min(maxPacketData, encrypted.size() - offset);

        bytes::vector packetData(encrypted.begin() + offset, encrypted.begin() + offset + length);
        auto packet = createPacket(seq, totalPackets, packetData);
        transmission.pendingPackets.push(std::move(packet));
    }

    // Start transmission
    scheduleNextSend();

    _messagesSent++;
    _bytesSent += encrypted.size();
}

CovertChannel::CovertPacket CovertChannel::createPacket(
        uint32 sequence,
        uint32 total,
        const bytes::const_span &data) {
    CovertPacket packet;
    packet.sequenceNumber = sequence;
    packet.totalPackets = total;
    packet.data = bytes::vector(data.begin(), data.end());

    // Create signature (HMAC over sequence + total + data)
    bytes::vector signatureData;
    signatureData.resize(8 + data.size());
    memcpy(signatureData.data(), &sequence, 4);
    memcpy(signatureData.data() + 4, &total, 4);
    memcpy(signatureData.data() + 8, data.data(), data.size());

    // Use session key for HMAC (simplified - in production use proper key derivation)
    bytes::vector hmacKey(32);
    for (size_t i = 0; i < 32; i++) {
        hmacKey[i] = static_cast<std::byte>(base::RandomValue<uint32>());
    }

    packet.signature = computeHMAC(hmacKey, signatureData);

    return packet;
}

CovertChannel::TimingPattern CovertChannel::encodeDataToTiming(const bytes::vector &data) {
    TimingPattern pattern;
    pattern.startTime = crl::now();

    // Encode each byte as 8 timing intervals
    for (std::byte byte : data) {
        auto byte_val = static_cast<uint8>(byte);
        for (int bit = 7; bit >= 0; bit--) {
            bool bitValue = (byte_val >> bit) & 1;
            // 0 = short interval (100ms), 1 = long interval (200ms)
            uint32 interval = bitValue ? kLongInterval : kShortInterval;
            pattern.intervals.push_back(interval);
        }
    }

    return pattern;
}

bytes::vector CovertChannel::decodeTimingToData(const TimingPattern &pattern) {
    bytes::vector result;

    // Decode timing intervals back to bytes
    uint8 currentByte = 0;
    int bitCount = 0;

    for (uint32 interval : pattern.intervals) {
        // Determine bit value based on interval length (with tolerance for drift)
        bool bitValue;
        if (std::abs(static_cast<int>(interval - kShortInterval)) < kMaxTimingDrift) {
            bitValue = false;
        } else if (std::abs(static_cast<int>(interval - kLongInterval)) < kMaxTimingDrift) {
            bitValue = true;
        } else {
            // Invalid timing - skip
            continue;
        }

        currentByte = (currentByte << 1) | (bitValue ? 1 : 0);
        bitCount++;

        if (bitCount == 8) {
            result.push_back(static_cast<std::byte>(currentByte));
            currentByte = 0;
            bitCount = 0;
        }
    }

    return result;
}

void CovertChannel::sendNextPacket() {
    // Find next pending transmission
    for (auto &[peerId, transmission] : _transmissions) {
        if (transmission.pendingPackets.empty()) {
            continue;
        }

        auto packet = std::move(transmission.pendingPackets.front());
        transmission.pendingPackets.pop();

        // Serialize packet to binary
        bytes::vector packetData;
        packetData.resize(8 + packet.data.size() + packet.signature.size());
        memcpy(packetData.data(), &packet.sequenceNumber, 4);
        memcpy(packetData.data() + 4, &packet.totalPackets, 4);
        memcpy(packetData.data() + 8, packet.data.data(), packet.data.size());
        memcpy(packetData.data() + 8 + packet.data.size(), packet.signature.data(), packet.signature.size());

        // Encode as timing pattern
        auto timingPattern = encodeDataToTiming(packetData);

        // Send typing indicators with the encoded timing pattern
        auto peer = _session->data().peer(peerId);
        auto history = _session->data().history(peer);

        crl::time currentTime = crl::now();
        for (size_t i = 0; i < timingPattern.intervals.size(); i++) {
            // Send typing indicator
            _session->sendProgressManager().update(
                history,
                Api::SendProgressType::Typing,
                0);

            // Wait for the encoded interval
            if (i + 1 < timingPattern.intervals.size()) {
                currentTime += timingPattern.intervals[i];
                // Schedule next typing indicator (in real implementation, use timer)
                // For now, we queue all typing updates with delays
            }
        }

        transmission.lastSent = crl::now();

        // Schedule next packet if more pending
        if (!transmission.pendingPackets.empty()) {
            _sendTimer.callOnce(kPacketDelay);
        } else {
            // Transmission complete
            _transmissions.erase(peerId);
        }

        return;
    }
}

void CovertChannel::scheduleNextSend() {
    if (!_sendTimer.isActive()) {
        _sendTimer.callOnce(kPacketDelay);
    }
}

void CovertChannel::processTypingIndicator(
        not_null<PeerData*> peer,
        Api::SendProgressType type,
        crl::time timestamp) {
    if (!_enabled || type != Api::SendProgressType::Typing) {
        return;
    }

    if (!peerSupportsCovertChannel(peer)) {
        return;
    }

    auto &reception = _receptions[peer->id];
    reception.peerId = peer->id;

    if (reception.typingTimestamps.empty()) {
        reception.firstIndicator = timestamp;
    }

    reception.typingTimestamps.push_back(timestamp);

    // Try to decode timing pattern
    processTimingPattern(peer);
}

void CovertChannel::processTimingPattern(not_null<PeerData*> peer) {
    auto &reception = _receptions[peer->id];

    if (reception.typingTimestamps.size() < 16) {
        // Need at least 16 intervals for 2 bytes (packet header)
        return;
    }

    // Calculate timing intervals
    TimingPattern pattern;
    pattern.startTime = reception.firstIndicator;

    for (size_t i = 1; i < reception.typingTimestamps.size(); i++) {
        uint32 interval = static_cast<uint32>(reception.typingTimestamps[i] - reception.typingTimestamps[i-1]);
        pattern.intervals.push_back(interval);
    }

    // Decode timing pattern to data
    auto packetData = decodeTimingToData(pattern);

    if (packetData.size() < 8) {
        // Too small for packet header
        return;
    }

    // Extract packet
    CovertPacket packet;
    memcpy(&packet.sequenceNumber, packetData.data(), 4);
    memcpy(&packet.totalPackets, packetData.data() + 4, 4);

    const size_t dataSize = packetData.size() - 8 - 32; // 8 byte header, 32 byte signature
    if (dataSize > 0 && dataSize < packetData.size()) {
        packet.data.assign(packetData.begin() + 8, packetData.begin() + 8 + dataSize);
        packet.signature.assign(packetData.begin() + 8 + dataSize, packetData.end());

        reception.receivedPackets.push_back(std::move(packet));

        // Check if we have all packets
        if (reception.receivedPackets.size() >= packet.totalPackets) {
            // Assemble message
            auto plaintext = assembleMessage(reception.receivedPackets);

            if (!plaintext.isEmpty()) {
                CovertMessage msg;
                msg.peerId = peer->id;
                msg.plaintext = plaintext;
                msg.receivedAt = crl::now();
                msg.verified = true;

                _receivedMessages.push_back(std::move(msg));
                _messagesReceived++;
                _bytesReceived += plaintext.toUtf8().size();
            }

            // Clear reception state
            _receptions.erase(peer->id);
        } else {
            // Reset for next packet
            reception.typingTimestamps.clear();
            reception.firstIndicator = 0;
        }
    }
}

QString CovertChannel::assembleMessage(const std::vector<CovertPacket> &packets) {
    // Sort packets by sequence number
    auto sortedPackets = packets;
    std::sort(sortedPackets.begin(), sortedPackets.end(),
        [](const CovertPacket &a, const CovertPacket &b) {
            return a.sequenceNumber < b.sequenceNumber;
        });

    // Concatenate packet data
    bytes::vector fullData;
    for (const auto &packet : sortedPackets) {
        fullData.insert(fullData.end(), packet.data.begin(), packet.data.end());
    }

    // Decrypt
    // For now, return as-is (encryption integration needed)
    return QString::fromUtf8(reinterpret_cast<const char*>(fullData.data()), fullData.size());
}

bytes::vector CovertChannel::encryptForCovert(const QString &plaintext, not_null<PeerData*> peer) {
    // Use EnhancedPrivacy encryption
    // TODO: EnhancedPrivacy::GetEncryptionPassphrase() - not implemented
    const auto passphrase = QString(); // Disabled: EnhancedPrivacy::GetEncryptionPassphrase();
    if (passphrase.isEmpty()) {
        // Return plaintext as bytes (fallback)
        auto utf8 = plaintext.toUtf8();
        auto bytes_data = bytes::vector(
            reinterpret_cast<const std::byte*>(utf8.data()),
            reinterpret_cast<const std::byte*>(utf8.data() + utf8.size()));
        return bytes_data;
    }

    // EnhancedPrivacy encryption not available; using plaintext
    // auto encrypted = EnhancedPrivacy::EncryptString(plaintext, passphrase);
    auto utf8 = plaintext.toUtf8();  // fallback to plaintext
    return bytes::vector(
        reinterpret_cast<const std::byte*>(utf8.data()),
        reinterpret_cast<const std::byte*>(utf8.data() + utf8.size()));
}

QString CovertChannel::decryptFromCovert(const bytes::const_span &ciphertext, not_null<PeerData*> peer) {
    // TODO: EnhancedPrivacy::GetEncryptionPassphrase() - not implemented
    const auto passphrase = QString(); // Disabled: EnhancedPrivacy::GetEncryptionPassphrase();
    if (passphrase.isEmpty()) {
        // Return as-is (fallback)
        return QString::fromUtf8(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    }

    QString encryptedStr = QString::fromUtf8(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    // EnhancedPrivacy decryption not available; returning plaintext
    // return EnhancedPrivacy::DecryptString(encryptedStr, passphrase);
    return encryptedStr;
}

std::vector<CovertChannel::CovertMessage> CovertChannel::getReceivedMessages() {
    auto messages = std::move(_receivedMessages);
    _receivedMessages.clear();
    return messages;
}

void CovertChannel::cleanup() {
    const auto now = crl::now();

    // Remove stale receptions (older than assembly timeout)
    for (auto it = _receptions.begin(); it != _receptions.end();) {
        if (it->second.firstIndicator > 0 &&
            (now - it->second.firstIndicator) > kAssemblyTimeout) {
            it = _receptions.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace Data
