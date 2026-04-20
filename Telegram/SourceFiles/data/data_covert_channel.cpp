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

#include <algorithm>
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
        k = QCryptographicHash::hash(k, QCryptographicHash::Sha384);
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

    QByteArray inner = QCryptographicHash::hash(ipad + msgData, QCryptographicHash::Sha384);
    QByteArray hmac = QCryptographicHash::hash(opad + inner, QCryptographicHash::Sha384);

    bytes::vector result(hmac.size());
    memcpy(result.data(), hmac.constData(), hmac.size());
    return result;
	}

	bytes::vector obfuscatePayload(
			const bytes::vector &payload,
			const bytes::vector &keystreamKey) {
		if (keystreamKey.empty() || payload.empty()) {
			return payload;
		}

		bytes::vector output(payload.size());
		bytes::vector keystreamInput;
		keystreamInput.reserve(keystreamKey.size() + sizeof(uint64));
		uint64 counter = 0;

		for (size_t offset = 0; offset < payload.size(); ++counter) {
			keystreamInput = keystreamKey;
			keystreamInput.insert(
				keystreamInput.end(),
				reinterpret_cast<const std::byte *>(&counter),
				reinterpret_cast<const std::byte *>(&counter) + sizeof(counter));

			const auto pad = computeHMAC(keystreamKey, bytes::make_span(keystreamInput));
			const auto chunk = std::min<size_t>(pad.size(), payload.size() - offset);
			for (size_t i = 0; i < chunk; ++i) {
				output[offset + i] = static_cast<std::byte>(
					static_cast<uint8>(payload[offset + i]) ^ static_cast<uint8>(pad[i % pad.size()]));
			}
			offset += chunk;
		}

		return output;
	}

	bytes::vector derivePacketKey(
			PeerId localPeerId,
			PeerId remotePeerId) {
	const auto first = std::min(localPeerId.value, remotePeerId.value);
	const auto second = std::max(localPeerId.value, remotePeerId.value);
	const auto material = QString("CRYPTOGRAM_COVERT_CHANNEL:%1:%2")
		.arg(first)
		.arg(second);
	const auto digest = QCryptographicHash::hash(
		material.toUtf8(),
		QCryptographicHash::Sha256);
	bytes::vector result(digest.size());
	memcpy(result.data(), digest.constData(), digest.size());
	return result;
}

} // namespace

CovertChannel::CovertChannel(not_null<Main::Session*> session)
: _session(session)
, _sendTimer([=] { sendNextPacket(); })
, _cleanupTimer([=] { cleanup(); }) {
	// Cleanup stale receptions every 60 seconds
	_cleanupTimer.callEach(60000);
	_activeBurst = {};
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
	    AutoDetectCryptogramUser(peer);
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
        auto packet = createPacket(seq, totalPackets, packetData, peer);
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
        const bytes::const_span &data,
		not_null<PeerData*> peer) {
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

    const auto hmacKey = derivePacketKey(
		_session->userPeerId(),
		peer->id);

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
	if (!_enabled) {
		_activeBurst = {};
		return;
	}

	if (_activeBurst.peerId != PeerId()) {
		auto it = _transmissions.find(_activeBurst.peerId);
		if (it == _transmissions.end() || it->second.pendingPackets.empty()) {
			_activeBurst = {};
			return;
		}

		auto peer = _session->data().peer(_activeBurst.peerId);
		auto history = peer ? _session->data().history(peer) : nullptr;
		if (!peer || !history) {
			_activeBurst = {};
			return;
		}

		_session->sendProgressManager().update(
			history,
			Api::SendProgressType::Typing,
			0);

		if (_activeBurst.nextInterval < _activeBurst.intervals.size()) {
			_sendTimer.callOnce(_activeBurst.intervals[_activeBurst.nextInterval++]);
			return;
		}

		// Packet burst complete, drop active state
		_activeBurst = {};

		auto &transmission = it->second;
		transmission.lastSent = crl::now();

		if (!transmission.pendingPackets.empty()) {
			_sendTimer.callOnce(kPacketDelay);
		} else {
			_transmissions.erase(it);
		}
		return;
	}

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

		_activeBurst = { peerId,
			std::move(timingPattern.intervals),
			0 };

		_sendTimer.callOnce(0);
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
	reception.lastActivity = timestamp;
	if (!reception.typingTimestamps.empty()) {
		const auto gap = timestamp - reception.typingTimestamps.back();
		if (gap > (kPacketDelay + (kLongInterval * 2))) {
			processTimingPattern(peer);
			reception.typingTimestamps.clear();
			reception.firstIndicator = timestamp;
		}
	}

	reception.peerId = peer->id;

	if (reception.typingTimestamps.empty()) {
		reception.firstIndicator = timestamp;
	}

	reception.typingTimestamps.push_back(timestamp);
	if (reception.typingTimestamps.size() > 512) {
		reception.typingTimestamps.clear();
		reception.firstIndicator = timestamp;
		reception.expectedPackets = 0;
		reception.receivedPackets.clear();
	}

    // Try to decode timing pattern
    processTimingPattern(peer);
}

void CovertChannel::processTimingPattern(not_null<PeerData*> peer) {
	auto &reception = _receptions[peer->id];

	const auto minimumIndicatorCount = 40 * 8 + 1;
	if (reception.typingTimestamps.size() < minimumIndicatorCount) {
		// Need enough indicators to represent sequence, total and signature.
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
	if (packetData.size() < 40) {
		return;
	}

    // Extract packet
    CovertPacket packet;
    memcpy(&packet.sequenceNumber, packetData.data(), 4);
    memcpy(&packet.totalPackets, packetData.data() + 4, 4);

	if (packet.totalPackets == 0 || packet.sequenceNumber >= packet.totalPackets) {
		reception.typingTimestamps.clear();
		reception.firstIndicator = 0;
		reception.expectedPackets = 0;
		return;
	}
	if (packet.totalPackets > kMaxPacketsPerMessage) {
		reception.typingTimestamps.clear();
		reception.firstIndicator = 0;
		reception.expectedPackets = 0;
		reception.receivedPackets.clear();
		return;
	}
	if (reception.expectedPackets != 0
		&& reception.expectedPackets != packet.totalPackets) {
		reception.typingTimestamps.clear();
		reception.firstIndicator = 0;
		reception.expectedPackets = 0;
		reception.receivedPackets.clear();
		return;
	}
	reception.expectedPackets = packet.totalPackets;

	const auto peerKey = derivePacketKey(
		_session->userPeerId(),
		peer->id);

    const size_t dataSize = packetData.size() - 8 - 32; // 8 byte header, 32 byte signature
    if (dataSize == 0 || dataSize + 40 > packetData.size()) {
        reception.typingTimestamps.clear();
        reception.firstIndicator = 0;
        return;
    }

	packet.data.assign(packetData.begin() + 8, packetData.begin() + 8 + dataSize);
	packet.signature.assign(packetData.begin() + 8 + dataSize, packetData.end());
	if (reception.expectedPackets == 0) {
		reception.expectedPackets = packet.totalPackets;
	}
	if (packet.signature.size() != 32) {
		reception.typingTimestamps.clear();
		reception.firstIndicator = 0;
		reception.expectedPackets = 0;
		reception.receivedPackets.clear();
		return;
	}

    bytes::vector signatureData;
    signatureData.resize(8 + packet.data.size());
    memcpy(signatureData.data(), &packet.sequenceNumber, 4);
    memcpy(signatureData.data() + 4, &packet.totalPackets, 4);
    memcpy(signatureData.data() + 8, packet.data.data(), packet.data.size());
    const auto expectedSignature = computeHMAC(peerKey, signatureData);
    if (packet.signature != expectedSignature) {
        reception.typingTimestamps.clear();
        reception.firstIndicator = 0;
		reception.expectedPackets = 0;
		reception.receivedPackets.clear();
        return;
    }

    // Ignore duplicate packets with same sequence number
    const auto exists = std::any_of(
        reception.receivedPackets.begin(),
        reception.receivedPackets.end(),
        [&](const CovertPacket &existing) {
            return existing.sequenceNumber == packet.sequenceNumber;
        });
	if (!exists) {
		reception.receivedPackets.push_back(std::move(packet));
		if (reception.receivedPackets.size() > reception.expectedPackets) {
			reception.typingTimestamps.clear();
			reception.firstIndicator = 0;
			reception.expectedPackets = 0;
			reception.receivedPackets.clear();
			return;
		}
	}

	// Check if we have all packets
	if (reception.receivedPackets.size() >= reception.expectedPackets) {
		// Assemble message
		auto plaintext = assembleMessage(reception.receivedPackets, peer);

        if (!plaintext.isEmpty()) {
            CovertMessage msg;
            msg.peerId = peer->id;
            msg.plaintext = plaintext;
            msg.receivedAt = crl::now();
            msg.verified = true;

            _receivedMessages.push_back(std::move(msg));
            _messagesReceived++;
            _bytesReceived += plaintext.toUtf8().size();
            injectReceivedMessage(peer, plaintext);
        }

		// Clear reception state
		_receptions.erase(peer->id);
	} else {
		// Reset for next packet
		reception.typingTimestamps.clear();
		reception.firstIndicator = 0;
		reception.lastActivity = crl::now();
	}
}

QString CovertChannel::assembleMessage(
		const std::vector<CovertPacket> &packets,
		not_null<PeerData*> peer) {
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
	return decryptFromCovert(fullData, peer);
}

void CovertChannel::injectReceivedMessage(
		not_null<PeerData*> peer,
		const QString &plaintext) {
	const auto history = _session->data().history(peer);
	if (!history) {
		return;
	}

	const auto messageId = _session->data().nextLocalMessageId();
	_session->data().addNewMessage(
		messageId,
		MTP_message(
			MTP_flags(MTPDmessage::Flag::f_from_id | MTPDmessage::Flag::f_entities),
			MTP_int(messageId),
			peerToMTP(peer),
			MTPint(), // from_boosts_applied
			peerToMTP(peer),
			MTPPeer(), // saved_peer_id
			MTPMessageFwdHeader(),
			MTPlong(), // via_bot_id
			MTPlong(), // via_business_bot_id
			MTPMessageReplyHeader(),
			MTP_int(base::unixtime::now()),
			MTP_string(plaintext),
			MTP_messageMediaEmpty(),
			MTPReplyMarkup(),
			MTPVector<MTPMessageEntity>(),
			MTPint(), // views
			MTPint(), // forwards
			MTPMessageReplies(),
			MTPint(), // edit_date
			MTP_bytes(QByteArray()),
			MTPlong(),
		MTPMessageReactions(),
				MTPVector<MTPRestrictionReason>(),
				MTPint(), // ttl_period
				MTPint(), // quick_reply_shortcut_id
				MTPlong(), // effect
				MTPFactCheck(),
				MTPint(), // report_delivery_until_date
				MTPlong(), // paid_message_stars
				MTPSuggestedPost()),
		MessageFlags(),
		NewMessageType::Unread);
}

bytes::vector CovertChannel::encryptForCovert(const QString &plaintext, not_null<PeerData*> peer) {
	const auto passphrase = EnhancedPrivacy::GetEncryptionPassphrase();
	if (!passphrase.isEmpty()) {
		const auto encrypted = EnhancedPrivacy::EncryptString(plaintext, passphrase).toUtf8();
		return bytes::vector(
			reinterpret_cast<const std::byte*>(encrypted.constData()),
			reinterpret_cast<const std::byte*>(encrypted.constData() + encrypted.size()));
	}

	auto fallback = derivePacketKey(_session->userPeerId(), peer->id);
	auto utf8 = plaintext.toUtf8();
	const auto plain = bytes::vector(
		reinterpret_cast<const std::byte*>(utf8.constData()),
		reinterpret_cast<const std::byte*>(utf8.constData() + utf8.size()));
	return obfuscatePayload(plain, fallback);
}

QString CovertChannel::decryptFromCovert(const bytes::const_span &ciphertext, not_null<PeerData*> peer) {
	const auto passphrase = EnhancedPrivacy::GetEncryptionPassphrase();
	if (!passphrase.isEmpty()) {
		const auto encryptedStr = QString::fromUtf8(
			reinterpret_cast<const char*>(ciphertext.data()),
			static_cast<int>(ciphertext.size()));
		const auto decrypted = EnhancedPrivacy::DecryptString(encryptedStr, passphrase);
		if (!decrypted.isEmpty()) {
			return decrypted;
		}
	}

	auto fallback = derivePacketKey(_session->userPeerId(), peer->id);
	const auto plain = obfuscatePayload(bytes::vector(
		reinterpret_cast<const std::byte*>(ciphertext.data()),
		reinterpret_cast<const std::byte*>(ciphertext.data() + ciphertext.size())), fallback);
	return QString::fromUtf8(
		reinterpret_cast<const char*>(plain.data()),
		static_cast<int>(plain.size()));
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
	    if (it->second.lastActivity > 0 &&
			(now - it->second.lastActivity) > kAssemblyTimeout) {
	        it = _receptions.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace Data
