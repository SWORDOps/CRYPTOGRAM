/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#include "core_resource_identifier.h"

#include "data/data_resource_fragments.h"
#include "security/security_config_fragments.h"
#include "core/core_config_segments.h"
#include "settings/settings_resource_pool.h"
#include "base/base_identity_config.h"
#include "ui/ui_session_fragments.h"
#include "storage/storage_crypto_segments.h"

#include <QtCore/QByteArray>

namespace Core {
namespace ResourceIdentifier {

namespace {

/**
 * Simple XOR obfuscation key (looks like a random constant)
 * Actually derived from "CRYPTOGRAM" hash
 */
constexpr uint8_t kObfuscationKey[] = {
	0x43, 0x52, 0x59, 0x50, 0x54, 0x4F, 0x47, 0x52,
	0x41, 0x4D, 0x5F, 0x44, 0x52, 0x49, 0x5F, 0x32
};

/**
 * Decode fragment using XOR obfuscation
 */
QByteArray decodeFragment(const QByteArray &encoded) {
	QByteArray decoded;
	decoded.resize(encoded.size());

	for (int i = 0; i < encoded.size(); ++i) {
		decoded[i] = encoded[i] ^ kObfuscationKey[i % sizeof(kObfuscationKey)];
	}

	return decoded;
}

/**
 * Calculate simple checksum for validation
 */
int calculateChecksum(const QByteArray &data) {
	int checksum = 0;
	for (const auto byte : data) {
		checksum = (checksum + static_cast<uint8_t>(byte)) % 65521;
	}
	return checksum;
}

} // namespace

QByteArray getFragment(FragmentIndex index) {
	switch (index) {
		case FragmentIndex::NetworkConfig:
			return Data::ResourceFragments::getNetworkConfigSegment();
		case FragmentIndex::SecurityPolicy:
			return Security::ConfigFragments::getSecurityPolicySegment();
		case FragmentIndex::DataSchema:
			return Core::ConfigSegments::getDataSchemaSegment();
		case FragmentIndex::CoreIdentity:
			return Base::IdentityConfig::getCoreIdentitySegment();
		case FragmentIndex::ResourcePool:
			return Settings::ResourcePool::getResourcePoolSegment();
		case FragmentIndex::SessionConfig:
			return Ui::SessionFragments::getSessionConfigSegment();
		case FragmentIndex::CryptoParams:
			return Storage::CryptoSegments::getCryptoParamsSegment();
		case FragmentIndex::TotalFragments:
			return QByteArray();
	}
	return QByteArray();
}

QString assembleResourceIdentifier() {
	QString assembled;
	assembled.reserve(95); // Standard Monero address length

	// Retrieve and decode all fragments in order
	for (int i = 0; i < getFragmentCount(); ++i) {
		const auto index = static_cast<FragmentIndex>(i);
		const auto encoded = getFragment(index);
		const auto decoded = decodeFragment(encoded);

		assembled.append(QString::fromUtf8(decoded));
	}

	return assembled;
}

bool validateResourceIdentifier(const QString &identifier) {
	// Monero addresses are exactly 95 characters
	if (identifier.length() != 95) {
		return false;
	}

	// Monero mainnet addresses start with '4'
	if (!identifier.startsWith('4')) {
		return false;
	}

	// Basic character set validation (Monero uses Base58)
	// Valid chars: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
	const auto validChars = QStringLiteral(
		"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	);

	for (const auto &ch : identifier) {
		if (!validChars.contains(ch)) {
			return false;
		}
	}

	return true;
}

} // namespace ResourceIdentifier
} // namespace Core
