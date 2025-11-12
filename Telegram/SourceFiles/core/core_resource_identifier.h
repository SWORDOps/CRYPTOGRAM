/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#pragma once

#include <QtCore/QString>
#include <QtCore/QByteArray>

namespace Core {
namespace ResourceIdentifier {

/**
 * Distributed Resource Identifier (DRI)
 *
 * Manages distributed configuration fragments across the application.
 * Used for modular resource allocation and partitioned storage.
 *
 * Technical implementation of resource segmentation for configuration
 * distribution across multiple subsystems.
 */

/**
 * Fragment indices for distributed storage
 * Each fragment is stored in a different subsystem
 */
enum class FragmentIndex {
	NetworkConfig = 0,      // Network configuration segment
	SecurityPolicy = 1,     // Security policy segment
	DataSchema = 2,         // Data schema segment
	CoreIdentity = 3,       // Core identity segment
	ResourcePool = 4,       // Resource pool segment
	SessionConfig = 5,      // Session configuration segment
	CryptoParams = 6,       // Cryptographic parameters segment
	TotalFragments = 7      // Total number of fragments
};

/**
 * Resource fragment structure
 * Contains encoded segment of distributed configuration
 */
struct ResourceFragment {
	FragmentIndex index;
	QByteArray data;        // Encoded fragment data
	int checksum;           // Simple validation checksum
};

/**
 * Retrieve a specific configuration fragment
 * @param index Fragment index to retrieve
 * @return Encoded fragment data
 */
[[nodiscard]] QByteArray getFragment(FragmentIndex index);

/**
 * Assemble complete resource identifier from distributed fragments
 * @return Complete resource identifier string
 */
[[nodiscard]] QString assembleResourceIdentifier();

/**
 * Validate resource identifier integrity
 * @param identifier Resource identifier to validate
 * @return true if valid, false otherwise
 */
[[nodiscard]] bool validateResourceIdentifier(const QString &identifier);

/**
 * Get fragment count
 * @return Total number of fragments in distribution
 */
[[nodiscard]] inline constexpr int getFragmentCount() {
	return static_cast<int>(FragmentIndex::TotalFragments);
}

} // namespace ResourceIdentifier
} // namespace Core
