/*
CRYPTOGRAM MLS Protocol Tests
Focuses on key package signing and basic supported-ciphersuite group flows.
*/

#include <catch2/catch_test_macros.hpp>

#include "data/data_mls_protocol.h"

using namespace Data;

TEST_CASE("MLS key packages are signed and verifiable", "[mls][unit]") {
	MLSProtocol protocol;

	const auto keyPackage = protocol.generateKeyPackage(
		MLSCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

	REQUIRE(keyPackage.isValid());
	REQUIRE_FALSE(keyPackage.initKey.empty());
	REQUIRE_FALSE(keyPackage.credentialPublicKey.empty());
	REQUIRE_FALSE(keyPackage.signature.empty());
	REQUIRE(protocol.verifyKeyPackage(keyPackage));

	auto tamperedPackage = keyPackage;
	tamperedPackage.signature[0] ^= std::byte{0x01};
	REQUIRE_FALSE(protocol.verifyKeyPackage(tamperedPackage));
}

TEST_CASE("MLS basic group messaging works on supported ciphersuite", "[mls][unit]") {
	MLSProtocol protocol;
	const QVector<UserId> members = {
		UserId(static_cast<uint64>(101)),
		UserId(static_cast<uint64>(202)),
	};

	const auto groupId = protocol.createGroup(
		members,
		MLSCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

	REQUIRE_FALSE(groupId.empty());
	REQUIRE(protocol.hasGroup(groupId));

	const bytes::vector plaintext = {
		std::byte{'h'},
		std::byte{'e'},
		std::byte{'l'},
		std::byte{'l'},
		std::byte{'o'},
	};

	const auto ciphertext = protocol.encryptMessage(groupId, plaintext);
	REQUIRE_FALSE(ciphertext.empty());

	const auto decrypted = protocol.decryptMessage(groupId, ciphertext);
	REQUIRE(decrypted.has_value());
	REQUIRE(decrypted.value() == plaintext);

	auto tamperedCiphertext = ciphertext;
	tamperedCiphertext.back() ^= std::byte{0x01};
	const auto tamperedDecrypt = protocol.decryptMessage(groupId, tamperedCiphertext);
	REQUIRE_FALSE(tamperedDecrypt.has_value());
}

TEST_CASE("MLS proposal processing modifies group state", "[mls][unit]") {
	MLSProtocol protocol;
	const QVector<UserId> members = {
		UserId(static_cast<uint64>(101)),
		UserId(static_cast<uint64>(202)),
	};

	const auto groupId = protocol.createGroup(
		members,
		MLSCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

	REQUIRE(protocol.hasGroup(groupId));

	auto state = protocol.getGroupState(groupId);
	REQUIRE(state.has_value());
	REQUIRE(state->memberCount() == 2);

	// Add a new member via proposal
	MLSProposal addProposal;
	addProposal.type = MLSProposalType::Add;
	addProposal.sender = UserId(static_cast<uint64>(303));
	addProposal.addKeyPackage = protocol.generateKeyPackage(
		MLSCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
	addProposal.timestamp = QDateTime::currentDateTime();

	REQUIRE(protocol.processProposal(groupId, addProposal));

	state = protocol.getGroupState(groupId);
	REQUIRE(state.has_value());
	REQUIRE(state->memberCount() == 3);
	REQUIRE(state->isMember(UserId(static_cast<uint64>(303))));

	// Remove a member via proposal
	MLSProposal removeProposal;
	removeProposal.type = MLSProposalType::Remove;
	removeProposal.sender = UserId(static_cast<uint64>(101));
	removeProposal.removeLeaf = MLSLeafIndex(0);
	removeProposal.timestamp = QDateTime::currentDateTime();

	REQUIRE(protocol.processProposal(groupId, removeProposal));

	state = protocol.getGroupState(groupId);
	REQUIRE(state.has_value());
	REQUIRE_FALSE(state->isMember(UserId(static_cast<uint64>(101))));
}
