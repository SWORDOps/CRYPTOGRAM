/*
SpyGram Double Ratchet Algorithm Tests
Tests the Double Ratchet algorithm implementation for forward secrecy
and break-in recovery properties.
*/

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>

#include "data/data_signal_protocol.h"
#include "crypto/crypto_double_ratchet.h"
#include "base/random.h"

using namespace Data;
using namespace Crypto;

class DoubleRatchetFixture {
public:
    DoubleRatchetFixture() {
        // Initialize Alice and Bob ratchets
        aliceIdentity = generateKeyPair();
        bobIdentity = generateKeyPair();
        
        // Bob's pre-key bundle
        bobPreKey = generateKeyPair();
        bobSignedPreKey = generateKeyPair();
        
        // Initialize Alice's ratchet (sender)
        aliceRatchet = std::make_unique<DoubleRatchet>();
        aliceRatchet->initializeSender(
            aliceIdentity,
            bobIdentity.publicKey,
            bobPreKey.publicKey
        );
        
        // Initialize Bob's ratchet (receiver)
        bobRatchet = std::make_unique<DoubleRatchet>();
    }

protected:
    KeyPair aliceIdentity;
    KeyPair bobIdentity;
    KeyPair bobPreKey;
    KeyPair bobSignedPreKey;
    
    std::unique_ptr<DoubleRatchet> aliceRatchet;
    std::unique_ptr<DoubleRatchet> bobRatchet;
    
    KeyPair generateKeyPair() {
        KeyPair pair;
        pair.privateKey.resize(32);
        pair.publicKey.resize(32);
        base::RandomFill(pair.privateKey.data(), 32);
        // In real implementation, derive public from private using Curve25519
        base::RandomFill(pair.publicKey.data(), 32);
        return pair;
    }
};

TEST_CASE_METHOD(DoubleRatchetFixture, "Double Ratchet initialization", "[ratchet][unit]") {
    SECTION("Sender initialization") {
        REQUIRE(aliceRatchet->isInitialized());
        REQUIRE(aliceRatchet->canEncrypt());
        
        // Check initial state
        auto state = aliceRatchet->getState();
        REQUIRE(state.sendingChainLength == 0);
        REQUIRE(state.receivingChainLength == 0);
        REQUIRE(state.previousChainLength == 0);
    }
    
    SECTION("Receiver initialization from initial message") {
        // Alice sends initial message
        auto initialMessage = aliceRatchet->encryptMessage("Hello Bob");
        REQUIRE(initialMessage.header.has_value());
        
        // Bob initializes from initial message
        bobRatchet->initializeReceiver(
            bobIdentity,
            bobPreKey,
            initialMessage.header.value()
        );
        
        REQUIRE(bobRatchet->isInitialized());
        REQUIRE(bobRatchet->canDecrypt());
    }
}

TEST_CASE_METHOD(DoubleRatchetFixture, "Message encryption and decryption", "[ratchet][unit]") {
    // Setup Bob's ratchet
    auto initialMessage = aliceRatchet->encryptMessage("Initial");
    bobRatchet->initializeReceiver(
        bobIdentity,
        bobPreKey,
        initialMessage.header.value()
    );
    bobRatchet->decryptMessage(initialMessage);

    SECTION("Basic message exchange") {
        // Alice -> Bob
        std::string plaintext1 = "Hello Bob!";
        auto encrypted1 = aliceRatchet->encryptMessage(plaintext1);
        auto decrypted1 = bobRatchet->decryptMessage(encrypted1);
        
        REQUIRE(decrypted1.has_value());
        REQUIRE(decrypted1.value() == plaintext1);
        
        // Bob -> Alice
        std::string plaintext2 = "Hello Alice!";
        auto encrypted2 = bobRatchet->encryptMessage(plaintext2);
        auto decrypted2 = aliceRatchet->decryptMessage(encrypted2);
        
        REQUIRE(decrypted2.has_value());
        REQUIRE(decrypted2.value() == plaintext2);
    }
    
    SECTION("Multiple messages in one direction") {
        std::vector<std::string> messages = {
            "Message 1",
            "Message 2",
            "Message 3",
            "Message 4",
            "Message 5"
        };
        
        // Alice sends multiple messages
        std::vector<RatchetMessage> encrypted;
        for (const auto& msg : messages) {
            encrypted.push_back(aliceRatchet->encryptMessage(msg));
        }
        
        // Bob decrypts all
        for (size_t i = 0; i < messages.size(); i++) {
            auto decrypted = bobRatchet->decryptMessage(encrypted[i]);
            REQUIRE(decrypted.has_value());
            REQUIRE(decrypted.value() == messages[i]);
        }
        
        // Verify chain progression
        auto aliceState = aliceRatchet->getState();
        REQUIRE(aliceState.sendingChainLength == 5);
    }
    
    SECTION("Alternating message exchange") {
        for (int i = 0; i < 10; i++) {
            if (i % 2 == 0) {
                // Alice -> Bob
                std::string msg = "Alice message " + std::to_string(i);
                auto encrypted = aliceRatchet->encryptMessage(msg);
                auto decrypted = bobRatchet->decryptMessage(encrypted);
                REQUIRE(decrypted.value() == msg);
            } else {
                // Bob -> Alice
                std::string msg = "Bob message " + std::to_string(i);
                auto encrypted = bobRatchet->encryptMessage(msg);
                auto decrypted = aliceRatchet->decryptMessage(encrypted);
                REQUIRE(decrypted.value() == msg);
            }
        }
        
        // Both should have performed ratchet steps
        REQUIRE(aliceRatchet->getState().ratchetCount > 0);
        REQUIRE(bobRatchet->getState().ratchetCount > 0);
    }
}

TEST_CASE_METHOD(DoubleRatchetFixture, "Out-of-order message handling", "[ratchet][unit]") {
    // Setup
    auto initialMessage = aliceRatchet->encryptMessage("Initial");
    bobRatchet->initializeReceiver(bobIdentity, bobPreKey, initialMessage.header.value());
    bobRatchet->decryptMessage(initialMessage);

    SECTION("Delayed messages") {
        // Alice sends messages
        auto msg1 = aliceRatchet->encryptMessage("Message 1");
        auto msg2 = aliceRatchet->encryptMessage("Message 2");
        auto msg3 = aliceRatchet->encryptMessage("Message 3");
        
        // Bob receives out of order: 3, 1, 2
        auto decrypt3 = bobRatchet->decryptMessage(msg3);
        auto decrypt1 = bobRatchet->decryptMessage(msg1);
        auto decrypt2 = bobRatchet->decryptMessage(msg2);
        
        REQUIRE(decrypt3.value() == "Message 3");
        REQUIRE(decrypt1.value() == "Message 1");
        REQUIRE(decrypt2.value() == "Message 2");
    }
    
    SECTION("Skipped message keys limit") {
        // Send many messages
        std::vector<RatchetMessage> messages;
        for (int i = 0; i < 1100; i++) {  // Exceed typical limit of 1000
            messages.push_back(aliceRatchet->encryptMessage("Msg " + std::to_string(i)));
        }
        
        // Try to decrypt very old message after receiving new ones
        auto decryptLatest = bobRatchet->decryptMessage(messages.back());
        REQUIRE(decryptLatest.has_value());
        
        // This should fail - too many skipped keys
        auto decryptOld = bobRatchet->decryptMessage(messages[0]);
        REQUIRE(!decryptOld.has_value());
        REQUIRE(bobRatchet->getLastError() == DoubleRatchet::TooManySkippedKeys);
    }
    
    SECTION("Message replay detection") {
        auto msg = aliceRatchet->encryptMessage("Test message");
        
        // First decryption succeeds
        auto decrypt1 = bobRatchet->decryptMessage(msg);
        REQUIRE(decrypt1.has_value());
        
        // Replay attempt fails
        auto decrypt2 = bobRatchet->decryptMessage(msg);
        REQUIRE(!decrypt2.has_value());
        REQUIRE(bobRatchet->getLastError() == DoubleRatchet::DuplicateMessage);
    }
}

TEST_CASE_METHOD(DoubleRatchetFixture, "Forward secrecy properties", "[ratchet][unit]") {
    // Setup
    auto initialMessage = aliceRatchet->encryptMessage("Initial");
    bobRatchet->initializeReceiver(bobIdentity, bobPreKey, initialMessage.header.value());
    bobRatchet->decryptMessage(initialMessage);

    SECTION("Key deletion after use") {
        // Get initial chain key
        auto initialChainKey = aliceRatchet->getCurrentChainKey();
        
        // Send message
        aliceRatchet->encryptMessage("Message");
        
        // Chain key should have changed
        auto newChainKey = aliceRatchet->getCurrentChainKey();
        REQUIRE(initialChainKey != newChainKey);
        
        // Old message key should be deleted
        REQUIRE(!aliceRatchet->hasMessageKey(initialChainKey, 0));
    }
    
    SECTION("Ratchet step forward secrecy") {
        // Save state before ratchet
        auto stateBeforeRatchet = aliceRatchet->exportState();
        
        // Force ratchet by Bob sending message
        bobRatchet->encryptMessage("Trigger ratchet");
        
        // Alice's old sending chain should be replaced
        auto stateAfterRatchet = aliceRatchet->exportState();
        REQUIRE(stateBeforeRatchet.sendingChainKey != stateAfterRatchet.sendingChainKey);
    }
}

TEST_CASE_METHOD(DoubleRatchetFixture, "Break-in recovery", "[ratchet][unit]") {
    // Setup
    auto initialMessage = aliceRatchet->encryptMessage("Initial");
    bobRatchet->initializeReceiver(bobIdentity, bobPreKey, initialMessage.header.value());
    bobRatchet->decryptMessage(initialMessage);

    SECTION("Recovery after compromise") {
        // Exchange some messages
        for (int i = 0; i < 5; i++) {
            auto msg = aliceRatchet->encryptMessage("Alice " + std::to_string(i));
            bobRatchet->decryptMessage(msg);
        }
        
        // "Compromise" - attacker gets current keys
        auto compromisedAliceState = aliceRatchet->exportState();
        auto compromisedBobState = bobRatchet->exportState();
        
        // Continue communication - Bob responds
        auto bobMsg = bobRatchet->encryptMessage("Bob response");
        aliceRatchet->decryptMessage(bobMsg);
        
        // Alice responds back
        auto aliceMsg = aliceRatchet->encryptMessage("Alice post-compromise");
        bobRatchet->decryptMessage(aliceMsg);
        
        // Create attacker ratchets from compromised state
        auto attackerAlice = std::make_unique<DoubleRatchet>();
        auto attackerBob = std::make_unique<DoubleRatchet>();
        attackerAlice->importState(compromisedAliceState);
        attackerBob->importState(compromisedBobState);
        
        // Attacker should NOT be able to decrypt post-compromise messages
        auto attackerDecrypt = attackerBob->decryptMessage(aliceMsg);
        REQUIRE(!attackerDecrypt.has_value());
    }
}

TEST_CASE_METHOD(DoubleRatchetFixture, "Chain key derivation", "[ratchet][unit]") {
    SECTION("Message key derivation") {
        ChainKey chainKey;
        chainKey.key.resize(32);
        base::RandomFill(chainKey.key.data(), 32);
        chainKey.index = 0;
        
        // Derive message keys
        auto messageKey1 = deriveMessageKey(chainKey);
        chainKey = advanceChainKey(chainKey);
        
        auto messageKey2 = deriveMessageKey(chainKey);
        chainKey = advanceChainKey(chainKey);
        
        // Keys should be different
        REQUIRE(messageKey1 != messageKey2);
        
        // Verify deterministic derivation
        ChainKey sameChainKey;
        sameChainKey.key = chainKey.key;
        sameChainKey.index = chainKey.index;
        
        auto messageKey3 = deriveMessageKey(sameChainKey);
        auto messageKey4 = deriveMessageKey(chainKey);
        
        REQUIRE(messageKey3 == messageKey4);
    }
    
    SECTION("Root key derivation") {
        RootKey rootKey;
        rootKey.resize(32);
        base::RandomFill(rootKey.data(), 32);
        
        KeyPair dhOutput = generateKeyPair();
        
        auto [newRootKey, newChainKey] = deriveRootKey(rootKey, dhOutput.publicKey);
        
        // Verify keys are derived correctly
        REQUIRE(newRootKey.size() == 32);
        REQUIRE(newChainKey.key.size() == 32);
        REQUIRE(newRootKey != rootKey);
    }
}

TEST_CASE("Double Ratchet performance", "[ratchet][benchmark]") {
    BENCHMARK_ADVANCED("Ratchet initialization")(Catch::Benchmark::Chronometer meter) {
        std::vector<std::unique_ptr<DoubleRatchet>> ratchets;
        ratchets.reserve(meter.runs());
        
        meter.measure([&ratchets] {
            auto ratchet = std::make_unique<DoubleRatchet>();
            KeyPair identity = {
                std::vector<uint8_t>(32),
                std::vector<uint8_t>(32)
            };
            base::RandomFill(identity.privateKey.data(), 32);
            base::RandomFill(identity.publicKey.data(), 32);
            
            ratchet->initializeSender(
                identity,
                identity.publicKey,
                identity.publicKey
            );
            ratchets.push_back(std::move(ratchet));
        });
    };
    
    BENCHMARK_ADVANCED("Message encryption")(Catch::Benchmark::Chronometer meter) {
        DoubleRatchetFixture fixture;
        std::string message = "Benchmark message content that is reasonably sized";
        
        meter.measure([&fixture, &message] {
            return fixture.aliceRatchet->encryptMessage(message);
        });
    };
    
    BENCHMARK_ADVANCED("Message decryption")(Catch::Benchmark::Chronometer meter) {
        DoubleRatchetFixture fixture;
        
        // Setup
        auto initialMessage = fixture.aliceRatchet->encryptMessage("Initial");
        fixture.bobRatchet->initializeReceiver(
            fixture.bobIdentity,
            fixture.bobPreKey,
            initialMessage.header.value()
        );
        fixture.bobRatchet->decryptMessage(initialMessage);
        
        // Prepare messages
        std::vector<RatchetMessage> messages;
        messages.reserve(meter.runs());
        for (size_t i = 0; i < meter.runs(); i++) {
            messages.push_back(fixture.aliceRatchet->encryptMessage("Test " + std::to_string(i)));
        }
        
        size_t index = 0;
        meter.measure([&fixture, &messages, &index] {
            return fixture.bobRatchet->decryptMessage(messages[index++]);
        });
    };
    
    BENCHMARK("Ratchet step") {
        DoubleRatchetFixture fixture;
        
        // Setup
        auto initialMessage = fixture.aliceRatchet->encryptMessage("Initial");
        fixture.bobRatchet->initializeReceiver(
            fixture.bobIdentity,
            fixture.bobPreKey,
            initialMessage.header.value()
        );
        fixture.bobRatchet->decryptMessage(initialMessage);
        
        // Alternate messages to trigger ratchet steps
        for (int i = 0; i < 100; i++) {
            if (i % 2 == 0) {
                auto msg = fixture.aliceRatchet->encryptMessage("Alice");
                fixture.bobRatchet->decryptMessage(msg);
            } else {
                auto msg = fixture.bobRatchet->encryptMessage("Bob");
                fixture.aliceRatchet->decryptMessage(msg);
            }
        }
    };
}

TEST_CASE("Double Ratchet state serialization", "[ratchet][unit]") {
    DoubleRatchetFixture fixture;
    
    // Exchange some messages
    auto initialMessage = fixture.aliceRatchet->encryptMessage("Initial");
    fixture.bobRatchet->initializeReceiver(
        fixture.bobIdentity,
        fixture.bobPreKey,
        initialMessage.header.value()
    );
    fixture.bobRatchet->decryptMessage(initialMessage);
    
    for (int i = 0; i < 5; i++) {
        auto msg = fixture.aliceRatchet->encryptMessage("Message " + std::to_string(i));
        fixture.bobRatchet->decryptMessage(msg);
    }
    
    SECTION("Export and import state") {
        // Export Alice's state
        auto aliceState = fixture.aliceRatchet->exportState();
        
        // Create new ratchet and import
        auto newAliceRatchet = std::make_unique<DoubleRatchet>();
        newAliceRatchet->importState(aliceState);
        
        // Should be able to continue communication
        auto msg = newAliceRatchet->encryptMessage("After import");
        auto decrypted = fixture.bobRatchet->decryptMessage(msg);
        
        REQUIRE(decrypted.has_value());
        REQUIRE(decrypted.value() == "After import");
    }
    
    SECTION("State size limits") {
        // Send many messages to increase state size
        for (int i = 0; i < 100; i++) {
            if (i % 3 == 0) {
                // Skip some to create skipped message keys
                fixture.aliceRatchet->encryptMessage("Skip " + std::to_string(i));
            } else {
                auto msg = fixture.aliceRatchet->encryptMessage("Message " + std::to_string(i));
                fixture.bobRatchet->decryptMessage(msg);
            }
        }
        
        auto state = fixture.bobRatchet->exportState();
        
        // State should be reasonably sized despite many skipped keys
        REQUIRE(state.skippedMessageKeys.size() <= 1000);  // Max skipped keys
        REQUIRE(state.serializedSize() < 100 * 1024);      // Less than 100KB
    }
}