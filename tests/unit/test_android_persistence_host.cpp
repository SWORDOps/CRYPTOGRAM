/*
 * CRYPTOGRAM — Path 2 host test: Android identity + session persistence.
 *
 * Exercises the JNI-free persistence API of
 * telegram-android/TMessagesProj/jni/cryptogram/interop/InteropCore.{h,cpp}
 * exactly the way the brief's verification gates demand:
 *
 *   1. generate identity -> save -> fresh "process" -> load:
 *      public identity AND encoded key bundle byte-identical.
 *   2. establish session -> encrypt msg A (state saved) -> fresh struct ->
 *      load -> decrypt a NEW message from the peer's persisted sending
 *      state; out-of-order delivery afterwards hits the skipped-key path,
 *      and a self-message that the reloaded state can never own FAILS
 *      CLEANLY (both branches asserted, nothing left ambiguous).
 *   3. HMAC tamper: flip one byte in the session file -> load fails and the
 *      file is DELETED (replaced-not-trusted), never re- trusted.
 *
 * Host-compilable with the plain protocol core only:
 *   g++ -std=c++17 -o /tmp/test_android_persistence_host \
 *       tests/unit/test_android_persistence_host.cpp \
 *       telegram-android/TMessagesProj/jni/cryptogram/interop/InteropCore.cpp \
 *       -Itelegram-android/TMessagesProj/jni/cryptogram -lcrypto
 */

#include "interop/InteropCore.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

static int gChecks = 0;
static int gFailures = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        ++gChecks;                                                         \
        if (!(cond)) {                                                     \
            ++gFailures;                                                   \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
        }                                                                  \
    } while (false)

#define PASS(name) std::printf("[PASS] %s\n", (name).c_str())
#define FAIL(name)                                       \
    do {                                                 \
        std::printf("[FAIL] %s\n", (name).c_str());      \
        ++gFailures;                                     \
    } while (false)

using interop::ByteVector;
using interop::SessionState;

static std::string gDir;

static std::string makePath(const std::string &name) {
    return gDir + "/" + name;
}

static void flipByteInFile(const std::string &path, size_t offset) {
    FILE *file = fopen(path.c_str(), "rb");
    if (!file) return;
    ByteVector data;
    char buffer[8192];
    size_t read = 0;
    while ((read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        data.insert(data.end(), buffer, buffer + read);
    }
    fclose(file);
    if (offset >= data.size()) return;
    data[offset] ^= 0x20;
    file = fopen(path.c_str(), "wb");
    if (!file) return;
    fwrite(data.data(), 1, data.size(), file);
    fclose(file);
}

// Flip ONE character inside the base64 VALUE of `key` (staying inside the
// base64 alphabet). The JSON stays structurally valid, so the failure is
// exactly the cryptographic one under test: HMAC mismatch (session file) or
// GCM/AAD mismatch (identity file) — not a syntax error.
static bool flipInsideValue(const std::string &path, const std::string &key) {
    FILE *file = fopen(path.c_str(), "rb");
    if (!file) return false;
    ByteVector data;
    char buffer[8192];
    size_t read = 0;
    while ((read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        data.insert(data.end(), buffer, buffer + read);
    }
    fclose(file);

    std::string text(data.begin(), data.end());
    const std::string needle = "\"" + key + "\":\"";
    const size_t at = text.find(needle);
    if (at == std::string::npos) return false;
    const size_t valueAt = at + needle.size();
    if (valueAt >= text.size()) return false;
    text[valueAt] = (text[valueAt] == 'A') ? 'B' : 'A';

    file = fopen(path.c_str(), "wb");
    if (!file) return false;
    const ByteVector out(text.begin(), text.end());
    const bool ok = fwrite(out.data(), 1, out.size(), file) == out.size();
    fclose(file);
    return ok;
}

static bool fileExists(const std::string &path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

static bool sameBytes(const ByteVector &a, const ByteVector &b) {
    return a == b;
}

static bool sameSession(const SessionState &a, const SessionState &b) {
    return sameBytes(a.rootKey, b.rootKey)
        && sameBytes(a.sendingChainKey, b.sendingChainKey)
        && sameBytes(a.receivingChainKey, b.receivingChainKey)
        && sameBytes(a.dhSendingPrivateKey, b.dhSendingPrivateKey)
        && sameBytes(a.dhSendingPublicKey, b.dhSendingPublicKey)
        && sameBytes(a.dhRemotePublicKey, b.dhRemotePublicKey)
        && sameBytes(a.remoteIdentityKey, b.remoteIdentityKey)
        && sameBytes(a.remoteX25519IdentityKey, b.remoteX25519IdentityKey)
        && a.sendingMessageCounter == b.sendingMessageCounter
        && a.receivingMessageCounter == b.receivingMessageCounter
        && a.previousSendingChainLength == b.previousSendingChainLength
        && a.pendingRemoteDH == b.pendingRemoteDH
        && a.skippedMessageKeys.size() == b.skippedMessageKeys.size()
        && std::equal(a.skippedMessageKeys.begin(),
                      a.skippedMessageKeys.end(),
                      b.skippedMessageKeys.begin(),
                      [](const SessionState::SkippedKey &x,
                         const SessionState::SkippedKey &y) {
                          return x.messageNumber == y.messageNumber
                              && x.key == y.key;
                      });
}

static ByteVector hmacKeyFor(const interop::LocalIdentity &identity) {
    return interop::hkdfExpandSha256(
        identity.ed25519PrivateSeed,
        "session_hmac",
        interop::kAesKeySize);
}

static bool encryptToEnvelope(
        SessionState &session,
        const std::string &plaintext,
        ByteVector &outEnvelope) {
    const ByteVector plain(plaintext.begin(), plaintext.end());
    interop::MessageMetadata metadata;
    const auto ciphertext = interop::encryptMessage(session, plain, metadata);
    if (ciphertext.empty()) return false;
    outEnvelope = interop::wrapEnvelope(ciphertext, metadata);
    return !outEnvelope.empty();
}

static bool decryptEnvelope(
        SessionState &session,
        const ByteVector &envelope,
        std::string &outPlaintext) {
    interop::Envelope unwrapped;
    if (!interop::unwrapEnvelope(envelope, unwrapped)) return false;
    const auto plain = interop::decryptMessage(
        session,
        unwrapped.ciphertext,
        unwrapped.metadata);
    if (plain.empty()) return false;
    outPlaintext.assign(plain.begin(), plain.end());
    return true;
}

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------

static void testBase64() {
    const std::string label = "base64 round-trip + strict decode";
    const std::vector<size_t> sizes = {0, 1, 2, 3, 31, 32, 33, 60, 128, 1000};
    for (const size_t size : sizes) {
        const auto data = interop::randomVector(size);
        const auto encoded = interop::base64Encode(data);
        ByteVector decoded;
        const std::string text(encoded.begin(), encoded.end());
        CHECK(interop::base64Decode(text, decoded));
        CHECK(decoded == data);
    }
    ByteVector decoded;
    CHECK(!interop::base64Decode("A", decoded));       // not a multiple of 4
    CHECK(!interop::base64Decode("AB@C", decoded));    // invalid character
    CHECK(!interop::base64Decode("=AAA", decoded));    // data after padding
    CHECK(!interop::base64Decode("A===", decoded));    // more than 2 padding
    CHECK(interop::base64Decode("", decoded));         // empty encodes to ""
    CHECK(decoded.empty());
    (void)label;
    PASS(label);
}

static void testPbkdf2Blob() {
    const std::string label = "PBKDF2/AES-GCM blob round-trip + auth";
    const auto plaintext = interop::randomVector(128);
    const ByteVector aad = {'a', 'a', 'd'};
    const auto blob = interop::encryptWithPbkdf2(plaintext, "pw-1", aad);
    CHECK(blob.size() == interop::kPbkdf2SaltSize + interop::kGcmIvSize + plaintext.size() + interop::kGcmTagSize);

    ByteVector decrypted;
    CHECK(interop::decryptWithPbkdf2(blob, "pw-1", aad, decrypted));
    CHECK(decrypted == plaintext);

    decrypted.clear();
    CHECK(!interop::decryptWithPbkdf2(blob, "pw-WRONG", aad, decrypted));
    CHECK(!interop::decryptWithPbkdf2(blob, "pw-1", ByteVector{'x'}, decrypted));

    auto tampered = blob;
    tampered[tampered.size() / 2] ^= 0x40;
    CHECK(!interop::decryptWithPbkdf2(tampered, "pw-1", aad, decrypted));

    // Distinct calls use distinct random salt/IV.
    const auto blob2 = interop::encryptWithPbkdf2(plaintext, "pw-1", aad);
    CHECK(blob != blob2);
    PASS(label);
}

static void testIdentityPersistence() {
    std::string label = "identity: save -> fresh load -> bundle byte-identical";
    const std::string path = makePath("identity.keys.json");
    const std::string password = "cryptogram-android-identity-v2:1234567890";

    interop::LocalIdentity original;
    CHECK(interop::generateLocalIdentity(original));
    CHECK(interop::saveIdentity(original, path, password));

    interop::LocalIdentity restored;
    CHECK(interop::loadIdentity(restored, path, password));
    CHECK(restored.initialized);
    CHECK(restored.ed25519Public == original.ed25519Public);
    CHECK(restored.x25519IdentityPublic == original.x25519IdentityPublic);
    CHECK(restored.signedPreKeyPublic == original.signedPreKeyPublic);
    CHECK(restored.oneTimePreKeyPublic == original.oneTimePreKeyPublic);
    CHECK(restored.registrationId == original.registrationId);
    // The BUNDLE (what peers actually see) must be byte-identical.
    const auto originalBundle =
        interop::encodeKeyBundle(interop::localKeyBundle(original));
    const auto restoredBundle =
        interop::encodeKeyBundle(interop::localKeyBundle(restored));
    CHECK(!originalBundle.empty());
    CHECK(originalBundle == restoredBundle);

    // Second independent "process" — still identical.
    interop::LocalIdentity restored2;
    CHECK(interop::loadIdentity(restored2, path, password));
    CHECK(interop::encodeKeyBundle(interop::localKeyBundle(restored2)) == originalBundle);

    // registrationId is readable in the clear (desktop parity) to rebuild
    // the password before decryption.
    std::string registrationId;
    CHECK(interop::readIdentityRegistrationId(path, registrationId));
    CHECK(registrationId == std::to_string(original.registrationId));
    PASS(label);

    label = "identity: wrong password rejected";
    interop::LocalIdentity rejected;
    CHECK(!interop::loadIdentity(rejected, path, "wrong-password"));
    CHECK(!rejected.initialized);
    PASS(label);

    label = "identity: tampered public field rejected (AAD binding)";
    // Keep the JSON valid; corrupt the identityPublic base64 VALUE so the
    // failure is the GCM/AAD one, not a syntax error.
    CHECK(flipInsideValue(path, "identityPublic"));
    interop::LocalIdentity tampered;
    CHECK(!interop::loadIdentity(tampered, path, password));
    CHECK(!tampered.initialized);
    // Structural corruption (whole-document byte flip) is rejected as well.
    flipByteInFile(path, 0);
    CHECK(!interop::loadIdentity(tampered, path, password));
    PASS(label);
}

static void testSessionRoundTrip() {
    const std::string label =
        "session: full-field round-trip incl. skipped keys + pendingRemoteDH";
    const std::string path = makePath("session_roundtrip.json");

    interop::SessionState state;
    state.rootKey = interop::randomVector(interop::kAesKeySize);
    state.sendingChainKey = interop::randomVector(interop::kAesKeySize);
    state.receivingChainKey = interop::randomVector(interop::kAesKeySize);
    state.dhSendingPrivateKey = interop::randomVector(interop::kKeySize);
    state.dhSendingPublicKey = interop::randomVector(interop::kKeySize);
    state.dhRemotePublicKey = interop::randomVector(interop::kKeySize);
    state.remoteIdentityKey = interop::randomVector(interop::kKeySize);
    state.remoteX25519IdentityKey = interop::randomVector(interop::kKeySize);
    state.sendingMessageCounter = 4242;
    state.receivingMessageCounter = 17;
    state.previousSendingChainLength = 9;
    state.pendingRemoteDH = true;
    for (uint32_t i = 0; i < 3; ++i) {
        SessionState::SkippedKey skipped;
        skipped.messageNumber = 100 + i;
        skipped.key = interop::randomVector(interop::kAesKeySize);
        state.skippedMessageKeys.push_back(std::move(skipped));
    }

    const auto hmacKey = interop::randomVector(interop::kAesKeySize);
    CHECK(interop::saveSessionFile(state, path, hmacKey, interop::kSessionSpecGeneration));

    SessionState restored;
    CHECK(interop::loadSessionFile(
        restored,
        path,
        hmacKey,
        interop::kSessionSpecGeneration));
    CHECK(sameSession(state, restored));
    PASS(label);
}

static void testSessionLifecycle() {
    // ------------------------------------------------------------------
    // The brief's gate 2, unambiguous:
    //   process 1: identities persisted; Alice<->Bob sessions established;
    //              messages exchanged; BOTH session states saved to disk.
    //   process 2: fresh structs reload identity + session from disk; a NEW
    //              message from the peer's persisted sending state decrypts;
    //              pre-restart messages arrive out of order -> skipped-key
    //              path; a self-message the reloaded state cannot own fails
    //              cleanly.
    // ------------------------------------------------------------------
    std::string label =
        "lifecycle: persisted identities establish stable sessions";
    const auto aliceSessionPath = makePath("alice.session.json");
    const auto bobSessionPath = makePath("bob.session.json");
    const auto aliceIdentityPath = makePath("alice.keys.json");
    const auto bobIdentityPath = makePath("bob.keys.json");
    const std::string alicePassword = "cryptogram-android-identity-v2:1111";
    const std::string bobPassword = "cryptogram-android-identity-v2:2222";

    // --- process 1 -----------------------------------------------------
    interop::LocalIdentity alice;
    interop::LocalIdentity bob;
    CHECK(interop::generateLocalIdentity(alice));
    CHECK(interop::generateLocalIdentity(bob));
    CHECK(interop::saveIdentity(alice, aliceIdentityPath, alicePassword));
    CHECK(interop::saveIdentity(bob, bobIdentityPath, bobPassword));

    interop::SessionState aliceSession;
    interop::SessionState bobSession;

    ByteVector kickoffEnvelope;
    {
        // Fresh "process": both sides restore their identity from disk
        // (this is the stable-bundle guarantee the bug fix is about).
        interop::LocalIdentity alice1;
        interop::LocalIdentity bob1;
        CHECK(interop::loadIdentity(alice1, aliceIdentityPath, alicePassword));
        CHECK(interop::loadIdentity(bob1, bobIdentityPath, bobPassword));
        CHECK(interop::encodeKeyBundle(interop::localKeyBundle(alice1))
              == interop::encodeKeyBundle(interop::localKeyBundle(alice)));

        // Alice consumes Bob's advertised bundle and kicks off X3DH.
        auto bobBundleRaw =
            interop::encodeKeyBundle(interop::localKeyBundle(bob1));
        interop::KeyBundle bobBundle;
        CHECK(interop::decodeKeyBundle(bobBundleRaw, bobBundle));
        CHECK(interop::establishSessionAlice(aliceSession, alice1, bobBundle));
        CHECK(encryptToEnvelope(aliceSession, "kickoff", kickoffEnvelope));

        // Bob learns Alice's ephemeral from the first message's metadata
        // and runs the BOB-side establishment.
        interop::Envelope kickoff;
        CHECK(interop::unwrapEnvelope(kickoffEnvelope, kickoff));
        auto aliceBundleRaw =
            interop::encodeKeyBundle(interop::localKeyBundle(alice1));
        interop::KeyBundle aliceBundle;
        CHECK(interop::decodeKeyBundle(aliceBundleRaw, aliceBundle));
        CHECK(interop::establishSessionBob(
            bobSession,
            bob1,
            kickoff.metadata.senderPublicKey,
            aliceBundle));
    }

    ByteVector envelopeA;
    ByteVector envelopeB;
    ByteVector envelopeC;
    CHECK(encryptToEnvelope(aliceSession, "message-A", envelopeA));
    // Save Alice's state AFTER message-A (counter advanced, receiving
    // chain untouched) — exactly what the wrapper does after every send.
    CHECK(interop::saveSessionFile(
        aliceSession,
        aliceSessionPath,
        hmacKeyFor(alice),
        interop::kSessionSpecGeneration));
    CHECK(encryptToEnvelope(bobSession, "message-B", envelopeB));
    CHECK(encryptToEnvelope(bobSession, "message-C", envelopeC));
    CHECK(interop::saveSessionFile(
        bobSession,
        bobSessionPath,
        hmacKeyFor(bob),
        interop::kSessionSpecGeneration));

    const SessionState savedAlice = aliceSession;
    const SessionState savedBob = bobSession;
    PASS(label);

    // --- process 2: fresh structs, reload everything from disk ----------
    label = "lifecycle: fresh process decrypts peer's NEW message from persisted state";
    interop::LocalIdentity alice2;
    interop::LocalIdentity bob2;
    CHECK(interop::loadIdentity(alice2, aliceIdentityPath, alicePassword));
    CHECK(interop::loadIdentity(bob2, bobIdentityPath, bobPassword));

    SessionState aliceSession2;
    SessionState bobSession2;
    CHECK(interop::loadSessionFile(
        aliceSession2,
        aliceSessionPath,
        hmacKeyFor(alice2),
        interop::kSessionSpecGeneration));
    CHECK(interop::loadSessionFile(
        bobSession2,
        bobSessionPath,
        hmacKeyFor(bob2),
        interop::kSessionSpecGeneration));
    // Persisted state round-tripped field-for-field.
    CHECK(sameSession(savedAlice, aliceSession2));
    CHECK(sameSession(savedBob, bobSession2));

    // The PEER (Bob) sends a brand-new message D from his reloaded sending
    // chain; Alice's reloaded receiving chain must decrypt it.
    ByteVector envelopeD;
    CHECK(encryptToEnvelope(bobSession2, "message-D-new", envelopeD));
    std::string plaintext;
    CHECK(decryptEnvelope(aliceSession2, envelopeD, plaintext));
    CHECK(plaintext == "message-D-new");
    // D arrived at counter 2 while Alice's receiving counter was 0:
    // messages B and C were skipped ahead of it.
    CHECK(aliceSession2.skippedMessageKeys.size() == 2);
    CHECK(aliceSession2.receivingMessageCounter == 3);
    PASS(label);

    label = "lifecycle: out-of-order pre-restart messages hit the skipped-key path";
    CHECK(decryptEnvelope(aliceSession2, envelopeB, plaintext));
    CHECK(plaintext == "message-B");
    CHECK(aliceSession2.skippedMessageKeys.size() == 1);
    CHECK(decryptEnvelope(aliceSession2, envelopeC, plaintext));
    CHECK(plaintext == "message-C");
    CHECK(aliceSession2.skippedMessageKeys.empty());
    // And Bob's reloaded receiving chain skips the undelivered kickoff to
    // receive Alice's pre-restart message A.
    CHECK(decryptEnvelope(bobSession2, envelopeA, plaintext));
    CHECK(plaintext == "message-A");
    CHECK(bobSession2.skippedMessageKeys.size() == 1); // the skipped kickoff
    PASS(label);

    label = "lifecycle: self-message delivered to its own reloaded state fails cleanly";
    {
        // message-A was ENCRYPTED by Alice; replaying it against Alice's
        // own reloaded session can never own that message key. It must
        // FAIL CLEANLY (empty result), not crash or emit garbage.
        interop::Envelope a;
        CHECK(interop::unwrapEnvelope(envelopeA, a));
        const auto result = interop::decryptMessage(
            aliceSession2,
            a.ciphertext,
            a.metadata);
        CHECK(result.empty());
    }
    PASS(label);

    // --- persistence helpers for the harness ----------------------------
    label = "session: specGeneration mismatch is replaced, not trusted";
    const std::string stalePath = makePath("stale.session.json");
    CHECK(interop::saveSessionFile(
        savedBob,
        stalePath,
        hmacKeyFor(bob),
        /*specGeneration=*/1));
    SessionState stale;
    CHECK(!interop::loadSessionFile(
        stale,
        stalePath,
        hmacKeyFor(bob),
        interop::kSessionSpecGeneration));
    CHECK(!fileExists(stalePath)); // deleted: re-establish instead of trust
    PASS(label);

    label = "session: HMAC tamper -> load fails, file replaced (deleted)";
    const std::string tamperPath = makePath("tampered.session.json");
    CHECK(interop::saveSessionFile(
        savedAlice,
        tamperPath,
        hmacKeyFor(alice),
        interop::kSessionSpecGeneration));
    // Keep the JSON valid; corrupt the sessionData base64 VALUE so the
    // verified failure is the HMAC mismatch itself.
    CHECK(flipInsideValue(tamperPath, "sessionData"));
    SessionState tampered;
    CHECK(!interop::loadSessionFile(
        tampered,
        tamperPath,
        hmacKeyFor(alice),
        interop::kSessionSpecGeneration));
    CHECK(!fileExists(tamperPath));
    // A second load also fails cleanly (file gone -> treated as a miss).
    CHECK(!interop::loadSessionFile(
        tampered,
        tamperPath,
        hmacKeyFor(alice),
        interop::kSessionSpecGeneration));
    PASS(label);

    label = "session: structurally corrupt file -> fails cleanly";
    const std::string corruptPath = makePath("corrupt.session.json");
    CHECK(interop::saveSessionFile(
        savedAlice,
        corruptPath,
        hmacKeyFor(alice),
        interop::kSessionSpecGeneration));
    flipByteInFile(corruptPath, 0); // whole-document corruption
    CHECK(!interop::loadSessionFile(
        tampered,
        corruptPath,
        hmacKeyFor(alice),
        interop::kSessionSpecGeneration));
    CHECK(!fileExists(corruptPath));
    PASS(label);

    label = "session: foreign HMAC key (regenerated identity) rejected";
    const std::string foreignPath = makePath("foreign.session.json");
    CHECK(interop::saveSessionFile(
        savedAlice,
        foreignPath,
        hmacKeyFor(alice),
        interop::kSessionSpecGeneration));
    CHECK(!interop::loadSessionFile(
        tampered,
        foreignPath,
        hmacKeyFor(bob), // wrong key: a different identity's HMAC key
        interop::kSessionSpecGeneration));
    CHECK(!fileExists(foreignPath));
    PASS(label);
}

int main() {
    std::printf("=== CRYPTOGRAM Path 2 host test: identity + session persistence ===\n");

    char pattern[64];
    std::snprintf(pattern, sizeof(pattern), "/tmp/cg_path2_host_%d", static_cast<int>(getpid()));
    if (mkdir(pattern, 0700) != 0) {
        std::printf("[FAIL] cannot create temp dir %s\n", pattern);
        return 1;
    }
    gDir = pattern;

    testBase64();
    testPbkdf2Blob();
    testIdentityPersistence();
    testSessionRoundTrip();
    testSessionLifecycle();

    std::printf("=== checks: %d, failures: %d ===\n", gChecks, gFailures);
    if (gFailures == 0) {
        std::printf("HOST TEST: ALL GATES PASSED\n");
    } else {
        std::printf("HOST TEST: FAILURES PRESENT\n");
    }
    return gFailures == 0 ? 0 : 1;
}
