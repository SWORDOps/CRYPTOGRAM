// Message encryption integration with peer trust
#include "core/peer_trust_encryption.h"

#include "core/application.h"
#include "core/core_settings.h"
#include "core/peer_trust.h"

namespace Core {

TrustEncryptionParams PeerTrustEncryption::GetEncryptionParams(uint64 peerId) {
    auto trustManager = Core::App().peerTrustManager();
    if (!trustManager || !trustManager->isEnabled()) {
        return TrustEncryptionParams::Default();
    }

    if (!trustManager->hasPeerTrust(peerId)) {
        return TrustEncryptionParams::Default();
    }

    const auto cipherIndex = Core::App().settings().preferredCipher();
    const auto cipher = CipherName(cipherIndex);

    return TrustEncryptionParams{
        .cipher = cipher,
        .useTPM = true,
        .verified = true
    };
}

QString PeerTrustEncryption::CipherName(int cipherIndex) {
    switch (cipherIndex) {
    case kAES256GCM:
        return "AES-256-GCM";
    case kChaCha20Poly1305:
        return "ChaCha20-Poly1305";
    case kAES192GCM:
        return "AES-192-GCM";
    default:
        return "AES-256-GCM";
    }
}

int PeerTrustEncryption::CipherKeySize(int cipherIndex) {
    switch (cipherIndex) {
    case kAES256GCM:
        return 32;
    case kChaCha20Poly1305:
        return 32;
    case kAES192GCM:
        return 24;
    default:
        return 32;
    }
}

} // namespace Core
