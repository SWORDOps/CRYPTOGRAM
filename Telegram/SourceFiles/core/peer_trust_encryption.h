// Message encryption integration with peer trust
#pragma once

#include <QString>
#include <QByteArray>

namespace Core {

struct TrustEncryptionParams {
    QString cipher;
    bool useTPM = false;
    bool verified = false;

    static TrustEncryptionParams Default() {
        return { .cipher = "AES-256-GCM", .useTPM = false, .verified = false };
    }
};

class PeerTrustEncryption {
public:
    static TrustEncryptionParams GetEncryptionParams(uint64 peerId);

    static QString CipherName(int cipherIndex);
    static int CipherKeySize(int cipherIndex);

private:
    static constexpr int kAES256GCM = 0;
    static constexpr int kChaCha20Poly1305 = 1;
    static constexpr int kAES192GCM = 2;

};

} // namespace Core
