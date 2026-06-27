#include "core/peer_trust_encryption.h"

namespace Core {
TrustEncryptionParams PeerTrustEncryption::GetEncryptionParams(uint64) { return TrustEncryptionParams::Default(); }
}
