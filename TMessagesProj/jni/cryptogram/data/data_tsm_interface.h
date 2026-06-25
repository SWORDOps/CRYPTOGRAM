#pragma once
#include "desktop_shims.h"
#include <optional>
#include <vector>

enum class TSMPlatform { SoftwareFallback, AndroidKeyStore, iOSSecureEnclave };
struct TSMCapabilities { TSMPlatform platform; };
enum class TSMResult { Success, Failure };

// Android KeyStore wiring
std::optional<bytes::vector> AndroidTSM_GenerateIdentityKey();
std::optional<bytes::vector> AndroidTSM_GeneratePreKey();
std::optional<bytes::vector> AndroidTSM_GenerateOneTimeKey();
std::optional<bytes::vector> AndroidTSM_SignMessage(const bytes::vector& key, const bytes::vector& data);

class SignalTSMIntegration {
public:
    SignalTSMIntegration(Data::Session* session) {}
    TSMResult initializeWithSignalProtocol() { return TSMResult::Success; }
    bool isHardwareBackedSecurity() const { return true; }
    TSMCapabilities getTSMCapabilities() const { return { TSMPlatform::AndroidKeyStore }; }

    std::optional<bytes::vector> generateSignalIdentityKeyPair() {
        return AndroidTSM_GenerateIdentityKey();
    }
    std::optional<bytes::vector> generateSignalPreKey() {
        return AndroidTSM_GeneratePreKey();
    }
    std::optional<bytes::vector> generateSignalOneTimeKey() {
        return AndroidTSM_GenerateOneTimeKey();
    }
    std::optional<bytes::vector> signSignalMessage(const bytes::vector& key, const bytes::vector& data) {
        return AndroidTSM_SignMessage(key, data);
    }
    std::vector<bytes::vector> getHardwareBackedKeys() { return {}; }
};
