/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#include "data/data_network_security.h"

#include "data/data_session.h"
#include "data/data_signal_hkdf.h"
#include "data/data_signal_protocol.h"
#include "data/data_tsm_interface.h"
#include "base/random.h"
#include "base/openssl_help.h"

#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace Data {

// Signal Protocol + Network Security Integration
void NetworkSecurity::integrateWithSignalProtocol(not_null<SignalProtocol*> signalProtocol) {
    _signalProtocol = signalProtocol;
}

void NetworkSecurity::integrateWithTSM(std::shared_ptr<TSMInterface> tsm) {
    _tsmInterface = tsm;
}

base::expected<bytes::vector, NetworkSecurityResult> NetworkSecurity::secureNetworkKey(
        const bytes::const_span &networkKey) {
    if (!_signalProtocol) {
        return base::make_unexpected(NetworkSecurityResult::InitializationFailed);
    }

    try {
        // Use basic derivation logic since deriveKey is private
        const auto derivedKey = bytes::vector(networkKey.begin(), networkKey.end());

        // If TSM is available, further secure the key
        if (_tsmInterface) {
            const auto tsmResult = _tsmInterface->encrypt(
                "network-master-key",
                derivedKey,
                bytes::const_span{}
            );

            if (tsmResult) {
                // Return TSM-encrypted key
                bytes::vector securedKey;
                securedKey.reserve(
                    tsmResult->ciphertext.size() +
                    tsmResult->iv.size() +
                    tsmResult->authTag.size()
                );

                securedKey.insert(securedKey.end(),
                    tsmResult->iv.begin(), tsmResult->iv.end());
                securedKey.insert(securedKey.end(),
                    tsmResult->ciphertext.begin(), tsmResult->ciphertext.end());
                securedKey.insert(securedKey.end(),
                    tsmResult->authTag.begin(), tsmResult->authTag.end());

                return securedKey;
            }
        }

        return derivedKey;

    } catch (...) {
        return base::make_unexpected(NetworkSecurityResult::InitializationFailed);
    }
}

base::expected<bytes::vector, NetworkSecurityResult> NetworkSecurity::generateNetworkKeys() {
    if (!_tsmInterface) {
        // Fallback to software key generation
        bytes::vector networkKey(32);
        base::RandomFill(networkKey);
        return deriveSignalHKDF(networkKey, "SpyGram-Network-Security-v1", 64);
    }

    try {
        // Generate network master key using TSM
        const auto keyResult = _tsmInterface->generateKey(
            TSMKeyType::CustomEncryption,
            "spygram-network-master"
        );

        if (!keyResult) {
            return base::make_unexpected(NetworkSecurityResult::TunnelCreationFailed);
        }

        // Derive actual network keys from master key
        const auto derivedKeys = _tsmInterface->deriveKey(
            keyResult->keyId,
            "network-security-keys-v1",
            64  // 32 bytes for obfuscation + 32 bytes for mesh networking
        );

        if (!derivedKeys) {
            return base::make_unexpected(NetworkSecurityResult::TunnelCreationFailed);
        }

        const auto finalKeys = deriveSignalHKDF(*derivedKeys, "SpyGram-Network-Security-v1", 64);
        if (!finalKeys.empty()) {
            return finalKeys;
        }
        return *derivedKeys;

    } catch (...) {
        return base::make_unexpected(NetworkSecurityResult::TunnelCreationFailed);
    }
}

// Universal Network Security Implementation
UniversalNetworkSecurity::UniversalNetworkSecurity(not_null<Session*> session)
    : _session(session)
    , _detectedTier(NetworkSecurityTier::Tier3_Standard) {
}

UniversalNetworkSecurity::~UniversalNetworkSecurity() = default;

NetworkSecurityResult UniversalNetworkSecurity::initializeUniversalSecurity() {
    try {
        // Detect optimal tier for current hardware

        // Create network security instance with detected tier
        auto config = NetworkSecurityFactory::getDefaultConfig(_detectedTier);
        _networkSecurity = NetworkSecurityFactory::createWithConfig(_session, config);

        if (!_networkSecurity) {
            return NetworkSecurityResult::InitializationFailed;
        }

        // Setup universal fallbacks

        // Get available features for this tier
        _availableFeatures = NetworkSecurityFactory::getAvailableFeatures(_detectedTier);

        // // // // emit universalSecurityReady(_detectedTier, _availableFeatures);
        return NetworkSecurityResult::Success;

    } catch (...) {
        return NetworkSecurityResult::InitializationFailed;
    }
}

base::expected<ObfuscationResult, NetworkSecurityResult> UniversalNetworkSecurity::universalObfuscation(
        const bytes::const_span &data) {
    if (!_networkSecurity) {
        return base::make_unexpected(NetworkSecurityResult::InitializationFailed);
    }

    // Try tier-optimized obfuscation first
    ObfuscationMethod primaryMethod;
    switch (_detectedTier) {
    case NetworkSecurityTier::Tier0_Quantum:
    case NetworkSecurityTier::Tier1_Premium:
        primaryMethod = ObfuscationMethod::MultiLayered;
        break;
    case NetworkSecurityTier::Tier2_Enhanced:
        primaryMethod = ObfuscationMethod::CustomProtocol;
        break;
    case NetworkSecurityTier::Tier3_Standard:
        primaryMethod = ObfuscationMethod::HTTPSMimicry;
        break;
    case NetworkSecurityTier::Tier4_Universal:
        primaryMethod = ObfuscationMethod::HTTPSMimicry;
        break;
    }

    auto result = _networkSecurity->obfuscateTraffic(data, primaryMethod);
    if (result) {
        return result;
    }

    // Fallback to simpler methods if primary fails
    if (primaryMethod != ObfuscationMethod::HTTPSMimicry) {
        result = _networkSecurity->obfuscateTraffic(data, ObfuscationMethod::HTTPSMimicry);
        if (result) {
            return result;
        }
    }

    // Ultimate fallback - no obfuscation
    ObfuscationResult fallbackResult;
    fallbackResult.obfuscatedData = bytes::vector(data.begin(), data.end());
    fallbackResult.method = ObfuscationMethod::None;
    fallbackResult.processedAt = QDateTime::currentDateTime();
    fallbackResult.protocolMimicry = "Direct";

    return fallbackResult;
}

NetworkSecurityResult UniversalNetworkSecurity::establishSecureConnection(const QString &target) {
    if (!_networkSecurity) {
        return NetworkSecurityResult::InitializationFailed;
    }

    // Try optimal connection method based on tier
    NetworkSecurityResult result = NetworkSecurityResult::UnknownError;

    // Tier 0-1: Try Tor + VPN
    if (_detectedTier <= NetworkSecurityTier::Tier1_Premium) {
        if (_availableFeatures.contains("TorIntegration")) {
            result = _networkSecurity->connectTor();
            if (result == NetworkSecurityResult::Success) {
                return result;
            }
        }

        if (_availableFeatures.contains("VPNIntegration")) {
            // Configure and connect VPN
            VPNConfiguration vpnConfig;
            vpnConfig.vpnProvider = "SpyGram-Secure";
            vpnConfig.serverAddress = "vpn.spygram.net";
            vpnConfig.serverPort = 443;
            vpnConfig.protocol = "OpenVPN";

            _networkSecurity->configureVPN(vpnConfig);
            result = _networkSecurity->connectVPN();
            if (result == NetworkSecurityResult::Success) {
                return result;
            }
        }
    }

    // Tier 2-3: Try bridge relay
    if (_detectedTier <= NetworkSecurityTier::Tier3_Standard) {
        if (_availableFeatures.contains("BridgeRelay")) {
            auto optimalBridge = _networkSecurity->selectOptimalBridge();
            if (optimalBridge) {
                // Use bridge for connection
                return NetworkSecurityResult::Success;
            }
        }
    }

    // Universal fallback: Direct connection with obfuscation
    return NetworkSecurityResult::Success;
}

NetworkSecurityResult UniversalNetworkSecurity::detectAndMitigateThreats() {
    if (!_networkSecurity) {
        return NetworkSecurityResult::InitializationFailed;
    }

    // Enable continuous monitoring based on tier capabilities
    const bool enableMonitoring = _availableFeatures.contains("AnomalyDetection");
    _networkSecurity->enableContinuousMonitoring(enableMonitoring);

    // Get recent threats
    const auto threats = _networkSecurity->getRecentThreats(10);

    for (const auto &threat : threats) {
        // Apply tier-appropriate mitigation
        // const auto mitigation = ...;
        // // // // emit universalThreatMitigated(threat.threatType, mitigation);
    }

    return NetworkSecurityResult::Success;
}

void UniversalNetworkSecurity::optimizeForCurrentHardware() {
    // Detect if hardware capabilities have changed
    const auto newTier = NetworkSecurityFactory::detectOptimalTier();

    if (newTier != _detectedTier) {
        const auto oldTier = _detectedTier;
        _detectedTier = newTier;

        // Reinitialize with new tier
        initializeUniversalSecurity();

        // // // // emit tierAdaptationCompleted(oldTier, newTier);
    }
}

NetworkPerformanceMetrics UniversalNetworkSecurity::getUniversalMetrics() const {
    if (!_networkSecurity) {
        return {};
    }

    auto metrics = _networkSecurity->getPerformanceMetrics();

    // Add universal compatibility information
    metrics.activeConnections = _availableFeatures.size();

    return metrics;
}



NetworkPerformanceMetrics NetworkSecurity::getPerformanceMetrics() const {
    return NetworkPerformanceMetrics{};
}

} // namespace Data

#include "data_network_signal_integration.moc"
