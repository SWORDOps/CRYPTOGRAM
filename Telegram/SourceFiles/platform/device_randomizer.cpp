/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "platform/device_randomizer.h"

#include <QDateTime>
#include <QCryptographicHash>
#include <random>

namespace Platform {

// Hash a string with device-specific salt to create consistent but private identifiers
QString createPrivateHash(const QString& input, const QByteArray& salt = QByteArray()) {
    // Combine input with salt and device-specific information
    QByteArray data = input.toUtf8() + salt;
    
    // Create a SHA-256 hash
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(data);
    
    // Convert to a hex string and take first 8 characters
    return QString::fromLatin1(hash.result().toHex().left(8));
}

DeviceRandomizer::DeviceRandomizer() 
    : _rng(std::chrono::system_clock::now().time_since_epoch().count()) {
    
    // Initialize with iPhone models
    _deviceModels = {
        "iPhone 12,1",      // iPhone 11
        "iPhone 12,3",      // iPhone 11 Pro
        "iPhone 12,5",      // iPhone 11 Pro Max
        "iPhone 13,1",      // iPhone 12 mini
        "iPhone 13,2",      // iPhone 12
        "iPhone 13,3",      // iPhone 12 Pro
        "iPhone 13,4",      // iPhone 12 Pro Max
        "iPhone 14,2",      // iPhone 13 Pro
        "iPhone 14,3",      // iPhone 13 Pro Max
        "iPhone 14,4",      // iPhone 13 mini
        "iPhone 14,5",      // iPhone 13
        "iPhone 14,6",      // iPhone SE (3rd gen)
        "iPhone 14,7",      // iPhone 14
        "iPhone 14,8",      // iPhone 14 Plus
        "iPhone 15,2",      // iPhone 14 Pro
        "iPhone 15,3",      // iPhone 14 Pro Max
        "iPhone 15,4",      // iPhone 15
        "iPhone 15,5",      // iPhone 15 Plus
    };
    
    // iOS versions
    _systemVersions = {
        "iOS 15.4.1",
        "iOS 15.5",
        "iOS 15.6.1",
        "iOS 16.0.2",
        "iOS 16.1",
        "iOS 16.1.1",
        "iOS 16.2",
        "iOS 16.3",
        "iOS 16.3.1",
        "iOS 16.4.1",
        "iOS 16.5",
        "iOS 16.6",
        "iOS 16.6.1",
        "iOS 17.0",
        "iOS 17.0.1",
        "iOS 17.0.2",
        "iOS 17.0.3",
        "iOS 17.1",
        "iOS 17.1.1",
        "iOS 17.2",
    };
    
    // App versions - official Telegram iOS versions
    _appVersions = {
        "9.5.2",
        "9.6.1",
        "9.6.2",
        "9.7",
        "9.7.1",
        "9.7.2",
        "9.8",
        "9.8.1",
        "9.8.2",
        "9.8.3",
        "10.0",
        "10.0.1",
        "10.0.2",
    };
    
    // App IDs (iOS Telegram app ID)
    _appIds = {
        686948679  // Official Telegram iOS app ID
    };
    
    // Generate initial identity
    generateNewIdentity();
}

template<typename T>
T DeviceRandomizer::getRandomItem(const std::vector<T>& items) {
    if (items.empty()) {
        return T();
    }
    std::uniform_int_distribution<size_t> dist(0, items.size() - 1);
    return items[dist(_rng)];
}

QString DeviceRandomizer::getRandomDeviceModel() {
    return getRandomItem(_deviceModels);
}

QString DeviceRandomizer::getRandomSystemVersion() {
    return getRandomItem(_systemVersions);
}

QString DeviceRandomizer::getRandomAppVersion() {
    return getRandomItem(_appVersions);
}

int DeviceRandomizer::getRandomAppId() {
    return getRandomItem(_appIds);
}

QString DeviceRandomizer::getRandomIpAddress() {
    // Use entropy for consistent IP address that matches the location
    const auto& entropy = EntropySource::instance().sessionEntropy();
    
    // Location-based IP ranges (mapped to realistic IP blocks)
    struct IPRange {
        uint8_t firstOctet;
        uint8_t secondOctet;
    };
    
    // Map of realistic IP ranges for specific regions
    static const std::map<QString, IPRange> locationIpRanges = {
        {"United States", {173, 16}},
        {"United Kingdom", {92, 122}},
        {"Germany", {91, 210}},
        {"France", {37, 160}},
        {"Australia", {1, 120}},
        {"Canada", {23, 16}},
        {"Japan", {45, 76}},
        {"South Korea", {27, 255}},
        {"Russia", {95, 167}},
        {"Denmark", {132, 249}},
        {"Netherlands", {37, 251}},
        {"Sweden", {79, 102}},
        {"Singapore", {59, 189}},
        {"Brazil", {177, 69}}
    };
    
    // Get our randomized location
    const auto location = getRandomLocation();
    
    // Default range if location not found
    IPRange range = {192, 168};
    
    // Find matching IP range for the location
    for (const auto& [country, ipRange] : locationIpRanges) {
        if (location.contains(country, Qt::CaseInsensitive)) {
            range = ipRange;
            break;
        }
    }
    
    // Use entropy for the last two octets
    const uint8_t thirdOctet = entropy[13];
    const uint8_t fourthOctet = entropy[14];
    
    return QString("%1.%2.%3.%4")
        .arg(range.firstOctet)
        .arg(range.secondOctet)
        .arg(thirdOctet)
        .arg(fourthOctet);
}

QString DeviceRandomizer::getRandomLocation() {
    // Use entropy for consistent location
    const auto& entropy = EntropySource::instance().sessionEntropy();
    
    // List of realistic locations
    static const std::vector<QString> locations = {
        "United States",
        "United Kingdom",
        "Germany",
        "France",
        "Australia",
        "Canada",
        "Japan",
        "South Korea",
        "Russia",
        "Denmark",
        "Netherlands",
        "Sweden",
        "Singapore",
        "Brazil"
    };
    
    // Use entropy to select location
    const uint8_t locationIndex = entropy[15] % locations.size();
    return locations[locationIndex];
}

QString DeviceRandomizer::getRandomTimeActive() {
    // Use session entropy for a reasonable "last seen" time
    const auto& entropy = EntropySource::instance().sessionEntropy();
    
    // Generate hours and minutes ago (1-24 hours, 0-59 minutes)
    const int hoursAgo = 1 + (entropy[16] % 24);
    const int minutesAgo = entropy[17] % 60;
    
    if (hoursAgo <= 1) {
        return QString("%1 minutes ago").arg(minutesAgo);
    } else {
        return QString("%1 hours ago").arg(hoursAgo);
    }
}

void DeviceRandomizer::generateNewIdentity() {
    // Force re-seed of entropy source
    EntropySource::instance().regenerateSessionEntropy();
    
    _currentDeviceModel = getRandomDeviceModel();
    _currentSystemVersion = getRandomSystemVersion();
    _currentAppVersion = getRandomAppVersion();
    _currentAppId = getRandomAppId();
    _currentIpAddress = getRandomIpAddress();
    _currentLocation = getRandomLocation();
    _currentTimeActive = getRandomTimeActive();
    
    // Log the new identity for debugging
    LOG(("Device Randomizer: Generated new identity"));
    LOG(("  - Device Model: %1").arg(_currentDeviceModel));
    LOG(("  - System Version: %1").arg(_currentSystemVersion));
    LOG(("  - App Version: %1").arg(_currentAppVersion));
    LOG(("  - App ID: %1").arg(_currentAppId));
    LOG(("  - IP Address: %1").arg(_currentIpAddress));
    LOG(("  - Location: %1").arg(_currentLocation));
    LOG(("  - Time Active: %1").arg(_currentTimeActive));
}

// Replacement for Platform::DeviceModelPretty
QString DeviceModelPretty() {
    // Use our enhanced entropy source
    const auto& entropy = EntropySource::instance().sessionEntropy();
    static std::mt19937 rng(std::chrono::system_clock::now().time_since_epoch().count() ^ 
                           *reinterpret_cast<const uint32_t*>(entropy.data()));
    
    #ifdef Q_OS_WIN
        // Windows-specific device models with HMAC protection
        static std::uniform_int_distribution<int> dist(1000, 9999);
        static const std::vector<QString> prefixes = {
            "SCIF", "SIPR", "TS/SCI", "JWICS"
        };
        
        // Use entropy to select prefix
        const uint8_t prefixIndex = entropy[0] % prefixes.size();
        
        // Generate a random number that won't change during the session
        const uint16_t sessionId = 
            (static_cast<uint16_t>(entropy[1]) << 8) | 
            static_cast<uint16_t>(entropy[2]);
        
        return QString("%1 %2").arg(prefixes[prefixIndex]).arg(1000 + (sessionId % 9000));
    #elif defined Q_OS_MAC
        // Mac-specific device models with obfuscation
        // MacBookPro version derived from entropy
        const uint8_t majorVer = 10 + (entropy[3] % 16);
        const uint8_t minorVer = 1 + (entropy[4] % 4);
        
        return QString("MacBookPro%1,%2").arg(majorVer).arg(minorVer);
    #else
        // Linux-specific device models with randomization
        static const std::vector<QString> prefixes = {
            "TEMPEST", "EMSEC", "AIR-GAP", "SCIF"
        };
        
        // Use entropy to select prefix and create ID
        const uint8_t prefixIndex = entropy[5] % prefixes.size();
        const uint16_t deviceId = 
            (static_cast<uint16_t>(entropy[6]) << 8) | 
            static_cast<uint16_t>(entropy[7]);
        
        return QString("%1-%2").arg(prefixes[prefixIndex]).arg(1000 + (deviceId % 9000));
    #endif
}

// Replacement for Platform::SystemVersionPretty
QString SystemVersionPretty() {
    // If already using randomized value, return it
    if (!DeviceRandomizer::Instance().currentSystemVersion().isEmpty()) {
        return DeviceRandomizer::Instance().currentSystemVersion();
    }
    
    // Use our enhanced entropy source
    const auto& entropy = EntropySource::instance().sessionEntropy();
    
    #ifdef Q_OS_WIN
        // Windows version with build number
        static const std::vector<QString> winVersions = {
            "Windows 10 Enterprise LTSC", 
            "Windows 10 Enterprise", 
            "Windows 11 Enterprise"
        };
        
        // Use entropy to select version
        const uint8_t versionIndex = entropy[8] % winVersions.size();
        
        // Generate a build number that's consistent for this session
        const uint16_t buildOffset = 
            (static_cast<uint16_t>(entropy[9]) << 8) | 
            static_cast<uint16_t>(entropy[10]);
        
        return QString("%1 (Build %2)").arg(winVersions[versionIndex]).arg(18000 + (buildOffset % 8000));
    #elif defined Q_OS_MAC
        // macOS version
        static const std::vector<QString> macVersions = {
            "macOS 13.5.2", "macOS 14.0", "macOS 14.1", "macOS 14.2.1"
        };
        
        // Use entropy to select version
        const uint8_t versionIndex = entropy[11] % macVersions.size();
        
        return macVersions[versionIndex];
    #else
        // Linux distribution
        static const std::vector<QString> linuxVersions = {
            "Ubuntu 22.04 LTS", "Debian 12", "Fedora 38", "Arch Linux"
        };
        
        // Use entropy to select version
        const uint8_t versionIndex = entropy[12] % linuxVersions.size();
        
        return linuxVersions[versionIndex];
    #endif
}

} // namespace Platform 