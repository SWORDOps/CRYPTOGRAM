/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QString>
#include <vector>
#include <random>
#include <chrono>
#include <array>

namespace Platform {

// Enhanced entropy source for device ID generation
class EntropySource {
public:
    static EntropySource& instance() {
        static EntropySource source;
        return source;
    }
    
    // Get unique entropy for this session that stays consistent
    const std::array<uint8_t, 32>& sessionEntropy() const {
        return _sessionEntropy;
    }
    
    // Regenerate session entropy (called on login)
    void regenerateSessionEntropy() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dis(0, 255);
        
        for (auto& byte : _sessionEntropy) {
            byte = dis(gen);
        }
    }
    
    // Get continuously changing entropy
    std::array<uint8_t, 32> dynamicEntropy() {
        std::array<uint8_t, 32> result;
        const auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        
        // Use current entropy + time to create new entropy
        for (size_t i = 0; i < result.size(); i++) {
            result[i] = static_cast<uint8_t>(_sessionEntropy[i] ^ 
                                           ((now >> (i % 8)) & 0xFF));
        }
        return result;
    }
    
private:
    EntropySource() {
        // Generate unique entropy for this session
        regenerateSessionEntropy();
    }
    
    std::array<uint8_t, 32> _sessionEntropy;
};

class DeviceRandomizer {
public:
    static DeviceRandomizer &Instance() {
        static DeviceRandomizer instance;
        return instance;
    }

    QString getRandomDeviceModel();
    QString getRandomSystemVersion();
    QString getRandomAppVersion();
    int getRandomAppId();
    QString getRandomIpAddress();
    QString getRandomLocation();
    QString getRandomTimeActive();

    void generateNewIdentity();
    
    // Current values
    QString currentDeviceModel() const { return _currentDeviceModel; }
    QString currentSystemVersion() const { return _currentSystemVersion; }
    QString currentAppVersion() const { return _currentAppVersion; }
    int currentAppId() const { return _currentAppId; }
    QString currentIpAddress() const { return _currentIpAddress; }
    QString currentLocation() const { return _currentLocation; }
    QString currentTimeActive() const { return _currentTimeActive; }

private:
    DeviceRandomizer();
    
    // Random number generator
    std::mt19937 _rng;
    
    // Available options
    std::vector<QString> _deviceModels;
    std::vector<QString> _systemVersions;
    std::vector<QString> _appVersions;
    std::vector<int> _appIds;
    
    // Current values (regenerated on login)
    QString _currentDeviceModel;
    QString _currentSystemVersion;
    QString _currentAppVersion;
    int _currentAppId;
    QString _currentIpAddress;
    QString _currentLocation;
    QString _currentTimeActive;
    
    // Helper methods
    template<typename T>
    T getRandomItem(const std::vector<T>& items);
};

// Replacement for Platform::DeviceModelPretty
QString DeviceModelPretty();

// Replacement for Platform::SystemVersionPretty
QString SystemVersionPretty();

} // namespace Platform 